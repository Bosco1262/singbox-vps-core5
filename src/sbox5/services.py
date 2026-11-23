# Copyright (C) 2026 Bosco1262
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

from pathlib import Path
import shlex
import sys

from .errors import ConflictError
from .i18n import tr
from .models import Settings
from .util import atomic_text, available, run

UNIT_ROOT = Path("/etc/systemd/system")
APP_ROOT = Path("/usr/local/libexec/sbox5/app")
BINARY_ROOT = Path("/usr/local/libexec/sbox5/bin")


def _nologin_shell() -> str:
    if Path("/sbin/nologin").exists():
        return "/sbin/nologin"
    return "/usr/sbin/nologin"


def ensure_system_user(name: str, allow_existing: bool = False) -> bool:
    import pwd
    try:
        pwd.getpwnam(name)
    except KeyError:
        run(["useradd", "--system", "--user-group", "--no-create-home", "--shell", _nologin_shell(), name])
        return True
    if not allow_existing:
        raise ConflictError(tr(f"The system user already exists; refusing to take it over: {name}", f"系统用户已存在，拒绝接管：{name}"))
    return False


def identity(name: str) -> tuple[int, int]:
    import grp
    import pwd
    account = pwd.getpwnam(name)
    return account.pw_uid, grp.getgrnam(name).gr_gid


def singbox_unit(settings: Settings) -> str:
    enabled_ports = [
        getattr(settings.ports, name)
        for name, protocol in settings.protocols.items()
        if protocol.enabled
    ]
    challenge_ports = settings.acme_challenge_ports() if settings.active_certificate_profiles() else []
    low_port = any(port < 1024 for port in enabled_ports) or any(port < 1024 for port in challenge_ports)
    capability = "CAP_NET_BIND_SERVICE" if low_port else ""
    lines = [
        "[Unit]",
        "Description=sbox5 five-protocol sing-box server",
        "After=network-online.target",
        "Wants=network-online.target",
        "",
        "[Service]",
        "Type=simple",
        "User=sbox5",
        "Group=sbox5",
        "WorkingDirectory=/var/lib/sbox5-runtime",
        "ExecStart=/usr/local/libexec/sbox5/bin/sing-box run -c /etc/sbox5/config.json",
        "Restart=on-failure",
        "RestartSec=3s",
        "LimitNOFILE=1048576",
        "UMask=0077",
        "NoNewPrivileges=true",
        "PrivateTmp=true",
        "PrivateDevices=true",
        "ProtectSystem=strict",
        "ProtectHome=true",
        "ProtectKernelTunables=true",
        "ProtectKernelModules=true",
        "ProtectKernelLogs=true",
        "ProtectControlGroups=true",
        "ProtectClock=true",
        "ProtectHostname=true",
        "ProtectProc=invisible",
        "ProcSubset=pid",
        "RestrictSUIDSGID=true",
        "LockPersonality=true",
        "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK",
        "SystemCallFilter=@system-service",
        "SystemCallErrorNumber=EPERM",
        f"CapabilityBoundingSet={capability}",
        f"AmbientCapabilities={capability}",
        "StateDirectory=sbox5-runtime",
        "RuntimeDirectory=sbox5-runtime",
        "ReadWritePaths=/var/lib/sbox5-runtime /run/sbox5-runtime /var/lib/sbox5/acme",
        "StandardOutput=journal",
        "StandardError=journal",
        "SyslogIdentifier=sbox5",
        "",
        "[Install]",
        "WantedBy=multi-user.target",
        "",
    ]
    return "\n".join(lines)


def argo_unit(settings: Settings) -> str:
    if settings.argo.mode == "quick":
        command = (
            "/usr/local/libexec/sbox5/bin/cloudflared tunnel --no-autoupdate "
            f"--url http://127.0.0.1:{settings.argo.local_port}"
        )
        output = (
            "StandardOutput=append:/var/lib/sbox5/argo/quick.log\n"
            "StandardError=inherit\n"
        )
    else:
        command = (
            "/usr/local/libexec/sbox5/bin/cloudflared tunnel --no-autoupdate "
            "run --token-file /etc/sbox5/secrets/argo.token"
        )
        output = "StandardOutput=journal\nStandardError=journal\n"
    return f"""[Unit]
Description=sbox5 Cloudflare Tunnel
After=network-online.target sbox5.service
Wants=network-online.target sbox5.service

[Service]
Type=simple
User=sbox5-argo
Group=sbox5-argo
ExecStart={command}
Restart=on-failure
RestartSec=5s
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
CapabilityBoundingSet=
AmbientCapabilities=
ReadWritePaths=/var/lib/sbox5/argo
{output}SyslogIdentifier=sbox5-argo

[Install]
WantedBy=multi-user.target
"""


def ddns_unit() -> str:
    return """[Unit]
Description=sbox5 Cloudflare DDNS update
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
User=sbox5-ddns
Group=sbox5-ddns
ExecStart=/usr/local/bin/sbox5 ddns-update --non-interactive
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
CapabilityBoundingSet=
AmbientCapabilities=
ReadWritePaths=/var/lib/sbox5/ddns
StandardOutput=journal
StandardError=journal
SyslogIdentifier=sbox5-ddns
"""


def ddns_timer(interval_seconds: int) -> str:
    return f"""[Unit]
Description=Schedule sbox5 Cloudflare DDNS updates

[Timer]
OnBootSec=2min
OnUnitActiveSec={interval_seconds}s
AccuracySec=30s
Persistent=true

[Install]
WantedBy=timers.target
"""


def subscription_unit() -> str:
    return """[Unit]
Description=sbox5 local subscription service
After=network.target

[Service]
Type=simple
User=sbox5-sub
Group=sbox5-sub
ExecStart=/usr/local/bin/sbox5 subscription-serve --non-interactive
Restart=on-failure
RestartSec=5s
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
CapabilityBoundingSet=
AmbientCapabilities=
StandardOutput=journal
StandardError=journal
SyslogIdentifier=sbox5-subscription

[Install]
WantedBy=multi-user.target
"""


def firewall_unit() -> str:
    write_paths = "/var/lib/sbox5 /run"
    if Path("/etc/ufw").is_dir():
        write_paths = "/etc/ufw " + write_paths
    return f"""[Unit]
Description=sbox5 owned firewall rules
Before=sbox5.service
After=local-fs.target

[Service]
Type=oneshot
ExecStart=/usr/local/bin/sbox5 firewall-apply --non-interactive
RemainAfterExit=yes
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=full
ProtectHome=true
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictSUIDSGID=true
ReadWritePaths={write_paths}
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW

[Install]
WantedBy=multi-user.target
"""


def _requires_low_port(settings: Settings) -> bool:
    ports = [settings.ports.as_dict()[name] for name, protocol in settings.protocols.items() if protocol.enabled]
    if settings.active_certificate_profiles():
        ports.extend(settings.acme_challenge_ports())
    return any(port < 1024 for port in ports)


def openrc_singbox(settings: Settings) -> str:
    setcap = ""
    if _requires_low_port(settings):
        setcap = "\n    if command -v setcap >/dev/null 2>&1; then\n        setcap cap_net_bind_service=+ep /usr/local/libexec/sbox5/bin/sing-box\n    fi"
    return f"""#!/sbin/openrc-run
name="sbox5"
description="sbox5 five-protocol sing-box server"
command="/usr/local/libexec/sbox5/bin/sing-box"
command_args="run -c /etc/sbox5/config.json"
command_user="sbox5:sbox5"
command_background="yes"
pidfile="/run/sbox5/sing-box.pid"
directory="/var/lib/sbox5-runtime"
output_log="/var/log/sbox5/sing-box.log"
error_log="/var/log/sbox5/sing-box.log"
depend() {{
    need net
    after sbox5-firewall
}}
start_pre() {{
    checkpath --directory --mode 0755 /run/sbox5
    checkpath --directory --owner sbox5:sbox5 --mode 0700 /var/lib/sbox5-runtime
    checkpath --directory --mode 0755 /var/log/sbox5{setcap}
}}
"""


def openrc_argo(settings: Settings) -> str:
    if settings.argo.mode == "quick":
        command_args = f"--no-autoupdate --url http://127.0.0.1:{settings.argo.local_port}"
        output_log = "/var/lib/sbox5/argo/quick.log"
    else:
        command_args = "--no-autoupdate run --token-file /etc/sbox5/secrets/argo.token"
        output_log = "/var/log/sbox5/argo.log"
    return f"""#!/sbin/openrc-run
name="sbox5-argo"
description="sbox5 Cloudflare Tunnel"
command="/usr/local/libexec/sbox5/bin/cloudflared"
command_args="{command_args}"
command_user="sbox5-argo:sbox5-argo"
command_background="yes"
pidfile="/run/sbox5/argo.pid"
output_log="{output_log}"
error_log="{output_log}"
depend() {{
    need net
    after sbox5
}}
start_pre() {{
    checkpath --directory --mode 0755 /run/sbox5
    checkpath --directory --owner sbox5-argo:sbox5-argo --mode 0700 /var/lib/sbox5/argo
    checkpath --directory --mode 0755 /var/log/sbox5
}}
"""


def openrc_ddns() -> str:
    return """#!/sbin/openrc-run
name="sbox5-ddns"
description="sbox5 Cloudflare DDNS loop"
command="/usr/local/bin/sbox5"
command_args="ddns-loop --non-interactive"
command_user="sbox5-ddns:sbox5-ddns"
command_background="yes"
pidfile="/run/sbox5/ddns.pid"
output_log="/var/log/sbox5/ddns.log"
error_log="/var/log/sbox5/ddns.log"
depend() {
    need net
}
start_pre() {
    checkpath --directory --mode 0755 /run/sbox5
    checkpath --directory --owner sbox5-ddns:sbox5-ddns --mode 0700 /var/lib/sbox5/ddns
    checkpath --directory --mode 0755 /var/log/sbox5
}
"""


def openrc_firewall() -> str:
    return """#!/sbin/openrc-run
name="sbox5-firewall"
description="sbox5 owned firewall rules"
command="/usr/local/bin/sbox5"
command_args="firewall-apply --non-interactive"
depend() {
    before sbox5
    after localmount
}
"""


def openrc_subscription() -> str:
    return """#!/sbin/openrc-run
name="sbox5-subscription"
description="sbox5 local subscription service"
command="/usr/local/bin/sbox5"
command_args="subscription-serve --non-interactive"
command_user="sbox5-sub:sbox5-sub"
command_background="yes"
pidfile="/run/sbox5/subscription.pid"
output_log="/var/log/sbox5/subscription.log"
error_log="/var/log/sbox5/subscription.log"
depend() {
    need net
}
start_pre() {
    checkpath --directory --mode 0755 /run/sbox5
    checkpath --directory --mode 0755 /var/log/sbox5
}
"""


def init_backend() -> str:
    if Path("/run/systemd/system").is_dir() and available("systemctl"):
        return "systemd"
    if available("rc-service") and available("rc-update"):
        return "openrc"
    return "systemd"


def openrc_name(name: str) -> str:
    if name.endswith(".service"):
        return name[:-8]
    if name.endswith(".timer"):
        return name[:-6]
    return name


def service_path(name: str) -> Path:
    if init_backend() == "openrc":
        return Path("/etc/init.d") / openrc_name(name)
    return UNIT_ROOT / name


def service_exists(name: str) -> bool:
    if init_backend() == "openrc":
        return service_path(name).is_file()
    return any(path.exists() for path in (
        UNIT_ROOT / name,
        Path("/usr/lib/systemd/system") / name,
        Path("/lib/systemd/system") / name,
    ))


def service_active(name: str) -> bool:
    if init_backend() == "openrc":
        return run(["rc-service", openrc_name(name), "status"], check=False).returncode == 0
    result = run(["systemctl", "is-active", name], check=False)
    return result.returncode == 0 and result.stdout.strip() == "active"


def service_enabled(name: str) -> bool:
    if init_backend() == "openrc":
        result = run(["rc-update", "show", "default"], check=False)
        base = openrc_name(name)
        for line in result.stdout.splitlines():
            parts = line.split()
            if parts and parts[0] == base:
                return True
        return False
    result = run(["systemctl", "is-enabled", name], check=False)
    return result.returncode == 0 and result.stdout.strip() == "enabled"


def service_state_text(name: str) -> str:
    if init_backend() == "openrc":
        result = run(["rc-service", openrc_name(name), "status"], check=False)
        return result.stdout.strip().splitlines()[0] if result.stdout.strip() else str(result.returncode)
    result = run(["systemctl", "is-active", name], check=False)
    return result.stdout.strip() or str(result.returncode)


def service_logs_command(name: str, follow: bool = False) -> list[str]:
    if init_backend() == "openrc":
        base = openrc_name(name)
        logs = {
            "sbox5": "sing-box.log",
            "sbox5-argo": "argo.log",
            "sbox5-ddns": "ddns.log",
            "sbox5-subscription": "subscription.log",
        }
        log = Path("/var/log/sbox5") / logs.get(base, f"{base}.log")
        if base == "sbox5-argo":
            quick_log = Path("/var/lib/sbox5/argo/quick.log")
            if quick_log.is_file():
                log = quick_log
        if log.is_file():
            command = ["tail", "-n", "200"]
            if follow:
                command.append("-f")
            command.append(str(log))
            return command
        return ["rc-service", base, "status"]
    command = ["journalctl", "-u", name, "--no-pager"]
    if follow:
        command.append("-f")
    return command


def service_stop(name: str) -> None:
    if init_backend() == "openrc":
        run(["rc-service", openrc_name(name), "stop"], check=False)
    else:
        run(["systemctl", "stop", name], check=False)


def service_start(name: str) -> None:
    if init_backend() == "openrc":
        run(["rc-service", openrc_name(name), "start"], check=True)
    else:
        run(["systemctl", "start", name], check=True)


def service_restart(name: str) -> None:
    if init_backend() == "openrc":
        run(["rc-service", openrc_name(name), "restart"], check=True)
    else:
        run(["systemctl", "restart", name], check=True)


def service_disable(name: str) -> None:
    if init_backend() == "openrc":
        run(["rc-update", "del", openrc_name(name), "default"], check=False)
    else:
        run(["systemctl", "disable", name], check=False)


def install_service(name: str, systemd_content: str, openrc_content: str) -> Path:
    if init_backend() == "openrc":
        path = Path("/etc/init.d") / openrc_name(name)
        atomic_text(path, openrc_content, 0o755)
        return path
    path = UNIT_ROOT / name
    atomic_text(path, systemd_content, 0o644)
    return path


def remove_service(name: str) -> None:
    path = service_path(name)
    if path.exists() and path.is_file() and not path.is_symlink():
        path.unlink()


def install_unit(name: str, content: str) -> Path:
    if not name.startswith("sbox5") or "/" in name:
        raise ConflictError(tr("Refusing to install a systemd unit that does not belong to this project", "拒绝安装非项目 systemd 单元"))
    path = UNIT_ROOT / name
    atomic_text(path, content, 0o644)
    return path


def reload_systemd() -> None:
    if init_backend() == "openrc":
        return
    run(["systemctl", "daemon-reload"])


def enable_start(name: str) -> None:
    if init_backend() == "openrc":
        run(["rc-update", "add", openrc_name(name), "default"], check=False)
        run(["rc-service", openrc_name(name), "start"], check=True, timeout=90)
        return
    run(["systemctl", "enable", "--now", name], timeout=90)


def restart(name: str) -> None:
    service_restart(name)


def require_active(name: str) -> None:
    if not service_active(name):
        raise ConflictError(tr(f"The service did not reach active state: {name}", f"服务未进入 active 状态：{name}"))


def copy_application(project_root: Path) -> list[Path]:
    installed: list[Path] = []
    for directory in ("src", "locks", "recovery"):
        source = project_root / directory
        for file_path in source.rglob("*"):
            if not file_path.is_file() or "__pycache__" in file_path.parts or file_path.suffix == ".pyc":
                continue
            relative = file_path.relative_to(project_root)
            destination = APP_ROOT / relative
            destination.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
            atomic_text(destination, file_path.read_text(encoding="utf-8"), 0o644)
            installed.append(destination)
    launcher_python = sys.executable or "python3"
    launcher = f"""#!/bin/sh
set -eu
umask 077
exec {shlex.quote(launcher_python)} -I -B /usr/local/libexec/sbox5/app/src/main.py --project-root /usr/local/libexec/sbox5/app "$@"
"""
    launcher_path = Path("/usr/local/bin/sbox5")
    atomic_text(launcher_path, launcher, 0o755)
    installed.append(launcher_path)
    return installed
