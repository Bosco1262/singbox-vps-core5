# Copyright (C) 2026 Bosco1262
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

from pathlib import Path

from .errors import ConflictError
from .i18n import tr
from .models import Settings
from .util import atomic_text, run

UNIT_ROOT = Path("/etc/systemd/system")
APP_ROOT = Path("/usr/local/libexec/sbox5/app")
BINARY_ROOT = Path("/usr/local/libexec/sbox5/bin")


def ensure_system_user(name: str, allow_existing: bool = False) -> bool:
    import pwd
    try:
        pwd.getpwnam(name)
    except KeyError:
        run(["useradd", "--system", "--no-create-home", "--shell", "/usr/sbin/nologin", name])
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


def argo_unit() -> str:
    return """[Unit]
Description=sbox5 Cloudflare Tunnel
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=sbox5-argo
Group=sbox5-argo
ExecStart=/usr/local/libexec/sbox5/bin/cloudflared tunnel --no-autoupdate run --token-file /etc/sbox5/secrets/argo.token
Restart=on-failure
RestartSec=5s
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
StandardOutput=journal
StandardError=journal
SyslogIdentifier=sbox5-argo

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


def firewall_unit() -> str:
    return """[Unit]
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
ReadWritePaths=/etc/ufw /var/lib/sbox5 /run
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW

[Install]
WantedBy=multi-user.target
"""


def install_unit(name: str, content: str) -> Path:
    if not name.startswith("sbox5") or "/" in name:
        raise ConflictError(tr("Refusing to install a systemd unit that does not belong to this project", "拒绝安装非项目 systemd 单元"))
    path = UNIT_ROOT / name
    atomic_text(path, content, 0o644)
    return path


def reload_systemd() -> None:
    run(["systemctl", "daemon-reload"])


def enable_start(name: str) -> None:
    run(["systemctl", "enable", "--now", name], timeout=90)


def restart(name: str) -> None:
    run(["systemctl", "restart", name], timeout=90)


def require_active(name: str) -> None:
    result = run(["systemctl", "is-active", name], check=False)
    if result.returncode != 0 or result.stdout.strip() != "active":
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
    launcher = """#!/usr/bin/env bash
set -Eeuo pipefail
umask 077
exec python3 -I -B /usr/local/libexec/sbox5/app/src/main.py --project-root /usr/local/libexec/sbox5/app "$@"
"""
    launcher_path = Path("/usr/local/bin/sbox5")
    atomic_text(launcher_path, launcher, 0o755)
    installed.append(launcher_path)
    return installed
