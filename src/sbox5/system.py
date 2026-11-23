# Copyright (C) 2026 Bosco1262
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import os
from pathlib import Path
import platform
import sys
from typing import Any

from .errors import ConfigError, ExternalCommandError
from .i18n import tr
from .models import Settings
from .util import available, atomic_text, port_is_free, require_linux_root, run


def architecture() -> str:
    machine = platform.machine().lower()
    if machine in ("x86_64", "amd64"):
        return "amd64"
    if machine in ("aarch64", "arm64"):
        return "arm64"
    raise ConfigError(tr(f"Unsupported CPU architecture: {machine}", f"不支持的 CPU 架构：{machine}"))


def _release() -> dict[str, str]:
    release: dict[str, str] = {}
    for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
        key, separator, value = line.partition("=")
        if separator:
            release[key] = value.strip().strip('"')
    return release


def _version_numbers(version: str) -> tuple[int, ...]:
    try:
        return tuple(int(part) for part in version.split(".") if part.isdigit())
    except ValueError as exc:
        raise ConfigError(tr("Unable to identify the system version", "无法识别系统版本")) from exc


def _family(release: dict[str, str]) -> str:
    distro = release.get("ID", "").lower()
    likes = release.get("ID_LIKE", "").lower().split()
    if distro in ("debian", "ubuntu"):
        return "debian"
    if distro == "alpine":
        return "alpine"
    if distro in ("rhel", "rocky", "almalinux", "centos", "ol") or "rhel" in likes:
        return "rhel"
    return ""


def package_manager() -> str:
    if available("apt-get") and available("dpkg-query"):
        return "apt"
    if available("apk"):
        return "apk"
    if available("dnf") or available("yum"):
        return "dnf"
    raise ConfigError(tr("No supported official package manager was found", "找不到受支持的官方包管理器"))


def preflight() -> None:
    require_linux_root()
    if sys.version_info < (3, 10):
        raise ConfigError(tr("Python 3.10 or later is required", "需要 Python 3.10 或更高版本"))
    if not Path("/etc/os-release").is_file() or not Path("/proc/1/comm").is_file():
        raise ConfigError(tr("A supported Linux distribution is required", "需要受支持的 Linux 发行版"))
    release = _release()
    distro = release.get("ID", "")
    version = release.get("VERSION_ID", "")
    numbers = _version_numbers(version)
    family = _family(release)
    if family == "debian":
        supported = (distro == "debian" and numbers >= (12,)) or (distro == "ubuntu" and numbers >= (22, 4))
        if not supported:
            raise ConfigError(tr("Debian 12+ or Ubuntu 22.04+ is required", "需要 Debian 12+ 或 Ubuntu 22.04+"))
    elif family == "alpine":
        if numbers < (3, 20):
            raise ConfigError(tr("Alpine 3.20+ is required", "需要 Alpine 3.20+"))
    elif family == "rhel":
        if numbers < (9,):
            raise ConfigError(tr("RHEL 9+, Rocky 9+, or AlmaLinux 9+ is required", "需要 RHEL 9+、Rocky 9+ 或 AlmaLinux 9+"))
    else:
        raise ConfigError(tr(f"Unsupported distribution: {distro or 'unknown'}", f"不支持的发行版：{distro or 'unknown'}"))
    from .services import init_backend
    backend = init_backend()
    if family == "alpine":
        if backend != "openrc" or not Path("/sbin/openrc-run").exists():
            raise ConfigError(tr("Alpine must boot with OpenRC; containers without an init system are not supported", "Alpine 必须使用 OpenRC 启动；不支持无 init 的容器"))
    elif backend != "systemd" or Path("/proc/1/comm").read_text(encoding="utf-8").strip() != "systemd":
        raise ConfigError(tr("PID 1 must be systemd on Debian/Ubuntu/RHEL", "Debian/Ubuntu/RHEL 的 PID 1 必须是 systemd"))
    if available("systemd-detect-virt"):
        result = run(["systemd-detect-virt"], check=False)
        virtualization = result.stdout.strip()
        if virtualization not in ("", "none", "kvm"):
            raise ConfigError(tr(f"Only KVM or VPS environments with an independent kernel are supported; the current one is {virtualization}", f"仅支持 KVM 或独立内核 VPS，当前环境为 {virtualization}"))
    wanted_manager = {"debian": "apt", "alpine": "apk", "rhel": "dnf"}[family]
    if package_manager() != wanted_manager:
        raise ConfigError(tr("The distribution's official package manager was not found", "找不到该发行版的官方包管理器"))
    architecture()


def check_ports(settings: Settings) -> None:
    occupied: list[str] = []
    for protocol, port in settings.ports.as_dict().items():
        if not settings.protocols[protocol].enabled:
            continue
        transport = "udp" if protocol in ("hysteria2", "tuic") else "tcp"
        if not port_is_free(port, transport):
            occupied.append(f"{protocol} {port}/{transport}")
    for profile in settings.active_certificate_profiles():
        if profile.mode != "acme":
            continue
        if profile.challenge == "http-01" and not port_is_free(80, "tcp"):
            occupied.append("acme-http-01 80/tcp")
        elif profile.challenge == "tls-alpn-01" and not port_is_free(443, "tcp"):
            occupied.append("acme-tls-alpn-01 443/tcp")
    if settings.argo.enabled and not port_is_free(settings.argo.local_port, "tcp"):
        occupied.append(f"argo-loopback {settings.argo.local_port}/tcp")
    if settings.subscription.enabled and not port_is_free(settings.subscription.port, "tcp"):
        occupied.append(f"subscription {settings.subscription.port}/tcp")
    if occupied:
        raise ConfigError(tr("The following ports are already in use: ", "以下端口已被占用：") + tr(", ", "、").join(occupied))


def _package_installed(name: str, manager: str | None = None) -> bool:
    manager = manager or package_manager()
    if manager == "apt":
        result = run(["dpkg-query", "-W", "-f=${Status}", name], check=False)
        return result.returncode == 0 and result.stdout.strip() == "install ok installed"
    if manager == "apk":
        return run(["apk", "info", "-e", name], check=False).returncode == 0
    return run(["rpm", "-q", "--quiet", name], check=False).returncode == 0


def ensure_packages(settings: Settings) -> dict[str, Any]:
    manager = package_manager()
    if manager == "apt":
        packages = ["ca-certificates", "python3", "openssl", "nftables", "iptables", "qrencode", "iproute2"]
    elif manager == "apk":
        packages = ["ca-certificates", "python3", "openssl", "nftables", "iptables", "qrencode", "libcap", "iproute2", "shadow"]
    else:
        packages = ["ca-certificates", "python3", "openssl", "nftables", "iptables-nft", "iproute"]
    missing = [name for name in packages if not _package_installed(name, manager)]
    if missing:
        if manager == "apt":
            environment = dict(os.environ)
            environment["DEBIAN_FRONTEND"] = "noninteractive"
            run(["apt-get", "update"], timeout=600, env=environment)
            run(["apt-get", "install", "-y", "--no-install-recommends", *missing], timeout=900, env=environment)
            note = tr("APT dependencies pulled in automatically are never downgraded or removed automatically", "APT 自动安装的依赖不自动降级或删除")
        elif manager == "apk":
            run(["apk", "add", "--no-cache", *missing], timeout=900)
            note = tr("APK dependencies are kept after uninstall; no third-party repositories are added", "APK 依赖在卸载后保留；不会添加第三方软件源")
        else:
            command = "dnf" if available("dnf") else "yum"
            run([command, "install", "-y", "--setopt=install_weak_deps=False", *missing], timeout=900)
            note = tr("DNF/RPM dependencies are kept after uninstall; EPEL and third-party repositories are not used", "DNF/RPM 依赖在卸载后保留；不使用 EPEL 或第三方软件源")
    else:
        note = tr("All required packages were already installed", "所有依赖包均已安装")
    return {
        "installed_by_project": missing,
        "upgraded_by_project": [],
        "removal_policy": "keep",
        "package_manager": manager,
        "note": note,
    }


def _sysctl_value(key: str) -> str:
    result = run(["sysctl", "-n", key], check=False)
    return result.stdout.strip() if result.returncode == 0 else ""


def configure_bbr(path: Path) -> list[dict[str, str]]:
    if not available("sysctl"):
        raise ExternalCommandError(tr("sysctl was not found", "找不到 sysctl"))
    available_algorithms = _sysctl_value("net.ipv4.tcp_available_congestion_control").split()
    if "bbr" not in available_algorithms and available("modprobe"):
        run(["modprobe", "tcp_bbr"])
        available_algorithms = _sysctl_value("net.ipv4.tcp_available_congestion_control").split()
    if "bbr" not in available_algorithms:
        raise ConfigError(tr("The current kernel does not support BBR; no kernel will be downloaded or replaced", "当前内核不支持 BBR；不会下载或替换内核"))
    records = []
    for key, value in (("net.core.default_qdisc", "fq"), ("net.ipv4.tcp_congestion_control", "bbr")):
        before = _sysctl_value(key)
        if not before:
            raise ConfigError(tr(f"Unable to read the current value of {key}; stopped to avoid an unrecoverable change", f"无法读取 {key} 的当前值；为避免产生不可恢复的变更，已停止"))
        records.append({"key": key, "before": before, "after": value})
    for record in records:
        run(["sysctl", "-w", f"{record['key']}={record['after']}"])
    atomic_text(path, "net.core.default_qdisc=fq\nnet.ipv4.tcp_congestion_control=bbr\n", 0o644)
    return records


def validate_token_text(value: str, name: str) -> str:
    token = value.strip()
    if not token or len(token) > 16384 or any(char in token for char in "\r\n\x00"):
        raise ConfigError(tr(f"{name} is empty, too long, or contains an illegal newline", f"{name} 为空、过长或包含非法换行"))
    return token


def read_token_file(path: Path, name: str) -> str:
    if not path.is_file() or path.is_symlink():
        raise ConfigError(tr(f"{name} must be a regular file", f"{name} 文件必须是普通文件"))
    if path.stat().st_size > 16385:
        raise ConfigError(tr(f"The {name} file is too large", f"{name} 文件过大"))
    return validate_token_text(path.read_text(encoding="utf-8"), name)
