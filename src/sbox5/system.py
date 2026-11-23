# Copyright (C) 2026 Bosco1262
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import os
from pathlib import Path
import platform
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


def preflight() -> None:
    require_linux_root()
    if not Path("/etc/os-release").is_file() or not Path("/proc/1/comm").is_file():
        raise ConfigError(tr("Only systemd Linux is supported", "仅支持 systemd Linux"))
    release = {}
    for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
        key, separator, value = line.partition("=")
        if separator:
            release[key] = value.strip().strip('"')
    distro = release.get("ID", "")
    version = release.get("VERSION_ID", "")
    try:
        numbers = tuple(int(part) for part in version.split("."))
    except ValueError as exc:
        raise ConfigError(tr("Unable to identify the system version", "无法识别系统版本")) from exc
    supported = (distro == "debian" and numbers >= (12,)) or (distro == "ubuntu" and numbers >= (22, 4))
    if not supported:
        raise ConfigError(tr("The initial release supports only Debian 12+ or Ubuntu 22.04+", "首版仅支持 Debian 12+ 或 Ubuntu 22.04+"))
    if Path("/proc/1/comm").read_text(encoding="utf-8").strip() != "systemd" or not available("systemctl"):
        raise ConfigError(tr("PID 1 must be systemd", "PID 1 必须是 systemd"))
    if available("systemd-detect-virt"):
        result = run(["systemd-detect-virt"], check=False)
        virtualization = result.stdout.strip()
        if virtualization not in ("", "none", "kvm"):
            raise ConfigError(tr(f"The initial release supports only KVM or VPS environments with an independent kernel; the current one is {virtualization}", f"首版仅支持 KVM 或独立内核 VPS，当前环境为 {virtualization}"))
    if not available("apt-get") or not available("dpkg-query"):
        raise ConfigError(tr("The official APT package manager was not found", "找不到系统官方 APT 包管理器"))
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
    if occupied:
        raise ConfigError(tr("The following ports are already in use: ", "以下端口已被占用：") + tr(", ", "、").join(occupied))


def _package_installed(name: str) -> bool:
    result = run(["dpkg-query", "-W", "-f=${Status}", name], check=False)
    return result.returncode == 0 and result.stdout.strip() == "install ok installed"


def ensure_packages(settings: Settings) -> dict[str, Any]:
    packages = ["ca-certificates", "python3", "openssl", "nftables", "iptables", "qrencode"]
    missing = [name for name in packages if not _package_installed(name)]
    if missing:
        environment = dict(os.environ)
        environment["DEBIAN_FRONTEND"] = "noninteractive"
        run(["apt-get", "update"], timeout=600, env=environment)
        run(["apt-get", "install", "-y", "--no-install-recommends", *missing], timeout=900, env=environment)
    return {
        "installed_by_project": missing,
        "upgraded_by_project": [],
        "removal_policy": "keep",
        "note": tr("APT dependencies pulled in automatically are never downgraded or removed automatically", "APT 自动升级的依赖不自动降级或删除"),
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
