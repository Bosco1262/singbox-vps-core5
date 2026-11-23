# Copyright (C) 2026 Bosco1262
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import platform
from pathlib import Path
from typing import Any

from .certificates import certificate_metadata
from .config import profile_certificate_path
from .errors import SBox5Error
from .i18n import tr
from .installer import (
    ARGO_STATE_PATH,
    CORE_STATE_PATH,
    DDNS_STATE_PATH,
    FIREWALL_STATE_PATH,
    STATE_PATH,
    SUBSCRIPTION_TOKEN_PATH,
)
from .models import Secrets, Settings
from .network import geolocation_summary, summary as network_summary
from .services import init_backend, service_exists, service_state_text
from .system import architecture
from .util import load_json, run


def _read_json(path: Path) -> dict[str, Any]:
    if not path.is_file() or path.is_symlink():
        return {}
    try:
        value = load_json(path)
    except (OSError, ValueError):
        return {}
    return value if isinstance(value, dict) else {}


def system_info(geo: bool = False) -> dict[str, Any]:
    release: dict[str, str] = {}
    if Path("/etc/os-release").is_file():
        for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
            key, separator, value = line.partition("=")
            if separator:
                release[key] = value.strip().strip('"')
    bbr = None
    try:
        bbr = run(["sysctl", "-n", "net.ipv4.tcp_congestion_control"], check=False)
    except (OSError, SBox5Error):
        pass
    try:
        arch = architecture()
    except Exception:
        arch = platform.machine()
    return {
        "distribution": release.get("PRETTY_NAME", release.get("ID", "unknown")),
        "kernel": platform.release(),
        "architecture": arch,
        "init": init_backend(),
        "bbr": bbr.stdout.strip() if bbr is not None and bbr.returncode == 0 else "unavailable",
        "addresses": network_summary(),
        "geolocation": geolocation_summary() if geo else {},
    }


def status_data(settings: Settings, secrets: Secrets, geo: bool = False) -> dict[str, Any]:
    state = _read_json(STATE_PATH)
    argo = _read_json(ARGO_STATE_PATH)
    ddns = _read_json(DDNS_STATE_PATH)
    firewall = _read_json(FIREWALL_STATE_PATH)
    core = _read_json(CORE_STATE_PATH)
    certificates: list[dict[str, Any]] = []
    for profile in settings.active_certificate_profiles():
        certificate = profile_certificate_path(profile)
        metadata: dict[str, Any] = {}
        if certificate.is_file():
            try:
                metadata = certificate_metadata(certificate)
            except Exception as exc:
                metadata = {"error": str(exc)}
        certificates.append({
            "id": profile.id,
            "mode": profile.mode,
            "challenge": profile.challenge,
            "not_after": metadata.get("not_after", ""),
            "error": metadata.get("error", ""),
        })
    services = {}
    for name in ("sbox5.service", "sbox5-argo.service", "sbox5-ddns.timer", "sbox5-firewall.service", "sbox5-subscription.service"):
        services[name] = service_state_text(name) if service_exists(name) else "not-installed"
    protocols = {}
    for name, protocol in settings.protocols.items():
        protocols[name] = {
            "enabled": protocol.enabled,
            "port": settings.ports.as_dict().get(name, 0),
            "tls_profile": protocol.tls_profile,
        }
    return {
        "version": state.get("version", ""),
        "system": system_info(geo=geo),
        "core": core or state.get("components", {}).get("sing-box", {}),
        "protocols": protocols,
        "certificates": certificates,
        "argo": {
            "enabled": settings.argo.enabled,
            "mode": settings.argo.mode,
            "hostname": settings.argo.hostname,
            "url": argo.get("quick_url", ""),
            "service": services["sbox5-argo.service"],
        },
        "warp": {
            "enabled": settings.warp.enabled,
            "credential": secrets.warp.public_state(),
        },
        "routing": {
            "outbound": "socks5" if settings.routing.socks5.enabled else "direct",
            "rules": len(settings.routing.routes),
            "rulesets": len(settings.routing.rule_sets),
        },
        "subscription": {
            "enabled": settings.subscription.enabled,
            "bind": settings.subscription.bind,
            "port": settings.subscription.port,
            "token_present": SUBSCRIPTION_TOKEN_PATH.is_file(),
            "service": services["sbox5-subscription.service"],
        },
        "ddns": {
            "enabled": settings.ddns.enabled,
            "record": settings.ddns.record,
            "last": ddns,
            "service": services["sbox5-ddns.timer"],
        },
        "firewall": {
            "backend": firewall.get("backend", ""),
            "owned": len(firewall.get("owned", [])),
            "service": services["sbox5-firewall.service"],
        },
        "services": services,
    }


def render_text(data: dict[str, Any]) -> str:
    system = data["system"]
    addresses = system.get("addresses", {})
    lines = [
        tr("== sbox5 status ==", "== sbox5 状态 =="),
        tr("System: ", "系统：") + str(system.get("distribution", "")),
        tr("Kernel: ", "内核：") + str(system.get("kernel", "")) + "  " + tr("Arch: ", "架构：") + str(system.get("architecture", "")),
        tr("Init: ", "Init：") + str(system.get("init", "")) + "  " + tr("BBR: ", "BBR：") + str(system.get("bbr", "")),
        tr("Core: ", "内核：") + str(data.get("core", {}).get("version", "") if isinstance(data.get("core"), dict) else data.get("core", "")),
        "IPv4: " + (", ".join(addresses.get("ipv4", [])) or "-"),
        "IPv6: " + (", ".join(addresses.get("ipv6", [])) or "-"),
    ]
    for family, label in (("ipv4", "IPv4"), ("ipv6", "IPv6")):
        for item in system.get("geolocation", {}).get(family, []):
            location = ", ".join(value for value in (item.get("city", ""), item.get("region", ""), item.get("country", "")) if value)
            detail = f"{item.get('address', '')} {location}".strip()
            if item.get("org"):
                detail += f" ({item['org']})"
            lines.append(f"Geo {label}: {detail}")
    lines.extend([
        "",
        tr("Protocols", "协议"),
    ])
    for name, protocol in data["protocols"].items():
        status = tr("on", "开") if protocol["enabled"] else tr("off", "关")
        tls = f" tls={protocol['tls_profile']}" if protocol["tls_profile"] else ""
        lines.append(f"  {name}: {status} port={protocol['port']}{tls}")
    lines.extend(["", tr("Certificates", "证书")])
    if data["certificates"]:
        for certificate in data["certificates"]:
            suffix = certificate.get("not_after") or certificate.get("error") or ""
            lines.append(f"  {certificate['id']}: {certificate['mode']}/{certificate['challenge']} {suffix}")
    else:
        lines.append(tr("  (none)", "  （无）"))
    lines.extend(["", tr("Services", "服务")])
    for name, state in data["services"].items():
        lines.append(f"  {name}: {state}")
    lines.extend([
        "",
        tr("Argo: ", "Argo：") + f"{data['argo']['mode']} {data['argo']['service']} {data['argo']['url']}".strip(),
        tr("WARP: ", "WARP：") + json_dump(data["warp"]["credential"]),
        tr("Routing: ", "分流：") + f"{data['routing']['outbound']} rules={data['routing']['rules']} rulesets={data['routing']['rulesets']}",
        tr("Subscription: ", "订阅：") + f"{data['subscription']['bind']}:{data['subscription']['port']} {data['subscription']['service']}",
        tr("DDNS: ", "DDNS：") + f"{data['ddns']['record']} {data['ddns']['service']}",
        tr("Firewall: ", "防火墙：") + f"{data['firewall']['backend']} owned={data['firewall']['owned']} {data['firewall']['service']}",
    ])
    return "\n".join(lines)


def json_dump(value: Any) -> str:
    import json
    return json.dumps(value, ensure_ascii=False, sort_keys=True)
