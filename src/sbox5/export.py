# Copyright (C) 2026 Bosco1262
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import base64
import json
import os
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlencode

from .config import certificate_profile, profile_certificate_path
from .errors import ConfigError
from .i18n import tr
from .models import Secrets, Settings
from .util import atomic_json, atomic_text, available, format_host_port, run


def _profile_for(settings: Settings, protocol: str):
    profile_id = settings.protocols[protocol].tls_profile
    if not profile_id:
        return None
    return certificate_profile(settings, profile_id)


def _certificate_for(settings: Settings, profile, certificate: dict[str, Any], certificates: dict[str, dict[str, Any]] | None):
    if profile is None:
        return certificate
    if certificates and profile.id in certificates:
        return certificates[profile.id]
    return certificate


def _client_tls(profile, certificate_pem: str, alpn: list[str]) -> dict[str, Any]:
    tls: dict[str, Any] = {
        "enabled": True,
        "server_name": profile.server_name,
        "alpn": alpn,
    }
    if profile.mode != "acme":
        tls["certificate"] = certificate_pem
    return tls


def build_client_outbounds(
    settings: Settings,
    secrets: Secrets,
    certificate_pem: str,
    certificate_pems: dict[str, str] | None = None,
    argo_host: str = "",
) -> list[dict[str, Any]]:
    host = settings.host
    certificate_pems = certificate_pems or {}
    inbounds: list[dict[str, Any]] = []
    resolved_argo_host = argo_host or settings.argo.hostname
    if settings.protocols["vless"].enabled:
        inbounds.append({
            "type": "vless",
            "tag": "vless",
            "server": host,
            "server_port": settings.ports.vless,
            "uuid": secrets.vless_uuid,
            "flow": "xtls-rprx-vision",
            "tls": {
                "enabled": True,
                "server_name": settings.reality_sni,
                "utls": {"enabled": True, "fingerprint": "chrome"},
                "reality": {"enabled": True, "public_key": secrets.reality_public_key, "short_id": secrets.reality_short_id},
            },
        })
    if settings.protocols["vmess"].enabled:
        cdn = settings.cdn.vmess
        vmess: dict[str, Any] = {
            "type": "vmess",
            "tag": "vmess",
            "server": cdn.address if cdn.enabled else host,
            "server_port": cdn.port if cdn.enabled else settings.ports.vmess,
            "uuid": secrets.vmess_uuid,
            "security": "auto",
            "alter_id": 0,
            "transport": {"type": "ws", "path": secrets.vmess_path, "max_early_data": 0},
        }
        if cdn.enabled:
            vmess["transport"]["headers"] = {"Host": cdn.host}
            vmess["tls"] = {"enabled": True, "server_name": cdn.sni}
        else:
            profile = _profile_for(settings, "vmess")
            if profile is not None:
                pem = certificate_pems.get(profile.id, certificate_pem if profile.id == "default" else "")
                vmess["tls"] = _client_tls(profile, pem, ["h2", "http/1.1"])
        inbounds.append(vmess)
        if settings.argo.enabled and resolved_argo_host:
            argo_cdn = settings.cdn.argo
            inbounds.append({
                "type": "vmess",
                "tag": "vmess-argo",
                "server": argo_cdn.address if argo_cdn.enabled else resolved_argo_host,
                "server_port": argo_cdn.port if argo_cdn.enabled else 443,
                "uuid": secrets.vmess_uuid,
                "security": "auto",
                "alter_id": 0,
                "tls": {"enabled": True, "server_name": argo_cdn.sni if argo_cdn.enabled else resolved_argo_host},
                "transport": {
                    "type": "ws",
                    "path": secrets.vmess_path,
                    "headers": {"Host": argo_cdn.host if argo_cdn.enabled else resolved_argo_host},
                    "max_early_data": 0,
                },
            })
    if settings.protocols["hysteria2"].enabled:
        profile = _profile_for(settings, "hysteria2")
        pem = certificate_pems.get(profile.id, certificate_pem if profile.id == "default" else "")
        hysteria2: dict[str, Any] = {
            "type": "hysteria2",
            "tag": "hysteria2",
            "server": host,
            "password": secrets.hysteria2_password,
            "obfs": {"type": "salamander", "password": secrets.hysteria2_obfs_password},
            "tls": _client_tls(profile, pem, ["h3"]),
        }
        hopping = settings.port_hopping.get("hysteria2")
        if hopping:
            hysteria2["server_ports"] = [hopping]
            hysteria2["hop_interval"] = "30s"
        else:
            hysteria2["server_port"] = settings.ports.hysteria2
        inbounds.append(hysteria2)
    if settings.protocols["tuic"].enabled:
        profile = _profile_for(settings, "tuic")
        pem = certificate_pems.get(profile.id, certificate_pem if profile.id == "default" else "")
        tuic: dict[str, Any] = {
            "type": "tuic",
            "tag": "tuic",
            "server": host,
            "server_port": settings.ports.tuic,
            "uuid": secrets.tuic_uuid,
            "password": secrets.tuic_password,
            "congestion_control": "bbr",
            "udp_relay_mode": "native",
            "zero_rtt_handshake": False,
            "tls": _client_tls(profile, pem, ["h3"]),
        }
        inbounds.append(tuic)
    if settings.protocols["anytls"].enabled:
        profile = _profile_for(settings, "anytls")
        pem = certificate_pems.get(profile.id, certificate_pem if profile.id == "default" else "")
        inbounds.append({
            "type": "anytls",
            "tag": "anytls",
            "server": host,
            "server_port": settings.ports.anytls,
            "password": secrets.anytls_password,
            "idle_session_check_interval": "30s",
            "idle_session_timeout": "30s",
            "min_idle_session": 0,
            "tls": _client_tls(profile, pem, ["h2", "http/1.1"]),
        })
    return inbounds


def build_singbox_client(
    settings: Settings,
    secrets: Secrets,
    certificate_pem: str,
    certificate_pems: dict[str, str] | None = None,
    argo_host: str = "",
) -> dict[str, Any]:
    outbounds = build_client_outbounds(settings, secrets, certificate_pem, certificate_pems, argo_host)
    final = outbounds[0]["tag"] if outbounds else "direct"
    return {
        "log": {"level": "info", "timestamp": True},
        "inbounds": [{"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 1080}],
        "outbounds": outbounds + [{"type": "direct", "tag": "direct"}],
        "route": {"final": final, "auto_detect_interface": True},
    }


def build_tun_client(
    settings: Settings,
    secrets: Secrets,
    certificate_pem: str,
    certificate_pems: dict[str, str] | None = None,
    argo_host: str = "",
    platform: str = "sfa",
) -> dict[str, Any]:
    outbounds = build_client_outbounds(settings, secrets, certificate_pem, certificate_pems, argo_host)
    final = outbounds[0]["tag"] if outbounds else "direct"
    stack = "system" if platform == "sfi" else "mixed"
    return {
        "log": {"level": "info", "timestamp": True},
        "dns": {"servers": [{"type": "local", "tag": "local"}], "final": "local"},
        "inbounds": [{
            "type": "tun",
            "tag": "tun-in",
            "address": ["172.19.0.1/30", "fdfe:dcba:9876::1/126"],
            "mtu": 9000,
            "auto_route": True,
            "strict_route": False,
            "stack": stack,
        }],
        "outbounds": outbounds + [{"type": "direct", "tag": "direct"}],
        "route": {
            "rules": [{"action": "sniff"}],
            "final": final,
            "default_domain_resolver": "local",
            "auto_detect_interface": True,
        },
    }


def _url(scheme: str, userinfo: str, host: str, port: int | str, query: dict[str, Any], name: str) -> str:
    authority = format_host_port(host, port)  # type: ignore[arg-type]
    return f"{scheme}://{userinfo}@{authority}?{urlencode(query)}#{quote(name)}"


def _tls_query(settings: Settings, profile, certificate: dict[str, Any], certificates: dict[str, dict[str, Any]] | None) -> dict[str, Any]:
    metadata = _certificate_for(settings, profile, certificate, certificates)
    query: dict[str, Any] = {"sni": profile.server_name}
    if profile.mode != "acme" and metadata.get("certificate_sha256"):
        query["pinSHA256"] = metadata["certificate_sha256"]
    return query


def build_share_links(
    settings: Settings,
    secrets: Secrets,
    certificate: dict[str, Any],
    certificates: dict[str, dict[str, Any]] | None = None,
    argo_host: str = "",
) -> dict[str, str]:
    host = settings.host
    resolved_argo_host = argo_host or settings.argo.hostname
    links: dict[str, str] = {}
    if settings.protocols["vless"].enabled:
        links["vless"] = _url("vless", secrets.vless_uuid, host, settings.ports.vless, {
            "encryption": "none", "flow": "xtls-rprx-vision", "security": "reality", "sni": settings.reality_sni,
            "fp": "chrome", "pbk": secrets.reality_public_key, "sid": secrets.reality_short_id, "type": "tcp",
        }, "sbox5-vless")
    if settings.protocols["vmess"].enabled:
        cdn = settings.cdn.vmess
        vmess = {
            "v": "2", "ps": "sbox5-vmess", "add": cdn.address if cdn.enabled else host,
            "port": str(cdn.port if cdn.enabled else settings.ports.vmess),
            "id": secrets.vmess_uuid, "aid": "0", "scy": "auto", "net": "ws", "type": "none",
            "host": cdn.host if cdn.enabled else "", "path": secrets.vmess_path,
            "tls": "tls" if cdn.enabled else "",
        }
        if cdn.enabled:
            vmess["sni"] = cdn.sni
        else:
            profile = _profile_for(settings, "vmess")
            if profile is not None:
                vmess["tls"] = "tls"
                vmess["sni"] = profile.server_name
                vmess["host"] = profile.server_name
        links["vmess"] = "vmess://" + base64.b64encode(json.dumps(vmess, ensure_ascii=False, separators=(",", ":")).encode()).decode()
        if settings.argo.enabled and resolved_argo_host:
            argo_cdn = settings.cdn.argo
            argo_vmess = {
                **vmess, "ps": "sbox5-vmess-argo",
                "add": argo_cdn.address if argo_cdn.enabled else resolved_argo_host,
                "port": str(argo_cdn.port if argo_cdn.enabled else 443),
                "host": argo_cdn.host if argo_cdn.enabled else resolved_argo_host,
                "sni": argo_cdn.sni if argo_cdn.enabled else resolved_argo_host,
                "tls": "tls",
            }
            links["vmess-argo"] = "vmess://" + base64.b64encode(json.dumps(argo_vmess, ensure_ascii=False, separators=(",", ":")).encode()).decode()
    if settings.protocols["hysteria2"].enabled:
        profile = _profile_for(settings, "hysteria2")
        query = {
            **_tls_query(settings, profile, certificate, certificates),
            "insecure": "0", "obfs": "salamander", "obfs-password": secrets.hysteria2_obfs_password,
        }
        hysteria2_port: int | str = settings.ports.hysteria2
        if settings.port_hopping.get("hysteria2"):
            start, end = settings.port_hopping["hysteria2"].split(":", 1)
            hysteria2_port = f"{settings.ports.hysteria2},{start}-{end}"
        links["hysteria2"] = _url(
            "hysteria2", quote(secrets.hysteria2_password, safe=""), host, hysteria2_port, query, "sbox5-hysteria2",
        )
    if settings.protocols["tuic"].enabled:
        profile = _profile_for(settings, "tuic")
        query = {
            **_tls_query(settings, profile, certificate, certificates),
            "allow_insecure": "0", "alpn": "h3", "congestion_control": "bbr", "udp_relay_mode": "native",
        }
        links["tuic"] = _url(
            "tuic", f"{secrets.tuic_uuid}:{quote(secrets.tuic_password, safe='')}", host, settings.ports.tuic, query, "sbox5-tuic",
        )
    if settings.protocols["anytls"].enabled:
        profile = _profile_for(settings, "anytls")
        query = {
            **_tls_query(settings, profile, certificate, certificates),
            "insecure": "0", "alpn": "h2,http/1.1",
        }
        links["anytls"] = _url(
            "anytls", quote(secrets.anytls_password, safe=""), host, settings.ports.anytls, query, "sbox5-anytls",
        )
    return links


def _mihomo_tls(profile, certificate: dict[str, Any]) -> dict[str, Any]:
    result: dict[str, Any] = {"sni": profile.server_name, "skip-cert-verify": False}
    if profile.mode != "acme" and certificate.get("certificate_fingerprint"):
        result["fingerprint"] = certificate["certificate_fingerprint"]
    return result


def _mihomo_certificate(settings: Settings, profile, certificate: dict[str, Any], certificates: dict[str, dict[str, Any]] | None) -> dict[str, Any]:
    return _certificate_for(settings, profile, certificate, certificates)


def build_mihomo(
    settings: Settings,
    secrets: Secrets,
    certificate: dict[str, Any],
    certificates: dict[str, dict[str, Any]] | None = None,
    argo_host: str = "",
) -> dict[str, Any]:
    host = settings.host
    resolved_argo_host = argo_host or settings.argo.hostname
    proxies: list[dict[str, Any]] = []
    if settings.protocols["vless"].enabled:
        proxies.append({
            "name": "sbox5-vless", "type": "vless", "server": host, "port": settings.ports.vless,
            "uuid": secrets.vless_uuid, "network": "tcp", "udp": True, "tls": True, "flow": "xtls-rprx-vision",
            "servername": settings.reality_sni, "client-fingerprint": "chrome",
            "reality-opts": {"public-key": secrets.reality_public_key, "short-id": secrets.reality_short_id},
        })
    if settings.protocols["vmess"].enabled:
        cdn = settings.cdn.vmess
        vmess: dict[str, Any] = {
            "name": "sbox5-vmess", "type": "vmess",
            "server": cdn.address if cdn.enabled else host,
            "port": cdn.port if cdn.enabled else settings.ports.vmess,
            "uuid": secrets.vmess_uuid, "alterId": 0, "cipher": "auto", "network": "ws", "udp": True,
            "ws-opts": {"path": secrets.vmess_path},
        }
        if cdn.enabled:
            vmess["tls"] = True
            vmess["servername"] = cdn.sni
            vmess["skip-cert-verify"] = False
            vmess["ws-opts"]["headers"] = {"Host": cdn.host}
        else:
            profile = _profile_for(settings, "vmess")
            if profile is not None:
                metadata = _mihomo_certificate(settings, profile, certificate, certificates)
                vmess.update({
                    "tls": True, "servername": profile.server_name, "skip-cert-verify": False,
                    **({"fingerprint": metadata["certificate_fingerprint"]} if profile.mode != "acme" and metadata.get("certificate_fingerprint") else {}),
                })
        proxies.append(vmess)
        if settings.argo.enabled and resolved_argo_host:
            argo_cdn = settings.cdn.argo
            proxies.append({
                "name": "sbox5-vmess-argo", "type": "vmess",
                "server": argo_cdn.address if argo_cdn.enabled else resolved_argo_host,
                "port": argo_cdn.port if argo_cdn.enabled else 443,
                "uuid": secrets.vmess_uuid, "alterId": 0, "cipher": "auto", "network": "ws", "udp": True,
                "tls": True,
                "servername": argo_cdn.sni if argo_cdn.enabled else resolved_argo_host,
                "skip-cert-verify": False,
                "ws-opts": {
                    "path": secrets.vmess_path,
                    "headers": {"Host": argo_cdn.host if argo_cdn.enabled else resolved_argo_host},
                },
            })
    if settings.protocols["hysteria2"].enabled:
        profile = _profile_for(settings, "hysteria2")
        metadata = _mihomo_certificate(settings, profile, certificate, certificates)
        hysteria2: dict[str, Any] = {
            "name": "sbox5-hysteria2", "type": "hysteria2", "server": host, "port": settings.ports.hysteria2,
            "password": secrets.hysteria2_password, "obfs": "salamander", "obfs-password": secrets.hysteria2_obfs_password,
            "alpn": ["h3"], **_mihomo_tls(profile, metadata),
        }
        if settings.port_hopping.get("hysteria2"):
            start, end = settings.port_hopping["hysteria2"].split(":", 1)
            hysteria2["ports"] = f"{start}-{end}"
            hysteria2["hop-interval"] = 30
        proxies.append(hysteria2)
    if settings.protocols["tuic"].enabled:
        profile = _profile_for(settings, "tuic")
        metadata = _mihomo_certificate(settings, profile, certificate, certificates)
        proxies.append({
            "name": "sbox5-tuic", "type": "tuic", "server": host, "port": settings.ports.tuic,
            "uuid": secrets.tuic_uuid, "password": secrets.tuic_password, "congestion-controller": "bbr",
            "udp-relay-mode": "native", "reduce-rtt": False, "alpn": ["h3"], **_mihomo_tls(profile, metadata),
        })
    if settings.protocols["anytls"].enabled:
        profile = _profile_for(settings, "anytls")
        metadata = _mihomo_certificate(settings, profile, certificate, certificates)
        proxies.append({
            "name": "sbox5-anytls", "type": "anytls", "server": host, "port": settings.ports.anytls,
            "password": secrets.anytls_password, "udp": True, "alpn": ["h2", "http/1.1"],
            "client-fingerprint": "chrome", **_mihomo_tls(profile, metadata),
        })
    names = [proxy["name"] for proxy in proxies]
    groups = []
    if names:
        groups = [
            {"name": "sbox5-select", "type": "select", "proxies": ["sbox5-auto", *names]},
            {"name": "sbox5-auto", "type": "url-test", "proxies": names, "url": "https://www.gstatic.com/generate_204", "interval": 300},
        ]
    return {"proxies": proxies, "proxy-groups": groups}


def yaml_dump(value: Any, indent: int = 0) -> str:
    prefix = " " * indent
    if isinstance(value, dict):
        lines: list[str] = []
        for key, item in value.items():
            encoded_key = json.dumps(str(key), ensure_ascii=False)
            if isinstance(item, (dict, list)):
                lines.append(f"{prefix}{encoded_key}:")
                lines.append(yaml_dump(item, indent + 2))
            else:
                lines.append(f"{prefix}{encoded_key}: {json.dumps(item, ensure_ascii=False)}")
        return "\n".join(lines)
    if isinstance(value, list):
        lines = []
        for item in value:
            if isinstance(item, (dict, list)):
                lines.append(f"{prefix}-")
                lines.append(yaml_dump(item, indent + 2))
            else:
                lines.append(f"{prefix}- {json.dumps(item, ensure_ascii=False)}")
        return "\n".join(lines)
    return prefix + json.dumps(value, ensure_ascii=False)


def export_nodes(
    settings: Settings,
    secrets: Secrets,
    certificate_path: Path,
    certificate: dict[str, Any],
    destination: Path,
    certificates: dict[str, dict[str, Any]] | None = None,
    argo_host: str = "",
) -> dict[str, Any]:
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(destination, 0o700)
    certificates = certificates or {"default": certificate}
    certificate_pems: dict[str, str] = {}
    certificate_files: set[str] = set()
    for profile in settings.active_certificate_profiles():
        if profile.mode == "acme":
            continue
        path = profile_certificate_path(profile)
        if path.is_file():
            certificate_pems[profile.id] = path.read_text(encoding="ascii")
            certificate_files.add("certificate.pem" if profile.id == "default" else f"certificate-{profile.id}.pem")
    if "default" not in certificate_pems and certificate_path.is_file():
        default_profile = next(
            (profile for profile in settings.active_certificate_profiles() if profile.id == "default"),
            None,
        )
        if default_profile is not None and default_profile.mode != "acme":
            certificate_pems["default"] = certificate_path.read_text(encoding="ascii")
            certificate_files.add("certificate.pem")
    for profile in settings.active_certificate_profiles():
        if profile.mode != "acme" and profile.id not in certificate_pems:
            raise ConfigError(tr(
                f"The certificate file for profile {profile.id} is missing",
                f"证书配置 {profile.id} 的证书文件缺失",
            ))
    default_pem = certificate_pems.get("default", "")
    resolved_argo_host = argo_host or settings.argo.hostname
    links = build_share_links(settings, secrets, certificate, certificates, resolved_argo_host)
    qr_files: list[str] = []
    if available("qrencode"):
        qr_files = [f"{protocol}.png" for protocol in links]
    expected = {
        "links.txt", "subscription-base64.txt", "sing-box-client.json", "sfa.json", "sfi.json", "sfw.json",
        "mihomo.yaml", "metadata.json", *qr_files, *certificate_files,
    }
    for path in list(destination.iterdir()):
        if path.name not in expected:
            if path.is_symlink() or not path.is_file():
                raise ConfigError(tr(f"The export directory contains an unknown entry; refusing to clean it: {path}", f"导出目录包含未知项目，拒绝清理：{path}"))
            path.unlink()
    raw_subscription = "\n".join(links.values()) + "\n"
    atomic_text(destination / "links.txt", raw_subscription, 0o600)
    atomic_text(destination / "subscription-base64.txt", base64.b64encode(raw_subscription.encode()).decode() + "\n", 0o600)
    atomic_json(
        destination / "sing-box-client.json",
        build_singbox_client(settings, secrets, default_pem, certificate_pems, resolved_argo_host),
        0o600,
    )
    for platform in ("sfa", "sfi", "sfw"):
        atomic_json(
            destination / f"{platform}.json",
            build_tun_client(settings, secrets, default_pem, certificate_pems, resolved_argo_host, platform),
            0o600,
        )
    atomic_text(destination / "mihomo.yaml", yaml_dump(build_mihomo(settings, secrets, certificate, certificates, resolved_argo_host)) + "\n", 0o600)
    for profile in settings.active_certificate_profiles():
        if profile.mode == "acme":
            continue
        pem = certificate_pems.get(profile.id, "")
        if not pem:
            continue
        name = "certificate.pem" if profile.id == "default" else f"certificate-{profile.id}.pem"
        atomic_text(destination / name, pem, 0o600)
    if qr_files:
        for protocol, link in links.items():
            output = destination / f"{protocol}.png"
            run(["qrencode", "-t", "PNG", "-o", str(output)], input_text=link, timeout=30)
            os.chmod(output, 0o600)
    warnings = [
        tr("All exported files contain credentials and must be treated as secrets; do not upload them to public subscription services.", "所有导出文件都含凭证，应视为秘密，不要上传到公共订阅服务。"),
        tr("Generic links in self-signed mode rely on client support for pinSHA256; use the full client configuration when unsupported.", "自签模式的通用链接依赖客户端支持 pinSHA256；不支持时请使用完整客户端配置。"),
        tr("Mihomo in self-signed mode uses the full certificate SHA256 fingerprint instead of skip-cert-verify.", "Mihomo 自签模式使用完整证书 SHA256 指纹，不使用 skip-cert-verify。"),
        tr("TUIC has no standard port-range URI field. A server-side UDP range is reachable, but the client must be configured with a specific port.", "TUIC 没有标准的端口范围 URI 字段。服务端 UDP 范围可达，但客户端仍需配置具体端口。"),
    ]
    metadata = {
        "qr_files": qr_files,
        "tls_verification": "certificate-pin" if any(profile.mode != "acme" for profile in settings.active_certificate_profiles()) else "public-ca",
        "warnings": warnings,
        "certificate": certificate,
        "certificates": certificates,
    }
    if settings.argo.enabled:
        if not resolved_argo_host:
            metadata["warnings"].append(tr(
                "Argo is enabled but its public hostname is not available yet; the Argo node was omitted from exports.",
                "Argo 已启用但公网域名尚不可用；导出中已省略 Argo 节点。",
            ))
        else:
            metadata["warnings"].append(tr(f"Argo only provides a VMess-WebSocket fallback entry; the Cloudflare ingress must point to http://127.0.0.1:{settings.argo.local_port} and match the selected path.", f"Argo 仅提供 VMess-WebSocket 备用入口；Cloudflare 后台 ingress 必须指向 http://127.0.0.1:{settings.argo.local_port} 并匹配所选路径。"))
    atomic_json(destination / "metadata.json", metadata, 0o600)
    return {"links": links, "files": sorted(path.name for path in destination.iterdir() if path.is_file()), "warnings": metadata["warnings"]}
