# Copyright (C) 2026 Bosco1262
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import base64
import json
import os
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlencode

from .errors import ConfigError
from .i18n import tr
from .models import Secrets, Settings
from .util import atomic_json, atomic_text, available, format_host_port, run


def _client_tls(settings: Settings, certificate_pem: str, alpn: list[str]) -> dict[str, Any]:
    tls: dict[str, Any] = {"enabled": True, "server_name": settings.tls_server_name, "alpn": alpn}
    if settings.certificate_mode == "self-signed":
        tls["certificate"] = certificate_pem
    return tls


def build_client_outbounds(settings: Settings, secrets: Secrets, certificate_pem: str) -> list[dict[str, Any]]:
    host = settings.host
    outbounds: list[dict[str, Any]] = [
        {
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
        },
        {
            "type": "vmess",
            "tag": "vmess",
            "server": host,
            "server_port": settings.ports.vmess,
            "uuid": secrets.vmess_uuid,
            "security": "auto",
            "alter_id": 0,
            "transport": {"type": "ws", "path": secrets.vmess_path, "max_early_data": 0},
        },
    ]
    if settings.argo.enabled:
        outbounds.append({
            "type": "vmess",
            "tag": "vmess-argo",
            "server": settings.argo.hostname,
            "server_port": 443,
            "uuid": secrets.vmess_uuid,
            "security": "auto",
            "alter_id": 0,
            "tls": {"enabled": True, "server_name": settings.argo.hostname},
            "transport": {"type": "ws", "path": secrets.vmess_path, "headers": {"Host": settings.argo.hostname}, "max_early_data": 0},
        })
    hysteria2: dict[str, Any] = {
        "type": "hysteria2",
        "tag": "hysteria2",
        "server": host,
        "password": secrets.hysteria2_password,
        "obfs": {"type": "salamander", "password": secrets.hysteria2_obfs_password},
        "tls": _client_tls(settings, certificate_pem, ["h3"]),
    }
    hopping = settings.port_hopping.get("hysteria2")
    if hopping:
        hysteria2["server_ports"] = [hopping]
        hysteria2["hop_interval"] = "30s"
    else:
        hysteria2["server_port"] = settings.ports.hysteria2
    outbounds.append(hysteria2)
    tuic: dict[str, Any] = {
        "type": "tuic",
        "tag": "tuic",
        "server": host,
        "uuid": secrets.tuic_uuid,
        "password": secrets.tuic_password,
        "congestion_control": "bbr",
        "udp_relay_mode": "native",
        "zero_rtt_handshake": False,
        "tls": _client_tls(settings, certificate_pem, ["h3"]),
    }
    tuic["server_port"] = settings.ports.tuic
    outbounds.append(tuic)
    outbounds.append({
        "type": "anytls",
        "tag": "anytls",
        "server": host,
        "server_port": settings.ports.anytls,
        "password": secrets.anytls_password,
        "idle_session_check_interval": "30s",
        "idle_session_timeout": "30s",
        "min_idle_session": 0,
        "tls": _client_tls(settings, certificate_pem, ["h2", "http/1.1"]),
    })
    return outbounds


def build_singbox_client(settings: Settings, secrets: Secrets, certificate_pem: str) -> dict[str, Any]:
    return {
        "log": {"level": "info", "timestamp": True},
        "inbounds": [{"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 1080}],
        "outbounds": build_client_outbounds(settings, secrets, certificate_pem) + [{"type": "direct", "tag": "direct"}],
        "route": {"final": "vless", "auto_detect_interface": True},
    }


def _url(scheme: str, userinfo: str, host: str, port: int, query: dict[str, Any], name: str) -> str:
    authority = format_host_port(host, port)
    return f"{scheme}://{userinfo}@{authority}?{urlencode(query)}#{quote(name)}"


def build_share_links(settings: Settings, secrets: Secrets, certificate: dict[str, str]) -> dict[str, str]:
    host = settings.host
    tls_query: dict[str, Any] = {"sni": settings.tls_server_name}
    if settings.certificate_mode == "self-signed":
        tls_query["pinSHA256"] = certificate["certificate_sha256"]
    vmess = {
        "v": "2", "ps": "sbox5-vmess", "add": host, "port": str(settings.ports.vmess),
        "id": secrets.vmess_uuid, "aid": "0", "scy": "auto", "net": "ws", "type": "none",
        "host": "", "path": secrets.vmess_path, "tls": "",
    }
    links = {
        "vless": _url("vless", secrets.vless_uuid, host, settings.ports.vless, {
            "encryption": "none", "flow": "xtls-rprx-vision", "security": "reality", "sni": settings.reality_sni,
            "fp": "chrome", "pbk": secrets.reality_public_key, "sid": secrets.reality_short_id, "type": "tcp",
        }, "sbox5-vless"),
        "vmess": "vmess://" + base64.b64encode(json.dumps(vmess, ensure_ascii=False, separators=(",", ":")).encode()).decode(),
        "hysteria2": _url("hysteria2", quote(secrets.hysteria2_password, safe=""), host, settings.ports.hysteria2, {
            **tls_query, "insecure": "0", "obfs": "salamander", "obfs-password": secrets.hysteria2_obfs_password,
        }, "sbox5-hysteria2"),
        "tuic": _url("tuic", f"{secrets.tuic_uuid}:{quote(secrets.tuic_password, safe='')}", host, settings.ports.tuic, {
            **tls_query, "allow_insecure": "0", "alpn": "h3", "congestion_control": "bbr", "udp_relay_mode": "native",
        }, "sbox5-tuic"),
        "anytls": _url("anytls", quote(secrets.anytls_password, safe=""), host, settings.ports.anytls, {
            **tls_query, "insecure": "0", "alpn": "h2,http/1.1",
        }, "sbox5-anytls"),
    }
    if settings.argo.enabled:
        argo_vmess = {
            **vmess, "ps": "sbox5-vmess-argo", "add": settings.argo.hostname, "port": "443",
            "host": settings.argo.hostname, "tls": "tls",
        }
        links["vmess-argo"] = "vmess://" + base64.b64encode(json.dumps(argo_vmess, ensure_ascii=False, separators=(",", ":")).encode()).decode()
    return links


def _mihomo_tls(settings: Settings, certificate: dict[str, str]) -> dict[str, Any]:
    result: dict[str, Any] = {"sni": settings.tls_server_name, "skip-cert-verify": False}
    if settings.certificate_mode == "self-signed":
        result["fingerprint"] = certificate["certificate_fingerprint"]
    return result


def build_mihomo(settings: Settings, secrets: Secrets, certificate: dict[str, str]) -> dict[str, Any]:
    host = settings.host
    hysteria2: dict[str, Any] = {
        "name": "sbox5-hysteria2", "type": "hysteria2", "server": host, "port": settings.ports.hysteria2,
        "password": secrets.hysteria2_password, "obfs": "salamander", "obfs-password": secrets.hysteria2_obfs_password,
        "alpn": ["h3"], **_mihomo_tls(settings, certificate),
    }
    if settings.port_hopping.get("hysteria2"):
        start, end = settings.port_hopping["hysteria2"].split(":", 1)
        hysteria2["ports"] = f"{start}-{end}"
        hysteria2["hop-interval"] = 30
    proxies = [
        {
            "name": "sbox5-vless", "type": "vless", "server": host, "port": settings.ports.vless,
            "uuid": secrets.vless_uuid, "network": "tcp", "udp": True, "tls": True, "flow": "xtls-rprx-vision",
            "servername": settings.reality_sni, "client-fingerprint": "chrome",
            "reality-opts": {"public-key": secrets.reality_public_key, "short-id": secrets.reality_short_id},
        },
        {
            "name": "sbox5-vmess", "type": "vmess", "server": host, "port": settings.ports.vmess,
            "uuid": secrets.vmess_uuid, "alterId": 0, "cipher": "auto", "network": "ws", "udp": True,
            "ws-opts": {"path": secrets.vmess_path},
        },
        hysteria2,
        {
            "name": "sbox5-tuic", "type": "tuic", "server": host, "port": settings.ports.tuic,
            "uuid": secrets.tuic_uuid, "password": secrets.tuic_password, "congestion-controller": "bbr",
            "udp-relay-mode": "native", "reduce-rtt": False, "alpn": ["h3"], **_mihomo_tls(settings, certificate),
        },
        {
            "name": "sbox5-anytls", "type": "anytls", "server": host, "port": settings.ports.anytls,
            "password": secrets.anytls_password, "udp": True, "alpn": ["h2", "http/1.1"],
            "client-fingerprint": "chrome", **_mihomo_tls(settings, certificate),
        },
    ]
    if settings.argo.enabled:
        proxies.insert(1, {
            "name": "sbox5-vmess-argo", "type": "vmess", "server": settings.argo.hostname, "port": 443,
            "uuid": secrets.vmess_uuid, "alterId": 0, "cipher": "auto", "network": "ws", "udp": True,
            "tls": True, "servername": settings.argo.hostname, "skip-cert-verify": False,
            "ws-opts": {"path": secrets.vmess_path, "headers": {"Host": settings.argo.hostname}},
        })
    names = [proxy["name"] for proxy in proxies]
    return {
        "proxies": proxies,
        "proxy-groups": [
            {"name": "sbox5-select", "type": "select", "proxies": ["sbox5-auto", *names]},
            {"name": "sbox5-auto", "type": "url-test", "proxies": names, "url": "https://www.gstatic.com/generate_204", "interval": 300},
        ],
    }


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


def export_nodes(settings: Settings, secrets: Secrets, certificate_path: Path, certificate: dict[str, str], destination: Path) -> dict[str, Any]:
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(destination, 0o700)
    certificate_pem = certificate_path.read_text(encoding="ascii") if settings.certificate_mode == "self-signed" else ""
    links = build_share_links(settings, secrets, certificate)
    qr_files: list[str] = []
    if available("qrencode"):
        qr_files = [f"{protocol}.png" for protocol in links]
    expected = {"links.txt", "subscription-base64.txt", "sing-box-client.json", "mihomo.yaml", "metadata.json", *qr_files}
    if certificate_pem:
        expected.add("certificate.pem")
    for path in list(destination.iterdir()):
        if path.name not in expected:
            if path.is_symlink() or not path.is_file():
                raise ConfigError(tr(f"The export directory contains an unknown entry; refusing to clean it: {path}", f"导出目录包含未知项目，拒绝清理：{path}"))
            path.unlink()
    raw_subscription = "\n".join(links.values()) + "\n"
    atomic_text(destination / "links.txt", raw_subscription, 0o600)
    atomic_text(destination / "subscription-base64.txt", base64.b64encode(raw_subscription.encode()).decode() + "\n", 0o600)
    atomic_json(destination / "sing-box-client.json", build_singbox_client(settings, secrets, certificate_pem), 0o600)
    atomic_text(destination / "mihomo.yaml", yaml_dump(build_mihomo(settings, secrets, certificate)) + "\n", 0o600)
    if certificate_pem:
        atomic_text(destination / "certificate.pem", certificate_pem, 0o600)
    if qr_files:
        for protocol, link in links.items():
            output = destination / f"{protocol}.png"
            run(["qrencode", "-t", "PNG", "-o", str(output)], input_text=link, timeout=30)
            os.chmod(output, 0o600)
    metadata = {
        "qr_files": qr_files,
        "tls_verification": "certificate-pin" if settings.certificate_mode == "self-signed" else "public-ca",
        "warnings": [
            tr("All exported files contain credentials and must be treated as secrets; do not upload them to public subscription services.", "所有导出文件都含凭证，应视为秘密，不要上传到公共订阅服务。"),
            tr("Generic links in self-signed mode rely on client support for pinSHA256; use the full client configuration when unsupported.", "自签模式的通用链接依赖客户端支持 pinSHA256；不支持时请使用完整客户端配置。"),
            tr("Mihomo in self-signed mode uses the full certificate SHA256 fingerprint instead of skip-cert-verify.", "Mihomo 自签模式使用完整证书 SHA256 指纹，不使用 skip-cert-verify。"),
        ],
        "certificate": certificate,
    }
    if settings.argo.enabled:
        metadata["warnings"].append(tr(f"Argo only provides a VMess-WebSocket fallback entry; the Cloudflare ingress must point to http://127.0.0.1:{settings.ports.vmess} and match the selected path.", f"Argo 仅提供 VMess-WebSocket 备用入口；Cloudflare 后台 ingress 必须指向 http://127.0.0.1:{settings.ports.vmess} 并匹配所选路径。"))
    atomic_json(destination / "metadata.json", metadata, 0o600)
    return {"links": links, "files": sorted(path.name for path in destination.iterdir() if path.is_file()), "warnings": metadata["warnings"]}
