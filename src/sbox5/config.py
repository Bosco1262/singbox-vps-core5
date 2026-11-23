# Copyright (C) 2026 Bosco1262
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .errors import ConfigError
from .i18n import tr
from .models import CertificateProfile, RuleSetSettings, Secrets, Settings
from .util import run, split_host_port

CERTIFICATE_PATH = Path("/etc/sbox5/tls/cert.pem")
KEY_PATH = Path("/etc/sbox5/tls/key.pem")
TLS_DIR = Path("/etc/sbox5/tls")
ACME_STATE_DIR = Path("/var/lib/sbox5/acme")
RULESET_DIR = Path("/var/lib/sbox5/rulesets")


def rule_set_path(item: RuleSetSettings) -> Path:
    return RULESET_DIR / item.filename


def certificate_profile(settings: Settings, profile_id: str) -> CertificateProfile:
    for profile in settings.certificate_profiles:
        if profile.id == profile_id:
            return profile
    raise ConfigError(tr(f"Certificate profile not found: {profile_id}", f"证书配置不存在：{profile_id}"))


def profile_certificate_path(profile: CertificateProfile) -> Path:
    if profile.id == "default":
        return CERTIFICATE_PATH
    return TLS_DIR / profile.id / "cert.pem"


def profile_key_path(profile: CertificateProfile) -> Path:
    if profile.id == "default":
        return KEY_PATH
    return TLS_DIR / profile.id / "key.pem"


def profile_acme_data_directory(profile: CertificateProfile) -> Path:
    return ACME_STATE_DIR / profile.id


def _tls(profile: CertificateProfile) -> dict[str, Any]:
    if profile.mode == "acme":
        return {
            "enabled": True,
            "server_name": profile.server_name,
            "certificate_provider": profile.id,
        }
    return {
        "enabled": True,
        "server_name": profile.server_name,
        "certificate_path": str(profile_certificate_path(profile)),
        "key_path": str(profile_key_path(profile)),
    }


def _acme_provider(profile: CertificateProfile, secrets: Secrets) -> dict[str, Any]:
    provider: dict[str, Any] = {
        "type": "acme",
        "tag": profile.id,
        "domain": list(profile.domains),
        "provider": profile.ca_provider,
        "data_directory": str(profile_acme_data_directory(profile)),
        "key_type": "p256",
    }
    if profile.email:
        provider["email"] = profile.email
    if profile.acme_profile:
        provider["profile"] = profile.acme_profile
    if profile.challenge == "http-01":
        provider["disable_tls_alpn_challenge"] = True
    elif profile.challenge == "tls-alpn-01":
        provider["disable_http_challenge"] = True
    else:
        token = secrets.acme_dns_tokens.get(profile.id, "")
        if not token:
            raise ConfigError(tr(
                f"ACME DNS-01 requires a DNS API token for profile {profile.id}",
                f"ACME DNS-01 需要为证书配置 {profile.id} 提供 DNS API Token",
            ))
        provider["disable_http_challenge"] = True
        provider["disable_tls_alpn_challenge"] = True
        provider["dns01_challenge"] = {"provider": profile.dns_provider, "api_token": token}
    return provider


def build_server_config(settings: Settings, secrets: Secrets) -> dict[str, Any]:
    settings.validate()
    secrets.validate()
    if not secrets.reality_private_key or not secrets.reality_public_key:
        raise ConfigError(tr("The Reality key pair has not been generated yet", "尚未生成 Reality 密钥"))
    target, target_port = split_host_port(settings.reality_target)
    inbounds: list[dict[str, Any]] = []
    profiles = {profile.id: profile for profile in settings.certificate_profiles}

    if settings.protocols["vless"].enabled:
        inbounds.append({
            "type": "vless",
            "tag": "vless-reality",
            "listen": "::",
            "listen_port": settings.ports.vless,
            "users": [{"name": "vless", "uuid": secrets.vless_uuid, "flow": "xtls-rprx-vision"}],
            "tls": {
                "enabled": True,
                "server_name": settings.reality_sni,
                "reality": {
                    "enabled": True,
                    "handshake": {"server": target, "server_port": target_port},
                    "private_key": secrets.reality_private_key,
                    "short_id": [secrets.reality_short_id],
                    "max_time_difference": "1m",
                },
            },
        })
    if settings.protocols["vmess"].enabled:
        vmess: dict[str, Any] = {
            "type": "vmess",
            "tag": "vmess-ws",
            "listen": "::",
            "listen_port": settings.ports.vmess,
            "users": [{"name": "vmess", "uuid": secrets.vmess_uuid, "alterId": 0}],
            "transport": {"type": "ws", "path": secrets.vmess_path, "max_early_data": 0},
        }
        profile_id = settings.protocols["vmess"].tls_profile
        if profile_id:
            vmess["tls"] = _tls(profiles[profile_id])
        inbounds.append(vmess)
        if settings.argo.enabled:
            inbounds.append({
                "type": "vmess",
                "tag": "vmess-argo-origin",
                "listen": "127.0.0.1",
                "listen_port": settings.argo.local_port,
                "users": [{"name": "vmess-argo", "uuid": secrets.vmess_uuid, "alterId": 0}],
                "transport": {"type": "ws", "path": secrets.vmess_path, "max_early_data": 0},
            })
    if settings.protocols["hysteria2"].enabled:
        inbounds.append({
            "type": "hysteria2",
            "tag": "hysteria2",
            "listen": "::",
            "listen_port": settings.ports.hysteria2,
            "users": [{"name": "hysteria2", "password": secrets.hysteria2_password}],
            "obfs": {"type": "salamander", "password": secrets.hysteria2_obfs_password},
            "tls": _tls(profiles[settings.protocols["hysteria2"].tls_profile]),
        })
    if settings.protocols["tuic"].enabled:
        inbounds.append({
            "type": "tuic",
            "tag": "tuic-v5",
            "listen": "::",
            "listen_port": settings.ports.tuic,
            "users": [{"name": "tuic", "uuid": secrets.tuic_uuid, "password": secrets.tuic_password}],
            "congestion_control": "bbr",
            "auth_timeout": "3s",
            "zero_rtt_handshake": False,
            "heartbeat": "10s",
            "tls": _tls(profiles[settings.protocols["tuic"].tls_profile]),
        })
    if settings.protocols["anytls"].enabled:
        inbounds.append({
            "type": "anytls",
            "tag": "anytls",
            "listen": "::",
            "listen_port": settings.ports.anytls,
            "users": [{"name": "anytls", "password": secrets.anytls_password}],
            "tls": _tls(profiles[settings.protocols["anytls"].tls_profile]),
        })

    providers = [
        _acme_provider(profile, secrets)
        for profile in settings.active_certificate_profiles()
        if profile.mode == "acme"
    ]
    outbounds: list[dict[str, Any]] = [
        {"type": "direct", "tag": "direct"},
        {
            "type": "direct",
            "tag": "direct-v4",
            "domain_resolver": {"server": "local", "strategy": "ipv4_only"},
        },
        {
            "type": "direct",
            "tag": "direct-v6",
            "domain_resolver": {"server": "local", "strategy": "ipv6_only"},
        },
    ]
    socks5 = settings.routing.socks5
    if socks5.enabled:
        outbound: dict[str, Any] = {
            "type": "socks",
            "tag": "socks5",
            "server": socks5.server,
            "server_port": socks5.port,
            "version": "5",
            "domain_resolver": "local",
        }
        if socks5.username:
            if not secrets.socks5_password:
                raise ConfigError(tr("Socks5 username requires a password", "Socks5 用户名需要密码"))
            outbound["username"] = socks5.username
            outbound["password"] = secrets.socks5_password
        outbounds.append(outbound)
    endpoints: list[dict[str, Any]] = []
    if settings.warp.enabled:
        credential = secrets.warp
        if not credential.configured:
            raise ConfigError(tr(
                "WARP is enabled but no credential is configured; run 'sbox5 warp register' or 'sbox5 warp import' first",
                "WARP 已启用但未配置凭证；请先运行 sbox5 warp register 或 sbox5 warp import",
            ))
        endpoints.append({
            "type": "wireguard",
            "tag": settings.warp.tag,
            "address": list(credential.addresses),
            "private_key": credential.private_key,
            "mtu": settings.warp.mtu,
            "domain_resolver": "local",
            "peers": [{
                "address": settings.warp.endpoint or credential.peer_address,
                "port": settings.warp.port or credential.peer_port,
                "public_key": credential.peer_public_key,
                "allowed_ips": ["0.0.0.0/0", "::/0"],
                "reserved": list(credential.reserved),
                "persistent_keepalive_interval": 30,
            }],
        })
    rules: list[dict[str, Any]] = [
        {"action": "sniff"},
        {"ip_is_private": True, "action": "route", "outbound": "direct"},
    ]
    for route in settings.routing.routes:
        rules.append({"domain_suffix": list(route.suffixes), "action": "route", "outbound": route.target})
    for item in settings.routing.rule_sets:
        rules.append({"rule_set": [item.tag], "action": "route", "outbound": item.target})
    config: dict[str, Any] = {
        "log": {"level": "warn", "timestamp": True},
        "dns": {"servers": [{"type": "local", "tag": "local"}], "final": "local"},
        "inbounds": inbounds,
        "outbounds": outbounds,
        "route": {
            "rules": rules,
            "rule_set": [
                {
                    "type": "local",
                    "tag": item.tag,
                    "format": "binary",
                    "path": str(rule_set_path(item)),
                }
                for item in settings.routing.rule_sets
            ],
            "final": "direct",
            "default_domain_resolver": "local",
            "auto_detect_interface": True,
        },
    }
    if endpoints:
        config["endpoints"] = endpoints
    if providers:
        config["certificate_providers"] = providers
    return config


def generate_reality_keypair(binary: Path, secrets: Secrets) -> None:
    result = run([str(binary), "generate", "reality-keypair"])
    values: dict[str, str] = {}
    for line in result.stdout.splitlines():
        key, separator, value = line.partition(":")
        if separator and key.strip() in ("PrivateKey", "PublicKey"):
            values[key.strip()] = value.strip()
    if set(values) != {"PrivateKey", "PublicKey"}:
        raise ConfigError(tr("sing-box did not return a valid Reality key pair", "sing-box 未返回有效的 Reality 密钥对"))
    secrets.reality_private_key = values["PrivateKey"]
    secrets.reality_public_key = values["PublicKey"]


def check_server_config(binary: Path, config_path: Path) -> None:
    run([str(binary), "check", "-c", str(config_path)], timeout=60)


def config_bytes(config: dict[str, Any]) -> bytes:
    return (json.dumps(config, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8")
