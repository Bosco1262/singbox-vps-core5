# Copyright (C) 2026 Bosco1262
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .errors import ConfigError
from .i18n import tr
from .models import Secrets, Settings
from .util import run, split_host_port

CERTIFICATE_PATH = Path("/etc/sbox5/tls/cert.pem")
KEY_PATH = Path("/etc/sbox5/tls/key.pem")


def _tls() -> dict[str, Any]:
    return {"enabled": True, "certificate_path": str(CERTIFICATE_PATH), "key_path": str(KEY_PATH)}


def build_server_config(settings: Settings, secrets: Secrets) -> dict[str, Any]:
    settings.validate()
    secrets.validate()
    if not secrets.reality_private_key or not secrets.reality_public_key:
        raise ConfigError(tr("The Reality key pair has not been generated yet", "尚未生成 Reality 密钥"))
    target, target_port = split_host_port(settings.reality_target)
    return {
        "log": {"level": "warn", "timestamp": True},
        "inbounds": [
            {
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
            },
            {
                "type": "vmess",
                "tag": "vmess-ws",
                "listen": "::",
                "listen_port": settings.ports.vmess,
                "users": [{"name": "vmess", "uuid": secrets.vmess_uuid, "alter_id": 0}],
                "transport": {"type": "ws", "path": secrets.vmess_path, "max_early_data": 0},
            },
            {
                "type": "hysteria2",
                "tag": "hysteria2",
                "listen": "::",
                "listen_port": settings.ports.hysteria2,
                "users": [{"name": "hysteria2", "password": secrets.hysteria2_password}],
                "obfs": {"type": "salamander", "password": secrets.hysteria2_obfs_password},
                "tls": _tls(),
            },
            {
                "type": "tuic",
                "tag": "tuic-v5",
                "listen": "::",
                "listen_port": settings.ports.tuic,
                "users": [{"name": "tuic", "uuid": secrets.tuic_uuid, "password": secrets.tuic_password}],
                "congestion_control": "bbr",
                "auth_timeout": "3s",
                "zero_rtt_handshake": False,
                "heartbeat": "10s",
                "tls": _tls(),
            },
            {
                "type": "anytls",
                "tag": "anytls",
                "listen": "::",
                "listen_port": settings.ports.anytls,
                "users": [{"name": "anytls", "password": secrets.anytls_password}],
                "tls": _tls(),
            },
        ],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"rules": [], "final": "direct", "auto_detect_interface": True},
    }


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
