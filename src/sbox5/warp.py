# Copyright (C) 2026 Bosco1262
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import base64
from datetime import datetime, timezone
import json
from pathlib import Path
import ssl
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPSHandler, HTTPRedirectHandler, Request, build_opener

from .errors import ExternalCommandError, VerificationError
from .i18n import tr
from .models import WarpCredential
from .util import run

_REGISTRATION_URL = "https://api.cloudflareclient.com/v0a2158/reg"
_ALLOWED_HOST = "api.cloudflareclient.com"


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req: Request, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        raise VerificationError(tr("The WARP registration endpoint must not redirect", "WARP 注册端点不允许重定向"))


def generate_wireguard_keypair(binary: Path) -> tuple[str, str]:
    result = run([str(binary), "generate", "wg-keypair"], timeout=30)
    values: dict[str, str] = {}
    for line in result.stdout.splitlines():
        key, separator, value = line.partition(":")
        if separator and key.strip().lower() in ("privatekey", "publickey"):
            values[key.strip().lower()] = value.strip()
    if set(values) != {"privatekey", "publickey"}:
        raise ExternalCommandError(tr("sing-box did not return a valid WireGuard key pair", "sing-box 未返回有效的 WireGuard 密钥对"))
    return values["privatekey"], values["publickey"]


def _request_registration(public_key: str) -> dict[str, Any]:
    payload = {
        "key": public_key,
        "install_id": "",
        "fcm_token": "",
        "tos": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "model": "PC",
        "serial_number": "",
        "locale": "en_US",
    }
    request = Request(
        _REGISTRATION_URL,
        data=json.dumps(payload, separators=(",", ":")).encode("utf-8"),
        method="POST",
        headers={
            "CF-Client-Version": "a-6.10-2158",
            "User-Agent": "okhttp/3.12.1",
            "Content-Type": "application/json",
            "Accept": "application/json",
        },
    )
    context = ssl.create_default_context()
    opener = build_opener(HTTPSHandler(context=context), _NoRedirect())
    try:
        with opener.open(request, timeout=30) as response:
            parsed = urlsplit(response.geturl())
            if parsed.scheme != "https" or parsed.hostname != _ALLOWED_HOST:
                raise VerificationError(tr("The WARP registration response came from an unexpected host", "WARP 注册响应来自非预期主机"))
            body = response.read(1024 * 1024 + 1)
    except HTTPError as exc:
        detail = exc.read(4096).decode("utf-8", "replace")
        raise ExternalCommandError(tr(f"The WARP registration endpoint rejected the request ({exc.code}): {detail}", f"WARP 注册端点拒绝请求（{exc.code}）：{detail}")) from exc
    except URLError as exc:
        raise ExternalCommandError(tr(f"The WARP registration request failed: {exc.reason}", f"WARP 注册请求失败：{exc.reason}")) from exc
    if len(body) > 1024 * 1024:
        raise VerificationError(tr("The WARP registration response is too large", "WARP 注册响应过大"))
    try:
        result = json.loads(body)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ExternalCommandError(tr("The WARP registration endpoint returned invalid JSON", "WARP 注册端点返回了无效 JSON")) from exc
    if not isinstance(result, dict):
        raise ExternalCommandError(tr("The WARP registration response has an invalid shape", "WARP 注册响应结构无效"))
    return result


def register_warp(binary: Path) -> WarpCredential:
    private_key, public_key = generate_wireguard_keypair(binary)
    result = _request_registration(public_key)
    config = result.get("config", result)
    if not isinstance(config, dict):
        raise ExternalCommandError(tr("The WARP registration response has no config object", "WARP 注册响应缺少 config 对象"))
    peers = config.get("peers")
    if not isinstance(peers, list) or not peers or not isinstance(peers[0], dict):
        raise ExternalCommandError(tr("The WARP registration response has no peer", "WARP 注册响应缺少 peer"))
    peer = peers[0]
    interface = config.get("interface", {})
    addresses = interface.get("addresses", {}) if isinstance(interface, dict) else {}
    address_values: list[str] = []
    for key, suffix in (("v4", "/32"), ("v6", "/128")):
        value = addresses.get(key) if isinstance(addresses, dict) else None
        if value:
            text = str(value)
            address_values.append(text if "/" in text else text + suffix)
    client_id = str(config.get("client_id", ""))
    decoded = b""
    padded = client_id + "=" * ((4 - len(client_id) % 4) % 4)
    for altchars in (None, b"-_"):
        try:
            decoded = base64.b64decode(padded, altchars=altchars, validate=True)
            break
        except Exception:
            continue
    if len(decoded) < 3:
        raise ExternalCommandError(tr("Unable to derive WARP reserved bytes from client_id", "无法从 client_id 推导 WARP reserved 字节"))
    endpoint = peer.get("endpoint", {}) if isinstance(peer.get("endpoint"), dict) else {}
    ports = endpoint.get("ports", [2408])
    port = int(ports[0]) if isinstance(ports, list) and ports else 2408
    credential = WarpCredential(
        private_key=private_key,
        public_key=public_key,
        peer_public_key=str(peer.get("public_key", "")),
        addresses=address_values,
        reserved=list(decoded[:3]),
        peer_address=str(endpoint.get("host", "engage.cloudflareclient.com")),
        peer_port=port,
        client_id=client_id,
        registered_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    )
    credential.validate()
    return credential


def import_warp_credential(
    private_key: str,
    peer_public_key: str,
    addresses: list[str],
    reserved: list[int],
    *,
    public_key: str = "",
    peer_address: str = "engage.cloudflareclient.com",
    peer_port: int = 2408,
    client_id: str = "",
) -> WarpCredential:
    credential = WarpCredential(
        private_key=private_key,
        public_key=public_key,
        peer_public_key=peer_public_key,
        addresses=addresses,
        reserved=reserved,
        peer_address=peer_address,
        peer_port=peer_port,
        client_id=client_id,
        registered_at=datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    )
    credential.validate()
    return credential
