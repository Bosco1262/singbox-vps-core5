# Copyright (C) 2026 Bosco1262
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import ipaddress
import json
from pathlib import Path
import ssl
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPSHandler, HTTPRedirectHandler, Request, build_opener

from .errors import ConfigError, ExternalCommandError
from .i18n import tr
from .models import DDNSSettings
from .util import atomic_json

_API_BASE = "https://api.cloudflare.com/client/v4"
_IP_ENDPOINTS = {
    4: (
        "https://api.ipify.org",
        "https://ipv4.icanhazip.com",
        "https://www.cloudflare.com/cdn-cgi/trace",
    ),
    6: (
        "https://api6.ipify.org",
        "https://ipv6.icanhazip.com",
        "https://www.cloudflare.com/cdn-cgi/trace",
    ),
}


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req: Request, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> None:
        raise ExternalCommandError(tr("The DDNS/IP lookup service must not redirect", "DDNS/IP 查询服务不允许重定向"))


def _https_opener() -> Any:
    return build_opener(HTTPSHandler(context=ssl.create_default_context()), _NoRedirect())


def _read_response(request: Request, timeout: int = 20, limit: int = 1024 * 1024) -> bytes:
    try:
        with _https_opener().open(request, timeout=timeout) as response:
            url = urlsplit(response.geturl())
            if url.scheme != "https":
                raise ExternalCommandError(tr("The network lookup was downgraded to non-HTTPS", "网络查询被降级为非 HTTPS"))
            return response.read(limit + 1)
    except HTTPError as exc:
        detail = exc.read(4096).decode("utf-8", "replace")
        raise ExternalCommandError(tr(f"The HTTPS request failed ({exc.code}): {detail}", f"HTTPS 请求失败（{exc.code}）：{detail}")) from exc
    except URLError as exc:
        raise ExternalCommandError(tr(f"The HTTPS request failed: {exc.reason}", f"HTTPS 请求失败：{exc.reason}")) from exc


def _detect_address(family: int) -> str | None:
    addresses: list[str] = []
    failures: list[str] = []
    for endpoint in _IP_ENDPOINTS[family]:
        try:
            body = _read_response(Request(endpoint, headers={"User-Agent": "sbox5/0.1"}), limit=4096)
            if len(body) > 4096:
                raise ExternalCommandError(tr("The IP lookup response is too large", "IP 查询响应过大"))
            text = body.decode("ascii", "strict").strip()
            if endpoint.endswith("/cdn-cgi/trace"):
                fields = dict(line.split("=", 1) for line in text.splitlines() if "=" in line)
                text = fields.get("ip", "")
            address = ipaddress.ip_address(text)
            if address.version != family or not address.is_global:
                raise ExternalCommandError(tr("The IP lookup returned the wrong address family or a non-public address", "IP 查询返回了错误地址族或非公网地址"))
            addresses.append(str(address))
        except (ValueError, UnicodeError, ExternalCommandError) as exc:
            failures.append(str(exc))
    if addresses and len(set(addresses)) > 1:
        raise ExternalCommandError(tr(f"IPv{family} lookup results conflict ({set(addresses)}); DNS is not updated this time to avoid a wrong write", f"IPv{family} 查询结果存在冲突（{set(addresses)}），为避免写错 DNS，本次不更新"))
    if len(addresses) >= 2 and len(set(addresses)) == 1:
        return addresses[0]
    return None


class CloudflareDDNS:
    def __init__(self, settings: DDNSSettings, token: str) -> None:
        settings.validate()
        if not settings.enabled:
            raise ConfigError(tr("DDNS is not enabled", "DDNS 未启用"))
        if not token or any(char in token for char in "\r\n\x00"):
            raise ConfigError(tr("The Cloudflare API Token is invalid", "Cloudflare API Token 无效"))
        self.settings = settings
        self._token = token

    def _request(self, method: str, path: str, *, params: dict[str, Any] | None = None, payload: dict[str, Any] | None = None) -> Any:
        url = _API_BASE + path
        if params:
            url += "?" + urlencode(params)
        data = json.dumps(payload, separators=(",", ":")).encode("utf-8") if payload is not None else None
        request = Request(url, data=data, method=method, headers={
            "Authorization": f"Bearer {self._token}",
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": "sbox5/0.1",
        })
        body = _read_response(request, timeout=30)
        if len(body) > 1024 * 1024:
            raise ExternalCommandError(tr("The Cloudflare API response is too large", "Cloudflare API 响应过大"))
        try:
            result = json.loads(body)
        except (UnicodeError, json.JSONDecodeError) as exc:
            raise ExternalCommandError(tr("The Cloudflare API returned invalid JSON", "Cloudflare API 返回了无效 JSON")) from exc
        if not result.get("success"):
            unknown = tr("unknown error", "未知错误")
            errors = result.get("errors", [])
            messages = "; ".join(str(item.get("message", unknown)) for item in errors if isinstance(item, dict))
            raise ExternalCommandError(tr(f"The Cloudflare API rejected the request: {messages or unknown}", f"Cloudflare API 拒绝请求：{messages or unknown}"))
        return result.get("result")

    def zone_id(self) -> str:
        result = self._request("GET", "/zones", params={"name": self.settings.zone, "status": "active", "match": "all"})
        if not isinstance(result, list) or len(result) != 1:
            raise ExternalCommandError(tr("Could not find exactly one active Cloudflare Zone; check the Zone name and Token permissions", "找不到唯一、活跃的 Cloudflare Zone；请检查 Zone 名称和 Token 权限"))
        return str(result[0]["id"])

    def _records(self, zone_id: str, record_type: str) -> list[dict[str, Any]]:
        result = self._request("GET", f"/zones/{zone_id}/dns_records", params={
            "type": record_type,
            "name.exact": self.settings.record,
            "match": "all",
        })
        if not isinstance(result, list):
            raise ExternalCommandError(tr("The Cloudflare DNS record response has an invalid format", "Cloudflare DNS 记录响应格式无效"))
        return result

    def _write_record(self, zone_id: str, record_type: str, address: str) -> str:
        records = self._records(zone_id, record_type)
        if len(records) > 1:
            raise ExternalCommandError(tr(f"{self.settings.record} has multiple {record_type} records; reduce them to one first to avoid a wrong update", f"{self.settings.record} 存在多条 {record_type} 记录；为避免误改，请先整理为一条"))
        payload = {
            "type": record_type,
            "name": self.settings.record,
            "content": address,
            "ttl": 120,
            "proxied": False,
        }
        if records:
            record = records[0]
            if record.get("content") == address and record.get("proxied") is False and record.get("ttl") == 120:
                return tr(f"{record_type} is already up to date", f"{record_type} 无需更新")
            self._request("PATCH", f"/zones/{zone_id}/dns_records/{record['id']}", payload=payload)
            return tr(f"{record_type} was updated to {address}", f"{record_type} 已更新为 {address}")
        self._request("POST", f"/zones/{zone_id}/dns_records", payload=payload)
        return tr(f"{record_type} was created as {address}", f"{record_type} 已创建为 {address}")

    def _ensure_dns_only(self, zone_id: str) -> list[str]:
        records = {record_type: self._records(zone_id, record_type) for record_type in ("A", "AAAA")}
        for record_type, items in records.items():
            if len(items) > 1:
                raise ExternalCommandError(tr(f"{self.settings.record} has multiple {record_type} records; DNS is left unchanged to avoid a wrong update", f"{self.settings.record} 存在多条 {record_type} 记录；为避免误改，DNS 保持不变"))
        changes: list[str] = []
        for record_type, items in records.items():
            for record in items:
                if record.get("proxied") is True:
                    self._request("PATCH", f"/zones/{zone_id}/dns_records/{record['id']}", payload={"proxied": False})
                    changes.append(tr(f"{record_type} was switched to DNS-only", f"{record_type} 已切换为 DNS-only"))
        return changes

    def sync(self, state_path: Path | None = None) -> dict[str, Any]:
        addresses: dict[str, str] = {}
        warnings: list[str] = []
        for family, enabled in ((4, self.settings.ipv4), (6, self.settings.ipv6)):
            if not enabled:
                continue
            address = _detect_address(family)
            if address:
                addresses["A" if family == 4 else "AAAA"] = address
            else:
                warnings.append(tr(f"IPv{family} is currently unavailable, or the two lookup sources did not cross-confirm successfully; skipped", f"IPv{family} 当前不可用或两个查询源未成功交叉确认，已跳过"))
        if not addresses:
            raise ExternalCommandError(tr("Could not reliably confirm any public IP; DNS is left unchanged", "未能可靠确认任何公网 IP，DNS 保持不变"))
        zone_id = self.zone_id()
        changes = self._ensure_dns_only(zone_id)
        for record_type, address in addresses.items():
            changes.append(self._write_record(zone_id, record_type, address))
        result = {"record": self.settings.record, "addresses": addresses, "changes": changes, "warnings": warnings}
        if state_path:
            atomic_json(state_path, result, 0o600)
        return result
