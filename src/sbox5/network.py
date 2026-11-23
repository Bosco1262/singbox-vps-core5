# Copyright (C) 2026 Bosco1262
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

from dataclasses import replace
import ipaddress
import json
import re
import ssl
from typing import Any
import urllib.request

from .errors import ConfigError, SBox5Error
from .i18n import tr
from .models import Settings
from .util import run

_ADDRESS = re.compile(r"\binet6?\s+([0-9A-Fa-f:.]+)/\d+")


def global_addresses() -> dict[int, list[str]]:
    result: dict[int, list[str]] = {4: [], 6: []}
    commands = ((4, ["ip", "-4", "addr", "show", "scope", "global"]), (6, ["ip", "-6", "addr", "show", "scope", "global"]))
    for family, command in commands:
        try:
            completed = run(command, check=False)
        except (OSError, SBox5Error):
            continue
        if completed.returncode != 0:
            continue
        for match in _ADDRESS.finditer(completed.stdout):
            try:
                address = ipaddress.ip_address(match.group(1))
            except ValueError:
                continue
            if address.version != family or not address.is_global:
                continue
            if str(address) not in result[family]:
                result[family].append(str(address))
    return result


def output_host(settings: Settings) -> str:
    if settings.output_family == "auto":
        return settings.host
    family = 4 if settings.output_family == "ipv4" else 6
    addresses = global_addresses()[family]
    if not addresses:
        raise ConfigError(tr(
            f"No global IPv{family} address was found for the selected output family",
            f"未找到所选输出地址族的全局 IPv{family} 地址",
        ))
    return addresses[0]


def effective_settings(settings: Settings) -> Settings:
    if settings.output_family == "auto":
        return settings
    return replace(settings, host=output_host(settings))


def summary() -> dict[str, Any]:
    addresses = global_addresses()
    return {"ipv4": addresses[4], "ipv6": addresses[6]}


def geolocation(address: str) -> dict[str, str]:
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return {}
    if not parsed.is_global:
        return {}
    request = urllib.request.Request(
        f"https://ipinfo.io/{parsed}/json",
        headers={"Accept": "application/json", "User-Agent": "sbox5-geo/1"},
    )
    try:
        with urllib.request.urlopen(request, timeout=5, context=ssl.create_default_context()) as response:
            payload = response.read(65536)
        data = json.loads(payload.decode("utf-8"))
    except (OSError, ValueError, json.JSONDecodeError):
        return {}
    if not isinstance(data, dict):
        return {}
    result = {"address": str(parsed)}
    for key in ("city", "region", "country", "org"):
        value = data.get(key, "")
        if isinstance(value, str) and value:
            result[key] = value
    return result


def geolocation_summary() -> dict[str, list[dict[str, str]]]:
    addresses = global_addresses()
    return {
        "ipv4": [item for item in (geolocation(address) for address in addresses[4]) if item],
        "ipv6": [item for item in (geolocation(address) for address in addresses[6]) if item],
    }
