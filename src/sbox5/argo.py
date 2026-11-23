# Copyright (C) 2026 Bosco1262
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

from datetime import datetime, timezone
import re
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .models import Settings
from .util import atomic_json, load_json

_QUICK_URL = re.compile(r"https://([a-z0-9][a-z0-9-]*\.trycloudflare\.com)")


def quick_url_from_log(log_path: Path) -> str:
    if not log_path.is_file() or log_path.is_symlink():
        return ""
    try:
        data = log_path.read_text(encoding="utf-8", errors="replace")[-262144:]
    except OSError:
        return ""
    matches = _QUICK_URL.findall(data)
    if not matches:
        return ""
    return f"https://{matches[-1]}"


def wait_for_quick_url(log_path: Path, timeout: int = 20) -> str:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        url = quick_url_from_log(log_path)
        if url:
            return url
        time.sleep(1)
    return ""


def read_state(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    return load_json(path)


def write_state(path: Path, settings: Settings, quick_url: str = "") -> dict[str, Any]:
    state = {
        "enabled": settings.argo.enabled,
        "mode": settings.argo.mode,
        "hostname": settings.argo.hostname,
        "local_port": settings.argo.local_port,
        "quick_url": quick_url,
        "updated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
    }
    atomic_json(path, state, 0o600)
    return state


def argo_host(settings: Settings, state: dict[str, Any]) -> str:
    if not settings.argo.enabled:
        return ""
    if settings.argo.mode == "quick":
        value = str(state.get("quick_url", ""))
        if not value:
            return ""
        parsed = urlsplit(value)
        return parsed.hostname or ""
    return settings.argo.hostname
