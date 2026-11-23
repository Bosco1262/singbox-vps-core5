# Copyright (C) 2026 Bosco1262
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

from typing import Any

from .certificates import certificate_metadata
from .config import check_server_config, profile_certificate_path
from .firewall import needs_firewall_service
from .i18n import tr
from .installer import (
    ARGO_TOKEN_PATH,
    CERTIFICATES_STATE_PATH,
    DDNS_TOKEN_PATH,
    EXPORT_DIR,
    FIREWALL_STATE_PATH,
    RULESET_DIR,
    SECRETS_PATH,
    SERVER_CONFIG_PATH,
    SETTINGS_PATH,
    SINGBOX_BINARY,
)
from .models import Secrets, Settings
from .network import output_host
from .services import service_active, service_exists
from .subscription import CONFIG_PATH as SUBSCRIPTION_CONFIG_PATH
from .subscription import TOKEN_PATH as SUBSCRIPTION_TOKEN_PATH
from .subscription import status as subscription_status
from .util import load_json


def _check(checks: list[dict[str, str]], name: str, status: str, detail: str = "") -> None:
    checks.append({"name": name, "status": status, "detail": detail})


def run_checks(settings: Settings, secrets: Secrets) -> list[dict[str, str]]:
    checks: list[dict[str, str]] = []
    for path, label, modes in (
        (SETTINGS_PATH, "settings permissions", {"0640", "0600"}),
        (SECRETS_PATH, "secrets permissions", {"0600"}),
    ):
        if not path.is_file() or path.is_symlink():
            _check(checks, label, "fail", str(path))
            continue
        mode = f"{path.stat().st_mode & 0o777:04o}"
        _check(checks, label, "ok" if mode in modes else "warn", f"{path} {mode}")
    if SINGBOX_BINARY.is_file():
        from .kernel import current_version
        try:
            _check(checks, "kernel", "ok", current_version(SINGBOX_BINARY))
        except Exception as exc:
            _check(checks, "kernel", "fail", str(exc))
    else:
        _check(checks, "kernel", "fail", tr("sing-box binary is missing", "sing-box 二进制缺失"))
    if SERVER_CONFIG_PATH.is_file():
        try:
            check_server_config(SINGBOX_BINARY, SERVER_CONFIG_PATH)
            _check(checks, "server config", "ok", str(SERVER_CONFIG_PATH))
        except Exception as exc:
            _check(checks, "server config", "fail", str(exc))
    else:
        _check(checks, "server config", "fail", str(SERVER_CONFIG_PATH))
    for name in ("sing-box-client.json", "sfa.json", "sfi.json", "sfw.json", "mihomo.yaml"):
        path = EXPORT_DIR / name
        _check(checks, f"export {name}", "ok" if path.is_file() else "warn", str(path))
    required_services = ["sbox5.service"]
    if needs_firewall_service(settings):
        required_services.append("sbox5-firewall.service")
    if settings.argo.enabled:
        required_services.append("sbox5-argo.service")
    if settings.subscription.enabled:
        required_services.append("sbox5-subscription.service")
    if settings.ddns.enabled:
        required_services.append("sbox5-ddns.timer")
    for name in required_services:
        if not service_exists(name):
            _check(checks, f"service {name}", "fail", tr("not installed", "未安装"))
        elif not service_active(name):
            _check(checks, f"service {name}", "fail", tr("not active", "未运行"))
        else:
            _check(checks, f"service {name}", "ok")
    for optional in ("sbox5-argo.service", "sbox5-subscription.service", "sbox5-ddns.timer"):
        if optional in required_services:
            continue
        if service_exists(optional):
            _check(checks, f"service {optional}", "ok" if service_active(optional) else "warn", tr("installed but inactive", "已安装但未运行"))
    for profile in settings.active_certificate_profiles():
        certificate = profile_certificate_path(profile)
        if not certificate.is_file():
            _check(checks, f"certificate {profile.id}", "fail", str(certificate))
            continue
        try:
            metadata = certificate_metadata(certificate)
            _check(checks, f"certificate {profile.id}", "ok", metadata.get("not_after", ""))
        except Exception as exc:
            _check(checks, f"certificate {profile.id}", "warn", str(exc))
    for token_path, name in ((ARGO_TOKEN_PATH, "Argo token"), (DDNS_TOKEN_PATH, "DDNS token")):
        if token_path.is_file() and not token_path.is_symlink():
            mode = f"{token_path.stat().st_mode & 0o777:04o}"
            _check(checks, f"{name} permissions", "ok" if mode == "0600" else "warn", f"{token_path} {mode}")
    if settings.subscription.enabled:
        status = subscription_status(SUBSCRIPTION_CONFIG_PATH)
        _check(checks, "subscription config", "ok" if status else "warn", str(SUBSCRIPTION_CONFIG_PATH))
        if not SUBSCRIPTION_TOKEN_PATH.is_file() or SUBSCRIPTION_TOKEN_PATH.is_symlink():
            _check(checks, "subscription token", "fail", str(SUBSCRIPTION_TOKEN_PATH))
        else:
            mode = f"{SUBSCRIPTION_TOKEN_PATH.stat().st_mode & 0o777:04o}"
            _check(checks, "subscription token", "ok" if mode == "0600" else "warn", mode)
    for ruleset in settings.routing.rule_sets:
        path = RULESET_DIR / ruleset.filename
        _check(checks, f"ruleset {ruleset.tag}", "ok" if path.is_file() else "fail", str(path))
    if FIREWALL_STATE_PATH.is_file():
        state = load_json(FIREWALL_STATE_PATH)
        _check(checks, "firewall state", "ok", str(state.get("backend", "")))
    else:
        _check(checks, "firewall state", "warn", tr("no firewall state", "无防火墙状态"))
    if settings.output_family != "auto":
        try:
            _check(checks, "output address", "ok", output_host(settings))
        except Exception as exc:
            _check(checks, "output address", "fail", str(exc))
    if CERTIFICATES_STATE_PATH.is_file():
        _check(checks, "certificate state", "ok", str(CERTIFICATES_STATE_PATH))
    return checks


def render_checks(checks: list[dict[str, str]]) -> str:
    icon = {"ok": "OK", "warn": "WARN", "fail": "FAIL"}
    return "\n".join(f"[{icon.get(item['status'], item['status'])}] {item['name']}: {item['detail']}".rstrip() for item in checks)


def doctor_data(settings: Settings, secrets: Secrets) -> dict[str, Any]:
    checks = run_checks(settings, secrets)
    counts = {status: sum(1 for item in checks if item["status"] == status) for status in ("ok", "warn", "fail")}
    return {"checks": checks, "counts": counts, "healthy": counts["fail"] == 0}
