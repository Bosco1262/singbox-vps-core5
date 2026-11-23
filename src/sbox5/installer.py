# Copyright (C) 2026 Bosco1262
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
from typing import Any

from . import __version__
from .argo import argo_host, wait_for_quick_url, write_state as write_argo_state
from .certificates import acme_profile_state, certificate_metadata, create_self_signed, imported_profile_state
from .config import (
    ACME_STATE_DIR,
    CERTIFICATE_PATH,
    KEY_PATH,
    RULESET_DIR,
    build_server_config,
    check_server_config,
    config_bytes,
    generate_reality_keypair,
    profile_acme_data_directory,
    profile_certificate_path,
    profile_key_path,
    rule_set_path,
)
from .ddns import CloudflareDDNS
from .download import download_verified_file, install_locked_binary
from .errors import ConfigError, ConflictError
from .export import export_nodes
from .firewall import apply_firewall, needs_firewall_service
from .i18n import get_language, tr
from .models import RULESET_ALLOWED_HOSTS, Secrets, Settings
from .services import (
    argo_unit,
    copy_application,
    ddns_timer,
    ddns_unit,
    enable_start,
    ensure_system_user,
    firewall_unit,
    identity,
    reload_systemd,
    require_active,
    singbox_unit,
)
from .snapshot import SNAPSHOT_ROOT, Snapshot, prune_snapshots
from .system import architecture, check_ports, configure_bbr, ensure_packages, preflight
from .util import atomic_json, atomic_text, atomic_write, load_json, run, sha256_file

CONFIG_DIR = Path("/etc/sbox5")
SETTINGS_PATH = CONFIG_DIR / "settings.json"
SECRETS_PATH = CONFIG_DIR / "secrets/protocols.json"
SERVER_CONFIG_PATH = CONFIG_DIR / "config.json"
ARGO_TOKEN_PATH = CONFIG_DIR / "secrets/argo.token"
DDNS_TOKEN_PATH = CONFIG_DIR / "secrets/cloudflare.token"
STATE_DIR = Path("/var/lib/sbox5")
STATE_PATH = STATE_DIR / "state.json"
FIREWALL_STATE_PATH = STATE_DIR / "firewall.json"
CERTIFICATE_STATE_PATH = STATE_DIR / "certificate.json"
CERTIFICATES_STATE_PATH = STATE_DIR / "certificates.json"
DDNS_STATE_PATH = STATE_DIR / "ddns/last.json"
ARGO_DIR = STATE_DIR / "argo"
ARGO_STATE_PATH = ARGO_DIR / "state.json"
ARGO_LOG_PATH = ARGO_DIR / "quick.log"
CORE_STATE_PATH = STATE_DIR / "core.json"
EXPORT_DIR = STATE_DIR / "exports"
SYSCTL_PATH = Path("/etc/sysctl.d/99-sbox5.conf")
BINARY_DIR = Path("/usr/local/libexec/sbox5/bin")
CORE_CACHE_DIR = Path("/usr/local/libexec/sbox5/core")
SINGBOX_BINARY = BINARY_DIR / "sing-box"
CLOUDFLARED_BINARY = BINARY_DIR / "cloudflared"
UNIT_DIR = Path("/etc/systemd/system")
UNITS = (
    "sbox5.service", "sbox5-argo.service", "sbox5-ddns.service", "sbox5-ddns.timer",
    "sbox5-firewall.service", "sbox5-acme.service", "sbox5-acme.timer",
)


def load_settings() -> Settings:
    return Settings.from_dict(load_json(SETTINGS_PATH))


def load_secrets() -> Secrets:
    return Secrets.from_dict(load_json(SECRETS_PATH))


def _excluded(path: Path) -> bool:
    return (
        "__pycache__" in path.parts or path.suffix == ".pyc"
        or SNAPSHOT_ROOT == path or SNAPSHOT_ROOT in path.parents
        or Path("/var/lib/sbox5/staging") == path or Path("/var/lib/sbox5/staging") in path.parents
        or Path("/etc/sbox5/acme") == path or Path("/etc/sbox5/acme") in path.parents
        or Path("/var/lib/sbox5/acme") == path or Path("/var/lib/sbox5/acme") in path.parents
    )


def managed_files(settings: Settings | None = None) -> list[Path]:
    files = {
        SETTINGS_PATH, SECRETS_PATH, SERVER_CONFIG_PATH, ARGO_TOKEN_PATH, DDNS_TOKEN_PATH,
        CERTIFICATE_PATH, KEY_PATH, STATE_PATH, FIREWALL_STATE_PATH, CERTIFICATE_STATE_PATH,
        CERTIFICATES_STATE_PATH, DDNS_STATE_PATH, ARGO_STATE_PATH, ARGO_LOG_PATH, CORE_STATE_PATH,
        SYSCTL_PATH, Path("/usr/local/bin/sbox5"), SINGBOX_BINARY, CLOUDFLARED_BINARY,
        *(UNIT_DIR / name for name in UNITS),
    }
    if settings is not None:
        for profile in settings.certificate_profiles:
            files.add(profile_certificate_path(profile))
            files.add(profile_key_path(profile))
    for root in (CONFIG_DIR, Path("/usr/local/libexec/sbox5"), STATE_DIR):
        if root.exists():
            for path in root.rglob("*"):
                if path.is_file() and not _excluded(path):
                    files.add(path)
    return sorted(files)


def _managed_directories(settings: Settings | None = None) -> list[Path]:
    directories = [
        CONFIG_DIR, CONFIG_DIR / "secrets", CONFIG_DIR / "tls", CONFIG_DIR / "tls" / "default",
        STATE_DIR, SNAPSHOT_ROOT, STATE_DIR / "ddns", STATE_DIR / "exports", ACME_STATE_DIR,
        ACME_STATE_DIR / "default", ARGO_DIR, RULESET_DIR, Path("/var/lib/sbox5-runtime"),
        Path("/usr/local/libexec/sbox5"), Path("/usr/local/libexec/sbox5/app"), BINARY_DIR, CORE_CACHE_DIR,
    ]
    if settings is not None:
        for profile in settings.certificate_profiles:
            directories.append(profile_certificate_path(profile).parent)
            if profile.mode == "acme":
                directories.append(profile_acme_data_directory(profile))
    return directories


class InstallTransaction:
    def __init__(
        self,
        project_root: Path,
        settings: Settings,
        secrets: Secrets,
        *,
        upgrade: bool,
        reconfigure: bool = False,
        feature: str = "install",
        ddns_token: str = "",
        argo_token: str = "",
        import_files: dict[str, tuple[Path, Path]] | None = None,
        rule_set_files: dict[str, Path] | None = None,
    ) -> None:
        self.project_root = project_root.resolve()
        self.settings = settings
        self.secrets = secrets
        self.upgrade = upgrade
        self.reconfigure = reconfigure
        self.feature = feature
        self.ddns_token = ddns_token
        self.argo_token = argo_token
        self.import_files = dict(import_files or {})
        self.rule_set_files = dict(rule_set_files or {})
        self.snapshot: Snapshot | None = None
        self.previous_state: dict[str, Any] = {}
        self.previous_settings: Settings | None = None
        self.components: dict[str, Any] = {}
        self.sysctls: list[dict[str, str]] = []
        self.users: list[str] = ["sbox5"]
        self.committed = False

    def _record(self, path: Path) -> None:
        assert self.snapshot is not None
        target = str(path.absolute())
        if not any(entry["path"] == target for entry in self.snapshot.manifest["files"]):
            self.snapshot.track_new(path)
        self.snapshot.record_after(path)

    def _write(self, path: Path, data: bytes, mode: int = 0o600, uid: int | None = None, gid: int | None = None) -> None:
        atomic_write(path, data, mode, uid, gid)
        self._record(path)

    def _json(self, path: Path, value: Any, mode: int = 0o600, uid: int | None = None, gid: int | None = None) -> None:
        atomic_json(path, value, mode, uid, gid)
        self._record(path)

    def _remove(self, path: Path) -> None:
        if path.is_symlink():
            raise ConflictError(tr(f"Refusing to delete a symbolic link: {path}", f"拒绝删除符号链接：{path}"))
        if path.exists():
            if not path.is_file():
                raise ConflictError(tr(f"Refusing to delete a non-regular file: {path}", f"拒绝删除非普通文件：{path}"))
            path.unlink()
            self._record(path)

    def _mkdir(self, path: Path, mode: int, uid: int | None = None, gid: int | None = None) -> None:
        path.mkdir(parents=True, exist_ok=True, mode=mode)
        if path.is_symlink():
            raise ConflictError(tr(f"A project directory must not be a symbolic link: {path}", f"项目目录不能是符号链接：{path}"))
        os.chmod(path, mode)
        if uid is not None and gid is not None:
            os.chown(path, uid, gid)

    def _stop_existing_services(self) -> None:
        for name in UNITS:
            if (UNIT_DIR / name).exists():
                run(["systemctl", "stop", name], check=False)

    def _create_users(self) -> None:
        assert self.snapshot is not None
        requested = ["sbox5"]
        if self.settings.ddns.enabled:
            requested.append("sbox5-ddns")
        if self.settings.argo.enabled:
            requested.append("sbox5-argo")
        if self.upgrade or self.reconfigure:
            requested = sorted(set(requested + self.previous_state.get("users", [])))
        for name in requested:
            created = ensure_system_user(name, allow_existing=self.upgrade or self.reconfigure)
            if created:
                self.snapshot.manifest["users_created"].append(name)
        self.users = requested

    def _write_tokens(self) -> None:
        if self.settings.ddns.enabled:
            if not self.ddns_token and DDNS_TOKEN_PATH.is_file() and not DDNS_TOKEN_PATH.is_symlink():
                self.ddns_token = DDNS_TOKEN_PATH.read_text(encoding="utf-8").strip()
            if not self.ddns_token:
                raise ConfigError(tr("Enabling DDNS requires a Cloudflare Token", "启用 DDNS 需要 Cloudflare Token"))
            uid, gid = identity("sbox5-ddns")
            self._write(DDNS_TOKEN_PATH, (self.ddns_token + "\n").encode(), 0o600, uid, gid)
        else:
            self._remove(DDNS_TOKEN_PATH)
        if self.settings.argo.enabled and self.settings.argo.mode == "token":
            if not self.argo_token and ARGO_TOKEN_PATH.is_file() and not ARGO_TOKEN_PATH.is_symlink():
                self.argo_token = ARGO_TOKEN_PATH.read_text(encoding="utf-8").strip()
            if not self.argo_token:
                raise ConfigError(tr("Token mode requires an Argo Tunnel Token", "Token 模式需要 Argo Tunnel Token"))
            uid, gid = identity("sbox5-argo")
            self._write(ARGO_TOKEN_PATH, (self.argo_token + "\n").encode(), 0o600, uid, gid)
        else:
            self._remove(ARGO_TOKEN_PATH)

    def _write_settings(self) -> None:
        gid = identity("sbox5-ddns")[1] if self.settings.ddns.enabled else 0
        self._json(SETTINGS_PATH, self.settings.as_dict(), 0o640 if self.settings.ddns.enabled else 0o600, 0, gid)
        self._json(SECRETS_PATH, self.secrets.as_dict(), 0o600)

    def _ensure_rulesets(self, uid: int, gid: int) -> None:
        assert self.snapshot is not None
        desired = {item.tag: item for item in self.settings.routing.rule_sets}
        desired_filenames = {item.filename for item in desired.values()}
        if self.previous_settings is not None:
            for previous in self.previous_settings.routing.rule_sets:
                if previous.filename not in desired_filenames:
                    self._remove(rule_set_path(previous))
        for tag, item in desired.items():
            destination = rule_set_path(item)
            if destination.exists() and not destination.is_symlink() and sha256_file(destination) == item.sha256:
                continue
            data: bytes | None = None
            if tag in self.rule_set_files:
                source = self.rule_set_files[tag]
                if source.is_symlink() or not source.is_file():
                    raise ConfigError(tr(f"Rule-set source must be a regular file: {source}", f"规则集源必须是普通文件：{source}"))
                if source.stat().st_size > 64 * 1024 * 1024:
                    raise ConfigError(tr("The rule-set source is too large", "规则集源文件过大"))
                data = source.read_bytes()
            elif item.source_url:
                staging = STATE_DIR / "staging" / f"ruleset-{item.filename}"
                staging.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                download_verified_file(
                    item.source_url, item.sha256, staging, RULESET_ALLOWED_HOSTS,
                    max_size=64 * 1024 * 1024, mode=0o600,
                )
                data = staging.read_bytes()
                staging.unlink()
            elif destination.is_file() and not destination.is_symlink():
                data = destination.read_bytes()
            else:
                raise ConfigError(tr(
                    f"Rule-set {item.tag} is missing and has no source URL; add it with 'sbox5 route ruleset add'",
                    f"规则集 {item.tag} 缺失且没有源 URL；请使用 sbox5 route ruleset add 添加",
                ))
            if hashlib.sha256(data).hexdigest() != item.sha256:
                raise ConfigError(tr(f"Rule-set SHA256 mismatch: {item.tag}", f"规则集 SHA256 不符：{item.tag}"))
            self._write(destination, data, 0o640, uid, gid)

    def _configure_sysctl(self) -> None:
        assert self.snapshot is not None
        previous_records = self.previous_state.get("sysctls", [])
        previous_bbr = bool(self.previous_settings and self.previous_settings.bbr)
        if self.settings.bbr:
            if previous_bbr and previous_records:
                self.snapshot.manifest["sysctls"] = previous_records
            else:
                self.snapshot.manifest["sysctls"] = [
                    {"key": key, "before": run(["sysctl", "-n", key], check=False).stdout.strip(), "after": value}
                    for key, value in (("net.core.default_qdisc", "fq"), ("net.ipv4.tcp_congestion_control", "bbr"))
                ]
            records = configure_bbr(SYSCTL_PATH)
            self._record(SYSCTL_PATH)
            self.snapshot.manifest["sysctls"] = previous_records if previous_bbr and previous_records else records
            self.sysctls = self.snapshot.manifest["sysctls"]
        else:
            if previous_bbr:
                self.snapshot.manifest["sysctls"] = [
                    {"key": record["key"], "before": record["before"], "after": record.get("after", "")}
                    for record in previous_records
                ]
                for record in previous_records:
                    run(["sysctl", "-w", f"{record['key']}={record['before']}"])
            self._remove(SYSCTL_PATH)
            self.sysctls = []

    def _install_units(self) -> None:
        desired: dict[str, str] = {"sbox5.service": singbox_unit(self.settings)}
        if self.settings.argo.enabled:
            desired["sbox5-argo.service"] = argo_unit(self.settings)
        if self.settings.ddns.enabled:
            desired["sbox5-ddns.service"] = ddns_unit()
            desired["sbox5-ddns.timer"] = ddns_timer(self.settings.ddns.interval_seconds)
        if needs_firewall_service(self.settings):
            desired["sbox5-firewall.service"] = firewall_unit()
        for name in UNITS:
            path = UNIT_DIR / name
            if name in desired:
                atomic_text(path, desired[name], 0o644)
                self._record(path)
            else:
                run(["systemctl", "disable", name], check=False)
                self._remove(path)
        reload_systemd()

    def _rollback(self) -> None:
        if not self.snapshot:
            return
        shutil.rmtree(STATE_DIR / "staging", ignore_errors=True)
        self.snapshot.seal()
        command = ["python3", "-I", str(self.snapshot.path / "restore.py"), "--snapshot", str(self.snapshot.path), "--automatic", "--lang", get_language()]
        result = subprocess.run(command, text=True, capture_output=True, shell=False, check=False)
        if result.returncode != 0:
            raise ConflictError(tr(
                f"Installation failed and automatic rollback did not complete. The snapshot is kept at {self.snapshot.path}.\n"
                f"After checking, run: python3 {self.snapshot.path / 'restore.py'}\n{result.stderr.strip()}",
                f"安装失败且自动回滚未完成。快照保留在 {self.snapshot.path}。\n"
                f"请检查后运行：python3 {self.snapshot.path / 'restore.py'}\n{result.stderr.strip()}",
            ))

    def run(self) -> dict[str, Any]:
        preflight()
        warnings: list[str] = []
        argo_state: dict[str, Any] = {}
        fresh_markers = (
            CONFIG_DIR, Path("/usr/local/libexec/sbox5"), STATE_DIR,
            Path("/usr/local/bin/sbox5"), SYSCTL_PATH, *(UNIT_DIR / name for name in UNITS),
        )
        if self.upgrade or self.reconfigure:
            if not SETTINGS_PATH.is_file() or not SECRETS_PATH.is_file() or not STATE_PATH.is_file():
                raise ConfigError(tr("A complete existing sbox5 installation was not found; cannot reconfigure", "找不到完整的现有 sbox5 安装，不能重新配置"))
            self.previous_state = load_json(STATE_PATH)
            self.previous_settings = load_settings()
            self.sysctls = self.previous_state.get("sysctls", [])
        elif any(path.exists() for path in fresh_markers):
            raise ConflictError(tr("Existing sbox5 paths were detected; to avoid taking over unknown files, use upgrade or inspect them manually first", "检测到已存在的 sbox5 路径；为避免接管未知文件，请使用 upgrade 或先人工检查"))
        self.snapshot = Snapshot.create(
            SNAPSHOT_ROOT, self.project_root, managed_files(self.settings), _managed_directories(self.settings), UNITS,
            feature=self.feature,
        )
        try:
            if self.settings.ddns.enabled:
                self.snapshot.manifest["external_resources"].append({"type": "cloudflare-dns", "name": self.settings.ddns.record})
            if any(profile.mode == "acme" for profile in self.settings.active_certificate_profiles()):
                self.snapshot.manifest["external_resources"].append({"type": "acme-local-state", "name": tr("/var/lib/sbox5/acme (preserved on rollback)", "/var/lib/sbox5/acme（回滚保留）")})
            self._stop_existing_services()
            check_ports(self.settings)
            if not self.reconfigure:
                self.snapshot.manifest["packages"] = ensure_packages(self.settings)
            else:
                self.snapshot.manifest["packages"] = self.previous_state.get("packages", {
                    "installed_by_project": [], "upgraded_by_project": [], "removal_policy": "keep",
                })
            self._create_users()
            self._mkdir(CONFIG_DIR, 0o711)
            self._mkdir(CONFIG_DIR / "secrets", 0o711)
            singbox_uid, singbox_gid = identity("sbox5")
            self._mkdir(CONFIG_DIR / "tls", 0o750, singbox_uid, singbox_gid)
            self._mkdir(ACME_STATE_DIR, 0o700, singbox_uid, singbox_gid)
            self._mkdir(RULESET_DIR, 0o750, singbox_uid, singbox_gid)
            if self.settings.argo.enabled:
                argo_uid, argo_gid = identity("sbox5-argo")
                self._mkdir(ARGO_DIR, 0o700, argo_uid, argo_gid)
                if self.settings.argo.mode == "quick":
                    self._write(ARGO_LOG_PATH, b"", 0o600, argo_uid, argo_gid)
                else:
                    self._remove(ARGO_LOG_PATH)
            self._mkdir(STATE_DIR, 0o711)
            self._mkdir(SNAPSHOT_ROOT, 0o700)
            self._mkdir(EXPORT_DIR, 0o700)
            self._mkdir(Path("/var/lib/sbox5-runtime"), 0o700, singbox_uid, singbox_gid)
            if self.settings.ddns.enabled:
                ddns_uid, ddns_gid = identity("sbox5-ddns")
                self._mkdir(STATE_DIR / "ddns", 0o700, ddns_uid, ddns_gid)
            self._mkdir(BINARY_DIR, 0o755)
            self._write_tokens()
            self._write_settings()
            if self.reconfigure:
                if not SINGBOX_BINARY.is_file():
                    raise ConfigError(tr("The installed sing-box binary is missing; run upgrade first", "已安装的 sing-box 二进制缺失；请先执行 upgrade"))
                self.components = dict(self.previous_state.get("components", {}))
            else:
                self.components["sing-box"] = install_locked_binary(
                    "sing-box", architecture(), self.project_root, SINGBOX_BINARY, STATE_DIR / "staging",
                )
                self._record(SINGBOX_BINARY)
            run([str(SINGBOX_BINARY), "version"], timeout=30)
            if not self.secrets.reality_private_key or not self.secrets.reality_public_key:
                generate_reality_keypair(SINGBOX_BINARY, self.secrets)
                self._write_settings()
            if self.settings.argo.enabled:
                if not CLOUDFLARED_BINARY.is_file():
                    self.components["cloudflared"] = install_locked_binary(
                        "cloudflared", architecture(), self.project_root, CLOUDFLARED_BINARY, STATE_DIR / "staging",
                    )
                    self._record(CLOUDFLARED_BINARY)
                run([str(CLOUDFLARED_BINARY), "--version"], timeout=30)
            else:
                self._remove(CLOUDFLARED_BINARY)
                self.components.pop("cloudflared", None)
            if (STATE_DIR / "staging").exists():
                shutil.rmtree(STATE_DIR / "staging")
            for path in copy_application(self.project_root):
                self._record(path)
            self.snapshot.record_nft_owned("before")
            firewall_result = apply_firewall(
                self.settings,
                FIREWALL_STATE_PATH,
                lambda resource, action: self.snapshot.manifest["firewall"]["owned"].append({**resource, "action": action}),
            )
            self._record(FIREWALL_STATE_PATH)
            self.snapshot.record_nft_owned("after")
            if self.settings.ddns.enabled:
                result = CloudflareDDNS(self.settings.ddns, self.ddns_token).sync(DDNS_STATE_PATH)
                ddns_uid, ddns_gid = identity("sbox5-ddns")
                os.chown(DDNS_STATE_PATH, ddns_uid, ddns_gid)
                self._record(DDNS_STATE_PATH)
                self.snapshot.manifest["operations"].append({"type": "ddns.initial", "changes": result["changes"]})
            certificate_states: dict[str, dict[str, Any]] = {}
            if self.previous_settings is not None:
                current_profiles = {profile.id: profile for profile in self.settings.certificate_profiles}
                for previous_profile in self.previous_settings.certificate_profiles:
                    current_profile = current_profiles.get(previous_profile.id)
                    if current_profile is not None and current_profile.mode != "acme":
                        continue
                    self._remove(profile_certificate_path(previous_profile))
                    self._remove(profile_key_path(previous_profile))
                    try:
                        profile_certificate_path(previous_profile).parent.rmdir()
                    except OSError:
                        pass
            for profile in self.settings.certificate_profiles:
                if profile.mode != "imported" or profile.id not in self.import_files:
                    continue
                source_certificate, source_key = self.import_files[profile.id]
                if source_certificate.is_symlink() or source_key.is_symlink():
                    raise ConfigError(tr("Imported certificate files must not be symbolic links", "导入证书文件不能是符号链接"))
                if not source_certificate.is_file() or not source_key.is_file():
                    raise ConfigError(tr("Imported certificate files must be regular files", "导入证书文件必须是普通文件"))
                if source_certificate.stat().st_size > 1024 * 1024 or source_key.stat().st_size > 1024 * 1024:
                    raise ConfigError(tr("Imported certificate files are too large", "导入证书文件过大"))
                certificate_path = profile_certificate_path(profile)
                key_path = profile_key_path(profile)
                self._mkdir(certificate_path.parent, 0o750, singbox_uid, singbox_gid)
                self._write(certificate_path, source_certificate.read_bytes(), 0o640, singbox_uid, singbox_gid)
                self._write(key_path, source_key.read_bytes(), 0o600, singbox_uid, singbox_gid)
                certificate_metadata(certificate_path)
            for profile in self.settings.active_certificate_profiles():
                certificate_path = profile_certificate_path(profile)
                key_path = profile_key_path(profile)
                self._mkdir(certificate_path.parent, 0o750, singbox_uid, singbox_gid)
                if profile.mode == "self-signed":
                    previous_profile = None
                    if self.previous_settings is not None:
                        previous_profile = next(
                            (item for item in self.previous_settings.certificate_profiles if item.id == profile.id),
                            None,
                        )
                    preserve = (
                        self.upgrade
                        and certificate_path.is_file()
                        and key_path.is_file()
                        and previous_profile is not None
                        and previous_profile.server_name == profile.server_name
                    )
                    if preserve:
                        metadata = certificate_metadata(certificate_path)
                    else:
                        metadata = create_self_signed(profile, certificate_path, key_path, singbox_uid, singbox_gid)
                    self._record(certificate_path)
                    self._record(key_path)
                elif profile.mode == "imported":
                    metadata = imported_profile_state(profile)
                    self._record(certificate_path)
                    self._record(key_path)
                else:
                    self._mkdir(profile_acme_data_directory(profile), 0o700, singbox_uid, singbox_gid)
                    metadata = acme_profile_state(profile)
                certificate_states[profile.id] = metadata
            default_metadata = certificate_states.get("default", {})
            self._json(CERTIFICATES_STATE_PATH, certificate_states, 0o600)
            self._json(CERTIFICATE_STATE_PATH, default_metadata, 0o600)
            self._ensure_rulesets(singbox_uid, singbox_gid)
            self._write(SERVER_CONFIG_PATH, config_bytes(build_server_config(self.settings, self.secrets)), 0o640, singbox_uid, singbox_gid)
            check_server_config(SINGBOX_BINARY, SERVER_CONFIG_PATH)
            initial_argo_host = self.settings.argo.hostname if self.settings.argo.mode == "token" else ""
            exported = export_nodes(
                self.settings, self.secrets, CERTIFICATE_PATH, default_metadata, EXPORT_DIR,
                certificates=certificate_states, argo_host=initial_argo_host,
            )
            for path in EXPORT_DIR.iterdir():
                if path.is_file():
                    self._record(path)
            check_server_config(SINGBOX_BINARY, EXPORT_DIR / "sing-box-client.json")
            self._configure_sysctl()
            self._install_units()
            if (UNIT_DIR / "sbox5-firewall.service").exists():
                enable_start("sbox5-firewall.service")
                require_active("sbox5-firewall.service")
            enable_start("sbox5.service")
            require_active("sbox5.service")
            if self.settings.argo.enabled:
                enable_start("sbox5-argo.service")
                require_active("sbox5-argo.service")
                quick_url = ""
                if self.settings.argo.mode == "quick":
                    quick_url = wait_for_quick_url(ARGO_LOG_PATH, timeout=20)
                    if not quick_url:
                        warnings.append(tr(
                            "The Argo quick tunnel is active but its URL was not found in the log yet; run 'sbox5 argo status' or 'sbox5 export' later.",
                            "Argo 临时隧道已启动，但日志中尚未出现 URL；请稍后运行 sbox5 argo status 或 sbox5 export。",
                        ))
                    self._record(ARGO_LOG_PATH)
                else:
                    self._remove(ARGO_LOG_PATH)
                argo_state = write_argo_state(ARGO_STATE_PATH, self.settings, quick_url)
                self._record(ARGO_STATE_PATH)
                resolved_argo_host = argo_host(self.settings, argo_state)
                self.snapshot.manifest["external_resources"].append({
                    "type": "cloudflare-quick-tunnel" if self.settings.argo.mode == "quick" else "cloudflare-argo",
                    "name": quick_url or self.settings.argo.hostname or "pending",
                })
                if self.settings.argo.mode == "quick" and resolved_argo_host:
                    exported = export_nodes(
                        self.settings, self.secrets, CERTIFICATE_PATH, default_metadata, EXPORT_DIR,
                        certificates=certificate_states, argo_host=resolved_argo_host,
                    )
                    for path in EXPORT_DIR.iterdir():
                        if path.is_file():
                            self._record(path)
                    check_server_config(SINGBOX_BINARY, EXPORT_DIR / "sing-box-client.json")
            else:
                self._remove(ARGO_STATE_PATH)
                self._remove(ARGO_LOG_PATH)
            if self.settings.ddns.enabled:
                run(["systemctl", "start", "sbox5-ddns.service"], timeout=180)
                self._record(DDNS_STATE_PATH)
                enable_start("sbox5-ddns.timer")
                require_active("sbox5-ddns.timer")
            self.snapshot.record_nft_owned("after")
            for entry in self.snapshot.manifest["files"]:
                path = Path(entry["path"])
                if path.exists() or entry.get("after") is not None:
                    self._record(path)
            state = {
                "schema_version": 3,
                "project_version": __version__,
                "installed_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "components": self.components,
                "users": self.users,
                "sysctls": self.sysctls,
                "protocols": {name: protocol.as_dict() for name, protocol in self.settings.protocols.items()},
                "certificate_profiles": [profile.as_dict() for profile in self.settings.certificate_profiles],
                "certificates": certificate_states,
                "argo": argo_state,
                "warp": self.settings.warp.as_dict(),
                "warp_credential": self.secrets.warp.public_state(),
                "routing": self.settings.routing.as_dict(),
                "packages": self.snapshot.manifest["packages"],
                "managed_files": [entry["path"] for entry in self.snapshot.manifest["files"] if Path(entry["path"]).exists()],
                "snapshot_id": self.snapshot.manifest["snapshot_id"],
                "firewall": firewall_result,
            }
            self.snapshot.manifest["certificates"] = [
                {
                    "id": profile.id,
                    "mode": profile.mode,
                    "domains": list(profile.domains),
                    "challenge": profile.challenge,
                }
                for profile in self.settings.certificate_profiles
            ]
            self._json(STATE_PATH, state, 0o600)
            self._record(STATE_PATH)
            self.snapshot.commit()
            self.committed = True
            try:
                prune_snapshots(SNAPSHOT_ROOT, keep=5)
            except OSError as exc:
                print(tr(f"Warning: failed to clean up old snapshots: {exc}", f"警告：旧快照清理失败：{exc}"))
            return {
                "snapshot": str(self.snapshot.path),
                "exports": str(EXPORT_DIR),
                "files": exported["files"],
                "warnings": exported["warnings"] + firewall_result["warnings"] + warnings,
            }
        except Exception as exc:
            if self.committed:
                raise
            try:
                self._rollback()
            except Exception as rollback_error:
                raise ConflictError(f"{exc}\n{rollback_error}") from exc
            raise ConflictError(tr(f"Installation failed and was rolled back automatically. The snapshot is kept at {self.snapshot.path}. Reason: {exc}", f"安装失败，已自动回滚。快照保留在 {self.snapshot.path}。原因：{exc}")) from exc


def reconfigure(
    project_root: Path,
    settings: Settings,
    secrets: Secrets,
    feature: str = "reconfigure",
    import_files: dict[str, tuple[Path, Path]] | None = None,
    rule_set_files: dict[str, Path] | None = None,
    argo_token: str = "",
) -> dict[str, Any]:
    settings.validate()
    secrets.validate()
    return InstallTransaction(
        project_root, settings, secrets, upgrade=True, reconfigure=True, feature=feature,
        import_files=import_files, rule_set_files=rule_set_files, argo_token=argo_token,
    ).run()
