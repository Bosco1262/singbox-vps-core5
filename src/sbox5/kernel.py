# Copyright (C) 2026 Bosco1262
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

from datetime import datetime, timezone
import re
import subprocess
from pathlib import Path
from typing import Any

from .config import check_server_config
from .download import install_locked_binary
from .errors import ConfigError, ConflictError
from .i18n import get_language, tr
from .installer import (
    CORE_CACHE_DIR,
    CORE_STATE_PATH,
    SINGBOX_BINARY,
    STATE_DIR,
    STATE_PATH,
    UNITS,
    _managed_directories,
    managed_files,
)
from .models import Settings
from .services import require_active
from .snapshot import SNAPSHOT_ROOT, Snapshot, prune_snapshots
from .system import architecture
from .util import atomic_json, atomic_write, load_json, run


def parse_version(output: str) -> str:
    match = re.search(r"\b(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?)\b", output)
    return match.group(1) if match else ""


def current_version(binary: Path = SINGBOX_BINARY) -> str:
    if not binary.is_file():
        return ""
    result = run([str(binary), "version"], check=False, timeout=30)
    return parse_version(result.stdout + "\n" + result.stderr)


def _lock_for_version(project_root: Path, version: str) -> Path:
    candidates = [project_root / "locks" / "sing-box.json"]
    versions_dir = project_root / "locks" / "versions"
    if versions_dir.is_dir():
        candidates.extend(sorted(path for path in versions_dir.glob("*.json") if path.name != "index.json"))
    for path in candidates:
        if not path.is_file():
            continue
        try:
            lock = load_json(path)
        except (OSError, ValueError):
            continue
        if str(lock.get("version", "")) == version:
            return path
    raise ConfigError(tr(
        f"No immutable lock is configured for sing-box {version}",
        f"没有为 sing-box {version} 配置不可变锁文件",
    ))


def catalog(project_root: Path) -> dict[str, Any]:
    index_path = project_root / "locks" / "versions" / "index.json"
    index = load_json(index_path) if index_path.is_file() else {}
    channels = {str(key): str(value) for key, value in index.get("channels", {}).items() if value}
    versions: dict[str, dict[str, Any]] = {}
    base = project_root / "locks" / "sing-box.json"
    if base.is_file():
        lock = load_json(base)
        versions[str(lock["version"])] = {"lock": str(base.relative_to(project_root)), "channel": "stable"}
        channels.setdefault("stable", str(lock["version"]))
    versions_dir = project_root / "locks" / "versions"
    if versions_dir.is_dir():
        for path in sorted(versions_dir.glob("*.json")):
            if path.name == "index.json":
                continue
            try:
                lock = load_json(path)
            except (OSError, ValueError):
                continue
            version = str(lock.get("version", ""))
            if not version:
                continue
            versions[version] = {"lock": str(path.relative_to(project_root)), "channel": "custom"}
    return {"channels": channels, "versions": versions}


def status(project_root: Path) -> dict[str, Any]:
    core_state = load_json(CORE_STATE_PATH) if CORE_STATE_PATH.is_file() else {}
    return {
        "current": current_version(),
        "state": core_state,
        "catalog": catalog(project_root),
        "binary": str(SINGBOX_BINARY),
    }


def _track(snapshot: Snapshot, path: Path) -> None:
    target = str(path.absolute())
    if not any(entry["path"] == target for entry in snapshot.manifest["files"]):
        snapshot.track_new(path)
    snapshot.record_after(path)


def _rollback(snapshot: Snapshot) -> None:
    snapshot.seal()
    command = [
        "python3", "-I", str(snapshot.path / "restore.py"), "--snapshot", str(snapshot.path),
        "--automatic", "--lang", get_language(),
    ]
    result = subprocess.run(command, text=True, capture_output=True, shell=False, check=False)
    if result.returncode != 0:
        raise ConflictError(tr(
            f"Core switch failed and automatic rollback did not complete. Snapshot: {snapshot.path}\n{result.stderr.strip()}",
            f"内核切换失败且自动回滚未完成。快照：{snapshot.path}\n{result.stderr.strip()}",
        ))


def _activate(
    project_root: Path,
    settings: Settings,
    version: str,
    *,
    lock_path: Path | None = None,
    cached_binary: Path | None = None,
    feature: str = "core",
) -> dict[str, Any]:
    snapshot = Snapshot.create(
        SNAPSHOT_ROOT, project_root, managed_files(settings), _managed_directories(settings), UNITS,
        feature=feature,
    )
    try:
        CORE_CACHE_DIR.mkdir(parents=True, exist_ok=True, mode=0o755)
        old_version = current_version()
        old_data = SINGBOX_BINARY.read_bytes() if SINGBOX_BINARY.is_file() else b""
        if old_version and old_data:
            old_cache = CORE_CACHE_DIR / f"sing-box-{old_version}"
            if not old_cache.exists():
                atomic_write(old_cache, old_data, 0o755)
                _track(snapshot, old_cache)
        run(["systemctl", "stop", "sbox5.service"], check=False, timeout=90)
        config_path = Path("/etc/sbox5/config.json")
        if cached_binary is not None:
            if not cached_binary.is_file():
                raise ConfigError(tr(f"The cached sing-box binary is missing: {cached_binary}", f"缓存的 sing-box 二进制缺失：{cached_binary}"))
            if current_version(cached_binary) != version:
                raise ConfigError(tr("The cached binary version does not match the requested version", "缓存二进制版本与目标版本不一致"))
            check_server_config(cached_binary, config_path)
            new_data = cached_binary.read_bytes()
            component = {"component": "sing-box", "version": version, "source": "local-cache", "binary_sha256": None}
        else:
            staging = STATE_DIR / "staging" / f"sing-box-{version}"
            staging.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            component = install_locked_binary(
                "sing-box", architecture(), project_root, staging, STATE_DIR / "staging",
                lock_path=lock_path,
            )
            check_server_config(staging, config_path)
            new_data = staging.read_bytes()
        new_cache = CORE_CACHE_DIR / f"sing-box-{version}"
        atomic_write(new_cache, new_data, 0o755)
        _track(snapshot, new_cache)
        atomic_write(SINGBOX_BINARY, new_data, 0o755)
        _track(snapshot, SINGBOX_BINARY)
        if current_version(SINGBOX_BINARY) != version:
            raise ConfigError(tr("The activated sing-box binary returned an unexpected version", "已激活的 sing-box 二进制版本不符"))
        state = {
            "schema_version": 1,
            "current": version,
            "previous": old_version,
            "updated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        }
        atomic_json(CORE_STATE_PATH, state, 0o600)
        _track(snapshot, CORE_STATE_PATH)
        if STATE_PATH.is_file():
            main_state = load_json(STATE_PATH)
            main_state.setdefault("components", {})["sing-box"] = component
            atomic_json(STATE_PATH, main_state, 0o600)
            _track(snapshot, STATE_PATH)
        run(["systemctl", "start", "sbox5.service"], timeout=90)
        require_active("sbox5.service")
        snapshot.commit()
        try:
            prune_snapshots(SNAPSHOT_ROOT, keep=5)
        except OSError:
            pass
        return {"current": version, "previous": old_version, "snapshot": str(snapshot.path)}
    except Exception as exc:
        try:
            _rollback(snapshot)
        except Exception as rollback_error:
            raise ConflictError(f"{exc}\n{rollback_error}") from exc
        raise ConflictError(tr(
            f"Core switch failed and was rolled back. Snapshot: {snapshot.path}. Reason: {exc}",
            f"内核切换失败，已自动回滚。快照：{snapshot.path}。原因：{exc}",
        )) from exc


def switch(project_root: Path, settings: Settings, version: str) -> dict[str, Any]:
    lock_path = _lock_for_version(project_root, version)
    return _activate(project_root, settings, version, lock_path=lock_path)


def rollback(project_root: Path, settings: Settings) -> dict[str, Any]:
    state = load_json(CORE_STATE_PATH) if CORE_STATE_PATH.is_file() else {}
    previous = str(state.get("previous", ""))
    if not previous:
        raise ConfigError(tr("There is no previous sing-box version to roll back to", "没有可回滚的上一版 sing-box"))
    cached = CORE_CACHE_DIR / f"sing-box-{previous}"
    if not cached.is_file():
        raise ConfigError(tr(f"The previous binary cache is missing: {cached}", f"上一版二进制缓存缺失：{cached}"))
    return _activate(project_root, settings, previous, cached_binary=cached, feature="core-rollback")
