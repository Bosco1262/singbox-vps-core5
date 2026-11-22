# Copyright (C) 2026 Bosco1262
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

from datetime import datetime, timezone
import os
from pathlib import Path
import secrets
import shutil
import stat
from typing import Any, Iterable

from . import __version__
from .errors import ConflictError
from .i18n import tr
from .util import atomic_json, atomic_text, available, load_json, run, sha256_file

SNAPSHOT_ROOT = Path("/var/lib/sbox5/snapshots")


def _stat_metadata(path: Path) -> dict[str, Any]:
    info = path.stat()
    return {
        "sha256": sha256_file(path),
        "mode": f"{stat.S_IMODE(info.st_mode):04o}",
        "uid": info.st_uid,
        "gid": info.st_gid,
    }


def _service_state(name: str) -> dict[str, Any]:
    active = run(["systemctl", "is-active", name], check=False).stdout.strip() == "active"
    enabled_result = run(["systemctl", "is-enabled", name], check=False)
    enabled = enabled_result.returncode == 0 and enabled_result.stdout.strip() == "enabled"
    masked = enabled_result.stdout.strip() == "masked"
    existed = any(path.exists() for path in (
        Path("/etc/systemd/system") / name,
        Path("/usr/lib/systemd/system") / name,
        Path("/lib/systemd/system") / name,
    ))
    return {"name": name, "existed": existed, "was_active": active, "was_enabled": enabled, "was_masked": masked}


class Snapshot:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.manifest_path = path / "manifest.json"
        self.manifest = load_json(self.manifest_path)

    @classmethod
    def create(
        cls,
        root: Path,
        project_root: Path,
        files: Iterable[Path],
        directories: Iterable[Path],
        services: Iterable[str],
        packages: dict[str, Any] | None = None,
    ) -> "Snapshot":
        created_at = datetime.now(timezone.utc)
        snapshot_id = created_at.strftime("%Y%m%dT%H%M%SZ") + "-" + secrets.token_hex(4)
        path = root / snapshot_id
        if path.exists():
            raise ConflictError(tr(f"The snapshot already exists: {path}", f"快照已存在：{path}"))
        path.mkdir(parents=True, mode=0o700)
        os.chmod(path, 0o700)
        payload = path / "payload"
        payload.mkdir(mode=0o700)
        manifest: dict[str, Any] = {
            "schema_version": 1,
            "snapshot_id": snapshot_id,
            "created_at": created_at.isoformat().replace("+00:00", "Z"),
            "project_version": __version__,
            "state": "prepared",
            "files": [],
            "directories": [],
            "services": [],
            "firewall": {"snapshots": [], "owned": []},
            "cron": {"snapshot": "", "owned_blocks": []},
            "packages": packages or {"installed_by_project": [], "upgraded_by_project": [], "removal_policy": "keep"},
            "sysctls": [],
            "users_created": [],
            "operations": [],
            "external_resources": [],
            "recovery": {"entrypoint": "restore.py", "python_minimum": "3.10", "network_required": False},
        }
        for index, file_path in enumerate(dict.fromkeys(files)):
            file_path = file_path.absolute()
            entry: dict[str, Any] = {
                "id": f"file:{file_path}",
                "path": str(file_path),
                "owned_by_project": True,
                "existed": file_path.exists(),
                "backup": "",
                "before": None,
                "after": None,
            }
            if file_path.is_symlink():
                raise ConflictError(tr(f"Installation stopped to avoid following a symbolic link: {file_path}", f"为避免跟随符号链接，安装已停止：{file_path}"))
            if file_path.exists():
                if not file_path.is_file():
                    raise ConflictError(tr(f"The target path is not a regular file: {file_path}", f"目标路径不是普通文件：{file_path}"))
                entry["before"] = _stat_metadata(file_path)
                backup = Path("payload/files") / f"{index:04d}"
                destination = path / backup
                destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                shutil.copyfile(file_path, destination)
                os.chmod(destination, 0o600)
                entry["backup"] = str(backup)
            manifest["files"].append(entry)
        for directory in dict.fromkeys(directories):
            manifest["directories"].append({"path": str(directory.absolute()), "existed": directory.absolute().exists()})
        manifest["services"] = [_service_state(name) for name in dict.fromkeys(services)] if available("systemctl") else []
        cls._capture_firewall(path, manifest)
        cls._capture_cron(path, manifest)
        shutil.copyfile(project_root / "recovery" / "restore.py", path / "restore.py")
        os.chmod(path / "restore.py", 0o700)
        atomic_json(path / "manifest.json", manifest, 0o600)
        snapshot = cls(path)
        snapshot.seal()
        return snapshot

    @staticmethod
    def _capture_firewall(path: Path, manifest: dict[str, Any]) -> None:
        commands = (
            ("nftables", ["nft", "list", "ruleset"]),
            ("iptables", ["iptables-save"]),
            ("ip6tables", ["ip6tables-save"]),
            ("ufw", ["ufw", "status", "verbose"]),
        )
        for name, command in commands:
            if not available(command[0]):
                continue
            result = run(command, check=False)
            if result.returncode != 0:
                continue
            relative = Path("payload/firewall") / f"{name}.txt"
            destination = path / relative
            destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            atomic_text(destination, result.stdout, 0o600)
            manifest["firewall"]["snapshots"].append({
                "backend": name,
                "path": str(relative),
                "sha256": sha256_file(destination),
            })

    @staticmethod
    def _capture_cron(path: Path, manifest: dict[str, Any]) -> None:
        if not available("crontab"):
            return
        result = run(["crontab", "-l"], check=False)
        if result.returncode != 0:
            return
        relative = Path("payload/cron/root")
        destination = path / relative
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        atomic_text(destination, result.stdout, 0o600)
        manifest["cron"] = {"snapshot": str(relative), "sha256": sha256_file(destination), "owned_blocks": []}

    def track_new(self, file_path: Path) -> None:
        file_path = file_path.absolute()
        target = str(file_path)
        if any(entry["path"] == target for entry in self.manifest["files"]):
            return
        if file_path.is_symlink() or not file_path.is_file():
            raise ConflictError(tr(f"Only regular files created by the project can be tracked: {target}", f"只能跟踪项目新建的普通文件：{target}"))
        self.manifest["files"].append({
            "id": f"file:{target}",
            "path": target,
            "owned_by_project": True,
            "existed": False,
            "backup": "",
            "before": None,
            "after": None,
        })

    def record_after(self, file_path: Path) -> None:
        target = str(file_path.absolute())
        for entry in self.manifest["files"]:
            if entry["path"] == target:
                entry["after"] = _stat_metadata(file_path.absolute()) if file_path.absolute().exists() else None
                self.manifest["operations"].append({"id": entry["id"], "type": "file.install", "after": entry["after"]})
                return
        raise ConflictError(tr(f"Attempted to record a file outside the transaction: {target}", f"尝试记录未纳入事务的文件：{target}"))

    def record_nft_owned(self, stage: str) -> None:
        if stage not in ("before", "after") or not available("nft"):
            return
        result = run(["nft", "list", "table", "inet", "sbox5"], check=False)
        content = result.stdout if result.returncode == 0 else ""
        relative = ""
        if content:
            path = Path("payload/firewall") / f"owned-nft-{stage}.nft"
            atomic_text(self.path / path, content, 0o600)
            relative = str(path)
        owned = self.manifest["firewall"]["owned"]
        item = next((entry for entry in owned if entry.get("kind") == "nft-table" and entry.get("name") == "sbox5"), None)
        if item is None:
            if stage == "after":
                return
            item = {"kind": "nft-table", "name": "sbox5"}
            owned.append(item)
        item[stage] = relative

    def seal(self) -> None:
        atomic_json(self.manifest_path, self.manifest, 0o600)
        entries: list[str] = []
        for file_path in sorted(self.path.rglob("*")):
            if not file_path.is_file() or file_path.name == "SHA256SUMS":
                continue
            relative = file_path.relative_to(self.path)
            entries.append(f"{sha256_file(file_path)}  {relative.as_posix()}")
        atomic_text(self.path / "SHA256SUMS", "\n".join(entries) + "\n", 0o600)

    def commit(self) -> None:
        self.manifest["state"] = "committed"
        self.seal()


def prune_snapshots(root: Path, keep: int = 3) -> None:
    if keep < 1 or not root.exists():
        return
    snapshots: list[Path] = []
    for path in root.iterdir():
        if not path.is_dir() or path.is_symlink() or path.name.startswith("pre-restore-"):
            continue
        try:
            manifest = load_json(path / "manifest.json")
        except (OSError, ValueError):
            continue
        if manifest.get("state") == "committed":
            snapshots.append(path)
    snapshots.sort(key=lambda path: path.name, reverse=True)
    for old in snapshots[keep:]:
        shutil.rmtree(old)
