# Copyright (C) 2026 Bosco1262
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import argparse
import grp
from pathlib import Path
import pwd
import subprocess
import sys

from .errors import ConfigError, ConflictError
from .firewall import apply_firewall
from .i18n import get_language, tr
from .installer import (
    FIREWALL_STATE_PATH,
    STATE_PATH,
    UNITS,
    load_settings,
    managed_files,
    _managed_directories,
)
from .snapshot import SNAPSHOT_ROOT, Snapshot, prune_snapshots
from .util import available, load_json, require_linux_root, run


def _rollback(snapshot: Snapshot) -> None:
    result = subprocess.run([
        "python3", "-I", str(snapshot.path / "restore.py"), "--snapshot", str(snapshot.path), "--automatic", "--lang", get_language(),
    ], text=True, capture_output=True, shell=False, check=False)
    if result.returncode != 0:
        raise ConflictError(tr(f"Uninstall failed and automatic restore did not complete; restore manually with snapshot {snapshot.path}: {result.stderr.strip()}", f"卸载失败且自动恢复未完成，请使用快照 {snapshot.path} 人工恢复：{result.stderr.strip()}"))


def uninstall(args: argparse.Namespace) -> int:
    require_linux_root()
    if not STATE_PATH.is_file():
        raise ConfigError(tr("No sbox5 installation state was found", "没有找到 sbox5 安装状态"))
    if args.non_interactive and not args.yes:
        raise ConfigError(tr("Non-interactive uninstall requires an explicit --yes", "非交互卸载必须显式指定 --yes"))
    if not args.yes and sys.stdin.isatty():
        if input(tr("Remove sbox5 files, services, project firewall rules, and users? Snapshots and packages are kept. [y/N] ", "确认移除 sbox5 文件、服务、项目防火墙规则和用户吗？快照与软件包会保留。[y/N] ")).strip().lower() not in ("y", "yes"):
            raise ConfigError(tr("User cancelled the uninstall", "用户取消卸载"))
    elif not args.yes:
        raise ConfigError(tr("Use --yes to confirm the uninstall", "请使用 --yes 确认卸载"))
    settings = load_settings()
    state = load_json(STATE_PATH)
    snapshot = Snapshot.create(
        SNAPSHOT_ROOT, Path(args.project_root), managed_files(settings), _managed_directories(settings), UNITS,
        feature="uninstall",
    )
    snapshot.record_nft_owned("before")
    if FIREWALL_STATE_PATH.is_file():
        for resource in load_json(FIREWALL_STATE_PATH).get("owned", []):
            if resource.get("kind") != "nft-table":
                snapshot.manifest["firewall"]["owned"].append({**resource, "action": "remove"})
    users_removed = []
    for name in state.get("users", []):
        if name not in ("sbox5", "sbox5-ddns", "sbox5-argo", "sbox5-sub"):
            raise ConflictError(tr(f"The state file contains a user outside this project: {name}", f"状态文件包含非项目用户：{name}"))
        try:
            account = pwd.getpwnam(name)
        except KeyError:
            continue
        users_removed.append({"name": name, "uid": account.pw_uid, "gid": account.pw_gid})
    snapshot.manifest["users_removed"] = users_removed
    sysctl_records = []
    for record in state.get("sysctls", []):
        current = run(["sysctl", "-n", record["key"]], check=False).stdout.strip()
        if current:
            sysctl_records.append({"key": record["key"], "before": current, "after": record.get("after", "")})
    snapshot.manifest["sysctls"] = sysctl_records
    for entry in snapshot.manifest["files"]:
        path = Path(entry["path"])
        if path.exists():
            snapshot.record_after(path)
        entry["removing"] = True
    snapshot.commit()
    try:
        for name in UNITS:
            run(["systemctl", "stop", name], check=False)
            run(["systemctl", "disable", name], check=False)
        settings.manage_firewall = False
        apply_firewall(settings, FIREWALL_STATE_PATH)
        if FIREWALL_STATE_PATH.is_file():
            tracked = {entry["path"] for entry in snapshot.manifest["files"]}
            if str(FIREWALL_STATE_PATH.absolute()) not in tracked:
                snapshot.track_new(FIREWALL_STATE_PATH)
            snapshot.record_after(FIREWALL_STATE_PATH)
            snapshot.seal()
        if available("nft") and run(["nft", "list", "table", "inet", "sbox5"], check=False).returncode == 0:
            run(["nft", "delete", "table", "inet", "sbox5"], check=True)
        for entry in sorted(snapshot.manifest["files"], key=lambda item: len(Path(item["path"]).parts), reverse=True):
            path = Path(entry["path"])
            if path.is_symlink():
                raise ConflictError(tr(f"A symbolic link was found during uninstall; stopped: {path}", f"卸载期间发现符号链接，已停止：{path}"))
            if path.exists():
                if not path.is_file():
                    raise ConflictError(tr(f"The uninstall target is not a regular file: {path}", f"卸载目标不是普通文件：{path}"))
                path.unlink()
        for record in state.get("sysctls", []):
            if record.get("before"):
                run(["sysctl", "-w", f"{record['key']}={record['before']}"], check=True)
        for name in users_removed:
            run(["userdel", name["name"]], check=True)
            try:
                grp.getgrnam(name["name"])
            except KeyError:
                pass
            else:
                run(["groupdel", name["name"]], check=False)
        preserved = {
            SNAPSHOT_ROOT, Path("/var/lib/sbox5"), Path("/var/lib/sbox5/acme"),
            Path("/etc/sbox5/acme"), Path("/var/log/sbox5-acme"),
        }
        for item in sorted(_managed_directories(settings), key=lambda path: len(path.parts), reverse=True):
            if item in preserved or any(parent in preserved for parent in item.parents):
                continue
            if item.is_dir() and not item.is_symlink():
                try:
                    item.rmdir()
                except OSError:
                    pass
        run(["systemctl", "daemon-reload"], check=True)
    except Exception as exc:
        try:
            _rollback(snapshot)
        except Exception as rollback_error:
            raise ConflictError(f"{exc}\n{rollback_error}") from exc
        raise ConflictError(tr(f"Uninstall failed and was restored automatically. Snapshot: {snapshot.path}. Reason: {exc}", f"卸载失败，已自动恢复。快照：{snapshot.path}。原因：{exc}")) from exc
    prune_snapshots(SNAPSHOT_ROOT, keep=5)
    print(tr("Uninstall completed. Standalone restore snapshot: ", "卸载完成。独立恢复快照：") + str(snapshot.path))
    print(tr("APT packages, the native ACME account store, and remote Cloudflare resources have not been deleted.", "APT 软件包、原生 ACME 账户库和远端 Cloudflare 资源均未删除。"))
    return 0
