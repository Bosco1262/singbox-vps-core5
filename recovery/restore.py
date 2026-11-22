# Copyright (C) 2026 Bosco1262
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import locale
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import Any

_LANGUAGE = "en"


def _normalize_language(raw: str | None) -> str | None:
    if not raw:
        return None
    value = raw.strip().lower().replace("_", "-")
    if value.startswith("zh"):
        return "zh-CN"
    if value.startswith("en"):
        return "en"
    return None


def _detect_language() -> str | None:
    for name in ("LC_ALL", "LC_MESSAGES", "LANG", "LANGUAGE"):
        detected = _normalize_language(os.environ.get(name))
        if detected:
            return detected
    try:
        detected = _normalize_language(locale.getdefaultlocale()[0])
        if detected:
            return detected
    except Exception:
        pass
    return None


def _resolve_language(argv: list[str]) -> str:
    index = 0
    while index < len(argv):
        argument = argv[index]
        if argument in ("-l", "--lang", "--language"):
            if index + 1 < len(argv):
                detected = _normalize_language(argv[index + 1])
                if detected:
                    return detected
            index += 2
            continue
        for prefix in ("-l=", "--lang=", "--language="):
            if argument.startswith(prefix):
                detected = _normalize_language(argument[len(prefix):])
                if detected:
                    return detected
        index += 1
    return _detect_language() or "en"


def tr(en_text: str, zh_text: str) -> str:
    return zh_text if _LANGUAGE == "zh-CN" else en_text


def fail(message: str) -> None:
    raise RuntimeError(message)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run(command: list[str], check: bool = False) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(command, text=True, capture_output=True, shell=False, check=False)
    if check and result.returncode != 0:
        fail(tr(f"{command[0]} failed: {(result.stderr or result.stdout).strip()}", f"{command[0]} 执行失败：{(result.stderr or result.stdout).strip()}"))
    return result


def relative(value: str) -> PurePosixPath:
    path = PurePosixPath(value)
    if not value or path.is_absolute() or ".." in path.parts or "\\" in value or "\x00" in value:
        fail(tr("The snapshot contains an unsafe relative path", "快照包含不安全的相对路径"))
    return path


def _allowed_target(path: PurePosixPath) -> bool:
    return (
        path == PurePosixPath("/usr/local/bin/sbox5")
        or path == PurePosixPath("/etc/sysctl.d/99-sbox5.conf")
        or any(root in path.parents for root in (PurePosixPath("/etc/sbox5"), PurePosixPath("/usr/local/libexec/sbox5"), PurePosixPath("/var/lib/sbox5")))
        or (path.parent == PurePosixPath("/etc/systemd/system") and path.name.startswith("sbox5"))
    )


def _allowed_directory(path: PurePosixPath) -> bool:
    return path in (PurePosixPath("/var/lib/sbox5-runtime"), PurePosixPath("/var/log/sbox5-acme")) or any(
        root == path or root in path.parents
        for root in (PurePosixPath("/etc/sbox5"), PurePosixPath("/usr/local/libexec/sbox5"), PurePosixPath("/var/lib/sbox5"))
    )


def _metadata(value: Any, label: str) -> None:
    if not isinstance(value, dict):
        fail(tr(f"Invalid snapshot metadata: {label}", f"快照元数据无效：{label}"))
    if not re.fullmatch(r"[0-9a-f]{64}", str(value.get("sha256", ""))):
        fail(tr(f"Invalid snapshot hash: {label}", f"快照哈希无效：{label}"))
    if not re.fullmatch(r"[0-7]{3,4}", str(value.get("mode", ""))):
        fail(tr(f"Invalid snapshot permissions: {label}", f"快照权限无效：{label}"))
    if not isinstance(value.get("uid"), int) or not isinstance(value.get("gid"), int):
        fail(tr(f"Invalid snapshot ownership: {label}", f"快照属主无效：{label}"))


def validate_manifest(manifest: dict[str, Any], verified: set[str]) -> None:
    for entry in manifest.get("files", []):
        value = entry.get("path")
        if not isinstance(value, str):
            fail(tr("Invalid snapshot file path", "快照文件路径无效"))
        target = PurePosixPath(value)
        if not target.is_absolute() or not _allowed_target(target):
            fail(tr(f"The snapshot contains a non-project restore target: {value}", f"快照包含非项目恢复目标：{value}"))
        if not isinstance(entry.get("existed"), bool) or not isinstance(entry.get("owned_by_project"), bool):
            fail(tr(f"Invalid snapshot file record: {value}", f"快照文件记录无效：{value}"))
        for stage in ("before", "after"):
            if entry.get(stage) is not None:
                _metadata(entry[stage], value)
        if entry.get("existed"):
            if not entry.get("backup") or str(entry["backup"]) not in verified:
                fail(tr(f"The file backup is not covered by SHA256SUMS: {value}", f"文件备份未纳入 SHA256SUMS：{value}"))
        elif entry.get("backup"):
            fail(tr(f"A missing file must not have a backup: {value}", f"不存在的文件不应包含备份：{value}"))
    for directory in manifest.get("directories", []):
        value = directory.get("path")
        if not isinstance(value, str):
            fail(tr("Invalid snapshot directory path", "快照目录路径无效"))
        path = PurePosixPath(value)
        if not path.is_absolute() or not _allowed_directory(path):
            fail(tr(f"The snapshot contains a non-project directory: {value}", f"快照包含非项目目录：{value}"))
    for service in manifest.get("services", []):
        if not re.fullmatch(r"sbox5[a-z0-9_.-]*", str(service.get("name", ""))):
            fail(tr("The snapshot contains a non-project service", "快照包含非项目服务"))
    for record in manifest.get("users_removed", []):
        if record.get("name") not in ("sbox5", "sbox5-ddns", "sbox5-argo"):
            fail(tr("The snapshot contains a non-project user", "快照包含非项目用户"))
        if not isinstance(record.get("uid"), int) or not isinstance(record.get("gid"), int) or record["uid"] <= 0 or record["gid"] <= 0:
            fail(tr("The snapshot contains an invalid user ID", "快照包含无效的用户 ID"))
    for username in manifest.get("users_created", []):
        if username not in ("sbox5", "sbox5-ddns", "sbox5-argo"):
            fail(tr("The snapshot contains a non-project user", "快照包含非项目用户"))
    for record in manifest.get("sysctls", []):
        if record.get("key") not in ("net.core.default_qdisc", "net.ipv4.tcp_congestion_control"):
            fail(tr("The snapshot contains a non-project sysctl", "快照包含非项目 sysctl"))
        if not isinstance(record.get("before"), str) or not record["before"]:
            fail(tr("Invalid sysctl record in the snapshot", "快照中的 sysctl 记录无效"))
    for item in manifest.get("firewall", {}).get("owned", []):
        kind = item.get("kind")
        if item.get("action", "add") not in ("add", "remove"):
            fail(tr("Invalid firewall action in the snapshot", "快照中的防火墙动作无效"))
        if kind == "nft-table":
            if not re.fullmatch(r"sbox5[a-z0-9_]*", str(item.get("name", ""))):
                fail(tr("Invalid nftables table name in the snapshot", "快照中的 nftables 表名无效"))
            for key in ("before", "after"):
                if item.get(key) and str(item[key]) not in verified:
                    fail(tr(f"The firewall backup is not covered by SHA256SUMS: {item[key]}", f"防火墙备份未纳入 SHA256SUMS：{item[key]}"))
        elif kind == "iptables-rule":
            spec = item.get("spec")
            if (
                not isinstance(item.get("ipv6"), bool)
                or item.get("table") not in ("filter", "nat")
                or item.get("chain") not in ("INPUT", "PREROUTING")
                or not isinstance(spec, list) or not spec or not all(isinstance(part, str) and part and "\x00" not in part for part in spec)
            ):
                fail(tr("Invalid iptables rule in the snapshot", "快照中的 iptables 规则无效"))
        elif kind == "ufw-rule":
            try:
                port = int(item.get("port"))
            except (TypeError, ValueError):
                fail(tr("Invalid UFW rule port in the snapshot", "快照中的 UFW 规则端口无效"))
            if not 1 <= port <= 65535 or item.get("protocol") not in ("tcp", "udp"):
                fail(tr("Invalid UFW rule in the snapshot", "快照中的 UFW 规则无效"))
            if not re.fullmatch(r"[a-z0-9-]+", str(item.get("name", "restored"))):
                fail(tr("Invalid UFW rule name in the snapshot", "快照中的 UFW 规则名称无效"))
        else:
            fail(tr(f"The snapshot contains an unknown firewall resource: {kind}", f"快照包含未知防火墙资源：{kind}"))


def verify_snapshot(snapshot: Path) -> dict[str, Any]:
    sums = snapshot / "SHA256SUMS"
    manifest_path = snapshot / "manifest.json"
    if not sums.is_file() or not manifest_path.is_file():
        fail(tr("The snapshot is missing manifest.json or SHA256SUMS", "快照缺少 manifest.json 或 SHA256SUMS"))
    verified: set[str] = set()
    for line in sums.read_text(encoding="utf-8").splitlines():
        expected, separator, name = line.partition("  ")
        if not separator or not re.fullmatch(r"[0-9a-f]{64}", expected):
            fail(tr("Invalid SHA256SUMS format", "SHA256SUMS 格式无效"))
        path = snapshot / relative(name)
        if not path.is_file() or sha256(path) != expected:
            fail(tr(f"Snapshot verification failed: {name}", f"快照校验失败：{name}"))
        verified.add(name)
    if "manifest.json" not in verified or "restore.py" not in verified:
        fail(tr("The snapshot verification manifest is incomplete", "快照校验清单不完整"))
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("schema_version") != 1:
        fail(tr("Unsupported snapshot format", "不支持的快照格式"))
    validate_manifest(manifest, verified)
    return manifest


def atomic_restore(source: Path, destination: Path, metadata: dict[str, Any]) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{destination.name}.restore.", dir=destination.parent)
    temp_path = Path(temporary)
    try:
        with os.fdopen(fd, "wb") as output, source.open("rb") as input_file:
            shutil.copyfileobj(input_file, output)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temp_path, int(metadata["mode"], 8))
        os.chown(temp_path, int(metadata["uid"]), int(metadata["gid"]))
        os.replace(temp_path, destination)
    finally:
        if temp_path.exists():
            temp_path.unlink()


def save_current(manifest: dict[str, Any], snapshot: Path) -> Path:
    prefix = "pre-restore-" + datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-"
    backup = Path(tempfile.mkdtemp(prefix=prefix, dir=snapshot.parent))
    os.chmod(backup, 0o700)
    records: list[dict[str, Any]] = []
    for entry in manifest["files"]:
        path = Path(entry["path"])
        if not path.is_file() or path.is_symlink():
            continue
        destination = backup / "files" / str(len(records))
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        shutil.copyfile(path, destination)
        info = path.stat()
        records.append({
            "path": str(path),
            "backup": str(destination.relative_to(backup)),
            "mode": f"{stat.S_IMODE(info.st_mode):04o}",
            "uid": info.st_uid,
            "gid": info.st_gid,
            "sha256": sha256(path),
        })
        os.chmod(destination, 0o600)
    (backup / "manifest.json").write_text(json.dumps(records, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.chmod(backup / "manifest.json", 0o600)
    return backup


def find_conflicts(manifest: dict[str, Any], snapshot: Path, structural_only: bool = False) -> list[str]:
    conflicts: list[str] = []
    for entry in manifest["files"]:
        path = Path(entry["path"])
        after = entry.get("after")
        symlink_parent = next((parent for parent in path.parents if parent != Path("/") and parent.is_symlink()), None)
        if path.is_symlink() or symlink_parent:
            conflicts.append(tr(f"The target or its parent directory is now a symbolic link: {path}", f"目标或父目录已变成符号链接：{path}"))
            continue
        if structural_only:
            if path.exists() and not path.is_file():
                conflicts.append(tr(f"The target is no longer a regular file: {path}", f"目标已不是普通文件：{path}"))
            continue
        if manifest.get("state") == "prepared" and not entry.get("existed") and not after and path.exists():
            conflicts.append(tr(f"A file not covered by the snapshot appeared before the transaction was interrupted: {path}", f"事务中断前已出现未纳入快照的文件：{path}"))
            continue
        if entry.get("removing"):
            if after and path.exists() and (not path.is_file() or sha256(path) != after["sha256"]):
                conflicts.append(tr(f"The original file in the uninstall snapshot has changed: {path}", f"卸载快照中的原文件已发生变化：{path}"))
            elif not after and path.exists() and not entry.get("existed"):
                conflicts.append(tr(f"An unregistered file appeared after the uninstall snapshot: {path}", f"卸载快照完成后出现未登记的文件：{path}"))
            continue
        if after and not path.exists():
            conflicts.append(tr(f"The file was deleted after installation: {path}", f"安装后文件已被删除：{path}"))
        elif after and (not path.is_file() or sha256(path) != after["sha256"]):
            conflicts.append(tr(f"The file was modified again after installation: {path}", f"安装后文件又被修改：{path}"))
        if not after and path.exists():
            if entry.get("existed") and entry.get("before"):
                if not path.is_file() or sha256(path) != entry["before"]["sha256"]:
                    conflicts.append(tr(f"After the interrupted transaction, the file differs from its pre-snapshot state: {path}", f"事务中断后文件与快照前状态不一致：{path}"))
            elif not entry.get("existed") and manifest.get("state") == "committed":
                conflicts.append(tr(f"An unregistered file change appeared after the snapshot: {path}", f"快照完成后出现未登记的文件变化：{path}"))
    if structural_only:
        return conflicts
    for item in manifest.get("firewall", {}).get("owned", []):
        if item.get("kind") == "nft-table" and item.get("after"):
            current = run(["nft", "list", "table", "inet", item["name"]])
            expected = (snapshot / relative(item["after"])).read_text(encoding="utf-8")
            if current.returncode != 0 or current.stdout != expected:
                conflicts.append(tr("The project nftables table was modified again after installation", "安装后项目 nftables 表又被修改"))
    return conflicts


def remove_firewall(manifest: dict[str, Any], snapshot: Path) -> list[str]:
    messages: list[str] = []
    for item in manifest.get("firewall", {}).get("owned", []):
        kind = item.get("kind")
        if kind == "nft-table" and re.fullmatch(r"sbox5[a-z0-9_]*", item.get("name", "")):
            name = item["name"]
            if run(["nft", "list", "table", "inet", name]).returncode == 0:
                run(["nft", "delete", "table", "inet", name], check=True)
                messages.append(tr(f"Deleted nftables table {name}", f"已删除 nftables table {name}"))
            if item.get("before"):
                run(["nft", "-f", str(snapshot / relative(item["before"]))], check=True)
                messages.append(tr(f"Restored nftables table {name}", f"已恢复 nftables table {name}"))
        elif kind == "iptables-rule":
            executable = "ip6tables" if item.get("ipv6") else "iptables"
            table = item.get("table")
            chain = item.get("chain")
            spec = item.get("spec")
            action = item.get("action", "add")
            if action not in ("add", "remove") or table not in ("filter", "nat") or chain not in ("INPUT", "PREROUTING") or not isinstance(spec, list):
                fail(tr("Invalid firewall rule in the snapshot", "快照中的防火墙规则无效"))
            if action == "remove":
                if run([executable, "-t", table, "-C", chain, *spec]).returncode != 0:
                    run([executable, "-t", table, "-I", chain, "1", *spec], check=True)
                    messages.append(tr(f"Restored {executable} project rules", f"已恢复 {executable} 项目规则"))
            elif run([executable, "-t", table, "-D", chain, *spec]).returncode == 0:
                messages.append(tr(f"Deleted {executable} project rules", f"已删除 {executable} 项目规则"))
        elif kind == "ufw-rule":
            port = int(item["port"])
            protocol = item["protocol"]
            action = item.get("action", "add")
            if action not in ("add", "remove") or not 1 <= port <= 65535 or protocol not in ("tcp", "udp"):
                fail(tr("Invalid UFW rule in the snapshot", "快照中的 UFW 规则无效"))
            if action == "remove":
                name = item.get("name", "restored")
                if not re.fullmatch(r"[a-z0-9-]+", name):
                    fail(tr("Invalid UFW rule name in the snapshot", "快照中的 UFW 规则名称无效"))
                run(["ufw", "allow", f"{port}/{protocol}", "comment", f"sbox5-{name}"], check=True)
                messages.append(tr(f"Restored UFW {port}/{protocol}", f"已恢复 UFW {port}/{protocol}"))
            elif run(["ufw", "--force", "delete", "allow", f"{port}/{protocol}"]).returncode == 0:
                messages.append(tr(f"Deleted UFW {port}/{protocol}", f"已删除 UFW {port}/{protocol}"))
    return messages


def restore(snapshot: Path, assume_yes: bool, automatic: bool) -> None:
    if os.name != "posix" or os.geteuid() != 0:
        fail(tr("Restore requires Linux root privileges", "恢复需要 Linux root 权限"))
    manifest = verify_snapshot(snapshot)
    conflicts = find_conflicts(manifest, snapshot, structural_only=automatic)
    if conflicts and automatic:
        fail(tr("Automatic rollback found conflicts:\n", "自动回滚发现冲突：\n") + "\n".join(conflicts))
    if conflicts and not assume_yes:
        print(tr("Additional modifications made after installation were detected:", "检测到安装后的额外修改："))
        for conflict in conflicts:
            print(" - " + conflict)
        if input(tr("The current state has been saved. Continue restoring anyway? [y/N] ", "已保存当前状态，仍要继续恢复吗？[y/N] ")).strip().lower() not in ("y", "yes"):
            fail(tr("User cancelled the restore", "用户取消恢复"))
    elif conflicts and assume_yes:
        fail(tr("Post-install conflicts were detected; run without --yes to confirm them one by one:\n", "检测到安装后冲突；请不带 --yes 运行以逐项确认：\n") + "\n".join(conflicts))
    current_backup = save_current(manifest, snapshot)
    services = manifest.get("services", [])
    for service in services:
        run(["systemctl", "stop", service["name"]], check=False)
    for service in services:
        if not service.get("existed"):
            run(["systemctl", "disable", service["name"]], check=False)
    for record in manifest.get("users_removed", []):
        import grp
        import pwd
        name = record["name"]
        uid, gid = record["uid"], record["gid"]
        try:
            account = pwd.getpwnam(name)
            if account.pw_uid != uid or account.pw_gid != gid:
                fail(tr(f"Project user ID conflict: {name}", f"项目用户 ID 发生冲突：{name}"))
        except KeyError:
            try:
                grp.getgrgid(gid)
            except KeyError:
                run(["groupadd", "--system", "--gid", str(gid), name], check=True)
            run(["useradd", "--system", "--uid", str(uid), "--gid", str(gid), "--no-create-home", "--shell", "/usr/sbin/nologin", name], check=True)
    for entry in sorted(manifest["files"], key=lambda item: len(PurePosixPath(item["path"]).parts), reverse=True):
        path = Path(entry["path"])
        if entry.get("existed"):
            source = snapshot / relative(entry["backup"])
            atomic_restore(source, path, entry["before"])
        elif entry.get("owned_by_project") and path.exists():
            if path.is_symlink() or not path.is_file():
                fail(tr(f"Refusing to delete a non-regular file: {path}", f"拒绝删除非普通文件：{path}"))
            path.unlink()
    firewall_messages = remove_firewall(manifest, snapshot)
    for record in manifest.get("sysctls", []):
        run(["sysctl", "-w", f"{record['key']}={record['before']}"], check=True)
    run(["systemctl", "daemon-reload"])
    for service in services:
        name = service["name"]
        if service.get("existed"):
            if service.get("was_enabled"):
                run(["systemctl", "enable", name], check=True)
            else:
                run(["systemctl", "disable", name])
            if service.get("was_active"):
                run(["systemctl", "start", name], check=True)
    for directory in sorted(manifest.get("directories", []), key=lambda item: len(PurePosixPath(item["path"]).parts), reverse=True):
        path = Path(directory["path"])
        if directory.get("existed") or not path.is_dir() or path.is_symlink():
            continue
        if path in (Path("/var/lib/sbox5"), Path("/var/lib/sbox5/snapshots")):
            continue
        try:
            path.rmdir()
        except OSError:
            pass
    for username in manifest.get("users_created", []):
        run(["userdel", username], check=False)
        try:
            import grp
            group = grp.getgrnam(username)
        except KeyError:
            continue
        if not group.gr_mem:
            run(["groupdel", username], check=False)
    print(tr("Restore completed. The pre-restore state was saved to: ", "恢复完成。恢复前状态已保存到：") + str(current_backup))
    for message in firewall_messages:
        print(message)
    if manifest.get("packages", {}).get("installed_by_project"):
        print(tr("Packages were kept per the safety policy and not removed automatically.", "软件包按安全策略保留，未自动删除。"))
    external = manifest.get("external_resources", [])
    if external:
        print(tr("The following external resources were not modified by the offline restorer:", "以下外部资源未被离线恢复器修改："))
        for item in external:
            print(f" - {item.get('type')}: {item.get('name')}")


def main() -> int:
    global _LANGUAGE
    _LANGUAGE = _resolve_language(sys.argv[1:])
    parser = argparse.ArgumentParser(description=tr("sbox5 standalone offline restorer", "sbox5 独立离线恢复器"))
    parser.add_argument("--snapshot", type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument("--yes", action="store_true")
    parser.add_argument("--automatic", action="store_true")
    parser.add_argument("-l", "--lang", "--language", dest="lang", metavar="LANG", help=tr("Language preference: en or zh-CN (default: auto-detect, English fallback)", "语言偏好：en 或 zh-CN（默认自动检测，回退英文）"))
    args = parser.parse_args()
    try:
        requested = getattr(args, "lang", None)
        if requested is not None:
            normalized = _normalize_language(requested)
            if normalized is None:
                fail(tr(f"Unsupported language: {requested}; use en or zh-CN", f"不支持的语言：{requested}；请使用 en 或 zh-CN"))
            _LANGUAGE = normalized
        restore(args.snapshot.resolve(), args.yes, args.automatic)
        return 0
    except (RuntimeError, OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        print(tr("Restore failed: ", "恢复失败：") + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
