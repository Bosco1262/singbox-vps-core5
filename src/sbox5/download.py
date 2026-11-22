# Copyright (C) 2026 Bosco1262
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import hashlib
import os
from pathlib import Path, PurePosixPath
import re
import ssl
import tarfile
from typing import Any
from urllib.parse import urlparse
from urllib.request import HTTPSHandler, HTTPRedirectHandler, Request, build_opener

from .errors import VerificationError
from .i18n import tr
from .util import atomic_write, load_json, run, sha256_file


class _RestrictedRedirect(HTTPRedirectHandler):
    max_redirections = 5

    def __init__(self, allowed_hosts: set[str]) -> None:
        self.allowed_hosts = allowed_hosts

    def redirect_request(self, req: Request, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> Request | None:
        _validate_url(newurl, self.allowed_hosts)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _validate_url(url: str, allowed_hosts: set[str]) -> None:
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.hostname.lower() not in allowed_hosts:
        raise VerificationError(tr(f"Refusing an unexpected download URL: {url}", f"拒绝非预期下载地址：{url}"))
    if parsed.username or parsed.password or parsed.port not in (None, 443):
        raise VerificationError(tr("The download URL contains disallowed credentials or a port", "下载地址包含不允许的凭证或端口"))


def _download_file(url: str, expected: dict[str, Any], allowed_hosts: set[str], destination: Path) -> Path:
    _validate_url(url, allowed_hosts)
    context = ssl.create_default_context()
    opener = build_opener(HTTPSHandler(context=context), _RestrictedRedirect(allowed_hosts))
    request = Request(url, headers={"User-Agent": "sbox5/0.1", "Accept": "application/octet-stream"})
    temporary = destination.with_suffix(destination.suffix + ".part")
    if temporary.exists() or temporary.is_symlink():
        temporary.unlink()
    digest = hashlib.sha256()
    size = 0
    expected_size = int(expected["size"])
    try:
        with opener.open(request, timeout=45) as response, temporary.open("xb") as handle:
            final_url = response.geturl()
            _validate_url(final_url, allowed_hosts)
            while True:
                chunk = response.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > expected_size:
                    raise VerificationError(tr(f"The download exceeds the locked size: {expected['name']}", f"下载文件超过锁定大小：{expected['name']}"))
                digest.update(chunk)
                handle.write(chunk)
            handle.flush()
            os.fsync(handle.fileno())
        if size != expected_size:
            raise VerificationError(tr(f"Download size mismatch: {expected['name']}, expected {expected_size}, got {size}", f"下载大小不符：{expected['name']}，期望 {expected_size}，实际 {size}"))
        if digest.hexdigest().lower() != expected["sha256"].lower():
            raise VerificationError(tr(f"SHA256 mismatch: {expected['name']}", f"SHA256 不符：{expected['name']}"))
        os.replace(temporary, destination)
        return destination
    finally:
        if temporary.exists():
            temporary.unlink()


def _verify_optional_signature(asset: dict[str, Any], data_path: Path, project_root: Path, allowed_hosts: set[str]) -> None:
    signature = asset.get("signature")
    if not signature:
        return
    signature_path = data_path.with_suffix(data_path.suffix + ".sig")
    _download_file(signature["url"], signature, allowed_hosts, signature_path)
    keyring = (project_root / signature["keyring"]).resolve()
    if project_root.resolve() not in keyring.parents or not keyring.is_file():
        raise VerificationError(tr("The GPG keyring path is invalid", "GPG keyring 路径无效"))
    result = run(["gpgv", "--status-fd", "1", "--keyring", str(keyring), str(signature_path), str(data_path)], check=False)
    valid = next((line.split()[2] for line in result.stdout.splitlines() if line.startswith("[GNUPG:] VALIDSIG ") and len(line.split()) > 2), "")
    if result.returncode != 0 or valid.lower() != signature["fingerprint"].lower():
        raise VerificationError(tr("GPG signature or full fingerprint verification failed", "GPG 签名或完整指纹验证失败"))


def _safe_archive_member(archive: tarfile.TarFile, member_name: str) -> tarfile.TarInfo:
    members = archive.getmembers()
    if len(members) > 128:
        raise VerificationError(tr("The archive has an abnormal number of members", "归档文件成员数量异常"))
    selected: tarfile.TarInfo | None = None
    total_size = 0
    for member in members:
        path = PurePosixPath(member.name)
        if path.is_absolute() or ".." in path.parts or "\\" in member.name:
            raise VerificationError(tr("The archive contains an unsafe path", "归档包含不安全路径"))
        if not (member.isfile() or member.isdir()):
            raise VerificationError(tr("The archive contains links, devices, or other non-regular files", "归档包含链接、设备或其他非普通文件"))
        total_size += member.size
        if total_size > 512 * 1024 * 1024:
            raise VerificationError(tr("The extracted archive would exceed the size limit", "归档解压后大小超过限制"))
        if member.name == member_name:
            selected = member
    if selected is None or not selected.isfile():
        raise VerificationError(tr("The locked executable was not found in the archive", "归档中找不到锁定的可执行文件"))
    return selected


def install_locked_binary(component: str, architecture: str, project_root: Path, destination: Path, staging: Path) -> dict[str, Any]:
    lock_path = project_root / "locks" / f"{component}.json"
    lock = load_json(lock_path)
    if lock.get("schema_version") != 1 or lock.get("component") != component:
        raise VerificationError(tr(f"Invalid lock file format for {component}", f"{component} 锁文件格式无效"))
    asset = lock["assets"].get(architecture)
    if not asset:
        raise VerificationError(tr(f"{component} does not support architecture {architecture}", f"{component} 不支持架构：{architecture}"))
    for key in ("url", "name", "sha256"):
        if not isinstance(asset.get(key), str) or not asset[key]:
            raise VerificationError(tr(f"The {component} lock file is missing a required field: {key}", f"{component} 锁文件缺少必要字段：{key}"))
    if not re.fullmatch(r"[0-9a-f]{64}", asset["sha256"].lower()):
        raise VerificationError(tr(f"The SHA256 format in the {component} lock file is invalid", f"{component} 锁文件 SHA256 格式无效"))
    if not isinstance(asset.get("size"), int) or asset["size"] <= 0:
        raise VerificationError(tr(f"The size in the {component} lock file is invalid", f"{component} 锁文件大小无效"))
    if "/" in asset["name"] or "\\" in asset["name"] or asset["name"].startswith("."):
        raise VerificationError(tr(f"The file name in the {component} lock file is invalid", f"{component} 锁文件文件名无效"))
    allowed_hosts = {str(host).lower() for host in lock["allowed_hosts"]}
    staging.mkdir(parents=True, exist_ok=True, mode=0o700)
    archive_path = staging / asset["name"]
    if archive_path.exists():
        archive_path.unlink()
    _download_file(asset["url"], asset, allowed_hosts, archive_path)
    _verify_optional_signature(asset, archive_path, project_root, allowed_hosts)
    if "archive_member" in asset:
        with tarfile.open(archive_path, "r:gz") as archive:
            member = _safe_archive_member(archive, asset["archive_member"])
            source = archive.extractfile(member)
            if source is None:
                raise VerificationError(tr("Unable to read the locked archive member", "无法读取锁定归档成员"))
            data = source.read(256 * 1024 * 1024 + 1)
            if len(data) > 256 * 1024 * 1024:
                raise VerificationError(tr("The executable exceeds the size limit", "可执行文件超过大小限制"))
        atomic_write(destination, data, 0o755)
    else:
        atomic_write(destination, archive_path.read_bytes(), 0o755)
    return {
        "component": component,
        "version": lock["version"],
        "sha256": asset["sha256"],
        "source": asset["url"],
        "binary_sha256": sha256_file(destination),
    }
