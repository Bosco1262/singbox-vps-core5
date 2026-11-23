# Copyright (C) 2026 Bosco1262
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import tempfile
from typing import Any

from .errors import ConfigError, ExternalCommandError
from .i18n import tr

_HOSTNAME = re.compile(r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def atomic_write(path: Path, data: bytes, mode: int = 0o600, uid: int | None = None, gid: int | None = None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temp_path = Path(temporary)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp_path, mode)
        if uid is not None and gid is not None:
            if not hasattr(os, "chown"):
                raise RuntimeError(tr("This platform does not support setting file ownership", "当前平台不支持文件属主设置"))
            os.chown(temp_path, uid, gid)
        os.replace(temp_path, path)
        if os.name == "posix":
            directory_fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    finally:
        if temp_path.exists():
            temp_path.unlink()


def atomic_text(path: Path, text: str, mode: int = 0o600, uid: int | None = None, gid: int | None = None) -> None:
    atomic_write(path, text.encode("utf-8"), mode, uid, gid)


def atomic_json(path: Path, value: Any, mode: int = 0o600, uid: int | None = None, gid: int | None = None) -> None:
    atomic_text(path, json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n", mode, uid, gid)


def run(command: list[str], *, timeout: int = 120, check: bool = True, input_text: str | None = None, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            command,
            input=input_text,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
            shell=False,
            env=env,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ExternalCommandError(tr(f"Unable to execute {command[0]}: {exc}", f"无法执行 {command[0]}: {exc}")) from exc
    if check and result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise ExternalCommandError(tr(f"{command[0]} failed with exit code {result.returncode}: {detail}", f"{command[0]} 执行失败（{result.returncode}）：{detail}"))
    return result


def require_linux_root() -> None:
    if os.name != "posix" or not hasattr(os, "geteuid") or os.geteuid() != 0:
        raise ConfigError(tr("This operation must run as root on a Debian/Ubuntu VPS", "此操作需要在 Debian/Ubuntu VPS 上以 root 执行"))


def normalize_host(value: str) -> str:
    value = value.strip()
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        pass
    if not value or any(char in value for char in "/@:?#[] \t\r\n"):
        raise ConfigError(tr("The server address must be a bare IP or domain, without URL, port, or spaces", "服务器地址必须是纯 IP 或域名，不能包含 URL、端口或空格"))
    try:
        ascii_host = value.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ConfigError(tr("The domain format is invalid", "域名格式无效")) from exc
    if not _HOSTNAME.fullmatch(ascii_host) or ".." in ascii_host:
        raise ConfigError(tr("The domain format is invalid", "域名格式无效"))
    return ascii_host


def split_host_port(value: str, default_port: int = 443) -> tuple[str, int]:
    value = value.strip()
    if value.startswith("["):
        match = re.fullmatch(r"\[([^]]+)](?::([0-9]{1,5}))?", value)
        if not match:
            raise ConfigError(tr("The Reality target has an invalid IPv6 format", "Reality 目标的 IPv6 格式无效"))
        host, port_text = match.group(1), match.group(2)
    elif value.count(":") == 1:
        host, port_text = value.rsplit(":", 1)
    elif value.count(":") > 1:
        host, port_text = value, None
    else:
        host, port_text = value, None
    port = int(port_text) if port_text else default_port
    validate_port(port)
    return normalize_host(host), port


def format_host_port(host: str, port: int) -> str:
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return f"{host}:{port}"
    return f"[{address}]:{port}" if address.version == 6 else f"{address}:{port}"


def validate_port(port: int) -> int:
    if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
        raise ConfigError(tr(f"Invalid port: {port}", f"端口无效：{port}"))
    return port


def validate_hostname(value: str, field: str | None = None) -> str:
    field = field or tr("domain name", "域名")
    try:
        return normalize_host(value)
    except ConfigError as exc:
        raise ConfigError(tr(f"Invalid {field}: {value}", f"{field}无效：{value}")) from exc


def available(command: str) -> bool:
    return shutil.which(command) is not None


def port_is_free(port: int, protocol: str) -> bool:
    sock_type = socket.SOCK_STREAM if protocol == "tcp" else socket.SOCK_DGRAM
    try:
        sock = socket.socket(socket.AF_INET6, sock_type)
    except OSError:
        sock = socket.socket(socket.AF_INET, sock_type)
    with sock:
        if protocol == "tcp":
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        address = "::" if sock.family == socket.AF_INET6 else "0.0.0.0"
        try:
            sock.bind((address, port))
            return True
        except OSError:
            return False
