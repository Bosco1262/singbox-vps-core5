# Copyright (C) 2026 Bosco1262
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import os
import ssl
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from .errors import ConfigError
from .i18n import tr
from .models import Settings
from .util import atomic_write, load_json

CONFIG_PATH = Path("/etc/sbox5/subscription.json")
TOKEN_PATH = Path("/etc/sbox5/secrets/subscription.token")
BUNDLE_DIR = Path("/var/lib/sbox5/subscription")
TLS_DIR = BUNDLE_DIR / "tls"
BUNDLE_FILES = (
    "links.txt",
    "subscription-base64.txt",
    "sing-box-client.json",
    "sfa.json",
    "sfi.json",
    "sfw.json",
    "mihomo.yaml",
    "metadata.json",
)
ENDPOINTS = {
    "links": ("links.txt", "text/plain; charset=utf-8"),
    "base64": ("subscription-base64.txt", "text/plain; charset=utf-8"),
    "sing-box": ("sing-box-client.json", "application/json; charset=utf-8"),
    "sfa": ("sfa.json", "application/json; charset=utf-8"),
    "sfi": ("sfi.json", "application/json; charset=utf-8"),
    "sfw": ("sfw.json", "application/json; charset=utf-8"),
    "mihomo": ("mihomo.yaml", "text/yaml; charset=utf-8"),
    "clash": ("mihomo.yaml", "text/yaml; charset=utf-8"),
    "metadata": ("metadata.json", "application/json; charset=utf-8"),
}


def generate_token() -> str:
    import secrets

    return secrets.token_urlsafe(48)


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def read_token(path: Path = TOKEN_PATH) -> str:
    if not path.is_file() or path.is_symlink():
        return ""
    return path.read_text(encoding="utf-8").strip()


def copy_bundle(source_dir: Path, destination: Path, uid: int, gid: int) -> list[Path]:
    if destination.is_symlink():
        raise ConfigError(tr("The subscription bundle directory must not be a symbolic link", "订阅包目录不能是符号链接"))
    destination.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(destination, 0o700)
    os.chown(destination, uid, gid)
    written: list[Path] = []
    for name in BUNDLE_FILES:
        source = source_dir / name
        target = destination / name
        if source.is_file() and not source.is_symlink():
            atomic_write(target, source.read_bytes(), 0o640, uid, gid)
            written.append(target)
        elif target.exists():
            if target.is_symlink():
                raise ConfigError(tr("Refusing to remove a symbolic link from the subscription bundle", "拒绝删除订阅包中的符号链接"))
            target.unlink()
    return written


def status(config_path: Path = CONFIG_PATH) -> dict[str, Any]:
    if not config_path.is_file():
        return {}
    config = load_json(config_path)
    return {
        "bind": config.get("bind"),
        "port": config.get("port"),
        "tls": bool(config.get("tls")),
        "bundle_dir": config.get("bundle_dir"),
    }


def base_url(settings: Settings, token: str) -> str:
    host = settings.host if settings.subscription.bind == "0.0.0.0" else "127.0.0.1"
    scheme = "https" if settings.subscription.tls_profile else "http"
    return f"{scheme}://{_format_host_port(host, settings.subscription.port)}/sub/{token}/"


def _format_host_port(host: str, port: int) -> str:
    import ipaddress

    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return f"{host}:{port}"
    return f"[{address}]:{port}" if address.version == 6 else f"{address}:{port}"


def _handler(config: dict[str, Any]) -> type[BaseHTTPRequestHandler]:
    bundle = Path(str(config["bundle_dir"]))
    expected = str(config["token_sha256"]).lower()

    class Handler(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"
        server_version = "sbox5-subscription"

        def log_request(self, code: int | str = "-", size: int | str = "-") -> None:
            sys.stderr.write(f"{self.client_address[0]} {self.command} {code}\n")

        def _deny(self, code: int = 404) -> None:
            body = b"not found\n"
            self.send_response(code)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _serve(self) -> None:
            path = urlsplit(self.path).path
            parts = [part for part in path.split("/") if part]
            if len(parts) != 3 or parts[0] != "sub":
                self._deny()
                return
            candidate = hashlib.sha256(parts[1].encode("utf-8")).hexdigest()
            if not hmac.compare_digest(candidate, expected):
                self._deny()
                return
            entry = ENDPOINTS.get(parts[2])
            if entry is None:
                self._deny()
                return
            filename, content_type = entry
            raw_target = bundle / filename
            target = raw_target.resolve()
            if raw_target.is_symlink() or bundle.resolve() not in target.parents or not target.is_file():
                self._deny()
                return
            data = target.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy", "default-src 'none'")
            self.send_header("Content-Disposition", f'inline; filename="{filename}"')
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(data)

        def do_GET(self) -> None:
            self._serve()

        def do_HEAD(self) -> None:
            self._serve()

    return Handler


def serve(config_path: Path = CONFIG_PATH) -> int:
    if not config_path.is_file():
        raise ConfigError(tr("The subscription configuration is missing", "订阅配置缺失"))
    config = load_json(config_path)
    bind = str(config.get("bind", "127.0.0.1"))
    port = int(config.get("port", 18090))
    server = ThreadingHTTPServer((bind, port), _handler(config))
    server.daemon_threads = True
    tls = config.get("tls")
    if isinstance(tls, dict) and tls.get("certificate_path") and tls.get("key_path"):
        certificate = Path(str(tls["certificate_path"]))
        key = Path(str(tls["key_path"]))
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(certfile=str(certificate), keyfile=str(key))
        server.socket = context.wrap_socket(server.socket, server_side=True)
    print(tr(
        f"sbox5 subscription listening on {bind}:{port}",
        f"sbox5 订阅服务监听于 {bind}:{port}",
    ), flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0
