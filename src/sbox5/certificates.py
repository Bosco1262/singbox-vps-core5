# Copyright (C) 2026 Bosco1262
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import base64
import hashlib
from pathlib import Path
import ssl
import subprocess
import tempfile
from typing import Any

from .errors import ExternalCommandError
from .i18n import tr
from .models import Settings
from .util import atomic_write, run, sha256_file


def _binary_command(command: list[str], input_data: bytes | None = None) -> bytes:
    try:
        result = subprocess.run(command, input=input_data, capture_output=True, shell=False, check=False, timeout=60)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ExternalCommandError(tr(f"The certificate tool failed: {exc}", f"证书工具执行失败：{exc}")) from exc
    if result.returncode != 0:
        raise ExternalCommandError(tr("The certificate tool returned an error: ", "证书工具返回错误：") + result.stderr.decode("utf-8", "replace").strip())
    return result.stdout


def certificate_metadata(certificate: Path) -> dict[str, Any]:
    pem = certificate.read_text(encoding="ascii")
    der = ssl.PEM_cert_to_DER_cert(pem)
    public_pem = _binary_command(["openssl", "x509", "-in", str(certificate), "-pubkey", "-noout"])
    public_der = _binary_command(["openssl", "pkey", "-pubin", "-outform", "der"], public_pem)
    certificate_digest = hashlib.sha256(der).digest()
    return {
        "certificate_sha256": base64.b64encode(certificate_digest).decode("ascii"),
        "certificate_fingerprint": ":".join(f"{value:02X}" for value in certificate_digest),
        "public_key_sha256": base64.b64encode(hashlib.sha256(public_der).digest()).decode("ascii"),
        "file_sha256": sha256_file(certificate),
    }


def create_self_signed(settings: Settings, certificate: Path, key: Path, uid: int, gid: int) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="sbox5-cert-") as temporary:
        temp = Path(temporary)
        temp_cert = temp / "cert.pem"
        temp_key = temp / "key.pem"
        run([
            "openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
            "-nodes", "-days", "825", "-sha256", "-subj", f"/CN={settings.tls_server_name}",
            "-addext", f"subjectAltName=DNS:{settings.tls_server_name}",
            "-addext", "basicConstraints=critical,CA:FALSE",
            "-addext", "keyUsage=critical,digitalSignature",
            "-addext", "extendedKeyUsage=serverAuth",
            "-keyout", str(temp_key), "-out", str(temp_cert),
        ])
        atomic_write(certificate, temp_cert.read_bytes(), 0o640, uid, gid)
        atomic_write(key, temp_key.read_bytes(), 0o600, uid, gid)
    return certificate_metadata(certificate)


def install_acme_certificate(domain: str, certificate: Path, key: Path, uid: int, gid: int) -> dict[str, Any]:
    source = Path("/etc/sbox5/acme/config/live") / domain
    fullchain = source / "fullchain.pem"
    private_key = source / "privkey.pem"
    if not fullchain.is_file() or not private_key.is_file():
        raise ExternalCommandError(tr("The ACME client did not generate the expected certificate", "ACME 客户端未生成预期证书"))
    atomic_write(certificate, fullchain.read_bytes(), 0o640, uid, gid)
    atomic_write(key, private_key.read_bytes(), 0o600, uid, gid)
    return certificate_metadata(certificate)


def issue_acme(domain: str, email: str = "") -> None:
    command = [
        "certbot", "certonly", "--standalone", "--non-interactive", "--agree-tos",
        "--preferred-challenges", "http-01", "-d", domain,
        "--config-dir", "/etc/sbox5/acme/config",
        "--work-dir", "/var/lib/sbox5/acme/work",
        "--logs-dir", "/var/log/sbox5-acme",
    ]
    if email:
        command += ["--email", email]
    else:
        command += ["--register-unsafely-without-email"]
    run(command, timeout=300)


def renew_acme() -> None:
    run([
        "certbot", "renew", "--non-interactive",
        "--config-dir", "/etc/sbox5/acme/config",
        "--work-dir", "/var/lib/sbox5/acme/work",
        "--logs-dir", "/var/log/sbox5-acme",
    ], timeout=300)
