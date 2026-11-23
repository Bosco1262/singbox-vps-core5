# Copyright (C) 2026 Bosco1262
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import base64
import hashlib
import ipaddress
from pathlib import Path
import ssl
import subprocess
import tempfile
from typing import Any

from .config import (
    ACME_STATE_DIR,
    profile_acme_data_directory,
    profile_certificate_path,
    profile_key_path,
)
from .errors import ConfigError, ExternalCommandError
from .i18n import tr
from .models import CertificateProfile
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
    details = _binary_command([
        "openssl", "x509", "-in", str(certificate), "-noout", "-enddate", "-issuer", "-subject",
    ]).decode("utf-8", "replace")
    metadata: dict[str, Any] = {
        "certificate_sha256": base64.b64encode(certificate_digest).decode("ascii"),
        "certificate_fingerprint": ":".join(f"{value:02X}" for value in certificate_digest),
        "public_key_sha256": base64.b64encode(hashlib.sha256(public_der).digest()).decode("ascii"),
        "file_sha256": sha256_file(certificate),
    }
    for line in details.splitlines():
        if line.startswith("notAfter="):
            metadata["not_after"] = line[len("notAfter="):].strip()
        elif line.startswith("issuer="):
            metadata["issuer"] = line[len("issuer="):].strip()
        elif line.startswith("subject="):
            metadata["subject"] = line[len("subject="):].strip()
    return metadata


def _subject_alt_name(host: str) -> str:
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return f"DNS:{host}"
    return f"IP:{address}"


def create_self_signed(profile: CertificateProfile, certificate: Path, key: Path, uid: int, gid: int) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="sbox5-cert-") as temporary:
        temp = Path(temporary)
        temp_cert = temp / "cert.pem"
        temp_key = temp / "key.pem"
        run([
            "openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
            "-nodes", "-days", "825", "-sha256", "-subj", f"/CN={profile.server_name}",
            "-addext", f"subjectAltName={_subject_alt_name(profile.server_name)}",
            "-addext", "basicConstraints=critical,CA:FALSE",
            "-addext", "keyUsage=critical,digitalSignature",
            "-addext", "extendedKeyUsage=serverAuth",
            "-keyout", str(temp_key), "-out", str(temp_cert),
        ])
        atomic_write(certificate, temp_cert.read_bytes(), 0o640, uid, gid)
        atomic_write(key, temp_key.read_bytes(), 0o600, uid, gid)
    return certificate_metadata(certificate)


def imported_certificate_metadata(profile: CertificateProfile) -> dict[str, Any]:
    certificate = profile_certificate_path(profile)
    key = profile_key_path(profile)
    if certificate.is_symlink() or key.is_symlink():
        raise ConfigError(tr("Imported certificate paths must not be symbolic links", "导入证书路径不能是符号链接"))
    if not certificate.is_file() or not key.is_file():
        raise ConfigError(tr(
            f"Imported certificate files are missing for profile {profile.id}: {certificate} / {key}",
            f"证书配置 {profile.id} 的导入文件缺失：{certificate} / {key}",
        ))
    return certificate_metadata(certificate)


def acme_profile_state(profile: CertificateProfile) -> dict[str, Any]:
    ACME_STATE_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    profile_acme_data_directory(profile).mkdir(parents=True, exist_ok=True, mode=0o700)
    return {
        "mode": "acme",
        "profile": profile.id,
        "domains": list(profile.domains),
        "provider": profile.ca_provider,
        "challenge": profile.challenge,
        "dns_provider": profile.dns_provider if profile.challenge == "dns-01" else "",
        "data_directory": str(profile_acme_data_directory(profile)),
        "status": "managed-by-sing-box",
    }


def imported_profile_state(profile: CertificateProfile) -> dict[str, Any]:
    return imported_certificate_metadata(profile)
