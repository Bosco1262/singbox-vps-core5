# Copyright (C) 2026 Bosco1262
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

from dataclasses import dataclass, field
import secrets as random_secrets
from typing import Any
import uuid

from .errors import ConfigError
from .i18n import tr
from .util import format_host_port, normalize_host, split_host_port, validate_hostname, validate_port

PROTOCOLS = ("vless", "vmess", "hysteria2", "tuic", "anytls")


@dataclass
class Ports:
    vless: int = 18443
    vmess: int = 18080
    hysteria2: int = 18444
    tuic: int = 18445
    anytls: int = 18446

    def validate(self) -> None:
        values = [validate_port(getattr(self, name)) for name in PROTOCOLS]
        if len(set(values)) != len(values):
            raise ConfigError(tr("The five protocols cannot share duplicate ports", "五种协议不能使用重复端口"))

    def as_dict(self) -> dict[str, int]:
        return {name: getattr(self, name) for name in PROTOCOLS}

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "Ports":
        ports = cls(**{name: int(value[name]) for name in PROTOCOLS})
        ports.validate()
        return ports


@dataclass
class DDNSSettings:
    enabled: bool = False
    zone: str = ""
    record: str = ""
    ipv4: bool = True
    ipv6: bool = True
    interval_seconds: int = 300

    def validate(self) -> None:
        if not self.enabled:
            return
        self.zone = validate_hostname(self.zone, tr("Cloudflare Zone", "Cloudflare Zone"))
        self.record = validate_hostname(self.record, tr("DDNS record", "DDNS 记录"))
        if self.record != self.zone and not self.record.endswith("." + self.zone):
            raise ConfigError(tr("The DDNS record must be inside the given Zone", "DDNS 记录必须位于指定 Zone 内"))
        if not self.ipv4 and not self.ipv6:
            raise ConfigError(tr("DDNS requires at least one of A or AAAA records", "DDNS 至少需要启用 A 或 AAAA 记录"))
        if not 60 <= self.interval_seconds <= 86400:
            raise ConfigError(tr("The DDNS update interval must be between 60 and 86400 seconds", "DDNS 更新间隔必须在 60 到 86400 秒之间"))

    def as_dict(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "zone": self.zone,
            "record": self.record,
            "ipv4": self.ipv4,
            "ipv6": self.ipv6,
            "interval_seconds": self.interval_seconds,
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "DDNSSettings":
        result = cls(**value)
        result.validate()
        return result


@dataclass
class ArgoSettings:
    enabled: bool = False
    hostname: str = ""

    def validate(self) -> None:
        if self.enabled:
            self.hostname = validate_hostname(self.hostname, tr("Argo public hostname", "Argo 公网域名"))

    def as_dict(self) -> dict[str, Any]:
        return {"enabled": self.enabled, "hostname": self.hostname}

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "ArgoSettings":
        result = cls(**value)
        result.validate()
        return result


@dataclass
class Settings:
    host: str
    reality_target: str
    reality_sni: str
    ports: Ports = field(default_factory=Ports)
    domain: str = ""
    certificate_mode: str = "self-signed"
    acme_email: str = ""
    tls_server_name: str = ""
    manage_firewall: bool = True
    bbr: bool = False
    port_hopping: dict[str, str] = field(default_factory=dict)
    ddns: DDNSSettings = field(default_factory=DDNSSettings)
    argo: ArgoSettings = field(default_factory=ArgoSettings)

    def validate(self) -> None:
        self.host = normalize_host(self.host)
        target_host, target_port = split_host_port(self.reality_target)
        self.reality_target = format_host_port(target_host, target_port)
        self.reality_sni = validate_hostname(self.reality_sni, tr("Reality SNI", "Reality SNI"))
        self.ports.validate()
        if self.domain:
            self.domain = validate_hostname(self.domain, tr("Certificate domain", "证书域名"))
        if self.certificate_mode not in ("self-signed", "acme"):
            raise ConfigError(tr("The certificate mode must be self-signed or acme", "证书模式只能是 self-signed 或 acme"))
        if self.acme_email and ("@" not in self.acme_email or any(char.isspace() for char in self.acme_email)):
            raise ConfigError(tr("The ACME email format is invalid", "ACME 邮箱格式无效"))
        if self.certificate_mode == "acme":
            if not self.domain:
                raise ConfigError(tr("ACME mode requires a certificate domain", "ACME 模式需要证书域名"))
            self.tls_server_name = self.domain
        elif not self.tls_server_name:
            self.tls_server_name = f"sbox5-{random_secrets.token_hex(8)}.internal"
        else:
            self.tls_server_name = validate_hostname(self.tls_server_name, tr("TLS name", "TLS 名称"))
        for protocol, value in self.port_hopping.items():
            if protocol != "hysteria2":
                raise ConfigError(tr("Port hopping is supported only for hysteria2", "端口跳跃仅支持 hysteria2"))
            start_text, separator, end_text = value.partition(":")
            if not separator:
                raise ConfigError(tr("The port hopping range must use the form START:END", "端口跳跃范围格式应为 起始:结束"))
            start, end = int(start_text), int(end_text)
            validate_port(start)
            validate_port(end)
            if start >= end or end - start > 20000:
                raise ConfigError(tr("The port hopping range is invalid or too large", "端口跳跃范围无效或过大"))
        self.ddns.validate()
        self.argo.validate()
        if self.ddns.enabled and self.host != self.ddns.record:
            raise ConfigError(tr("When DDNS is enabled, the server address must be the DDNS record", "启用 DDNS 时，服务器地址必须使用 DDNS 记录"))
        if self.ddns.enabled and self.argo.enabled and self.ddns.record == self.argo.hostname:
            raise ConfigError(tr("The DDNS record and the Argo hostname must differ: the former must be DNS-only, the latter needs the Cloudflare proxy", "DDNS 记录与 Argo 域名不能相同：前者必须 DNS-only，后者需要 Cloudflare 代理"))
        if self.certificate_mode == "acme" and self.ddns.enabled and self.domain != self.ddns.record:
            raise ConfigError(tr("In the initial release, ACME with DDNS requires the certificate domain to match the DDNS record", "首版 ACME + DDNS 模式要求证书域名与 DDNS 记录一致"))

    def as_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "reality_target": self.reality_target,
            "reality_sni": self.reality_sni,
            "ports": self.ports.as_dict(),
            "domain": self.domain,
            "certificate_mode": self.certificate_mode,
            "acme_email": self.acme_email,
            "tls_server_name": self.tls_server_name,
            "manage_firewall": self.manage_firewall,
            "bbr": self.bbr,
            "port_hopping": self.port_hopping,
            "ddns": self.ddns.as_dict(),
            "argo": self.argo.as_dict(),
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "Settings":
        result = cls(
            host=value["host"],
            reality_target=value["reality_target"],
            reality_sni=value["reality_sni"],
            ports=Ports.from_dict(value["ports"]),
            domain=value.get("domain", ""),
            certificate_mode=value.get("certificate_mode", "self-signed"),
            acme_email=value.get("acme_email", ""),
            tls_server_name=value.get("tls_server_name", ""),
            manage_firewall=bool(value.get("manage_firewall", True)),
            bbr=bool(value.get("bbr", False)),
            port_hopping=dict(value.get("port_hopping", {})),
            ddns=DDNSSettings.from_dict(value.get("ddns", {})),
            argo=ArgoSettings.from_dict(value.get("argo", {})),
        )
        result.validate()
        return result


@dataclass
class Secrets:
    vless_uuid: str = field(default_factory=lambda: str(uuid.uuid4()))
    vmess_uuid: str = field(default_factory=lambda: str(uuid.uuid4()))
    tuic_uuid: str = field(default_factory=lambda: str(uuid.uuid4()))
    hysteria2_password: str = field(default_factory=lambda: random_secrets.token_urlsafe(32))
    hysteria2_obfs_password: str = field(default_factory=lambda: random_secrets.token_urlsafe(32))
    tuic_password: str = field(default_factory=lambda: random_secrets.token_urlsafe(32))
    anytls_password: str = field(default_factory=lambda: random_secrets.token_urlsafe(32))
    vmess_path: str = field(default_factory=lambda: "/" + random_secrets.token_urlsafe(24))
    reality_short_id: str = field(default_factory=lambda: random_secrets.token_hex(8))
    reality_private_key: str = ""
    reality_public_key: str = ""

    def validate(self) -> None:
        for value in (self.vless_uuid, self.vmess_uuid, self.tuic_uuid):
            if str(uuid.UUID(value)) != value:
                raise ConfigError(tr("The internal UUID state is invalid", "内部 UUID 状态无效"))
        if len({self.vless_uuid, self.vmess_uuid, self.tuic_uuid}) != 3:
            raise ConfigError(tr("Different protocols cannot reuse the same UUID", "不同协议不能复用 UUID"))
        for value in (self.hysteria2_password, self.hysteria2_obfs_password, self.tuic_password, self.anytls_password):
            if len(value) < 32:
                raise ConfigError(tr("The protocol password strength is insufficient", "协议密码强度不足"))
        if self.hysteria2_password == self.hysteria2_obfs_password:
            raise ConfigError(tr("The Hysteria2 authentication and obfuscation passwords must differ", "Hysteria2 认证与混淆密码不能相同"))
        if not self.vmess_path.startswith("/") or len(self.vmess_path) < 24:
            raise ConfigError(tr("The VMess WebSocket path is invalid", "VMess WebSocket 路径无效"))

    def as_dict(self) -> dict[str, str]:
        return {
            "vless_uuid": self.vless_uuid,
            "vmess_uuid": self.vmess_uuid,
            "tuic_uuid": self.tuic_uuid,
            "hysteria2_password": self.hysteria2_password,
            "hysteria2_obfs_password": self.hysteria2_obfs_password,
            "tuic_password": self.tuic_password,
            "anytls_password": self.anytls_password,
            "vmess_path": self.vmess_path,
            "reality_short_id": self.reality_short_id,
            "reality_private_key": self.reality_private_key,
            "reality_public_key": self.reality_public_key,
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "Secrets":
        result = cls(**{name: str(value[name]) for name in cls.__dataclass_fields__ if name in value})
        result.validate()
        return result
