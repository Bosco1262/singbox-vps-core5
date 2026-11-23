# Copyright (C) 2026 Bosco1262
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

from dataclasses import dataclass, field
import re
import secrets as random_secrets
from typing import Any
import uuid

from .errors import ConfigError
from .i18n import tr
from .util import format_host_port, normalize_host, split_host_port, validate_hostname, validate_port

PROTOCOLS = ("vless", "vmess", "hysteria2", "tuic", "anytls")
TLS_PROTOCOLS = ("vmess", "hysteria2", "tuic", "anytls")
TLS_REQUIRED_PROTOCOLS = ("hysteria2", "tuic", "anytls")
UDP_PROTOCOLS = ("hysteria2", "tuic")
CERTIFICATE_MODES = ("self-signed", "acme", "imported")
ACME_CHALLENGES = ("http-01", "dns-01", "tls-alpn-01")
_PROFILE_ID = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")


def _validate_email(value: str) -> str:
    value = value.strip()
    if value and ("@" not in value or any(char.isspace() for char in value)):
        raise ConfigError(tr("The ACME email format is invalid", "ACME 邮箱格式无效"))
    return value


def _validate_dns_provider(value: str) -> str:
    value = value.strip().lower()
    if value not in ("cloudflare",):
        raise ConfigError(tr(
            f"Unsupported ACME DNS provider in this phase: {value}. Only cloudflare is supported",
            f"当前阶段不支持的 ACME DNS 提供商：{value}。仅支持 cloudflare",
        ))
    return value


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
class ProtocolSettings:
    enabled: bool = True
    tls_profile: str = "default"

    def validate(self, name: str) -> None:
        if not isinstance(self.enabled, bool):
            raise ConfigError(tr(f"The enabled flag for {name} is invalid", f"{name} 的启用标记无效"))
        if not isinstance(self.tls_profile, str):
            raise ConfigError(tr(f"The TLS profile for {name} is invalid", f"{name} 的 TLS 配置无效"))
        if self.tls_profile and not _PROFILE_ID.fullmatch(self.tls_profile):
            raise ConfigError(tr(f"The TLS profile ID for {name} is invalid", f"{name} 的 TLS 配置 ID 无效"))

    def as_dict(self) -> dict[str, Any]:
        return {"enabled": self.enabled, "tls_profile": self.tls_profile}

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "ProtocolSettings":
        return cls(enabled=bool(value.get("enabled", True)), tls_profile=str(value.get("tls_profile", "default")))


def default_protocols() -> dict[str, ProtocolSettings]:
    return {
        "vless": ProtocolSettings(True, ""),
        "vmess": ProtocolSettings(True, ""),
        "hysteria2": ProtocolSettings(True, "default"),
        "tuic": ProtocolSettings(True, "default"),
        "anytls": ProtocolSettings(True, "default"),
    }


@dataclass
class CertificateProfile:
    id: str = "default"
    mode: str = "self-signed"
    domains: list[str] = field(default_factory=list)
    email: str = ""
    server_name: str = ""
    challenge: str = "http-01"
    dns_provider: str = "cloudflare"
    ca_provider: str = "letsencrypt"
    acme_profile: str = ""

    def validate(self) -> None:
        self.id = self.id.strip().lower()
        if not _PROFILE_ID.fullmatch(self.id):
            raise ConfigError(tr(f"Invalid certificate profile ID: {self.id}", f"证书配置 ID 无效：{self.id}"))
        self.mode = self.mode.strip().lower()
        if self.mode not in CERTIFICATE_MODES:
            raise ConfigError(tr(
                f"The certificate mode must be one of {', '.join(CERTIFICATE_MODES)}",
                f"证书模式必须是 {', '.join(CERTIFICATE_MODES)} 之一",
            ))
        self.domains = [validate_hostname(item, tr("certificate domain", "证书域名")) for item in self.domains if item]
        self.email = _validate_email(self.email)
        self.challenge = self.challenge.strip().lower() or "http-01"
        if self.challenge not in ACME_CHALLENGES:
            raise ConfigError(tr(f"Invalid ACME challenge: {self.challenge}", f"ACME 验证方式无效：{self.challenge}"))
        self.ca_provider = self.ca_provider.strip() or "letsencrypt"
        if self.ca_provider not in ("letsencrypt", "zerossl") and not self.ca_provider.startswith("https://"):
            raise ConfigError(tr(f"Invalid ACME CA provider: {self.ca_provider}", f"ACME CA 提供商无效：{self.ca_provider}"))
        if self.mode == "acme":
            if not self.domains:
                raise ConfigError(tr("ACME mode requires at least one domain or IP", "ACME 模式至少需要一个域名或 IP"))
            self.server_name = self.domains[0]
            if self.challenge == "dns-01":
                self.dns_provider = _validate_dns_provider(self.dns_provider)
        else:
            if not self.server_name:
                if self.domains:
                    self.server_name = self.domains[0]
                elif self.mode == "self-signed":
                    self.server_name = f"sbox5-{random_secrets.token_hex(8)}.internal"
                else:
                    raise ConfigError(tr("Imported certificates require an explicit server name", "导入证书需要显式指定 server_name"))
            self.server_name = validate_hostname(self.server_name, tr("TLS name", "TLS 名称"))
        if self.acme_profile and not re.fullmatch(r"[a-z0-9_-]{1,32}", self.acme_profile):
            raise ConfigError(tr("Invalid ACME profile name", "ACME profile 名称无效"))

    def as_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "mode": self.mode,
            "domains": self.domains,
            "email": self.email,
            "server_name": self.server_name,
            "challenge": self.challenge,
            "dns_provider": self.dns_provider,
            "ca_provider": self.ca_provider,
            "acme_profile": self.acme_profile,
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "CertificateProfile":
        result = cls(
            id=str(value.get("id", "default")),
            mode=str(value.get("mode", "self-signed")),
            domains=[str(item) for item in value.get("domains", [])],
            email=str(value.get("email", "")),
            server_name=str(value.get("server_name", "")),
            challenge=str(value.get("challenge", "http-01")),
            dns_provider=str(value.get("dns_provider", "cloudflare")),
            ca_provider=str(value.get("ca_provider", "letsencrypt")),
            acme_profile=str(value.get("acme_profile", "")),
        )
        result.validate()
        return result


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
    schema_version: int = 2
    protocols: dict[str, ProtocolSettings] = field(default_factory=default_protocols)
    certificate_profiles: list[CertificateProfile] = field(default_factory=list)

    def _migrate_certificate_profiles(self) -> None:
        if not self.certificate_profiles:
            mode = self.certificate_mode if self.certificate_mode in CERTIFICATE_MODES else "self-signed"
            domains = [self.domain] if mode == "acme" and self.domain else []
            server_name = self.tls_server_name
            if mode == "self-signed" and not server_name:
                server_name = f"sbox5-{random_secrets.token_hex(8)}.internal"
            profile = CertificateProfile(
                id="default",
                mode=mode,
                domains=domains,
                email=self.acme_email,
                server_name=server_name,
                challenge="http-01",
            )
            profile.validate()
            self.certificate_profiles = [profile]
            self.certificate_mode = profile.mode
            self.domain = profile.domains[0] if profile.domains else ""
            self.acme_email = profile.email
            self.tls_server_name = profile.server_name
            return
        profiles: list[CertificateProfile] = []
        for item in self.certificate_profiles:
            item.validate()
            profiles.append(item)
        self.certificate_profiles = profiles
        ids = {item.id for item in profiles}
        if len(ids) != len(profiles):
            raise ConfigError(tr("Certificate profile IDs must be unique", "证书配置 ID 必须唯一"))
        if "default" not in ids:
            raise ConfigError(tr("A certificate profile with id 'default' is required", "必须存在 id 为 default 的证书配置"))
        default = next(item for item in profiles if item.id == "default")
        self.certificate_mode = default.mode
        self.domain = default.domains[0] if default.domains else ""
        self.acme_email = default.email
        self.tls_server_name = default.server_name

    def _migrate_protocols(self) -> None:
        defaults = default_protocols()
        if not self.protocols:
            self.protocols = defaults
            return
        unknown = set(self.protocols) - set(PROTOCOLS)
        if unknown:
            raise ConfigError(tr(f"Unknown protocols in settings: {', '.join(sorted(unknown))}", f"设置中包含未知协议：{', '.join(sorted(unknown))}"))
        result: dict[str, ProtocolSettings] = {}
        for name in PROTOCOLS:
            current = self.protocols.get(name, defaults[name])
            if isinstance(current, ProtocolSettings):
                current.validate(name)
            elif isinstance(current, dict):
                normalized = dict(current)
                if "tls_profile" not in normalized:
                    normalized["tls_profile"] = "" if name in ("vless", "vmess") else "default"
                current = ProtocolSettings.from_dict(normalized)
                current.validate(name)
            else:
                raise ConfigError(tr(f"Invalid protocol settings for {name}", f"{name} 的协议设置无效"))
            result[name] = current
        self.protocols = result

    def _validate_port_hopping(self) -> None:
        ranges: list[tuple[str, int, int]] = []
        active_ports = {
            getattr(self.ports, name)
            for name, protocol in self.protocols.items()
            if protocol.enabled
        }
        acme_ports = self.acme_challenge_ports()
        for protocol, value in self.port_hopping.items():
            if protocol not in UDP_PROTOCOLS:
                raise ConfigError(tr(
                    "Port hopping is supported only for hysteria2 and tuic",
                    "端口跳跃仅支持 hysteria2 和 tuic",
                ))
            if not self.protocols[protocol].enabled:
                raise ConfigError(tr(f"Port hopping requires {protocol} to be enabled", f"端口跳跃要求 {protocol} 已启用"))
            if not isinstance(value, str):
                raise ConfigError(tr("The port hopping range is invalid", "端口跳跃范围无效"))
            start_text, separator, end_text = value.partition(":")
            if not separator:
                raise ConfigError(tr("The port hopping range must use the form START:END", "端口跳跃范围格式应为 起始:结束"))
            try:
                start, end = int(start_text), int(end_text)
            except ValueError as exc:
                raise ConfigError(tr("The port hopping range is invalid", "端口跳跃范围无效")) from exc
            validate_port(start)
            validate_port(end)
            if start >= end or end - start > 20000:
                raise ConfigError(tr("The port hopping range is invalid or too large", "端口跳跃范围无效或过大"))
            if any(start <= port <= end for port in active_ports):
                raise ConfigError(tr(
                    "The port hopping range must not contain an enabled protocol port",
                    "端口跳跃范围不能包含已启用协议的端口",
                ))
            if any(start <= port <= end for port in acme_ports):
                raise ConfigError(tr(
                    "The port hopping range must not contain an ACME challenge port",
                    "端口跳跃范围不能包含 ACME 验证端口",
                ))
            ranges.append((protocol, start, end))
        ranges.sort(key=lambda item: item[1])
        for previous, current in zip(ranges, ranges[1:]):
            if current[1] <= previous[2]:
                raise ConfigError(tr(
                    "Port hopping ranges cannot overlap",
                    "端口跳跃范围不能重叠",
                ))

    def active_certificate_profiles(self) -> list[CertificateProfile]:
        profiles = {item.id: item for item in self.certificate_profiles}
        active: dict[str, CertificateProfile] = {}
        for name in TLS_PROTOCOLS:
            protocol = self.protocols[name]
            if not protocol.enabled or not protocol.tls_profile:
                continue
            profile = profiles.get(protocol.tls_profile)
            if profile is None:
                raise ConfigError(tr(
                    f"The TLS profile {protocol.tls_profile} used by {name} does not exist",
                    f"{name} 使用的 TLS 配置 {protocol.tls_profile} 不存在",
                ))
            active[profile.id] = profile
        return [active[key] for key in sorted(active)]

    def acme_challenge_ports(self) -> list[int]:
        ports: list[int] = []
        for profile in self.active_certificate_profiles():
            if profile.mode != "acme":
                continue
            if profile.challenge == "http-01":
                ports.append(80)
            elif profile.challenge == "tls-alpn-01":
                ports.append(443)
        return ports

    def validate(self) -> None:
        self.schema_version = 2
        self.host = normalize_host(self.host)
        target_host, target_port = split_host_port(self.reality_target)
        self.reality_target = format_host_port(target_host, target_port)
        self.reality_sni = validate_hostname(self.reality_sni, tr("Reality SNI", "Reality SNI"))
        self.ports.validate()
        if self.domain:
            self.domain = validate_hostname(self.domain, tr("Certificate domain", "证书域名"))
        self._migrate_protocols()
        self._migrate_certificate_profiles()
        self.acme_email = _validate_email(self.acme_email)
        if not any(protocol.enabled for protocol in self.protocols.values()):
            raise ConfigError(tr("At least one protocol must be enabled", "至少需要启用一个协议"))
        profile_ids = {item.id for item in self.certificate_profiles}
        for name in TLS_PROTOCOLS:
            protocol = self.protocols[name]
            if protocol.tls_profile and protocol.tls_profile not in profile_ids:
                raise ConfigError(tr(f"The TLS profile for {name} does not exist", f"{name} 的 TLS 配置不存在"))
            if name in TLS_REQUIRED_PROTOCOLS and protocol.enabled and not protocol.tls_profile:
                raise ConfigError(tr(f"{name} requires a TLS profile", f"{name} 需要 TLS 配置"))
        self._validate_port_hopping()
        acme_ports = set(self.acme_challenge_ports())
        for name, protocol in self.protocols.items():
            if protocol.enabled and getattr(self.ports, name) in acme_ports:
                raise ConfigError(tr(
                    f"The {name} port conflicts with an active ACME challenge port",
                    f"{name} 端口与活动的 ACME 验证端口冲突",
                ))
        self.ddns.validate()
        self.argo.validate()
        if self.ddns.enabled and self.host != self.ddns.record:
            raise ConfigError(tr("When DDNS is enabled, the server address must be the DDNS record", "启用 DDNS 时，服务器地址必须使用 DDNS 记录"))
        if self.ddns.enabled and self.argo.enabled and self.ddns.record == self.argo.hostname:
            raise ConfigError(tr("The DDNS record and the Argo hostname must differ: the former must be DNS-only, the latter needs the Cloudflare proxy", "DDNS 记录与 Argo 域名不能相同：前者必须 DNS-only，后者需要 Cloudflare 代理"))
        if self.certificate_mode == "acme" and self.ddns.enabled and self.domain != self.ddns.record:
            raise ConfigError(tr("ACME with DDNS requires the certificate domain to match the DDNS record", "ACME + DDNS 模式要求证书域名与 DDNS 记录一致"))
        if self.argo.enabled:
            if not self.protocols["vmess"].enabled:
                raise ConfigError(tr("Argo requires the vmess inbound to be enabled", "Argo 要求启用 vmess 入站"))
            if self.protocols["vmess"].tls_profile:
                raise ConfigError(tr(
                    "Argo requires the vmess inbound to be plaintext WebSocket; disable VMess TLS before enabling Argo",
                    "Argo 要求 vmess 入站使用明文 WebSocket；启用 Argo 前请关闭 VMess TLS",
                ))

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 2,
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
            "protocols": {name: protocol.as_dict() for name, protocol in self.protocols.items()},
            "certificate_profiles": [profile.as_dict() for profile in self.certificate_profiles],
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "Settings":
        protocols: dict[str, ProtocolSettings] = {}
        if "protocols" in value:
            protocols = {
                str(name): ProtocolSettings.from_dict(item) if isinstance(item, dict) else item
                for name, item in value["protocols"].items()
            }
        profiles: list[CertificateProfile] = []
        if "certificate_profiles" in value:
            profiles = [CertificateProfile.from_dict(item) for item in value["certificate_profiles"]]
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
            schema_version=int(value.get("schema_version", 2)),
            protocols=protocols,
            certificate_profiles=profiles,
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
    acme_dns_tokens: dict[str, str] = field(default_factory=dict)

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
        for profile_id, token in self.acme_dns_tokens.items():
            if not _PROFILE_ID.fullmatch(str(profile_id)):
                raise ConfigError(tr("Invalid ACME token profile ID", "ACME Token 的证书配置 ID 无效"))
            if not isinstance(token, str) or not token or len(token) > 16384 or any(char in token for char in "\r\n\x00"):
                raise ConfigError(tr(f"The ACME DNS token for {profile_id} is invalid", f"{profile_id} 的 ACME DNS Token 无效"))

    def as_dict(self) -> dict[str, Any]:
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
            "acme_dns_tokens": dict(self.acme_dns_tokens),
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "Secrets":
        values: dict[str, Any] = {}
        for name in cls.__dataclass_fields__:
            if name not in value:
                continue
            if name == "acme_dns_tokens":
                raw = value[name]
                if not isinstance(raw, dict):
                    raise ConfigError(tr("The ACME DNS token state is invalid", "ACME DNS Token 状态无效"))
                values[name] = {str(key): str(item) for key, item in raw.items()}
            else:
                values[name] = str(value[name])
        result = cls(**values)
        result.validate()
        return result
