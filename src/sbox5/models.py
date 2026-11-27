# Copyright (C) 2026 Bosco1262
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import base64
from dataclasses import dataclass, field
import ipaddress
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
PROFILE_ID = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")
TAG_PATTERN = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")
RULESET_FILENAME = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}\.srs$")
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
ROUTE_TARGETS = ("direct", "direct-v4", "direct-v6", "warp", "socks5")
RULESET_ALLOWED_HOSTS = {"github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com"}
_PROFILE_ID = PROFILE_ID


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


def _validate_domain_suffix(value: str) -> str:
    original = value.strip().lower()
    if not original or original == "." or "/" in original or " " in original:
        raise ConfigError(tr(f"Invalid domain suffix: {value}", f"域名后缀无效：{value}"))
    if original.startswith("*."):
        original = original[1:]
    candidate = original[1:] if original.startswith(".") else original
    normalize_host(candidate)
    return original


def _validate_source_url(value: str) -> str:
    from urllib.parse import urlsplit

    parsed = urlsplit(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.hostname.lower() not in RULESET_ALLOWED_HOSTS:
        raise ConfigError(tr(
            f"Rule-set URLs must use HTTPS and an official GitHub release host: {value}",
            f"规则集 URL 必须使用 HTTPS 和官方 GitHub Release 主机：{value}",
        ))
    if parsed.username or parsed.password or parsed.port not in (None, 443):
        raise ConfigError(tr("The rule-set URL contains disallowed credentials or a port", "规则集 URL 包含不允许的凭证或端口"))
    return value


def _validate_wireguard_key(value: str, label: str) -> str:
    value = value.strip()
    try:
        decoded = base64.b64decode(value, validate=True)
    except Exception as exc:
        raise ConfigError(tr(f"Invalid WireGuard {label}", f"WireGuard {label} 无效")) from exc
    if len(decoded) != 32:
        raise ConfigError(tr(f"Invalid WireGuard {label} length", f"WireGuard {label} 长度无效"))
    return value


@dataclass
class WarpCredential:
    private_key: str = ""
    public_key: str = ""
    peer_public_key: str = ""
    addresses: list[str] = field(default_factory=list)
    reserved: list[int] = field(default_factory=lambda: [0, 0, 0])
    peer_address: str = "engage.cloudflareclient.com"
    peer_port: int = 2408
    client_id: str = ""
    registered_at: str = ""

    @property
    def configured(self) -> bool:
        return bool(self.private_key and self.peer_public_key and self.addresses)

    def validate(self) -> None:
        if not any((self.private_key, self.public_key, self.peer_public_key, self.addresses)):
            return
        self.private_key = _validate_wireguard_key(self.private_key, tr("private key", "私钥"))
        if self.public_key:
            self.public_key = _validate_wireguard_key(self.public_key, tr("public key", "公钥"))
        self.peer_public_key = _validate_wireguard_key(self.peer_public_key, tr("peer public key", "对端公钥"))
        if not self.addresses or len(self.addresses) > 4:
            raise ConfigError(tr("WARP requires one or two local addresses", "WARP 需要一到两个本地地址"))
        normalized: list[str] = []
        for address in self.addresses:
            try:
                normalized.append(str(ipaddress.ip_interface(address)))
            except ValueError as exc:
                raise ConfigError(tr(f"Invalid WARP address: {address}", f"WARP 地址无效：{address}")) from exc
        self.addresses = normalized
        if not isinstance(self.reserved, list) or len(self.reserved) != 3 or any(
            not isinstance(item, int) or isinstance(item, bool) or not 0 <= item <= 255 for item in self.reserved
        ):
            raise ConfigError(tr("WARP reserved field must contain exactly three bytes", "WARP reserved 字段必须包含三个字节"))
        self.peer_address = validate_hostname(self.peer_address or "engage.cloudflareclient.com", tr("WARP peer address", "WARP 对端地址"))
        self.peer_port = validate_port(self.peer_port)
        if self.client_id and (len(self.client_id) > 256 or any(char in self.client_id for char in "\r\n\x00")):
            raise ConfigError(tr("Invalid WARP client ID", "WARP client ID 无效"))
        if self.registered_at and len(self.registered_at) > 64:
            raise ConfigError(tr("Invalid WARP registration timestamp", "WARP 注册时间戳无效"))

    def as_dict(self) -> dict[str, Any]:
        return {
            "private_key": self.private_key,
            "public_key": self.public_key,
            "peer_public_key": self.peer_public_key,
            "addresses": list(self.addresses),
            "reserved": list(self.reserved),
            "peer_address": self.peer_address,
            "peer_port": self.peer_port,
            "client_id": self.client_id,
            "registered_at": self.registered_at,
        }

    def public_state(self) -> dict[str, Any]:
        return {
            "configured": self.configured,
            "public_key": self.public_key,
            "peer_public_key": self.peer_public_key,
            "addresses": list(self.addresses),
            "reserved": list(self.reserved),
            "peer_address": self.peer_address,
            "peer_port": self.peer_port,
            "registered_at": self.registered_at,
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "WarpCredential":
        result = cls(
            private_key=str(value.get("private_key", "")),
            public_key=str(value.get("public_key", "")),
            peer_public_key=str(value.get("peer_public_key", "")),
            addresses=[str(item) for item in value.get("addresses", [])],
            reserved=[int(item) for item in value.get("reserved", [0, 0, 0])],
            peer_address=str(value.get("peer_address", "engage.cloudflareclient.com")),
            peer_port=int(value.get("peer_port", 2408)),
            client_id=str(value.get("client_id", "")),
            registered_at=str(value.get("registered_at", "")),
        )
        result.validate()
        return result


@dataclass
class WarpSettings:
    enabled: bool = False
    tag: str = "warp"
    endpoint: str = ""
    port: int = 0
    mtu: int = 1280

    def validate(self) -> None:
        self.tag = self.tag.strip().lower() or "warp"
        if not TAG_PATTERN.fullmatch(self.tag):
            raise ConfigError(tr(f"Invalid WARP tag: {self.tag}", f"WARP 标签无效：{self.tag}"))
        if self.tag in ("direct", "direct-v4", "direct-v6", "socks5"):
            raise ConfigError(tr(f"The WARP tag is reserved: {self.tag}", f"WARP 标签为保留名称：{self.tag}"))
        if self.endpoint:
            self.endpoint = validate_hostname(self.endpoint, tr("WARP endpoint", "WARP 端点"))
        if self.port:
            self.port = validate_port(self.port)
        if not 1280 <= self.mtu <= 1500:
            raise ConfigError(tr("WARP MTU must be between 1280 and 1500", "WARP MTU 必须在 1280 到 1500 之间"))

    def as_dict(self) -> dict[str, Any]:
        return {"enabled": self.enabled, "tag": self.tag, "endpoint": self.endpoint, "port": self.port, "mtu": self.mtu}

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "WarpSettings":
        result = cls(
            enabled=bool(value.get("enabled", False)),
            tag=str(value.get("tag", "warp")),
            endpoint=str(value.get("endpoint", "")),
            port=int(value.get("port", 0)),
            mtu=int(value.get("mtu", 1280)),
        )
        result.validate()
        return result


@dataclass
class Socks5Settings:
    enabled: bool = False
    server: str = ""
    port: int = 1080
    username: str = ""

    def validate(self) -> None:
        if not self.enabled:
            return
        if not self.server:
            raise ConfigError(tr("Socks5 requires a server address", "Socks5 需要服务器地址"))
        self.server = validate_hostname(self.server, tr("Socks5 server", "Socks5 服务器"))
        self.port = validate_port(self.port)
        if self.username and not re.fullmatch(r"[A-Za-z0-9_.@-]{1,128}", self.username):
            raise ConfigError(tr("Invalid Socks5 username", "Socks5 用户名无效"))

    def as_dict(self) -> dict[str, Any]:
        return {"enabled": self.enabled, "server": self.server, "port": self.port, "username": self.username}

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "Socks5Settings":
        result = cls(
            enabled=bool(value.get("enabled", False)),
            server=str(value.get("server", "")),
            port=int(value.get("port", 1080)),
            username=str(value.get("username", "")),
        )
        result.validate()
        return result


@dataclass
class DomainRoute:
    target: str
    suffixes: list[str] = field(default_factory=list)

    def validate(self, targets: set[str]) -> None:
        self.target = self.target.strip().lower()
        if self.target not in targets:
            raise ConfigError(tr(f"Route target is not available: {self.target}", f"路由目标不可用：{self.target}"))
        suffixes = []
        for suffix in self.suffixes:
            normalized = _validate_domain_suffix(suffix)
            if normalized not in suffixes:
                suffixes.append(normalized)
        if not suffixes:
            raise ConfigError(tr("A domain route requires at least one suffix", "域名路由至少需要一个后缀"))
        self.suffixes = suffixes

    def as_dict(self) -> dict[str, Any]:
        return {"target": self.target, "suffixes": list(self.suffixes)}

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "DomainRoute":
        return cls(target=str(value.get("target", "")), suffixes=[str(item) for item in value.get("suffixes", [])])


@dataclass
class RuleSetSettings:
    tag: str
    filename: str
    sha256: str
    target: str
    source_url: str = ""

    def validate(self, targets: set[str]) -> None:
        self.tag = self.tag.strip().lower()
        if not TAG_PATTERN.fullmatch(self.tag):
            raise ConfigError(tr(f"Invalid rule-set tag: {self.tag}", f"规则集标签无效：{self.tag}"))
        self.filename = self.filename.strip().lower()
        if not RULESET_FILENAME.fullmatch(self.filename):
            raise ConfigError(tr(f"Invalid rule-set filename: {self.filename}", f"规则集文件名无效：{self.filename}"))
        self.sha256 = self.sha256.strip().lower()
        if not SHA256_PATTERN.fullmatch(self.sha256):
            raise ConfigError(tr("The rule-set SHA256 must be 64 lowercase hex characters", "规则集 SHA256 必须为 64 位小写十六进制"))
        self.target = self.target.strip().lower()
        if self.target not in targets:
            raise ConfigError(tr(f"Rule-set target is not available: {self.target}", f"规则集目标不可用：{self.target}"))
        if self.source_url:
            self.source_url = _validate_source_url(self.source_url)

    def as_dict(self) -> dict[str, Any]:
        return {
            "tag": self.tag,
            "filename": self.filename,
            "sha256": self.sha256,
            "target": self.target,
            "source_url": self.source_url,
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "RuleSetSettings":
        return cls(
            tag=str(value.get("tag", "")),
            filename=str(value.get("filename", "")),
            sha256=str(value.get("sha256", "")),
            target=str(value.get("target", "")),
            source_url=str(value.get("source_url", "")),
        )


@dataclass
class RoutingSettings:
    routes: list[DomainRoute] = field(default_factory=list)
    rule_sets: list[RuleSetSettings] = field(default_factory=list)
    socks5: Socks5Settings = field(default_factory=Socks5Settings)

    def validate(self, targets: set[str]) -> None:
        self.socks5.validate()
        routes: list[DomainRoute] = []
        for route in self.routes:
            route.validate(targets)
            routes.append(route)
        self.routes = routes
        rule_sets: list[RuleSetSettings] = []
        tags: set[str] = set()
        filenames: set[str] = set()
        for item in self.rule_sets:
            item.validate(targets)
            if item.tag in tags:
                raise ConfigError(tr(f"Duplicate rule-set tag: {item.tag}", f"规则集标签重复：{item.tag}"))
            if item.filename in filenames:
                raise ConfigError(tr(f"Duplicate rule-set filename: {item.filename}", f"规则集文件名重复：{item.filename}"))
            tags.add(item.tag)
            filenames.add(item.filename)
            rule_sets.append(item)
        self.rule_sets = rule_sets

    def as_dict(self) -> dict[str, Any]:
        return {
            "routes": [route.as_dict() for route in self.routes],
            "rule_sets": [item.as_dict() for item in self.rule_sets],
            "socks5": self.socks5.as_dict(),
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "RoutingSettings":
        return cls(
            routes=[DomainRoute.from_dict(item) for item in value.get("routes", [])],
            rule_sets=[RuleSetSettings.from_dict(item) for item in value.get("rule_sets", [])],
            socks5=Socks5Settings.from_dict(value.get("socks5", {})),
        )


@dataclass
class CdnProfile:
    enabled: bool = False
    address: str = ""
    port: int = 443
    host: str = ""
    sni: str = ""

    def validate(self, label: str) -> None:
        if not self.enabled:
            return
        if not self.address:
            raise ConfigError(tr(f"{label} CDN requires a preferred IP or domain", f"{label} CDN 需要优选 IP 或域名"))
        self.address = normalize_host(self.address)
        self.port = validate_port(self.port)
        if not self.host:
            try:
                ipaddress.ip_address(self.address)
            except ValueError:
                self.host = self.address
            else:
                raise ConfigError(tr(f"{label} CDN with an IP address requires an explicit Host/SNI", f"{label} CDN 使用 IP 时必须显式提供 Host/SNI"))
        self.host = validate_hostname(self.host, tr(f"{label} CDN Host", f"{label} CDN Host"))
        self.sni = validate_hostname(self.sni or self.host, tr(f"{label} CDN SNI", f"{label} CDN SNI"))

    def as_dict(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "address": self.address,
            "port": self.port,
            "host": self.host,
            "sni": self.sni,
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "CdnProfile":
        return cls(
            enabled=bool(value.get("enabled", False)),
            address=str(value.get("address", "")),
            port=int(value.get("port", 443)),
            host=str(value.get("host", "")),
            sni=str(value.get("sni", "")),
        )


@dataclass
class CdnSettings:
    vmess: CdnProfile = field(default_factory=CdnProfile)
    argo: CdnProfile = field(default_factory=CdnProfile)

    def as_dict(self) -> dict[str, Any]:
        return {"vmess": self.vmess.as_dict(), "argo": self.argo.as_dict()}

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "CdnSettings":
        return cls(
            vmess=CdnProfile.from_dict(value.get("vmess", {})),
            argo=CdnProfile.from_dict(value.get("argo", {})),
        )


@dataclass
class SubscriptionSettings:
    enabled: bool = False
    bind: str = "127.0.0.1"
    port: int = 18090
    tls_profile: str = ""

    def validate(self, profiles: dict[str, CertificateProfile]) -> None:
        if not self.enabled:
            return
        self.bind = self.bind.strip()
        if self.bind not in ("127.0.0.1", "0.0.0.0"):
            raise ConfigError(tr("Subscription bind must be 127.0.0.1 or 0.0.0.0", "订阅服务绑定地址必须是 127.0.0.1 或 0.0.0.0"))
        self.port = validate_port(self.port)
        if self.port < 1024:
            raise ConfigError(tr("The subscription port must be 1024 or higher", "订阅端口必须大于等于 1024"))
        if self.tls_profile:
            profile = profiles.get(self.tls_profile)
            if profile is None:
                raise ConfigError(tr("The subscription TLS profile does not exist", "订阅 TLS 配置不存在"))
            if profile.mode == "acme":
                raise ConfigError(tr(
                    "Native ACME certificates cannot be used by the local subscription server; use a self-signed/imported profile or a reverse proxy",
                    "本地订阅服务不能使用原生 ACME 证书；请使用自签/导入证书配置或反向代理",
                ))
        if self.bind == "0.0.0.0" and not self.tls_profile:
            raise ConfigError(tr(
                "A public subscription listener requires TLS; bind 127.0.0.1 and use a reverse proxy for ACME",
                "公网订阅监听必须启用 TLS；建议绑定 127.0.0.1 并使用反向代理处理 ACME",
            ))

    def as_dict(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "bind": self.bind,
            "port": self.port,
            "tls_profile": self.tls_profile,
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "SubscriptionSettings":
        return cls(
            enabled=bool(value.get("enabled", False)),
            bind=str(value.get("bind", "127.0.0.1")),
            port=int(value.get("port", 18090)),
            tls_profile=str(value.get("tls_profile", "")),
        )


@dataclass
class ArgoSettings:
    enabled: bool = False
    mode: str = "token"
    hostname: str = ""
    local_port: int = 18081

    def validate(self) -> None:
        self.mode = self.mode.strip().lower() or "token"
        if self.mode not in ("quick", "token"):
            raise ConfigError(tr("Argo mode must be quick or token", "Argo 模式只能是 quick 或 token"))
        self.local_port = validate_port(self.local_port)
        if self.local_port < 1024:
            raise ConfigError(tr("The Argo loopback port must be 1024 or higher", "Argo 回环端口必须大于等于 1024"))
        if self.enabled and self.mode == "token":
            self.hostname = validate_hostname(self.hostname, tr("Argo public hostname", "Argo 公网域名"))
        elif self.hostname:
            self.hostname = validate_hostname(self.hostname, tr("Argo public hostname", "Argo 公网域名"))

    def as_dict(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "mode": self.mode,
            "hostname": self.hostname,
            "local_port": self.local_port,
        }

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> "ArgoSettings":
        result = cls(
            enabled=bool(value.get("enabled", False)),
            mode=str(value.get("mode", "token")),
            hostname=str(value.get("hostname", "")),
            local_port=int(value.get("local_port", 18081)),
        )
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
    warp: WarpSettings = field(default_factory=WarpSettings)
    routing: RoutingSettings = field(default_factory=RoutingSettings)
    cdn: CdnSettings = field(default_factory=CdnSettings)
    subscription: SubscriptionSettings = field(default_factory=SubscriptionSettings)
    output_family: str = "auto"
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

    def route_targets(self) -> set[str]:
        targets = {"direct", "direct-v4", "direct-v6"}
        if self.warp.enabled:
            targets.add(self.warp.tag)
        if self.routing.socks5.enabled:
            targets.add("socks5")
        return targets

    def validate(self) -> None:
        self.schema_version = 3
        if isinstance(self.argo, dict):
            self.argo = ArgoSettings.from_dict(self.argo)
        if isinstance(self.warp, dict):
            self.warp = WarpSettings.from_dict(self.warp)
        if isinstance(self.routing, dict):
            self.routing = RoutingSettings.from_dict(self.routing)
        if isinstance(self.cdn, dict):
            self.cdn = CdnSettings.from_dict(self.cdn)
        if isinstance(self.subscription, dict):
            self.subscription = SubscriptionSettings.from_dict(self.subscription)
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
        self.warp.validate()
        self.routing.validate(self.route_targets())
        self.output_family = self.output_family.strip().lower() or "auto"
        if self.output_family not in ("auto", "ipv4", "ipv6"):
            raise ConfigError(tr("Output family must be auto, ipv4, or ipv6", "输出地址族必须是 auto、ipv4 或 ipv6"))
        if self.ddns.enabled and self.host != self.ddns.record:
            raise ConfigError(tr("When DDNS is enabled, the server address must be the DDNS record", "启用 DDNS 时，服务器地址必须使用 DDNS 记录"))
        if self.ddns.enabled and self.argo.enabled and self.argo.mode == "token" and self.ddns.record == self.argo.hostname:
            raise ConfigError(tr("The DDNS record and the Argo hostname must differ: the former must be DNS-only, the latter needs the Cloudflare proxy", "DDNS 记录与 Argo 域名不能相同：前者必须 DNS-only，后者需要 Cloudflare 代理"))
        if self.certificate_mode == "acme" and self.ddns.enabled and self.domain != self.ddns.record:
            raise ConfigError(tr("ACME with DDNS requires the certificate domain to match the DDNS record", "ACME + DDNS 模式要求证书域名与 DDNS 记录一致"))
        if self.argo.enabled:
            if not self.protocols["vmess"].enabled:
                raise ConfigError(tr("Argo requires the vmess inbound to be enabled", "Argo 要求启用 vmess 入站"))
            active_ports = {
                getattr(self.ports, name)
                for name, protocol in self.protocols.items()
                if protocol.enabled
            }
            if self.argo.local_port in active_ports or self.argo.local_port in acme_ports:
                raise ConfigError(tr(
                    "The Argo loopback port conflicts with an enabled or ACME port",
                    "Argo 回环端口与已启用端口或 ACME 端口冲突",
                ))
            for value in self.port_hopping.values():
                start, end = value.split(":", 1)
                if int(start) <= self.argo.local_port <= int(end):
                    raise ConfigError(tr(
                        "The Argo loopback port must not be inside a port-hopping range",
                        "Argo 回环端口不能位于端口跳跃范围内",
                    ))
        if self.cdn.argo.enabled:
            if not self.argo.enabled:
                raise ConfigError(tr("Argo CDN settings require Argo to be enabled", "Argo CDN 配置要求启用 Argo"))
            if self.argo.mode != "token":
                raise ConfigError(tr(
                    "Argo CDN requires token mode because quick tunnel hostnames are ephemeral",
                    "Argo CDN 需要 token 模式，因为临时隧道域名会变化",
                ))
            if not self.cdn.argo.host:
                self.cdn.argo.host = self.argo.hostname
            if not self.cdn.argo.sni:
                self.cdn.argo.sni = self.argo.hostname or self.cdn.argo.host
        self.cdn.vmess.validate("VMess")
        self.cdn.argo.validate("Argo")
        if self.cdn.vmess.enabled:
            if not self.protocols["vmess"].enabled:
                raise ConfigError(tr("VMess CDN settings require the vmess inbound", "VMess CDN 配置要求启用 vmess 入站"))
            if self.protocols["vmess"].tls_profile:
                raise ConfigError(tr(
                    "VMess CDN requires the origin VMess inbound to be plaintext WebSocket",
                    "VMess CDN 要求源站 VMess 入站使用明文 WebSocket",
                ))
        profiles_by_id = {profile.id: profile for profile in self.certificate_profiles}
        self.subscription.validate(profiles_by_id)
        if self.subscription.enabled:
            enabled_ports = {
                getattr(self.ports, name)
                for name, protocol in self.protocols.items()
                if protocol.enabled
            }
            if self.subscription.port in enabled_ports or self.subscription.port in acme_ports:
                raise ConfigError(tr("The subscription port conflicts with an enabled or ACME port", "订阅端口与已启用端口或 ACME 端口冲突"))
            if self.argo.enabled and self.subscription.port == self.argo.local_port:
                raise ConfigError(tr("The subscription port conflicts with the Argo loopback port", "订阅端口与 Argo 回环端口冲突"))
            for value in self.port_hopping.values():
                start, end = value.split(":", 1)
                if int(start) <= self.subscription.port <= int(end):
                    raise ConfigError(tr("The subscription port must not be inside a port-hopping range", "订阅端口不能位于端口跳跃范围内"))

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 3,
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
            "warp": self.warp.as_dict(),
            "routing": self.routing.as_dict(),
            "cdn": self.cdn.as_dict(),
            "subscription": self.subscription.as_dict(),
            "output_family": self.output_family,
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
            warp=WarpSettings.from_dict(value.get("warp", {})),
            routing=RoutingSettings.from_dict(value.get("routing", {})),
            cdn=CdnSettings.from_dict(value.get("cdn", {})),
            subscription=SubscriptionSettings.from_dict(value.get("subscription", {})),
            output_family=str(value.get("output_family", "auto")),
            schema_version=int(value.get("schema_version", 3)),
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
    warp: WarpCredential = field(default_factory=WarpCredential)
    socks5_password: str = ""

    def rotate(self, scope: str = "all") -> None:
        if scope not in ("all", *PROTOCOLS):
            raise ConfigError(tr(f"Unknown secret scope: {scope}", f"未知密钥范围：{scope}"))
        if scope in ("all", "vless"):
            self.vless_uuid = str(uuid.uuid4())
            self.reality_short_id = random_secrets.token_hex(8)
        if scope in ("all", "vmess"):
            self.vmess_uuid = str(uuid.uuid4())
            self.vmess_path = "/" + random_secrets.token_urlsafe(24)
        if scope in ("all", "hysteria2"):
            self.hysteria2_password = random_secrets.token_urlsafe(32)
            self.hysteria2_obfs_password = random_secrets.token_urlsafe(32)
            if self.hysteria2_obfs_password == self.hysteria2_password:
                self.hysteria2_obfs_password = random_secrets.token_urlsafe(32)
        if scope in ("all", "tuic"):
            self.tuic_uuid = str(uuid.uuid4())
            self.tuic_password = random_secrets.token_urlsafe(32)
        if scope in ("all", "anytls"):
            self.anytls_password = random_secrets.token_urlsafe(32)

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
        self.warp.validate()
        if self.socks5_password and (
            len(self.socks5_password) > 4096 or any(char in self.socks5_password for char in "\r\n\x00")
        ):
            raise ConfigError(tr("The Socks5 password is invalid", "Socks5 密码无效"))

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
            "warp": self.warp.as_dict(),
            "socks5_password": self.socks5_password,
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
            elif name == "warp":
                raw = value[name]
                if not isinstance(raw, dict):
                    raise ConfigError(tr("The WARP credential state is invalid", "WARP 凭证状态无效"))
                values[name] = WarpCredential.from_dict(raw)
            else:
                values[name] = str(value[name])
        result = cls(**values)
        result.validate()
        return result
