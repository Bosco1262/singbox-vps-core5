# Copyright (C) 2026 Bosco1262
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import argparse
from getpass import getpass
import ipaddress
import json
from pathlib import Path
import subprocess
import sys

from . import __version__
from .argo import argo_host, quick_url_from_log, read_state as read_argo_state, wait_for_quick_url, write_state as write_argo_state
from .config import CERTIFICATE_PATH, check_server_config
from .ddns import CloudflareDDNS
from .errors import ConfigError, SBox5Error
from .export import build_share_links, export_nodes
from .firewall import apply_firewall
from .i18n import get_language, normalize_language, resolve_language, set_language, tr
from .installer import (
    ARGO_LOG_PATH,
    ARGO_STATE_PATH,
    ARGO_TOKEN_PATH,
    CERTIFICATE_STATE_PATH,
    CERTIFICATES_STATE_PATH,
    DDNS_STATE_PATH,
    DDNS_TOKEN_PATH,
    EXPORT_DIR,
    FIREWALL_STATE_PATH,
    SINGBOX_BINARY,
    STATE_PATH,
    InstallTransaction,
    load_secrets,
    load_settings,
    reconfigure,
)
from .kernel import catalog as core_catalog
from .kernel import rollback as core_rollback
from .kernel import status as core_status
from .kernel import switch as core_switch
from .models import (
    ArgoSettings,
    CdnProfile,
    CertificateProfile,
    DDNSSettings,
    DomainRoute,
    PROTOCOLS,
    Ports,
    ProtocolSettings,
    ROUTE_TARGETS,
    RuleSetSettings,
    Secrets,
    Settings,
    Socks5Settings,
    WarpCredential,
)
from .services import identity, require_active
from .snapshot import SNAPSHOT_ROOT
from .subscription import (
    BUNDLE_DIR as SUBSCRIPTION_BUNDLE_DIR,
    CONFIG_PATH as SUBSCRIPTION_CONFIG_PATH,
    TOKEN_PATH as SUBSCRIPTION_TOKEN_PATH,
    base_url as subscription_base_url,
    copy_bundle as subscription_copy_bundle,
    generate_token as subscription_generate_token,
    read_token as subscription_read_token,
    serve as subscription_serve,
    status as subscription_status,
)
from .system import read_token_file, validate_token_text
from .util import available, load_json, require_linux_root, run, split_host_port
from .warp import import_warp_credential, register_warp


def _interactive(args: argparse.Namespace) -> bool:
    return not getattr(args, "non_interactive", False) and sys.stdin.isatty()


def _prompt(value: str, label: str, args: argparse.Namespace, secret: bool = False) -> str:
    if value:
        return value
    if _interactive(args):
        prompt = label + tr(": ", "：")
        return (getpass(prompt) if secret else input(prompt)).strip()
    raise ConfigError(tr(f"Missing {label} in non-interactive mode", f"非交互模式缺少 {label}"))


def _confirm(args: argparse.Namespace, text: str) -> None:
    if getattr(args, "yes", False) or not _interactive(args):
        return
    if input(f"{text} [y/N] ").strip().lower() not in ("y", "yes"):
        raise ConfigError(tr("User cancelled the operation", "用户取消操作"))


def _current_argo_host(settings: Settings) -> str:
    state = read_argo_state(ARGO_STATE_PATH)
    if settings.argo.enabled and settings.argo.mode == "quick":
        url = quick_url_from_log(ARGO_LOG_PATH) or state.get("quick_url", "")
        if url:
            state["quick_url"] = url
    return argo_host(settings, state)


def _add_install_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--host")
    parser.add_argument("--reality-target")
    parser.add_argument("--reality-sni")
    parser.add_argument("--certificate-mode", choices=("self-signed", "acme", "imported"))
    parser.add_argument("--domain")
    parser.add_argument("--acme-email")
    parser.add_argument("--tls-server-name")
    parser.add_argument("--acme-challenge", choices=("http-01", "dns-01", "tls-alpn-01"))
    parser.add_argument("--acme-dns-provider", default="cloudflare")
    parser.add_argument("--acme-dns-token-file", type=Path)
    parser.add_argument("--vmess-tls", action=argparse.BooleanOptionalAction, default=None)
    for protocol in ("vless", "vmess", "hysteria2", "tuic", "anytls"):
        parser.add_argument(f"--{protocol}-port", type=int)
    parser.add_argument("--firewall", action=argparse.BooleanOptionalAction, default=None)
    parser.add_argument("--bbr", action=argparse.BooleanOptionalAction, default=None)
    parser.add_argument("--hysteria2-port-hopping", metavar="START:END")
    parser.add_argument("--tuic-port-hopping", metavar="START:END")
    parser.add_argument("--no-port-hopping", action="store_true")
    parser.add_argument("--ddns", action=argparse.BooleanOptionalAction, default=None)
    parser.add_argument("--cloudflare-zone")
    parser.add_argument("--ddns-record")
    parser.add_argument("--ddns-ipv4", action=argparse.BooleanOptionalAction, default=None)
    parser.add_argument("--ddns-ipv6", action=argparse.BooleanOptionalAction, default=None)
    parser.add_argument("--ddns-interval", type=int)
    parser.add_argument("--ddns-token-file", type=Path)
    parser.add_argument("--argo", action=argparse.BooleanOptionalAction, default=None)
    parser.add_argument("--argo-mode", choices=("quick", "token"))
    parser.add_argument("--argo-hostname")
    parser.add_argument("--argo-local-port", type=int)
    parser.add_argument("--argo-token-file", type=Path)
    parser.add_argument("--non-interactive", action="store_true")
    parser.add_argument("--yes", action="store_true")


def _add_language_argument(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "-l", "--lang", "--language", dest="lang", metavar="LANG", default=argparse.SUPPRESS,
        help=tr(
            "Language preference: en or zh-CN (default: auto-detect, English fallback)",
            "语言偏好：en 或 zh-CN（默认自动检测，回退英文）",
        ),
    )


def _request(args: argparse.Namespace, upgrade: bool) -> tuple[Settings, Secrets, str, str]:
    previous = load_settings() if upgrade else None
    secrets = load_secrets() if upgrade else Secrets()
    ddns_requested = args.ddns
    if ddns_requested is None and any((args.cloudflare_zone, args.ddns_record, args.ddns_token_file)):
        ddns_requested = True
    ddns_enabled = ddns_requested if ddns_requested is not None else (previous.ddns.enabled if previous else False)
    argo_requested = args.argo
    if argo_requested is None and any((args.argo_hostname, args.argo_token_file)):
        argo_requested = True
    argo_enabled = argo_requested if argo_requested is not None else (previous.argo.enabled if previous else False)
    previous_ddns = previous.ddns if previous else DDNSSettings()
    record = args.ddns_record or previous_ddns.record
    host = args.host or (record if ddns_enabled else "") or (previous.host if previous else "")
    host = _prompt(host, tr("Server public IP or domain", "服务器公网 IP 或域名"), args)
    if ddns_enabled and not record:
        record = host
    zone = args.cloudflare_zone or previous_ddns.zone
    if ddns_enabled:
        zone = _prompt(zone, tr("Cloudflare Zone (for example example.com)", "Cloudflare Zone（例如 example.com）"), args)
        record = _prompt(record, tr("Full DDNS record (for example vpn.example.com)", "DDNS 完整记录（例如 vpn.example.com）"), args)
    reality_target = args.reality_target or (previous.reality_target if previous else "")
    reality_target = _prompt(reality_target, tr("Reality handshake target (for example www.example.com:443)", "Reality 握手目标（例如 www.example.com:443）"), args)
    reality_sni = args.reality_sni or (previous.reality_sni if previous else "") or split_host_port(reality_target)[0]
    certificate_mode = args.certificate_mode or (previous.certificate_mode if previous else "self-signed")
    domain = args.domain or (previous.domain if previous else "")
    if certificate_mode == "acme" and not domain:
        try:
            ipaddress.ip_address(host)
        except ValueError:
            domain = host
    if certificate_mode == "acme":
        domain = _prompt(domain, tr("ACME certificate domain", "ACME 证书域名"), args)
    tls_server_name = args.tls_server_name or ""
    if not tls_server_name and previous and certificate_mode == previous.certificate_mode:
        tls_server_name = previous.tls_server_name
    if certificate_mode == "imported" and not tls_server_name:
        tls_server_name = _prompt("", tr("TLS server name for the imported certificate", "导入证书的 TLS server_name"), args)
    acme_email = args.acme_email if args.acme_email is not None else (previous.acme_email if previous else "")
    default_previous = None
    if previous is not None:
        default_previous = next((profile for profile in previous.certificate_profiles if profile.id == "default"), None)
    challenge = args.acme_challenge or (default_previous.challenge if default_previous else "http-01")
    dns_provider = args.acme_dns_provider or (default_previous.dns_provider if default_previous else "cloudflare")
    profiles: list[CertificateProfile] = []
    if previous is not None:
        profiles.extend(profile for profile in previous.certificate_profiles if profile.id != "default")
    profiles.insert(0, CertificateProfile(
        id="default",
        mode=certificate_mode,
        domains=[domain] if certificate_mode == "acme" else [],
        email=acme_email,
        server_name=tls_server_name,
        challenge=challenge,
        dns_provider=dns_provider,
        ca_provider=default_previous.ca_provider if default_previous else "letsencrypt",
        acme_profile=default_previous.acme_profile if default_previous else "",
    ))
    ports = Ports()
    for protocol in ports.as_dict():
        argument = getattr(args, f"{protocol}_port")
        if argument is not None:
            setattr(ports, protocol, argument)
        elif previous:
            setattr(ports, protocol, getattr(previous.ports, protocol))
    hopping = dict(previous.port_hopping) if previous else {}
    if args.no_port_hopping and (args.hysteria2_port_hopping or args.tuic_port_hopping):
        raise ConfigError(tr(
            "--no-port-hopping cannot be combined with a hopping range",
            "--no-port-hopping 不能与跳跃范围同时使用",
        ))
    if args.no_port_hopping:
        hopping = {}
    else:
        if args.hysteria2_port_hopping:
            hopping["hysteria2"] = args.hysteria2_port_hopping
        if args.tuic_port_hopping:
            hopping["tuic"] = args.tuic_port_hopping
    protocols = {name: value for name, value in (previous.protocols.items() if previous else [])}
    if args.vmess_tls is not None:
        protocols.setdefault("vmess", previous.protocols["vmess"] if previous else None)
        if protocols["vmess"] is None:
            protocols["vmess"] = ProtocolSettings(True, "")
        protocols["vmess"].tls_profile = "default" if args.vmess_tls else ""
    settings = Settings(
        host=host,
        reality_target=reality_target,
        reality_sni=reality_sni,
        ports=ports,
        domain=domain,
        certificate_mode=certificate_mode,
        acme_email=acme_email,
        tls_server_name=tls_server_name,
        manage_firewall=args.firewall if args.firewall is not None else (previous.manage_firewall if previous else True),
        bbr=args.bbr if args.bbr is not None else (previous.bbr if previous else False),
        port_hopping=hopping,
        ddns=DDNSSettings(
            enabled=ddns_enabled,
            zone=zone,
            record=record,
            ipv4=args.ddns_ipv4 if args.ddns_ipv4 is not None else previous_ddns.ipv4,
            ipv6=args.ddns_ipv6 if args.ddns_ipv6 is not None else previous_ddns.ipv6,
            interval_seconds=args.ddns_interval or previous_ddns.interval_seconds,
        ),
        argo=ArgoSettings(
            enabled=argo_enabled,
            mode=args.argo_mode or (previous.argo.mode if previous else "token"),
            hostname=args.argo_hostname or (previous.argo.hostname if previous else ""),
            local_port=args.argo_local_port or (previous.argo.local_port if previous else 18081),
        ),
        protocols=protocols,
        certificate_profiles=profiles,
    )
    if argo_enabled and settings.argo.mode == "token":
        settings.argo.hostname = _prompt(settings.argo.hostname, tr("Argo public hostname", "Argo 公网域名"), args)
    settings.validate()
    ddns_token = read_token_file(args.ddns_token_file, "Cloudflare Token") if args.ddns_token_file else ""
    argo_token = read_token_file(args.argo_token_file, "Argo Token") if args.argo_token_file else ""
    if ddns_enabled and not ddns_token and not DDNS_TOKEN_PATH.is_file():
        ddns_token = _prompt("", tr("Cloudflare API Token (input hidden)", "Cloudflare API Token（输入不可见）"), args, secret=True)
    if argo_enabled and settings.argo.mode == "token" and not argo_token and not ARGO_TOKEN_PATH.is_file():
        argo_token = _prompt("", tr("Argo Tunnel Token (input hidden)", "Argo Tunnel Token（输入不可见）"), args, secret=True)
    if ddns_token:
        ddns_token = validate_token_text(ddns_token, "Cloudflare Token")
    if argo_token:
        argo_token = validate_token_text(argo_token, "Argo Token")
    for profile in settings.active_certificate_profiles():
        if profile.mode != "acme" or profile.challenge != "dns-01":
            continue
        token = read_token_file(args.acme_dns_token_file, "ACME DNS Token") if args.acme_dns_token_file else ""
        if not token:
            token = secrets.acme_dns_tokens.get(profile.id, "")
        if not token:
            token = _prompt("", tr(f"ACME DNS API Token for {profile.id} (input hidden)", f"{profile.id} 的 ACME DNS API Token（输入不可见）"), args, secret=True)
        secrets.acme_dns_tokens[profile.id] = validate_token_text(token, "ACME DNS Token")
    secrets.validate()
    return settings, secrets, ddns_token, argo_token


def _install(args: argparse.Namespace, upgrade: bool) -> int:
    require_linux_root()
    settings, secrets, ddns_token, argo_token = _request(args, upgrade)
    action = tr("upgrade", "升级") if upgrade else tr("install", "安装")
    print(tr("About to run: ", "即将执行：") + action)
    print(f" - {tr('Address', '地址')}: {settings.host}")
    print(f" - {tr('Ports', '端口')}: {json.dumps(settings.ports.as_dict(), sort_keys=True)}")
    print(f" - {tr('Certificate', '证书')}: {settings.certificate_mode} / {settings.tls_server_name}")
    ddns_state = tr("enabled ", "启用 ") + settings.ddns.record if settings.ddns.enabled else tr("disabled", "禁用")
    argo_state = (
        tr("enabled ", "启用 ") + settings.argo.mode
        + (f" / {settings.argo.hostname}" if settings.argo.hostname else "")
        if settings.argo.enabled else tr("disabled", "禁用")
    )
    print(f" - DDNS: {ddns_state}")
    print(f" - Argo: {argo_state}")
    print(f" - {tr('Firewall auto-management', '防火墙自动管理')}: {settings.manage_firewall}; BBR: {settings.bbr}")
    _confirm(args, tr("Continue?", "确认继续吗？"))
    result = InstallTransaction(
        args.project_root, settings, secrets, upgrade=upgrade,
        feature="upgrade" if upgrade else "install",
        ddns_token=ddns_token, argo_token=argo_token,
    ).run()
    print(tr("Install transaction committed.", "安装事务已提交。"))
    print(tr("Snapshot: ", "快照：") + result["snapshot"])
    print(tr("Client export directory: ", "客户端导出目录：") + result["exports"])
    print(tr(
        "Use sbox5 show to view nodes; export files contain secrets and must not be uploaded publicly.",
        "使用 sbox5 show 查看节点；导出文件包含秘密，请勿公开上传。",
    ))
    for warning in result["warnings"]:
        print(tr("Warning: ", "警告：") + warning)
    return 0


def _status() -> int:
    require_linux_root()
    state = load_json(STATE_PATH)
    settings = load_settings()
    secrets = load_secrets()
    argo_state = read_argo_state(ARGO_STATE_PATH)
    if settings.argo.enabled and settings.argo.mode == "quick":
        url = quick_url_from_log(ARGO_LOG_PATH) or argo_state.get("quick_url", "")
        if url:
            argo_state["quick_url"] = url
    print(json.dumps({
        "schema_version": state.get("schema_version"),
        "project_version": state.get("project_version"),
        "installed_at": state.get("installed_at"),
        "components": state.get("components"),
        "protocols": state.get("protocols"),
        "certificate_profiles": state.get("certificate_profiles"),
        "snapshot_id": state.get("snapshot_id"),
        "argo": argo_state,
        "warp": settings.warp.as_dict(),
        "warp_credential": secrets.warp.public_state(),
        "routing": settings.routing.as_dict(),
        "cdn": settings.cdn.as_dict(),
        "subscription": settings.subscription.as_dict(),
    }, ensure_ascii=False, indent=2, sort_keys=True))
    for name in ("sbox5.service", "sbox5-argo.service", "sbox5-ddns.timer", "sbox5-subscription.service", "sbox5-firewall.service"):
        if (Path("/etc/systemd/system") / name).exists():
            result = run(["systemctl", "is-active", name], check=False)
            print(f"{name}: {result.stdout.strip() or result.returncode}")
    if CERTIFICATES_STATE_PATH.is_file():
        print(tr("Certificates: ", "证书：") + json.dumps(load_json(CERTIFICATES_STATE_PATH), ensure_ascii=False, sort_keys=True))
    if FIREWALL_STATE_PATH.is_file():
        firewall_state = load_json(FIREWALL_STATE_PATH)
        print(tr("Firewall: ", "防火墙：") + f"{firewall_state.get('backend')} ({len(firewall_state.get('owned', []))} owned)")
    if DDNS_STATE_PATH.is_file():
        print(tr("DDNS state: ", "DDNS 状态：") + json.dumps(load_json(DDNS_STATE_PATH), ensure_ascii=False, sort_keys=True))
    return 0


def _show(args: argparse.Namespace) -> int:
    require_linux_root()
    settings, secrets = load_settings(), load_secrets()
    metadata = load_json(CERTIFICATE_STATE_PATH) if CERTIFICATE_STATE_PATH.is_file() else {}
    certificates = load_json(CERTIFICATES_STATE_PATH) if CERTIFICATES_STATE_PATH.is_file() else {"default": metadata}
    links = build_share_links(settings, secrets, metadata, certificates, _current_argo_host(settings))
    if args.protocol:
        if args.protocol not in links:
            raise ConfigError(tr("This node is not enabled", "该节点未启用"))
        selected = {args.protocol: links[args.protocol]}
    else:
        selected = links
    if args.json:
        print(json.dumps(selected, ensure_ascii=False, indent=2))
    else:
        for name, link in selected.items():
            print(f"[{name}]\n{link}")
    if args.qr:
        if not available("qrencode"):
            raise ConfigError(tr("qrencode is not installed", "未安装 qrencode"))
        if len(selected) != 1:
            raise ConfigError(tr("QR mode requires --protocol to select exactly one node", "二维码模式必须用 --protocol 选择一个节点"))
        result = run(["qrencode", "-t", "ANSIUTF8"], input_text=next(iter(selected.values())), timeout=30)
        print(result.stdout)
    return 0


def _export() -> int:
    require_linux_root()
    settings, secrets = load_settings(), load_secrets()
    metadata = load_json(CERTIFICATE_STATE_PATH) if CERTIFICATE_STATE_PATH.is_file() else {}
    certificates = load_json(CERTIFICATES_STATE_PATH) if CERTIFICATES_STATE_PATH.is_file() else {"default": metadata}
    result = export_nodes(
        settings, secrets, CERTIFICATE_PATH, metadata, EXPORT_DIR,
        certificates=certificates, argo_host=_current_argo_host(settings),
    )
    check_server_config(SINGBOX_BINARY, EXPORT_DIR / "sing-box-client.json")
    check_server_config(SINGBOX_BINARY, EXPORT_DIR / "sfa.json")
    if settings.subscription.enabled:
        try:
            sub_uid, sub_gid = identity("sbox5-sub")
            subscription_copy_bundle(EXPORT_DIR, SUBSCRIPTION_BUNDLE_DIR, sub_uid, sub_gid)
        except KeyError:
            print(tr("Warning: subscription service user is missing; the bundle was not refreshed.", "警告：订阅服务用户缺失，订阅包未刷新。"), file=sys.stderr)
    print(tr("Exported to ", "已导出到 ") + str(EXPORT_DIR))
    for warning in result["warnings"]:
        print(tr("Warning: ", "警告：") + warning)
    return 0


def _check() -> int:
    require_linux_root()
    check_server_config(SINGBOX_BINARY, Path("/etc/sbox5/config.json"))
    check_server_config(SINGBOX_BINARY, EXPORT_DIR / "sing-box-client.json")
    check_server_config(SINGBOX_BINARY, EXPORT_DIR / "sfa.json")
    print(tr(
        "Server and sing-box client configurations both passed sing-box check.",
        "服务端与 sing-box 客户端配置均通过 sing-box check。",
    ))
    return 0


def _ddns_update() -> int:
    settings = load_settings()
    if not settings.ddns.enabled:
        raise ConfigError(tr("DDNS is not enabled", "DDNS 未启用"))
    token = validate_token_text(DDNS_TOKEN_PATH.read_text(encoding="utf-8"), "Cloudflare Token")
    result = CloudflareDDNS(settings.ddns, token).sync(DDNS_STATE_PATH)
    for change in result["changes"]:
        print(change)
    for warning in result["warnings"]:
        print(tr("Warning: ", "警告：") + warning)
    return 0


def _firewall_apply() -> int:
    require_linux_root()
    result = apply_firewall(load_settings(), FIREWALL_STATE_PATH)
    print(tr("Firewall backend: ", "防火墙后端：") + result["backend"])
    for warning in result["warnings"]:
        print(tr("Warning: ", "警告：") + warning)
    return 0


def _apply_reconfigure(
    args: argparse.Namespace,
    settings: Settings,
    secrets: Secrets,
    feature: str,
    import_files: dict[str, tuple[Path, Path]] | None = None,
    rule_set_files: dict[str, Path] | None = None,
    argo_token: str = "",
    subscription_token: str = "",
) -> int:
    settings.validate()
    secrets.validate()
    _confirm(args, tr("Apply this configuration change and restart services?", "应用此配置变更并重启服务吗？"))
    result = reconfigure(
        args.project_root, settings, secrets, feature,
        import_files=import_files, rule_set_files=rule_set_files, argo_token=argo_token,
        subscription_token=subscription_token,
    )
    print(tr("Configuration transaction committed.", "配置事务已提交。"))
    print(tr("Snapshot: ", "快照：") + result["snapshot"])
    print(tr("Client export directory: ", "客户端导出目录：") + result["exports"])
    for warning in result["warnings"]:
        print(tr("Warning: ", "警告：") + warning)
    return 0


def _port(args: argparse.Namespace) -> int:
    require_linux_root()
    settings, secrets = load_settings(), load_secrets()
    if args.port_command == "set":
        setattr(settings.ports, args.protocol, args.port)
    elif args.port_command == "hopping":
        if args.hopping_command == "set":
            settings.port_hopping[args.protocol] = args.range
        else:
            settings.port_hopping.pop(args.protocol, None)
    else:
        raise ConfigError(tr("Unknown port command", "未知端口命令"))
    return _apply_reconfigure(args, settings, secrets, "port")


def _protocol(args: argparse.Namespace) -> int:
    require_linux_root()
    settings, secrets = load_settings(), load_secrets()
    protocol = settings.protocols[args.name]
    if args.enabled:
        protocol.enabled = True
    elif args.disabled:
        protocol.enabled = False
    if args.tls_profile is not None:
        if args.name == "vless":
            raise ConfigError(tr("VLESS uses Reality and does not accept a TLS profile", "VLESS 使用 Reality，不接受 TLS 配置"))
        protocol.tls_profile = "" if args.tls_profile.lower() in ("none", "off", "disabled") else args.tls_profile
    return _apply_reconfigure(args, settings, secrets, "protocol")


def _argo(args: argparse.Namespace) -> int:
    require_linux_root()
    settings, secrets = load_settings(), load_secrets()
    if args.argo_command == "status":
        state = read_argo_state(ARGO_STATE_PATH)
        if settings.argo.enabled and settings.argo.mode == "quick":
            url = quick_url_from_log(ARGO_LOG_PATH) or state.get("quick_url", "")
            if url:
                state["quick_url"] = url
        unit = Path("/etc/systemd/system/sbox5-argo.service")
        active = run(["systemctl", "is-active", "sbox5-argo.service"], check=False).stdout.strip() if unit.exists() else "not-installed"
        data = {"settings": settings.argo.as_dict(), "state": state, "service": active}
        print(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) if args.json else json.dumps(data, ensure_ascii=False, sort_keys=True))
        return 0
    if args.argo_command == "set":
        settings.argo.enabled = True
        settings.argo.mode = args.mode
        if args.local_port is not None:
            settings.argo.local_port = args.local_port
        if args.mode == "quick":
            settings.argo.hostname = args.hostname or ""
            return _apply_reconfigure(args, settings, secrets, "argo")
        if args.hostname is not None:
            settings.argo.hostname = args.hostname
        settings.argo.hostname = _prompt(settings.argo.hostname, tr("Argo public hostname", "Argo 公网域名"), args)
        token = read_token_file(args.token_file, "Argo Token") if args.token_file else ""
        if not token and not ARGO_TOKEN_PATH.is_file():
            token = _prompt("", tr("Argo Tunnel Token (input hidden)", "Argo Tunnel Token（输入不可见）"), args, secret=True)
        return _apply_reconfigure(
            args, settings, secrets, "argo",
            argo_token=validate_token_text(token, "Argo Token") if token else "",
        )
    if args.argo_command in ("start", "stop"):
        if not settings.argo.enabled:
            raise ConfigError(tr("Argo is not enabled", "Argo 未启用"))
        run(["systemctl", args.argo_command, "sbox5-argo.service"], timeout=90)
        if args.argo_command == "start":
            require_active("sbox5-argo.service")
        print(tr("Argo service: ", "Argo 服务：") + args.argo_command)
        return 0
    if args.argo_command == "reset":
        if not settings.argo.enabled:
            raise ConfigError(tr("Argo is not enabled", "Argo 未启用"))
        if settings.argo.mode == "token":
            token = read_token_file(args.token_file, "Argo Token") if args.token_file else ""
            if not token:
                token = _prompt("", tr("New Argo Tunnel Token (input hidden)", "新的 Argo Tunnel Token（输入不可见）"), args, secret=True)
            return _apply_reconfigure(args, settings, secrets, "argo", argo_token=validate_token_text(token, "Argo Token"))
        run(["systemctl", "stop", "sbox5-argo.service"], check=False)
        for path in (ARGO_LOG_PATH, ARGO_STATE_PATH):
            if path.is_symlink():
                raise ConfigError(tr(f"Refusing to remove a symbolic link: {path}", f"拒绝删除符号链接：{path}"))
            if path.exists():
                path.unlink()
        run(["systemctl", "start", "sbox5-argo.service"], check=False)
        require_active("sbox5-argo.service")
        url = wait_for_quick_url(ARGO_LOG_PATH, timeout=20)
        state = write_argo_state(ARGO_STATE_PATH, settings, url)
        print(json.dumps(state, ensure_ascii=False, sort_keys=True))
        if not url:
            print(tr("Warning: the quick tunnel URL is not available yet.", "警告：临时隧道 URL 尚未出现。"), file=sys.stderr)
        elif settings.subscription.enabled:
            print(tr(
                "Run 'sbox5 export' to refresh the subscription bundle with the new Argo URL.",
                "请运行 sbox5 export，以将新的 Argo URL 刷新到订阅包。",
            ), file=sys.stderr)
        return 0
    raise ConfigError(tr("Unknown Argo command", "未知 Argo 命令"))


def _parse_reserved(value: str) -> list[int]:
    parts = [item for item in value.replace(",", " ").split() if item]
    try:
        values = [int(item) for item in parts]
    except ValueError as exc:
        raise ConfigError(tr("Reserved bytes must be three integers", "reserved 必须是三个整数")) from exc
    if len(values) != 3 or any(not 0 <= item <= 255 for item in values):
        raise ConfigError(tr("Reserved bytes must be three integers between 0 and 255", "reserved 必须是 0 到 255 之间的三个整数"))
    return values


def _warp(args: argparse.Namespace) -> int:
    require_linux_root()
    settings, secrets = load_settings(), load_secrets()
    if args.warp_command == "status":
        unit = Path("/etc/systemd/system/sbox5.service")
        active = run(["systemctl", "is-active", "sbox5.service"], check=False).stdout.strip() if unit.exists() else "not-installed"
        data = {
            "settings": settings.warp.as_dict(),
            "credential": secrets.warp.public_state(),
            "service": active,
        }
        print(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) if args.json else json.dumps(data, ensure_ascii=False, sort_keys=True))
        return 0
    if args.warp_command in ("register", "rotate"):
        if not SINGBOX_BINARY.is_file():
            raise ConfigError(tr("The sing-box binary is not installed", "sing-box 二进制未安装"))
        secrets.warp = register_warp(SINGBOX_BINARY)
        settings.warp.enabled = True
        return _apply_reconfigure(args, settings, secrets, "warp")
    if args.warp_command == "import":
        private_key = read_token_file(args.private_key_file, "WARP private key")
        secrets.warp = import_warp_credential(
            private_key,
            args.peer_public_key,
            list(args.address),
            _parse_reserved(args.reserved),
            public_key=args.public_key or "",
            peer_address=args.peer_address,
            peer_port=args.peer_port,
            client_id=args.client_id or "",
        )
        settings.warp.enabled = True
        return _apply_reconfigure(args, settings, secrets, "warp")
    if args.warp_command in ("enable", "disable"):
        if args.warp_command == "enable" and not secrets.warp.configured:
            raise ConfigError(tr("No WARP credential is configured", "未配置 WARP 凭证"))
        settings.warp.enabled = args.warp_command == "enable"
        return _apply_reconfigure(args, settings, secrets, "warp")
    if args.warp_command == "clear":
        settings.warp.enabled = False
        secrets.warp = WarpCredential()
        return _apply_reconfigure(args, settings, secrets, "warp")
    raise ConfigError(tr("Unknown WARP command", "未知 WARP 命令"))


def _route(args: argparse.Namespace) -> int:
    require_linux_root()
    settings, secrets = load_settings(), load_secrets()
    if args.route_command == "list":
        data = {
            "routes": settings.routing.as_dict()["routes"],
            "rule_sets": settings.routing.as_dict()["rule_sets"],
            "socks5": settings.routing.socks5.as_dict(),
            "warp": settings.warp.as_dict(),
            "targets": sorted(settings.route_targets()),
        }
        print(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) if args.json else json.dumps(data, ensure_ascii=False, sort_keys=True))
        return 0
    if args.route_command == "add":
        route = next((item for item in settings.routing.routes if item.target == args.target), None)
        if route is None:
            route = DomainRoute(target=args.target, suffixes=[])
            settings.routing.routes.append(route)
        existing = {item.strip().lower().lstrip(".") for item in route.suffixes}
        for suffix in args.suffix:
            if suffix.strip().lower().lstrip(".") not in existing:
                route.suffixes.append(suffix)
        return _apply_reconfigure(args, settings, secrets, "route")
    if args.route_command == "remove":
        route = next((item for item in settings.routing.routes if item.target == args.target), None)
        if route is None:
            raise ConfigError(tr(f"No route exists for target {args.target}", f"目标 {args.target} 没有路由"))
        removals = {item.strip().lower().lstrip(".") for item in args.suffix}
        route.suffixes = [
            item for item in route.suffixes
            if item.strip().lower().lstrip(".") not in removals
        ]
        if not route.suffixes:
            settings.routing.routes.remove(route)
        return _apply_reconfigure(args, settings, secrets, "route")
    if args.route_command == "clear":
        settings.routing.routes = []
        return _apply_reconfigure(args, settings, secrets, "route")
    if args.route_command == "socks5":
        if args.socks5_command == "set":
            settings.routing.socks5 = Socks5Settings(
                enabled=True, server=args.server, port=args.port, username=args.username or "",
            )
            password = read_token_file(args.password_file, "Socks5 password") if args.password_file else ""
            if settings.routing.socks5.username and not password:
                password = _prompt("", tr("Socks5 password (input hidden)", "Socks5 密码（输入不可见）"), args, secret=True)
            if settings.routing.socks5.username and not password:
                raise ConfigError(tr("Socks5 username requires a password", "Socks5 用户名需要密码"))
            secrets.socks5_password = validate_token_text(password, "Socks5 password") if password else ""
            return _apply_reconfigure(args, settings, secrets, "route")
        settings.routing.socks5 = Socks5Settings()
        secrets.socks5_password = ""
        return _apply_reconfigure(args, settings, secrets, "route")
    if args.route_command == "ruleset":
        if args.ruleset_command == "list":
            print(json.dumps(settings.routing.rule_sets, ensure_ascii=False, indent=2, sort_keys=True, default=lambda item: item.as_dict()) if args.json else json.dumps([item.as_dict() for item in settings.routing.rule_sets], ensure_ascii=False, sort_keys=True))
            return 0
        if args.ruleset_command == "add":
            if any(item.tag == args.tag for item in settings.routing.rule_sets):
                raise ConfigError(tr(f"Rule-set already exists: {args.tag}", f"规则集已存在：{args.tag}"))
            item = RuleSetSettings(
                tag=args.tag,
                filename=args.filename or f"{args.tag}.srs",
                sha256=args.sha256,
                target=args.target,
                source_url=args.url or "",
            )
            item.validate(settings.route_targets())
            settings.routing.rule_sets.append(item)
            files = {item.tag: args.file} if args.file else None
            return _apply_reconfigure(args, settings, secrets, "route", rule_set_files=files)
        if args.ruleset_command == "remove":
            item = next((entry for entry in settings.routing.rule_sets if entry.tag == args.tag), None)
            if item is None:
                raise ConfigError(tr(f"Rule-set not found: {args.tag}", f"规则集不存在：{args.tag}"))
            settings.routing.rule_sets.remove(item)
            return _apply_reconfigure(args, settings, secrets, "route")
        if args.ruleset_command == "update":
            item = next((entry for entry in settings.routing.rule_sets if entry.tag == args.tag), None)
            if item is None:
                raise ConfigError(tr(f"Rule-set not found: {args.tag}", f"规则集不存在：{args.tag}"))
            item.sha256 = args.sha256
            if args.filename:
                item.filename = args.filename
            if args.url:
                item.source_url = args.url
            elif args.file:
                item.source_url = ""
            item.validate(settings.route_targets())
            files = {item.tag: args.file} if args.file else None
            return _apply_reconfigure(args, settings, secrets, "route", rule_set_files=files)
    raise ConfigError(tr("Unknown route command", "未知路由命令"))


def _certificate(args: argparse.Namespace) -> int:
    require_linux_root()
    settings, secrets = load_settings(), load_secrets()
    if args.cert_command == "list":
        data = {
            "profiles": [profile.as_dict() for profile in settings.certificate_profiles],
            "bindings": {
                name: protocol.tls_profile
                for name, protocol in settings.protocols.items()
                if name != "vless"
            },
        }
        if CERTIFICATES_STATE_PATH.is_file():
            data["state"] = load_json(CERTIFICATES_STATE_PATH)
        if args.json:
            print(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True))
        else:
            for profile in settings.certificate_profiles:
                print(
                    f"{profile.id}\t{profile.mode}\t{profile.server_name}\t"
                    f"{','.join(profile.domains)}\t{profile.challenge if profile.mode == 'acme' else '-'}"
                )
            print(tr("Bindings: ", "绑定：") + json.dumps(data["bindings"], ensure_ascii=False, sort_keys=True))
        return 0

    import_files: dict[str, tuple[Path, Path]] = {}
    if args.cert_command == "add":
        if any(profile.id == args.id for profile in settings.certificate_profiles):
            raise ConfigError(tr(f"Certificate profile already exists: {args.id}", f"证书配置已存在：{args.id}"))
        profile = CertificateProfile(
            id=args.id,
            mode=args.mode,
            domains=list(args.domain or []),
            email=args.email or "",
            server_name=args.server_name or "",
            challenge=args.challenge or "http-01",
            dns_provider=args.dns_provider or "cloudflare",
            ca_provider=args.ca_provider or "letsencrypt",
            acme_profile=args.acme_profile or "",
        )
        profile.validate()
        if any(existing.id == profile.id for existing in settings.certificate_profiles):
            raise ConfigError(tr(f"Certificate profile already exists: {profile.id}", f"证书配置已存在：{profile.id}"))
        if profile.mode == "imported":
            if not args.cert or not args.key:
                raise ConfigError(tr("Imported profiles require --cert and --key", "导入证书配置需要 --cert 和 --key"))
            import_files[profile.id] = (args.cert, args.key)
        if profile.mode == "acme" and profile.challenge == "dns-01":
            token = read_token_file(args.dns_token_file, "ACME DNS Token") if args.dns_token_file else ""
            if not token:
                token = _prompt(
                    "", tr(f"ACME DNS API Token for {profile.id} (input hidden)", f"{profile.id} 的 ACME DNS API Token（输入不可见）"),
                    args, secret=True,
                )
            secrets.acme_dns_tokens[profile.id] = validate_token_text(token, "ACME DNS Token")
        settings.certificate_profiles.append(profile)
        if args.bind_protocol:
            if args.bind_protocol == "vless":
                raise ConfigError(tr("VLESS uses Reality and cannot bind a certificate profile", "VLESS 使用 Reality，不能绑定证书配置"))
            settings.protocols[args.bind_protocol].tls_profile = profile.id
        return _apply_reconfigure(args, settings, secrets, "certificate", import_files)

    if args.cert_command == "remove":
        if args.id == "default":
            raise ConfigError(tr("The default certificate profile cannot be removed", "不能删除 default 证书配置"))
        if any(protocol.tls_profile == args.id for protocol in settings.protocols.values()):
            raise ConfigError(tr(
                f"Certificate profile {args.id} is still bound to a protocol; unbind it first",
                f"证书配置 {args.id} 仍绑定到协议；请先解除绑定",
            ))
        if not any(profile.id == args.id for profile in settings.certificate_profiles):
            raise ConfigError(tr(f"Certificate profile not found: {args.id}", f"证书配置不存在：{args.id}"))
        settings.certificate_profiles = [profile for profile in settings.certificate_profiles if profile.id != args.id]
        secrets.acme_dns_tokens.pop(args.id, None)
        return _apply_reconfigure(args, settings, secrets, "certificate")

    if args.cert_command == "bind":
        if args.protocol == "vless":
            raise ConfigError(tr("VLESS uses Reality and cannot bind a certificate profile", "VLESS 使用 Reality，不能绑定证书配置"))
        if args.profile.lower() not in ("none", "off", "disabled") and not any(
            profile.id == args.profile for profile in settings.certificate_profiles
        ):
            raise ConfigError(tr(f"Certificate profile not found: {args.profile}", f"证书配置不存在：{args.profile}"))
        settings.protocols[args.protocol].tls_profile = (
            "" if args.profile.lower() in ("none", "off", "disabled") else args.profile
        )
        return _apply_reconfigure(args, settings, secrets, "certificate")

    raise ConfigError(tr("Unknown certificate command", "未知证书命令"))


def _core(args: argparse.Namespace) -> int:
    require_linux_root()
    if args.core_command == "status":
        print(json.dumps(core_status(args.project_root), ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    if args.core_command == "list":
        print(json.dumps(core_catalog(args.project_root), ensure_ascii=False, indent=2, sort_keys=True))
        return 0
    if args.core_command == "switch":
        version = args.version
        if not version:
            channels = core_catalog(args.project_root)["channels"]
            version = channels.get(args.channel, "")
            if not version:
                raise ConfigError(tr(
                    f"No locked sing-box version is configured for the {args.channel} channel",
                    f"{args.channel} 通道没有已锁定的 sing-box 版本",
                ))
        settings = load_settings()
        _confirm(args, tr(f"Switch sing-box to {version} and restart the service?", f"将 sing-box 切换到 {version} 并重启服务吗？"))
        result = core_switch(args.project_root, settings, version)
        print(tr("Core switched: ", "内核已切换：") + f"{result['previous'] or '-'} -> {result['current']}")
        print(tr("Snapshot: ", "快照：") + result["snapshot"])
        return 0
    if args.core_command == "rollback":
        settings = load_settings()
        _confirm(args, tr("Roll back to the previous sing-box version?", "回滚到上一版 sing-box 吗？"))
        result = core_rollback(args.project_root, settings)
        print(tr("Core rolled back: ", "内核已回滚：") + f"{result['previous'] or '-'} -> {result['current']}")
        print(tr("Snapshot: ", "快照：") + result["snapshot"])
        return 0
    raise ConfigError(tr("Unknown core command", "未知内核命令"))


def _cdn(args: argparse.Namespace) -> int:
    require_linux_root()
    settings, secrets = load_settings(), load_secrets()
    if args.cdn_command == "list":
        data = settings.cdn.as_dict()
        print(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) if args.json else json.dumps(data, ensure_ascii=False, sort_keys=True))
        return 0
    profile = settings.cdn.vmess if args.target == "vmess" else settings.cdn.argo
    if args.cdn_command == "set":
        profile.enabled = True
        profile.address = args.address
        profile.port = args.port
        profile.host = args.host or ""
        profile.sni = args.sni or ""
        return _apply_reconfigure(args, settings, secrets, "cdn")
    if args.cdn_command == "clear":
        if args.target == "vmess":
            settings.cdn.vmess = CdnProfile()
        else:
            settings.cdn.argo = CdnProfile()
        return _apply_reconfigure(args, settings, secrets, "cdn")
    raise ConfigError(tr("Unknown CDN command", "未知 CDN 命令"))


def _subscription(args: argparse.Namespace) -> int:
    if args.subscription_command == "serve":
        return subscription_serve()
    require_linux_root()
    settings, secrets = load_settings(), load_secrets()
    if args.subscription_command == "status":
        unit = Path("/etc/systemd/system/sbox5-subscription.service")
        active = run(["systemctl", "is-active", "sbox5-subscription.service"], check=False).stdout.strip() if unit.exists() else "not-installed"
        data = {
            "settings": settings.subscription.as_dict(),
            "config": subscription_status(SUBSCRIPTION_CONFIG_PATH),
            "service": active,
        }
        print(json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) if args.json else json.dumps(data, ensure_ascii=False, sort_keys=True))
        return 0
    if args.subscription_command == "url":
        token = subscription_read_token(SUBSCRIPTION_TOKEN_PATH)
        if not token:
            raise ConfigError(tr("The subscription token is missing", "订阅 Token 缺失"))
        url = subscription_base_url(settings, token) + "base64"
        print(url)
        if settings.subscription.bind == "127.0.0.1" and not settings.subscription.tls_profile:
            print(tr(
                "The service is bound to localhost. Publish it through a TLS reverse proxy before sharing the URL.",
                "服务绑定在 localhost。共享 URL 前请通过 TLS 反向代理发布。",
            ), file=sys.stderr)
        return 0
    if args.subscription_command == "set":
        settings.subscription.enabled = True
        if args.bind:
            settings.subscription.bind = args.bind
        if args.port is not None:
            settings.subscription.port = args.port
        if args.tls_profile is not None:
            settings.subscription.tls_profile = "" if args.tls_profile.lower() in ("none", "off", "disabled") else args.tls_profile
        return _apply_reconfigure(args, settings, secrets, "subscription")
    if args.subscription_command == "enable":
        settings.subscription.enabled = True
        return _apply_reconfigure(args, settings, secrets, "subscription")
    if args.subscription_command == "disable":
        settings.subscription.enabled = False
        return _apply_reconfigure(args, settings, secrets, "subscription")
    if args.subscription_command in ("start", "stop"):
        unit = Path("/etc/systemd/system/sbox5-subscription.service")
        if not unit.exists():
            raise ConfigError(tr("The subscription service is not installed", "订阅服务未安装"))
        run(["systemctl", args.subscription_command, "sbox5-subscription.service"], timeout=90)
        if args.subscription_command == "start":
            require_active("sbox5-subscription.service")
        return 0
    if args.subscription_command == "rotate":
        if not settings.subscription.enabled:
            raise ConfigError(tr("The subscription service is disabled", "订阅服务未启用"))
        token = subscription_generate_token()
        _apply_reconfigure(args, settings, secrets, "subscription", subscription_token=token)
        print(tr("New subscription URL: ", "新的订阅 URL：") + subscription_base_url(settings, token) + "base64")
        return 0
    raise ConfigError(tr("Unknown subscription command", "未知订阅命令"))


def _snapshots() -> int:
    require_linux_root()
    if not SNAPSHOT_ROOT.exists():
        return 0
    for path in sorted(SNAPSHOT_ROOT.iterdir(), reverse=True):
        manifest = path / "manifest.json"
        if path.is_dir() and manifest.is_file() and not path.name.startswith("pre-restore-"):
            data = load_json(manifest)
            print(f"{path.name}\t{data.get('state')}\t{data.get('created_at')}")
    return 0


def _rollback(args: argparse.Namespace) -> int:
    require_linux_root()
    if args.snapshot:
        snapshot = args.snapshot.resolve()
    else:
        candidates = []
        if SNAPSHOT_ROOT.exists():
            for path in SNAPSHOT_ROOT.iterdir():
                manifest = path / "manifest.json"
                if path.is_dir() and manifest.is_file() and not path.name.startswith("pre-restore-"):
                    if load_json(manifest).get("state") == "committed":
                        candidates.append(path)
        if not candidates:
            raise ConfigError(tr("There is no committed snapshot to restore", "没有可恢复的已提交快照"))
        snapshot = max(candidates)
    if snapshot.parent != SNAPSHOT_ROOT.resolve() or not (snapshot / "restore.py").is_file():
        raise ConfigError(tr("The snapshot must be a direct child directory of /var/lib/sbox5/snapshots", "快照必须位于 /var/lib/sbox5/snapshots 的直接子目录"))
    command = ["python3", "-I", str(snapshot / "restore.py"), "--snapshot", str(snapshot), "--lang", get_language()]
    if args.yes:
        command.append("--yes")
    return subprocess.run(command, shell=False, check=False).returncode


def build_parser() -> argparse.ArgumentParser:
    language = argparse.ArgumentParser(add_help=False)
    _add_language_argument(language)
    parser = argparse.ArgumentParser(
        prog="sbox5",
        description=tr("Auditable, rollback-ready sing-box five-protocol VPS manager", "可审计、可回滚的 sing-box 五协议 VPS 管理器"),
    )
    parser.add_argument("--project-root", type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument("--version", action="version", version=__version__)
    _add_language_argument(parser)
    commands = parser.add_subparsers(dest="command", required=True)
    install = commands.add_parser("install", parents=[language], help=tr("Fresh installation", "全新安装"))
    _add_install_arguments(install)
    upgrade = commands.add_parser("upgrade", parents=[language], help=tr("Upgrade from the current lock files", "按当前项目锁文件升级"))
    _add_install_arguments(upgrade)
    commands.add_parser("status", parents=[language], help=tr("Show non-sensitive runtime status", "显示非敏感运行状态"))
    show = commands.add_parser("show", parents=[language], help=tr("Show node credentials", "显示节点凭据"))
    show.add_argument("--protocol", choices=("vless", "vmess", "vmess-argo", "hysteria2", "tuic", "anytls"))
    show.add_argument("--json", action="store_true")
    show.add_argument("--qr", action="store_true")
    commands.add_parser("export", parents=[language], help=tr("Re-export local client files", "重新导出本地客户端文件"))
    commands.add_parser("check", parents=[language], help=tr("Validate server and client configurations", "检查服务端和客户端配置"))
    port = commands.add_parser("port", parents=[language], help=tr("Change protocol ports or UDP hopping ranges", "修改协议端口或 UDP 跳跃范围"))
    port_commands = port.add_subparsers(dest="port_command", required=True)
    port_set = port_commands.add_parser("set", parents=[language], help=tr("Change one protocol port", "修改单个协议端口"))
    port_set.add_argument("--protocol", choices=PROTOCOLS, required=True)
    port_set.add_argument("--port", type=int, required=True)
    port_set.add_argument("--yes", action="store_true")
    hopping = port_commands.add_parser("hopping", parents=[language], help=tr("Manage UDP port-hopping ranges", "管理 UDP 端口跳跃范围"))
    hopping_commands = hopping.add_subparsers(dest="hopping_command", required=True)
    hopping_set = hopping_commands.add_parser("set", parents=[language], help=tr("Set a UDP hopping range", "设置 UDP 跳跃范围"))
    hopping_set.add_argument("--protocol", choices=("hysteria2", "tuic"), required=True)
    hopping_set.add_argument("--range", required=True, metavar="START:END")
    hopping_set.add_argument("--yes", action="store_true")
    hopping_clear = hopping_commands.add_parser("clear", parents=[language], help=tr("Clear a UDP hopping range", "清除 UDP 跳跃范围"))
    hopping_clear.add_argument("--protocol", choices=("hysteria2", "tuic"), required=True)
    hopping_clear.add_argument("--yes", action="store_true")
    protocol = commands.add_parser("protocol", parents=[language], help=tr("Enable, disable, or re-bind a protocol", "启用、禁用或重新绑定协议"))
    protocol_commands = protocol.add_subparsers(dest="protocol_command", required=True)
    protocol_set = protocol_commands.add_parser("set", parents=[language], help=tr("Change protocol state or TLS profile", "修改协议状态或 TLS 配置"))
    protocol_set.add_argument("name", choices=PROTOCOLS)
    state = protocol_set.add_mutually_exclusive_group()
    state.add_argument("--enabled", action="store_true")
    state.add_argument("--disabled", action="store_true")
    protocol_set.add_argument("--tls-profile", help=tr("TLS profile ID, or 'none' to disable VMess TLS", "TLS 配置 ID，或用 none 关闭 VMess TLS"))
    protocol_set.add_argument("--yes", action="store_true")
    cert = commands.add_parser("cert", parents=[language], help=tr("Manage certificate profiles and bindings", "管理证书配置与绑定"))
    cert_commands = cert.add_subparsers(dest="cert_command", required=True)
    cert_list = cert_commands.add_parser("list", parents=[language], help=tr("List certificate profiles", "列出证书配置"))
    cert_list.add_argument("--json", action="store_true")
    cert_add = cert_commands.add_parser("add", parents=[language], help=tr("Add a certificate profile", "添加证书配置"))
    cert_add.add_argument("--id", required=True)
    cert_add.add_argument("--mode", choices=("self-signed", "acme", "imported"), required=True)
    cert_add.add_argument("--domain", action="append", default=[])
    cert_add.add_argument("--email")
    cert_add.add_argument("--server-name")
    cert_add.add_argument("--challenge", choices=("http-01", "dns-01", "tls-alpn-01"))
    cert_add.add_argument("--dns-provider", default="cloudflare")
    cert_add.add_argument("--ca-provider", default="letsencrypt")
    cert_add.add_argument("--acme-profile")
    cert_add.add_argument("--dns-token-file", type=Path)
    cert_add.add_argument("--cert", type=Path)
    cert_add.add_argument("--key", type=Path)
    cert_add.add_argument("--bind-protocol", choices=PROTOCOLS)
    cert_add.add_argument("--yes", action="store_true")
    cert_remove = cert_commands.add_parser("remove", parents=[language], help=tr("Remove an unbound certificate profile", "删除未绑定的证书配置"))
    cert_remove.add_argument("--id", required=True)
    cert_remove.add_argument("--yes", action="store_true")
    cert_bind = cert_commands.add_parser("bind", parents=[language], help=tr("Bind a protocol to a certificate profile", "将协议绑定到证书配置"))
    cert_bind.add_argument("--protocol", choices=PROTOCOLS, required=True)
    cert_bind.add_argument("--profile", required=True, help=tr("Profile ID, or 'none'", "配置 ID，或 none"))
    cert_bind.add_argument("--yes", action="store_true")
    argo = commands.add_parser("argo", parents=[language], help=tr("Manage the Cloudflare Argo tunnel", "管理 Cloudflare Argo 隧道"))
    argo_commands = argo.add_subparsers(dest="argo_command", required=True)
    argo_status = argo_commands.add_parser("status", parents=[language], help=tr("Show Argo status and quick URL", "显示 Argo 状态与临时 URL"))
    argo_status.add_argument("--json", action="store_true")
    argo_set = argo_commands.add_parser("set", parents=[language], help=tr("Configure quick or token mode", "配置 quick 或 token 模式"))
    argo_set.add_argument("--mode", choices=("quick", "token"), required=True)
    argo_set.add_argument("--hostname")
    argo_set.add_argument("--local-port", type=int)
    argo_set.add_argument("--token-file", type=Path)
    argo_set.add_argument("--yes", action="store_true")
    argo_start = argo_commands.add_parser("start", parents=[language], help=tr("Start the Argo service", "启动 Argo 服务"))
    argo_stop = argo_commands.add_parser("stop", parents=[language], help=tr("Stop the Argo service", "停止 Argo 服务"))
    argo_reset = argo_commands.add_parser("reset", parents=[language], help=tr("Reset quick tunnel or replace a token", "重置临时隧道或更换 Token"))
    argo_reset.add_argument("--token-file", type=Path)
    argo_reset.add_argument("--yes", action="store_true")
    warp = commands.add_parser("warp", parents=[language], help=tr("Manage native Cloudflare WARP credentials", "管理原生 Cloudflare WARP 凭证"))
    warp_commands = warp.add_subparsers(dest="warp_command", required=True)
    warp_status = warp_commands.add_parser("status", parents=[language], help=tr("Show WARP status without private keys", "显示 WARP 状态（不含私钥）"))
    warp_status.add_argument("--json", action="store_true")
    warp_register = warp_commands.add_parser("register", parents=[language], help=tr("Register a new WARP credential", "注册新的 WARP 凭证"))
    warp_register.add_argument("--yes", action="store_true")
    warp_rotate = warp_commands.add_parser("rotate", parents=[language], help=tr("Rotate the WARP credential", "轮换 WARP 凭证"))
    warp_rotate.add_argument("--yes", action="store_true")
    warp_import = warp_commands.add_parser("import", parents=[language], help=tr("Import a manual WireGuard WARP credential", "导入手动 WireGuard WARP 凭证"))
    warp_import.add_argument("--private-key-file", type=Path, required=True)
    warp_import.add_argument("--peer-public-key", required=True)
    warp_import.add_argument("--address", action="append", required=True)
    warp_import.add_argument("--reserved", default="0,0,0")
    warp_import.add_argument("--public-key")
    warp_import.add_argument("--peer-address", default="engage.cloudflareclient.com")
    warp_import.add_argument("--peer-port", type=int, default=2408)
    warp_import.add_argument("--client-id")
    warp_import.add_argument("--yes", action="store_true")
    warp_enable = warp_commands.add_parser("enable", parents=[language], help=tr("Enable a configured WARP credential", "启用已配置的 WARP 凭证"))
    warp_enable.add_argument("--yes", action="store_true")
    warp_disable = warp_commands.add_parser("disable", parents=[language], help=tr("Disable WARP without deleting credentials", "禁用 WARP，保留凭证"))
    warp_disable.add_argument("--yes", action="store_true")
    warp_clear = warp_commands.add_parser("clear", parents=[language], help=tr("Disable WARP and delete credentials", "禁用 WARP 并删除凭证"))
    warp_clear.add_argument("--yes", action="store_true")
    route = commands.add_parser("route", parents=[language], help=tr("Manage domain routing, Socks5, and rule sets", "管理域名分流、Socks5 与规则集"))
    route_commands = route.add_subparsers(dest="route_command", required=True)
    route_list = route_commands.add_parser("list", parents=[language], help=tr("Show routing state", "显示分流状态"))
    route_list.add_argument("--json", action="store_true")
    route_add = route_commands.add_parser("add", parents=[language], help=tr("Route domain suffixes to a target", "将域名后缀分流到目标"))
    route_add.add_argument("--target", choices=ROUTE_TARGETS, required=True)
    route_add.add_argument("--suffix", action="append", required=True)
    route_add.add_argument("--yes", action="store_true")
    route_remove = route_commands.add_parser("remove", parents=[language], help=tr("Remove domain suffixes from a route", "从路由中移除域名后缀"))
    route_remove.add_argument("--target", choices=ROUTE_TARGETS, required=True)
    route_remove.add_argument("--suffix", action="append", required=True)
    route_remove.add_argument("--yes", action="store_true")
    route_clear = route_commands.add_parser("clear", parents=[language], help=tr("Clear all domain routes", "清空所有域名路由"))
    route_clear.add_argument("--yes", action="store_true")
    socks5 = route_commands.add_parser("socks5", parents=[language], help=tr("Manage the optional Socks5 outbound", "管理可选 Socks5 出站"))
    socks5_commands = socks5.add_subparsers(dest="socks5_command", required=True)
    socks5_set = socks5_commands.add_parser("set", parents=[language], help=tr("Set Socks5 outbound parameters", "设置 Socks5 出站参数"))
    socks5_set.add_argument("--server", required=True)
    socks5_set.add_argument("--port", type=int, default=1080)
    socks5_set.add_argument("--username")
    socks5_set.add_argument("--password-file", type=Path)
    socks5_set.add_argument("--yes", action="store_true")
    socks5_clear = socks5_commands.add_parser("clear", parents=[language], help=tr("Remove the Socks5 outbound", "移除 Socks5 出站"))
    socks5_clear.add_argument("--yes", action="store_true")
    ruleset = route_commands.add_parser("ruleset", parents=[language], help=tr("Manage local .srs rule sets", "管理本地 .srs 规则集"))
    ruleset_commands = ruleset.add_subparsers(dest="ruleset_command", required=True)
    ruleset_list = ruleset_commands.add_parser("list", parents=[language], help=tr("List rule sets", "列出规则集"))
    ruleset_list.add_argument("--json", action="store_true")
    ruleset_add = ruleset_commands.add_parser("add", parents=[language], help=tr("Add a rule set from a local file or URL", "从本地文件或 URL 添加规则集"))
    ruleset_add.add_argument("--tag", required=True)
    ruleset_add.add_argument("--target", choices=ROUTE_TARGETS, required=True)
    ruleset_add.add_argument("--sha256", required=True)
    ruleset_add.add_argument("--filename")
    source = ruleset_add.add_mutually_exclusive_group(required=True)
    source.add_argument("--file", type=Path)
    source.add_argument("--url")
    ruleset_add.add_argument("--yes", action="store_true")
    ruleset_remove = ruleset_commands.add_parser("remove", parents=[language], help=tr("Remove a rule set", "移除规则集"))
    ruleset_remove.add_argument("--tag", required=True)
    ruleset_remove.add_argument("--yes", action="store_true")
    ruleset_update = ruleset_commands.add_parser("update", parents=[language], help=tr("Update a rule set hash or source", "更新规则集哈希或来源"))
    ruleset_update.add_argument("--tag", required=True)
    ruleset_update.add_argument("--sha256", required=True)
    ruleset_update.add_argument("--filename")
    update_source = ruleset_update.add_mutually_exclusive_group(required=True)
    update_source.add_argument("--file", type=Path)
    update_source.add_argument("--url")
    ruleset_update.add_argument("--yes", action="store_true")
    core = commands.add_parser("core", parents=[language], help=tr("Manage locked sing-box versions", "管理锁定的 sing-box 版本"))
    core_commands = core.add_subparsers(dest="core_command", required=True)
    core_status = core_commands.add_parser("status", parents=[language], help=tr("Show the active core version", "显示当前内核版本"))
    core_status.add_argument("--json", action="store_true")
    core_list = core_commands.add_parser("list", parents=[language], help=tr("List locked versions and channels", "列出锁定版本与通道"))
    core_list.add_argument("--json", action="store_true")
    core_switch = core_commands.add_parser("switch", parents=[language], help=tr("Switch to a locked core version", "切换到已锁定内核版本"))
    core_target = core_switch.add_mutually_exclusive_group(required=True)
    core_target.add_argument("--version")
    core_target.add_argument("--channel", choices=("stable", "beta"))
    core_switch.add_argument("--yes", action="store_true")
    core_rollback = core_commands.add_parser("rollback", parents=[language], help=tr("Roll back to the previous core version", "回滚到上一版内核"))
    core_rollback.add_argument("--yes", action="store_true")
    cdn = commands.add_parser("cdn", parents=[language], help=tr("Manage VMess/Argo CDN preference", "管理 VMess/Argo CDN 优选"))
    cdn_commands = cdn.add_subparsers(dest="cdn_command", required=True)
    cdn_list = cdn_commands.add_parser("list", parents=[language], help=tr("Show CDN settings", "显示 CDN 设置"))
    cdn_list.add_argument("--json", action="store_true")
    cdn_set = cdn_commands.add_parser("set", parents=[language], help=tr("Set a CDN preferred address", "设置 CDN 优选地址"))
    cdn_set.add_argument("--target", choices=("vmess", "argo"), required=True)
    cdn_set.add_argument("--address", required=True)
    cdn_set.add_argument("--port", type=int, default=443)
    cdn_set.add_argument("--host")
    cdn_set.add_argument("--sni")
    cdn_set.add_argument("--yes", action="store_true")
    cdn_clear = cdn_commands.add_parser("clear", parents=[language], help=tr("Clear CDN settings for a target", "清除目标的 CDN 设置"))
    cdn_clear.add_argument("--target", choices=("vmess", "argo"), required=True)
    cdn_clear.add_argument("--yes", action="store_true")
    subscription = commands.add_parser("subscription", parents=[language], help=tr("Manage the local subscription service", "管理本地订阅服务"))
    subscription_commands = subscription.add_subparsers(dest="subscription_command", required=True)
    subscription_status = subscription_commands.add_parser("status", parents=[language], help=tr("Show subscription service status", "显示订阅服务状态"))
    subscription_status.add_argument("--json", action="store_true")
    subscription_commands.add_parser("url", parents=[language], help=tr("Print the tokenized subscription URL", "输出带 Token 的订阅 URL"))
    subscription_set = subscription_commands.add_parser("set", parents=[language], help=tr("Configure and enable the subscription service", "配置并启用订阅服务"))
    subscription_set.add_argument("--bind", choices=("127.0.0.1", "0.0.0.0"))
    subscription_set.add_argument("--port", type=int)
    subscription_set.add_argument("--tls-profile", help=tr("Self-signed/imported profile ID, or 'none'", "自签/导入证书配置 ID，或 none"))
    subscription_set.add_argument("--yes", action="store_true")
    subscription_enable = subscription_commands.add_parser("enable", parents=[language], help=tr("Enable the subscription service", "启用订阅服务"))
    subscription_enable.add_argument("--yes", action="store_true")
    subscription_disable = subscription_commands.add_parser("disable", parents=[language], help=tr("Disable and remove the subscription service", "禁用并移除订阅服务"))
    subscription_disable.add_argument("--yes", action="store_true")
    subscription_commands.add_parser("start", parents=[language], help=tr("Start the subscription service", "启动订阅服务"))
    subscription_commands.add_parser("stop", parents=[language], help=tr("Stop the subscription service", "停止订阅服务"))
    subscription_rotate = subscription_commands.add_parser("rotate", parents=[language], help=tr("Rotate the subscription path token", "轮换订阅路径 Token"))
    subscription_rotate.add_argument("--yes", action="store_true")
    commands.add_parser("subscription-serve", parents=[language], help=argparse.SUPPRESS).add_argument("--non-interactive", action="store_true")
    commands.add_parser("ddns-update", parents=[language], help=argparse.SUPPRESS).add_argument("--non-interactive", action="store_true")
    commands.add_parser("firewall-apply", parents=[language], help=argparse.SUPPRESS).add_argument("--non-interactive", action="store_true")
    commands.add_parser("snapshots", parents=[language], help=tr("List transaction snapshots", "列出事务快照"))
    rollback = commands.add_parser("rollback", parents=[language], help=tr("Restore a snapshot with the standalone restorer", "使用独立恢复器恢复快照"))
    rollback.add_argument("--snapshot", type=Path)
    rollback.add_argument("--yes", action="store_true")
    uninstall = commands.add_parser("uninstall", parents=[language], help=tr("Remove project files and rules, keeping snapshots and packages", "移除项目文件和规则，保留快照与软件包"))
    uninstall.add_argument("--yes", action="store_true")
    uninstall.add_argument("--non-interactive", action="store_true")
    hidden = {"ddns-update", "firewall-apply", "subscription-serve"}
    commands._choices_actions = [action for action in commands._choices_actions if action.dest not in hidden]
    return parser


def main(argv: list[str] | None = None) -> int:
    raw = list(sys.argv[1:] if argv is None else argv)
    set_language(resolve_language(raw))
    parser = build_parser()
    args = parser.parse_args(raw)
    try:
        requested = getattr(args, "lang", None)
        if requested is not None:
            normalized = normalize_language(requested)
            if normalized is None:
                raise ConfigError(tr(f"Unsupported language: {requested}; use en or zh-CN", f"不支持的语言：{requested}；请使用 en 或 zh-CN"))
            set_language(normalized)
        if args.command in ("install", "upgrade"):
            return _install(args, args.command == "upgrade")
        if args.command == "status":
            return _status()
        if args.command == "show":
            return _show(args)
        if args.command == "export":
            return _export()
        if args.command == "check":
            return _check()
        if args.command == "port":
            return _port(args)
        if args.command == "protocol":
            return _protocol(args)
        if args.command == "cert":
            return _certificate(args)
        if args.command == "argo":
            return _argo(args)
        if args.command == "warp":
            return _warp(args)
        if args.command == "route":
            return _route(args)
        if args.command == "core":
            return _core(args)
        if args.command == "cdn":
            return _cdn(args)
        if args.command == "subscription":
            return _subscription(args)
        if args.command == "subscription-serve":
            return subscription_serve()
        if args.command == "ddns-update":
            return _ddns_update()
        if args.command == "firewall-apply":
            return _firewall_apply()
        if args.command == "snapshots":
            return _snapshots()
        if args.command == "rollback":
            return _rollback(args)
        if args.command == "uninstall":
            from .uninstall import uninstall
            return uninstall(args)
        parser.error(tr("Unknown command", "未知命令"))
    except (SBox5Error, OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        print(tr("Error: ", "错误：") + str(exc), file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print(tr("Operation cancelled.", "操作已取消。"), file=sys.stderr)
        return 130
    return 0
