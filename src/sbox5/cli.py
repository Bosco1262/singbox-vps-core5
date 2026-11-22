# Copyright (C) 2026 Bosco1262
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import argparse
from getpass import getpass
import ipaddress
import json
from pathlib import Path
import stat
import subprocess
import sys

from . import __version__
from .certificates import install_acme_certificate, renew_acme
from .config import CERTIFICATE_PATH, KEY_PATH, check_server_config
from .ddns import CloudflareDDNS
from .errors import ConfigError, SBox5Error
from .export import build_share_links, export_nodes
from .firewall import apply_firewall
from .i18n import get_language, normalize_language, resolve_language, set_language, tr
from .installer import (
    ARGO_TOKEN_PATH,
    CERTIFICATE_STATE_PATH,
    DDNS_STATE_PATH,
    DDNS_TOKEN_PATH,
    EXPORT_DIR,
    FIREWALL_STATE_PATH,
    SINGBOX_BINARY,
    STATE_PATH,
    InstallTransaction,
    load_secrets,
    load_settings,
)
from .models import ArgoSettings, DDNSSettings, Ports, Secrets, Settings
from .services import identity, require_active, restart
from .snapshot import SNAPSHOT_ROOT
from .system import read_token_file, validate_token_text
from .util import atomic_json, atomic_write, available, load_json, require_linux_root, run, split_host_port


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


def _add_install_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--host")
    parser.add_argument("--reality-target")
    parser.add_argument("--reality-sni")
    parser.add_argument("--certificate-mode", choices=("self-signed", "acme"))
    parser.add_argument("--domain")
    parser.add_argument("--acme-email")
    for protocol in ("vless", "vmess", "hysteria2", "tuic", "anytls"):
        parser.add_argument(f"--{protocol}-port", type=int)
    parser.add_argument("--firewall", action=argparse.BooleanOptionalAction, default=None)
    parser.add_argument("--bbr", action=argparse.BooleanOptionalAction, default=None)
    hopping = parser.add_mutually_exclusive_group()
    hopping.add_argument("--hysteria2-port-hopping", metavar="START:END")
    hopping.add_argument("--no-port-hopping", action="store_true")
    parser.add_argument("--ddns", action=argparse.BooleanOptionalAction, default=None)
    parser.add_argument("--cloudflare-zone")
    parser.add_argument("--ddns-record")
    parser.add_argument("--ddns-ipv4", action=argparse.BooleanOptionalAction, default=None)
    parser.add_argument("--ddns-ipv6", action=argparse.BooleanOptionalAction, default=None)
    parser.add_argument("--ddns-interval", type=int)
    parser.add_argument("--ddns-token-file", type=Path)
    parser.add_argument("--argo", action=argparse.BooleanOptionalAction, default=None)
    parser.add_argument("--argo-hostname")
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
    ports = Ports()
    for protocol in ports.as_dict():
        argument = getattr(args, f"{protocol}_port")
        if argument is not None:
            setattr(ports, protocol, argument)
        elif previous:
            setattr(ports, protocol, getattr(previous.ports, protocol))
    hopping = dict(previous.port_hopping) if previous else {}
    if args.no_port_hopping:
        hopping = {}
    elif args.hysteria2_port_hopping:
        hopping = {"hysteria2": args.hysteria2_port_hopping}
    tls_server_name = ""
    if previous and certificate_mode == previous.certificate_mode:
        tls_server_name = previous.tls_server_name
    settings = Settings(
        host=host,
        reality_target=reality_target,
        reality_sni=reality_sni,
        ports=ports,
        domain=domain,
        certificate_mode=certificate_mode,
        acme_email=args.acme_email if args.acme_email is not None else (previous.acme_email if previous else ""),
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
            hostname=args.argo_hostname or (previous.argo.hostname if previous else ""),
        ),
    )
    if argo_enabled:
        settings.argo.hostname = _prompt(settings.argo.hostname, tr("Argo public hostname", "Argo 公网域名"), args)
    settings.validate()
    ddns_token = read_token_file(args.ddns_token_file, "Cloudflare Token") if args.ddns_token_file else ""
    argo_token = read_token_file(args.argo_token_file, "Argo Token") if args.argo_token_file else ""
    if ddns_enabled and not ddns_token and not DDNS_TOKEN_PATH.is_file():
        ddns_token = _prompt("", tr("Cloudflare API Token (input hidden)", "Cloudflare API Token（输入不可见）"), args, secret=True)
    if argo_enabled and not argo_token and not ARGO_TOKEN_PATH.is_file():
        argo_token = _prompt("", tr("Argo Tunnel Token (input hidden)", "Argo Tunnel Token（输入不可见）"), args, secret=True)
    if ddns_token:
        ddns_token = validate_token_text(ddns_token, "Cloudflare Token")
    if argo_token:
        argo_token = validate_token_text(argo_token, "Argo Token")
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
    argo_state = tr("enabled ", "启用 ") + settings.argo.hostname if settings.argo.enabled else tr("disabled", "禁用")
    print(f" - DDNS: {ddns_state}")
    print(f" - Argo: {argo_state}")
    print(f" - {tr('Firewall auto-management', '防火墙自动管理')}: {settings.manage_firewall}; BBR: {settings.bbr}")
    _confirm(args, tr("Continue?", "确认继续吗？"))
    result = InstallTransaction(
        args.project_root, settings, secrets, upgrade=upgrade, ddns_token=ddns_token, argo_token=argo_token,
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
    print(json.dumps({
        "project_version": state.get("project_version"),
        "installed_at": state.get("installed_at"),
        "components": state.get("components"),
        "snapshot_id": state.get("snapshot_id"),
    }, ensure_ascii=False, indent=2, sort_keys=True))
    for name in ("sbox5.service", "sbox5-argo.service", "sbox5-ddns.timer", "sbox5-acme.timer", "sbox5-firewall.service"):
        if (Path("/etc/systemd/system") / name).exists():
            result = run(["systemctl", "is-active", name], check=False)
            print(f"{name}: {result.stdout.strip() or result.returncode}")
    if DDNS_STATE_PATH.is_file():
        print(tr("DDNS state: ", "DDNS 状态：") + json.dumps(load_json(DDNS_STATE_PATH), ensure_ascii=False, sort_keys=True))
    return 0


def _show(args: argparse.Namespace) -> int:
    require_linux_root()
    settings, secrets = load_settings(), load_secrets()
    metadata = load_json(CERTIFICATE_STATE_PATH)
    links = build_share_links(settings, secrets, metadata)
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
    metadata = load_json(CERTIFICATE_STATE_PATH)
    result = export_nodes(settings, secrets, CERTIFICATE_PATH, metadata, EXPORT_DIR)
    check_server_config(SINGBOX_BINARY, EXPORT_DIR / "sing-box-client.json")
    print(tr("Exported to ", "已导出到 ") + str(EXPORT_DIR))
    for warning in result["warnings"]:
        print(tr("Warning: ", "警告：") + warning)
    return 0


def _check() -> int:
    require_linux_root()
    check_server_config(SINGBOX_BINARY, Path("/etc/sbox5/config.json"))
    check_server_config(SINGBOX_BINARY, EXPORT_DIR / "sing-box-client.json")
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


def _acme_renew() -> int:
    require_linux_root()
    settings = load_settings()
    if settings.certificate_mode != "acme":
        raise ConfigError(tr("The current mode is not ACME", "当前不是 ACME 模式"))
    old_certificate, old_key = CERTIFICATE_PATH.read_bytes(), KEY_PATH.read_bytes()
    cert_stat, key_stat = CERTIFICATE_PATH.stat(), KEY_PATH.stat()
    renew_acme()
    uid, gid = identity("sbox5")
    try:
        metadata = install_acme_certificate(settings.domain, CERTIFICATE_PATH, KEY_PATH, uid, gid)
        check_server_config(SINGBOX_BINARY, Path("/etc/sbox5/config.json"))
        if old_certificate != CERTIFICATE_PATH.read_bytes() or old_key != KEY_PATH.read_bytes():
            restart("sbox5.service")
            require_active("sbox5.service")
    except Exception as exc:
        atomic_write(CERTIFICATE_PATH, old_certificate, stat.S_IMODE(cert_stat.st_mode), cert_stat.st_uid, cert_stat.st_gid)
        atomic_write(KEY_PATH, old_key, stat.S_IMODE(key_stat.st_mode), key_stat.st_uid, key_stat.st_gid)
        check_server_config(SINGBOX_BINARY, Path("/etc/sbox5/config.json"))
        restart("sbox5.service")
        raise ConfigError(tr(f"Failed to deploy the new certificate; the previous certificate was restored: {exc}", f"新证书部署失败，已恢复旧证书：{exc}")) from exc
    atomic_json(CERTIFICATE_STATE_PATH, metadata, 0o600)
    try:
        export_nodes(settings, load_secrets(), CERTIFICATE_PATH, metadata, EXPORT_DIR)
    except SBox5Error as exc:
        print(tr(f"Warning: the certificate was updated but refreshing the exported files failed: {exc}", f"警告：证书已更新，但导出文件刷新失败：{exc}"), file=sys.stderr)
    print(tr("ACME renewal and configuration check completed.", "ACME 续期与配置检查完成。"))
    return 0


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
    commands.add_parser("ddns-update", parents=[language], help=argparse.SUPPRESS).add_argument("--non-interactive", action="store_true")
    commands.add_parser("firewall-apply", parents=[language], help=argparse.SUPPRESS).add_argument("--non-interactive", action="store_true")
    commands.add_parser("acme-renew", parents=[language], help=argparse.SUPPRESS).add_argument("--non-interactive", action="store_true")
    commands.add_parser("snapshots", parents=[language], help=tr("List transaction snapshots", "列出事务快照"))
    rollback = commands.add_parser("rollback", parents=[language], help=tr("Restore a snapshot with the standalone restorer", "使用独立恢复器恢复快照"))
    rollback.add_argument("--snapshot", type=Path)
    rollback.add_argument("--yes", action="store_true")
    uninstall = commands.add_parser("uninstall", parents=[language], help=tr("Remove project files and rules, keeping snapshots and packages", "移除项目文件和规则，保留快照与软件包"))
    uninstall.add_argument("--yes", action="store_true")
    uninstall.add_argument("--non-interactive", action="store_true")
    hidden = {"ddns-update", "firewall-apply", "acme-renew"}
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
        if args.command == "ddns-update":
            return _ddns_update()
        if args.command == "firewall-apply":
            return _firewall_apply()
        if args.command == "acme-renew":
            return _acme_renew()
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
