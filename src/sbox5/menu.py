# Copyright (C) 2026 Bosco1262
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import sys

from .dashboard import render_text, status_data
from .errors import ConfigError
from .i18n import get_language, tr
from .installer import load_secrets, load_settings
from .models import PROTOCOLS


MENU = (
    ("1", tr("Status dashboard", "状态面板")),
    ("2", tr("Show node links and QR codes", "显示节点链接与二维码")),
    ("3", tr("Re-export client files", "重新导出客户端文件")),
    ("4", tr("Enable or disable a protocol", "启用或禁用协议")),
    ("5", tr("Change a protocol port", "修改协议端口")),
    ("6", tr("List certificate profiles", "列出证书配置")),
    ("7", tr("Argo status", "Argo 状态")),
    ("8", tr("WARP status", "WARP 状态")),
    ("9", tr("Routing status", "分流状态")),
    ("10", tr("Core versions", "内核版本")),
    ("11", tr("Subscription status", "订阅状态")),
    ("12", tr("IPv4/IPv6 export family", "IPv4/IPv6 导出地址族")),
    ("13", tr("Service logs", "服务日志")),
    ("14", tr("Health check", "健康检查")),
    ("15", tr("Snapshots", "事务快照")),
    ("16", tr("IP geolocation", "IP 归属地")),
    ("0", tr("Exit", "退出")),
)

SERVICES = ("core", "argo", "ddns", "subscription", "firewall")


def _call(arguments: list[str]) -> int:
    from .cli import main
    try:
        return main(["--language", get_language(), *arguments])
    except SystemExit as exc:
        return int(exc.code or 1)


def _pause() -> None:
    try:
        input(tr("\nPress Enter to continue...", "\n按回车继续..."))
    except EOFError:
        raise SystemExit(0)


def _ask(prompt: str) -> str:
    try:
        return input(prompt).strip()
    except EOFError:
        raise SystemExit(0)


def run() -> int:
    if not sys.stdin.isatty():
        raise ConfigError(tr("The interactive menu needs a terminal", "交互菜单需要终端"))
    while True:
        try:
            settings, secrets = load_settings(), load_secrets()
            print("")
            print(render_text(status_data(settings, secrets)))
            print("")
            for key, label in MENU:
                print(f"  {key.rjust(2)}. {label}")
            choice = _ask(tr("Choice: ", "选择："))
        except (OSError, ValueError, KeyError) as exc:
            print(tr("Unable to read the current state: ", "无法读取当前状态：") + str(exc), file=sys.stderr)
            return 1
        if choice == "0":
            return 0
        if choice == "1":
            _pause()
            continue
        if choice == "2":
            _call(["show"])
        elif choice == "3":
            _call(["export"])
        elif choice == "4":
            name = _ask(tr("Protocol (vless/vmess/hysteria2/tuic/anytls): ", "协议（vless/vmess/hysteria2/tuic/anytls）："))
            if name not in PROTOCOLS:
                print(tr("Unknown protocol", "未知协议"))
                _pause()
                continue
            state = _ask(tr("Enable? [y/N]: ", "启用？[y/N]：")).lower() in ("y", "yes")
            _call(["protocol", "set", name, "--enabled" if state else "--disabled", "--yes"])
        elif choice == "5":
            name = _ask(tr("Protocol: ", "协议："))
            if name not in PROTOCOLS:
                print(tr("Unknown protocol", "未知协议"))
                _pause()
                continue
            port = _ask(tr("New port: ", "新端口："))
            _call(["port", "set", "--protocol", name, "--port", port, "--yes"])
        elif choice == "6":
            _call(["cert", "list"])
        elif choice == "7":
            _call(["argo", "status"])
        elif choice == "8":
            _call(["warp", "status"])
        elif choice == "9":
            _call(["route", "list"])
        elif choice == "10":
            _call(["core", "list"])
        elif choice == "11":
            _call(["subscription", "status"])
        elif choice == "12":
            print(tr("Current: ", "当前：") + settings.output_family)
            family = _ask(tr("Family (auto/ipv4/ipv6): ", "地址族（auto/ipv4/ipv6）："))
            if family not in ("auto", "ipv4", "ipv6"):
                print(tr("Unknown family", "未知地址族"))
                _pause()
                continue
            _call(["ip", "set", "--family", family, "--yes"])
        elif choice == "13":
            service = _ask(tr("Service (core/argo/ddns/subscription/firewall): ", "服务（core/argo/ddns/subscription/firewall）："))
            if service not in SERVICES:
                print(tr("Unknown service", "未知服务"))
                _pause()
                continue
            _call(["logs", "--service", service])
        elif choice == "14":
            _call(["doctor"])
        elif choice == "15":
            _call(["snapshots"])
        elif choice == "16":
            print(render_text(status_data(settings, secrets, geo=True)))
        else:
            print(tr("Unknown choice", "未知选项"))
        _pause()
