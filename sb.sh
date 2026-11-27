#!/bin/sh
# Copyright (C) 2026 Bosco1262
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Upstream-style interactive console for sbox5.
# This script only renders menus and passes explicit arguments to the sbox5
# Python CLI. It never edits configuration, services, firewall, or sysctl.

set -u
umask 077

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
SBOX5=${SBOX5_BIN:-"$SCRIPT_DIR/sbox5"}
LANG_ARG=
NO_COLOR=${NO_COLOR:-}

usage() {
    cat <<'EOF'
Usage: sudo ./sb.sh [options]

Options:
  -h, --help              Show this help
  --version               Show the sbox5 version
  -l, --lang LANGUAGE     Language passed to sbox5 (en or zh-CN)
  --language LANGUAGE     Alias for --lang
  --no-color              Disable ANSI colors

The console is a menu front-end. Every privileged action is executed by the
sbox5 Python CLI, which owns snapshots, locks, validation, and rollback.
EOF
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        -h|--help)
            usage
            exit 0
            ;;
        --version)
            if [ -x "$SBOX5" ]; then
                "$SBOX5" --version
            else
                printf '%s\n' "sbox5 upstream-compatible console"
            fi
            exit 0
            ;;
        -l|--lang|--language)
            if [ "$#" -lt 2 ]; then
                printf '%s\n' "missing language value" >&2
                exit 2
            fi
            LANG_ARG=$2
            shift 2
            continue
            ;;
        --no-color)
            NO_COLOR=1
            shift
            continue
            ;;
        *)
            printf 'unknown option: %s\n' "$1" >&2
            usage >&2
            exit 2
            ;;
    esac
done

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
    ESC=$(printf '\033')
    RED="${ESC}[31;1m"
    GREEN="${ESC}[32;1m"
    YELLOW="${ESC}[33;1m"
    BLUE="${ESC}[36;1m"
    CYAN="${ESC}[35;1m"
    DIM="${ESC}[2m"
    RESET="${ESC}[0m"
else
    RED= GREEN= YELLOW= BLUE= CYAN= DIM= RESET=
fi

say() { printf '%s\n' "$*"; }
ok() { printf '%s%s%s\n' "$GREEN" "$*" "$RESET"; }
warn() { printf '%s%s%s\n' "$YELLOW" "$*" "$RESET"; }
err() { printf '%s%s%s\n' "$RED" "$*" "$RESET" >&2; }
section() { printf '%s\n' "--------------------------------------------------------------------------------"; }
item() { printf '  %s%2s%s. %s\n' "$CYAN" "$1" "$RESET" "$2"; }

clear_screen() {
    if [ -t 1 ]; then
        clear 2>/dev/null || true
    fi
}

pause() {
    printf '%s' "${DIM}按回车继续 / Press Enter to continue...${RESET}"
    IFS= read -r _ || exit 0
}

ask() {
    printf '%s' "${YELLOW}$1${RESET}"
    IFS= read -r REPLY || exit 0
}

ask_default() {
    if [ -n "$2" ]; then
        printf '%s [%s]: ' "$1" "$2"
    else
        printf '%s: ' "$1"
    fi
    IFS= read -r REPLY || exit 0
    if [ -z "$REPLY" ] && [ -n "$2" ]; then
        REPLY=$2
    fi
}

confirm() {
    printf '%s [y/N]: ' "$1"
    IFS= read -r REPLY || exit 0
    case "$REPLY" in
        y|Y|yes|YES) return 0 ;;
        *) return 1 ;;
    esac
}

run_sbox5() {
    if [ -n "$LANG_ARG" ]; then
        set -- --language "$LANG_ARG" "$@"
    fi
    if "$SBOX5" "$@"; then
        return 0
    fi
    status=$?
    printf '\n%s操作失败 / Operation failed (exit %s)%s\n' "$RED" "$status" "$RESET" >&2
    return "$status"
}

require_host() {
    if [ "$(uname -s 2>/dev/null)" != "Linux" ]; then
        err "此控制台仅支持 Linux / This console requires Linux."
        exit 1
    fi
    if [ "$(id -u 2>/dev/null)" -ne 0 ]; then
        err "请使用 sudo 运行 / Run it as root: sudo ./sb.sh"
        exit 1
    fi
    if [ ! -x "$SBOX5" ]; then
        err "找不到可执行的 sbox5 / Cannot execute sbox5: $SBOX5"
        err "请先执行 chmod +x sbox5 / Run: chmod +x sbox5"
        exit 1
    fi
}

banner() {
    printf '%s\n' "============================================================"
    printf '%s\n' "  sbox5 · 上游兼容控制台 / upstream-compatible console"
    printf '%s\n' "  界面仿照上游流程，安全逻辑由 sbox5 Python 引擎执行"
    printf '%s\n' "  Menu-style front-end; all changes go through sbox5."
    printf '%s\n' "============================================================"
}

status_header() {
    if [ -f /etc/sbox5/settings.json ]; then
        run_sbox5 status --text 2>/dev/null || warn "状态读取失败 / Unable to read status"
    else
        warn "尚未安装 / Not installed"
    fi
}

main_menu() {
    section
    item 1 "一键安装 / Install"
    item 2 "卸载 / Uninstall"
    section
    item 3 "变更配置 / Change configuration"
    item 4 "端口与跳跃 / Ports and hopping"
    item 5 "域名分流 / Routing"
    item 6 "服务控制 / Service control"
    item 7 "更新与回滚 / Update and rollback"
    item 8 "内核版本 / Core versions"
    section
    item 9 "刷新与查看节点 / Refresh nodes"
    item 10 "服务日志 / Logs"
    item 11 "BBR 加速 / BBR"
    item 12 "证书与 ACME / Certificates"
    item 13 "WARP 出站 / WARP"
    item 14 "IP 地址 / IP addresses"
    item 15 "使用说明 / Help"
    section
    item 0 "退出 / Exit"
    section
}

ask_service() {
    ask_default "服务 / Service (core/argo/ddns/subscription/firewall)" "core"
    case "$REPLY" in
        core|argo|ddns|subscription|firewall) SERVICE=$REPLY; return 0 ;;
        *) warn "未知服务 / Unknown service"; return 1 ;;
    esac
}

install_wizard() (
    if [ -f /etc/sbox5/settings.json ]; then
        warn "检测到已安装。请使用菜单 7.2 升级，或先卸载再安装。"
        warn "Existing installation detected. Use menu 7.2, or uninstall first."
        return 0
    fi

    say "安装向导 / Installation wizard"
    say "Token、ACME 密钥和最终确认由 Python 端安全处理。"
    say "Tokens, ACME keys, and the final confirmation are handled by Python."
    section

    set -- install

    ask "公网 IP/域名（留空自动探测）/ Public IP or domain (blank = auto-detect): "
    if [ -n "$REPLY" ]; then
        set -- "$@" --host="$REPLY"
    fi

    ask_default "Reality 目标 / target" "www.apple.com:443"
    REALITY_TARGET=$REPLY
    set -- "$@" --reality-target="$REALITY_TARGET"

    ask "Reality SNI（留空从目标提取）/ SNI (blank = derive from target): "
    if [ -n "$REPLY" ]; then set -- "$@" --reality-sni="$REPLY"; fi

    say "证书模式 / Certificate mode:"
    say "  1. 自签 self-signed (默认/default)"
    say "  2. ACME (sing-box 原生)"
    ask "选择 / Choice [1]: "
    case "${REPLY:-1}" in
        2)
            set -- "$@" --certificate-mode=acme
            ask "ACME 域名 / domain: "
            if [ -n "$REPLY" ]; then set -- "$@" --domain="$REPLY"; fi
            ask "ACME 邮箱 / email: "
            if [ -n "$REPLY" ]; then set -- "$@" --acme-email="$REPLY"; fi
            say "验证方式 / Challenge:"
            say "  1. http-01 (默认/default)"
            say "  2. tls-alpn-01"
            say "  3. dns-01 (Cloudflare)"
            ask "选择 / Choice [1]: "
            case "${REPLY:-1}" in
                2) set -- "$@" --acme-challenge=tls-alpn-01 ;;
                3) set -- "$@" --acme-challenge=dns-01 --acme-dns-provider=cloudflare ;;
                *) set -- "$@" --acme-challenge=http-01 ;;
            esac
            ;;
        *)
            set -- "$@" --certificate-mode=self-signed
            ;;
    esac

    if confirm "启用 VMess TLS？/ Enable VMess TLS?"; then
        set -- "$@" --vmess-tls
    else
        set -- "$@" --no-vmess-tls
    fi

    say "端口 / Ports:"
    say "  1. 随机随机空闲端口 random free ports (默认/default)"
    say "  2. 自定义 custom"
    ask "选择 / Choice [1]: "
    case "${REPLY:-1}" in
        2)
            for proto in vless vmess hysteria2 tuic anytls; do
                ask "  $proto 端口 / port: "
                case "$REPLY" in
                    ''|*[!0-9]*) err "端口必须为数字 / Port must be numeric"; return 1 ;;
                esac
                set -- "$@" "--${proto}-port=$REPLY"
            done
            ;;
    esac

    if confirm "启用 Cloudflare DDNS？/ Enable DDNS?"; then
        set -- "$@" --ddns
        ask "Cloudflare Zone（如 example.com）: "
        if [ -n "$REPLY" ]; then set -- "$@" --cloudflare-zone="$REPLY"; fi
        ask "DDNS 完整记录（如 vpn.example.com）: "
        if [ -n "$REPLY" ]; then set -- "$@" --ddns-record="$REPLY"; fi
    else
        set -- "$@" --no-ddns
    fi

    if confirm "启用 Argo 隧道？/ Enable Argo tunnel?"; then
        set -- "$@" --argo
        say "Argo 模式 / Mode: 1 quick 2 token (默认/default)"
        ask "选择 / Choice [2]: "
        case "${REPLY:-2}" in
            1) set -- "$@" --argo-mode=quick ;;
            *)
                set -- "$@" --argo-mode=token
                ask "Argo 公网域名 / hostname: "
                if [ -n "$REPLY" ]; then set -- "$@" --argo-hostname="$REPLY"; fi
                ;;
        esac
    else
        set -- "$@" --no-argo
    fi

    if confirm "开启 BBR？/ Enable BBR?"; then
        set -- "$@" --bbr
    else
        set -- "$@" --no-bbr
    fi

    if confirm "自动管理防火墙？/ Manage firewall?"; then
        set -- "$@" --firewall
    else
        set -- "$@" --no-firewall
    fi

    section
    say "即将调用 sbox5 install；请阅读 Python 端摘要并确认。"
    say "Calling sbox5 install; review the Python summary and confirm."
    run_sbox5 "$@"
)

reality_action() (
    ask_default "Reality 目标 / target" "www.apple.com:443"
    TARGET=$REPLY
    ask "Reality SNI（留空从目标提取）/ SNI (blank = derive): "
    if [ -n "$REPLY" ]; then
        run_sbox5 reality set --target="$TARGET" --sni="$REPLY"
    else
        run_sbox5 reality set --target="$TARGET"
    fi
)

secrets_action() (
    say "轮换后旧客户端链接立即失效，需要重新导入导出文件。"
    say "Rotation invalidates existing client links; re-import the exports."
    say "  1. all"
    say "  2. vless"
    say "  3. vmess"
    say "  4. hysteria2"
    say "  5. tuic"
    say "  6. anytls"
    say "  0. 返回 / Back"
    ask "选择 / Choice: "
    case "$REPLY" in
        1) SCOPE=all ;;
        2) SCOPE=vless ;;
        3) SCOPE=vmess ;;
        4) SCOPE=hysteria2 ;;
        5) SCOPE=tuic ;;
        6) SCOPE=anytls ;;
        0) return 0 ;;
        *) warn "未知选项 / Unknown choice"; return 0 ;;
    esac
    run_sbox5 secrets rotate --protocol="$SCOPE"
)

argo_action() (
    say "  1. 状态 / status"
    say "  2. quick 隧道 / quick tunnel"
    say "  3. token 隧道 / token tunnel"
    say "  4. 启动 / start"
    say "  5. 停止 / stop"
    say "  6. 重置 / reset"
    say "  0. 返回 / Back"
    ask "选择 / Choice: "
    case "$REPLY" in
        1) run_sbox5 argo status ;;
        2) run_sbox5 argo set --mode=quick ;;
        3)
            ask "Argo 公网域名 / hostname: "
            if [ -n "$REPLY" ]; then
                run_sbox5 argo set --mode=token --hostname="$REPLY"
            else
                run_sbox5 argo set --mode=token
            fi
            ;;
        4) run_sbox5 argo start ;;
        5) run_sbox5 argo stop ;;
        6) run_sbox5 argo reset ;;
        0) return 0 ;;
        *) warn "未知选项 / Unknown choice" ;;
    esac
)

ip_action() (
    say "  1. 查看地址 / show addresses"
    say "  2. 设置导出地址族 / set export family"
    say "  0. 返回 / Back"
    ask "选择 / Choice: "
    case "$REPLY" in
        1) run_sbox5 ip show ;;
        2)
            say "  1. auto  2. ipv4  3. ipv6"
            ask "选择 / Choice: "
            case "$REPLY" in
                1) FAMILY=auto ;;
                2) FAMILY=ipv4 ;;
                3) FAMILY=ipv6 ;;
                *) warn "未知选项 / Unknown choice"; return 0 ;;
            esac
            run_sbox5 ip set --family="$FAMILY"
            ;;
        0) return 0 ;;
        *) warn "未知选项 / Unknown choice" ;;
    esac
)

subscription_action() (
    say "  1. 状态 / status"
    say "  2. 配置并启用 / configure and enable"
    say "  3. 输出 URL / print URL"
    say "  4. 轮换 Token / rotate token"
    say "  5. 启动 / start"
    say "  6. 停止 / stop"
    say "  0. 返回 / Back"
    ask "选择 / Choice: "
    case "$REPLY" in
        1) run_sbox5 subscription status ;;
        2)
            ask_default "绑定地址 / bind (127.0.0.1/0.0.0.0)" "127.0.0.1"
            BIND=$REPLY
            case "$BIND" in
                127.0.0.1|0.0.0.0) ;;
                *) warn "绑定地址无效 / Invalid bind"; return 0 ;;
            esac
            ask_default "端口 / port" "18090"
            PORT=$REPLY
            ask_default "TLS 配置（none 或证书配置 ID）/ TLS profile" "none"
            run_sbox5 subscription set --bind="$BIND" --port="$PORT" --tls-profile="$REPLY"
            ;;
        3) run_sbox5 subscription url ;;
        4) run_sbox5 subscription rotate ;;
        5) run_sbox5 subscription start ;;
        6) run_sbox5 subscription stop ;;
        0) return 0 ;;
        *) warn "未知选项 / Unknown choice" ;;
    esac
)

cdn_action() (
    ask "目标 / Target (vmess/argo): "
    TARGET=$REPLY
    case "$TARGET" in
        vmess|argo) ;;
        *) warn "目标无效 / Invalid target"; return 0 ;;
    esac
    ask "优选地址 / preferred address: "
    ADDRESS=$REPLY
    if [ -z "$ADDRESS" ]; then warn "地址不能为空 / Address is required"; return 0; fi
    ask_default "端口 / port" "443"
    PORT=$REPLY
    set -- cdn set --target="$TARGET" --address="$ADDRESS" --port="$PORT"
    ask "Host（可留空）/ Host (optional): "
    if [ -n "$REPLY" ]; then set -- "$@" --host="$REPLY"; fi
    ask "SNI（可留空）/ SNI (optional): "
    if [ -n "$REPLY" ]; then set -- "$@" --sni="$REPLY"; fi
    run_sbox5 "$@"
)

config_menu() {
    while :; do
        clear_screen
        section
        item 1 "Reality 目标/SNI / Reality target/SNI"
        item 2 "证书模式与绑定 / Certificates"
        item 3 "UUID/密码/VMess 路径 / Rotate credentials"
        item 4 "Argo 隧道 / Argo"
        item 5 "IPv4/IPv6 导出 / Export family"
        item 6 "WARP 出站 / WARP"
        item 7 "本地订阅 / Local subscription"
        item 8 "VMess/Argo CDN"
        item 0 "返回 / Back"
        section
        ask "选择 / Choice: "
        case "$REPLY" in
            1) reality_action ;;
            2) cert_menu ;;
            3) secrets_action ;;
            4) argo_action ;;
            5) ip_action ;;
            6) warp_menu ;;
            7) subscription_action ;;
            8) cdn_action ;;
            0) return 0 ;;
            *) warn "未知选项 / Unknown choice" ;;
        esac
        pause
    done
}

ports_menu() {
    while :; do
        clear_screen
        section
        item 1 "修改协议主端口 / Change protocol port"
        item 2 "设置 UDP 跳跃范围 / Set UDP hopping"
        item 3 "清除 UDP 跳跃范围 / Clear UDP hopping"
        item 0 "返回 / Back"
        section
        ask "选择 / Choice: "
        case "$REPLY" in
            1)
                ask "协议 / Protocol (vless/vmess/hysteria2/tuic/anytls): "
                PROTO=$REPLY
                case "$PROTO" in
                    vless|vmess|hysteria2|tuic|anytls) ;;
                    *) warn "未知协议 / Unknown protocol"; pause; continue ;;
                esac
                ask "新端口 / New port: "
                case "$REPLY" in
                    ''|*[!0-9]*) warn "端口必须为数字 / Port must be numeric"; pause; continue ;;
                esac
                run_sbox5 port set --protocol="$PROTO" --port="$REPLY"
                ;;
            2)
                ask "协议 / Protocol (hysteria2/tuic): "
                PROTO=$REPLY
                case "$PROTO" in
                    hysteria2|tuic) ;;
                    *) warn "未知协议 / Unknown protocol"; pause; continue ;;
                esac
                ask "范围 / Range (START:END): "
                run_sbox5 port hopping set --protocol="$PROTO" --range="$REPLY"
                ;;
            3)
                ask "协议 / Protocol (hysteria2/tuic): "
                PROTO=$REPLY
                case "$PROTO" in
                    hysteria2|tuic) ;;
                    *) warn "未知协议 / Unknown protocol"; pause; continue ;;
                esac
                run_sbox5 port hopping clear --protocol="$PROTO"
                ;;
            0) return 0 ;;
            *) warn "未知选项 / Unknown choice" ;;
        esac
        pause
    done
}

routing_menu() {
    while :; do
        clear_screen
        section
        item 1 "查看分流 / Show routing"
        item 2 "添加域名后缀 / Add domain suffix"
        item 3 "删除域名后缀 / Remove domain suffix"
        item 4 "清空域名路由 / Clear domain routes"
        item 5 "添加/更新规则集 / Add or update rule set"
        item 6 "删除规则集 / Remove rule set"
        item 0 "返回 / Back"
        section
        ask "选择 / Choice: "
        case "$REPLY" in
            1) run_sbox5 route list --text ;;
            2)
                ask "目标 / Target (warp/socks5/direct/direct-v4/direct-v6): "
                TARGET=$REPLY
                case "$TARGET" in
                    warp|socks5|direct|direct-v4|direct-v6) ;;
                    *) warn "目标无效 / Invalid target"; pause; continue ;;
                esac
                ask "域名后缀 / Domain suffix: "
                if [ -z "$REPLY" ]; then warn "后缀不能为空 / Suffix is required"; pause; continue; fi
                run_sbox5 route add --target="$TARGET" --suffix="$REPLY"
                ;;
            3)
                ask "目标 / Target (warp/socks5/direct/direct-v4/direct-v6): "
                TARGET=$REPLY
                case "$TARGET" in
                    warp|socks5|direct|direct-v4|direct-v6) ;;
                    *) warn "目标无效 / Invalid target"; pause; continue ;;
                esac
                ask "域名后缀 / Domain suffix: "
                if [ -z "$REPLY" ]; then warn "后缀不能为空 / Suffix is required"; pause; continue; fi
                run_sbox5 route remove --target="$TARGET" --suffix="$REPLY"
                ;;
            4) run_sbox5 route clear ;;
            5)
                ask "标签 / Tag: "
                TAG=$REPLY
                ask "目标 / Target (warp/socks5/direct/direct-v4/direct-v6): "
                TARGET=$REPLY
                case "$TARGET" in
                    warp|socks5|direct|direct-v4|direct-v6) ;;
                    *) warn "目标无效 / Invalid target"; pause; continue ;;
                esac
                ask "SHA256（64 位十六进制）/ SHA256: "
                SHA=$REPLY
                say "来源 / Source: 1 本地文件 file 2 URL"
                ask "选择 / Choice [1]: "
                case "${REPLY:-1}" in
                    2)
                        ask "URL: "
                        run_sbox5 route ruleset add --tag="$TAG" --target="$TARGET" --sha256="$SHA" --url="$REPLY"
                        ;;
                    *)
                        ask "本地文件路径 / Local file path: "
                        run_sbox5 route ruleset add --tag="$TAG" --target="$TARGET" --sha256="$SHA" --file="$REPLY"
                        ;;
                esac
                ;;
            6)
                ask "标签 / Tag: "
                run_sbox5 route ruleset remove --tag="$REPLY"
                ;;
            0) return 0 ;;
            *) warn "未知选项 / Unknown choice" ;;
        esac
        pause
    done
}

service_menu() {
    while :; do
        clear_screen
        section
        item 1 "状态 / Status"
        item 2 "启动 / Start"
        item 3 "停止 / Stop"
        item 4 "重启 / Restart"
        item 0 "返回 / Back"
        section
        ask "选择 / Choice: "
        case "$REPLY" in
            1) if ask_service; then run_sbox5 service status --service="$SERVICE"; fi ;;
            2) if ask_service; then run_sbox5 service start --service="$SERVICE"; fi ;;
            3) if ask_service; then run_sbox5 service stop --service="$SERVICE"; fi ;;
            4) if ask_service; then run_sbox5 service restart --service="$SERVICE"; fi ;;
            0) return 0 ;;
            *) warn "未知选项 / Unknown choice" ;;
        esac
        pause
    done
}

update_menu() {
    while :; do
        clear_screen
        section
        item 1 "检查并拉取项目更新 / Fast-forward project"
        item 2 "按锁文件升级/重装 / Upgrade with locks"
        item 3 "查看事务快照 / List snapshots"
        item 4 "回滚到快照 / Roll back"
        item 0 "返回 / Back"
        section
        ask "选择 / Choice: "
        case "$REPLY" in
            1) run_sbox5 self-update ;;
            2) run_sbox5 upgrade ;;
            3) run_sbox5 snapshots ;;
            4)
                run_sbox5 snapshots
                ask "快照 ID（留空使用最新）/ Snapshot ID (blank = latest): "
                if [ -n "$REPLY" ]; then
                    run_sbox5 rollback --snapshot="/var/lib/sbox5/snapshots/$REPLY"
                else
                    run_sbox5 rollback
                fi
                ;;
            0) return 0 ;;
            *) warn "未知选项 / Unknown choice" ;;
        esac
        pause
    done
}

core_menu() {
    while :; do
        clear_screen
        section
        item 1 "当前内核 / Current core"
        item 2 "锁定版本与通道 / Locked versions"
        item 3 "切换通道或版本 / Switch"
        item 4 "回滚内核 / Roll back core"
        item 0 "返回 / Back"
        section
        ask "选择 / Choice: "
        case "$REPLY" in
            1) run_sbox5 core status --text ;;
            2) run_sbox5 core list --text ;;
            3)
                say "  1. stable  2. beta  3. 指定版本 / specific version"
                ask "选择 / Choice: "
                case "$REPLY" in
                    1) run_sbox5 core switch --channel=stable ;;
                    2) run_sbox5 core switch --channel=beta ;;
                    3)
                        ask "版本 / Version: "
                        run_sbox5 core switch --version="$REPLY"
                        ;;
                    *) warn "未知选项 / Unknown choice" ;;
                esac
                ;;
            4) run_sbox5 core rollback ;;
            0) return 0 ;;
            *) warn "未知选项 / Unknown choice" ;;
        esac
        pause
    done
}

nodes_menu() {
    while :; do
        clear_screen
        section
        item 1 "重新导出客户端文件 / Export client files"
        item 2 "查看全部分享链接 / Show all links"
        item 3 "指定协议二维码 / QR for one protocol"
        item 4 "本地订阅 URL / Subscription URL"
        item 5 "订阅状态 / Subscription status"
        item 0 "返回 / Back"
        section
        ask "选择 / Choice: "
        case "$REPLY" in
            1) run_sbox5 export ;;
            2) run_sbox5 show ;;
            3)
                ask "协议 / Protocol (vless/vmess/hysteria2/tuic/anytls): "
                case "$REPLY" in
                    vless|vmess|hysteria2|tuic|anytls) run_sbox5 show --protocol="$REPLY" --qr ;;
                    *) warn "未知协议 / Unknown protocol" ;;
                esac
                ;;
            4) run_sbox5 subscription url ;;
            5) run_sbox5 subscription status ;;
            0) return 0 ;;
            *) warn "未知选项 / Unknown choice" ;;
        esac
        pause
    done
}

logs_menu() {
    while :; do
        clear_screen
        section
        item 1 "core"
        item 2 "argo"
        item 3 "ddns"
        item 4 "subscription"
        item 5 "firewall"
        item 6 "core（持续跟随 / follow）"
        item 0 "返回 / Back"
        section
        ask "选择 / Choice: "
        case "$REPLY" in
            1) run_sbox5 logs --service=core ;;
            2) run_sbox5 logs --service=argo ;;
            3) run_sbox5 logs --service=ddns ;;
            4) run_sbox5 logs --service=subscription ;;
            5) run_sbox5 logs --service=firewall ;;
            6) run_sbox5 logs --service=core --follow ;;
            0) return 0 ;;
            *) warn "未知选项 / Unknown choice" ;;
        esac
        pause
    done
}

bbr_menu() {
    while :; do
        clear_screen
        section
        item 1 "查看 BBR / Status"
        item 2 "开启 BBR / Enable"
        item 3 "关闭 BBR / Disable"
        item 0 "返回 / Back"
        section
        ask "选择 / Choice: "
        case "$REPLY" in
            1) run_sbox5 bbr status ;;
            2) run_sbox5 bbr enable ;;
            3) run_sbox5 bbr disable ;;
            0) return 0 ;;
            *) warn "未知选项 / Unknown choice" ;;
        esac
        pause
    done
}

cert_menu() {
    while :; do
        clear_screen
        section
        item 1 "列出证书配置 / List profiles"
        item 2 "添加自签证书 / Add self-signed"
        item 3 "添加 ACME 证书 / Add ACME"
        item 4 "导入证书 / Import certificate"
        item 5 "绑定协议 / Bind protocol"
        item 6 "删除未绑定证书 / Remove profile"
        item 0 "返回 / Back"
        section
        ask "选择 / Choice: "
        case "$REPLY" in
            1) run_sbox5 cert list ;;
            2)
                ask "配置 ID / Profile ID: "; ID=$REPLY
                ask "server_name: "; NAME=$REPLY
                if [ -n "$NAME" ]; then
                    run_sbox5 cert add --id="$ID" --mode=self-signed --server-name="$NAME"
                else
                    run_sbox5 cert add --id="$ID" --mode=self-signed
                fi
                ;;
            3)
                ask "配置 ID / Profile ID: "; ID=$REPLY
                ask "域名 / Domain: "; DOMAIN=$REPLY
                if [ -z "$DOMAIN" ]; then warn "域名不能为空 / Domain is required"; pause; continue; fi
                ask "邮箱 / Email: "; EMAIL=$REPLY
                say "验证方式 / Challenge: 1 http-01 2 tls-alpn-01 3 dns-01"
                ask "选择 / Choice [1]: "
                case "${REPLY:-1}" in
                    2) CHALLENGE=tls-alpn-01 ;;
                    3) CHALLENGE=dns-01 ;;
                    *) CHALLENGE=http-01 ;;
                esac
                run_sbox5 cert add --id="$ID" --mode=acme --domain="$DOMAIN" --email="$EMAIL" --challenge="$CHALLENGE" --dns-provider=cloudflare
                ;;
            4)
                ask "配置 ID / Profile ID: "; ID=$REPLY
                ask "server_name: "; NAME=$REPLY
                if [ -z "$NAME" ]; then warn "server_name 不能为空 / server_name is required"; pause; continue; fi
                ask "证书路径 / Certificate path: "; CERT=$REPLY
                ask "私钥路径 / Key path: "; KEY=$REPLY
                run_sbox5 cert add --id="$ID" --mode=imported --server-name="$NAME" --cert="$CERT" --key="$KEY"
                ;;
            5)
                ask "协议 / Protocol (vmess/hysteria2/tuic/anytls): "; PROTO=$REPLY
                ask "配置 ID（或 none）/ Profile ID (or none): "; PROFILE=$REPLY
                run_sbox5 cert bind --protocol="$PROTO" --profile="$PROFILE"
                ;;
            6)
                ask "配置 ID / Profile ID: "
                run_sbox5 cert remove --id="$REPLY"
                ;;
            0) return 0 ;;
            *) warn "未知选项 / Unknown choice" ;;
        esac
        pause
    done
}

warp_menu() {
    while :; do
        clear_screen
        section
        item 1 "状态 / Status"
        item 2 "注册新凭证 / Register"
        item 3 "轮换凭证 / Rotate"
        item 4 "启用 / Enable"
        item 5 "禁用 / Disable"
        item 6 "导入凭证 / Import"
        item 7 "清除凭证 / Clear"
        item 0 "返回 / Back"
        section
        ask "选择 / Choice: "
        case "$REPLY" in
            1) run_sbox5 warp status ;;
            2) run_sbox5 warp register ;;
            3) run_sbox5 warp rotate ;;
            4) run_sbox5 warp enable ;;
            5) run_sbox5 warp disable ;;
            6)
                ask "私钥文件 / Private key file: "; PRIVATE=$REPLY
                ask "对端公钥 / Peer public key: "; PEER=$REPLY
                ask "IPv4 地址 / IPv4 address (例如 172.16.0.2/32): "; ADDRESS=$REPLY
                ask_default "reserved" "0,0,0"
                set -- warp import --private-key-file="$PRIVATE" --peer-public-key="$PEER" --address="$ADDRESS" --reserved="$REPLY"
                ask "IPv6 地址（可留空）/ IPv6 address (optional): "
                if [ -n "$REPLY" ]; then set -- "$@" --address="$REPLY"; fi
                run_sbox5 "$@"
                ;;
            7) run_sbox5 warp clear ;;
            0) return 0 ;;
            *) warn "未知选项 / Unknown choice" ;;
        esac
        pause
    done
}

help_action() {
    section
    say "支持 / Supported:"
    say "  install, uninstall, protocol, port, route, service, upgrade,"
    say "  core, export, show, logs, bbr, cert, argo, warp, subscription,"
    say "  ip, snapshots, rollback, self-update"
    say ""
    say "不支持 / Not supported:"
    say "  TG 推送、GitLab 推送、WARP-plus/Psiphon、Serv00/FreeBSD、"
    say "  旧 /etc/s-box、1.10.7 旧内核。"
    say ""
    say "替代方案 / Alternatives:"
    say "  本地订阅服务: sbox5 subscription set"
    say "  外部 Socks5: sbox5 route socks5 set"
    say ""
    say "文档 / Documentation:"
    say "  $SCRIPT_DIR/README.md"
    say "  $SCRIPT_DIR/README.zh-CN.md"
    say ""
    run_sbox5 --help
}

main_loop() {
    while :; do
        clear_screen
        banner
        status_header
        main_menu
        ask "选择 / Choice: "
        case "$REPLY" in
            1) install_wizard ;;
            2) run_sbox5 uninstall ;;
            3) config_menu ;;
            4) ports_menu ;;
            5) routing_menu ;;
            6) service_menu ;;
            7) update_menu ;;
            8) core_menu ;;
            9) nodes_menu ;;
            10) logs_menu ;;
            11) bbr_menu ;;
            12) cert_menu ;;
            13) warp_menu ;;
            14) ip_action ;;
            15) help_action ;;
            0|q|Q) exit 0 ;;
            *) warn "未知选项 / Unknown choice" ;;
        esac
        pause
    done
}

require_host
main_loop
