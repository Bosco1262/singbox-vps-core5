# singbox-vps-core5 (sbox5)

[English](README.md) | [简体中文](README.zh-CN.md)

[![License: GPLv3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
[![Python: 3.10+](https://img.shields.io/badge/Python-3.10%2B-green.svg)](https://www.python.org/)
[![Platform: Linux](https://img.shields.io/badge/Platform-Debian%2012%2B%20%7C%20Ubuntu%2022.04%2B%20%7C%20Alpine%203.20%2B%20%7C%20RHEL%209%2B-orange.svg)]()
[![Tests: 90 Passed](https://img.shields.io/badge/Tests-90%20Passed-brightgreen.svg)]()

**singbox-vps-core5** (`sbox5`) 是一个面向 Linux VPS 的生产加固、可审计且支持故障回滚的多协议代理套件。在严苛的安全隔离、非 root systemd 沙盒与不可变供应链锁的保护下，实现五大现代协议（**VLESS-Reality**、**VMess-WS**、**Hysteria2**、**TUIC v5** 与 **AnyTLS**）的原生平滑共存。

---

## 核心特性

- **五协议原生共存**：单机同时运行 VLESS-Reality、VMess-WebSocket（可选 TLS）、Hysteria2（含 Salamander 混淆）、TUIC v5 与 AnyTLS，互不干扰；每个协议可独立启停；
- **原生 ACME 与按协议 TLS**：使用 sing-box 原生 ACME certificate provider（HTTP-01 / TLS-ALPN-01 / DNS-01，CA 支持时可申请 IP 证书），按协议绑定 TLS 配置；不再依赖 certbot，也不需要外部续期定时器；
- **非 root 权限隔离**：核心服务分别运行于专用系统账户（`sbox5`、`sbox5-argo`、`sbox5-ddns`、`sbox5-sub`），彻底废除特权执行；
- **供应链哈希硬锁**：通过 `locks/*.json` 硬编码官方下载源与 SHA256，流式校验哈希与归档结构，杜绝上游静默投毒；
- **零外部库依赖**：纯 Python 3.10+ 标准库实现，无需 `pip install`，无外部脚本远程管道执行；
- **原子事务与快照回滚**：安装、升级、重新配置、卸载前自动捕获系统快照（配置、防火墙、用户、sysctl），失败全自动回滚，快照自带离线无依赖 `restore.py`；
- **落盘前官方语法预检**：生成配置后强制调用官方 `sing-box check` 预检，验证通过后方可启动服务；现代路由规则以 `{"action":"sniff"}` 开头，保证客户端使用 IP 直连时域名分流仍然生效；
- **双源交叉验证 DDNS**：对接 Cloudflare API，至少由两个独立 HTTPS 端点交叉确认公网 IP 后方可写入，强制 `proxied: false`；
- **最小权限防火墙接管**：优先适配既有 UFW，或建立独立 `inet sbox5` 表；iptables 回退方案使用隔离的 `SBOX5-INPUT` / `SBOX5-PREROUTING` 自定义链，绝不执行全局 `iptables -F` 或清空宿主规则；
- **Hysteria2 / TUIC UDP 端口跳跃**：在独立防火墙表/链中声明式维护 UDP 范围并精确回滚；TUIC 没有标准端口范围 URI 字段，客户端需选择具体端口；
- **Argo Quick/Token 隧道**：`cloudflared` 临时隧道与固定 Token 隧道由加固的非 root 服务托管；专用回环 VMess 入口让 Argo 与公网 VMess TLS 共存；
- **原生 WARP 与多目标分流**：WARP 凭证通过 Cloudflare 客户端注册端点或手动导入（绝不使用共享私钥）；域名后缀与本地 `.srs` 规则集可分流到 WARP、本地 IPv4/IPv6 或可选 Socks5 出站；
- **CDN 优选与全客户端导出**：支持 VMess/Argo 的 CDN 优选 IP/域名与显式 Host/SNI；导出 SFA、SFI、SFW、sing-box、Mihomo、分享链接、二维码与 Base64 订阅包；
- **本地订阅服务**：独立低权限 `sbox5-sub` 服务，仅通过高熵路径 Token 提供白名单文件；服务端只保存 Token 哈希；默认 localhost + TLS 反向代理，也可用自签/导入证书启用内置 TLS；
- **锁定内核生命周期**：稳定版/通道/指定版本切换只接受不可变锁文件，新二进制先通过 `sing-box check`，失败自动回滚；
- **运维控制台**：`sbox5 menu` 提供状态面板、日志、健康检查、协议/端口操作与证书/订阅视图；`sbox5 doctor --json` 输出可脚本化的 PASS/WARN/FAIL 结果；
- **双栈导出切换**：`sbox5 ip set --family ipv4|ipv6|auto` 选择写入分享链接、SFA/SFI/SFW、sing-box 客户端与 Mihomo 的全局地址，服务端监听仍保持双栈；
- **跨发行版服务**：Debian/Ubuntu/RHEL 使用加固 systemd 单元；Alpine 使用 OpenRC runscript、专用用户、文件日志、DDNS 循环，并仅在低端口/原生 ACME 需要时使用 `setcap cap_net_bind_service`；
- **客户端零降级证书校验**：自签证书内嵌公钥，Mihomo 绑定完整 DER SHA256 指纹，彻底杜绝 `insecure: true` 风险。

---

## 系统要求

- **操作系统**：Debian 12+ / Ubuntu 22.04+ / Alpine 3.20+ / RHEL 9+、Rocky 9+ 或 AlmaLinux 9+（64-bit x86_64 / arm64）
- **Init 系统**：Debian/Ubuntu/RHEL 使用 systemd；Alpine 使用 OpenRC
- **虚拟化架构**：KVM、Google Compute Engine、AWS、Azure/Hyper-V、VMware、Xen 或具有独立内核的物理机；预检会拒绝 Docker、LXC、WSL 等容器/共享内核环境。
- **运行环境**：Python 3.10+（标准库）
- **防火墙**：UFW、nftables 或 iptables。RHEL 上 firewalld 运行时 sbox5 不会修改 firewalld：请先用 `firewall-cmd` 开放端口，再使用 `--no-firewall` 安装，或明确停用 firewalld。

---

## 快速开始

### 1. 安装

```bash
# 使用 sudo 克隆仓库
sudo git clone https://github.com/Bosco1262/singbox-vps-core5.git /usr/local/src/singbox-vps-core5
cd /usr/local/src/singbox-vps-core5

# 拉取后赋予执行权限
sudo chmod +x install.sh sbox5

# 运行安装程序（交互式引导）
sudo ./install.sh
```

或直接调用管理 CLI：

```bash
sudo ./sbox5 install
```

在最小化 Alpine 或 RHEL 镜像上，请先用发行版官方包管理器安装 Python 3.10+（`apk add python3` 或 `dnf install python3`）。RHEL 9 默认的 `python3` 是 3.9，请先从 AppStream 安装 `python3.11`（或更新版本），启动器会自动识别。安装器随后会自行安装其余官方软件包（nftables、iptables、OpenSSL、iproute2，以及 Alpine 的 libcap/shadow）。

### 2. 命令参考

```text
sbox5 <subcommand>

  install      全新安装（支持交互式引导或全参数自动安装）
  upgrade      按 locks 锁文件无缝升级核心程序（复用原有配置）
  status       查看服务状态、组件版本、协议与证书配置（--geo 可选查询 IP 归属地）
  menu         交互式面板：状态、日志、健康检查与常用操作
  doctor       本地健康检查（--json 便于自动化）
  logs         查看服务日志（--service core|argo|ddns|subscription|firewall，--follow）
  ip show      显示探测到的全局 IPv4/IPv6 地址
  ip set       选择 auto/ipv4/ipv6 作为客户端导出地址
  show         查看节点链接（--protocol 筛选, --json 输出, --qr 终端渲染二维码）
  export       重新生成客户端配置文件到 /var/lib/sbox5/exports
  check        调用 sing-box 官方二进制校验服务端与客户端配置有效性
  port set     修改协议端口，自动快照并可回滚
  port hopping 管理 Hysteria2/TUIC UDP 端口跳跃范围
  protocol set 启用/禁用协议或切换 TLS 配置
  cert list    列出证书配置与协议绑定
  cert add     添加自签、原生 ACME 或导入证书配置
  cert bind    将协议绑定到证书配置（VMess 可用 none 关闭 TLS）
  cert remove  删除未绑定的证书配置并自动快照
  argo         管理 quick/token 隧道、状态、启停与重置
  warp         注册、导入、轮换、启停或清除 WARP
  route        管理域名分流、Socks5 与本地 .srs 规则集
  core         查看、列出、切换或回滚已锁定 sing-box 版本
  cdn          设置或清除 VMess/Argo CDN 优选地址与 Host/SNI
  subscription 管理本地 Token 订阅服务
  snapshots    列出本地历史快照与提交状态
  rollback     使用快照附带的独立恢复器一键回滚系统
  uninstall    安全卸载（自动拍摄快照，清理规则与文件，保留软件包）
```

---

## 交互安装参数

| 参数项                         | 说明                                        | 默认值 / 选项                            |
| :----------------------------- | :------------------------------------------ | :--------------------------------------- |
| `--host`                       | 服务器公网 IP 或绑定的域名                  | 自动探测 / 手动指定                      |
| `--reality-target`             | Reality 握手偷取的目标主机与端口            | 例如 `www.apple.com:443`                 |
| `--reality-sni`                | Reality 伪装域名                            | 默认自动从 target 提取                   |
| `--certificate-mode`           | TLS 证书模式                                | `self-signed`、`acme`（sing-box 原生）或 `imported` |
| `--domain`                     | ACME 域名或 IP                              | HTTP-01/TLS-ALPN-01 需解析至本机         |
| `--acme-email`                 | ACME 账户邮箱                               | 可选                                     |
| `--acme-challenge`             | ACME 验证方式                               | `http-01`、`tls-alpn-01` 或 `dns-01`     |
| `--acme-dns-provider`          | DNS-01 提供商                               | `cloudflare`                             |
| `--acme-dns-token-file`        | DNS-01 API Token 文件                       | root 可读普通文件；原生 ACME 运行时会写入 `config.json`（`0640 root:sbox5`） |
| `--tls-server-name`            | 自签/导入证书的 TLS server_name             | 自签模式自动生成                         |
| `--vmess-tls` / `--no-vmess-tls` | 是否启用 VMess TLS                        | 默认关闭；与 Argo 互斥                   |
| `--vless-port`                 | VLESS-Reality 监听端口                      | 默认 `18443`                             |
| `--vmess-port`                 | VMess-WebSocket 监听端口                    | 默认 `18080`                             |
| `--hysteria2-port`             | Hysteria2 UDP 监听端口                      | 默认 `18444`                             |
| `--tuic-port`                  | TUIC v5 UDP 监听端口                        | 默认 `18445`                             |
| `--anytls-port`                | AnyTLS TCP 监听端口                         | 默认 `18446`                             |
| `--hysteria2-port-hopping`     | Hysteria2 UDP 跳跃范围                      | 可选，如 `20000:30000`                   |
| `--tuic-port-hopping`          | TUIC UDP 跳跃范围                           | 可选，如 `30000:40000`                   |
| `--ddns` / `--no-ddns`         | 是否启用 Cloudflare DDNS                    | 默认禁用                                 |
| `--cloudflare-zone`            | Cloudflare 主域名 Zone                      | 如 `example.com`                         |
| `--ddns-record`                | DDNS 解析目标完整记录                       | 如 `vpn.example.com`                     |
| `--argo` / `--no-argo`         | 是否启用 Cloudflare Tunnel (VMess 备用通道) | 默认禁用                                 |
| `--argo-mode`                  | Argo 隧道模式                               | `quick` 或 `token`                       |
| `--argo-hostname`              | Argo 隧道外部域名                           | token 模式必填                           |
| `--argo-local-port`            | Argo 使用的回环 VMess 入口端口              | 默认 `18081`                             |
| `--bbr` / `--no-bbr`           | 启用系统 BBR 拥塞控制                       | 默认禁用                                 |
| `--firewall` / `--no-firewall` | 自动配置防火墙放行规则                      | 默认启用                                 |
| `-l`, `--lang`, `--language`   | 显示语言偏好 (`en`, `zh-CN`)                | 自动检测 / 默认 `en`                     |

---

## 客户端配置导出

安装完成后，完整的客户端配置文件将保存在安全目录（权限 `0700`）：

```text
/var/lib/sbox5/exports/
├── links.txt                # 通用分享链接 (vless://, vmess://, hysteria2://, tuic://, anytls://)
├── subscription-base64.txt  # Base64 编码订阅文本
├── sing-box-client.json     # 官方 sing-box mixed 入站客户端配置
├── sfa.json / sfi.json / sfw.json  # Android/iOS/Windows 的 sing-box TUN 配置
├── mihomo.yaml              # Mihomo (Clash.Meta) 完整配置 (已绑定 DER SHA256 指纹)
├── metadata.json            # 导出元数据与证书校验警告
├── certificate*.pem         # 自签/导入的公开证书，用于指纹固定
└── *.png                    # 节点二维码 (若系统安装了 qrencode)
```

查看节点：

```bash
# 查看所有节点链接
sudo sbox5 show

# 查看特定协议并渲染终端二维码
sudo sbox5 show --protocol hysteria2 --qr
```

---

## 安全架构

```text
Host System (Debian 12 / Ubuntu 22.04)
 ├── /etc/sbox5/
 │    ├── config.json               (0640, group: sbox5)
 │    ├── settings.json             (0600 / 0640)
 │    ├── tls/ [cert.pem, key.pem]  (0750 dir, key: 0600, sbox5:sbox5)
 │    ├── tls/<profile>/            (额外证书配置)
 │    └── secrets/ [argo, ddns, protocols, subscription] (0711 dir, tokens: 0600)
 ├── /var/lib/sbox5/
 │    ├── acme/<profile>/           (0700, sing-box 原生 ACME 状态)
 │    ├── certificates.json         (按证书配置保存的状态)
 │    ├── argo/                     (state.json 与临时隧道日志)
 │    ├── rulesets/                 (本地 .srs 规则集)
 │    ├── subscription/             (0700, Token 化订阅包与可选 TLS)
 │    ├── core.json                 (当前/上一版内核)
 │    ├── snapshots/                (0700, 独立快照存储)
 │    └── exports/                  (0700, 客户端配置文件)
 └── Services:
      ├── sbox5.service             (User=sbox5, hardened systemd sandbox, native ACME)
      ├── sbox5-argo.service        (User=sbox5-argo, quick 或 token 隧道)
      ├── sbox5-ddns.timer          (User=sbox5-ddns, dual-source check)
      ├── sbox5-subscription.service(User=sbox5-sub, Token 化本地订阅)
      └── sbox5-firewall.service    (Minimal rule enforcement, no flush)
```

---

## Argo、WARP、分流与内核

```bash
# Argo 临时隧道（URL 从加固服务日志中读取）
sudo sbox5 argo set --mode quick --yes
sudo sbox5 argo status
sudo sbox5 argo reset --yes

# Argo 固定 Token 隧道
sudo sbox5 argo set --mode token --hostname tunnel.example.com --token-file /root/tunnel.token --yes

# 原生 WARP 注册或手动导入
sudo sbox5 warp register --yes
sudo sbox5 warp status
sudo sbox5 warp import --private-key-file /root/wg.key --peer-public-key <key> \
  --address 172.16.0.2/32 --address 2606:4700:110::2/128 --reserved 1,2,3 --yes

# 域名/规则集分流到 WARP、本地 IPv4/IPv6 或 Socks5
sudo sbox5 route add --target warp --suffix .openai.com --yes
sudo sbox5 route socks5 set --server 127.0.0.1 --port 1080 --username user --yes
sudo sbox5 route ruleset add --tag geosite-cn --target direct-v4 \
  --url https://github.com/SagerNet/sing-geosite/releases/download/<tag>/geosite-cn.srs \
  --sha256 <64位SHA256> --yes
sudo sbox5 route list

# 锁定内核生命周期
sudo sbox5 core list
sudo sbox5 core switch --channel stable --yes
sudo sbox5 core rollback --yes

# VMess/Argo CDN 优选
sudo sbox5 cdn set --target vmess --address 104.16.0.1 --host cdn.example.com --sni cdn.example.com --yes
sudo sbox5 cdn set --target argo --address 104.16.0.1 --yes
sudo sbox5 cdn list

# 本地订阅服务（推荐 localhost + TLS 反向代理）
sudo sbox5 subscription set --bind 127.0.0.1 --port 18090 --yes
sudo sbox5 subscription url
sudo sbox5 subscription rotate --yes

# 可选：使用自签/导入证书配置启用内置 TLS
sudo sbox5 subscription set --bind 0.0.0.0 --port 18090 --tls-profile default --yes
```

VMess CDN 要求源站 VMess 入站保持明文 WebSocket；Argo CDN 要求 token 模式，因为临时隧道域名会变化。

订阅服务只暴露白名单文件：

```text
/sub/<token>/links       /sub/<token>/base64
/sub/<token>/sing-box    /sub/<token>/sfa | sfi | sfw
/sub/<token>/mihomo      /sub/<token>/clash
/sub/<token>/metadata
```

本地订阅进程无法读取原生 ACME 证书；ACME 请使用 TLS 反向代理，或使用自签/导入证书配置启用内置 TLS。原始 Token 只保存在 `/etc/sbox5/secrets/subscription.token`（`0600`），服务配置只保存其 SHA256 哈希。

WARP 注册使用 Cloudflare 客户端注册端点，绝不会回退到硬编码/共享私钥；WARP 私钥保存在 `secrets/protocols.json`（`0600`），并会注入 `config.json`（`0640 root:sbox5`）。内核只接受已锁定版本；切换测试版前需添加 `locks/versions/<version>.json` 并在 `locks/versions/index.json` 设置 `channels.beta`。

### Phase 4 运维

```bash
# 交互式状态面板与常用操作
sudo sbox5 menu

# 可选的公网 IP 归属地查询（通过 HTTPS 访问 ipinfo.io，不发送任何凭据）
sudo sbox5 status --geo

# 日志与健康检查
sudo sbox5 logs --service core --follow
sudo sbox5 doctor
sudo sbox5 doctor --json

# 选择写入客户端导出的地址（服务端仍保持双栈监听）
sudo sbox5 ip show
sudo sbox5 ip set --family ipv6 --yes
sudo sbox5 ip set --family auto --yes
```

`ip set` 只影响分享链接、SFA/SFI/SFW、sing-box 客户端 JSON 与 Mihomo，不改变监听套接字。所选地址族没有全局地址时会明确失败，不会导出空主机名。

平台说明：

- **Alpine / OpenRC**：服务安装为 `/etc/init.d/sbox5*`，使用专用用户、`/var/log/sbox5` 文件日志，并以常驻 DDNS 循环替代 systemd timer。低端口或原生 ACME HTTP-01/TLS-ALPN-01 在服务启动时对项目自有 sing-box 二进制执行 `setcap cap_net_bind_service=+ep`，并自动安装 `libcap`。
- **RHEL / Rocky / AlmaLinux**：sbox5 不会修改 firewalld 区域。firewalld 运行时应先用 `firewall-cmd` 开放端口并使用 `--no-firewall` 安装，或明确停用 firewalld 后再使用项目自有 nftables 表。SELinux 策略由管理员负责；`sbox5 doctor` 会报告服务与配置故障。发行版提供 `qrencode` 时导出二维码 PNG；分享链接与客户端配置始终会导出。
- **快照**：OpenRC runscript、`/etc/init.d` 变更、服务启用状态与新日志目录都会写入 manifest，并可由离线 `recovery/restore.py` 恢复。

---

## MVP → Phase 4 迁移说明

- `settings.json` / `state.json` 会自动从 schema v1/v2 迁移到 v3；原有 v1/v2 快照仍由其自带的 `restore.py` 恢复。
- 旧的 certbot ACME 配置会迁移为 sing-box 原生 ACME，默认使用 HTTP-01。旧 `/etc/sbox5/acme` 状态会保留但不再使用；sing-box 会在下次启动时重新签发证书。
- 原有协议端口与凭据保持不变；TUIC/Hysteria2 跳跃范围会通过新的防火墙 reconcile 路径重新下发。
- 原有 Argo 配置会迁移为 token 模式并保留域名。Argo 现在使用回环 VMess 入口（默认 `18081`），因此 VMess TLS 与 Argo 可以共存；请将 Cloudflare ingress 更新为 `http://127.0.0.1:18081`。
- Phase 2 新增原生 WARP、可选 Socks5、本地 `.srs` 规则集与锁定内核切换；`warp-plus` / Psiphon 仍明确排除。
- Phase 3 新增 CDN 优选、SFA/SFI/SFW 导出与**仅本地**订阅服务。按设计不包含 GitLab/Telegram 推送；请通过自己的 HTTPS 反向代理发布带 Token 的订阅 URL。
- Phase 4 新增交互菜单、日志、doctor、双栈导出选择、Alpine/OpenRC 与 RHEL 9 兼容。firewalld 被视为管理员边界，sbox5 绝不自动修改。

---

## 鸣谢与血统说明

本项目是一个**完全全新编写的独立重构版本**。灵感源于 [yonggekkk/sing-box-yg](https://github.com/yonggekkk/sing-box-yg) 项目中的五协议共存理念。

虽然受到多协议架构概念的启发，但**本项目与原项目不存在任何共享代码行**。新版全面摒弃了脆弱的 Shell 字符串处理、root 提权执行与不可信远程脚本，基于类型安全的 Python 3.10+ 标准库、加密供应链锁定、非 root systemd 沙盒以及不可变回滚快照进行重构。项目不提供 Serv00/FreeBSD 支持，亦不接管旧版 `/etc/s-box` 安装目录。

---

## License

Copyright (C) 2026 Bosco1262

本项目采用 [GNU General Public License v3.0 或更高版本](LICENSE)。
