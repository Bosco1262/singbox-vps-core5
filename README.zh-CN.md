# singbox-vps-core5 (sbox5)

[English](README.md) | [简体中文](README.zh-CN.md)

[![License: GPLv3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
[![Python: 3.10+](https://img.shields.io/badge/Python-3.10%2B-green.svg)](https://www.python.org/)
[![Platform: Linux](https://img.shields.io/badge/Platform-Debian%2012%2B%20%7C%20Ubuntu%2022.04%2B-orange.svg)]()
[![Tests: 61 Passed](https://img.shields.io/badge/Tests-61%20Passed-brightgreen.svg)]()

**singbox-vps-core5** (`sbox5`) 是一个面向 Linux VPS 的生产加固、可审计且支持故障回滚的多协议代理套件。在严苛的安全隔离、非 root systemd 沙盒与不可变供应链锁的保护下，实现五大现代协议（**VLESS-Reality**、**VMess-WS**、**Hysteria2**、**TUIC v5** 与 **AnyTLS**）的原生平滑共存。

---

## 核心特性

- **五协议原生共存**：单机同时运行 VLESS-Reality、VMess-WebSocket（可选 TLS）、Hysteria2（含 Salamander 混淆）、TUIC v5 与 AnyTLS，互不干扰；每个协议可独立启停；
- **原生 ACME 与按协议 TLS**：使用 sing-box 原生 ACME certificate provider（HTTP-01 / TLS-ALPN-01 / DNS-01，CA 支持时可申请 IP 证书），按协议绑定 TLS 配置；不再依赖 certbot，也不需要外部续期定时器；
- **非 root 权限隔离**：核心服务分别运行于专用系统账户（`sbox5`、`sbox5-argo`、`sbox5-ddns`），彻底废除特权执行；
- **供应链哈希硬锁**：通过 `locks/*.json` 硬编码官方下载源与 SHA256，流式校验哈希与归档结构，杜绝上游静默投毒；
- **零外部库依赖**：纯 Python 3.10+ 标准库实现，无需 `pip install`，无外部脚本远程管道执行；
- **原子事务与快照回滚**：安装、升级、重新配置、卸载前自动捕获系统快照（配置、防火墙、用户、sysctl），失败全自动回滚，快照自带离线无依赖 `restore.py`；
- **落盘前官方语法预检**：生成配置后强制调用官方 `sing-box check` 预检，验证通过后方可启动服务；现代路由规则以 `{"action":"sniff"}` 开头，保证客户端使用 IP 直连时域名分流仍然生效；
- **双源交叉验证 DDNS**：对接 Cloudflare API，至少由两个独立 HTTPS 端点交叉确认公网 IP 后方可写入，强制 `proxied: false`；
- **最小权限防火墙接管**：优先适配既有 UFW，或建立独立 `inet sbox5` 表；iptables 回退方案使用隔离的 `SBOX5-INPUT` / `SBOX5-PREROUTING` 自定义链，绝不执行全局 `iptables -F` 或清空宿主规则；
- **Hysteria2 / TUIC UDP 端口跳跃**：在独立防火墙表/链中声明式维护 UDP 范围并精确回滚；TUIC 没有标准端口范围 URI 字段，客户端需选择具体端口；
- **客户端零降级证书校验**：自签证书内嵌公钥，Mihomo 绑定完整 DER SHA256 指纹，彻底杜绝 `insecure: true` 风险。

---

## 系统要求

- **操作系统**：Debian 12+ / Ubuntu 22.04+ (64-bit x86_64 / arm64)
- **Init 系统**：systemd (PID 1)
- **虚拟化架构**：KVM / 物理机（需独立内核模块支持）
- **运行环境**：Python 3.10+ (标准库)

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

### 2. 命令参考

```text
sbox5 <subcommand>

  install      全新安装（支持交互式引导或全参数自动安装）
  upgrade      按 locks 锁文件无缝升级核心程序（复用原有配置）
  status       查看服务状态、组件版本、协议与证书配置
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
├── sing-box-client.json     # 官方 sing-box 完整客户端配置 (已内联自签公钥)
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
 │    └── secrets/ [argo, ddns, protocols] (0711 dir, tokens: 0600)
 ├── /var/lib/sbox5/
 │    ├── acme/<profile>/           (0700, sing-box 原生 ACME 状态)
 │    ├── certificates.json         (按证书配置保存的状态)
 │    ├── argo/                     (state.json 与临时隧道日志)
 │    ├── rulesets/                 (本地 .srs 规则集)
 │    ├── core.json                 (当前/上一版内核)
 │    ├── snapshots/                (0700, 独立快照存储)
 │    └── exports/                  (0700, 客户端配置文件)
 └── Services:
      ├── sbox5.service             (User=sbox5, hardened systemd sandbox, native ACME)
      ├── sbox5-argo.service        (User=sbox5-argo, quick 或 token 隧道)
      ├── sbox5-ddns.timer          (User=sbox5-ddns, dual-source check)
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
```

WARP 注册使用 Cloudflare 客户端注册端点，失败会显式报错，绝不会回退到硬编码/共享私钥；仍可使用手动导入。WARP 私钥保存在 `secrets/protocols.json`（`0600`），并会注入 `config.json`（`0640 root:sbox5`），因为 sing-box 运行时需要读取。内核只接受已锁定版本；切换测试版前需添加 `locks/versions/<version>.json` 并在 `locks/versions/index.json` 设置 `channels.beta`。

---

## MVP → Phase 2 迁移说明

- `settings.json` / `state.json` 会自动从 schema v1/v2 迁移到 v3；原有 v1/v2 快照仍由其自带的 `restore.py` 恢复。
- 旧的 certbot ACME 配置会迁移为 sing-box 原生 ACME，默认使用 HTTP-01。旧 `/etc/sbox5/acme` 状态会保留但不再使用；sing-box 会在下次启动时重新签发证书。
- 原有协议端口与凭据保持不变；TUIC/Hysteria2 跳跃范围会通过新的防火墙 reconcile 路径重新下发。
- 原有 Argo 配置会迁移为 token 模式并保留域名。Argo 现在使用回环 VMess 入口（默认 `18081`），因此 VMess TLS 与 Argo 可以共存；请将 Cloudflare ingress 更新为 `http://127.0.0.1:18081`。
- Phase 2 新增原生 WARP、可选 Socks5、本地 `.srs` 规则集与锁定内核切换；`warp-plus` / Psiphon 仍明确排除。

---

## 鸣谢与血统说明

本项目是一个**完全全新编写的独立重构版本**。灵感源于 [yonggekkk/sing-box-yg](https://github.com/yonggekkk/sing-box-yg) 项目中的五协议共存理念。

虽然受到多协议架构概念的启发，但**本项目与原项目不存在任何共享代码行**。新版全面摒弃了脆弱的 Shell 字符串处理、root 提权执行与不可信远程脚本，基于类型安全的 Python 3.10+ 标准库、加密供应链锁定、非 root systemd 沙盒以及不可变回滚快照进行重构。项目不提供 Serv00/FreeBSD 支持，亦不接管旧版 `/etc/s-box` 安装目录。

---

## License

Copyright (C) 2026 Bosco1262

本项目采用 [GNU General Public License v3.0 或更高版本](LICENSE)。
