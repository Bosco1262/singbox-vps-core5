# singbox-vps-core5 (sbox5)

[English](README.md) | [简体中文](README.zh-CN.md)

[![License: GPLv3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
[![Python: 3.10+](https://img.shields.io/badge/Python-3.10%2B-green.svg)](https://www.python.org/)
[![Platform: Linux](https://img.shields.io/badge/Platform-Debian%2012%2B%20%7C%20Ubuntu%2022.04%2B-orange.svg)]()
[![Tests: 32 Passed](https://img.shields.io/badge/Tests-32%20Passed-brightgreen.svg)]()

**singbox-vps-core5** (`sbox5`) 是一个面向 Linux VPS 的生产加固、可审计且支持故障回滚的多协议代理套件。在严苛的安全隔离、非 root systemd 沙盒与不可变供应链锁的保护下，实现五大现代协议（**VLESS-Reality**、**VMess-WS**、**Hysteria2**、**TUIC v5** 与 **AnyTLS**）的原生平滑共存。

---

## 核心特性

- **五协议原生共存**：单机同时运行 VLESS-Reality、VMess-WebSocket、Hysteria2（含 Salamander 混淆）、TUIC v5 与 AnyTLS，互不干扰；
- **非 root 权限隔离**：核心服务分别运行于专用系统账户（`sbox5`、`sbox5-argo`、`sbox5-ddns`），彻底废除特权执行；
- **供应链哈希硬锁**：通过 `locks/*.json` 硬编码官方下载源与 SHA256，流式校验哈希与归档结构，杜绝上游静默投毒；
- **零外部库依赖**：纯 Python 3.10+ 标准库实现，无需 `pip install`，无外部脚本远程管道执行；
- **原子事务与快照回滚**：安装、升级、卸载前自动捕获系统快照（配置、防火墙、用户、sysctl），失败全自动回滚，快照自带离线无依赖 `restore.py`；
- **落盘前官方语法预检**：生成配置后强制调用官方 `sing-box check` 预检，验证通过后方可启动服务；
- **双源交叉验证 DDNS**：对接 Cloudflare API，至少由两个独立 HTTPS 端点交叉确认公网 IP 后方可写入，强制 `proxied: false`；
- **最小权限防火墙接管**：优先适配既有 UFW，或建立独立 `inet sbox5` 表，绝不执行全局 `iptables -F` 或清空宿主规则；
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
  status       查看各服务单元状态、组件版本与 DDNS 运行状态
  show         查看节点链接（--protocol 筛选, --json 输出, --qr 终端渲染二维码）
  export       重新生成客户端配置文件到 /var/lib/sbox5/exports
  check        调用 sing-box 官方二进制校验服务端与客户端配置有效性
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
| `--certificate-mode`           | TLS 证书模式                                | `self-signed` (自签) 或 `acme` (Certbot) |
| `--domain`                     | ACME 域名 (仅 ACME 模式需要)                | 需解析至本机的域名                       |
| `--vless-port`                 | VLESS-Reality 监听端口                      | 默认 `18443`                             |
| `--vmess-port`                 | VMess-WebSocket 监听端口                    | 默认 `18080`                             |
| `--hysteria2-port`             | Hysteria2 UDP 监听端口                      | 默认 `18444`                             |
| `--tuic-port`                  | TUIC v5 UDP 监听端口                        | 默认 `18445`                             |
| `--anytls-port`                | AnyTLS TCP 监听端口                         | 默认 `18446`                             |
| `--hysteria2-port-hopping`     | Hysteria2 端口跳跃范围                      | 可选，如 `20000:30000`                   |
| `--ddns` / `--no-ddns`         | 是否启用 Cloudflare DDNS                    | 默认禁用                                 |
| `--cloudflare-zone`            | Cloudflare 主域名 Zone                      | 如 `example.com`                         |
| `--ddns-record`                | DDNS 解析目标完整记录                       | 如 `vpn.example.com`                     |
| `--argo` / `--no-argo`         | 是否启用 Cloudflare Tunnel (VMess 备用通道) | 默认禁用                                 |
| `--argo-hostname`              | Argo 隧道外部域名                           | 如 `tunnel.example.com`                  |
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
 │    └── secrets/ [argo, ddns]     (0711 dir, tokens: 0600)
 ├── /var/lib/sbox5/
 │    ├── snapshots/                (0700, 独立快照存储)
 │    └── exports/                  (0700, 客户端配置文件)
 └── Services:
      ├── sbox5.service             (User=sbox5, hardened systemd sandbox)
      ├── sbox5-argo.service        (User=sbox5-argo, --token-file)
      ├── sbox5-ddns.timer          (User=sbox5-ddns, dual-source check)
      └── sbox5-firewall.service    (Minimal rule enforcement, no flush)
```

---

## 鸣谢与血统说明

本项目是一个**完全全新编写的独立重构版本**。灵感源于 [yonggekkk/sing-box-yg](https://github.com/yonggekkk/sing-box-yg) 项目中的五协议共存理念。

虽然受到多协议架构概念的启发，但**本项目与原项目不存在任何共享代码行**。新版全面摒弃了脆弱的 Shell 字符串处理、root 提权执行与不可信远程脚本，基于类型安全的 Python 3.10+ 标准库、加密供应链锁定、非 root systemd 沙盒以及不可变回滚快照进行重构。项目不提供 Serv00/FreeBSD 支持，亦不接管旧版 `/etc/s-box` 安装目录。

---

## License

Copyright (C) 2026 Bosco1262

本项目采用 [GNU General Public License v3.0 或更高版本](LICENSE)。
