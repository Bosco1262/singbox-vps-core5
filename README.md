# singbox-vps-core5 (sbox5)

[English](README.md) | [简体中文](README.zh-CN.md)

[![License: GPLv3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
[![Python: 3.10+](https://img.shields.io/badge/Python-3.10%2B-green.svg)](https://www.python.org/)
[![Platform: Linux](https://img.shields.io/badge/Platform-Debian%2012%2B%20%7C%20Ubuntu%2022.04%2B%20%7C%20Alpine%203.20%2B%20%7C%20RHEL%209%2B-orange.svg)]()
[![Tests: 116 Passed](https://img.shields.io/badge/Tests-116%20Passed-brightgreen.svg)]()

**singbox-vps-core5** (`sbox5`) is a production-hardened, auditable, and rollback-ready proxy suite for Linux VPS. It enables seamless coexistence of five modern protocols (**VLESS-Reality**, **VMess-WS**, **Hysteria2**, **TUIC v5**, and **AnyTLS**) under strict security isolation, non-root systemd sandboxing, and immutable supply-chain locking.

---

## Features

- **Coexisting 5 Modern Protocols**: VLESS-Reality, VMess-WebSocket (optional TLS), Hysteria2 (with Salamander obfs), TUIC v5 (BBR native), and AnyTLS running concurrently without conflicts. Each protocol can be enabled or disabled independently.
- **Native ACME & Per-Protocol TLS**: sing-box native ACME certificate providers (HTTP-01, TLS-ALPN-01, DNS-01; IP certificates where the CA supports them) with per-protocol TLS profile binding. No certbot, no external renewal timer.
- **Strict Non-Root Isolation**: Core proxy services run under dedicated non-login system accounts (`sbox5`, `sbox5-argo`, `sbox5-ddns`, `sbox5-sub`), eliminating privileged execution.
- **Cryptographic Supply-Chain Locks**: Pinned upstream binaries via `locks/*.json` with strict SHA256 hashes and archive member security verification.
- **Zero External Dependencies**: Pure Python 3.10+ standard library. Zero `pip` packages required.
- **Fail-Safe Rollback & Snapshots**: Every install, upgrade, reconfigure, or uninstall creates an immutable snapshot with a self-contained offline `restore.py`.
- **Pre-Flight Validation**: All configs verified via official `sing-box check` before any service startup or certificate renewal; modern route rules start with `{"action":"sniff"}` so domain-based routing works for IP-literal client connections.
- **Dual-Source Cloudflare DDNS**: Cross-confirmed IP detection against multiple independent endpoints; prevents split-brain and stale DNS writes.
- **Non-Destructive Firewall Management**: Adapts to existing UFW, or builds dedicated `inet sbox5` nftables tables. The iptables fallback uses isolated `SBOX5-INPUT` / `SBOX5-PREROUTING` chains. Never flushes system rules.
- **Hysteria2 / TUIC UDP Port Hopping**: Declarative UDP ranges are reconciled in dedicated firewall chains/table, with SNAT-style local redirects and precise rollback. TUIC has no standard port-range URI field, so the client must choose a concrete port.
- **Argo Quick & Token Tunnels**: `cloudflared` quick tunnels and fixed token tunnels are managed as hardened non-root services. A dedicated loopback-only VMess ingress lets Argo coexist with public VMess TLS.
- **Native WARP & Multi-Target Routing**: WARP credentials are registered through the Cloudflare client endpoint or imported manually (never shared keys). Domain suffixes and local `.srs` rule sets route to WARP, direct IPv4/IPv6, or an optional Socks5 outbound.
- **CDN Preference & Full Client Export**: Optional VMess/Argo CDN preferred IP/domain with explicit Host/SNI; exports SFA, SFI, SFW, sing-box, Mihomo, share links, QR codes, and a Base64 subscription bundle.
- **Local Subscription Service**: A dedicated non-root `sbox5-sub` service serves only a whitelisted bundle through a high-entropy path token. The server stores only the token hash; localhost + TLS reverse proxy is the default, with optional built-in TLS using a self-signed/imported profile.
- **Locked Core Lifecycle**: Stable/channel/version switching only accepts immutable lock files, pre-checks the new binary with `sing-box check`, and rolls back automatically on failure.
- **Operations Console**: `sbox5 menu` provides a live status dashboard, logs, health checks, protocol/port actions, and certificate/subscription views without memorizing flags. `sbox5 doctor --json` gives scriptable PASS/WARN/FAIL results.
- **Dual-Stack Export Control**: `sbox5 ip set --family ipv4|ipv6|auto` selects which detected global address is written into share links, SFA/SFI/SFW, sing-box client configs, and Mihomo, while the server keeps dual-stack listeners.
- **Cross-Distro Services**: Debian/Ubuntu/RHEL use hardened systemd units; Alpine uses OpenRC runscripts with dedicated users, file logs, a DDNS loop, and `setcap cap_net_bind_service` only when low ports or native ACME require it.
- **Zero-Trust TLS**: Self-signed mode automatically inlines certificates into sing-box client configs and binds full SHA256 DER fingerprints in Mihomo (Clash.Meta). No `insecure: true` anywhere.

---

## System Requirements

- **OS**: Debian 12+ / Ubuntu 22.04+ / Alpine 3.20+ / RHEL 9+, Rocky 9+, or AlmaLinux 9+ (64-bit x86_64 / arm64)
- **Init**: systemd on Debian/Ubuntu/RHEL; OpenRC on Alpine
- **Virtualization**: KVM, Google Compute Engine, AWS, Azure/Hyper-V, VMware, Xen, or bare metal with an independent kernel. Containers and shared-kernel environments (Docker, LXC, WSL) are rejected by preflight.
- **Runtime**: Python 3.10+ (Standard Library)
- **Firewall**: UFW, nftables, or iptables. On RHEL with firewalld active, sbox5 refuses to modify firewalld: open ports with `firewall-cmd`, then install with `--no-firewall` or disable firewalld deliberately.

---

## Quick Start

### 1. Installation

```bash
# Clone the repository as root
sudo git clone https://github.com/Bosco1262/singbox-vps-core5.git /usr/local/src/singbox-vps-core5
cd /usr/local/src/singbox-vps-core5

# Grant execute permissions after cloning
sudo chmod +x install.sh sbox5 sb.sh

# Run installer (Interactive mode)
sudo ./install.sh
```

Or invoke the CLI directly:
```bash
sudo ./sbox5 install
```

On a minimal Alpine or RHEL image, install Python 3.10+ first with the distribution package manager (`apk add python3` or `dnf install python3`). RHEL 9's default `python3` is 3.9, so install `python3.11` (or newer) from AppStream first; the launcher detects it automatically. The installer then installs the remaining official packages (nftables, iptables, OpenSSL, iproute2, libcap/shadow on Alpine) itself.

### 2. Command Reference

```text
sbox5 <subcommand>

  install      Fresh installation (interactive guidance or parameter-driven)
  upgrade      Seamless core component upgrade based on lock files
  status       Display non-sensitive service status, versions, protocols, and certificate profiles (--text for the dashboard, --geo for optional IP geolocation)
  menu         Interactive dashboard for status, logs, health checks, and common changes
  service      Start, stop, restart, or inspect a service (core|argo|ddns|subscription|firewall)
  bbr          Show, enable, or disable BBR
  reality set  Change the Reality target and SNI
  secrets rotate Rotate protocol UUIDs, passwords, and the VMess path
  self-update  Fast-forward the trusted git checkout (HTTPS origin only)
  doctor       Run local health checks (--json for automation)
  logs         Show service logs (--service core|argo|ddns|subscription|firewall, --follow)
  ip show      Show detected global IPv4/IPv6 addresses
  ip set       Select auto/ipv4/ipv6 for exported client addresses
  show         Display node credentials and links (--protocol, --json, --qr)
  export       Re-export client configuration files to /var/lib/sbox5/exports
  check        Verify server and client configs with official sing-box binary
  port set     Change a protocol port with snapshot-backed rollback
  port hopping Manage Hysteria2/TUIC UDP port-hopping ranges
  protocol set Enable/disable a protocol or change its TLS profile
  cert list    List certificate profiles and protocol bindings
  cert add     Add a self-signed, native ACME, or imported certificate profile
  cert bind    Bind a protocol to a certificate profile (or 'none' for VMess)
  cert remove  Remove an unbound certificate profile with snapshot rollback
  argo         Manage quick/token tunnels, status, start/stop, and reset
  warp         Register, import, rotate, enable/disable, or clear WARP
  route        Manage domain routes, Socks5, and local .srs rule sets
  core         Show, list, switch, or roll back locked sing-box versions
  cdn          Set or clear VMess/Argo CDN preferred address and Host/SNI
  subscription Manage the local tokenized subscription service
  snapshots    List local transaction snapshots and states
  rollback     One-click system rollback using the snapshot's standalone restorer
  uninstall    Safe uninstall (creates snapshot, cleans rules and files, preserves packages)
```

### Upstream-compatible console (`sb.sh`)

`sudo ./sb.sh` opens a numbered console that follows the familiar upstream menu flow. It is a presentation layer only: every action calls the `sbox5` CLI, so snapshots, hash locks, `sing-box check`, non-root services, and firewall isolation remain in force.

- The console never edits `/etc/sbox5`, calls `systemctl`/`nft`/`iptables`, or downloads remote scripts.
- Menu 7.1 only fast-forwards a clean git checkout from the pinned HTTPS origin; it never executes remote code.
- Intentionally not included: Telegram/GitLab push, WARP-plus/Psiphon, Serv00/FreeBSD, and the legacy `/etc/s-box`.
- No global `sb` shortcut is installed; run the script from the repository.
- `sbox5 menu` remains the compact native menu.

---

## Interactive Installation Options

On a fresh install, any protocol port not provided explicitly is randomly selected from `10000-65535` and verified free for both TCP and UDP. Upgrades and reconfigurations keep the existing ports.

| Option | Description | Default / Choices |
| :--- | :--- | :--- |
| `--host` | Public server IP or bound domain | Auto-detected / Manual |
| `--reality-target` | Reality handshake fallback target | e.g., `www.apple.com:443` |
| `--reality-sni` | Reality server name indication | Extracted from target |
| `--certificate-mode` | TLS certificate mode | `self-signed`, `acme` (sing-box native), or `imported` |
| `--domain` | ACME domain or IP | Must resolve to this server for HTTP-01/TLS-ALPN-01 |
| `--acme-email` | ACME account email | Optional |
| `--acme-challenge` | ACME challenge type | `http-01`, `tls-alpn-01`, or `dns-01` |
| `--acme-dns-provider` | DNS-01 provider | `cloudflare` |
| `--acme-dns-token-file` | DNS-01 API token file | Root-readable regular file; native ACME places the token in `config.json` (`0640 root:sbox5`) at runtime |
| `--tls-server-name` | TLS server name for self-signed/imported profiles | Auto-generated for self-signed |
| `--vmess-tls` / `--no-vmess-tls` | Enable VMess TLS | Default disabled; incompatible with Argo |
| `--vless-port` | VLESS-Reality listening port | Random free port on fresh install |
| `--vmess-port` | VMess-WebSocket listening port | Random free port on fresh install |
| `--hysteria2-port` | Hysteria2 UDP listening port | Random free port on fresh install |
| `--tuic-port` | TUIC v5 UDP listening port | Random free port on fresh install |
| `--anytls-port` | AnyTLS TCP listening port | Random free port on fresh install |
| `--hysteria2-port-hopping`| Hysteria2 UDP hopping range | Optional, e.g., `20000:30000` |
| `--tuic-port-hopping` | TUIC UDP hopping range | Optional, e.g., `30000:40000` |
| `--ddns` / `--no-ddns` | Enable Cloudflare DDNS | Default disabled |
| `--cloudflare-zone` | Cloudflare apex zone domain | e.g., `example.com` |
| `--ddns-record` | Complete DDNS target record | e.g., `vpn.example.com` |
| `--argo` / `--no-argo` | Enable Cloudflare Tunnel (VMess backup) | Default disabled |
| `--argo-mode` | Argo tunnel mode | `quick` or `token` |
| `--argo-hostname` | Cloudflare Tunnel external domain | Required for token mode |
| `--argo-local-port` | Loopback-only VMess ingress for Argo | Default `18081` |
| `--bbr` / `--no-bbr` | Enable kernel BBR congestion control | Default disabled |
| `--firewall` / `--no-firewall` | Automatically manage firewall rules | Default enabled |
| `-l`, `--lang`, `--language` | Language preference (`en`, `zh-CN`) | Auto-detected / `en` |

---

## Client Configuration

After installation, complete client profiles are exported into a secure directory (`0700` permissions):
```text
/var/lib/sbox5/exports/
├── links.txt                # Universal share links (vless://, vmess://, hysteria2://, tuic://, anytls://)
├── subscription-base64.txt  # Base64 encoded subscription bundle
├── sing-box-client.json     # Official sing-box mixed-inbound client configuration
├── sfa.json / sfi.json / sfw.json  # Sing-box TUN profiles for Android/iOS/Windows
├── mihomo.yaml              # Mihomo (Clash.Meta) profile with bound certificate fingerprint
├── metadata.json            # Export metadata and TLS verification details
├── certificate*.pem         # Public self-signed/imported certificates for pinning
└── *.png                    # QR codes for nodes (if qrencode is available)
```

Displaying nodes:
```bash
# View all share links
sudo sbox5 show

# View specific protocol and render terminal QR code
sudo sbox5 show --protocol hysteria2 --qr
```

---

## Architecture & Security

```text
Host System (Debian 12 / Ubuntu 22.04)
 ├── /etc/sbox5/
 │    ├── config.json               (0640, group: sbox5)
 │    ├── settings.json             (0600 / 0640)
 │    ├── tls/ [cert.pem, key.pem]  (0750 dir, key: 0600, sbox5:sbox5)
 │    ├── tls/<profile>/            (additional certificate profiles)
 │    └── secrets/ [argo, ddns, protocols, subscription] (0711 dir, tokens: 0600)
 ├── /var/lib/sbox5/
 │    ├── acme/<profile>/           (0700, native sing-box ACME state)
 │    ├── certificates.json         (per-profile certificate state)
 │    ├── argo/                     (state.json + quick tunnel log)
 │    ├── rulesets/                 (local .srs rule sets)
 │    ├── subscription/             (0700, tokenized bundle + optional TLS)
 │    ├── core.json                 (current/previous core versions)
 │    ├── snapshots/                (0700, standalone snapshot storage)
 │    └── exports/                  (0700, client configuration profiles)
 └── Services:
      ├── sbox5.service             (User=sbox5, hardened systemd sandbox, native ACME)
      ├── sbox5-argo.service        (User=sbox5-argo, quick or token tunnel)
      ├── sbox5-ddns.timer          (User=sbox5-ddns, dual-source check)
      ├── sbox5-subscription.service(User=sbox5-sub, tokenized local subscription)
      └── sbox5-firewall.service    (Minimal rule enforcement, no flush)
```

---

## Argo, WARP, Routing & Core

```bash
# Argo quick tunnel (URL is read from the hardened service log)
sudo sbox5 argo set --mode quick --yes
sudo sbox5 argo status
sudo sbox5 argo reset --yes

# Argo fixed token tunnel
sudo sbox5 argo set --mode token --hostname tunnel.example.com --token-file /root/tunnel.token --yes

# Native WARP registration or manual import
sudo sbox5 warp register --yes
sudo sbox5 warp status
sudo sbox5 warp import --private-key-file /root/wg.key --peer-public-key <key> \
  --address 172.16.0.2/32 --address 2606:4700:110::2/128 --reserved 1,2,3 --yes

# Domain/rule-set routing to WARP, local IPv4/IPv6, or Socks5
sudo sbox5 route add --target warp --suffix .openai.com --yes
sudo sbox5 route socks5 set --server 127.0.0.1 --port 1080 --username user --yes
sudo sbox5 route ruleset add --tag geosite-cn --target direct-v4 \
  --url https://github.com/SagerNet/sing-geosite/releases/download/<tag>/geosite-cn.srs \
  --sha256 <64-hex-sha256> --yes
sudo sbox5 route list

# Locked core lifecycle
sudo sbox5 core list
sudo sbox5 core switch --channel stable --yes
sudo sbox5 core rollback --yes

# CDN preference for VMess/Argo
sudo sbox5 cdn set --target vmess --address 104.16.0.1 --host cdn.example.com --sni cdn.example.com --yes
sudo sbox5 cdn set --target argo --address 104.16.0.1 --yes
sudo sbox5 cdn list

# Local subscription service (localhost + TLS reverse proxy recommended)
sudo sbox5 subscription set --bind 127.0.0.1 --port 18090 --yes
sudo sbox5 subscription url
sudo sbox5 subscription rotate --yes

# Optional built-in TLS using a self-signed/imported certificate profile
sudo sbox5 subscription set --bind 0.0.0.0 --port 18090 --tls-profile default --yes
```

VMess CDN requires the origin VMess inbound to remain plaintext WebSocket; Argo CDN requires token mode because quick tunnel hostnames are ephemeral.

The subscription service exposes only whitelisted bundle files:

```text
/sub/<token>/links       /sub/<token>/base64
/sub/<token>/sing-box    /sub/<token>/sfa | sfi | sfw
/sub/<token>/mihomo      /sub/<token>/clash
/sub/<token>/metadata
```

Native ACME certificates cannot be read by the local subscription process; use a TLS reverse proxy for ACME, or a self-signed/imported certificate profile with built-in TLS. The raw token is stored only in `/etc/sbox5/secrets/subscription.token` (`0600`); the service config contains only its SHA256 hash.

WARP registration uses Cloudflare's client registration endpoint and is never replaced by hard-coded/shared private keys. WARP private keys stay in `secrets/protocols.json` (`0600`) and are injected into `config.json` (`0640 root:sbox5`). Only locked sing-box versions are accepted; add a `locks/versions/<version>.json` file and set `channels.beta` in `locks/versions/index.json` before switching to a beta build.

### Phase 4 operations

```bash
# Live dashboard and common actions
sudo sbox5 menu

# Optional public IP geolocation (HTTPS request to ipinfo.io; no credentials are sent)
sudo sbox5 status --geo

# Logs and health checks
sudo sbox5 logs --service core --follow
sudo sbox5 doctor
sudo sbox5 doctor --json

# Choose the address written into client exports (server listeners stay dual-stack)
sudo sbox5 ip show
sudo sbox5 ip set --family ipv6 --yes
sudo sbox5 ip set --family auto --yes
```

`ip set` affects share links, SFA/SFI/SFW, sing-box client JSON, and Mihomo; it does not change listen sockets. If the selected family has no global address, the command fails explicitly instead of exporting an empty host.

Platform notes:

- **Alpine / OpenRC**: services are installed as `/etc/init.d/sbox5*` with dedicated users, file logs under `/var/log/sbox5`, and a long-running DDNS loop instead of a systemd timer. Low ports and native ACME HTTP-01/TLS-ALPN-01 use `setcap cap_net_bind_service=+ep` on the project-owned sing-box binary at service start; the `libcap` package is installed automatically.
- **RHEL / Rocky / AlmaLinux**: sbox5 never edits firewalld zones. If firewalld is running, open the required ports with `firewall-cmd` and install with `--no-firewall`, or deliberately disable firewalld before using the project-owned nftables table. SELinux policy is left to the administrator; `sbox5 doctor` reports service and config failures. QR PNG export uses `qrencode` when the distribution provides it; links and client configs are always exported.
- **Snapshots**: OpenRC runscripts, `/etc/init.d` changes, service enablement, and the new log directory are captured in the manifest and restored by the offline `recovery/restore.py`.

---

## Migration Notes (MVP → Phase 4)

- `settings.json` / `state.json` are migrated from schema v1/v2 to v3 automatically. Original v1/v2 snapshots remain restorable by their own bundled `restore.py`.
- Legacy certbot ACME profiles become native sing-box ACME profiles using HTTP-01 by default. The old certbot state under `/etc/sbox5/acme` is preserved but no longer used; the certificate is re-issued by sing-box on the next start.
- Existing protocol ports and credentials are preserved. TUIC/Hysteria2 hopping ranges are reapplied through the firewall reconciliation path.
- Existing Argo settings are migrated to token mode with the existing hostname. Argo now uses a loopback-only VMess ingress (`18081` by default), so VMess TLS and Argo can coexist; update the Cloudflare ingress to `http://127.0.0.1:18081`.
- Phase 2 adds native WARP, optional Socks5, local `.srs` rule sets, and locked core switching. `warp-plus` / Psiphon remain intentionally excluded.
- Phase 3 adds CDN preference, SFA/SFI/SFW exports, and a local subscription service only. GitLab/Telegram push are not included by design; use the tokenized subscription URL from your own HTTPS reverse proxy.
- Phase 4 adds the interactive menu, logs, doctor, dual-stack export selection, Alpine/OpenRC support, and RHEL 9 compatibility. Firewalld is treated as an administrator-owned boundary and is never modified automatically.

---

## Acknowledgements & Lineage

This project is an **independent, ground-up clean-room rewrite** inspired by the 5-protocol coexisting architecture popularized by [yonggekkk/sing-box-yg](https://github.com/yonggekkk/sing-box-yg).

While inspired by the multi-protocol proxy concept, **this repository shares zero lines of code with the original project**. It completely replaces fragile shell string manipulations, root execution, and remote execution with **type-safe Python 3.10+, cryptographic locks, non-root systemd sandboxes, and immutable rollback snapshots**. It does not support Serv00/FreeBSD and does not take over legacy `/etc/s-box` installations.

---

## License

Copyright (C) 2026 Bosco1262

This project is licensed under the [GNU General Public License v3.0 or later](LICENSE).
