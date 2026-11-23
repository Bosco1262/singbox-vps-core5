# singbox-vps-core5 (sbox5)

[English](README.md) | [简体中文](README.zh-CN.md)

[![License: GPLv3](https://img.shields.io/badge/License-GPLv3-blue.svg)](LICENSE)
[![Python: 3.10+](https://img.shields.io/badge/Python-3.10%2B-green.svg)](https://www.python.org/)
[![Platform: Linux](https://img.shields.io/badge/Platform-Debian%2012%2B%20%7C%20Ubuntu%2022.04%2B-orange.svg)]()
[![Tests: 46 Passed](https://img.shields.io/badge/Tests-46%20Passed-brightgreen.svg)]()

**singbox-vps-core5** (`sbox5`) is a production-hardened, auditable, and rollback-ready proxy suite for Linux VPS. It enables seamless coexistence of five modern protocols (**VLESS-Reality**, **VMess-WS**, **Hysteria2**, **TUIC v5**, and **AnyTLS**) under strict security isolation, non-root systemd sandboxing, and immutable supply-chain locking.

---

## Features

- **Coexisting 5 Modern Protocols**: VLESS-Reality, VMess-WebSocket (optional TLS), Hysteria2 (with Salamander obfs), TUIC v5 (BBR native), and AnyTLS running concurrently without conflicts. Each protocol can be enabled or disabled independently.
- **Native ACME & Per-Protocol TLS**: sing-box native ACME certificate providers (HTTP-01, TLS-ALPN-01, DNS-01; IP certificates where the CA supports them) with per-protocol TLS profile binding. No certbot, no external renewal timer.
- **Strict Non-Root Isolation**: Core proxy services run under dedicated non-login system accounts (`sbox5`, `sbox5-argo`, `sbox5-ddns`), eliminating privileged execution.
- **Cryptographic Supply-Chain Locks**: Pinned upstream binaries via `locks/*.json` with strict SHA256 hashes and archive member security verification.
- **Zero External Dependencies**: Pure Python 3.10+ standard library. Zero `pip` packages required.
- **Fail-Safe Rollback & Snapshots**: Every install, upgrade, reconfigure, or uninstall creates an immutable snapshot with a self-contained offline `restore.py`.
- **Pre-Flight Validation**: All configs verified via official `sing-box check` before any service startup or certificate renewal; modern route rules start with `{"action":"sniff"}` so domain-based routing works for IP-literal client connections.
- **Dual-Source Cloudflare DDNS**: Cross-confirmed IP detection against multiple independent endpoints; prevents split-brain and stale DNS writes.
- **Non-Destructive Firewall Management**: Adapts to existing UFW, or builds dedicated `inet sbox5` nftables tables. The iptables fallback uses isolated `SBOX5-INPUT` / `SBOX5-PREROUTING` chains. Never flushes system rules.
- **Hysteria2 / TUIC UDP Port Hopping**: Declarative UDP ranges are reconciled in dedicated firewall chains/table, with SNAT-style local redirects and precise rollback. TUIC has no standard port-range URI field, so the client must choose a concrete port.
- **Zero-Trust TLS**: Self-signed mode automatically inlines certificates into sing-box client configs and binds full SHA256 DER fingerprints in Mihomo (Clash.Meta). No `insecure: true` anywhere.

---

## System Requirements

- **OS**: Debian 12+ / Ubuntu 22.04+ (64-bit x86_64 / arm64)
- **Init**: systemd (PID 1)
- **Virtualization**: KVM / Bare-metal (with independent kernel module support)
- **Runtime**: Python 3.10+ (Standard Library)

---

## Quick Start

### 1. Installation

```bash
# Clone the repository as root
sudo git clone https://github.com/Bosco1262/singbox-vps-core5.git /usr/local/src/singbox-vps-core5
cd /usr/local/src/singbox-vps-core5

# Grant execute permissions after cloning
sudo chmod +x install.sh sbox5

# Run installer (Interactive mode)
sudo ./install.sh
```

Or invoke the CLI directly:
```bash
sudo ./sbox5 install
```

### 2. Command Reference

```text
sbox5 <subcommand>

  install      Fresh installation (interactive guidance or parameter-driven)
  upgrade      Seamless core component upgrade based on lock files
  status       Display non-sensitive service status, versions, protocols, and certificate profiles
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
  snapshots    List local transaction snapshots and states
  rollback     One-click system rollback using the snapshot's standalone restorer
  uninstall    Safe uninstall (creates snapshot, cleans rules and files, preserves packages)
```

---

## Interactive Installation Options

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
| `--vless-port` | VLESS-Reality listening port | Default `18443` |
| `--vmess-port` | VMess-WebSocket listening port | Default `18080` |
| `--hysteria2-port` | Hysteria2 UDP listening port | Default `18444` |
| `--tuic-port` | TUIC v5 UDP listening port | Default `18445` |
| `--anytls-port` | AnyTLS TCP listening port | Default `18446` |
| `--hysteria2-port-hopping`| Hysteria2 UDP hopping range | Optional, e.g., `20000:30000` |
| `--tuic-port-hopping` | TUIC UDP hopping range | Optional, e.g., `30000:40000` |
| `--ddns` / `--no-ddns` | Enable Cloudflare DDNS | Default disabled |
| `--cloudflare-zone` | Cloudflare apex zone domain | e.g., `example.com` |
| `--ddns-record` | Complete DDNS target record | e.g., `vpn.example.com` |
| `--argo` / `--no-argo` | Enable Cloudflare Tunnel (VMess backup) | Default disabled |
| `--argo-hostname` | Cloudflare Tunnel external domain | e.g., `tunnel.example.com` |
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
├── sing-box-client.json     # Official sing-box client configuration
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
 │    └── secrets/ [argo, ddns, protocols] (0711 dir, tokens: 0600)
 ├── /var/lib/sbox5/
 │    ├── acme/<profile>/           (0700, native sing-box ACME state)
 │    ├── certificates.json         (per-profile certificate state)
 │    ├── snapshots/                (0700, standalone snapshot storage)
 │    └── exports/                  (0700, client configuration profiles)
 └── Services:
      ├── sbox5.service             (User=sbox5, hardened systemd sandbox, native ACME)
      ├── sbox5-argo.service        (User=sbox5-argo, --token-file)
      ├── sbox5-ddns.timer          (User=sbox5-ddns, dual-source check)
      └── sbox5-firewall.service    (Minimal rule enforcement, no flush)
```

---

## Migration Notes (MVP → Phase 1)

- `settings.json` / `state.json` are migrated from schema v1 to v2 automatically. The original v1 snapshot remains restorable by its own bundled `restore.py`.
- Legacy certbot ACME profiles become native sing-box ACME profiles using HTTP-01 by default. The old certbot state under `/etc/sbox5/acme` is preserved but no longer used; the certificate is re-issued by sing-box on the next start.
- Existing protocol ports and credentials are preserved. TUIC/Hysteria2 hopping ranges are reapplied through the new firewall reconciliation path.
- `warp-plus` / Psiphon are intentionally not carried into Phase 1; native WARP and optional Socks5 outbounds are planned for Phase 2.

---

## Acknowledgements & Lineage

This project is an **independent, ground-up clean-room rewrite** inspired by the 5-protocol coexisting architecture popularized by [yonggekkk/sing-box-yg](https://github.com/yonggekkk/sing-box-yg).

While inspired by the multi-protocol proxy concept, **this repository shares zero lines of code with the original project**. It completely replaces fragile shell string manipulations, root execution, and remote execution with **type-safe Python 3.10+, cryptographic locks, non-root systemd sandboxes, and immutable rollback snapshots**. It does not support Serv00/FreeBSD and does not take over legacy `/etc/s-box` installations.

---

## License

Copyright (C) 2026 Bosco1262

This project is licensed under the [GNU General Public License v3.0 or later](LICENSE).
