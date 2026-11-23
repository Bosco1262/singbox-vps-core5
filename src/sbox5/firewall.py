# Copyright (C) 2026 Bosco1262
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import json
from pathlib import Path
import re
from typing import Any, Callable

from .errors import ConflictError, ExternalCommandError
from .i18n import tr
from .models import Settings
from .util import atomic_json, available, load_json, run

TABLE_NAME = "sbox5"
INPUT_CHAIN = "SBOX5-INPUT"
PREROUTING_CHAIN = "SBOX5-PREROUTING"
ChangeCallback = Callable[[dict[str, Any], str], None]
_RESOURCE_PRIORITY = {"ufw-rule": 0, "iptables-rule": 0, "iptables-jump": 1, "iptables-chain": 2, "nft-table": 3}


def required_ports(settings: Settings) -> list[dict[str, Any]]:
    ports: list[dict[str, Any]] = []
    for name in ("vless", "vmess", "hysteria2", "tuic", "anytls"):
        if not settings.protocols[name].enabled:
            continue
        ports.append({
            "port": getattr(settings.ports, name),
            "protocol": "udp" if name in ("hysteria2", "tuic") else "tcp",
            "name": name,
        })
    for profile in settings.active_certificate_profiles():
        if profile.mode != "acme":
            continue
        if profile.challenge == "http-01":
            ports.append({"port": 80, "protocol": "tcp", "name": f"acme-http-{profile.id}"})
        elif profile.challenge == "tls-alpn-01":
            ports.append({"port": 443, "protocol": "tcp", "name": f"acme-tls-{profile.id}"})
    if settings.subscription.enabled and settings.subscription.bind == "0.0.0.0":
        ports.append({"port": settings.subscription.port, "protocol": "tcp", "name": "subscription"})
    result: list[dict[str, Any]] = []
    seen: set[tuple[int, str]] = set()
    for item in ports:
        key = (int(item["port"]), str(item["protocol"]))
        if key in seen:
            continue
        seen.add(key)
        result.append(item)
    return result


def _key(item: dict[str, Any]) -> str:
    return json.dumps(item, sort_keys=True, separators=(",", ":"))


def _ufw_active() -> bool:
    if not available("ufw"):
        return False
    result = run(["ufw", "status"], check=False)
    return result.returncode == 0 and "status: active" in result.stdout.lower()


def _ufw_resources(settings: Settings) -> list[dict[str, Any]]:
    return [
        {"kind": "ufw-rule", "port": str(item["port"]), "protocol": item["protocol"], "name": item["name"]}
        for item in required_ports(settings)
    ]


def _apply_ufw(settings: Settings, callback: ChangeCallback) -> None:
    status = run(["ufw", "status"], check=True).stdout
    for resource in _ufw_resources(settings):
        token = f"{resource['port']}/{resource['protocol']}"
        exists = any(token in line.split() and "ALLOW" in line.upper() for line in status.splitlines())
        if not exists:
            run(["ufw", "allow", token, "comment", f"sbox5-{resource['name']}"], check=True)
            callback(resource, "add")


def _nft_table_exists() -> bool:
    return available("nft") and run(["nft", "list", "table", "inet", TABLE_NAME], check=False).returncode == 0


def _restrictive_nft_ruleset() -> bool:
    result = run(["nft", "list", "ruleset"], check=False)
    if result.returncode != 0:
        raise ExternalCommandError(tr("Unable to read the current nftables ruleset", "无法读取 nftables 当前规则"))
    without_project = "\n".join(line for line in result.stdout.splitlines() if TABLE_NAME not in line)
    return bool(re.search(r"\bpolicy\s+drop\b|\bdrop\b", without_project))


def _ensure_nft_chain(chain: str, definition: list[str]) -> None:
    if run(["nft", "list", "chain", "inet", TABLE_NAME, chain], check=False).returncode != 0:
        run(["nft", "add", "chain", "inet", TABLE_NAME, chain, *definition], check=True)


def _apply_nft(settings: Settings, check_conflicts: bool = True) -> list[str]:
    if check_conflicts and not _nft_table_exists() and _restrictive_nft_ruleset():
        raise ConflictError(tr("Custom nftables DROP rules were detected. To avoid changing their semantics, open the required ports manually and retry", "检测到自定义 nftables DROP 规则。为避免改变其语义，请手动开放所需端口后重试"))
    if not _nft_table_exists():
        run(["nft", "add", "table", "inet", TABLE_NAME], check=True)
    _ensure_nft_chain("input", ["{", "type", "filter", "hook", "input", "priority", "0;", "policy", "accept;", "}"])
    run(["nft", "flush", "chain", "inet", TABLE_NAME, "input"], check=True)
    for item in required_ports(settings):
        run(["nft", "add", "rule", "inet", TABLE_NAME, "input", item["protocol"], "dport", str(item["port"]), "accept"], check=True)
    _ensure_nft_chain("prerouting", ["{", "type", "nat", "hook", "prerouting", "priority", "dstnat;", "policy", "accept;", "}"])
    run(["nft", "flush", "chain", "inet", TABLE_NAME, "prerouting"], check=True)
    for protocol_name, value in sorted(settings.port_hopping.items()):
        start, end = value.split(":", 1)
        run([
            "nft", "add", "rule", "inet", TABLE_NAME, "prerouting", "iifname", "!=", "lo",
            "udp", "dport", f"{start}-{end}",
            "redirect", "to", f":{getattr(settings.ports, protocol_name)}",
        ], check=True)
    warnings: list[str] = []
    if _restrictive_nft_ruleset():
        warnings.append(tr("Other DROP rules exist on the system; project rules will not override them. If a node is unreachable, check the rule order manually", "系统存在其他 DROP 规则；项目规则不会覆盖它们，如节点不可达请人工检查规则顺序"))
    return warnings


def _nat_specs(settings: Settings) -> list[list[str]]:
    specs: list[list[str]] = []
    for protocol_name, value in sorted(settings.port_hopping.items()):
        start, end = value.split(":", 1)
        specs.append([
            "-p", "udp", "--dport", f"{start}:{end}", "-m", "comment",
            "--comment", f"sbox5-{protocol_name}-hop", "-j", "REDIRECT",
            "--to-ports", str(getattr(settings.ports, protocol_name)),
        ])
    return specs


def _iptables_executables() -> list[str]:
    executables = ["iptables"]
    if Path("/proc/net/if_inet6").exists() and available("ip6tables"):
        executables.append("ip6tables")
    return executables


def _nat_available(executable: str) -> bool:
    return run([executable, "-t", "nat", "-L", "-n"], check=False).returncode == 0


def _chain_resources(settings: Settings, executable: str, nat_only: bool) -> list[dict[str, Any]]:
    ipv6 = executable == "ip6tables"
    resources: list[dict[str, Any]] = []
    if not nat_only:
        table, chain = "filter", INPUT_CHAIN
        resources.append({"kind": "iptables-chain", "ipv6": ipv6, "table": table, "chain": chain})
        resources.append({
            "kind": "iptables-jump", "ipv6": ipv6, "table": table, "chain": "INPUT",
            "target": chain, "spec": ["-j", chain],
        })
        for item in required_ports(settings):
            resources.append({
                "kind": "iptables-rule", "ipv6": ipv6, "table": table, "chain": chain,
                "spec": [
                    "-p", item["protocol"], "--dport", str(item["port"]), "-m", "comment",
                    "--comment", f"sbox5-{item['name']}", "-j", "ACCEPT",
                ],
            })
    if settings.port_hopping:
        table, chain = "nat", PREROUTING_CHAIN
        resources.append({"kind": "iptables-chain", "ipv6": ipv6, "table": table, "chain": chain})
        resources.append({
            "kind": "iptables-jump", "ipv6": ipv6, "table": table, "chain": "PREROUTING",
            "target": chain, "spec": ["-j", chain],
        })
        for spec in _nat_specs(settings):
            resources.append({"kind": "iptables-rule", "ipv6": ipv6, "table": table, "chain": chain, "spec": spec})
    return resources


def _iptables_resources(settings: Settings, nat_only: bool = False) -> list[dict[str, Any]]:
    resources: list[dict[str, Any]] = []
    for executable in _iptables_executables():
        if nat_only and not _nat_available(executable):
            continue
        resources.extend(_chain_resources(settings, executable, nat_only))
    return resources


def _chain_exists(executable: str, table: str, chain: str) -> bool:
    return run([executable, "-t", table, "-S", chain], check=False).returncode == 0


def _supported_iptables_resources(
    settings: Settings,
    nat_only: bool = False,
) -> tuple[list[dict[str, Any]], list[str]]:
    resources: list[dict[str, Any]] = []
    warnings: list[str] = []
    for executable in _iptables_executables():
        if nat_only and not _nat_available(executable):
            warnings.append(tr(
                f"{executable} does not support the nat table; UDP port hopping is skipped for this address family",
                f"{executable} 不支持 nat 表；该地址族的 UDP 端口跳跃已跳过",
            ))
            continue
        resources.extend(_chain_resources(settings, executable, nat_only))
    return resources, warnings


def _apply_iptables_resources(
    resources: list[dict[str, Any]],
    callback: ChangeCallback,
    previous_owned: list[dict[str, Any]] | None = None,
) -> None:
    previous_keys = {_key(item) for item in (previous_owned or [])}
    for resource in resources:
        executable = "ip6tables" if resource.get("ipv6") else "iptables"
        table, chain = resource["table"], resource["chain"]
        kind = resource["kind"]
        if kind == "iptables-chain":
            if _chain_exists(executable, table, chain):
                if _key(resource) not in previous_keys:
                    raise ConflictError(tr(
                        f"The iptables chain already exists and is not owned by sbox5: {chain}",
                        f"iptables 链已存在且不属于 sbox5：{chain}",
                    ))
            else:
                run([executable, "-t", table, "-N", chain], check=True)
                callback(resource, "add")
        elif kind == "iptables-jump":
            spec = resource["spec"]
            if run([executable, "-t", table, "-C", chain, *spec], check=False).returncode == 0:
                if _key(resource) not in previous_keys:
                    raise ConflictError(tr(
                        f"The iptables jump already exists and is not owned by sbox5: {chain} -> {resource['target']}",
                        f"iptables 跳转已存在且不属于 sbox5：{chain} -> {resource['target']}",
                    ))
            else:
                run([executable, "-t", table, "-I", chain, "1", *spec], check=True)
                callback(resource, "add")
        else:
            spec = resource["spec"]
            if run([executable, "-t", table, "-C", chain, *spec], check=False).returncode != 0:
                run([executable, "-t", table, "-A", chain, *spec], check=True)
                callback(resource, "add")


def _delete_resource(resource: dict[str, Any], callback: ChangeCallback) -> None:
    kind = resource.get("kind")
    if kind == "ufw-rule":
        token = f"{int(resource['port'])}/{resource['protocol']}"
        if run(["ufw", "--force", "delete", "allow", token], check=False).returncode == 0:
            callback(resource, "remove")
    elif kind in ("iptables-rule", "iptables-jump"):
        executable = "ip6tables" if resource.get("ipv6") else "iptables"
        table, chain, spec = resource["table"], resource["chain"], resource["spec"]
        if run([executable, "-t", table, "-D", chain, *spec], check=False).returncode == 0:
            callback(resource, "remove")
    elif kind == "iptables-chain":
        executable = "ip6tables" if resource.get("ipv6") else "iptables"
        table, chain = resource["table"], resource["chain"]
        run([executable, "-t", table, "-F", chain], check=False)
        if run([executable, "-t", table, "-X", chain], check=False).returncode == 0:
            callback(resource, "remove")


def _remove_resources(resources: list[dict[str, Any]], callback: ChangeCallback) -> None:
    for resource in sorted(resources, key=lambda item: _RESOURCE_PRIORITY.get(str(item.get("kind")), 0)):
        if resource.get("kind") != "nft-table":
            _delete_resource(resource, callback)


def apply_firewall(settings: Settings, state_path: Path | None = None, on_change: ChangeCallback | None = None) -> dict[str, Any]:
    callback = on_change or (lambda resource, action: None)
    previous: dict[str, Any] = {}
    if state_path and state_path.is_file():
        previous = load_json(state_path)
    previous_owned = previous.get("owned", [])
    if not settings.manage_firewall:
        _remove_resources(previous_owned, callback)
        if any(item.get("kind") == "nft-table" for item in previous_owned) and _nft_table_exists():
            run(["nft", "delete", "table", "inet", TABLE_NAME], check=True)
        result = {
            "version": 2,
            "backend": "manual",
            "owned": [],
            "required": required_ports(settings),
            "warnings": [tr("Firewall management is left manual", "防火墙保持手动管理")],
        }
        if state_path:
            atomic_json(state_path, result, 0o600)
        return result

    warnings: list[str] = []
    desired: list[dict[str, Any]] = []
    use_nft = False
    previous_nft = any(item.get("kind") == "nft-table" and item.get("name") == TABLE_NAME for item in previous_owned)
    if _ufw_active():
        backend = "ufw"
        desired += _ufw_resources(settings)
        if settings.port_hopping:
            if available("nft"):
                if _nft_table_exists() and not previous_nft:
                    raise ConflictError(tr(
                        "The nftables table inet sbox5 already exists and is not owned by sbox5",
                        "nftables 表 inet sbox5 已存在且不属于 sbox5",
                    ))
                use_nft = True
                desired.append({"kind": "nft-table", "name": TABLE_NAME})
            elif available("iptables"):
                nat_resources, nat_warnings = _supported_iptables_resources(settings, nat_only=True)
                desired += nat_resources
                warnings += nat_warnings
            else:
                raise ExternalCommandError(tr("Port hopping requires nftables or iptables", "端口跳跃需要 nftables 或 iptables"))
    elif available("nft"):
        backend = "nftables"
        if _nft_table_exists() and not previous_nft:
            raise ConflictError(tr(
                "The nftables table inet sbox5 already exists and is not owned by sbox5",
                "nftables 表 inet sbox5 已存在且不属于 sbox5",
            ))
        use_nft = True
        desired.append({"kind": "nft-table", "name": TABLE_NAME})
    elif available("iptables"):
        backend = "iptables"
        iptables_resources, iptables_warnings = _supported_iptables_resources(settings)
        desired += iptables_resources
        warnings += iptables_warnings
    else:
        raise ExternalCommandError(tr("No supported firewall backend (UFW, nftables, or iptables) was found; open the ports manually", "找不到受支持的 UFW、nftables 或 iptables；请手动开放端口"))

    desired_keys = {_key(item) for item in desired}
    stale = [
        resource for resource in previous_owned
        if resource.get("kind") != "nft-table" and _key(resource) not in desired_keys
    ]
    _remove_resources(stale, callback)

    if backend == "ufw":
        _apply_ufw(settings, callback)
        if use_nft:
            warnings += _apply_nft(settings, check_conflicts=False)
        elif settings.port_hopping:
            _apply_iptables_resources(
                [item for item in desired if item.get("kind", "").startswith("iptables-")],
                callback,
                previous_owned,
            )
    elif backend == "nftables":
        warnings += _apply_nft(settings)
    else:
        _apply_iptables_resources(desired, callback, previous_owned)

    if not use_nft and previous_nft and _nft_table_exists():
        run(["nft", "delete", "table", "inet", TABLE_NAME], check=True)
    result = {
        "version": 2,
        "backend": backend,
        "owned": desired,
        "required": required_ports(settings),
        "warnings": warnings,
    }
    if state_path:
        atomic_json(state_path, result, 0o600)
    return result


def needs_firewall_service(settings: Settings) -> bool:
    if not settings.manage_firewall:
        return False
    if settings.port_hopping:
        return True
    return not _ufw_active()
