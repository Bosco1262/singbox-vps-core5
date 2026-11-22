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
ChangeCallback = Callable[[dict[str, Any], str], None]


def required_ports(settings: Settings) -> list[dict[str, Any]]:
    ports = [
        {"port": settings.ports.vless, "protocol": "tcp", "name": "vless"},
        {"port": settings.ports.vmess, "protocol": "tcp", "name": "vmess"},
        {"port": settings.ports.hysteria2, "protocol": "udp", "name": "hysteria2"},
        {"port": settings.ports.tuic, "protocol": "udp", "name": "tuic"},
        {"port": settings.ports.anytls, "protocol": "tcp", "name": "anytls"},
    ]
    if settings.certificate_mode == "acme":
        ports.append({"port": 80, "protocol": "tcp", "name": "acme"})
    return ports


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
        exists = any(line.split() and line.split()[0] == token and "ALLOW" in line.upper() for line in status.splitlines())
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
    for protocol_name, value in settings.port_hopping.items():
        start, end = value.split(":", 1)
        run([
            "nft", "add", "rule", "inet", TABLE_NAME, "prerouting", "udp", "dport", f"{start}-{end}",
            "redirect", "to", f":{getattr(settings.ports, protocol_name)}",
        ], check=True)
    warnings: list[str] = []
    if _restrictive_nft_ruleset():
        warnings.append(tr("Other DROP rules exist on the system; project rules will not override them. If a node is unreachable, check the rule order manually", "系统存在其他 DROP 规则；项目规则不会覆盖它们，如节点不可达请人工检查规则顺序"))
    return warnings


def _nat_specs(settings: Settings) -> list[list[str]]:
    specs: list[list[str]] = []
    for protocol_name, value in settings.port_hopping.items():
        start, end = value.split(":", 1)
        specs.append([
            "-p", "udp", "--dport", f"{start}:{end}", "-j", "REDIRECT",
            "--to-ports", str(getattr(settings.ports, protocol_name)),
        ])
    return specs


def _iptables_executables() -> list[str]:
    executables = ["iptables"]
    if Path("/proc/net/if_inet6").exists() and available("ip6tables"):
        executables.append("ip6tables")
    return executables


def _iptables_resources(settings: Settings, nat_only: bool = False) -> list[dict[str, Any]]:
    resources: list[dict[str, Any]] = []
    for executable in _iptables_executables():
        ipv6 = executable == "ip6tables"
        if not nat_only:
            for item in required_ports(settings):
                resources.append({
                    "kind": "iptables-rule", "ipv6": ipv6, "table": "filter", "chain": "INPUT",
                    "spec": ["-p", item["protocol"], "--dport", str(item["port"]), "-j", "ACCEPT"],
                })
        for spec in _nat_specs(settings):
            resources.append({"kind": "iptables-rule", "ipv6": ipv6, "table": "nat", "chain": "PREROUTING", "spec": spec})
    return resources


def _apply_iptables(settings: Settings, callback: ChangeCallback, nat_only: bool = False) -> None:
    for resource in _iptables_resources(settings, nat_only):
        executable = "ip6tables" if resource["ipv6"] else "iptables"
        table, chain, spec = resource["table"], resource["chain"], resource["spec"]
        if run([executable, "-t", table, "-C", chain, *spec], check=False).returncode != 0:
            run([executable, "-t", table, "-I", chain, "1", *spec], check=True)
            callback(resource, "add")


def _delete_resource(resource: dict[str, Any], callback: ChangeCallback) -> None:
    kind = resource.get("kind")
    if kind == "ufw-rule":
        token = f"{int(resource['port'])}/{resource['protocol']}"
        if run(["ufw", "--force", "delete", "allow", token], check=False).returncode == 0:
            callback(resource, "remove")
    elif kind == "iptables-rule":
        executable = "ip6tables" if resource.get("ipv6") else "iptables"
        table, chain, spec = resource["table"], resource["chain"], resource["spec"]
        if run([executable, "-t", table, "-D", chain, *spec], check=False).returncode == 0:
            callback(resource, "remove")


def apply_firewall(settings: Settings, state_path: Path | None = None, on_change: ChangeCallback | None = None) -> dict[str, Any]:
    callback = on_change or (lambda resource, action: None)
    previous: dict[str, Any] = {}
    if state_path and state_path.is_file():
        previous = load_json(state_path)
    previous_owned = previous.get("owned", [])
    if not settings.manage_firewall:
        for resource in previous_owned:
            if resource.get("kind") != "nft-table":
                _delete_resource(resource, callback)
        if any(item.get("kind") == "nft-table" for item in previous_owned) and _nft_table_exists():
            run(["nft", "delete", "table", "inet", TABLE_NAME], check=True)
        result = {"backend": "manual", "owned": [], "required": required_ports(settings), "warnings": [tr("Firewall management is left manual", "防火墙保持手动管理")]}
        if state_path:
            atomic_json(state_path, result, 0o600)
        return result
    warnings: list[str] = []
    desired: list[dict[str, Any]] = []
    use_nft = False
    if _ufw_active():
        backend = "ufw"
        _apply_ufw(settings, callback)
        desired += _ufw_resources(settings)
        if settings.port_hopping:
            if available("nft"):
                use_nft = True
                warnings += _apply_nft(settings, check_conflicts=False)
            elif available("iptables"):
                _apply_iptables(settings, callback, nat_only=True)
                desired += _iptables_resources(settings, nat_only=True)
            else:
                raise ExternalCommandError(tr("Port hopping requires nftables or iptables", "端口跳跃需要 nftables 或 iptables"))
    elif available("nft"):
        backend = "nftables"
        use_nft = True
        warnings += _apply_nft(settings)
    elif available("iptables"):
        backend = "iptables"
        _apply_iptables(settings, callback)
        desired += _iptables_resources(settings)
    else:
        raise ExternalCommandError(tr("No supported firewall backend (UFW, nftables, or iptables) was found; open the ports manually", "找不到受支持的 UFW、nftables 或 iptables；请手动开放端口"))
    if use_nft:
        desired.append({"kind": "nft-table", "name": TABLE_NAME})
    desired_keys = {_key(item) for item in desired}
    for resource in previous_owned:
        if resource.get("kind") != "nft-table" and _key(resource) not in desired_keys:
            _delete_resource(resource, callback)
    if not use_nft and any(item.get("kind") == "nft-table" for item in previous_owned) and _nft_table_exists():
        run(["nft", "delete", "table", "inet", TABLE_NAME], check=True)
    result = {"backend": backend, "owned": desired, "required": required_ports(settings), "warnings": warnings}
    if state_path:
        atomic_json(state_path, result, 0o600)
    return result


def needs_firewall_service(settings: Settings) -> bool:
    if not settings.manage_firewall:
        return False
    if settings.port_hopping:
        return True
    return not _ufw_active()
