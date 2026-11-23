# Copyright (C) 2026 Bosco1262
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from sbox5.cli import build_parser
from sbox5.ddns import CloudflareDDNS, _detect_address
from sbox5.download import _safe_archive_member, _validate_url
from sbox5.errors import ExternalCommandError, VerificationError
from sbox5.firewall import _iptables_resources, apply_firewall, required_ports
from sbox5.models import DDNSSettings, Settings
from sbox5.services import argo_unit, singbox_unit
from sbox5.snapshot import Snapshot, prune_snapshots
from sbox5.util import atomic_json, sha256_file


class DownloadTests(unittest.TestCase):
    def test_download_url_is_pinned_to_https_and_port(self):
        allowed = {"github.com"}
        _validate_url("https://github.com/example/file", allowed)
        for url in (
            "http://github.com/example/file", "https://evil.example/file",
            "https://user:pass@github.com/file", "https://github.com:8443/file",
        ):
            with self.subTest(url=url), self.assertRaises(VerificationError):
                _validate_url(url, allowed)

    def _archive(self, member: tarfile.TarInfo):
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            archive.addfile(member, io.BytesIO(b"binary") if member.isfile() else None)
        buffer.seek(0)
        return tarfile.open(fileobj=buffer, mode="r:gz")

    def test_archive_rejects_links_and_traversal(self):
        link = tarfile.TarInfo("pkg/link")
        link.type = tarfile.SYMTYPE
        link.linkname = "/etc/passwd"
        with self._archive(link) as archive, self.assertRaises(VerificationError):
            _safe_archive_member(archive, "pkg/link")
        traversal = tarfile.TarInfo("../sing-box")
        traversal.size = 6
        with self._archive(traversal) as archive, self.assertRaises(VerificationError):
            _safe_archive_member(archive, "../sing-box")

    def test_archive_reads_only_regular_selected_member(self):
        member = tarfile.TarInfo("pkg/sing-box")
        member.size = 6
        with self._archive(member) as archive:
            selected = _safe_archive_member(archive, "pkg/sing-box")
            self.assertEqual(archive.extractfile(selected).read(), b"binary")


class DDNSTests(unittest.TestCase):
    def test_duplicate_records_block_every_change(self):
        ddns = CloudflareDDNS(DDNSSettings(enabled=True, zone="example.com", record="vpn.example.com"), "test-token")
        calls = []
        ddns._records = lambda zone, kind: ([{"id": "1", "proxied": True}, {"id": "2", "proxied": True}] if kind == "A" else [])
        ddns._request = lambda *args, **kwargs: calls.append((args, kwargs))
        with self.assertRaises(ExternalCommandError):
            ddns._ensure_dns_only("zone")
        self.assertEqual(calls, [])

    def test_updates_are_dns_only_and_use_short_ttl(self):
        ddns = CloudflareDDNS(DDNSSettings(enabled=True, zone="example.com", record="vpn.example.com"), "test-token")
        records = {"A": [{"id": "a", "content": "1.1.1.1", "proxied": True, "ttl": 1}], "AAAA": []}
        writes = []

        def request(method, path, *, params=None, payload=None):
            if method == "PATCH":
                writes.append((method, payload))
                record_id = path.rsplit("/", 1)[-1]
                for items in records.values():
                    for record in items:
                        if record["id"] == record_id:
                            record.update(payload)
                return {}
            if method == "POST":
                writes.append((method, payload))
                records[payload["type"]].append({"id": "new", **payload})
                return {}
            raise AssertionError(method)

        ddns._request = request
        ddns._records = lambda zone, kind: records[kind]
        changes = ddns._ensure_dns_only("zone")
        changes.append(ddns._write_record("zone", "A", "8.8.8.8"))
        changes.append(ddns._write_record("zone", "AAAA", "2606:4700:4700::1111"))
        self.assertTrue(all(payload["proxied"] is False for method, payload in writes if "proxied" in payload))
        self.assertEqual(records["A"][0]["content"], "8.8.8.8")
        self.assertEqual(records["AAAA"][0]["ttl"], 120)

    def test_detect_address_requires_two_matching_sources(self):
        with patch("sbox5.ddns._read_response") as mock_read:
            # Endpoint 1 (ipify: raw IP), Endpoint 2 (icanhazip: fails), Endpoint 3 (cf trace: ip=...)
            # 端点 1（ipify：纯 IP），端点 2（icanhazip：失败），端点 3（cf trace：ip=...）
            mock_read.side_effect = [b"1.1.1.1\n", ExternalCommandError("timeout"), b"ip=1.1.1.1\n"]
            self.assertEqual(_detect_address(4), "1.1.1.1")

            # only 1 endpoint succeeds -> returns None (insufficient cross-confirmation)
            # 仅 1 个端点成功 -> 返回 None（交叉确认不足）
            mock_read.side_effect = [b"1.1.1.1\n", ExternalCommandError("fail"), ExternalCommandError("fail")]
            self.assertIsNone(_detect_address(4))

            # conflicting addresses -> raises ExternalCommandError
            # 地址冲突 -> 抛出 ExternalCommandError
            mock_read.side_effect = [b"1.1.1.1\n", b"1.0.0.1\n", b"ip=1.1.1.1\n"]
            with self.assertRaises(ExternalCommandError):
                _detect_address(4)


class FirewallTests(unittest.TestCase):
    def test_acme_port_and_iptables_rule_shape(self):
        configured = Settings(host="vpn.example.com", reality_target="www.example.com:443", reality_sni="www.example.com", certificate_mode="acme", domain="vpn.example.com", port_hopping={"hysteria2": "20000:21000"})
        configured.validate()
        self.assertIn(80, [item["port"] for item in required_ports(configured)])
        with patch("sbox5.firewall._iptables_executables", return_value=["iptables", "ip6tables"]):
            rules = _iptables_resources(configured)
        self.assertTrue(any(rule["table"] == "nat" and rule["ipv6"] for rule in rules))
        self.assertTrue(any(rule["kind"] == "iptables-chain" and rule["chain"] == "SBOX5-INPUT" for rule in rules))
        self.assertTrue(any(rule["kind"] == "iptables-jump" and rule["target"] == "SBOX5-PREROUTING" for rule in rules))
        self.assertFalse(any(rule.get("flush") for rule in rules))

    def test_manual_mode_records_only_owned_rule_removal(self):
        configured = Settings(host="198.51.100.20", reality_target="www.example.com:443", reality_sni="www.example.com", manage_firewall=False)
        configured.validate()
        previous = {"owned": [{"kind": "ufw-rule", "port": "18443", "protocol": "tcp", "name": "vless"}]}
        changes = []

        def fake_run(command, **kwargs):
            return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary) / "firewall.json"
            atomic_json(state, previous)
            with patch("sbox5.firewall.run", side_effect=fake_run), patch("sbox5.firewall._nft_table_exists", return_value=False):
                result = apply_firewall(configured, state, lambda resource, action: changes.append((resource, action)))
            self.assertEqual(result["owned"], [])
            self.assertEqual(changes[0][1], "remove")
            self.assertEqual(json.loads(state.read_text(encoding="utf-8"))["backend"], "manual")

    def test_iptables_apply_creates_isolated_chains_and_jumps(self):
        configured = Settings(
            host="198.51.100.20", reality_target="www.example.com:443", reality_sni="www.example.com",
            port_hopping={"tuic": "30000:31000"},
        )
        configured.validate()
        commands = []
        changes = []

        def fake_run(command, **kwargs):
            commands.append(command)
            return subprocess.CompletedProcess(command, 1 if "-C" in command else 0, stdout="", stderr="")

        with tempfile.TemporaryDirectory() as temporary:
            state = Path(temporary) / "firewall.json"
            with patch("sbox5.firewall.available", side_effect=lambda name: name == "iptables"), \
                    patch("sbox5.firewall._ufw_active", return_value=False), \
                    patch("sbox5.firewall._nft_table_exists", return_value=False), \
                    patch("sbox5.firewall._nat_available", return_value=True), \
                    patch("sbox5.firewall._chain_exists", return_value=False), \
                    patch("sbox5.firewall._iptables_executables", return_value=["iptables"]), \
                    patch("sbox5.firewall.run", side_effect=fake_run):
                result = apply_firewall(configured, state, lambda resource, action: changes.append((resource, action)))
        self.assertEqual(result["backend"], "iptables")
        self.assertTrue(any(command[:4] == ["iptables", "-t", "filter", "-N"] and command[4] == "SBOX5-INPUT" for command in commands))
        self.assertTrue(any(command[:4] == ["iptables", "-t", "nat", "-N"] and command[4] == "SBOX5-PREROUTING" for command in commands))
        self.assertTrue(any(command[:5] == ["iptables", "-t", "filter", "-I", "INPUT"] for command in commands))
        self.assertTrue(any(changes and resource["kind"] == "iptables-chain" for resource, action in changes))
        self.assertTrue(any(resource["kind"] == "iptables-jump" for resource, action in changes))


class SnapshotTests(unittest.TestCase):
    def test_prune_preserves_pre_restore_and_unknown_directories(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for name in ("20240101T000000Z-a", "20250101T000000Z-b", "20260101T000000Z-c"):
                path = root / name
                path.mkdir()
                (path / "manifest.json").write_text('{"state": "committed"}', encoding="utf-8")
            prepared = root / "20260102T000000Z-prepared"
            prepared.mkdir()
            (prepared / "manifest.json").write_text('{"state": "prepared"}', encoding="utf-8")
            (root / "pre-restore-20260101").mkdir()
            (root / "incomplete").mkdir()
            prune_snapshots(root, keep=2)
            self.assertFalse((root / "20240101T000000Z-a").exists())
            self.assertTrue(prepared.exists())
            self.assertTrue((root / "pre-restore-20260101").exists())
            self.assertTrue((root / "incomplete").exists())

    def test_new_file_is_hashed_into_manifest(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            snapshot_path = root / "snapshot"
            snapshot_path.mkdir()
            atomic_json(snapshot_path / "manifest.json", {"files": [], "operations": []})
            snapshot = Snapshot(snapshot_path)
            target = root / "new-file"
            target.write_text("content")
            snapshot.track_new(target)
            snapshot.record_after(target)
            snapshot.seal()
            sums = (snapshot_path / "SHA256SUMS").read_text()
            self.assertIn(sha256_file(target), snapshot.manifest["files"][0]["after"]["sha256"])
            self.assertIn("manifest.json", sums)


class RecoveryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location("sbox5_restore", ROOT / "recovery" / "restore.py")
        cls.restore = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.restore)

    def test_relative_path_rejects_traversal(self):
        for value in ("../escape", "/absolute", "payload\\..\\escape", "a\x00b"):
            with self.subTest(value=value), self.assertRaises(RuntimeError):
                self.restore.relative(value)

    def test_manifest_is_validated_before_destructive_actions(self):
        verified = {"manifest.json", "restore.py"}
        good = {"schema_version": 1, "files": [{"path": "/etc/passwd", "existed": False, "owned_by_project": True}]}
        with self.assertRaises(RuntimeError):
            self.restore.validate_manifest(good, verified)
        bad_kind = {"schema_version": 1, "firewall": {"owned": [{"kind": "route", "action": "add"}]}}
        with self.assertRaises(RuntimeError):
            self.restore.validate_manifest(bad_kind, verified)
        bad_user = {"schema_version": 1, "users_created": ["root"]}
        with self.assertRaises(RuntimeError):
            self.restore.validate_manifest(bad_user, verified)
        bad_sysctl = {"schema_version": 1, "sysctls": [{"key": "kernel.kptr_restrict", "before": "1"}]}
        with self.assertRaises(RuntimeError):
            self.restore.validate_manifest(bad_sysctl, verified)
        self.restore.validate_manifest({"schema_version": 1}, verified)
        self.restore.validate_manifest({
            "schema_version": 2,
            "services": [{"name": "sbox5.service", "backend": "systemd"}],
            "firewall": {"owned": [
                {"kind": "iptables-chain", "ipv6": False, "table": "nat", "chain": "SBOX5-PREROUTING", "action": "add"},
                {"kind": "iptables-jump", "ipv6": False, "table": "nat", "chain": "PREROUTING", "target": "SBOX5-PREROUTING", "spec": ["-j", "SBOX5-PREROUTING"], "action": "add"},
            ]},
        }, verified)

    def test_drift_detection_and_uninstall_absence(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "file"
            path.write_text("current")
            digest = self.restore.sha256(path)
            manifest = {"files": [{"path": str(path), "after": {"sha256": digest}, "existed": True}], "firewall": {"owned": []}}
            self.assertEqual(self.restore.find_conflicts(manifest, Path(temporary)), [])
            path.write_text("changed")
            self.assertTrue(self.restore.find_conflicts(manifest, Path(temporary)))
            path.unlink()
            manifest["files"][0]["removing"] = True
            self.assertEqual(self.restore.find_conflicts(manifest, Path(temporary)), [])

    def test_automatic_rollback_ignores_transaction_drift_but_not_symlinks(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            path = root / "file"
            path.write_text("transaction wrote this")
            manifest = {"state": "prepared", "files": [{"path": str(path), "existed": False, "owned_by_project": True, "after": None}], "firewall": {"owned": []}}
            self.assertTrue(self.restore.find_conflicts(manifest, root))
            self.assertEqual(self.restore.find_conflicts(manifest, root, structural_only=True), [])
            directory = root / "unexpected-directory"
            directory.mkdir()
            manifest["files"].append({"path": str(directory), "existed": False, "owned_by_project": True, "after": None})
            self.assertTrue(self.restore.find_conflicts(manifest, root, structural_only=True))


class LockTests(unittest.TestCase):
    def test_lock_assets_match_runtime_architecture_names(self):
        for component in ("sing-box", "cloudflared"):
            lock = json.loads((ROOT / "locks" / f"{component}.json").read_text(encoding="utf-8"))
            self.assertEqual(set(lock["assets"]), {"amd64", "arm64"})
            for asset in lock["assets"].values():
                self.assertTrue(asset["url"].startswith("https://"))
                self.assertGreater(asset["size"], 0)
                self.assertRegex(asset["sha256"], r"^[0-9a-f]{64}$")


class CommandTests(unittest.TestCase):
    def test_internal_systemd_commands_accept_non_interactive(self):
        parser = build_parser()
        for command in ("ddns-update", "firewall-apply"):
            args = parser.parse_args([command, "--non-interactive"])
            self.assertTrue(args.non_interactive)

    def test_port_and_protocol_commands_parse(self):
        parser = build_parser()
        port = parser.parse_args(["port", "set", "--protocol", "tuic", "--port", "20000", "--yes"])
        self.assertEqual((port.command, port.port_command, port.protocol, port.port), ("port", "set", "tuic", 20000))
        hopping = parser.parse_args([
            "port", "hopping", "set", "--protocol", "tuic", "--range", "30000:31000", "--yes",
        ])
        self.assertEqual((hopping.hopping_command, hopping.range), ("set", "30000:31000"))
        protocol = parser.parse_args(["protocol", "set", "vmess", "--tls-profile", "none", "--yes"])
        self.assertEqual((protocol.protocol_command, protocol.name, protocol.tls_profile), ("set", "vmess", "none"))
        cert = parser.parse_args([
            "cert", "add", "--id", "edge", "--mode", "acme", "--domain", "edge.example.com",
            "--bind-protocol", "hysteria2", "--yes",
        ])
        self.assertEqual((cert.cert_command, cert.id, cert.mode, cert.domain, cert.bind_protocol),
                         ("add", "edge", "acme", ["edge.example.com"], "hysteria2"))
        bind = parser.parse_args(["cert", "bind", "--protocol", "vmess", "--profile", "none", "--yes"])
        self.assertEqual((bind.cert_command, bind.protocol, bind.profile), ("bind", "vmess", "none"))

    def test_units_use_non_root_core_and_token_files(self):
        configured = Settings(host="198.51.100.20", reality_target="www.example.com:443", reality_sni="www.example.com")
        configured.validate()
        unit = singbox_unit(configured)
        self.assertIn("User=sbox5", unit)
        self.assertNotIn("AmbientCapabilities=CAP_NET_BIND_SERVICE", unit)
        self.assertIn("--token-file /etc/sbox5/secrets/argo.token", argo_unit())

    def test_native_acme_requires_low_port_capability(self):
        configured = Settings(
            host="198.51.100.20", reality_target="www.example.com:443",
            reality_sni="www.example.com", certificate_mode="acme", domain="example.com",
        )
        configured.validate()
        unit = singbox_unit(configured)
        self.assertIn("AmbientCapabilities=CAP_NET_BIND_SERVICE", unit)
        self.assertIn("ReadWritePaths=/var/lib/sbox5-runtime /run/sbox5-runtime /var/lib/sbox5/acme", unit)


if __name__ == "__main__":
    unittest.main()
