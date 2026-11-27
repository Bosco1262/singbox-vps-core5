# Copyright (C) 2026 Bosco1262
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import argparse
import io
from contextlib import redirect_stdout
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from sbox5 import network
from sbox5.cli import (
    _bbr,
    _core_text,
    _prompt_default,
    _reality,
    _route_text,
    _secrets,
    _self_update,
    _service,
    _status,
    build_parser,
)
from sbox5.errors import ConfigError
from sbox5.models import Secrets, Settings


def settings(**changes) -> Settings:
    values = dict(host="198.51.100.20", reality_target="www.example.com:443", reality_sni="www.example.com")
    values.update(changes)
    result = Settings(**values)
    result.validate()
    return result


def completed(stdout: str = "") -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess([], 0, stdout, "")


class SecretsRotateTests(unittest.TestCase):
    def test_rotate_all_changes_every_credential(self):
        before = Secrets()
        after = Secrets.from_dict(before.as_dict())
        after.rotate("all")
        after.validate()
        for name in (
            "vless_uuid", "vmess_uuid", "tuic_uuid", "hysteria2_password",
            "hysteria2_obfs_password", "tuic_password", "anytls_password",
            "vmess_path", "reality_short_id",
        ):
            self.assertNotEqual(getattr(after, name), getattr(before, name), name)

    def test_rotate_one_protocol_preserves_the_others(self):
        before = Secrets()
        after = Secrets.from_dict(before.as_dict())
        after.rotate("vmess")
        after.validate()
        self.assertNotEqual(after.vmess_uuid, before.vmess_uuid)
        self.assertNotEqual(after.vmess_path, before.vmess_path)
        self.assertEqual(after.vless_uuid, before.vless_uuid)
        self.assertEqual(after.tuic_uuid, before.tuic_uuid)
        self.assertEqual(after.hysteria2_password, before.hysteria2_password)
        self.assertEqual(after.anytls_password, before.anytls_password)

    def test_unknown_scope_is_rejected(self):
        with self.assertRaises(ConfigError):
            Secrets().rotate("unknown")


class ParserTests(unittest.TestCase):
    def test_console_commands_parse(self):
        parser = build_parser()
        self.assertTrue(parser.parse_args(["status", "--text"]).text)
        self.assertEqual(parser.parse_args(["service", "restart", "--service", "argo"]).service, "argo")
        self.assertEqual(parser.parse_args(["bbr", "enable", "--yes"]).bbr_command, "enable")
        reality = parser.parse_args(["reality", "set", "--target", "www.example.com:443"])
        self.assertEqual(reality.target, "www.example.com:443")
        self.assertEqual(parser.parse_args(["secrets", "rotate", "--protocol", "vmess"]).protocol, "vmess")
        self.assertTrue(parser.parse_args(["self-update", "--yes"]).yes)
        self.assertTrue(parser.parse_args(["route", "list", "--text"]).text)
        self.assertTrue(parser.parse_args(["core", "list", "--text"]).text)


class HandlerTests(unittest.TestCase):
    def test_service_restart_uses_the_unit_and_checks_active(self):
        args = build_parser().parse_args(["service", "restart", "--service", "argo"])
        with mock.patch("sbox5.cli.require_linux_root"), \
             mock.patch("sbox5.cli.service_exists", return_value=True), \
             mock.patch("sbox5.cli.service_restart") as restart, \
             mock.patch("sbox5.cli.require_active") as active, \
             redirect_stdout(io.StringIO()):
            self.assertEqual(_service(args), 0)
        restart.assert_called_once_with("sbox5-argo.service")
        active.assert_called_once_with("sbox5-argo.service")

    def test_service_status_prints_state(self):
        args = build_parser().parse_args(["service", "status", "--service", "core"])
        output = io.StringIO()
        with mock.patch("sbox5.cli.require_linux_root"), \
             mock.patch("sbox5.cli.service_exists", return_value=True), \
             mock.patch("sbox5.cli.service_state_text", return_value="active"), \
             mock.patch("sbox5.cli.service_enabled", return_value=True), \
             redirect_stdout(output):
            self.assertEqual(_service(args), 0)
        self.assertIn("sbox5.service: active enabled=True", output.getvalue())

    def test_bbr_enable_sets_the_flag_and_reconfigures(self):
        configured = settings()
        args = build_parser().parse_args(["bbr", "enable", "--yes"])
        with mock.patch("sbox5.cli.require_linux_root"), \
             mock.patch("sbox5.cli.load_settings", return_value=configured), \
             mock.patch("sbox5.cli.load_secrets", return_value=Secrets()), \
             mock.patch("sbox5.cli._apply_reconfigure", return_value=0) as apply:
            self.assertEqual(_bbr(args), 0)
        self.assertTrue(configured.bbr)
        self.assertEqual(apply.call_args.args[3], "bbr")

    def test_reality_set_derives_sni_and_normalizes(self):
        configured = settings()
        args = build_parser().parse_args(["reality", "set", "--target", "[2606:4700:4700::1111]:443"])
        with mock.patch("sbox5.cli.require_linux_root"), \
             mock.patch("sbox5.cli.load_settings", return_value=configured), \
             mock.patch("sbox5.cli.load_secrets", return_value=Secrets()), \
             mock.patch("sbox5.cli._apply_reconfigure", return_value=0) as apply:
            self.assertEqual(_reality(args), 0)
        configured.validate()
        self.assertEqual(configured.reality_target, "[2606:4700:4700::1111]:443")
        self.assertEqual(configured.reality_sni, "2606:4700:4700::1111")
        self.assertEqual(apply.call_args.args[3], "reality")

    def test_secrets_rotate_updates_the_scope(self):
        configured = Secrets()
        original = configured.vless_uuid
        args = build_parser().parse_args(["secrets", "rotate", "--protocol", "vless", "--yes"])
        with mock.patch("sbox5.cli.require_linux_root"), \
             mock.patch("sbox5.cli.load_settings", return_value=settings()), \
             mock.patch("sbox5.cli.load_secrets", return_value=configured), \
             mock.patch("sbox5.cli._apply_reconfigure", return_value=0) as apply, \
             redirect_stdout(io.StringIO()):
            self.assertEqual(_secrets(args), 0)
        self.assertNotEqual(configured.vless_uuid, original)
        self.assertEqual(apply.call_args.args[3], "secrets")

    def test_status_text_renders_the_dashboard(self):
        args = build_parser().parse_args(["status", "--text", "--geo"])
        with mock.patch("sbox5.cli.require_linux_root"), \
             mock.patch("sbox5.cli.load_json", return_value={}), \
             mock.patch("sbox5.cli.load_settings", return_value=settings()), \
             mock.patch("sbox5.cli.load_secrets", return_value=Secrets()), \
             mock.patch("sbox5.cli.dashboard_status", return_value={"ok": True}) as status_data, \
             mock.patch("sbox5.cli.render_dashboard", return_value="dashboard") as render, \
             redirect_stdout(io.StringIO()):
            self.assertEqual(_status(args), 0)
        status_data.assert_called_once()
        self.assertTrue(status_data.call_args.kwargs["geo"])
        render.assert_called_once_with({"ok": True})


class SelfUpdateTests(unittest.TestCase):
    def _args(self, root: Path):
        args = build_parser().parse_args(["self-update", "--yes"])
        args.project_root = root
        return args

    def test_dirty_worktree_is_rejected(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            (root / ".git").mkdir()
            with mock.patch("sbox5.cli.require_linux_root"), \
                 mock.patch("sbox5.cli.available", return_value=True), \
                 mock.patch("sbox5.cli.run", return_value=completed(" M README.md\n")):
                with self.assertRaises(ConfigError):
                    _self_update(self._args(root))

    def test_untrusted_origin_is_rejected(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            (root / ".git").mkdir()
            with mock.patch("sbox5.cli.require_linux_root"), \
                 mock.patch("sbox5.cli.available", return_value=True), \
                 mock.patch("sbox5.cli.run", side_effect=[
                     completed(""), completed("https://example.com/repo.git\n"),
                 ]):
                with self.assertRaises(ConfigError):
                    _self_update(self._args(root))

    def test_missing_git_checkout_is_rejected(self):
        with tempfile.TemporaryDirectory() as raw:
            with mock.patch("sbox5.cli.require_linux_root"):
                with self.assertRaises(ConfigError):
                    _self_update(self._args(Path(raw)))

    def test_trusted_origin_fast_forwards_and_reports_head(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            (root / ".git").mkdir()
            with mock.patch("sbox5.cli.require_linux_root"), \
                 mock.patch("sbox5.cli.available", return_value=True), \
                 mock.patch("sbox5.cli._confirm") as confirm, \
                 mock.patch("sbox5.cli.run", side_effect=[
                     completed(""), completed("https://github.com/Bosco1262/singbox-vps-core5.git\n"),
                     completed("main\n"), completed(""), completed(""), completed("abc1234\n"),
                 ]) as run, \
                 redirect_stdout(io.StringIO()):
                self.assertEqual(_self_update(self._args(root)), 0)
        confirm.assert_called_once()
        merge = run.call_args_list[4].args[0]
        self.assertIn("merge", merge)
        self.assertIn("--ff-only", merge)
        self.assertIn("origin/main", merge)
        self.assertEqual(run.call_args_list[3].kwargs["env"]["GIT_TERMINAL_PROMPT"], "0")

    def test_detached_checkout_is_rejected(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            (root / ".git").mkdir()
            with mock.patch("sbox5.cli.require_linux_root"), \
                 mock.patch("sbox5.cli.available", return_value=True), \
                 mock.patch("sbox5.cli.run", side_effect=[
                     completed(""), completed("https://github.com/Bosco1262/singbox-vps-core5\n"),
                     completed("\n"),
                 ]):
                with self.assertRaises(ConfigError):
                    _self_update(self._args(root))


class TextOutputTests(unittest.TestCase):
    def test_route_text_lists_targets_routes_and_socks5(self):
        text = _route_text({
            "targets": ["direct", "warp"],
            "routes": [{"target": "warp", "suffixes": [".openai.com"]}],
            "rule_sets": [{"tag": "cn", "target": "direct", "filename": "cn.srs"}],
            "socks5": {"enabled": True, "server": "127.0.0.1", "port": 1080},
        })
        self.assertIn("warp: .openai.com", text)
        self.assertIn("cn -> direct (cn.srs)", text)
        self.assertIn("127.0.0.1:1080", text)

    def test_core_text_lists_channels_and_versions(self):
        text = _core_text({
            "current": "1.14.4",
            "catalog": {
                "channels": {"stable": "1.14.4"},
                "versions": {"1.14.4": {"channel": "stable", "lock": "locks/sing-box.json"}},
            },
        })
        self.assertIn("1.14.4", text)
        self.assertIn("stable", text)
        self.assertIn("locks/sing-box.json", text)


class PreferredHostTests(unittest.TestCase):
    def test_prefers_ipv4_then_ipv6(self):
        with mock.patch("sbox5.network.global_addresses", return_value={4: ["1.2.3.4"], 6: ["2001:db8::1"]}):
            self.assertEqual(network.preferred_host(), "1.2.3.4")
        with mock.patch("sbox5.network.global_addresses", return_value={4: [], 6: ["2001:db8::1"]}):
            self.assertEqual(network.preferred_host(), "2001:db8::1")
        with mock.patch("sbox5.network.global_addresses", return_value={4: [], 6: []}):
            self.assertEqual(network.preferred_host(), "")


class PromptDefaultTests(unittest.TestCase):
    def test_non_interactive_uses_the_default(self):
        args = argparse.Namespace(non_interactive=True)
        self.assertEqual(_prompt_default("", "1.2.3.4", "host", args), "1.2.3.4")
        with self.assertRaises(ConfigError):
            _prompt_default("", "", "host", args)


if __name__ == "__main__":
    unittest.main()
