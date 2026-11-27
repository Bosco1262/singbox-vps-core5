# Copyright (C) 2026 Bosco1262
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from sbox5 import network
from sbox5.cli import _select_ports, build_parser
from sbox5.errors import ConfigError, ConflictError
from sbox5.export import build_share_links
from sbox5.firewall import apply_firewall
from sbox5.installer import _fresh_install_conflicts
from sbox5.models import Ports, Secrets, Settings
from sbox5.services import (
    openrc_argo,
    openrc_ddns,
    openrc_firewall,
    openrc_name,
    openrc_singbox,
    openrc_subscription,
)
from sbox5.snapshot import _service_state
from sbox5.system import _check_virtualization, _family, _version_numbers
from sbox5.util import random_free_port


def settings(**changes) -> Settings:
    values = dict(host="198.51.100.20", reality_target="www.example.com:443", reality_sni="www.example.com")
    values.update(changes)
    result = Settings(**values)
    result.validate()
    return result


def secrets() -> Secrets:
    result = Secrets()
    result.reality_private_key = "private"
    result.reality_public_key = "public"
    result.validate()
    return result


class OutputFamilyTests(unittest.TestCase):
    def test_geolocation_uses_https_and_returns_selected_fields(self):
        class Response:
            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def read(self, limit):
                return b'{"city":"Mountain View","region":"California","country":"US","org":"AS15169 Google"}'

        with mock.patch("sbox5.network.urllib.request.urlopen", return_value=Response()) as urlopen:
            data = network.geolocation("8.8.8.8")
        self.assertEqual((data["city"], data["country"]), ("Mountain View", "US"))
        self.assertIn("https://ipinfo.io/8.8.8.8/json", urlopen.call_args.args[0].full_url)
        self.assertEqual(network.geolocation("127.0.0.1"), {})

    def test_global_addresses_are_parsed_and_filtered(self):
        def fake_run(command, **kwargs):
            if command[1] == "-4":
                stdout = "2: eth0 inet 8.8.8.8/32 scope global eth0\n3: lo inet 127.0.0.1/8 scope host lo\n"
            else:
                stdout = "2: eth0 inet6 2001:4860:4860::8888/128 scope global dynamic\n3: lo inet6 ::1/128 scope host\n"
            return subprocess.CompletedProcess(command, 0, stdout, "")
        with mock.patch.object(network, "run", side_effect=fake_run):
            addresses = network.global_addresses()
        self.assertEqual(addresses[4], ["8.8.8.8"])
        self.assertEqual(addresses[6], ["2001:4860:4860::8888"])

    def test_effective_settings_and_links_use_selected_family(self):
        configured = settings(output_family="ipv4")
        with mock.patch.object(network, "run", return_value=subprocess.CompletedProcess([], 0, "inet 8.8.8.8/32 scope global eth0\n", "")):
            effective = network.effective_settings(configured)
            link = build_share_links(configured, secrets(), {
                "certificate_sha256": "x", "public_key_sha256": "y",
                "file_sha256": "z", "certificate_fingerprint": "",
            })["vless"]
        self.assertEqual(effective.host, "8.8.8.8")
        self.assertIn("@8.8.8.8:", link)

    def test_missing_selected_family_is_explicit(self):
        configured = settings(output_family="ipv6")
        with mock.patch.object(network, "run", return_value=subprocess.CompletedProcess([], 0, "", "")):
            with self.assertRaises(Exception):
                network.effective_settings(configured)

    def test_output_family_validation(self):
        with self.assertRaises(Exception):
            settings(output_family="ipv5")


class OpenRCTests(unittest.TestCase):
    def test_name_mapping(self):
        self.assertEqual(openrc_name("sbox5.service"), "sbox5")
        self.assertEqual(openrc_name("sbox5-ddns.timer"), "sbox5-ddns")
        self.assertEqual(openrc_name("sbox5-firewall.service"), "sbox5-firewall")

    def test_low_port_uses_file_capability(self):
        configured = settings(ports=Ports(hysteria2=443))
        unit = openrc_singbox(configured)
        self.assertIn('command_user="sbox5:sbox5"', unit)
        self.assertIn("setcap cap_net_bind_service=+ep", unit)

    def test_high_port_does_not_grant_capability(self):
        configured = settings(ports=Ports(hysteria2=8443))
        unit = openrc_singbox(configured)
        self.assertNotIn("setcap", unit)

    def test_snapshot_uses_openrc_service_names(self):
        with mock.patch("sbox5.services.init_backend", return_value="openrc"), \
             mock.patch("sbox5.services.service_exists", return_value=True), \
             mock.patch("sbox5.services.service_active", return_value=True), \
             mock.patch("sbox5.services.service_enabled", return_value=True):
            state = _service_state("sbox5.service")
        self.assertEqual(state["backend"], "openrc")
        self.assertEqual(state["name"], "sbox5")

    def test_openrc_services_are_non_root(self):
        configured = settings()
        self.assertIn('command_user="sbox5-argo:sbox5-argo"', openrc_argo(configured))
        self.assertIn('command_user="sbox5-ddns:sbox5-ddns"', openrc_ddns())
        self.assertIn('command_user="sbox5-sub:sbox5-sub"', openrc_subscription())
        self.assertIn("firewall-apply", openrc_firewall())


class PlatformTests(unittest.TestCase):
    def test_distribution_families(self):
        self.assertEqual(_family({"ID": "debian"}), "debian")
        self.assertEqual(_family({"ID": "ubuntu"}), "debian")
        self.assertEqual(_family({"ID": "alpine"}), "alpine")
        self.assertEqual(_family({"ID": "rocky", "ID_LIKE": "rhel centos fedora"}), "rhel")
        self.assertEqual(_family({"ID": "custom"}), "")

    def test_versions(self):
        self.assertEqual(_version_numbers("3.20.3"), (3, 20, 3))
        self.assertEqual(_version_numbers("22.04"), (22, 4))

    def test_virtualization_allows_google_and_rejects_containers(self):
        google = subprocess.CompletedProcess([], 0, "google\n", "")
        with mock.patch("sbox5.system.available", return_value=True), \
             mock.patch("sbox5.system.run", side_effect=[google, google]):
            _check_virtualization()
        with mock.patch("sbox5.system.available", return_value=True), \
             mock.patch("sbox5.system.run", return_value=subprocess.CompletedProcess([], 0, "docker\n", "")):
            with self.assertRaises(ConfigError):
                _check_virtualization()

    def test_cli_phase4_commands_parse(self):
        parser = build_parser()
        self.assertEqual(parser.parse_args(["ip", "show"]).ip_command, "show")
        self.assertEqual(parser.parse_args(["ip", "set", "--family", "ipv4", "--yes"]).family, "ipv4")
        self.assertEqual(parser.parse_args(["logs", "--service", "argo", "--follow"]).service, "argo")
        self.assertEqual(parser.parse_args(["doctor", "--json"]).json, True)
        self.assertEqual(parser.parse_args(["menu"]).command, "menu")


class RandomPortTests(unittest.TestCase):
    def test_random_free_port_skips_excluded_and_occupied_ports(self):
        with mock.patch("sbox5.util.secrets.randbelow", side_effect=[1, 2, 3]), \
             mock.patch("sbox5.util.port_is_free", side_effect=[True, False, True, True]):
            self.assertEqual(random_free_port({10001}), 10003)

    def test_fresh_install_randomizes_unspecified_ports(self):
        args = build_parser().parse_args(["install"])
        with mock.patch("sbox5.cli.random_free_port", side_effect=[20101, 20102, 20103, 20104, 20105]):
            ports = _select_ports(args, None, {}, False)
        self.assertEqual(ports.as_dict(), {
            "vless": 20101, "vmess": 20102, "hysteria2": 20103, "tuic": 20104, "anytls": 20105,
        })

    def test_explicit_ports_and_reserved_ranges_are_avoided(self):
        args = build_parser().parse_args(["install", "--vless-port", "12345"])
        with mock.patch("sbox5.cli.random_free_port", side_effect=[20102, 20103, 20104, 20105]) as picker:
            ports = _select_ports(args, None, {"hysteria2": "30000:30010"}, True)
        self.assertEqual(ports.vless, 12345)
        for call in picker.call_args_list:
            reserved = call.args[0]
            self.assertIn(12345, reserved)
            self.assertIn(18081, reserved)
            self.assertTrue(set(range(30000, 30011)) <= reserved)

    def test_upgrade_keeps_existing_ports(self):
        previous = settings(ports=Ports(vless=20001, vmess=20002, hysteria2=20003, tuic=20004, anytls=20005))
        args = build_parser().parse_args(["upgrade"])
        with mock.patch("sbox5.cli.random_free_port") as picker:
            ports = _select_ports(args, previous, {}, False)
        picker.assert_not_called()
        self.assertEqual(ports.as_dict(), previous.ports.as_dict())


class FirewalldTests(unittest.TestCase):
    def test_active_firewalld_is_not_modified(self):
        configured = settings()
        with mock.patch("sbox5.firewall._firewalld_active", return_value=True):
            with self.assertRaises(ConflictError):
                apply_firewall(configured)


class FreshInstallTests(unittest.TestCase):
    def test_rollback_snapshots_do_not_block_fresh_install(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            state = root / "var/lib/sbox5"
            (state / "snapshots").mkdir(parents=True)
            with mock.patch("sbox5.installer.STATE_DIR", state), \
                 mock.patch("sbox5.installer.CONFIG_DIR", root / "etc/sbox5"), \
                 mock.patch("sbox5.installer.SYSCTL_PATH", root / "etc/sysctl.d/99-sbox5.conf"), \
                 mock.patch("sbox5.installer.UNIT_DIR", root / "etc/systemd/system"), \
                 mock.patch("sbox5.installer.service_path", side_effect=lambda name: root / "units" / name):
                self.assertEqual(_fresh_install_conflicts(), [])
                (state / "state.json").write_text("{}", encoding="utf-8")
                conflicts = _fresh_install_conflicts()
                self.assertIn(state / "state.json", conflicts)


class RestoreAllowlistTests(unittest.TestCase):
    def test_openrc_init_scripts_are_allowed(self):
        path = ROOT / "recovery" / "restore.py"
        spec = importlib.util.spec_from_file_location("sbox5_restore_test", path)
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(module)
        from pathlib import PurePosixPath
        self.assertTrue(module._allowed_target(PurePosixPath("/etc/init.d/sbox5")))
        self.assertFalse(module._allowed_target(PurePosixPath("/etc/init.d/other")))
        self.assertTrue(module._allowed_directory(PurePosixPath("/var/log/sbox5")))


if __name__ == "__main__":
    unittest.main()
