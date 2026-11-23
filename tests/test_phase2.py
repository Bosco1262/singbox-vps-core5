# Copyright (C) 2026 Bosco1262
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import base64
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from sbox5.argo import quick_url_from_log
from sbox5.cli import build_parser
from sbox5 import cli as cli_module
from sbox5.config import build_server_config
from sbox5.errors import ConfigError
from sbox5.export import build_share_links
from sbox5.kernel import _lock_for_version, catalog, parse_version
from sbox5.models import (
    ArgoSettings,
    DomainRoute,
    ProtocolSettings,
    RuleSetSettings,
    Secrets,
    Settings,
    Socks5Settings,
    WarpCredential,
    WarpSettings,
)
from sbox5.services import argo_unit
from sbox5.warp import register_warp

KEY = base64.b64encode(bytes(range(32))).decode()


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


def warp_credential() -> WarpCredential:
    credential = WarpCredential(
        private_key=KEY,
        public_key=KEY,
        peer_public_key=KEY,
        addresses=["172.16.0.2/32", "2606:4700:110::2/128"],
        reserved=[1, 2, 3],
        peer_address="engage.cloudflareclient.com",
        peer_port=2408,
    )
    credential.validate()
    return credential


class ArgoTests(unittest.TestCase):
    def test_quick_url_is_extracted_from_log(self):
        with tempfile.TemporaryDirectory() as temporary:
            log = Path(temporary) / "quick.log"
            log.write_text("noise\nhttps://example-test.trycloudflare.com\n", encoding="utf-8")
            self.assertEqual(quick_url_from_log(log), "https://example-test.trycloudflare.com")

    def test_argo_loopback_inbound_is_plaintext_and_local(self):
        configured = settings(argo=ArgoSettings(enabled=True, mode="token", hostname="argo.example.com"))
        document = build_server_config(configured, secrets())
        inbounds = {item["tag"]: item for item in document["inbounds"]}
        self.assertEqual(inbounds["vmess-argo-origin"]["listen"], "127.0.0.1")
        self.assertEqual(inbounds["vmess-argo-origin"]["listen_port"], 18081)
        self.assertNotIn("tls", inbounds["vmess-argo-origin"])

    def test_quick_and_token_units(self):
        quick = settings(argo=ArgoSettings(enabled=True, mode="quick", local_port=18082))
        quick_unit = argo_unit(quick)
        self.assertIn("--url http://127.0.0.1:18082", quick_unit)
        self.assertIn("append:/var/lib/sbox5/argo/quick.log", quick_unit)
        token = settings(argo=ArgoSettings(enabled=True, mode="token", hostname="argo.example.com"))
        self.assertIn("--token-file /etc/sbox5/secrets/argo.token", argo_unit(token))

    def test_quick_tunnel_host_is_exported(self):
        configured = settings(argo=ArgoSettings(enabled=True, mode="quick"))
        links = build_share_links(
            configured, secrets(), {"certificate_sha256": "test"},
            {"default": {"certificate_sha256": "test"}}, "random-test.trycloudflare.com",
        )
        decoded = json.loads(base64.b64decode(links["vmess-argo"][8:]).decode())
        self.assertEqual(decoded["add"], "random-test.trycloudflare.com")
        self.assertEqual(decoded["sni"], "random-test.trycloudflare.com")

    def test_argo_local_port_conflicts_are_rejected(self):
        with self.assertRaises(ConfigError):
            settings(argo=ArgoSettings(enabled=True, mode="quick", local_port=18443))
        with self.assertRaises(ConfigError):
            settings(argo=ArgoSettings(enabled=True, mode="token", hostname="argo.example.com", local_port=80))


class WarpTests(unittest.TestCase):
    def test_warp_endpoint_is_generated_without_shared_keys(self):
        configured = settings(warp=WarpSettings(enabled=True))
        secret = secrets()
        secret.warp = warp_credential()
        document = build_server_config(configured, secret)
        endpoint = document["endpoints"][0]
        self.assertEqual(endpoint["type"], "wireguard")
        self.assertEqual(endpoint["tag"], "warp")
        self.assertEqual(endpoint["private_key"], KEY)
        self.assertEqual(endpoint["peers"][0]["public_key"], KEY)
        self.assertEqual(endpoint["peers"][0]["reserved"], [1, 2, 3])
        self.assertEqual(endpoint["peers"][0]["allowed_ips"], ["0.0.0.0/0", "::/0"])

    def test_warp_requires_credentials(self):
        configured = settings(warp=WarpSettings(enabled=True))
        with self.assertRaises(ConfigError):
            build_server_config(configured, secrets())

    def test_warp_registration_response_is_parsed(self):
        client_id = base64.b64encode(b"\x01\x02\x03").decode()
        response = {
            "config": {
                "client_id": client_id,
                "interface": {"addresses": {"v4": "172.16.0.2", "v6": "2606:4700:110::2"}},
                "peers": [{
                    "public_key": KEY,
                    "endpoint": {"host": "engage.cloudflareclient.com", "ports": [2408]},
                }],
            },
        }
        with patch("sbox5.warp.generate_wireguard_keypair", return_value=(KEY, KEY)), \
                patch("sbox5.warp._request_registration", return_value=response):
            credential = register_warp(Path("/nonexistent/sing-box"))
        self.assertEqual(credential.addresses, ["172.16.0.2/32", "2606:4700:110::2/128"])
        self.assertEqual(credential.reserved, [1, 2, 3])
        self.assertEqual(credential.peer_public_key, KEY)
        self.assertTrue(credential.configured)


class RoutingTests(unittest.TestCase):
    def test_domain_routes_socks5_and_rulesets(self):
        configured = settings(
            warp=WarpSettings(enabled=True),
            routing={
                "routes": [
                    {"target": "warp", "suffixes": [".openai.com"]},
                    {"target": "direct-v4", "suffixes": [".example.cn"]},
                ],
                "socks5": {"enabled": True, "server": "127.0.0.1", "port": 1080, "username": "user"},
                "rule_sets": [{
                    "tag": "cn",
                    "filename": "cn.srs",
                    "sha256": "a" * 64,
                    "target": "direct-v4",
                }],
            },
        )
        secret = secrets()
        secret.warp = warp_credential()
        secret.socks5_password = "password"
        document = build_server_config(configured, secret)
        outbounds = {item["tag"]: item for item in document["outbounds"]}
        self.assertEqual(outbounds["socks5"]["type"], "socks")
        self.assertEqual(outbounds["socks5"]["username"], "user")
        self.assertEqual(outbounds["direct-v4"]["domain_resolver"]["strategy"], "ipv4_only")
        rules = document["route"]["rules"]
        self.assertEqual(rules[0], {"action": "sniff"})
        self.assertIn({"domain_suffix": [".openai.com"], "action": "route", "outbound": "warp"}, rules)
        self.assertIn({"rule_set": ["cn"], "action": "route", "outbound": "direct-v4"}, rules)
        self.assertEqual(document["route"]["rule_set"][0]["type"], "local")
        self.assertEqual(document["dns"]["servers"][0]["type"], "local")

    def test_route_target_unavailable_is_rejected(self):
        with self.assertRaises(ConfigError):
            settings(routing={"routes": [{"target": "warp", "suffixes": [".example.com"]}]})

    def test_socks5_username_requires_password(self):
        configured = settings(routing={
            "socks5": {"enabled": True, "server": "127.0.0.1", "port": 1080, "username": "user"},
        })
        with self.assertRaises(ConfigError):
            build_server_config(configured, secrets())

    def test_invalid_ruleset_url_is_rejected(self):
        with self.assertRaises(ConfigError):
            settings(routing={
                "rule_sets": [{
                    "tag": "bad",
                    "filename": "bad.srs",
                    "sha256": "a" * 64,
                    "target": "direct",
                    "source_url": "https://evil.example/bad.srs",
                }],
            })


class KernelTests(unittest.TestCase):
    def test_version_parsing_and_catalog(self):
        self.assertEqual(parse_version("sing-box version 1.14.4"), "1.14.4")
        data = catalog(ROOT)
        self.assertEqual(data["channels"]["stable"], "1.14.4")
        self.assertIn("1.14.4", data["versions"])
        self.assertEqual(_lock_for_version(ROOT, "1.14.4"), ROOT / "locks" / "sing-box.json")
        with self.assertRaises(ConfigError):
            _lock_for_version(ROOT, "9.9.9")


class Phase2CommandTests(unittest.TestCase):
    def test_command_handlers_exist(self):
        for name in ("_certificate", "_argo", "_warp", "_route", "_core", "_cdn", "_subscription"):
            self.assertTrue(callable(getattr(cli_module, name, None)), name)

    def test_new_commands_parse(self):
        parser = build_parser()
        argo = parser.parse_args(["argo", "set", "--mode", "quick", "--local-port", "18082", "--yes"])
        self.assertEqual((argo.argo_command, argo.mode, argo.local_port), ("set", "quick", 18082))
        warp = parser.parse_args(["warp", "import", "--private-key-file", "key", "--peer-public-key", KEY,
                                   "--address", "172.16.0.2/32", "--address", "2606:4700:110::2/128"])
        self.assertEqual((warp.warp_command, len(warp.address)), ("import", 2))
        route = parser.parse_args(["route", "add", "--target", "warp", "--suffix", ".openai.com", "--yes"])
        self.assertEqual((route.route_command, route.target, route.suffix), ("add", "warp", [".openai.com"]))
        ruleset = parser.parse_args([
            "route", "ruleset", "add", "--tag", "cn", "--target", "direct", "--sha256", "a" * 64,
            "--file", "cn.srs", "--yes",
        ])
        self.assertEqual((ruleset.ruleset_command, ruleset.tag), ("add", "cn"))
        core = parser.parse_args(["core", "switch", "--channel", "stable", "--yes"])
        self.assertEqual((core.core_command, core.channel), ("switch", "stable"))
        cdn = parser.parse_args(["cdn", "set", "--target", "vmess", "--address", "104.16.0.1", "--host", "cdn.example.com", "--yes"])
        self.assertEqual((cdn.cdn_command, cdn.target), ("set", "vmess"))
        subscription = parser.parse_args(["subscription", "set", "--bind", "127.0.0.1", "--port", "18090", "--yes"])
        self.assertEqual((subscription.subscription_command, subscription.port), ("set", 18090))
        serve = parser.parse_args(["subscription-serve", "--non-interactive"])
        self.assertTrue(serve.non_interactive)


if __name__ == "__main__":
    unittest.main()
