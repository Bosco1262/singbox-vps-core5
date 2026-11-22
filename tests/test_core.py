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
from urllib.parse import parse_qs, urlsplit

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from sbox5.config import build_server_config
from sbox5.errors import ConfigError
from sbox5.export import build_mihomo, build_share_links, build_singbox_client, export_nodes, yaml_dump
from sbox5.models import ArgoSettings, DDNSSettings, Secrets, Settings
from sbox5.util import format_host_port, normalize_host, split_host_port


def settings(**changes):
    values = dict(host="198.51.100.20", reality_target="[2606:4700:4700::1111]:443", reality_sni="www.example.com")
    values.update(changes)
    result = Settings(**values)
    result.validate()
    return result


def secrets():
    result = Secrets()
    result.reality_private_key = "private-test-key"
    result.reality_public_key = "public-test-key"
    result.validate()
    return result


def certificate():
    digest = bytes(range(32))
    return {
        "certificate_sha256": base64.b64encode(digest).decode(),
        "public_key_sha256": base64.b64encode(digest).decode(),
        "certificate_fingerprint": ":".join(f"{value:02X}" for value in digest),
        "file_sha256": "0" * 64,
    }


class ModelTests(unittest.TestCase):
    def test_ipv6_host_and_reality_target(self):
        self.assertEqual(normalize_host("2001:4860:4860::8888"), "2001:4860:4860::8888")
        configured = settings(host="2001:4860:4860::8888")
        self.assertEqual(configured.reality_target, "[2606:4700:4700::1111]:443")
        self.assertEqual(split_host_port(configured.reality_target), ("2606:4700:4700::1111", 443))
        self.assertEqual(format_host_port(configured.host, 443), "[2001:4860:4860::8888]:443")

    def test_protocol_credentials_are_independent(self):
        value = secrets()
        self.assertEqual(len({value.vless_uuid, value.vmess_uuid, value.tuic_uuid}), 3)
        self.assertNotEqual(value.hysteria2_password, value.hysteria2_obfs_password)
        restored = Secrets.from_dict({"vless_uuid": value.vless_uuid})
        self.assertEqual(restored.vless_uuid, value.vless_uuid)
        self.assertTrue(restored.vmess_uuid)

    def test_ddns_argo_conflict_is_rejected(self):
        with self.assertRaises(ConfigError):
            settings(
                host="vpn.example.com",
                ddns=DDNSSettings(enabled=True, zone="example.com", record="vpn.example.com"),
                argo=ArgoSettings(enabled=True, hostname="vpn.example.com"),
            )

    def test_only_hysteria2_port_hopping_is_accepted(self):
        with self.assertRaises(ConfigError):
            settings(port_hopping={"tuic": "20000:21000"})
        configured = settings(port_hopping={"hysteria2": "20000:21000"})
        self.assertEqual(configured.port_hopping["hysteria2"], "20000:21000")


class ConfigTests(unittest.TestCase):
    def test_server_schema_and_secret_separation(self):
        configured, secret = settings(), secrets()
        document = build_server_config(configured, secret)
        inbounds = {item["type"]: item for item in document["inbounds"]}
        self.assertNotIn("transport", inbounds["vless"])
        self.assertNotIn("certificate_path", inbounds["vless"]["tls"])
        self.assertEqual(inbounds["vmess"]["users"][0]["alter_id"], 0)
        self.assertEqual(inbounds["hysteria2"]["obfs"]["password"], secret.hysteria2_obfs_password)
        self.assertNotEqual(inbounds["hysteria2"]["users"][0]["password"], secret.hysteria2_obfs_password)
        self.assertNotIn("version", inbounds["tuic"])
        self.assertFalse(inbounds["tuic"]["zero_rtt_handshake"])
        self.assertNotIn("insecure", json.dumps(document))

    def test_client_schema_and_port_hopping(self):
        configured = settings(port_hopping={"hysteria2": "20000:21000"})
        document = build_singbox_client(configured, secrets(), "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n")
        outbounds = {item["tag"]: item for item in document["outbounds"]}
        self.assertEqual(outbounds["vmess"]["alter_id"], 0)
        self.assertEqual(outbounds["hysteria2"]["server_ports"], ["20000:21000"])
        self.assertNotIn("server_port", outbounds["hysteria2"])
        for name in ("hysteria2", "tuic", "anytls"):
            self.assertIn("certificate", outbounds[name]["tls"])
            self.assertNotIn("insecure", outbounds[name]["tls"])
        self.assertNotIn("version", outbounds["tuic"])

    def test_argo_is_an_additional_vmess_endpoint(self):
        configured = settings(argo=ArgoSettings(enabled=True, hostname="argo.example.com"))
        document = build_singbox_client(configured, secrets(), "")
        argo = next(item for item in document["outbounds"] if item["tag"] == "vmess-argo")
        self.assertEqual(argo["server_port"], 443)
        self.assertEqual(argo["tls"]["server_name"], "argo.example.com")
        self.assertNotIn("insecure", argo["tls"])


class ExportTests(unittest.TestCase):
    def test_links_never_disable_tls_verification(self):
        links = build_share_links(settings(), secrets(), certificate())
        self.assertEqual(parse_qs(urlsplit(links["hysteria2"]).query)["insecure"], ["0"])
        self.assertEqual(parse_qs(urlsplit(links["tuic"]).query)["allow_insecure"], ["0"])
        self.assertEqual(parse_qs(urlsplit(links["anytls"]).query)["insecure"], ["0"])
        for name in ("hysteria2", "tuic", "anytls"):
            self.assertIn("pinSHA256", parse_qs(urlsplit(links[name]).query))
        secret = secrets()
        links = build_share_links(settings(), secret, certificate())
        decoded = base64.b64decode(links["vmess"][8:]).decode()
        self.assertEqual(json.loads(decoded)["id"], secret.vmess_uuid)

    def test_mihomo_uses_certificate_fingerprint(self):
        document = build_mihomo(settings(), secrets(), certificate())
        rendered = yaml_dump(document)
        self.assertNotIn('"skip-cert-verify": true', rendered)
        self.assertIn(certificate()["certificate_fingerprint"], rendered)
        self.assertIn('"type": "anytls"', rendered)

    def test_export_contains_no_private_key(self):
        configured, secret = settings(), secrets()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cert = root / "cert.pem"
            cert.write_text("-----BEGIN CERTIFICATE-----\npublic-only\n-----END CERTIFICATE-----\n", encoding="ascii")
            with patch("sbox5.export.available", return_value=False):
                result = export_nodes(configured, secret, cert, certificate(), root / "exports")
            self.assertIn("sing-box-client.json", result["files"])
            for path in (root / "exports").iterdir():
                if path.is_file():
                    self.assertNotIn(secret.reality_private_key, path.read_text(encoding="utf-8"))
            self.assertIn("pinSHA256", (root / "exports" / "links.txt").read_text())


if __name__ == "__main__":
    unittest.main()
