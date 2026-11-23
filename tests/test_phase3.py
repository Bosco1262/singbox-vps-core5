# Copyright (C) 2026 Bosco1262
# SPDX-License-Identifier: GPL-3.0-or-later

from __future__ import annotations

import base64
from http.server import ThreadingHTTPServer
import json
from pathlib import Path
import sys
import tempfile
import threading
import unittest
from urllib.error import HTTPError
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from sbox5.errors import ConfigError
from sbox5.export import build_mihomo, build_share_links, build_singbox_client, build_tun_client, export_nodes
from sbox5.models import (
    ArgoSettings,
    CertificateProfile,
    Secrets,
    Settings,
    SubscriptionSettings,
)
from sbox5.subscription import _handler, base_url, token_hash


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


def certificate() -> dict:
    return {
        "certificate_sha256": base64.b64encode(bytes(range(32))).decode(),
        "certificate_fingerprint": ":".join(f"{value:02X}" for value in range(32)),
        "public_key_sha256": base64.b64encode(bytes(range(32))).decode(),
        "file_sha256": "0" * 64,
    }


class CdnTests(unittest.TestCase):
    def test_vmess_cdn_is_applied_to_links_and_clients(self):
        configured = settings(cdn={
            "vmess": {
                "enabled": True, "address": "104.16.0.1", "port": 443,
                "host": "cdn.example.com", "sni": "cdn.example.com",
            },
        })
        link = build_share_links(configured, secrets(), certificate(), {"default": certificate()})["vmess"]
        decoded = json.loads(base64.b64decode(link[8:]).decode())
        self.assertEqual((decoded["add"], decoded["port"], decoded["host"], decoded["sni"], decoded["tls"]),
                         ("104.16.0.1", "443", "cdn.example.com", "cdn.example.com", "tls"))
        client = build_singbox_client(configured, secrets(), "PEM")
        vmess = next(item for item in client["outbounds"] if item["tag"] == "vmess")
        self.assertEqual((vmess["server"], vmess["server_port"]), ("104.16.0.1", 443))
        self.assertEqual(vmess["tls"]["server_name"], "cdn.example.com")
        self.assertEqual(vmess["transport"]["headers"], {"Host": "cdn.example.com"})
        mihomo = build_mihomo(configured, secrets(), certificate(), {"default": certificate()})
        proxy = next(item for item in mihomo["proxies"] if item["name"] == "sbox5-vmess")
        self.assertEqual((proxy["server"], proxy["servername"]), ("104.16.0.1", "cdn.example.com"))

    def test_vmess_cdn_requires_plaintext_origin(self):
        with self.assertRaises(ConfigError):
            settings(
                protocols={
                    "vless": {"enabled": True, "tls_profile": ""},
                    "vmess": {"enabled": True, "tls_profile": "default"},
                },
                cdn={"vmess": {"enabled": True, "address": "104.16.0.1", "host": "cdn.example.com"}},
            )

    def test_cdn_ip_requires_host(self):
        with self.assertRaises(ConfigError):
            settings(cdn={"vmess": {"enabled": True, "address": "104.16.0.1"}})

    def test_argo_cdn_requires_token_mode(self):
        with self.assertRaises(ConfigError):
            settings(
                argo=ArgoSettings(enabled=True, mode="quick"),
                cdn={"argo": {"enabled": True, "address": "104.16.0.1", "host": "argo.example.com"}},
            )

    def test_argo_cdn_is_applied(self):
        configured = settings(
            argo=ArgoSettings(enabled=True, mode="token", hostname="argo.example.com"),
            cdn={"argo": {"enabled": True, "address": "104.16.0.1"}},
        )
        client = build_singbox_client(configured, secrets(), "", argo_host="argo.example.com")
        argo = next(item for item in client["outbounds"] if item["tag"] == "vmess-argo")
        self.assertEqual((argo["server"], argo["server_port"]), ("104.16.0.1", 443))
        self.assertEqual(argo["tls"]["server_name"], "argo.example.com")
        self.assertEqual(argo["transport"]["headers"]["Host"], "argo.example.com")


class TunExportTests(unittest.TestCase):
    def test_tun_client_targets(self):
        sfa = build_tun_client(settings(), secrets(), "PEM", platform="sfa")
        sfi = build_tun_client(settings(), secrets(), "PEM", platform="sfi")
        self.assertEqual(sfa["inbounds"][0]["type"], "tun")
        self.assertEqual(sfa["inbounds"][0]["stack"], "mixed")
        self.assertEqual(sfi["inbounds"][0]["stack"], "system")
        self.assertEqual(sfa["route"]["rules"][0], {"action": "sniff"})

    def test_export_writes_all_client_targets(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cert = root / "cert.pem"
            cert.write_text("-----BEGIN CERTIFICATE-----\npublic\n-----END CERTIFICATE-----\n", encoding="ascii")
            result = export_nodes(settings(), secrets(), cert, certificate(), root / "exports")
            for name in ("sing-box-client.json", "sfa.json", "sfi.json", "sfw.json", "mihomo.yaml", "links.txt"):
                self.assertIn(name, result["files"])


class SubscriptionModelTests(unittest.TestCase):
    def test_public_bind_requires_tls(self):
        with self.assertRaises(ConfigError):
            settings(subscription={"enabled": True, "bind": "0.0.0.0", "port": 18090})

    def test_native_acme_cannot_be_used_for_subscription_tls(self):
        profile = CertificateProfile(id="default", mode="acme", domains=["sub.example.com"])
        with self.assertRaises(ConfigError):
            settings(
                certificate_profiles=[profile],
                subscription={"enabled": True, "bind": "127.0.0.1", "port": 18090, "tls_profile": "default"},
            )

    def test_self_signed_can_be_used_for_subscription_tls(self):
        configured = settings(subscription={
            "enabled": True, "bind": "0.0.0.0", "port": 18090, "tls_profile": "default",
        })
        self.assertEqual(configured.subscription.tls_profile, "default")
        self.assertTrue(base_url(configured, "token").startswith("https://198.51.100.20:18090/sub/token/"))

    def test_subscription_port_conflicts_with_protocol_port(self):
        with self.assertRaises(ConfigError):
            settings(subscription={"enabled": True, "bind": "127.0.0.1", "port": 18443})


class SubscriptionServerTests(unittest.TestCase):
    def test_token_path_and_whitelist(self):
        token = "test-token-1234567890"
        with tempfile.TemporaryDirectory() as temporary:
            bundle = Path(temporary)
            (bundle / "links.txt").write_bytes(b"vless://test\n")
            config = {
                "bind": "127.0.0.1",
                "port": 0,
                "bundle_dir": str(bundle),
                "token_sha256": token_hash(token),
            }
            server = ThreadingHTTPServer(("127.0.0.1", 0), _handler(config))
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                port = server.server_address[1]
                with urlopen(f"http://127.0.0.1:{port}/sub/{token}/links", timeout=5) as response:
                    self.assertEqual(response.status, 200)
                    self.assertEqual(response.read(), b"vless://test\n")
                with self.assertRaises(HTTPError) as missing:
                    urlopen(f"http://127.0.0.1:{port}/sub/{token}/mihomo", timeout=5)
                self.assertEqual(missing.exception.code, 404)
                with self.assertRaises(HTTPError) as bad:
                    urlopen(f"http://127.0.0.1:{port}/sub/wrong-token/links", timeout=5)
                self.assertEqual(bad.exception.code, 404)
                with self.assertRaises(HTTPError) as traversal:
                    urlopen(f"http://127.0.0.1:{port}/sub/{token}/../links", timeout=5)
                self.assertEqual(traversal.exception.code, 404)
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
