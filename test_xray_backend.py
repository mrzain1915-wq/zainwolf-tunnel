import base64
import json
import tempfile
import unittest
from pathlib import Path

from config_import import parse_import_text
from xray_backend import build_runtime_config, write_runtime_config

VLESS_URI = (
    "vless://11111111-2222-3333-4444-555555555555@203.0.113.10:443"
    "?encryption=none&type=ws&host=example.com&headerType=none&path=%2Fvless"
    "&security=tls&fp=chrome&sni=example.com#Vless_Config"
)


class XrayImportTests(unittest.TestCase):
    def test_vless_share_link_is_fully_parsed(self):
        got = parse_import_text(VLESS_URI)
        self.assertEqual(got["kind"], "proxy_uri")
        self.assertEqual(got["protocol"], "vless")
        self.assertEqual(got["host"], "203.0.113.10")
        self.assertEqual(got["port"], 443)
        self.assertEqual(got["network"], "ws")
        self.assertEqual(got["security"], "tls")
        self.assertEqual(got["sni"], "example.com")
        outbound = got["outbound"]
        self.assertEqual(outbound["settings"]["vnext"][0]["users"][0]["id"], "11111111-2222-3333-4444-555555555555")
        self.assertEqual(outbound["streamSettings"]["wsSettings"]["path"], "/vless")
        self.assertEqual(outbound["streamSettings"]["wsSettings"]["headers"]["Host"], "example.com")
        self.assertEqual(outbound["streamSettings"]["tlsSettings"]["fingerprint"], "chrome")

    def test_vless_link_without_fingerprint_is_supported(self):
        link = VLESS_URI.replace("&fp=chrome", "").replace("#Vless_Config", "#Vless_WS_TLS")
        got = parse_import_text(link)
        tls = got["outbound"]["streamSettings"]["tlsSettings"]
        self.assertNotIn("fingerprint", tls)
        self.assertEqual(tls["serverName"], "example.com")
        self.assertEqual(got["outbound"]["streamSettings"]["wsSettings"]["path"], "/vless")

    def test_trojan_share_link_is_parsed(self):
        got = parse_import_text("trojan://my%40secret@server.example.net:443?security=tls&sni=server.example.net&type=ws&host=cdn.example.net&path=%2Ftunnel#Test")
        self.assertEqual((got["protocol"], got["host"], got["port"]), ("trojan", "server.example.net", 443))
        self.assertEqual(got["outbound"]["settings"]["servers"][0]["password"], "my@secret")
        self.assertEqual(got["outbound"]["streamSettings"]["wsSettings"]["path"], "/tunnel")

    def test_vmess_base64_json_link_is_parsed(self):
        raw = json.dumps({"ps": "vmess test", "add": "vmess.example.net", "port": "8443",
                          "id": "11111111-2222-3333-4444-555555555555", "aid": "0", "scy": "auto",
                          "net": "ws", "tls": "tls", "sni": "vmess.example.net",
                          "host": "cdn.example.net", "path": "/vmess"}).encode()
        link = "vmess://" + base64.urlsafe_b64encode(raw).decode().rstrip("=")
        got = parse_import_text(link)
        self.assertEqual((got["protocol"], got["host"], got["port"]), ("vmess", "vmess.example.net", 8443))
        self.assertEqual(got["outbound"]["streamSettings"]["wsSettings"]["path"], "/vmess")
        self.assertEqual(got["outbound"]["streamSettings"]["wsSettings"]["headers"]["Host"], "cdn.example.net")

    def test_runtime_config_has_loopback_inbounds_and_profile_outbound(self):
        profile = parse_import_text(VLESS_URI)
        config = build_runtime_config(profile, 1080, 8080)
        self.assertEqual(config["inbounds"][0]["listen"], "127.0.0.1")
        self.assertEqual(config["inbounds"][0]["port"], 1080)
        self.assertEqual(config["inbounds"][1]["listen"], "127.0.0.1")
        self.assertEqual(config["inbounds"][1]["port"], 8080)
        self.assertEqual(config["outbounds"][0]["protocol"], "vless")

    def test_runtime_config_rejects_same_ports(self):
        profile = parse_import_text(VLESS_URI)
        with self.assertRaises(ValueError):
            build_runtime_config(profile, 1080, 1080)

    def test_json_outbound_is_preserved(self):
        sample = {
            "inbounds": [], "outbounds": [{
                "protocol": "vless", "tag": "VLESS", "settings": {
                    "vnext": [{"address": "203.0.113.10", "port": 443,
                               "users": [{"id": "11111111-2222-3333-4444-555555555555", "encryption": "none"}]}]},
                "streamSettings": {"network": "ws", "security": "tls", "tlsSettings": {"serverName": "example.com"},
                                   "wsSettings": {"path": "/vless", "headers": {"Host": "example.com"}}}}]}
        profile = parse_import_text(json.dumps(sample))
        config = build_runtime_config(profile, 1080, 8080)
        self.assertEqual(config["outbounds"][0]["streamSettings"]["wsSettings"]["path"], "/vless")

    def test_runtime_config_written_as_valid_json(self):
        with tempfile.TemporaryDirectory() as d:
            profile = parse_import_text(VLESS_URI)
            path = write_runtime_config(profile, 1080, 8080, Path(d))
            data = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(data["outbounds"][0]["protocol"], "vless")


if __name__ == "__main__":
    unittest.main()
