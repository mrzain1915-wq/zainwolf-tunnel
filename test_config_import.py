import json
import unittest

from config_import import parse_import_text


class ConfigImportTests(unittest.TestCase):
    def test_standard_ssh_uri_with_credentials(self):
        got = parse_import_text("ssh://ali:secret%40word@example.com:2222")
        self.assertEqual((got["kind"], got["host"], got["port"], got["username"], got["password"]),
                         ("ssh", "example.com", 2222, "ali", "secret@word"))
        self.assertEqual(got["server_field"], "example.com:2222@ali:secret@word")

    def test_ssh_uri_missing_password_can_prompt_in_ui(self):
        got = parse_import_text("ssh://ali@example.com:2222")
        self.assertEqual(got["username"], "ali")
        self.assertEqual(got["password"], "")
        self.assertTrue(got["missing_credentials"])

    def test_ssh_uri_default_port(self):
        got = parse_import_text("ssh://ali:secret@example.com")
        self.assertEqual(got["port"], 22)

    def test_legacy_login_format(self):
        got = parse_import_text("example.com:443@ali:secret")
        self.assertEqual(got["server_field"], "example.com:443@ali:secret")

    def test_custom_ssh_scheme_legacy_format(self):
        got = parse_import_text("ssh://example.com:443@ali:secret")
        self.assertEqual((got["host"], got["port"], got["username"], got["password"]),
                         ("example.com", 443, "ali", "secret"))

    def test_vless_uri_is_detected_not_misparsed_as_ssh(self):
        self.assertEqual(parse_import_text("vless://id@example.com:443?type=ws")["kind"], "proxy_uri")
        self.assertEqual(parse_import_text("vless://id@example.com:443?type=ws")["protocol"], "vless")

    def test_vless_json_profile_detected(self):
        sample = {"inbounds": [], "outbounds": [{"protocol": "vless", "settings": {"vnext": [{"address": "203.0.113.10", "port": 443}]}, "streamSettings": {"network": "ws", "security": "tls", "tlsSettings": {"serverName": "example.com"}}}]}
        got = parse_import_text(json.dumps(sample))
        self.assertEqual(got["kind"], "proxy_json")
        self.assertEqual(got["protocol"], "vless")
        self.assertEqual(got["network"], "ws")
        self.assertEqual(got["sni"], "example.com")

    def test_inbound_only_json_detected(self):
        self.assertEqual(parse_import_text('{"inbounds":[{}],"outbounds":[]}')["kind"], "server_json")

    def test_empty_input_error(self):
        with self.assertRaises(ValueError):
            parse_import_text(" ")


if __name__ == "__main__":
    unittest.main()
