import json
import tempfile
import unittest
from pathlib import Path

from tunnel_profiles import (
    delete_profile,
    load_profiles,
    save_profile,
    save_profiles,
    strip_password_from_server_spec,
)

SAMPLE = {
    "server": "ssh.example.com:443@user",
    "proxy_mode": "HTTP + Payload",
    "proxy": "proxy.example.com:8080",
    "payload": "CONNECT [host_port] HTTP/1.1[crlf][crlf]",
    "local_port": "1080",
    "http_port": "8081",
    "use_system_proxy": True,
    "full_traffic": False,
}


class ProfileStoreTests(unittest.TestCase):
    def test_save_load_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "profiles.json"
            save_profile(path, "Home SSH", SAMPLE)
            loaded = load_profiles(path)
            self.assertEqual(loaded["Home SSH"], SAMPLE)

    def test_password_is_never_stored(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "profiles.json"
            data = dict(SAMPLE)
            data["server"] = strip_password_from_server_spec(
                "ssh.example.com:443@user:s3cret-password")
            save_profile(path, "Home SSH", data)
            self.assertNotIn("s3cret-password", path.read_text(encoding="utf-8"))
            self.assertEqual(load_profiles(path)["Home SSH"]["server"],
                             "ssh.example.com:443@user")

    def test_overwrite_keeps_other_profiles(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "profiles.json"
            save_profile(path, "A", SAMPLE)
            save_profile(path, "B", dict(SAMPLE, proxy_mode="SOCKS5"))
            save_profile(path, "A", dict(SAMPLE, proxy_mode="Direct SSH"))
            loaded = load_profiles(path)
            self.assertEqual(loaded["A"]["proxy_mode"], "Direct SSH")
            self.assertEqual(loaded["B"]["proxy_mode"], "SOCKS5")

    def test_delete_profile(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "profiles.json"
            save_profile(path, "A", SAMPLE)
            save_profile(path, "B", SAMPLE)
            delete_profile(path, "A")
            loaded = load_profiles(path)
            self.assertNotIn("A", loaded)
            self.assertIn("B", loaded)
            # Deleting a missing profile is a no-op.
            delete_profile(path, "A")
            self.assertIn("B", load_profiles(path))

    def test_load_missing_or_corrupt_file_returns_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "profiles.json"
            self.assertEqual(load_profiles(path), {})
            path.write_text("{not valid json", encoding="utf-8")
            self.assertEqual(load_profiles(path), {})
            path.write_text(json.dumps(["not", "a", "dict"]), encoding="utf-8")
            self.assertEqual(load_profiles(path), {})

    def test_strip_password_from_server_spec(self):
        self.assertEqual(
            strip_password_from_server_spec("ssh.example.com:443@user:pass:word@tail"),
            "ssh.example.com:443@user")
        self.assertEqual(
            strip_password_from_server_spec("[2001:db8::5]:22@user:secret"),
            "[2001:db8::5]:22@user")
        self.assertEqual(strip_password_from_server_spec("not-a-valid-spec"), "")
        self.assertEqual(strip_password_from_server_spec(""), "")

    def test_save_profiles_writes_sorted_json(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "profiles.json"
            save_profiles(path, {"B": SAMPLE, "A": SAMPLE})
            raw = path.read_text(encoding="utf-8")
            self.assertLess(raw.index('"A"'), raw.index('"B"'))


if __name__ == "__main__":
    unittest.main(verbosity=2)
