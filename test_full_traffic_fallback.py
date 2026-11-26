import unittest
from unittest.mock import patch

import ZainWolfTunnel


class FakeVar:
    def __init__(self, value):
        self.value = value

    def get(self):
        return self.value

    def set(self, value):
        self.value = value


class FakeApp:
    _effective_full_traffic_mode = ZainWolfTunnel.ZainWolfTunnelApp._effective_full_traffic_mode

    def __init__(self, enabled=True):
        self.full_traffic_var = FakeVar(enabled)
        self.root = object()
        self.logs = []
        self.saved = 0

    def log(self, message, level="info"):
        self.logs.append((message, level))

    def _save_settings(self):
        self.saved += 1


class FullTrafficFallbackTests(unittest.TestCase):
    @patch.object(ZainWolfTunnel.messagebox, "showwarning")
    def test_unchecked_mode_stays_local_proxy_without_warning(self, warning):
        app = FakeApp(enabled=False)
        with patch.object(ZainWolfTunnel, "helpers_available", return_value=False), \
             patch.object(ZainWolfTunnel, "is_admin", return_value=False):
            self.assertFalse(app._effective_full_traffic_mode())
        warning.assert_not_called()
        self.assertEqual(app.saved, 0)

    @patch.object(ZainWolfTunnel.messagebox, "showwarning")
    def test_missing_helpers_falls_back_instead_of_blocking_connection(self, warning):
        app = FakeApp(enabled=True)
        with patch.object(ZainWolfTunnel.os, "name", "nt"), \
             patch.object(ZainWolfTunnel, "is_admin", return_value=True), \
             patch.object(ZainWolfTunnel, "helpers_available", return_value=False):
            self.assertFalse(app._effective_full_traffic_mode())
        self.assertFalse(app.full_traffic_var.get())
        self.assertEqual(app.saved, 1)
        self.assertTrue(any("Continuing with local SOCKS5/HTTP proxy mode only" in msg for msg, _ in app.logs))
        warning.assert_called_once()

    @patch.object(ZainWolfTunnel.messagebox, "showwarning")
    def test_available_helpers_keep_full_traffic_enabled(self, warning):
        app = FakeApp(enabled=True)
        with patch.object(ZainWolfTunnel.os, "name", "nt"), \
             patch.object(ZainWolfTunnel, "is_admin", return_value=True), \
             patch.object(ZainWolfTunnel, "helpers_available", return_value=True):
            self.assertTrue(app._effective_full_traffic_mode())
        self.assertTrue(app.full_traffic_var.get())
        self.assertEqual(app.saved, 0)
        warning.assert_not_called()

    @patch.object(ZainWolfTunnel.messagebox, "showwarning")
    def test_non_admin_falls_back_to_local_proxy(self, warning):
        app = FakeApp(enabled=True)
        with patch.object(ZainWolfTunnel.os, "name", "nt"), \
             patch.object(ZainWolfTunnel, "is_admin", return_value=False), \
             patch.object(ZainWolfTunnel, "helpers_available", return_value=True):
            self.assertFalse(app._effective_full_traffic_mode())
        self.assertFalse(app.full_traffic_var.get())
        warning.assert_called_once()


if __name__ == "__main__":
    unittest.main()
