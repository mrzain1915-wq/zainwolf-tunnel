import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent
BUILD_SCRIPT = ROOT / "build_windows_exe.bat"
INSTALL_SCRIPT = ROOT / "INSTALL_FULL_TRAFFIC_HELPERS.bat"
SOURCE_BUILD_SCRIPT = ROOT / "BUILD_TUN2SOCKS_FROM_SOURCE.bat"
SETUP_SCRIPT = ROOT / "setup_windows_tun_helpers.ps1"


class SourceIntegratedBuildTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build_source = BUILD_SCRIPT.read_text(encoding="utf-8")
        cls.install_source = INSTALL_SCRIPT.read_text(encoding="utf-8")
        cls.go_build_source = SOURCE_BUILD_SCRIPT.read_text(encoding="utf-8")
        cls.setup_source = SETUP_SCRIPT.read_text(encoding="utf-8")

    def test_ci_builds_tun2socks_from_upstream_source_without_release_exe(self):
        workflow = (ROOT / ".github" / "workflows" / "build-windows.yml").read_text(encoding="utf-8")
        self.assertIn("xjasonlyu/tun2socks", workflow)
        self.assertIn("v2.7.0", workflow)
        self.assertIn("go build", workflow)
        self.assertNotIn("xjasonlyu/tun2socks/releases/download", workflow)

    def test_uploaded_wintun_amd64_dll_and_license_are_bundled(self):
        dll = ROOT / "tools" / "wintun.dll"
        license_file = ROOT / "tools" / "licenses" / "Wintun-LICENSE.txt"
        self.assertTrue(dll.is_file())
        self.assertGreater(dll.stat().st_size, 100_000)
        self.assertTrue(license_file.is_file())
        self.assertIn("LICENSE GRANT", license_file.read_text(encoding="utf-8", errors="replace"))

    def test_source_build_uses_go_and_not_github_release_assets(self):
        self.assertIn("Go 1.26.3 or newer", self.go_build_source)
        self.assertIn("go build", self.go_build_source)
        self.assertIn("GOTOOLCHAIN=local", self.go_build_source)
        self.assertIn("proxy.golang.org", self.go_build_source)
        self.assertIn("goproxy.io", self.go_build_source)
        self.assertIn("GOSUMDB=sum.golang.org", self.go_build_source)
        self.assertIn("go mod download", self.go_build_source)
        self.assertIn("download_retry", self.go_build_source)
        self.assertIn("tools\\tun2socks.exe", self.go_build_source)
        self.assertNotIn("github.com/xjasonlyu/tun2socks/releases/download", self.go_build_source)

    def test_full_traffic_installer_calls_local_source_build(self):
        self.assertIn("tools\\wintun.dll", self.install_source)
        self.assertIn("BUILD_TUN2SOCKS_FROM_SOURCE.bat", self.install_source)
        self.assertIn("tools\\tun2socks.exe", self.install_source)
        self.assertNotIn("setup_windows_tun_helpers.ps1", self.install_source)

    def test_standard_build_does_not_require_go_or_helpers(self):
        self.assertIn("build_standard", self.build_source)
        self.assertIn("standard local-proxy version", self.build_source)
        self.assertIn("if exist \"tools\\tun2socks.exe\" if exist \"tools\\wintun.dll\"", self.build_source)
        self.assertNotIn("BUILD_TUN2SOCKS_FROM_SOURCE.bat", self.build_source)

    def test_old_network_installer_points_to_new_included_source_workflow(self):
        self.assertIn("INSTALL_FULL_TRAFFIC_HELPERS.bat", self.setup_source)
        self.assertIn("third_party\\tun2socks-2.7.0", self.setup_source)
        self.assertNotIn("--insecure", self.setup_source)


if __name__ == "__main__":
    unittest.main()
