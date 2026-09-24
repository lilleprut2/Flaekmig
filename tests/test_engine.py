import unittest
import tempfile
from pathlib import Path

from core.engine import Engine
from core.models import ScanResult, Target, PortInfo
from main import has_msf_exploit_results, has_version_number, parse_discovery_services, write_empty_discovery_report


class FakePlugin:
    name = "fake"
    description = "Fake plugin for tests"
    required_binary = None
    supported_targets = ["host"]

    def run(self, target: Target) -> ScanResult:
        # pretend port 80 and 445 discovered
        ports = [PortInfo(port=80), PortInfo(port=445)]
        return ScanResult(plugin=self.name, target=target, raw="", ports=ports)

    def parse(self, output: str) -> ScanResult:
        return self.run(Target(host="test"))


class EngineTests(unittest.TestCase):
    def test_empty_discovery_report_identifies_target(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "discovery.json"
            write_empty_discovery_report(str(path), "192.0.2.44")
            content = path.read_text(encoding="utf-8")
            self.assertIn("Nmap scan report for 192.0.2.44", content)
            self.assertIn("No open ports found for 192.0.2.44", content)

    def test_msf_patch_requires_exploit_module(self):
        self.assertTrue(
            has_msf_exploit_results("   0  exploit/unix/ftp/vsftpd_234_backdoor")
        )
        self.assertFalse(
            has_msf_exploit_results("   0  auxiliary/scanner/ftp/ftp_version")
        )
        self.assertFalse(has_msf_exploit_results("[-] No results from search"))

    def test_msf_search_requires_version_number(self):
        self.assertTrue(has_version_number("Apache httpd 2.2.8 ((Ubuntu) DAV/2)"))
        self.assertTrue(has_version_number("OpenSSH 4.7p1 Debian 8ubuntu1"))
        self.assertFalse(has_version_number("OpenBSD or Solaris rlogind"))
        self.assertFalse(has_version_number("Linux telnetd"))

    def test_parse_nmap_normal_output_drops_reason_column(self):
        output = (
            "21/tcp open ftp syn-ack vsftpd 2.3.4\n"
            "513/tcp open login syn-ack\n"
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "discovery.json"
            path.write_text(output, encoding="utf-8")

            self.assertEqual(
                parse_discovery_services(path),
                [("ftp", "vsftpd 2.3.4"), ("login", "")],
            )

    def test_rules_recommendations(self):
        e = Engine()
        e.register_plugin(FakePlugin())
        res = e.run_target("127.0.0.1")
        tools = {r.tool for r in res.recommendations}
        # Expect gobuster (http), nuclei (http), enum4linux (smb), crackmapexec (smb)
        self.assertIn("gobuster", tools)
        self.assertIn("nuclei", tools)
        self.assertIn("enum4linux", tools)


if __name__ == "__main__":
    unittest.main()
