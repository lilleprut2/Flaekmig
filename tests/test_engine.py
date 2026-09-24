import json
import os
import unittest
import tempfile
from pathlib import Path
from unittest import mock

from core.engine import Engine
from core.models import ScanResult, Target, PortInfo
from main import (
    build_metasploit_search_terms,
    dump_raw_nmap_output,
    has_msf_exploit_results,
    has_version_number,
    parse_discovery_services,
    write_empty_discovery_report,
)
from plugins.nmap.plugin import NmapPlugin


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
            self.assertEqual(json.loads(content), [])

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
        self.assertTrue(has_version_number("Microsoft Windows Server 2008 R2 - 2012 microsoft-ds"))
        self.assertFalse(has_version_number("OpenBSD or Solaris rlogind"))
        self.assertFalse(has_version_number("Linux telnetd"))

    def test_metasploit_search_normalizes_windows_server_banner(self):
        self.assertEqual(
            build_metasploit_search_terms(
                "microsoft-ds",
                "Microsoft Windows Server 2008 R2 - 2012 microsoft-ds",
            ),
            ["Windows Server 2008 R2"],
        )

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

    def test_parse_json_discovery_format(self):
        payload = [
            {"port": 80, "service": "Apache", "version": "2.4.49"},
            {"port": 443, "service": "nginx", "version": "1.25.1"},
        ]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "discovery.json"
            path.write_text(json.dumps(payload), encoding="utf-8")

            self.assertEqual(
                parse_discovery_services(path),
                [("Apache", "2.4.49"), ("nginx", "1.25.1")],
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

    def test_blackarch_repo_is_loaded_on_arch(self):
        e = Engine()
        pacman_conf = "[core]\nInclude = /etc/pacman.d/mirrorlist\n"

        with mock.patch("platform.system", return_value="Linux"), \
             mock.patch("os.path.exists", side_effect=lambda path: path in ["/etc/arch-release", "/etc/pacman.conf"]), \
             mock.patch("builtins.open", mock.mock_open(read_data=pacman_conf)), \
             mock.patch("shutil.which", side_effect=lambda cmd: "/usr/bin/pacman" if cmd == "pacman" else "/usr/bin/curl" if cmd == "curl" else None), \
             mock.patch("subprocess.run") as run_mock:

            e.ensure_blackarch_repo_loaded()

        self.assertTrue(run_mock.called)
        commands = [call.args[0] for call in run_mock.call_args_list]
        self.assertTrue(any("blackarch.org/strap.sh" in command for command in commands))
        self.assertTrue(any("sudo pacman -Syy --noconfirm" in command for command in commands))

    def test_nmap_scan_dumps_raw_output(self):
        raw_output = "Nmap scan report\nHost is up\n"
        process = mock.Mock(returncode=0, stdout=raw_output, stderr="")

        with tempfile.TemporaryDirectory() as directory, \
             mock.patch("plugins.nmap.plugin.shutil.which", return_value="/usr/bin/nmap"), \
             mock.patch("plugins.nmap.plugin.subprocess.run", return_value=process):
            current_directory = os.getcwd()
            try:
                os.chdir(directory)
                NmapPlugin().run(Target(host="192.0.2.10"))
                dump_path = Path(directory) / "nmapdump.json"
                self.assertEqual(dump_path.read_text(encoding="utf-8"), raw_output)
            finally:
                os.chdir(current_directory)

    def test_rustscan_report_raw_output_can_be_dumped_before_rewrite(self):
        raw_output = "# Nmap 7.95 scan\n80/tcp open http syn-ack Apache 2.4.49\n"

        with tempfile.TemporaryDirectory() as directory:
            source_path = Path(directory) / "discovery.json"
            dump_path = Path(directory) / "nmapdump.json"
            source_path.write_text(raw_output, encoding="utf-8")

            dump_raw_nmap_output(str(source_path), str(dump_path))

            self.assertEqual(dump_path.read_text(encoding="utf-8"), raw_output)


if __name__ == "__main__":
    unittest.main()
