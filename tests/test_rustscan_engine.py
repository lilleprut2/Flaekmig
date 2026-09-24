import shutil
import tempfile
import unittest
from unittest.mock import patch

from core.models import NetworkProfile, RustScanConfig, Target
from core.network_profiler import NetworkProfiler
from core.rustscan_optimizer import RustScanOptimizer
from core.statistics import ScanHistoryManager, scan_score
from main import build_adaptive_rustscan_command
from plugins.rustscan.plugin import RustScanPlugin


class FakeProfiler:
    def profile(self, target):
        return NetworkProfile(
            target=target,
            average_latency_ms=10.0,
            min_latency_ms=9.0,
            max_latency_ms=12.0,
            packet_loss_percent=0.0,
            quality="EXCELLENT",
            network_type="LOCAL_LAN",
            host_responsive=True,
        )


class RustScanEngineTests(unittest.TestCase):
    def test_network_classification(self):
        profiler = NetworkProfiler()
        self.assertEqual(profiler.classify(5.0, 0.0), "EXCELLENT")
        self.assertEqual(profiler.classify(50.0, 2.0), "GOOD")
        self.assertEqual(profiler.classify(150.0, 10.0), "FAIR")
        self.assertEqual(profiler.classify(400.0, 20.0), "POOR")
        self.assertEqual(profiler.classify(None, 100.0, False), "UNREACHABLE")

    def test_profile_calculates_latency_and_loss(self):
        profiler = NetworkProfiler(ping_count=5)
        completed = type(
            "Completed",
            (),
            {"stdout": "5 packets transmitted, 4 received, 20% packet loss\ntime=10.0 ms\ntime=20.0 ms\ntime=30.0 ms\ntime=40.0 ms"},
        )()
        with patch("core.network_profiler.subprocess.run", return_value=completed) as ping:
            profile = profiler.profile("192.0.2.1")
        self.assertEqual(ping.call_args.args[0][1:3], ["-c", "5"])
        self.assertEqual(profile.average_latency_ms, 25.0)
        self.assertEqual(profile.min_latency_ms, 10.0)
        self.assertEqual(profile.max_latency_ms, 40.0)
        self.assertEqual(profile.packet_loss_percent, 20.0)
        self.assertEqual(profile.quality, "POOR")

    def test_ping_output_parsing(self):
        profiler = NetworkProfiler(ping_count=5)
        output = "5 packets transmitted, 4 received, 20% packet loss\ntime=1.2 ms\ntime=2.8 ms"
        self.assertEqual(profiler._parse_latencies(output), [1.2, 2.8])
        self.assertEqual(profiler._parse_packet_loss(output, [1.2, 2.8]), 20.0)

    def test_history_persists_score(self):
        with tempfile.NamedTemporaryFile(suffix=".db") as database:
            history = ScanHistoryManager(database.name)
            record = history.record_scan(
                "127.0.0.1", 2.0, 1.0, 5000, 2500, 4.0, 3, "EXCELLENT"
            )
            self.assertEqual(record.score, scan_score(3, 4.0, 1.0))
            self.assertEqual(history.count("127.0.0.1"), 1)
            self.assertEqual(history.recent("127.0.0.1")[0].batch_size, 5000)
            history.close()

    def test_optimizer_uses_quality_baseline(self):
        with tempfile.NamedTemporaryFile(suffix=".db") as database:
            history = ScanHistoryManager(database.name)
            optimizer = RustScanOptimizer(history)
            expected = {
                "EXCELLENT": (1000, 1500),
                "GOOD": (500, 2000),
                "FAIR": (100, 3000),
                "POOR": (25, 6000),
                "UNREACHABLE": (5, 10000),
            }
            for quality, values in expected.items():
                profile = NetworkProfile("10.0.0.1", 10.0, 1.0, 20.0, 0.0, quality)
                decision = optimizer.select_config(profile)
                self.assertEqual(decision.config, RustScanConfig(batch_size=values[0], timeout_ms=values[1]))
            history.close()

    def test_quality_baseline_values_reach_rustscan_command(self):
        expected = {
            "EXCELLENT": (1000, 1500),
            "GOOD": (500, 2000),
            "FAIR": (100, 3000),
            "POOR": (25, 6000),
            "UNREACHABLE": (5, 10000),
        }
        for quality, (batch_size, timeout_ms) in expected.items():
            profile = NetworkProfile("10.0.0.1", 10.0, 1.0, 20.0, 0.0, quality)
            decision = RustScanOptimizer().select_config(profile)
            command = RustScanPlugin.build_command(Target.from_string("10.0.0.1"), decision.config)
            self.assertEqual(decision.config, RustScanConfig(batch_size=batch_size, timeout_ms=timeout_ms))
            self.assertEqual(command[command.index("--batch-size") + 1], str(batch_size))
            self.assertEqual(command[command.index("--timeout") + 1], str(timeout_ms))

    def test_optimizer_reduces_aggressiveness_after_loss(self):
        with tempfile.NamedTemporaryFile(suffix=".db") as database:
            history = ScanHistoryManager(database.name)
            for _ in range(10):
                history.record_scan("10.0.0.1", 200.0, 15.0, 7500, 1500, 10.0, 5, "FAIR")
            optimizer = RustScanOptimizer(history)
            profile = NetworkProfile("10.0.0.1", 200.0, 190.0, 220.0, 15.0, "FAIR")
            decision = optimizer.select_config(profile)
            self.assertLess(decision.config.batch_size, 5000)
            self.assertGreaterEqual(decision.config.timeout_ms, 2500)
            history.close()

    def test_rustscan_plugin_profiles_records_and_builds_command(self):
        with tempfile.NamedTemporaryFile(suffix=".db") as database:
            history = ScanHistoryManager(database.name)
            calls = []

            def runner(command, **kwargs):
                calls.append(command)
                return type("Completed", (), {"stdout": "192.0.2.1 -> 80/tcp open"})()

            plugin = RustScanPlugin(FakeProfiler(), history, runner)
            with patch("plugins.rustscan.plugin.shutil.which", return_value="/usr/bin/rustscan"):
                result = plugin.run(Target.from_string("10.0.0.1"))
            self.assertEqual(len(result.ports), 1)
            self.assertEqual(result.config.batch_size, 1000)
            self.assertEqual(history.count("10.0.0.1"), 1)
            self.assertIn("--batch-size", calls[0])
            history.close()

    def test_rustscan_parser_accepts_common_output_formats(self):
        plugin = RustScanPlugin.__new__(RustScanPlugin)
        result = plugin.parse("Open 22/tcp\n80/tcp open\nOpen 22/tcp")
        self.assertEqual([port.port for port in result.ports], [22, 80])

    def test_engine_can_install_rustscan_when_missing(self):
        from core.engine import Engine

        engine = Engine()
        engine.available_binaries["rustscan"] = {"binary": None, "python": None}
        with patch.object(engine, "detect_binaries", return_value={"rustscan": {"binary": "/usr/bin/rustscan", "python": None}}), \
             patch("platform.system", return_value="linux"), \
             patch("shutil.which", side_effect=lambda cmd: "/usr/bin/cargo" if cmd == "cargo" else None), \
             patch("subprocess.run") as run_mock, \
             patch.object(engine, "write_installed_tools_file"):
            ok = engine.ensure_tool("rustscan", attempt_install=True)

        self.assertTrue(ok)
        self.assertTrue(any("cargo install rustscan" in str(call.args[0]) for call in run_mock.call_args_list))

    def test_ip_flow_builds_adaptive_command_before_execution(self):
        with tempfile.NamedTemporaryFile(suffix=".db") as database:
            history = ScanHistoryManager(database.name)
            profiler = NetworkProfiler()
            optimizer = RustScanOptimizer(history)

            with patch("core.network_profiler.subprocess.run") as ping_run:
                ping_run.return_value = type(
                    "Completed",
                    (),
                    {"stdout": "5 packets transmitted, 5 received, 0% packet loss\ntime=5.0 ms\ntime=6.0 ms\ntime=7.0 ms\ntime=8.0 ms\ntime=9.0 ms"},
                )()
                profile, decision, command = build_adaptive_rustscan_command(
                    "10.0.0.5",
                    history=history,
                    profiler=profiler,
                    optimizer=optimizer,
                    rust_bin="/usr/bin/rustscan",
                )

            self.assertEqual(profile.quality, "EXCELLENT")
            self.assertEqual(decision.config.batch_size, 1000)
            self.assertEqual(command[0], shutil.which("rustscan") or "/usr/bin/rustscan")
            self.assertEqual(command[1], "-a")
            self.assertEqual(command[2], "10.0.0.5")
            self.assertEqual(command[3], "--batch-size")
            self.assertEqual(command[4], "1000")
            self.assertIn("--range", command)
            self.assertNotIn("-p", command)
            self.assertIn("-sV", command)
            self.assertTrue(command[-1].endswith("/discovery.json"))
            history.close()

    def test_ip_delicate_mode_forces_batch_size_to_50(self):
        with tempfile.NamedTemporaryFile(suffix=".db") as database:
            history = ScanHistoryManager(database.name)
            profiler = NetworkProfiler()
            optimizer = RustScanOptimizer(history)

            with patch("core.network_profiler.subprocess.run") as ping_run:
                ping_run.return_value = type(
                    "Completed",
                    (),
                    {"stdout": "5 packets transmitted, 5 received, 0% packet loss\ntime=5.0 ms\ntime=6.0 ms\ntime=7.0 ms\ntime=8.0 ms\ntime=9.0 ms"},
                )()
                profile, decision, command = build_adaptive_rustscan_command(
                    "10.0.0.5",
                    history=history,
                    profiler=profiler,
                    optimizer=optimizer,
                    rust_bin="/usr/bin/rustscan",
                    delicate=True,
                )

            self.assertEqual(profile.quality, "EXCELLENT")
            self.assertEqual(decision.config.batch_size, 50)
            self.assertEqual(command[command.index("--batch-size") + 1], "50")
            history.close()


if __name__ == "__main__":
    unittest.main()
