import unittest

from core.engine import Engine
from core.models import ScanResult, Target, PortInfo


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
