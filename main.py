#!/usr/bin/env python3
"""Flaekmig CLI entrypoint (minimal)."""
import argparse
from core.engine import Engine
from plugins.nmap.plugin import NmapPlugin


def main():
    parser = argparse.ArgumentParser(prog="flaekmig")
    parser.add_argument("target", help="Target hostname or CIDR")
    parser.add_argument("--plugins", nargs="*", help="Optional plugins to run (by name)")
    args = parser.parse_args()

    engine = Engine()

    # Register minimal builtin plugins. Real loader would be dynamic.
    engine.register_plugin(NmapPlugin())

    # Classify target and display detected kind
    from core.models import Target

    target = Target.from_string(args.target)
    print(f"Detected target: {target.host} (type={target.kind})")

    # Print detected tool availability
    print("\nDetected tool availability:")
    for tool, path in sorted(engine.available_binaries.items()):
        status = "INSTALLED" if path else "MISSING"
        print(f"- {tool}: {status}")

    results = engine.run_target(target, plugin_names=args.plugins)

    print("\nRecommendations:")
    for rec in results.recommendations:
        print(f"- {rec.tool} (score={rec.confidence:.2f}) — {rec.reason}")


if __name__ == "__main__":
    main()
