#!/usr/bin/env python3
"""Report TIGRESS detection visibility before trusting coverage.

Detection quality is bounded by visibility (Olaf Hartong): a green self-test on
a grid whose sensors have no telemetry CLI is a false comfort. This prints,
per enabled sensor, whether its telemetry CLI is present and whether its ML
model is trained, plus which log sinks are configured. Exits non-zero when an
enabled sensor is blind (missing CLI).

Usage:
    python scripts/visibility.py [--config config/config.yaml]
"""

import argparse
import json
import os
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from src.core.selftest import visibility_report  # noqa: E402


def main():
    """Print the visibility report and exit non-zero if the grid is blind."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", default="config/config.yaml",
                        help="Path to the TIGRESS config file")
    args = parser.parse_args()

    report = visibility_report(args.config)
    print(json.dumps(report, indent=2))

    if report["warnings"]:
        print(f"\n{len(report['warnings'])} visibility warning(s):", file=sys.stderr)
        for w in report["warnings"]:
            print(f"  - {w}", file=sys.stderr)
    status = "OK" if report["ok"] else "BLIND"
    print(f"\nVisibility {status}", file=sys.stderr)
    sys.exit(0 if report["ok"] else 1)


if __name__ == "__main__":
    main()
