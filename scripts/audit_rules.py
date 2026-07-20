#!/usr/bin/env python3
"""Audit detection rules for single-behaviour signal discipline (Liburdi).

Reports rules that combine multiple behaviours (more than one match condition)
and are candidates for splitting into separate detection signals recombined by
the correlation engine. Advisory by default; pass --strict to exit non-zero
when any multi-behaviour rule is found (useful as a CI gate).

Usage:
    python scripts/audit_rules.py [--rules config/rules.yaml] [--strict]
"""

import argparse
import os
import sys

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from src.core.rule_audit import audit_rules_file  # noqa: E402


def main():
    """Audit the rules file and print any multi-behaviour findings."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rules", default="config/rules.yaml",
                        help="Path to the rules YAML file to audit")
    parser.add_argument("--strict", action="store_true",
                        help="Exit non-zero if any multi-behaviour rule is found")
    args = parser.parse_args()

    findings = audit_rules_file(args.rules)
    if not findings:
        print(f"OK: all rules in {args.rules} are single-behaviour signals.")
        sys.exit(0)

    print(f"Found {len(findings)} multi-behaviour rule(s) in {args.rules}:\n")
    for f in findings:
        print(f"  [{f['section']}] {f['rule_id']}: "
              f"{f['condition_count']} conditions on {f['fields']}")
        print(f"      → {f['recommendation']}")
    sys.exit(1 if args.strict else 0)


if __name__ == "__main__":
    main()
