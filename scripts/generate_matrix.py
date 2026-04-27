#!/usr/bin/env python3
"""
generate_matrix.py — GitHub Actions matrix generator

Reads config/deployments.yaml and prints a JSON matrix for use in GitHub
Actions `strategy.matrix`. Run as a step before plan/apply jobs.

Usage:
    python3 scripts/generate_matrix.py              # all deployments
    python3 scripts/generate_matrix.py --env prod   # only prod deployments

Output (stdout):
    {"include": [
      {"deployment_id": "prod-us-east-1", "account_id": "123456789012",
       "region": "us-east-1", "environment": "prod"},
      ...
    ]}
"""

import argparse
import json
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    print("ERROR: pyyaml is required. Run: pip install pyyaml", file=sys.stderr)
    sys.exit(1)

CONFIG_PATH = Path(__file__).parent.parent / "config" / "deployments.yaml"


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate GitHub Actions matrix from deployments.yaml")
    parser.add_argument("--env", choices=["prod", "nonprod"],
                        help="Filter to a single environment")
    args = parser.parse_args()

    if not CONFIG_PATH.exists():
        print(f"ERROR: config not found at {CONFIG_PATH}", file=sys.stderr)
        return 1

    with open(CONFIG_PATH) as f:
        config = yaml.safe_load(f)

    entries = []
    for deployment_id, dep in config["deployments"].items():
        if args.env and dep["environment"] != args.env:
            continue
        entries.append({
            "deployment_id": deployment_id,
            "account_id":    str(dep["account_id"]),
            "region":        dep["region"],
            "environment":   dep["environment"],
        })

    if not entries:
        print("ERROR: no matching deployments found", file=sys.stderr)
        return 1

    print(json.dumps({"include": entries}))
    return 0


if __name__ == "__main__":
    sys.exit(main())
