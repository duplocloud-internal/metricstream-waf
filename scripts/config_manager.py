#!/usr/bin/env python3
"""
config_manager.py — Programmatic updater for config/deployments.yaml

Used by GitHub Actions workflow_dispatch workflows so operators can make
all common WAF configuration changes through the GitHub UI without editing
any files directly.

All commands print the updated YAML to stdout and exit 0 on success.
The calling workflow writes the output back to the file, commits, and opens a PR.

COMMANDS
────────
  add-deployment        Register a new account+region deployment
  set-rule-mode         Switch a managed rule between count and block
  set-rate-limit        Change the rate limit threshold for a deployment
  add-customer          Add or update a customer IP whitelist
  remove-customer       Remove a customer IP whitelist
  add-crs-override      Add a CRS rule false-positive override
  remove-crs-override   Remove a CRS rule override

USAGE EXAMPLES
──────────────
  python3 scripts/config_manager.py add-deployment \\
      --deployment-id prod-ap-southeast-1 \\
      --account-id 123456789012 \\
      --region ap-southeast-1 \\
      --environment prod

  python3 scripts/config_manager.py set-rule-mode \\
      --deployment-id prod-us-east-1 \\
      --rule CommonRuleSet \\
      --mode block

  python3 scripts/config_manager.py add-customer \\
      --deployment-id prod-us-east-1 \\
      --customer-key acme-corp \\
      --hostname acme.metricstream.com \\
      --allowed-ips "203.0.113.0/24,198.51.100.10/32" \\
      --priority-offset 0

  python3 scripts/config_manager.py remove-customer \\
      --deployment-id prod-us-east-1 \\
      --customer-key acme-corp
"""

import argparse
import ipaddress
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    print("ERROR: pyyaml required. Run: pip install pyyaml", file=sys.stderr)
    sys.exit(1)

CONFIG_PATH = Path(__file__).parent.parent / "config" / "deployments.yaml"

MANAGED_RULES = [
    "AmazonIpReputationList",
    "AnonymousIpList",
    "KnownBadInputsRuleSet",
    "CommonRuleSet",
]

DEFAULT_MANAGED_RULE_MODES = {
    "AmazonIpReputationList": "block",
    "AnonymousIpList":        "count",
    "KnownBadInputsRuleSet":  "block",
    "CommonRuleSet":          "count",
}


# ── YAML I/O ──────────────────────────────────────────────────────────────────

def load() -> dict:
    if not CONFIG_PATH.exists():
        print(f"ERROR: config not found at {CONFIG_PATH}", file=sys.stderr)
        sys.exit(1)
    with open(CONFIG_PATH) as f:
        return yaml.safe_load(f)


def dump(config: dict) -> str:
    return yaml.dump(config, default_flow_style=False, sort_keys=False,
                     allow_unicode=True, width=100)


def get_deployment(config: dict, deployment_id: str) -> dict:
    if deployment_id not in config["deployments"]:
        print(f"ERROR: deployment '{deployment_id}' not found in deployments.yaml", file=sys.stderr)
        print("Available deployments:", file=sys.stderr)
        for d in config["deployments"]:
            print(f"  - {d}", file=sys.stderr)
        sys.exit(1)
    return config["deployments"][deployment_id]


# ── Validation helpers ────────────────────────────────────────────────────────

def validate_cidrs(cidr_string: str) -> list[str]:
    cidrs = [c.strip() for c in cidr_string.split(",") if c.strip()]
    for cidr in cidrs:
        try:
            ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            print(f"ERROR: invalid CIDR '{cidr}'", file=sys.stderr)
            sys.exit(1)
    if not cidrs:
        print("ERROR: at least one IP CIDR is required", file=sys.stderr)
        sys.exit(1)
    return cidrs


def validate_priority_offset(offset: int, deployment: dict, exclude_key: str = "") -> None:
    existing = {
        k: v["priority_offset"]
        for k, v in deployment.get("customer_ip_whitelists", {}).items()
        if k != exclude_key
    }
    if offset < 0 or offset > 89:
        print(f"ERROR: priority_offset must be 0-89, got {offset}", file=sys.stderr)
        sys.exit(1)
    if offset in existing.values():
        conflict = [k for k, v in existing.items() if v == offset]
        print(f"ERROR: priority_offset {offset} already used by: {conflict}", file=sys.stderr)
        sys.exit(1)


# ── Commands ──────────────────────────────────────────────────────────────────

def cmd_add_deployment(args: argparse.Namespace) -> None:
    config = load()
    dep_id = args.deployment_id
    account_id = str(args.account_id)

    if dep_id in config["deployments"]:
        print(f"ERROR: deployment '{dep_id}' already exists. Use set-* commands to modify it.",
              file=sys.stderr)
        sys.exit(1)

    # Register account in state_backends if not already present
    if "state_backends" not in config:
        config["state_backends"] = {}
    if account_id not in config["state_backends"]:
        bucket_name   = args.state_bucket or f"metricstream-terraform-state-{account_id}"
        bucket_region = args.state_bucket_region or args.region
        dynamo_table  = args.state_dynamodb_table or "metricstream-terraform-locks"
        config["state_backends"][account_id] = {
            "bucket":         bucket_name,
            "region":         bucket_region,
            "dynamodb_table": dynamo_table,
        }
        print(
            f"INFO: Added state_backends entry for account {account_id} "
            f"(bucket: {bucket_name}, region: {bucket_region})",
            file=sys.stderr,
        )

    env = args.environment
    config["deployments"][dep_id] = {
        "account_id":                 account_id,
        "region":                     args.region,
        "environment":                env,
        "rate_limit_threshold":       args.rate_limit or (2000 if env == "prod" else 500),
        "log_retention_days":         365 if env == "prod" else 90,
        "cloudwatch_retention_days":  90  if env == "prod" else 30,
        "object_lock_retention_days": 90  if env == "prod" else 30,
        "alarm_high_block_threshold": 1000 if env == "prod" else 200,
        "alarm_low_allowed_threshold":100  if env == "prod" else 10,
        "alarm_sns_arns":             [],
        "kms_key_arn":                "",
        "managed_rule_modes":         dict(DEFAULT_MANAGED_RULE_MODES),
        "customer_ip_whitelists":     {},
        "crs_rule_overrides":         [],
    }
    print(dump(config), end="")


def cmd_set_rule_mode(args: argparse.Namespace) -> None:
    config = load()
    dep = get_deployment(config, args.deployment_id)

    if args.rule not in MANAGED_RULES:
        print(f"ERROR: unknown rule '{args.rule}'. Valid rules: {MANAGED_RULES}", file=sys.stderr)
        sys.exit(1)
    if args.mode not in ("block", "count"):
        print("ERROR: mode must be 'block' or 'count'", file=sys.stderr)
        sys.exit(1)

    if "managed_rule_modes" not in dep:
        dep["managed_rule_modes"] = dict(DEFAULT_MANAGED_RULE_MODES)
    dep["managed_rule_modes"][args.rule] = args.mode
    print(dump(config), end="")


def cmd_set_rate_limit(args: argparse.Namespace) -> None:
    config = load()
    dep = get_deployment(config, args.deployment_id)

    if args.threshold < 100:
        print("ERROR: threshold must be >= 100 (AWS WAF minimum)", file=sys.stderr)
        sys.exit(1)
    dep["rate_limit_threshold"] = args.threshold
    print(dump(config), end="")


def cmd_add_customer(args: argparse.Namespace) -> None:
    config = load()
    dep = get_deployment(config, args.deployment_id)

    cidrs = validate_cidrs(args.allowed_ips)
    cidrs_v6 = validate_cidrs(args.allowed_ips_ipv6) if args.allowed_ips_ipv6 else []

    existing_key = args.customer_key in dep.get("customer_ip_whitelists", {})
    validate_priority_offset(
        args.priority_offset, dep,
        exclude_key=args.customer_key if existing_key else "",
    )

    if "customer_ip_whitelists" not in dep:
        dep["customer_ip_whitelists"] = {}

    dep["customer_ip_whitelists"][args.customer_key] = {
        "hostname":              args.hostname,
        "allowed_ip_cidrs":      cidrs,
        "allowed_ip_cidrs_ipv6": cidrs_v6,
        "priority_offset":       args.priority_offset,
    }
    print(dump(config), end="")


def cmd_remove_customer(args: argparse.Namespace) -> None:
    config = load()
    dep = get_deployment(config, args.deployment_id)

    if args.customer_key not in dep.get("customer_ip_whitelists", {}):
        print(f"ERROR: customer '{args.customer_key}' not found in '{args.deployment_id}'",
              file=sys.stderr)
        sys.exit(1)

    del dep["customer_ip_whitelists"][args.customer_key]
    print(dump(config), end="")


def cmd_add_crs_override(args: argparse.Namespace) -> None:
    config = load()
    dep = get_deployment(config, args.deployment_id)

    if "crs_rule_overrides" not in dep:
        dep["crs_rule_overrides"] = []

    # Remove existing entry for same rule if present
    dep["crs_rule_overrides"] = [
        o for o in dep["crs_rule_overrides"] if o["rule_name"] != args.rule_name
    ]
    dep["crs_rule_overrides"].append({
        "rule_name":     args.rule_name,
        "reason":        args.reason,
        "approved_by":   args.approved_by,
        "approved_date": args.approved_date,
    })
    print(dump(config), end="")


def cmd_remove_crs_override(args: argparse.Namespace) -> None:
    config = load()
    dep = get_deployment(config, args.deployment_id)

    before = len(dep.get("crs_rule_overrides", []))
    dep["crs_rule_overrides"] = [
        o for o in dep.get("crs_rule_overrides", []) if o["rule_name"] != args.rule_name
    ]
    if len(dep["crs_rule_overrides"]) == before:
        print(f"ERROR: override for rule '{args.rule_name}' not found in '{args.deployment_id}'",
              file=sys.stderr)
        sys.exit(1)
    print(dump(config), end="")


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> int:
    p = argparse.ArgumentParser(description="Programmatic deployments.yaml manager")
    sub = p.add_subparsers(dest="command", required=True)

    # add-deployment
    s = sub.add_parser("add-deployment", help="Register a new account+region deployment")
    s.add_argument("--deployment-id", required=True)
    s.add_argument("--account-id",    required=True)
    s.add_argument("--region",        required=True)
    s.add_argument("--environment",   required=True, choices=["prod", "nonprod"])
    s.add_argument("--rate-limit",    type=int, default=None,
                   help="Rate limit threshold (default: 2000 for prod, 500 for nonprod)")
    s.add_argument("--state-bucket", default=None,
                   help="State S3 bucket name for this account "
                        "(default: metricstream-terraform-state-{account_id}). "
                        "Only used when adding a new account to state_backends.")
    s.add_argument("--state-bucket-region", default=None,
                   help="Region where the state bucket lives (default: same as --region)")
    s.add_argument("--state-dynamodb-table", default=None,
                   help="DynamoDB lock table name (default: metricstream-terraform-locks)")

    # set-rule-mode
    s = sub.add_parser("set-rule-mode", help="Switch a managed rule between count and block")
    s.add_argument("--deployment-id", required=True)
    s.add_argument("--rule",          required=True, choices=MANAGED_RULES)
    s.add_argument("--mode",          required=True, choices=["block", "count"])

    # set-rate-limit
    s = sub.add_parser("set-rate-limit", help="Change the rate limit threshold")
    s.add_argument("--deployment-id", required=True)
    s.add_argument("--threshold",     required=True, type=int)

    # add-customer
    s = sub.add_parser("add-customer", help="Add or update a customer IP whitelist")
    s.add_argument("--deployment-id",    required=True)
    s.add_argument("--customer-key",     required=True, help="Short identifier, e.g. acme-corp")
    s.add_argument("--hostname",         required=True, help="Exact host header, e.g. acme.metricstream.com")
    s.add_argument("--allowed-ips",      required=True, help="Comma-separated IPv4 CIDRs")
    s.add_argument("--allowed-ips-ipv6", default="",    help="Comma-separated IPv6 CIDRs (optional)")
    s.add_argument("--priority-offset",  required=True, type=int, help="Unique integer 0-89")

    # remove-customer
    s = sub.add_parser("remove-customer", help="Remove a customer IP whitelist")
    s.add_argument("--deployment-id", required=True)
    s.add_argument("--customer-key",  required=True)

    # add-crs-override
    s = sub.add_parser("add-crs-override", help="Add a CRS false-positive rule override")
    s.add_argument("--deployment-id", required=True)
    s.add_argument("--rule-name",     required=True)
    s.add_argument("--reason",        required=True)
    s.add_argument("--approved-by",   required=True)
    s.add_argument("--approved-date", required=True, help="YYYY-MM-DD")

    # remove-crs-override
    s = sub.add_parser("remove-crs-override", help="Remove a CRS rule override")
    s.add_argument("--deployment-id", required=True)
    s.add_argument("--rule-name",     required=True)

    args = p.parse_args()

    dispatch = {
        "add-deployment":    cmd_add_deployment,
        "set-rule-mode":     cmd_set_rule_mode,
        "set-rate-limit":    cmd_set_rate_limit,
        "add-customer":      cmd_add_customer,
        "remove-customer":   cmd_remove_customer,
        "add-crs-override":  cmd_add_crs_override,
        "remove-crs-override": cmd_remove_crs_override,
    }
    dispatch[args.command](args)
    return 0


if __name__ == "__main__":
    sys.exit(main())
