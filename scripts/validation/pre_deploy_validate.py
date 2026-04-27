#!/usr/bin/env python3
"""
pre_deploy_validate.py — MetricStream WAF Pre-Deployment Validation

Runs a suite of checks on terraform.tfvars before any WAF deployment.
Catches configuration errors that Terraform plan won't catch until apply.

Usage:
    python3 scripts/validation/pre_deploy_validate.py --env prod
    python3 scripts/validation/pre_deploy_validate.py --env nonprod
    python3 scripts/validation/pre_deploy_validate.py --env prod --tfvars path/to/custom.tfvars
"""

import sys
import re
import json
import argparse
import ipaddress
from pathlib import Path
from typing import Any

# ── ANSI colours ─────────────────────────────────────────────────────────────
RED   = "\033[91m"
GRN   = "\033[92m"
YEL   = "\033[93m"
BLU   = "\033[94m"
RESET = "\033[0m"
BOLD  = "\033[1m"

PASS = f"{GRN}✓ PASS{RESET}"
FAIL = f"{RED}✗ FAIL{RESET}"
WARN = f"{YEL}⚠ WARN{RESET}"
INFO = f"{BLU}ℹ INFO{RESET}"

# ── WCU budget ───────────────────────────────────────────────────────────────
WCU_LIMIT = 5000
GLOBAL_RULE_WCUS = {
    "AmazonIpReputationList":    25,
    "AnonymousIpList":           50,
    "KnownBadInputsRuleSet":    200,
    "CommonRuleSet":             700,
    "GlobalRateLimit":            2,  # rate-based rule is 2 WCU
}
IP_WHITELIST_RULE_WCU = 5  # per scope-down rule (AND + byte_match + ip_set_ref)


def header(msg: str) -> None:
    print(f"\n{BOLD}{BLU}{'─'*60}{RESET}")
    print(f"{BOLD}{BLU}  {msg}{RESET}")
    print(f"{BOLD}{BLU}{'─'*60}{RESET}")


def result(check: str, passed: bool, detail: str = "", warn: bool = False) -> bool:
    icon = WARN if warn else (PASS if passed else FAIL)
    print(f"  {icon}  {check}")
    if detail:
        prefix = "    " + (" " * 7)
        print(f"{prefix}{detail}")
    return passed or warn


# ── HCL tfvars parser (minimal — handles maps and lists) ─────────────────────

def parse_tfvars(path: Path) -> dict[str, Any]:
    """
    Very lightweight HCL tfvars parser.
    Handles: string = "value", number = 123, list = [...], nested map = {...}
    Not a full HCL parser — convert to JSON for complex structures if needed.
    """
    content = path.read_text()

    # Strip HCL comments
    content = re.sub(r'#[^\n]*', '', content)
    content = re.sub(r'//[^\n]*', '', content)

    parsed: dict[str, Any] = {}

    # Rate limit threshold
    m = re.search(r'rate_limit_threshold\s*=\s*(\d+)', content)
    if m:
        parsed["rate_limit_threshold"] = int(m.group(1))

    # AWS region
    m = re.search(r'aws_region\s*=\s*"([^"]+)"', content)
    if m:
        parsed["aws_region"] = m.group(1)

    # Customer IP whitelists — extract each customer block
    customers = {}
    # Match each "customer-key" = { ... } block inside customer_ip_whitelists = { ... }
    outer = re.search(r'customer_ip_whitelists\s*=\s*\{(.*?)\n\}', content, re.DOTALL)
    if outer:
        block = outer.group(1)
        # Find each customer entry
        for m in re.finditer(r'"([^"]+)"\s*=\s*\{([^}]+)\}', block, re.DOTALL):
            key = m.group(1)
            body = m.group(2)

            # Parse hostname
            hm = re.search(r'hostname\s*=\s*"([^"]+)"', body)
            hostname = hm.group(1) if hm else None

            # Parse priority_offset
            pm = re.search(r'priority_offset\s*=\s*(\d+)', body)
            priority_offset = int(pm.group(1)) if pm else None

            # Parse allowed_ip_cidrs — collect quoted strings in list
            ipv4_cidrs = re.findall(r'"(\d+\.\d+\.\d+\.\d+/\d+)"', body)
            single_ips = re.findall(r'"(\d+\.\d+\.\d+\.\d+)"', body)
            all_ipv4 = ipv4_cidrs + single_ips

            customers[key] = {
                "hostname": hostname,
                "allowed_ip_cidrs": all_ipv4,
                "priority_offset": priority_offset,
            }

    parsed["customer_ip_whitelists"] = customers

    # CRS rule overrides
    crs_overrides = re.findall(r'rule_name\s*=\s*"([^"]+)"', content)
    parsed["crs_rule_overrides"] = crs_overrides

    return parsed


# ── Validation checks ─────────────────────────────────────────────────────────

def check_rate_limit(config: dict) -> bool:
    threshold = config.get("rate_limit_threshold", 2000)
    ok = threshold >= 100
    detail = f"threshold={threshold}" + (" (AWS minimum is 100)" if not ok else "")
    return result("Rate limit threshold >= 100 (AWS minimum)", ok, detail)


def check_unique_priority_offsets(config: dict) -> bool:
    customers = config.get("customer_ip_whitelists", {})
    offsets = [v.get("priority_offset") for v in customers.values() if v.get("priority_offset") is not None]
    duplicates = [x for x in offsets if offsets.count(x) > 1]
    ok = len(duplicates) == 0
    detail = f"Duplicate offsets: {set(duplicates)}" if not ok else f"{len(customers)} customers, all offsets unique"
    return result("Customer priority offsets are unique", ok, detail)


def check_offset_range(config: dict) -> bool:
    customers = config.get("customer_ip_whitelists", {})
    bad = {k: v["priority_offset"] for k, v in customers.items() if v.get("priority_offset", 0) > 89}
    ok = len(bad) == 0
    detail = f"Out-of-range offsets: {bad}" if not ok else f"All offsets in 0–89 range"
    return result("All priority offsets in valid range (0–89)", ok, detail)


def check_ip_cidr_syntax(config: dict) -> bool:
    customers = config.get("customer_ip_whitelists", {})
    errors = []
    for cust_key, v in customers.items():
        for cidr in v.get("allowed_ip_cidrs", []):
            try:
                ipaddress.ip_network(cidr, strict=False)
            except ValueError:
                errors.append(f"{cust_key}: invalid CIDR '{cidr}'")
    ok = len(errors) == 0
    detail = "; ".join(errors) if errors else f"All CIDRs valid"
    return result("All IP CIDRs are valid notation", ok, detail)


def check_no_public_cidrs_without_whitelist(config: dict) -> bool:
    """Warn if any customer has 0.0.0.0/0 in their allowlist — that defeats the purpose."""
    customers = config.get("customer_ip_whitelists", {})
    warnings = []
    for k, v in customers.items():
        if "0.0.0.0/0" in v.get("allowed_ip_cidrs", []) or "::/0" in v.get("allowed_ip_cidrs", []):
            warnings.append(k)
    ok = len(warnings) == 0
    detail = f"Customers with 0.0.0.0/0 (allowlist defeats purpose): {warnings}" if warnings else "No catch-all CIDRs detected"
    return result("No catch-all CIDRs (0.0.0.0/0) in customer allowlists", ok, detail, warn=not ok)


def check_wcu_budget(config: dict) -> bool:
    customers = config.get("customer_ip_whitelists", {})
    global_wcu = sum(GLOBAL_RULE_WCUS.values())
    whitelist_wcu = len(customers) * IP_WHITELIST_RULE_WCU
    total_wcu = global_wcu + whitelist_wcu
    ok = total_wcu < WCU_LIMIT
    detail = (f"Global rules: {global_wcu} WCU | "
              f"IP whitelist rules ({len(customers)}): {whitelist_wcu} WCU | "
              f"Total: {total_wcu}/{WCU_LIMIT} WCU")
    if total_wcu > WCU_LIMIT * 0.8:
        return result(f"WCU budget under limit ({total_wcu}/{WCU_LIMIT})", ok, detail, warn=True)
    return result(f"WCU budget under limit ({total_wcu}/{WCU_LIMIT})", ok, detail)


def check_hostnames_are_fqdn(config: dict) -> bool:
    customers = config.get("customer_ip_whitelists", {})
    bad = {k: v["hostname"] for k, v in customers.items()
           if v.get("hostname") and (not "." in v["hostname"] or v["hostname"].startswith("."))}
    ok = len(bad) == 0
    detail = f"Invalid hostnames: {bad}" if not ok else "All hostnames look like valid FQDNs"
    return result("All customer hostnames are valid FQDNs", ok, detail)


def check_no_empty_ip_lists(config: dict) -> bool:
    customers = config.get("customer_ip_whitelists", {})
    empty = [k for k, v in customers.items() if len(v.get("allowed_ip_cidrs", [])) == 0]
    ok = len(empty) == 0
    detail = f"Customers with empty IP lists: {empty}" if not ok else "All customers have at least one IP"
    return result("All customers have at least one IP in allowlist", ok, detail)


def check_crs_overrides_have_justification(config: dict) -> bool:
    # We just check count here — full justification check requires parsing complex HCL
    overrides = config.get("crs_rule_overrides", [])
    ok = True  # Can't easily validate justification text from simple parse
    detail = f"{len(overrides)} CRS overrides configured" + (
        " — ensure each has ticket + approval in tfvars comment" if overrides else ""
    )
    return result("CRS rule overrides noted", ok, detail, warn=len(overrides) > 0)


def check_region(config: dict) -> bool:
    region = config.get("aws_region", "us-east-1")
    valid_regions = [
        "us-east-1", "us-east-2", "us-west-1", "us-west-2",
        "eu-west-1", "eu-west-2", "eu-central-1",
        "ap-southeast-1", "ap-southeast-2", "ap-northeast-1",
    ]
    ok = region in valid_regions
    detail = f"Region: {region}"
    return result("AWS region is a recognised region", ok, detail, warn=not ok)


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(description="MetricStream WAF pre-deployment validation")
    parser.add_argument("--env", choices=["prod", "nonprod"], required=True)
    parser.add_argument("--tfvars", help="Path to tfvars file (default: terraform/environments/<env>/terraform.tfvars)")
    args = parser.parse_args()

    base = Path(__file__).parent.parent.parent
    tfvars_path = Path(args.tfvars) if args.tfvars else base / "terraform" / "environments" / args.env / "terraform.tfvars"

    header(f"MetricStream WAF — Pre-Deployment Validation ({args.env.upper()})")
    print(f"  {INFO}  tfvars: {tfvars_path}")

    if not tfvars_path.exists():
        print(f"\n  {FAIL}  tfvars file not found: {tfvars_path}")
        return 1

    config = parse_tfvars(tfvars_path)
    customers = config.get("customer_ip_whitelists", {})
    print(f"  {INFO}  Found {len(customers)} customer(s) with IP whitelisting")

    header("Configuration Checks")
    checks = [
        check_rate_limit(config),
        check_unique_priority_offsets(config),
        check_offset_range(config),
        check_ip_cidr_syntax(config),
        check_no_public_cidrs_without_whitelist(config),
        check_no_empty_ip_lists(config),
        check_hostnames_are_fqdn(config),
        check_wcu_budget(config),
        check_crs_overrides_have_justification(config),
        check_region(config),
    ]

    passed = sum(1 for c in checks if c)
    failed = len(checks) - passed

    header("Summary")
    print(f"  Checks run:    {len(checks)}")
    print(f"  {GRN}Passed:{RESET}        {passed}")
    if failed > 0:
        print(f"  {RED}Failed:{RESET}        {failed}")
        print(f"\n  {RED}✗ Validation FAILED — fix errors before deploying{RESET}\n")
        return 1
    else:
        print(f"\n  {GRN}✓ All checks passed — safe to proceed with terraform plan{RESET}\n")
        return 0


if __name__ == "__main__":
    sys.exit(main())
