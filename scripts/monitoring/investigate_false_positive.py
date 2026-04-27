#!/usr/bin/env python3
"""
investigate_false_positive.py — MetricStream WAF False-Positive Investigation

Queries CloudWatch Insights to analyze WAF block events for a given IP or customer.
Generates a structured report to help determine if blocks are false positives.

Usage:
    # Investigate blocks from a specific IP
    python3 scripts/monitoring/investigate_false_positive.py \\
        --env prod --region us-east-1 --ip 203.0.113.50

    # Investigate blocks for a specific customer hostname
    python3 scripts/monitoring/investigate_false_positive.py \\
        --env prod --region us-east-1 --hostname customer-a.metricstream.com

    # Combined: specific IP + last 24 hours
    python3 scripts/monitoring/investigate_false_positive.py \\
        --env prod --region us-east-1 --ip 203.0.113.50 --hours 24
"""

import sys
import time
import json
import argparse
import datetime
from typing import Optional

try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
except ImportError:
    print("ERROR: boto3 not installed. Run: pip install boto3")
    sys.exit(1)

# ── ANSI colours ─────────────────────────────────────────────────────────────
RED = "\033[91m"; GRN = "\033[92m"; YEL = "\033[93m"; BLU = "\033[94m"
BOLD = "\033[1m"; RESET = "\033[0m"


def header(msg: str) -> None:
    print(f"\n{BOLD}{BLU}{'─'*60}{RESET}")
    print(f"{BOLD}{BLU}  {msg}{RESET}")
    print(f"{BOLD}{BLU}{'─'*60}{RESET}")


def run_insights_query(logs_client, log_group: str, query: str, hours: int) -> list[dict]:
    """Run a CloudWatch Insights query and wait for results."""
    end_time = int(time.time())
    start_time = end_time - (hours * 3600)

    print(f"  Querying last {hours} hours of WAF logs...")

    try:
        response = logs_client.start_query(
            logGroupName=log_group,
            startTime=start_time,
            endTime=end_time,
            queryString=query,
            limit=100,
        )
        query_id = response["queryId"]
    except ClientError as e:
        if "ResourceNotFoundException" in str(e):
            print(f"  {RED}ERROR: Log group '{log_group}' not found.{RESET}")
            print(f"  Ensure WAF logging is configured and the environment is correct.")
        else:
            print(f"  {RED}ERROR: {e}{RESET}")
        return []

    # Poll for results
    while True:
        time.sleep(1)
        status = logs_client.get_query_results(queryId=query_id)
        if status["status"] in ("Complete", "Failed", "Cancelled"):
            break
        sys.stdout.write(".")
        sys.stdout.flush()

    print()

    if status["status"] != "Complete":
        print(f"  {YEL}Query {status['status']} — no results{RESET}")
        return []

    results = []
    for row in status.get("results", []):
        results.append({item["field"]: item["value"] for item in row})
    return results


def print_table(rows: list[dict], columns: list[str], max_width: int = 50) -> None:
    if not rows:
        print(f"  {YEL}No results found{RESET}")
        return

    # Calculate column widths
    widths = {col: len(col) for col in columns}
    for row in rows:
        for col in columns:
            val = str(row.get(col, ""))[:max_width]
            widths[col] = max(widths[col], len(val))

    # Header
    header_row = "  " + " │ ".join(col.ljust(widths[col]) for col in columns)
    sep = "  " + "─┼─".join("─" * widths[col] for col in columns)
    print(header_row)
    print(sep)

    # Rows
    for row in rows:
        cells = [str(row.get(col, ""))[:max_width].ljust(widths[col]) for col in columns]
        print("  " + " │ ".join(cells))


def investigate_ip(logs_client: any, log_group: str, ip: str, hours: int) -> None:
    header(f"Block Events for IP: {ip}")

    query = f"""
fields @timestamp, httpRequest.clientIp, httpRequest.uri, httpRequest.httpMethod,
       terminatingRuleId, action
| filter httpRequest.clientIp = "{ip}"
| filter action = "BLOCK"
| sort @timestamp desc
| limit 50
"""

    results = run_insights_query(logs_client, log_group, query, hours)

    if results:
        print(f"  {RED}Found {len(results)} block event(s) for this IP{RESET}")
        print_table(results, ["@timestamp", "httpRequest.uri", "httpRequest.httpMethod", "terminatingRuleId"])
    else:
        print(f"  {GRN}No block events found for IP {ip} in the last {hours} hours{RESET}")
        print(f"  → This IP was not blocked. Check application logs for errors.")


def investigate_hostname(logs_client: any, log_group: str, hostname: str, hours: int) -> None:
    header(f"Block Events for Hostname: {hostname}")

    # CloudWatch Insights doesn't support filtering on array elements directly,
    # so we search across all blocks and filter by the host in post-processing.
    query = f"""
fields @timestamp, httpRequest.clientIp, httpRequest.uri, terminatingRuleId, action
| filter action = "BLOCK"
| filter httpRequest.headers.0.value like "{hostname}"
    or httpRequest.headers.1.value like "{hostname}"
    or httpRequest.headers.2.value like "{hostname}"
| stats count() as block_count by terminatingRuleId
| sort block_count desc
"""

    results = run_insights_query(logs_client, log_group, query, hours)

    if results:
        print(f"  Blocks by rule for {hostname}:")
        print_table(results, ["terminatingRuleId", "block_count"])
    else:
        print(f"  {GRN}No block events found for hostname {hostname}{RESET}")


def block_summary_by_rule(logs_client: any, log_group: str, hours: int) -> None:
    header("Block Summary by Rule (All Traffic)")

    query = """
fields terminatingRuleId, action
| filter action = "BLOCK"
| stats count() as block_count by terminatingRuleId
| sort block_count desc
"""

    results = run_insights_query(logs_client, log_group, query, hours)
    if results:
        print_table(results, ["terminatingRuleId", "block_count"])


def top_blocked_ips(logs_client: any, log_group: str, hours: int) -> None:
    header("Top Blocked IP Addresses")

    query = """
fields httpRequest.clientIp, httpRequest.country, terminatingRuleId
| filter action = "BLOCK"
| stats count() as block_count by httpRequest.clientIp, httpRequest.country
| sort block_count desc
| limit 20
"""

    results = run_insights_query(logs_client, log_group, query, hours)
    if results:
        print_table(results, ["httpRequest.clientIp", "httpRequest.country", "block_count"])


def false_positive_likelihood(logs_client: any, log_group: str, ip: str, hostname: Optional[str], hours: int) -> None:
    """Heuristic: if the IP is hitting known-pattern URIs, likely legitimate."""
    header("False Positive Assessment")

    filter_clause = f'filter httpRequest.clientIp = "{ip}"'
    if hostname:
        filter_clause += f'\n| filter httpRequest.headers.0.value like "{hostname}"'

    query = f"""
fields @timestamp, httpRequest.clientIp, httpRequest.uri, terminatingRuleId, terminatingRuleMatchDetails
| {filter_clause}
| filter action = "BLOCK"
| sort @timestamp desc
| limit 20
"""

    results = run_insights_query(logs_client, log_group, query, hours)

    if not results:
        print(f"  {GRN}No blocks found — IP {ip} was NOT blocked recently{RESET}")
        return

    # Heuristic analysis
    rules_triggered = set(r.get("terminatingRuleId", "") for r in results)
    uris = [r.get("httpRequest.uri", "") for r in results]

    print(f"  Rules triggered: {', '.join(rules_triggered)}")
    print(f"  URIs affected:   {', '.join(set(uris))}")
    print()

    # Guidance
    guidance = []

    if any("IPReputation" in r for r in rules_triggered):
        guidance.append(f"{RED}IP Reputation hit — this IP is on a threat intelligence list. Likely NOT a false positive.{RESET}")

    if any("AnonymousIP" in r for r in rules_triggered):
        guidance.append(f"{YEL}Anonymous IP hit — IP may be a VPN/proxy. Check if customer uses corporate VPN.{RESET}")

    if any("CommonRuleSet" in r or "CRS" in r for r in rules_triggered):
        guidance.append(f"{YEL}CRS hit — review the terminatingRuleMatchDetails to see what pattern triggered.")
        guidance.append(f"    If legitimate traffic, add a rule_action_override in terraform.tfvars.")

    if any("KnownBadInputs" in r for r in rules_triggered):
        guidance.append(f"{RED}Known Bad Inputs hit — this matches exploit patterns. Very unlikely to be a false positive.{RESET}")

    if any("IPWhitelist" in r for r in rules_triggered):
        guidance.append(f"{YEL}IP Whitelist block — customer's IP is not in their approved IP set. Update customer's IP list in terraform.tfvars.{RESET}")

    if any("RateLimit" in r for r in rules_triggered):
        guidance.append(f"{YEL}Rate limit hit — IP exceeded request threshold. Check if legitimate bulk operation.{RESET}")

    if guidance:
        print(f"  {BOLD}Assessment:{RESET}")
        for g in guidance:
            print(f"  • {g}")
    else:
        print(f"  {YEL}Could not determine likelihood — review terminatingRuleMatchDetails manually{RESET}")

    print()
    print(f"  {BOLD}Next steps:{RESET}")
    print(f"  1. Share this report with the security team")
    print(f"  2. If false positive confirmed: follow docs/runbook.md#false-positive-handling")
    print(f"  3. For P1/P2: implement temporary override immediately (Section 9, Step 3)")


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(description="Investigate WAF false positives via CloudWatch Insights")
    parser.add_argument("--env",      required=True, choices=["prod", "nonprod"])
    parser.add_argument("--region",   default="us-east-1")
    parser.add_argument("--ip",       help="Customer IP address to investigate")
    parser.add_argument("--hostname", help="Customer hostname to investigate")
    parser.add_argument("--hours",    type=int, default=48, help="Look-back window in hours (default: 48)")
    parser.add_argument("--summary",  action="store_true", help="Show overall block summary for all rules")
    args = parser.parse_args()

    if not args.ip and not args.hostname and not args.summary:
        parser.error("Provide at least one of: --ip, --hostname, --summary")

    log_group = f"/aws/waf/metricstream-{args.env}"

    print(f"\n{BOLD}{BLU}MetricStream WAF — False Positive Investigation{RESET}")
    print(f"  Environment: {args.env}")
    print(f"  Region:      {args.region}")
    print(f"  Log group:   {log_group}")
    print(f"  Look-back:   {args.hours} hours")

    try:
        logs_client = boto3.client("logs", region_name=args.region)
    except NoCredentialsError:
        print(f"\n{RED}ERROR: AWS credentials not configured. Run 'aws configure' or set environment variables.{RESET}")
        return 1

    if args.summary:
        block_summary_by_rule(logs_client, log_group, args.hours)
        top_blocked_ips(logs_client, log_group, args.hours)

    if args.ip:
        investigate_ip(logs_client, log_group, args.ip, args.hours)
        if args.hostname:
            investigate_hostname(logs_client, log_group, args.hostname, args.hours)
        false_positive_likelihood(logs_client, log_group, args.ip, args.hostname, args.hours)

    elif args.hostname:
        investigate_hostname(logs_client, log_group, args.hostname, args.hours)

    print()
    return 0


if __name__ == "__main__":
    sys.exit(main())
