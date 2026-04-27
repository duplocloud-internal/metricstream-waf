#!/usr/bin/env python3
"""
orchestrate.py — MetricStream WAF Multi-Account/Region Deployment Orchestrator

Reads config/deployments.yaml and drives terraform init + plan/apply/drift
for one or all deployments.

The same terraform root (terraform/deployment/) is used for every deployment.
Backend config and all WAF variables are injected per deployment — no manual
tfvars files needed.

USAGE
─────
  # Plan all deployments
  python3 scripts/orchestrate.py plan

  # Apply a specific deployment
  python3 scripts/orchestrate.py apply --deployment prod-us-east-1

  # Daily drift check on all deployments
  python3 scripts/orchestrate.py drift

  # See what's configured
  python3 scripts/orchestrate.py list

CREDENTIALS
───────────
  AWS credentials must be pre-configured for the target account before
  this script runs. In CI/CD, the GitHub Actions workflow assumes the right
  IAM role per deployment before calling this script. Locally, use:

    aws sso login --profile my-profile
    AWS_PROFILE=my-profile python3 scripts/orchestrate.py plan --deployment nonprod-us-east-1
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:
    print("ERROR: pyyaml is required. Run: pip install pyyaml", file=sys.stderr)
    sys.exit(1)

# ── Paths ─────────────────────────────────────────────────────────────────────
REPO_ROOT   = Path(__file__).parent.parent
CONFIG_PATH = REPO_ROOT / "config" / "deployments.yaml"
TF_DIR      = REPO_ROOT / "terraform" / "deployment"

# ── Colours ───────────────────────────────────────────────────────────────────
RED   = "\033[91m"
GRN   = "\033[92m"
YEL   = "\033[93m"
BLU   = "\033[94m"
BOLD  = "\033[1m"
RESET = "\033[0m"


def log(msg: str, colour: str = RESET) -> None:
    print(f"{colour}{msg}{RESET}", flush=True)


def banner(msg: str) -> None:
    width = 64
    log(f"\n{BOLD}{BLU}{'═' * width}{RESET}")
    log(f"{BOLD}{BLU}  {msg}{RESET}")
    log(f"{BOLD}{BLU}{'═' * width}{RESET}")


# ── Config loading ─────────────────────────────────────────────────────────────

def load_config() -> dict[str, Any]:
    if not CONFIG_PATH.exists():
        log(f"Config not found: {CONFIG_PATH}", RED)
        sys.exit(1)
    with open(CONFIG_PATH) as f:
        return yaml.safe_load(f)


# ── tfvars JSON generation ─────────────────────────────────────────────────────

def _build_tfvars(deployment_id: str, dep: dict[str, Any]) -> dict[str, Any]:
    """Build the complete variable map for a deployment."""
    return {
        "deployment_id":              deployment_id,
        "account_id":                 str(dep["account_id"]),
        "region":                     dep["region"],
        "environment":                dep["environment"],
        "rate_limit_threshold":       dep.get("rate_limit_threshold", 2000),
        "log_retention_days":         dep.get("log_retention_days", 365),
        "cloudwatch_retention_days":  dep.get("cloudwatch_retention_days", 90),
        "object_lock_retention_days": dep.get("object_lock_retention_days", 90),
        "alarm_high_block_threshold": dep.get("alarm_high_block_threshold", 1000),
        "alarm_low_allowed_threshold":dep.get("alarm_low_allowed_threshold", 100),
        "alarm_sns_arns":             dep.get("alarm_sns_arns", []),
        "kms_key_arn":                dep.get("kms_key_arn", ""),
        "customer_ip_whitelists":     dep.get("customer_ip_whitelists", {}),
        "crs_rule_overrides":         dep.get("crs_rule_overrides", []),
        "managed_rule_modes":         dep.get("managed_rule_modes", {}),
    }


def _write_tfvars(deployment_id: str, dep: dict[str, Any]) -> str:
    """Write a temporary .tfvars.json file; return its path."""
    tfvars = _build_tfvars(deployment_id, dep)
    fd, path = tempfile.mkstemp(suffix=f"-{deployment_id}.tfvars.json",
                                 prefix="metricstream-waf-")
    with os.fdopen(fd, "w") as f:
        json.dump(tfvars, f, indent=2)
    return path


# ── Backend config ─────────────────────────────────────────────────────────────

def _resolve_backend(dep: dict[str, Any], config: dict[str, Any]) -> dict[str, Any]:
    """
    Resolve the Terraform state backend for a deployment.

    Priority (most → least specific):
      1. Per-deployment  state_backend  key inside the deployment entry
      2. state_backends[account_id]     per-account map at config root
      3. state_backend                  legacy single-bucket fallback
    """
    if "state_backend" in dep:
        return dep["state_backend"]

    account_id = str(dep["account_id"])
    if "state_backends" in config and account_id in config["state_backends"]:
        return config["state_backends"][account_id]

    if "state_backend" in config:
        return config["state_backend"]

    log(
        f"ERROR: No state backend configured for account {account_id}.\n"
        "  Add an entry to state_backends in config/deployments.yaml:\n"
        f'    state_backends:\n'
        f'      "{account_id}":\n'
        f'        bucket:         "metricstream-terraform-state-{account_id}"\n'
        f'        region:         "us-east-1"\n'
        f'        dynamodb_table: "metricstream-terraform-locks"',
        RED,
    )
    sys.exit(1)


def _backend_config_args(deployment_id: str, backend: dict[str, Any]) -> list[str]:
    """Return -backend-config flags for terraform init."""
    return [
        f"-backend-config=bucket={backend['bucket']}",
        f"-backend-config=key=waf/{deployment_id}/terraform.tfstate",
        f"-backend-config=region={backend['region']}",
        f"-backend-config=dynamodb_table={backend['dynamodb_table']}",
        "-backend-config=encrypt=true",
    ]


# ── Terraform runners ──────────────────────────────────────────────────────────

def _run(cmd: list[str]) -> int:
    log(f"  $ {' '.join(cmd)}", BLU)
    return subprocess.run(cmd, cwd=TF_DIR).returncode


def _tf_init(deployment_id: str, backend: dict[str, Any]) -> int:
    return _run([
        "terraform", "init",
        "-input=false",
        "-reconfigure",   # re-init backend config for each deployment
        *_backend_config_args(deployment_id, backend),
    ])


def _tf_plan(deployment_id: str, tfvars_path: str, save_plan: bool = True) -> int:
    cmd = [
        "terraform", "plan",
        "-input=false",
        "-no-color",
        f"-var-file={tfvars_path}",
    ]
    if save_plan:
        cmd.append(f"-out={TF_DIR}/{deployment_id}.tfplan")
    return _run(cmd)


def _tf_apply(deployment_id: str, tfvars_path: str) -> int:
    plan_file = TF_DIR / f"{deployment_id}.tfplan"
    if plan_file.exists():
        return _run(["terraform", "apply", "-input=false", "-no-color", str(plan_file)])
    # No saved plan — apply directly (used when called standalone, e.g. CI auto-apply)
    return _run([
        "terraform", "apply",
        "-input=false",
        "-auto-approve",
        "-no-color",
        f"-var-file={tfvars_path}",
    ])


def _tf_drift(tfvars_path: str) -> tuple[int, bool]:
    """Return (returncode, drift_detected). Exit code 2 = changes present = drift."""
    result = subprocess.run(
        [
            "terraform", "plan",
            "-input=false",
            "-detailed-exitcode",
            "-compact-warnings",
            "-no-color",
            f"-var-file={tfvars_path}",
        ],
        cwd=TF_DIR,
    )
    return result.returncode, result.returncode == 2


# ── Per-deployment driver ──────────────────────────────────────────────────────

def _deploy_one(deployment_id: str, dep: dict[str, Any], config: dict[str, Any],
                action: str) -> bool:
    banner(f"{action.upper()} — {deployment_id}")
    log(f"  Account  : {dep['account_id']}", BLU)
    log(f"  Region   : {dep['region']}", BLU)
    log(f"  Env      : {dep['environment']}", BLU)

    backend = _resolve_backend(dep, config)
    log(f"  State    : s3://{backend['bucket']}/waf/{deployment_id}/terraform.tfstate", BLU)

    tfvars_path = _write_tfvars(deployment_id, dep)
    try:
        if _tf_init(deployment_id, backend) != 0:
            log(f"  ✗ init failed — {deployment_id}", RED)
            return False

        rc = _tf_plan(deployment_id, tfvars_path) if action == "plan" \
             else _tf_apply(deployment_id, tfvars_path)
    finally:
        os.unlink(tfvars_path)

    if rc == 0:
        log(f"  ✓ {action} succeeded — {deployment_id}", GRN)
        return True
    log(f"  ✗ {action} failed (exit {rc}) — {deployment_id}", RED)
    return False


def _drift_one(deployment_id: str, dep: dict[str, Any], config: dict[str, Any]) -> bool:
    """Return True if drift was detected."""
    banner(f"DRIFT CHECK — {deployment_id}")
    log(f"  Account : {dep['account_id']}", BLU)
    log(f"  Region  : {dep['region']}", BLU)

    backend = _resolve_backend(dep, config)
    tfvars_path = _write_tfvars(deployment_id, dep)
    try:
        if _tf_init(deployment_id, backend) != 0:
            log(f"  ✗ init failed — {deployment_id}", RED)
            return False
        rc, drifted = _tf_drift(tfvars_path)
    finally:
        os.unlink(tfvars_path)

    if rc == 1:
        log(f"  ✗ terraform error — {deployment_id}", RED)
        return False
    if drifted:
        log(f"  ⚠  DRIFT DETECTED — {deployment_id}", YEL)
        return True
    log(f"  ✓ No drift — {deployment_id}", GRN)
    return False


# ── Actions ───────────────────────────────────────────────────────────────────

def action_list(deployments: dict[str, Any]) -> int:
    banner("Configured Deployments")
    fmt = f"  {{:<30}} {{:<15}} {{:<15}} {{}}"
    log(fmt.format("Deployment ID", "Account ID", "Region", "Environment"), BOLD)
    log("  " + "─" * 62)
    for dep_id, dep in deployments.items():
        env_colour = GRN if dep["environment"] == "prod" else YEL
        log(fmt.format(dep_id, dep["account_id"], dep["region"],
                       f"{env_colour}{dep['environment']}{RESET}"))
    log(f"\n  Total: {len(deployments)} deployment(s)")
    return 0


def action_deploy(deployments: dict[str, Any], config: dict[str, Any],
                  action: str, target: str | None, fail_fast: bool) -> int:
    targets = {target: deployments[target]} if target else deployments
    banner(f"MetricStream WAF — {action.upper()} ({len(targets)} deployment(s))")

    failures = []
    for dep_id, dep in targets.items():
        ok = _deploy_one(dep_id, dep, config, action)
        if not ok:
            failures.append(dep_id)
            if fail_fast:
                break

    banner("Summary")
    log(f"  Targeted : {len(targets)}")
    if failures:
        log(f"  Failed   : {', '.join(failures)}", RED)
        return 1
    log(f"  ✓ All {action} runs succeeded", GRN)
    return 0


def action_drift(deployments: dict[str, Any], config: dict[str, Any],
                 target: str | None) -> int:
    targets = {target: deployments[target]} if target else deployments
    banner(f"MetricStream WAF — DRIFT DETECTION ({len(targets)} deployment(s))")

    drifted = []
    for dep_id, dep in targets.items():
        if _drift_one(dep_id, dep, config):
            drifted.append(dep_id)

    banner("Drift Summary")
    if drifted:
        log(f"  ⚠  Drift detected in: {', '.join(drifted)}", YEL)
        log("  Action required:", YEL)
        log("    1. Check AWS CloudTrail for the source of manual changes", YEL)
        log("    2. Emergency fix: update Terraform, create retroactive PR", YEL)
        log("    3. Unauthorised change: revert via apply, file security incident", YEL)
        return 1
    log(f"  ✓ No drift detected in any deployment", GRN)
    return 0


# ── Entry point ────────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(
        description="MetricStream WAF multi-account/region orchestrator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "action",
        choices=["plan", "apply", "drift", "list"],
        help="Terraform action to run",
    )
    parser.add_argument(
        "--deployment", "-d",
        metavar="ID",
        help="Target a single deployment ID (default: all deployments)",
    )
    parser.add_argument(
        "--fail-fast",
        action="store_true",
        help="Stop after the first deployment failure (default: continue all)",
    )
    args = parser.parse_args()

    config      = load_config()
    deployments = config["deployments"]

    # Validate --deployment argument
    if args.deployment and args.deployment not in deployments:
        log(f"\nDeployment '{args.deployment}' not found in config.", RED)
        log(f"Available deployments:", RED)
        for d in deployments:
            log(f"  - {d}")
        return 1

    if args.action == "list":
        return action_list(deployments)
    elif args.action == "drift":
        return action_drift(deployments, config, args.deployment)
    else:
        return action_deploy(deployments, config, args.action, args.deployment, args.fail_fast)


if __name__ == "__main__":
    sys.exit(main())
