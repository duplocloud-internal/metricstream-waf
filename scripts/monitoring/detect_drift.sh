#!/usr/bin/env bash
# detect_drift.sh — MetricStream WAF Drift Detection
#
# Runs terraform plan in both environments and alerts if drift is detected.
# Intended to run daily via cron or CI/CD schedule.
#
# Usage:
#   ./scripts/monitoring/detect_drift.sh [--slack-webhook <url>] [--env <prod|nonprod|all>]
#
# Exit codes:
#   0 — No drift
#   1 — Drift detected or error
#   2 — Terraform error

set -euo pipefail

RED='\033[91m'; GRN='\033[92m'; YEL='\033[93m'; RESET='\033[0m'; BOLD='\033[1m'

SLACK_WEBHOOK=""
ENV_TARGET="all"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DRIFT_DETECTED=0
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

while [[ $# -gt 0 ]]; do
  case $1 in
    --slack-webhook) SLACK_WEBHOOK="$2"; shift 2 ;;
    --env)           ENV_TARGET="$2";   shift 2 ;;
    *) echo "Unknown arg: $1"; exit 1 ;;
  esac
done

log() { echo -e "[$(date -u +%H:%M:%S)] $1"; }

send_slack_alert() {
  local env="$1"
  local message="$2"
  if [[ -n "$SLACK_WEBHOOK" ]]; then
    curl -s -X POST "$SLACK_WEBHOOK" \
      -H 'Content-type: application/json' \
      --data "{
        \"blocks\": [
          {
            \"type\": \"header\",
            \"text\": { \"type\": \"plain_text\", \"text\": \"⚠️ WAF Configuration Drift Detected\" }
          },
          {
            \"type\": \"section\",
            \"fields\": [
              { \"type\": \"mrkdwn\", \"text\": \"*Environment:*\n${env}\" },
              { \"type\": \"mrkdwn\", \"text\": \"*Time:*\n${TIMESTAMP}\" }
            ]
          },
          {
            \"type\": \"section\",
            \"text\": { \"type\": \"mrkdwn\", \"text\": \"*Action Required:*\n${message}\" }
          },
          {
            \"type\": \"section\",
            \"text\": { \"type\": \"mrkdwn\", \"text\": \"Manual changes to WAF are prohibited in production. Investigate the source of the drift immediately.\nRunbook: <https://github.com/metricstream/metricstream-waf/blob/main/docs/runbook.md|WAF Runbook>\" }
          }
        ]
      }" > /dev/null
    log "Slack alert sent for ${env}"
  fi
}

check_env_drift() {
  local env="$1"
  local tf_dir="${REPO_ROOT}/terraform/environments/${env}"

  log "Checking ${env} environment for drift..."

  if [[ ! -d "$tf_dir" ]]; then
    log "${RED}ERROR: Terraform directory not found: ${tf_dir}${RESET}"
    return 2
  fi

  cd "$tf_dir"

  # Init if needed (quiet mode)
  if [[ ! -d ".terraform" ]]; then
    log "Initializing Terraform for ${env}..."
    terraform init -input=false -backend=true > /dev/null 2>&1
  fi

  # Run plan with -detailed-exitcode:
  #   Exit 0 = No changes (no drift)
  #   Exit 1 = Error
  #   Exit 2 = Changes detected (drift!)
  local plan_output
  local exit_code=0

  plan_output=$(terraform plan \
    -input=false \
    -detailed-exitcode \
    -compact-warnings \
    -no-color \
    2>&1) || exit_code=$?

  case $exit_code in
    0)
      log "${GRN}✓ ${env}: No drift detected${RESET}"
      ;;
    2)
      log "${YEL}⚠ ${env}: DRIFT DETECTED — WAF configuration has changed outside Terraform${RESET}"
      DRIFT_DETECTED=1

      # Extract the change summary
      CHANGE_SUMMARY=$(echo "$plan_output" | grep -E "^(  [+~-]|Plan:)" | head -20 || true)

      echo ""
      echo "────────────────────────────────────────────"
      echo "DRIFT DETAILS (${env}):"
      echo "$CHANGE_SUMMARY"
      echo "────────────────────────────────────────────"
      echo ""

      send_slack_alert "$env" "Drift detected in ${env} WAF. Changes:\n\`\`\`${CHANGE_SUMMARY}\`\`\`"

      # Write drift report
      local report_dir="${REPO_ROOT}/drift-reports"
      mkdir -p "$report_dir"
      local report_file="${report_dir}/drift-${env}-$(date -u +%Y%m%d-%H%M%S).txt"
      {
        echo "WAF Drift Report"
        echo "Environment: ${env}"
        echo "Timestamp: ${TIMESTAMP}"
        echo "─────────────────────────────────────────"
        echo "$plan_output"
      } > "$report_file"
      log "Drift report written to: ${report_file}"
      ;;
    1)
      log "${RED}✗ ${env}: Terraform plan ERROR — check configuration${RESET}"
      echo "$plan_output" | tail -20
      return 1
      ;;
  esac
}

# ── Main ──────────────────────────────────────────────────────────────────────
log "${BOLD}MetricStream WAF Drift Detection${RESET}"
log "Timestamp: ${TIMESTAMP}"

case "$ENV_TARGET" in
  prod)    check_env_drift "prod";;
  nonprod) check_env_drift "nonprod";;
  all)
    check_env_drift "nonprod"
    check_env_drift "prod"
    ;;
  *)
    echo "Unknown env target: ${ENV_TARGET}"
    exit 1
    ;;
esac

if [[ "$DRIFT_DETECTED" -eq 1 ]]; then
  log ""
  log "${YEL}${BOLD}DRIFT DETECTED — ACTION REQUIRED:${RESET}"
  log "  1. Investigate who made manual changes (check AWS CloudTrail)"
  log "  2. If emergency change: update Terraform to match, create retroactive PR"
  log "  3. If unauthorized: revert via terraform apply and file security incident"
  log "  4. See runbook: docs/runbook.md#drift-detection"
  exit 1
else
  log ""
  log "${GRN}${BOLD}✓ No drift detected in any environment${RESET}"
  exit 0
fi
