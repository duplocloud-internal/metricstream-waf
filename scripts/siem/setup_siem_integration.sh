#!/usr/bin/env bash
# setup_siem_integration.sh — Configure CloudWatch → SIEM log streaming
#
# Sets up CloudWatch Logs subscription filter to stream WAF block events
# to the MetricStream SIEM in real-time via Lambda or Kinesis Data Firehose.
#
# Usage:
#   # Stream via Lambda
#   ./scripts/siem/setup_siem_integration.sh \
#       --env prod --region us-east-1 \
#       --destination-type lambda \
#       --destination-arn arn:aws:lambda:us-east-1:ACCOUNT:function:siem-ingest
#
#   # Stream via Kinesis Data Firehose
#   ./scripts/siem/setup_siem_integration.sh \
#       --env prod --region us-east-1 \
#       --destination-type kinesis \
#       --destination-arn arn:aws:kinesis:us-east-1:ACCOUNT:stream/siem-ingestion \
#       --role-arn arn:aws:iam::ACCOUNT:role/CloudWatchLogsToKinesis

set -euo pipefail

RED='\033[91m'; GRN='\033[92m'; YEL='\033[93m'; BLU='\033[94m'; RESET='\033[0m'; BOLD='\033[1m'

# ── Defaults ──────────────────────────────────────────────────────────────────
ENV=""
REGION="us-east-1"
DESTINATION_TYPE=""
DESTINATION_ARN=""
ROLE_ARN=""
FILTER_PATTERN=""  # Empty = all WAF log events (BLOCK actions are pre-filtered in WAF config)
DRY_RUN=false

while [[ $# -gt 0 ]]; do
  case $1 in
    --env)              ENV="$2";              shift 2 ;;
    --region)           REGION="$2";           shift 2 ;;
    --destination-type) DESTINATION_TYPE="$2"; shift 2 ;;
    --destination-arn)  DESTINATION_ARN="$2";  shift 2 ;;
    --role-arn)         ROLE_ARN="$2";         shift 2 ;;
    --filter-pattern)   FILTER_PATTERN="$2";   shift 2 ;;
    --dry-run)          DRY_RUN=true;          shift ;;
    *) echo "Unknown arg: $1"; exit 1 ;;
  esac
done

# ── Validation ────────────────────────────────────────────────────────────────
if [[ -z "$ENV" || -z "$DESTINATION_TYPE" || -z "$DESTINATION_ARN" ]]; then
  echo "Usage: $0 --env <prod|nonprod> --destination-type <lambda|kinesis> --destination-arn <arn> [--role-arn <arn>]"
  exit 1
fi

if [[ "$DESTINATION_TYPE" == "kinesis" && -z "$ROLE_ARN" ]]; then
  echo "ERROR: --role-arn is required for Kinesis destination"
  exit 1
fi

LOG_GROUP="/aws/waf/metricstream-${ENV}"
FILTER_NAME="metricstream-waf-${ENV}-to-siem"
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)

echo -e "${BOLD}${BLU}MetricStream WAF — SIEM Integration Setup${RESET}"
echo -e "  Environment:      ${ENV}"
echo -e "  Region:           ${REGION}"
echo -e "  Log group:        ${LOG_GROUP}"
echo -e "  Destination type: ${DESTINATION_TYPE}"
echo -e "  Destination ARN:  ${DESTINATION_ARN}"
echo -e "  Filter name:      ${FILTER_NAME}"
if [[ "$DRY_RUN" == "true" ]]; then
  echo -e "  ${YEL}DRY RUN — no changes will be made${RESET}"
fi
echo ""

# ── Check log group exists ────────────────────────────────────────────────────
echo "Checking log group exists..."
if ! aws logs describe-log-groups \
  --log-group-name-prefix "$LOG_GROUP" \
  --region "$REGION" \
  --query "logGroups[?logGroupName=='${LOG_GROUP}'].logGroupName" \
  --output text | grep -q "$LOG_GROUP"; then
  echo -e "  ${RED}ERROR: Log group '${LOG_GROUP}' not found.${RESET}"
  echo -e "  Ensure WAF has been deployed and logging is configured."
  exit 1
fi
echo -e "  ${GRN}✓ Log group found${RESET}"

# ── Check for existing subscription filter ────────────────────────────────────
echo "Checking for existing subscription filters..."
EXISTING=$(aws logs describe-subscription-filters \
  --log-group-name "$LOG_GROUP" \
  --region "$REGION" \
  --query "subscriptionFilters[].filterName" \
  --output text 2>/dev/null || true)

if echo "$EXISTING" | grep -q "$FILTER_NAME"; then
  echo -e "  ${YEL}⚠ Filter '${FILTER_NAME}' already exists — will be updated${RESET}"
else
  echo -e "  No existing filter named '${FILTER_NAME}' — will create"
fi

# CloudWatch Logs allows max 2 subscription filters per log group
FILTER_COUNT=$(echo "$EXISTING" | wc -w | tr -d ' ')
if [[ "$FILTER_COUNT" -ge 2 && ! "$EXISTING" =~ "$FILTER_NAME" ]]; then
  echo -e "  ${RED}ERROR: Log group already has ${FILTER_COUNT} subscription filters (max 2).${RESET}"
  echo -e "  Remove an existing filter before adding a new one:"
  echo -e "  ${EXISTING}"
  exit 1
fi

# ── Grant CloudWatch Logs permission to invoke Lambda (if applicable) ─────────
if [[ "$DESTINATION_TYPE" == "lambda" ]]; then
  echo "Granting CloudWatch Logs permission to invoke Lambda..."
  FUNCTION_NAME=$(echo "$DESTINATION_ARN" | awk -F: '{print $NF}')
  STATEMENT_ID="metricstream-waf-${ENV}-logs-invoke"

  # Remove existing policy statement (ignore errors)
  aws lambda remove-permission \
    --function-name "$FUNCTION_NAME" \
    --statement-id "$STATEMENT_ID" \
    --region "$REGION" 2>/dev/null || true

  if [[ "$DRY_RUN" == "false" ]]; then
    aws lambda add-permission \
      --function-name "$FUNCTION_NAME" \
      --statement-id "$STATEMENT_ID" \
      --action lambda:InvokeFunction \
      --principal "logs.${REGION}.amazonaws.com" \
      --source-arn "arn:aws:logs:${REGION}:${ACCOUNT_ID}:log-group:${LOG_GROUP}:*" \
      --region "$REGION" > /dev/null
    echo -e "  ${GRN}✓ Lambda invoke permission granted${RESET}"
  else
    echo -e "  ${YEL}[DRY RUN] Would grant Lambda invoke permission${RESET}"
  fi
fi

# ── Create/update subscription filter ────────────────────────────────────────
echo "Creating subscription filter..."

if [[ "$DRY_RUN" == "false" ]]; then
  FILTER_CMD=(
    aws logs put-subscription-filter
    --log-group-name "$LOG_GROUP"
    --filter-name "$FILTER_NAME"
    --filter-pattern "$FILTER_PATTERN"
    --destination-arn "$DESTINATION_ARN"
    --region "$REGION"
  )

  if [[ "$DESTINATION_TYPE" == "kinesis" ]]; then
    FILTER_CMD+=(--role-arn "$ROLE_ARN")
  fi

  "${FILTER_CMD[@]}"
  echo -e "  ${GRN}✓ Subscription filter created/updated${RESET}"
else
  echo -e "  ${YEL}[DRY RUN] Would run: aws logs put-subscription-filter ...${RESET}"
fi

# ── Verify subscription filter ────────────────────────────────────────────────
if [[ "$DRY_RUN" == "false" ]]; then
  echo ""
  echo "Verifying subscription filter..."
  sleep 2  # Brief pause for eventual consistency

  FILTER_DETAILS=$(aws logs describe-subscription-filters \
    --log-group-name "$LOG_GROUP" \
    --filter-name-prefix "$FILTER_NAME" \
    --region "$REGION" \
    --output json 2>/dev/null)

  if echo "$FILTER_DETAILS" | grep -q "\"filterName\""; then
    echo -e "  ${GRN}✓ Subscription filter verified${RESET}"
    echo ""
    echo "  Filter details:"
    echo "$FILTER_DETAILS" | python3 -c "
import json, sys
data = json.load(sys.stdin)
for f in data.get('subscriptionFilters', []):
    print(f\"    Name:        {f.get('filterName')}\")
    print(f\"    Destination: {f.get('destinationArn')}\")
    print(f\"    Pattern:     '{f.get('filterPattern', '(empty = all)')}'\")" 2>/dev/null || true
  else
    echo -e "  ${RED}✗ Could not verify subscription filter — check AWS Console${RESET}"
  fi
fi

echo ""
echo -e "${GRN}${BOLD}SIEM integration configured successfully${RESET}"
echo ""
echo "  Next steps:"
echo "  1. Send a test request that will be blocked by WAF"
echo "  2. Verify the block event appears in your SIEM within 1-2 minutes"
echo "  3. Configure SIEM correlation rule to join WAF + ALB access logs on request_id"
echo "  4. Set up SIEM dashboard (see docs/siem-correlation.md)"
