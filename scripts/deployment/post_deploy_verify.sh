#!/usr/bin/env bash
# post_deploy_verify.sh — MetricStream WAF Post-Deployment Verification
#
# Verifies the WAF was deployed correctly after terraform apply.
# Checks: WAF exists, rules present, logging configured, IP sets created.
#
# Usage:
#   ./scripts/deployment/post_deploy_verify.sh --env prod --region us-east-1
#   ./scripts/deployment/post_deploy_verify.sh --env nonprod --region us-east-1

set -euo pipefail

# ── Colours ───────────────────────────────────────────────────────────────────
RED='\033[91m'; GRN='\033[92m'; YEL='\033[93m'; BLU='\033[94m'
BOLD='\033[1m'; RESET='\033[0m'

PASS="${GRN}✓ PASS${RESET}"
FAIL="${RED}✗ FAIL${RESET}"
WARN="${YEL}⚠ WARN${RESET}"
INFO="${BLU}ℹ INFO${RESET}"

ERRORS=0

header() { echo -e "\n${BOLD}${BLU}──────────────────────────────────────────────────────────────${RESET}"; echo -e "${BOLD}${BLU}  $1${RESET}"; echo -e "${BOLD}${BLU}──────────────────────────────────────────────────────────────${RESET}"; }
pass()   { echo -e "  ${PASS}  $1"; }
fail()   { echo -e "  ${FAIL}  $1"; ERRORS=$((ERRORS+1)); }
warn()   { echo -e "  ${WARN}  $1"; }
info()   { echo -e "  ${INFO}  $1"; }

# ── Argument parsing ──────────────────────────────────────────────────────────
ENV=""
REGION="us-east-1"

while [[ $# -gt 0 ]]; do
  case $1 in
    --env)    ENV="$2";    shift 2 ;;
    --region) REGION="$2"; shift 2 ;;
    *) echo "Unknown arg: $1"; exit 1 ;;
  esac
done

if [[ -z "$ENV" ]]; then
  echo "Usage: $0 --env <prod|nonprod> [--region <region>]"
  exit 1
fi

WAF_NAME="metricstream-waf-${ENV}-${REGION}"
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text 2>/dev/null || echo "UNKNOWN")
EXPECTED_LOG_GROUP="/aws/waf/metricstream-${ENV}"
EXPECTED_S3_PREFIX="aws-waf-logs-metricstream-${ENV}-${ACCOUNT_ID}"

header "MetricStream WAF Post-Deployment Verification (${ENV^^} / ${REGION})"
info "WAF name:  ${WAF_NAME}"
info "Account:   ${ACCOUNT_ID}"
info "Region:    ${REGION}"

# ── 1. WAF exists ─────────────────────────────────────────────────────────────
header "1. Web ACL Existence"

WAF_ID=$(aws wafv2 list-web-acls \
  --scope REGIONAL \
  --region "$REGION" \
  --query "WebACLs[?Name=='${WAF_NAME}'].Id" \
  --output text 2>/dev/null || true)

if [[ -z "$WAF_ID" || "$WAF_ID" == "None" ]]; then
  fail "WAF '${WAF_NAME}' not found in region ${REGION}"
  echo -e "\n  ${RED}✗ Cannot continue — WAF does not exist.${RESET}\n"
  exit 1
fi

pass "WAF found: ${WAF_NAME} (ID: ${WAF_ID})"

WAF_ARN="arn:aws:wafv2:${REGION}:${ACCOUNT_ID}:regional/webacl/${WAF_NAME}/${WAF_ID}"
info "ARN: ${WAF_ARN}"

# ── 2. Default action is Allow ────────────────────────────────────────────────
header "2. Default Action"

DEFAULT_ACTION=$(aws wafv2 get-web-acl \
  --name "$WAF_NAME" --scope REGIONAL --id "$WAF_ID" --region "$REGION" \
  --query 'WebACL.DefaultAction' --output json 2>/dev/null)

if echo "$DEFAULT_ACTION" | grep -q '"Allow"'; then
  pass "Default action is ALLOW (as required)"
else
  fail "Default action is NOT Allow: ${DEFAULT_ACTION}"
fi

# ── 3. Rule count and global rules ───────────────────────────────────────────
header "3. WAF Rules"

RULES=$(aws wafv2 get-web-acl \
  --name "$WAF_NAME" --scope REGIONAL --id "$WAF_ID" --region "$REGION" \
  --query 'WebACL.Rules' --output json 2>/dev/null)

RULE_COUNT=$(echo "$RULES" | python3 -c "import json,sys; print(len(json.load(sys.stdin)))" 2>/dev/null || echo "0")
info "Total rules: ${RULE_COUNT}"

# Check for each expected global rule
EXPECTED_GLOBAL_RULES=(
  "AWSManagedRulesAmazonIpReputationList"
  "AWSManagedRulesAnonymousIpList"
  "AWSManagedRulesKnownBadInputsRuleSet"
  "AWSManagedRulesCommonRuleSet"
  "GlobalRateLimit"
)

for rule_name in "${EXPECTED_GLOBAL_RULES[@]}"; do
  if echo "$RULES" | grep -q "\"$rule_name\""; then
    pass "Global rule present: ${rule_name}"
  else
    fail "Global rule MISSING: ${rule_name}"
  fi
done

# Check WCU capacity
WCU=$(aws wafv2 get-web-acl \
  --name "$WAF_NAME" --scope REGIONAL --id "$WAF_ID" --region "$REGION" \
  --query 'WebACL.Capacity' --output text 2>/dev/null || echo "0")

info "WCU usage: ${WCU}/5000"
if [[ "$WCU" -gt 4000 ]]; then
  warn "WCU usage is above 80% (${WCU}/5000) — monitor headroom"
elif [[ "$WCU" -gt 5000 ]]; then
  fail "WCU limit EXCEEDED (${WCU}/5000)"
else
  pass "WCU usage is within safe range (${WCU}/5000)"
fi

# ── 4. Logging configuration ──────────────────────────────────────────────────
header "4. Logging Configuration"

LOGGING=$(aws wafv2 get-logging-configuration \
  --resource-arn "$WAF_ARN" --region "$REGION" \
  --output json 2>/dev/null || echo "{}")

if echo "$LOGGING" | grep -q "LogDestinationConfigs"; then
  pass "Logging is configured"

  if echo "$LOGGING" | grep -q "aws-waf-logs-"; then
    pass "S3 log destination configured"
  else
    fail "S3 log destination NOT configured"
  fi

  if echo "$LOGGING" | grep -q ":log-group:"; then
    pass "CloudWatch log destination configured"
  else
    fail "CloudWatch log destination NOT configured"
  fi

  if echo "$LOGGING" | grep -q "BLOCK"; then
    pass "Logging filter includes BLOCK actions"
  else
    warn "Logging filter does not appear to include BLOCK actions — verify manually"
  fi
else
  fail "Logging NOT configured on WAF"
fi

# ── 5. CloudWatch log group ───────────────────────────────────────────────────
header "5. CloudWatch Log Group"

LOG_GROUP=$(aws logs describe-log-groups \
  --log-group-name-prefix "$EXPECTED_LOG_GROUP" \
  --region "$REGION" \
  --query "logGroups[?logGroupName=='${EXPECTED_LOG_GROUP}'].logGroupName" \
  --output text 2>/dev/null || true)

if [[ "$LOG_GROUP" == "$EXPECTED_LOG_GROUP" ]]; then
  pass "CloudWatch log group exists: ${EXPECTED_LOG_GROUP}"
else
  fail "CloudWatch log group NOT found: ${EXPECTED_LOG_GROUP}"
fi

# ── 6. S3 log bucket ─────────────────────────────────────────────────────────
header "6. S3 Log Bucket"

S3_BUCKET=$(aws s3api list-buckets \
  --query "Buckets[?starts_with(Name, '${EXPECTED_S3_PREFIX}')].Name" \
  --output text 2>/dev/null || true)

if [[ -n "$S3_BUCKET" ]]; then
  pass "S3 log bucket found: ${S3_BUCKET}"

  # Check Object Lock
  OBJECT_LOCK=$(aws s3api get-object-lock-configuration \
    --bucket "$S3_BUCKET" --output json 2>/dev/null || echo "{}")

  if echo "$OBJECT_LOCK" | grep -q "ObjectLockConfiguration"; then
    pass "S3 Object Lock is enabled"
    if echo "$OBJECT_LOCK" | grep -q "COMPLIANCE"; then
      pass "S3 Object Lock mode is COMPLIANCE"
    else
      warn "S3 Object Lock mode is not COMPLIANCE — verify manually"
    fi
  else
    fail "S3 Object Lock NOT enabled on log bucket"
  fi

  # Check encryption
  ENCRYPTION=$(aws s3api get-bucket-encryption \
    --bucket "$S3_BUCKET" --output json 2>/dev/null || echo "{}")

  if echo "$ENCRYPTION" | grep -q "aws:kms"; then
    pass "S3 bucket uses SSE-KMS encryption"
  else
    fail "S3 bucket does NOT use SSE-KMS encryption"
  fi

  # Check versioning
  VERSIONING=$(aws s3api get-bucket-versioning \
    --bucket "$S3_BUCKET" --query "Status" --output text 2>/dev/null || echo "")

  if [[ "$VERSIONING" == "Enabled" ]]; then
    pass "S3 versioning is enabled"
  else
    fail "S3 versioning is NOT enabled"
  fi
else
  fail "S3 log bucket NOT found (expected prefix: ${EXPECTED_S3_PREFIX})"
fi

# ── 7. IP sets ────────────────────────────────────────────────────────────────
header "7. IP Sets"

IP_SETS=$(aws wafv2 list-ip-sets \
  --scope REGIONAL --region "$REGION" \
  --query "IPSets[?starts_with(Name, 'metricstream-')].Name" \
  --output text 2>/dev/null || true)

IP_SET_COUNT=$(echo "$IP_SETS" | wc -w | tr -d ' ')
if [[ "$IP_SET_COUNT" -gt 0 ]]; then
  pass "Found ${IP_SET_COUNT} MetricStream IP set(s)"
  for ip_set in $IP_SETS; do
    info "  IP set: ${ip_set}"
  done
else
  info "No customer IP sets found (expected if no customers have IP whitelisting)"
fi

# ── 8. Tags ───────────────────────────────────────────────────────────────────
header "8. Resource Tags"

TAGS=$(aws wafv2 list-tags-for-resource \
  --resource-arn "$WAF_ARN" --region "$REGION" \
  --query 'TagInfoForResource.TagList' --output json 2>/dev/null || echo "[]")

REQUIRED_TAGS=("ManagedBy" "Team" "Environment")
for tag in "${REQUIRED_TAGS[@]}"; do
  if echo "$TAGS" | grep -q "\"$tag\""; then
    pass "Tag present: ${tag}"
  else
    warn "Tag missing: ${tag}"
  fi
done

# ── Summary ────────────────────────────────────────────────────────────────────
header "Verification Summary"

if [[ "$ERRORS" -eq 0 ]]; then
  echo -e "  ${GRN}${BOLD}✓ All verifications passed — WAF deployment looks healthy${RESET}"
  echo ""
  echo -e "  ${INFO}  Next step: Register WAF in DuploCloud Plan"
  echo -e "  ${INFO}  WAF ARN: ${WAF_ARN}"
  echo ""
  exit 0
else
  echo -e "  ${RED}${BOLD}✗ ${ERRORS} verification(s) FAILED — review errors above${RESET}"
  echo ""
  exit 1
fi
