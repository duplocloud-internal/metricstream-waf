################################################################################
# Production WAF — terraform.tfvars
# Edit this file to manage customer IP whitelists and configuration.
#
# PROCESS FOR CHANGES:
#   1. Edit this file
#   2. Run: terraform plan -out=prod.tfplan
#   3. Create PR — requires Infrastructure Lead + Security Team Lead approval
#   4. Merge triggers automatic apply via CI/CD
################################################################################

aws_region = "us-east-1"

# KMS key for WAF log encryption.
# Option A — use an existing key (uncomment and fill in the ARN):
# kms_key_arn = "arn:aws:kms:us-east-1:ACCOUNT_ID:key/YOUR-KEY-ID"
#
# Option B — leave commented out (default): Terraform creates and manages the key.

# Rate limit: requests per IP per 5 minutes
# Increase if high-volume legitimate integrations are being rate-limited
rate_limit_threshold = 2000

# SNS topics for CloudWatch alarms
alarm_sns_arns = [
  # "arn:aws:sns:us-east-1:ACCOUNT_ID:security-alerts",
  # "arn:aws:sns:us-east-1:ACCOUNT_ID:platform-alerts",
]

################################################################################
# CUSTOMER IP WHITELISTS
#
# Add an entry here for each customer that requires IP whitelisting.
# Customers NOT listed here are covered by global rules only (no scope-down).
#
# priority_offset values must be unique. Gaps are fine (e.g., 0, 1, 2...).
# After removing a customer, the offset slot is free to reuse.
################################################################################

customer_ip_whitelists = {

  # ── Customer Example (remove/replace before production deployment) ──────────
  # "example-customer" = {
  #   hostname         = "example-customer.metricstream.com"
  #   allowed_ip_cidrs = [
  #     "203.0.113.0/24",  # Example Corp HQ — New York
  #     "198.51.100.10/32" # Example Corp VPN gateway
  #   ]
  #   allowed_ip_cidrs_ipv6 = []
  #   priority_offset       = 0   # → WAF priority 10
  # }
  # ─────────────────────────────────────────────────────────────────────────────

  # Add production customers below:
  # "customer-key" = {
  #   hostname              = "customer.metricstream.com"
  #   allowed_ip_cidrs      = ["x.x.x.x/32"]
  #   allowed_ip_cidrs_ipv6 = []
  #   priority_offset       = 0
  # }
}

################################################################################
# CRS RULE OVERRIDES
#
# Add entries here ONLY for confirmed false positives.
# Each entry requires:
#   - rule_name   : Exact AWS CRS rule name
#   - reason      : Business justification
#   - approved_by : "Security Team Lead" + name
#   - approved_date : YYYY-MM-DD
#
# Review all overrides quarterly to verify they are still needed.
################################################################################

crs_rule_overrides = [
  # Example (uncomment if applicable):
  # {
  #   rule_name     = "SizeRestrictions_BODY"
  #   reason        = "Bulk data import API sends POST bodies up to 5MB. Confirmed legitimate."
  #   approved_by   = "Security Team Lead — Jane Smith"
  #   approved_date = "2026-04-01"
  # },
]
