################################################################################
# Nonproduction WAF — terraform.tfvars
# Mirror of prod config with nonprod hostnames and test IP ranges.
# Use this environment to validate rule changes before prod promotion.
################################################################################

aws_region = "us-east-1"

# KMS key for WAF log encryption.
# Option A — use an existing key (uncomment and fill in the ARN):
# kms_key_arn = "arn:aws:kms:us-east-1:ACCOUNT_ID:key/YOUR-KEY-ID"
#
# Option B — leave commented out (default): Terraform creates and manages the key.

# Lower rate limit for nonprod (less legitimate traffic expected)
rate_limit_threshold = 500

alarm_sns_arns = [
  # "arn:aws:sns:us-east-1:ACCOUNT_ID:platform-alerts-nonprod",
]

customer_ip_whitelists = {
  # Add nonprod customer entries here to mirror prod configuration.
  # Use nonprod hostnames (e.g., "acme.nonprod.metricstream.com")
  # and test/staging IP ranges.
  #
  # "example-customer-nonprod" = {
  #   hostname              = "example-customer.nonprod.metricstream.com"
  #   allowed_ip_cidrs      = ["203.0.113.0/24"]
  #   allowed_ip_cidrs_ipv6 = []
  #   priority_offset       = 0
  # }
}

crs_rule_overrides = []
