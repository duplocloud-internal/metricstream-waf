################################################################################
# Deployment Variables
# All values injected per-deployment from config/deployments.yaml by
# scripts/orchestrate.py — never set these manually in a tfvars file.
################################################################################

variable "deployment_id" {
  description = "Unique deployment identifier (e.g. prod-us-east-1). Used in state key and resource names."
  type        = string
}

variable "account_id" {
  description = "12-digit AWS account ID for this deployment."
  type        = string
  validation {
    condition     = can(regex("^[0-9]{12}$", var.account_id))
    error_message = "account_id must be exactly 12 digits."
  }
}

variable "region" {
  description = "AWS region for this deployment (e.g. us-east-1, eu-west-1)."
  type        = string
}

variable "environment" {
  description = "Environment label: prod or nonprod."
  type        = string
  validation {
    condition     = contains(["prod", "nonprod"], var.environment)
    error_message = "environment must be 'prod' or 'nonprod'."
  }
}

variable "rate_limit_threshold" {
  description = "Max requests per IP per 5-minute window before rate limiting. AWS minimum is 100."
  type        = number
  default     = 2000
  validation {
    condition     = var.rate_limit_threshold >= 100
    error_message = "rate_limit_threshold must be >= 100 (AWS WAF minimum)."
  }
}

variable "log_retention_days" {
  description = "Days before S3 WAF logs expire (after Glacier transition)."
  type        = number
  default     = 365
}

variable "cloudwatch_retention_days" {
  description = "CloudWatch log group retention in days."
  type        = number
  default     = 90
}

variable "object_lock_retention_days" {
  description = "S3 Object Lock COMPLIANCE retention in days. Logs cannot be deleted before this period."
  type        = number
  default     = 90
}

variable "alarm_high_block_threshold" {
  description = "Blocked request count in 5 minutes that triggers the high-block-rate alarm."
  type        = number
  default     = 1000
}

variable "alarm_low_allowed_threshold" {
  description = "Allowed request count below which the low-traffic alarm fires (possible false-positive surge)."
  type        = number
  default     = 100
}

variable "alarm_sns_arns" {
  description = "SNS topic ARNs for CloudWatch alarm notifications."
  type        = list(string)
  default     = []
}

variable "kms_key_arn" {
  description = "Existing KMS key ARN for WAF log encryption. Leave empty to auto-create a new key."
  type        = string
  default     = ""
  validation {
    condition     = var.kms_key_arn == "" || can(regex("^arn:aws:kms:", var.kms_key_arn))
    error_message = "kms_key_arn must be empty or a valid KMS ARN (arn:aws:kms:...)."
  }
}

variable "customer_ip_whitelists" {
  description = <<-EOT
    Customers with IP whitelisting enabled. Each entry creates a WAF scope-down
    rule that blocks traffic to that customer's hostname from non-listed IPs.
    Customers not listed here are covered by global rules only.

    priority_offset: Unique integer 0-89. WAF priority = 10 + offset.
    allowed_ip_cidrs: IPv4 CIDRs. Use /32 for single IPs.
    allowed_ip_cidrs_ipv6: IPv6 CIDRs. Leave empty if not needed.
  EOT
  type = map(object({
    hostname              = string
    allowed_ip_cidrs      = list(string)
    allowed_ip_cidrs_ipv6 = optional(list(string), [])
    priority_offset       = number
  }))
  default = {}

  validation {
    condition = length(
      distinct([for k, v in var.customer_ip_whitelists : v.priority_offset])
    ) == length(var.customer_ip_whitelists)
    error_message = "Each customer must have a unique priority_offset."
  }

  validation {
    condition = alltrue([
      for k, v in var.customer_ip_whitelists :
      v.priority_offset >= 0 && v.priority_offset <= 89
    ])
    error_message = "priority_offset must be between 0 and 89."
  }
}

variable "managed_rule_modes" {
  description = <<-EOT
    Override action per AWS managed rule group.
    "block" → rule fires and blocks.  "count" → rule only counts (safe rollout mode).
    Omit a key to use the module default (block for IPReputation+KnownBadInputs, count for rest).
  EOT
  type = object({
    AmazonIpReputationList = optional(string, "block")
    AnonymousIpList        = optional(string, "count")
    KnownBadInputsRuleSet  = optional(string, "block")
    CommonRuleSet          = optional(string, "count")
  })
  default = {}

  validation {
    condition = alltrue([
      for mode in values(var.managed_rule_modes) : contains(["block", "count"], mode)
    ])
    error_message = "Each managed_rule_modes value must be 'block' or 'count'."
  }
}

variable "crs_rule_overrides" {
  description = <<-EOT
    Common Rule Set rules to override to COUNT mode for confirmed false positives.
    Each entry requires a rule name, business reason, approver, and approval date.
    Review all overrides quarterly.
  EOT
  type = list(object({
    rule_name     = string
    reason        = string
    approved_by   = string
    approved_date = string
  }))
  default = []
}
