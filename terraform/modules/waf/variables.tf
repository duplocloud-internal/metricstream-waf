################################################################################
# WAF Module — Variables
################################################################################

variable "environment" {
  description = "Environment name: prod or nonprod"
  type        = string
  validation {
    condition     = contains(["prod", "nonprod"], var.environment)
    error_message = "Environment must be 'prod' or 'nonprod'."
  }
}

variable "customer_ip_whitelists" {
  description = <<-EOT
    Customers with IP whitelisting enabled. Each entry generates a scope-down
    WAF rule scoped to that customer's hostname.
    Customers NOT in this map receive global rules only — no per-customer rule.
  EOT
  type = map(object({
    hostname        = string
    priority_offset = number
  }))
  default = {}
}

variable "ip_set_arns" {
  description = "Map of customer key to IPv4 IP set ARN (from ip-sets module output)"
  type        = map(string)
  default     = {}
}

variable "ip_set_arns_ipv6" {
  description = "Map of customer key to IPv6 IP set ARN (from ip-sets module output)"
  type        = map(string)
  default     = {}
}

variable "s3_log_bucket_arn" {
  description = "ARN of S3 bucket for WAF logs (from logging module output)"
  type        = string
}


variable "rate_limit_threshold" {
  description = <<-EOT
    Maximum requests per IP per 5-minute window before rate limiting kicks in.
    Default 2000 is conservative. Adjust upward if legitimate high-volume
    integrations (webhooks, batch APIs) are being blocked.
  EOT
  type        = number
  default     = 2000

  validation {
    condition     = var.rate_limit_threshold >= 100
    error_message = "Rate limit threshold must be at least 100 (AWS WAF minimum)."
  }
}

variable "crs_rule_overrides" {
  description = <<-EOT
    List of Common Rule Set rule names to override to COUNT mode.
    Use for confirmed false positives only — each override requires
    a ticket reference and security team approval.

    Example:
    [
      {
        rule_name = "SizeRestrictions_BODY"
        reason    = "Bulk import API uses POST bodies up to 5MB. Ticket #12345"
        approved_by = "Security Team Lead"
        approved_date = "2026-04-01"
      }
    ]
  EOT
  type = list(object({
    rule_name     = string
    reason        = string
    approved_by   = string
    approved_date = string
  }))
  default = []
}

variable "managed_rule_modes" {
  description = <<-EOT
    Override action for each AWS managed rule group.
    "block" → none{}  (rule fires with its own Block action)
    "count" → count{} (rule only counts, does not block — use during validation period)

    Defaults match the recommended rollout sequence:
      AmazonIpReputationList + KnownBadInputsRuleSet → block immediately (low FP risk)
      AnonymousIpList + CommonRuleSet                → count first, switch to block
                                                        after 1-2 weeks of log review
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

variable "common_tags" {
  description = "Common tags applied to all resources"
  type        = map(string)
  default     = {}
}
