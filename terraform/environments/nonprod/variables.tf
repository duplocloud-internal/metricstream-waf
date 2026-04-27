variable "aws_region" {
  description = "AWS region for the production WAF deployment"
  type        = string
  default     = "us-east-1"
}

variable "customer_ip_whitelists" {
  description = <<-EOT
    Map of production customers with IP whitelisting enabled.
    Only these customers receive a WAF scope-down rule.
    All others are protected by global rules only.

    Keys: short identifier (e.g., "acme-corp") — used in resource names
    Values:
      hostname         : Exact host header to match (e.g., "acme.metricstream.com")
      allowed_ip_cidrs : IPv4 CIDR ranges approved for this customer
      allowed_ip_cidrs_ipv6: IPv6 CIDR ranges (optional)
      priority_offset  : Unique integer 0–89 (WAF priority = 10 + offset)
  EOT
  type = map(object({
    hostname              = string
    allowed_ip_cidrs      = list(string)
    allowed_ip_cidrs_ipv6 = optional(list(string), [])
    priority_offset       = number
  }))
  default = {}
}

variable "rate_limit_threshold" {
  description = "Max requests per IP per 5-minute window. Default 2000 for production."
  type        = number
  default     = 2000
}

variable "crs_rule_overrides" {
  description = "Confirmed false-positive CRS rules to set to COUNT. Requires ticket + approval."
  type = list(object({
    rule_name     = string
    reason        = string
    approved_by   = string
    approved_date = string
  }))
  default = []
}

variable "alarm_sns_arns" {
  description = "SNS topic ARNs for CloudWatch WAF alarms (security + platform notifications)"
  type        = list(string)
  default     = []
}

variable "kms_key_arn" {
  description = <<-EOT
    Optional ARN of an existing KMS key to use for WAF log encryption.
    Leave empty (default) to have Terraform create and manage a new key.
    The existing key must already grant access to CloudWatch Logs, S3,
    and the WAF log delivery service.
  EOT
  type    = string
  default = ""
}
