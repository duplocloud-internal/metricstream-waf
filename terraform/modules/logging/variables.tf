variable "environment" {
  description = "Environment name: prod or nonprod"
  type        = string
}

variable "kms_key_arn" {
  description = "ARN of the MetricStream-managed KMS key for log encryption"
  type        = string
}

variable "log_retention_days" {
  description = "Days before S3 WAF logs expire (after Glacier transition)"
  type        = number
  default     = 365
}

variable "cloudwatch_retention_days" {
  description = "CloudWatch log group retention in days"
  type        = number
  default     = 90
}

variable "object_lock_retention_days" {
  description = "S3 Object Lock COMPLIANCE retention in days — logs cannot be deleted before this"
  type        = number
  default     = 90
}

variable "alarm_high_block_threshold" {
  description = "Number of blocked requests in 5 minutes to trigger high-block-rate alarm"
  type        = number
  default     = 1000
}

variable "alarm_low_allowed_threshold" {
  description = "Allowed requests below this in 5 minutes triggers low-traffic alarm"
  type        = number
  default     = 100
}

variable "alarm_sns_arns" {
  description = "List of SNS topic ARNs for CloudWatch alarm notifications"
  type        = list(string)
  default     = []
}

variable "common_tags" {
  description = "Common tags applied to all resources"
  type        = map(string)
  default     = {}
}
