################################################################################
# KMS Module — Variables
################################################################################

variable "environment" {
  description = "Environment name: prod or nonprod"
  type        = string
  validation {
    condition     = contains(["prod", "nonprod"], var.environment)
    error_message = "Environment must be 'prod' or 'nonprod'."
  }
}

variable "existing_kms_key_arn" {
  description = <<-EOT
    ARN of an existing KMS key to use for WAF log encryption.
    Leave empty (default) to have Terraform create and manage a new key.
    When provided, the key must already grant permissions to CloudWatch Logs,
    S3, and the WAF log delivery service — Terraform will not modify its policy.
  EOT
  type    = string
  default = ""

  validation {
    condition     = var.existing_kms_key_arn == "" || can(regex("^arn:aws:kms:", var.existing_kms_key_arn))
    error_message = "existing_kms_key_arn must be empty or a valid KMS key ARN (arn:aws:kms:...)."
  }
}

variable "common_tags" {
  description = "Common tags applied to all resources"
  type        = map(string)
  default     = {}
}
