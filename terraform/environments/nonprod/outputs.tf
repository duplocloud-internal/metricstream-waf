output "waf_arn" {
  value       = module.waf.waf_arn
  description = "Nonproduction WAF ARN — register this in DuploCloud Plan"
}

output "waf_id" {
  value       = module.waf.waf_id
  description = "Production WAF ID"
}

output "waf_name" {
  value       = module.waf.waf_name
  description = "Production WAF name"
}

output "waf_capacity" {
  value       = module.waf.waf_capacity
  description = "Current WCU usage (limit: 5000)"
}

output "kms_key_arn" {
  value       = module.kms.key_arn
  description = "KMS key ARN used for WAF log encryption"
}

output "s3_log_bucket" {
  value       = module.logging.s3_bucket_id
  description = "S3 bucket name for WAF logs"
}

output "cloudwatch_log_group" {
  value       = module.logging.cloudwatch_log_group_name
  description = "CloudWatch log group name for WAF logs"
}

output "duplocloud_registration_instructions" {
  value       = module.waf.duplocloud_registration_instructions
  description = "Instructions for registering this WAF in DuploCloud"
}

output "customer_ip_sets" {
  value       = module.ip_sets.ip_set_ids
  description = "Map of customer key to IP set ID"
}
