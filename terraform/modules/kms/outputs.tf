output "key_arn" {
  value       = local.kms_key_arn
  description = "ARN of the KMS key used for WAF log encryption (existing or newly created)"
}

output "key_id" {
  value       = one(aws_kms_key.waf_logs[*].key_id)
  description = "Key ID of the newly created KMS key; null when an existing key was provided"
}

output "key_alias" {
  value       = one(aws_kms_alias.waf_logs[*].name)
  description = "Alias of the newly created KMS key; null when an existing key was provided"
}
