output "s3_bucket_arn" {
  value       = aws_s3_bucket.waf_logs.arn
  description = "ARN of the WAF logs S3 bucket"
}

output "s3_bucket_id" {
  value       = aws_s3_bucket.waf_logs.id
  description = "ID (name) of the WAF logs S3 bucket"
}

output "cloudwatch_log_group_arn" {
  value       = aws_cloudwatch_log_group.waf_logs.arn
  description = "ARN of the WAF CloudWatch log group"
}

output "cloudwatch_log_group_name" {
  value       = aws_cloudwatch_log_group.waf_logs.name
  description = "Name of the WAF CloudWatch log group"
}
