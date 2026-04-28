################################################################################
# Logging Module — S3 (Object Lock + SSE-KMS) + CloudWatch Log Group
################################################################################

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

################################################################################
# S3 Bucket — WAF Logs
# Name MUST start with "aws-waf-logs-" for WAF to deliver logs
# Object Lock: tamper-proof audit trail (MetricStream security requirement)
# Encryption: SSE-KMS with MetricStream-managed key
################################################################################

resource "aws_s3_bucket" "waf_logs" {
  # WAF requires bucket names to start with "aws-waf-logs-"
  # Region included to prevent collision when the same account deploys to multiple regions.
  bucket = "aws-waf-logs-metricstream-${var.environment}-${data.aws_region.current.name}-${data.aws_caller_identity.current.account_id}"

  # Object Lock must be enabled at creation — cannot be added later
  object_lock_enabled = true

  tags = merge(var.common_tags, {
    Name    = "aws-waf-logs-metricstream-${var.environment}"
    Purpose = "waf-logging"
  })
}

# Block all public access
resource "aws_s3_bucket_public_access_block" "waf_logs" {
  bucket                  = aws_s3_bucket.waf_logs.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Versioning — required for Object Lock
resource "aws_s3_bucket_versioning" "waf_logs" {
  bucket = aws_s3_bucket.waf_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

# Object Lock configuration — COMPLIANCE mode prevents any deletion
resource "aws_s3_bucket_object_lock_configuration" "waf_logs" {
  bucket = aws_s3_bucket.waf_logs.id

  rule {
    default_retention {
      mode = "COMPLIANCE"
      days = var.object_lock_retention_days
    }
  }

  depends_on = [aws_s3_bucket_versioning.waf_logs]
}

# SSE-KMS encryption using MetricStream-managed key
resource "aws_s3_bucket_server_side_encryption_configuration" "waf_logs" {
  bucket = aws_s3_bucket.waf_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = var.kms_key_arn
    }
    bucket_key_enabled = true # Reduces KMS API calls and cost
  }
}

# Lifecycle: transition to Glacier, then expire
resource "aws_s3_bucket_lifecycle_configuration" "waf_logs" {
  bucket = aws_s3_bucket.waf_logs.id

  rule {
    id     = "waf-logs-lifecycle"
    status = "Enabled"

    filter {}

    transition {
      days          = 90
      storage_class = "GLACIER"
    }

    # Only expire after Object Lock retention period is satisfied
    expiration {
      days = var.log_retention_days
    }

    noncurrent_version_expiration {
      noncurrent_days = 30
    }
  }

  depends_on = [aws_s3_bucket_versioning.waf_logs]
}

# Bucket policy — allow WAF/ALB log delivery, deny non-TLS access
resource "aws_s3_bucket_policy" "waf_logs" {
  bucket = aws_s3_bucket.waf_logs.id
  policy = data.aws_iam_policy_document.waf_logs_bucket_policy.json

  depends_on = [aws_s3_bucket_public_access_block.waf_logs]
}

data "aws_iam_policy_document" "waf_logs_bucket_policy" {
  # Deny non-TLS access
  statement {
    sid    = "DenyNonTLS"
    effect = "Deny"
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.waf_logs.arn, "${aws_s3_bucket.waf_logs.arn}/*"]
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

  # Allow WAF log delivery
  statement {
    sid    = "AllowWAFLogDelivery"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["delivery.logs.amazonaws.com"]
    }
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.waf_logs.arn}/waf-logs/*"]
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }

  # Allow log delivery service to check bucket ACL
  statement {
    sid    = "AllowLogDeliveryAclCheck"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["delivery.logs.amazonaws.com"]
    }
    actions   = ["s3:GetBucketAcl"]
    resources = [aws_s3_bucket.waf_logs.arn]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

################################################################################
# CloudWatch Log Group — Real-time monitoring and SIEM streaming
################################################################################

resource "aws_cloudwatch_log_group" "waf_logs" {
  name              = "/aws/waf/metricstream-${var.environment}"
  retention_in_days = var.cloudwatch_retention_days
  kms_key_id        = var.kms_key_arn

  tags = merge(var.common_tags, {
    Name    = "waf-logs-${var.environment}"
    Purpose = "waf-logging"
  })
}

################################################################################
# CloudWatch Alarms — High block rate, low allowed requests, CRS spikes
################################################################################

resource "aws_cloudwatch_metric_alarm" "high_block_rate" {
  alarm_name          = "WAF-HighBlockRate-${var.environment}"
  alarm_description   = "WAF blocking unusually high number of requests — possible attack or false-positive surge"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "BlockedRequests"
  namespace           = "AWS/WAFV2"
  period              = 300
  statistic           = "Sum"
  threshold           = var.alarm_high_block_threshold
  treat_missing_data  = "notBreaching"

  dimensions = {
    WebACL = "metricstream-waf-${var.environment}-${data.aws_region.current.name}"
    Region = data.aws_region.current.name
    Rule   = "ALL"
  }

  alarm_actions = var.alarm_sns_arns
  ok_actions    = var.alarm_sns_arns

  tags = var.common_tags
}

resource "aws_cloudwatch_metric_alarm" "low_allowed_requests" {
  alarm_name          = "WAF-LowAllowedRequests-${var.environment}"
  alarm_description   = "WAF allowing significantly fewer requests — possible false-positive surge causing customer outage"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = 2
  metric_name         = "AllowedRequests"
  namespace           = "AWS/WAFV2"
  period              = 300
  statistic           = "Sum"
  threshold           = var.alarm_low_allowed_threshold
  treat_missing_data  = "notBreaching"

  dimensions = {
    WebACL = "metricstream-waf-${var.environment}-${data.aws_region.current.name}"
    Region = data.aws_region.current.name
    Rule   = "ALL"
  }

  alarm_actions = var.alarm_sns_arns

  tags = var.common_tags
}

resource "aws_cloudwatch_metric_alarm" "crs_high_blocks" {
  alarm_name          = "WAF-CRS-HighBlocks-${var.environment}"
  alarm_description   = "Common Rule Set blocking >100 requests in 5 minutes — investigate false positives"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "BlockedRequests"
  namespace           = "AWS/WAFV2"
  period              = 300
  statistic           = "Sum"
  threshold           = 100
  treat_missing_data  = "notBreaching"

  dimensions = {
    WebACL = "metricstream-waf-${var.environment}-${data.aws_region.current.name}"
    Region = data.aws_region.current.name
    Rule   = "AWSManagedRulesCommonRuleSet"
  }

  alarm_actions = var.alarm_sns_arns

  tags = var.common_tags
}
