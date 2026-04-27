################################################################################
# KMS Module — WAF log encryption key
#
# If var.existing_kms_key_arn is provided, no key is created and that ARN is
# used directly. Otherwise a new customer-managed key is created here.
################################################################################

locals {
  create_key  = var.existing_kms_key_arn == ""
  kms_key_arn = local.create_key ? aws_kms_key.waf_logs[0].arn : var.existing_kms_key_arn
}

resource "aws_kms_key" "waf_logs" {
  count = local.create_key ? 1 : 0

  description             = "MetricStream WAF log encryption key — ${var.environment}"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  multi_region            = false

  policy = data.aws_iam_policy_document.kms_policy[0].json

  tags = merge(var.common_tags, {
    Name    = "metricstream-waf-logs-${var.environment}"
    Purpose = "waf-log-encryption"
  })
}

resource "aws_kms_alias" "waf_logs" {
  count = local.create_key ? 1 : 0

  name          = "alias/metricstream-waf-logs-${var.environment}"
  target_key_id = aws_kms_key.waf_logs[0].key_id
}

################################################################################
# Key Policy — only evaluated when creating a new key
################################################################################

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

data "aws_iam_policy_document" "kms_policy" {
  count = local.create_key ? 1 : 0

  # Root account full control
  statement {
    sid    = "Enable IAM User Permissions"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
    actions   = ["kms:*"]
    resources = ["*"]
  }

  # Allow CloudWatch Logs service to use the key
  statement {
    sid    = "Allow CloudWatch Logs"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["logs.${data.aws_region.current.name}.amazonaws.com"]
    }
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:DescribeKey",
    ]
    resources = ["*"]
    condition {
      test     = "ArnLike"
      variable = "kms:EncryptionContext:aws:logs:arn"
      values   = ["arn:aws:logs:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:*"]
    }
  }

  # Allow S3 service to use the key for WAF log delivery
  statement {
    sid    = "Allow S3 WAF Log Delivery"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["s3.amazonaws.com"]
    }
    actions = [
      "kms:GenerateDataKey",
      "kms:Decrypt",
    ]
    resources = ["*"]
  }

  # Allow WAF service to use the key
  statement {
    sid    = "Allow WAF Logging"
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["delivery.logs.amazonaws.com"]
    }
    actions = [
      "kms:Encrypt",
      "kms:Decrypt",
      "kms:ReEncrypt*",
      "kms:GenerateDataKey*",
      "kms:DescribeKey",
    ]
    resources = ["*"]
  }
}
