################################################################################
# MetricStream WAF — Parametric Deployment Root
#
# This single Terraform root is used for ALL account+region deployments.
# It is never applied directly. Use:
#   python3 scripts/orchestrate.py plan --deployment <id>
#   python3 scripts/orchestrate.py apply --deployment <id>
#
# All variables come from config/deployments.yaml via the orchestrator.
# The S3 backend is configured at `terraform init` time via -backend-config
# flags — the empty backend "s3" {} block below is intentional.
#
# State key per deployment: waf/{deployment_id}/terraform.tfstate
################################################################################

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  # Backend config is injected per deployment at init time.
  # See scripts/orchestrate.py → _backend_config_args()
  backend "s3" {}
}

################################################################################
# Provider
# Credentials are provided by the CI/CD runner (GitHub OIDC → target account
# role) or by the developer's local AWS profile / environment variables.
# The orchestrator ensures the shell is authenticated to the correct account
# before invoking terraform, so no assume_role is needed here.
################################################################################

provider "aws" {
  region = var.region

  default_tags {
    tags = local.common_tags
  }
}

################################################################################
# Locals
################################################################################

locals {
  common_tags = {
    DeploymentId = var.deployment_id
    Environment  = var.environment
    AccountId    = var.account_id
    Region       = var.region
    ManagedBy    = "terraform"
    Team         = "platform"
    CostCenter   = "infrastructure"
    Project      = "metricstream-waf"
    Owner        = "platform-team@metricstream.com"
  }
}

################################################################################
# KMS — encryption key for WAF logs
################################################################################

module "kms" {
  source               = "../../modules/kms"
  environment          = var.environment
  existing_kms_key_arn = var.kms_key_arn
  common_tags          = local.common_tags
}

################################################################################
# Logging — S3 (Object Lock + SSE-KMS) + CloudWatch + alarms
################################################################################

module "logging" {
  source      = "../../modules/logging"
  environment = var.environment
  kms_key_arn = module.kms.key_arn

  log_retention_days         = var.log_retention_days
  cloudwatch_retention_days  = var.cloudwatch_retention_days
  object_lock_retention_days = var.object_lock_retention_days

  alarm_high_block_threshold  = var.alarm_high_block_threshold
  alarm_low_allowed_threshold = var.alarm_low_allowed_threshold
  alarm_sns_arns              = var.alarm_sns_arns

  common_tags = local.common_tags
}

################################################################################
# IP Sets — per-customer allowlists
################################################################################

module "ip_sets" {
  source      = "../../modules/ip-sets"
  environment = var.environment

  customer_ip_whitelists = var.customer_ip_whitelists
  common_tags            = local.common_tags
}

################################################################################
# WAF — Web ACL with global rules + customer scope-down rules
################################################################################

module "waf" {
  source      = "../../modules/waf"
  environment = var.environment

  customer_ip_whitelists = {
    for k, v in var.customer_ip_whitelists : k => {
      hostname        = v.hostname
      priority_offset = v.priority_offset
    }
  }

  ip_set_arns      = module.ip_sets.ip_set_arns
  ip_set_arns_ipv6 = module.ip_sets.ip_set_arns_ipv6

  s3_log_bucket_arn        = module.logging.s3_bucket_arn
  cloudwatch_log_group_arn = module.logging.cloudwatch_log_group_arn

  rate_limit_threshold = var.rate_limit_threshold
  crs_rule_overrides   = var.crs_rule_overrides
  managed_rule_modes   = var.managed_rule_modes

  common_tags = local.common_tags

  depends_on = [module.logging, module.ip_sets]
}
