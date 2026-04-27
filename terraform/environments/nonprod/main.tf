################################################################################
# DEPRECATED — do not use.
# This environment root has been replaced by terraform/deployment/ which
# supports multiple AWS accounts and regions from a single parametric root.
# Manage all deployments via config/deployments.yaml and scripts/orchestrate.py.
# This directory can be safely deleted once the new deployment is confirmed.
################################################################################

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  backend "s3" {
    bucket         = "metricstream-terraform-state"
    key            = "waf/nonprod/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "metricstream-terraform-locks"
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = local.common_tags
  }
}

locals {
  common_tags = {
    Environment = "nonproduction"
    ManagedBy   = "terraform"
    Team        = "platform"
    CostCenter  = "infrastructure"
    Project     = "metricstream-waf"
    Owner       = "platform-team@metricstream.com"
  }

  customer_ip_whitelists = var.customer_ip_whitelists
}

module "kms" {
  source               = "../../modules/kms"
  environment          = "nonprod"
  existing_kms_key_arn = var.kms_key_arn
  common_tags          = local.common_tags
}

module "logging" {
  source      = "../../modules/logging"
  environment = "nonprod"
  kms_key_arn = module.kms.key_arn

  # Shorter retention for nonprod — reduce cost
  log_retention_days         = 90
  cloudwatch_retention_days  = 30
  object_lock_retention_days = 30

  # Lower thresholds for nonprod traffic volumes
  alarm_high_block_threshold  = 200
  alarm_low_allowed_threshold = 10
  alarm_sns_arns              = var.alarm_sns_arns

  common_tags = local.common_tags
}

module "ip_sets" {
  source      = "../../modules/ip-sets"
  environment = "nonprod"

  customer_ip_whitelists = local.customer_ip_whitelists
  common_tags            = local.common_tags
}

module "waf" {
  source      = "../../modules/waf"
  environment = "nonprod"

  customer_ip_whitelists = {
    for k, v in local.customer_ip_whitelists : k => {
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

  common_tags = local.common_tags

  depends_on = [module.logging, module.ip_sets]
}
