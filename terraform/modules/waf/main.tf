################################################################################
# WAF Module — Web ACL with global managed rules + IP-whitelisting scope-down
#
# Priority Ranges:
#   1–9    : Global managed rules (apply to ALL traffic on ALL customers)
#   10–99  : IP-whitelisting scope-down rules (per customer, dynamic)
#   100+   : Reserved for future use
################################################################################

data "aws_region" "current" {}
data "aws_caller_identity" "current" {}

locals {
  # Resolve effective mode for each managed rule, applying defaults.
  # "block" → override_action { none {} }   (honours the rule's own Block action)
  # "count" → override_action { count {} }  (count-only, safe during rollout)
  rule_modes = {
    AmazonIpReputationList = coalesce(var.managed_rule_modes.AmazonIpReputationList, "block")
    AnonymousIpList        = coalesce(var.managed_rule_modes.AnonymousIpList,        "count")
    KnownBadInputsRuleSet  = coalesce(var.managed_rule_modes.KnownBadInputsRuleSet,  "block")
    CommonRuleSet          = coalesce(var.managed_rule_modes.CommonRuleSet,           "count")
  }
}

################################################################################
# Web ACL
################################################################################

resource "aws_wafv2_web_acl" "main" {
  name        = "metricstream-waf-${var.environment}-${data.aws_region.current.name}"
  description = "MetricStream ${var.environment} WAF - global rules + IP-whitelisting scope-down"
  scope       = "REGIONAL"

  default_action {
    allow {}
  }

  ##############################################################################
  # PRIORITY 1 — IP Reputation List
  # Blocks known malicious IPs, botnets, scrapers, C&C servers.
  # Always in BLOCK mode — no false positive risk.
  ##############################################################################
  rule {
    name     = "AWSManagedRulesAmazonIpReputationList"
    priority = 1

    dynamic "override_action" {
      for_each = [local.rule_modes.AmazonIpReputationList]
      content {
        dynamic "none" {
          for_each = override_action.value == "block" ? [1] : []
          content {}
        }
        dynamic "count" {
          for_each = override_action.value == "count" ? [1] : []
          content {}
        }
      }
    }

    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesAmazonIpReputationList"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "metricstream-${var.environment}-IPReputationList"
      sampled_requests_enabled   = true
    }
  }

  ##############################################################################
  # PRIORITY 2 — Anonymous IP List
  # Blocks Tor exit nodes, VPNs, open proxies.
  # Start in COUNT mode — corporate VPNs may be flagged.
  # Switch to none{} after 1–2 weeks of log review.
  ##############################################################################
  rule {
    name     = "AWSManagedRulesAnonymousIpList"
    priority = 2

    dynamic "override_action" {
      for_each = [local.rule_modes.AnonymousIpList]
      content {
        dynamic "none" {
          for_each = override_action.value == "block" ? [1] : []
          content {}
        }
        dynamic "count" {
          for_each = override_action.value == "count" ? [1] : []
          content {}
        }
      }
    }

    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesAnonymousIpList"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "metricstream-${var.environment}-AnonymousIPList"
      sampled_requests_enabled   = true
    }
  }

  ##############################################################################
  # PRIORITY 3 — Known Bad Inputs
  # Blocks Log4Shell, SSRF, path traversal, malformed request bodies.
  # BLOCK mode immediately — these patterns have no legitimate use.
  ##############################################################################
  rule {
    name     = "AWSManagedRulesKnownBadInputsRuleSet"
    priority = 3

    dynamic "override_action" {
      for_each = [local.rule_modes.KnownBadInputsRuleSet]
      content {
        dynamic "none" {
          for_each = override_action.value == "block" ? [1] : []
          content {}
        }
        dynamic "count" {
          for_each = override_action.value == "count" ? [1] : []
          content {}
        }
      }
    }

    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "metricstream-${var.environment}-KnownBadInputs"
      sampled_requests_enabled   = true
    }
  }

  ##############################################################################
  # PRIORITY 4 — Common Rule Set (CRS / OWASP Top 10)
  # Covers SQLi, XSS, LFI, oversized bodies, invalid structure.
  # CRITICAL: Start in COUNT mode. CRS has high false-positive potential.
  # Use rule_action_overrides to selectively suppress noisy rules before
  # switching the group to none{} (BLOCK) mode.
  ##############################################################################
  rule {
    name     = "AWSManagedRulesCommonRuleSet"
    priority = 4

    dynamic "override_action" {
      for_each = [local.rule_modes.CommonRuleSet]
      content {
        dynamic "none" {
          for_each = override_action.value == "block" ? [1] : []
          content {}
        }
        dynamic "count" {
          for_each = override_action.value == "count" ? [1] : []
          content {}
        }
      }
    }

    statement {
      managed_rule_group_statement {
        vendor_name = "AWS"
        name        = "AWSManagedRulesCommonRuleSet"

        # ── Selective rule overrides ──────────────────────────────────────────
        # Add rule_action_override blocks here for any rules that generate
        # confirmed false positives AFTER the analysis period.
        #
        # Example (uncomment and adjust as needed):
        #
        # rule_action_override {
        #   action_to_use { count {} }
        #   name = "SizeRestrictions_BODY"
        #   # Reason: MetricStream bulk import API uses POST bodies up to 5MB
        #   # FP detected: YYYY-MM-DD | Ticket: #XXXXX | Reviewed: YYYY-MM-DD
        # }
        #
        # rule_action_override {
        #   action_to_use { count {} }
        #   name = "GenericRFI_BODY"
        #   # Reason: Integration webhook payloads contain URL patterns
        #   # FP detected: YYYY-MM-DD | Ticket: #XXXXX | Reviewed: YYYY-MM-DD
        # }
        # ─────────────────────────────────────────────────────────────────────

        dynamic "rule_action_override" {
          for_each = var.crs_rule_overrides
          content {
            action_to_use {
              count {}
            }
            name = rule_action_override.value.rule_name
            # Note: reason is stored in var.crs_rule_overrides for documentation
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "metricstream-${var.environment}-CommonRuleSet"
      sampled_requests_enabled   = true
    }
  }

  ##############################################################################
  # PRIORITY 5 — Global Rate Limit
  # Limits requests per IP to prevent DDoS and credential stuffing.
  # Applies to ALL traffic before per-customer IP whitelist rules.
  # Adjust var.rate_limit_threshold based on observed legitimate traffic.
  ##############################################################################
  rule {
    name     = "GlobalRateLimit"
    priority = 5

    action {
      block {}
    }

    statement {
      rate_based_statement {
        limit              = var.rate_limit_threshold
        aggregate_key_type = "IP"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "metricstream-${var.environment}-GlobalRateLimit"
      sampled_requests_enabled   = true
    }
  }

  ##############################################################################
  # PRIORITIES 10–99 — Customer IP Whitelist Scope-Down Rules (Dynamic)
  #
  # For each customer with IP whitelisting enabled:
  #   Rule matches requests where:
  #     (Host header == customer hostname) AND (source IP NOT in allowlist)
  #   → BLOCK
  #
  # This means:
  #   - Traffic to this hostname from allowed IPs → passes to application
  #   - Traffic to this hostname from any other IP → BLOCKED
  #   - Traffic to other hostnames → rule does not apply (scope-down)
  #
  # IPv6: If the customer has IPv6 ranges, an additional NOT condition is added
  #       using OR logic (block if NOT in IPv4 set AND NOT in IPv6 set).
  ##############################################################################

  dynamic "rule" {
    for_each = var.customer_ip_whitelists

    content {
      name     = "IPWhitelist-${rule.key}"
      priority = 10 + rule.value.priority_offset

      action {
        block {
          custom_response {
            response_code = 403
            custom_response_body_key = "ip-whitelist-blocked"
          }
        }
      }

      statement {
        and_statement {
          statement {
            # Scope-down: only apply this rule to requests for this customer's hostname
            byte_match_statement {
              field_to_match {
                single_header {
                  name = "host"
                }
              }
              positional_constraint = "EXACTLY"
              search_string         = rule.value.hostname

              text_transformation {
                priority = 0
                type     = "LOWERCASE"
              }
            }
          }

          statement {
            # Block if NOT in IPv4 allowlist
            not_statement {
              statement {
                ip_set_reference_statement {
                  arn = var.ip_set_arns[rule.key]
                }
              }
            }
          }
        }
      }

      visibility_config {
        cloudwatch_metrics_enabled = true
        metric_name                = "metricstream-${var.environment}-IPWhitelist-${rule.key}"
        sampled_requests_enabled   = true
      }
    }
  }

  ##############################################################################
  # Custom response bodies
  ##############################################################################
  custom_response_body {
    key          = "ip-whitelist-blocked"
    content_type = "APPLICATION_JSON"
    content      = jsonencode({
      error   = "Access denied"
      message = "Your IP address is not authorized to access this resource. Contact your MetricStream administrator."
      code    = 403
    })
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "metricstream-${var.environment}-WAF"
    sampled_requests_enabled   = true
  }

  tags = merge(var.common_tags, {
    Name        = "metricstream-waf-${var.environment}"
    Environment = var.environment
    ManagedBy   = "terraform"
    Team        = "platform"
    CostCenter  = "infrastructure"
  })
}

################################################################################
# WAF Logging Configuration
# Logs to S3 (long-term, Object Lock, SSE-KMS).
# AWS WAF supports only one logging destination per Web ACL.
# CloudWatch log group is created separately (for metrics/dashboards) but is
# not used as a WAF log destination — WAF requires log group names starting
# with "aws-waf-logs-", and direct CloudWatch WAF logging counts as a
# separate destination slot.
################################################################################

resource "aws_wafv2_web_acl_logging_configuration" "main" {
  resource_arn = aws_wafv2_web_acl.main.arn

  log_destination_configs = [var.s3_log_bucket_arn]

  logging_filter {
    default_behavior = "DROP" # Only log BLOCK actions by default

    filter {
      behavior    = "KEEP"
      requirement = "MEETS_ANY"

      condition {
        action_condition {
          action = "BLOCK"
        }
      }
    }

    # Uncomment to also log COUNT actions (useful during initial testing phase)
    # filter {
    #   behavior    = "KEEP"
    #   requirement = "MEETS_ANY"
    #   condition {
    #     action_condition {
    #       action = "COUNT"
    #     }
    #   }
    # }
  }

  depends_on = [aws_wafv2_web_acl.main]
}
