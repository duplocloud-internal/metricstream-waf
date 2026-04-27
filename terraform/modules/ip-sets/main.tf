################################################################################
# IP Sets Module — Customer IP allowlists for scope-down rules
################################################################################

resource "aws_wafv2_ip_set" "customer_allowlists" {
  for_each = var.customer_ip_whitelists

  name               = "metricstream-${each.key}-allowlist"
  description        = "IP allowlist for ${each.key} — hostname: ${each.value.hostname}"
  scope              = "REGIONAL"
  ip_address_version = "IPV4"
  addresses          = each.value.allowed_ip_cidrs

  tags = merge(var.common_tags, {
    Name        = "metricstream-${each.key}-allowlist"
    Customer    = each.key
    Environment = var.environment
    Hostname    = each.value.hostname
  })
}

# IPv6 IP sets — separate resource as AWS requires version-specific sets
resource "aws_wafv2_ip_set" "customer_allowlists_ipv6" {
  for_each = {
    for k, v in var.customer_ip_whitelists :
    k => v if length(v.allowed_ip_cidrs_ipv6) > 0
  }

  name               = "metricstream-${each.key}-allowlist-ipv6"
  description        = "IPv6 allowlist for ${each.key} — hostname: ${each.value.hostname}"
  scope              = "REGIONAL"
  ip_address_version = "IPV6"
  addresses          = each.value.allowed_ip_cidrs_ipv6

  tags = merge(var.common_tags, {
    Name        = "metricstream-${each.key}-allowlist-ipv6"
    Customer    = each.key
    Environment = var.environment
  })
}
