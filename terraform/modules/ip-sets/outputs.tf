output "ip_set_arns" {
  value = {
    for k, v in aws_wafv2_ip_set.customer_allowlists :
    k => v.arn
  }
  description = "Map of customer key to IPv4 IP set ARN"
}

output "ip_set_arns_ipv6" {
  value = {
    for k, v in aws_wafv2_ip_set.customer_allowlists_ipv6 :
    k => v.arn
  }
  description = "Map of customer key to IPv6 IP set ARN"
}

output "ip_set_ids" {
  value = {
    for k, v in aws_wafv2_ip_set.customer_allowlists :
    k => v.id
  }
  description = "Map of customer key to IP set ID"
}
