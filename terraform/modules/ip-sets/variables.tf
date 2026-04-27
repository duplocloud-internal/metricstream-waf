variable "environment" {
  description = "Environment name: prod or nonprod"
  type        = string
}

variable "customer_ip_whitelists" {
  description = <<-EOT
    Map of customers with IP whitelisting enabled.
    Only customers explicitly listed here receive a scope-down WAF rule.
    Customers not listed are subject to global rules only.

    priority_offset: Added to base priority 10. Must be unique across all customers.
      Customer 1 → priority_offset = 0 → WAF priority 10
      Customer 2 → priority_offset = 1 → WAF priority 11
      ...

    allowed_ip_cidrs: IPv4 CIDR ranges. Use /32 for single IPs.
    allowed_ip_cidrs_ipv6: IPv6 CIDR ranges. Use /128 for single IPs.
  EOT
  type = map(object({
    hostname              = string
    allowed_ip_cidrs      = list(string)
    allowed_ip_cidrs_ipv6 = optional(list(string), [])
    priority_offset       = number
  }))
  default = {}

  validation {
    condition = alltrue([
      for k, v in var.customer_ip_whitelists :
      v.priority_offset >= 0 && v.priority_offset <= 89
    ])
    error_message = "priority_offset must be between 0 and 89 (WAF priorities 10–99 are reserved for IP whitelists)."
  }

  validation {
    condition = length(
      distinct([for k, v in var.customer_ip_whitelists : v.priority_offset])
    ) == length(var.customer_ip_whitelists)
    error_message = "Each customer must have a unique priority_offset."
  }
}

variable "common_tags" {
  description = "Common tags applied to all resources"
  type        = map(string)
  default     = {}
}
