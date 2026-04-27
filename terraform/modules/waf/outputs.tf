output "waf_arn" {
  value       = aws_wafv2_web_acl.main.arn
  description = "ARN of the WAF Web ACL — register this in DuploCloud Plan"
}

output "waf_id" {
  value       = aws_wafv2_web_acl.main.id
  description = "ID of the WAF Web ACL"
}

output "waf_name" {
  value       = aws_wafv2_web_acl.main.name
  description = "Name of the WAF Web ACL"
}

output "waf_capacity" {
  value       = aws_wafv2_web_acl.main.capacity
  description = "Current WCU capacity used by the Web ACL (limit: 5000)"
}

output "duplocloud_registration_instructions" {
  value = <<-EOT
    ============================================================
    DuploCloud WAF Registration Instructions
    ============================================================
    1. Navigate to: Administrator → Plans → [Your Plan] → WAF tab
    2. Click "Add"
    3. Fill in:
       Name:    metricstream-waf-${var.environment}
       WAF ARN: ${aws_wafv2_web_acl.main.arn}
    4. Click "Create"

    For Kubernetes Ingress annotation:
       alb.ingress.kubernetes.io/wafv2-acl-arn: "${aws_wafv2_web_acl.main.arn}"
    ============================================================
  EOT
  description = "Step-by-step instructions for registering this WAF in DuploCloud"
}
