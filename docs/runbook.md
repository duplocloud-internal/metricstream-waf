# MetricStream WAF — Operational Runbook

## Quick Reference

| Task | Command |
|---|---|
| Validate config | `python3 scripts/validation/pre_deploy_validate.py --env prod` |
| Verify deployment | `./scripts/deployment/post_deploy_verify.sh --env prod --region us-east-1` |
| Check for drift | `./scripts/monitoring/detect_drift.sh --env all` |
| Investigate false positive | `python3 scripts/monitoring/investigate_false_positive.py --env prod --ip <IP>` |
| Set up SIEM streaming | `./scripts/siem/setup_siem_integration.sh --env prod ...` |

---

## Adding a New Customer IP Whitelist

**When:** Customer requests IP-based access restriction.

1. Obtain from customer:
   - Approved IP ranges in CIDR notation (e.g., `203.0.113.0/24`)
   - Confirm their exact MetricStream hostname

2. Choose the next available `priority_offset` (check existing entries in `terraform.tfvars`)

3. Edit `terraform/environments/prod/terraform.tfvars`:
   ```hcl
   customer_ip_whitelists = {
     # ...existing entries...
     "new-customer-key" = {
       hostname         = "new-customer.metricstream.com"
       allowed_ip_cidrs = ["203.0.113.0/24"]
       priority_offset  = 5   # Next available offset
     }
   }
   ```

4. Validate: `python3 scripts/validation/pre_deploy_validate.py --env prod`

5. Create PR — needs Infrastructure Lead approval

6. After merge and CI/CD deploy, verify:
   ```bash
   ./scripts/deployment/post_deploy_verify.sh --env prod --region us-east-1
   ```

7. Test: confirm access from customer's IP succeeds and non-listed IP returns 403

8. Notify customer

**Checklist:**
- [ ] IP CIDRs validated as customer-owned
- [ ] Unique priority_offset assigned
- [ ] Pre-deploy validation passed
- [ ] PR approved by Infrastructure Lead
- [ ] Deployment verified
- [ ] Tested from allowed IP (passes) and non-allowed IP (blocked)
- [ ] Customer notified

---

## Updating an Existing Customer IP Whitelist

Edit `allowed_ip_cidrs` in `terraform.tfvars`, create PR, deploy via CI/CD.
No downtime — IP sets update atomically.

---

## Removing a Customer IP Whitelist

Remove the customer's block from `terraform.tfvars`, create PR, deploy.
Terraform will remove both the WAF rule and the IP set.
Customer traffic will then only be subject to global rules.

---

## Switching a Managed Rule from COUNT to BLOCK

After validation period:

1. In `terraform/modules/waf/main.tf`, change the rule's `override_action`:
   ```hcl
   # Before (COUNT mode — monitoring only):
   override_action { count {} }

   # After (BLOCK mode — active enforcement):
   override_action { none {} }
   ```

2. Deploy to nonprod first, monitor for 48h

3. If no false positives, deploy to prod

4. Monitor CloudWatch alarms for 24h post-deployment

---

## Adding a CRS Rule Override (False Positive Fix)

When a specific CRS rule generates confirmed false positives:

1. Identify the rule name from WAF logs (field: `terminatingRuleId`)

2. Get security team approval (document in ticket)

3. Add to `terraform/environments/prod/terraform.tfvars`:
   ```hcl
   crs_rule_overrides = [
     {
       rule_name     = "SizeRestrictions_BODY"
       reason        = "Bulk import API sends POST bodies up to 5MB. Ticket #12345"
       approved_by   = "Security Team Lead — Jane Smith"
       approved_date = "2026-04-01"
     }
   ]
   ```

4. Create PR, deploy via standard workflow

5. Schedule quarterly review of all overrides

---

## False-Positive Handling Process

### Detection
- Customer reports being blocked
- CloudWatch alarm triggers (high block rate / low allowed requests)
- Daily log review

### Triage

Run the investigation script:
```bash
python3 scripts/monitoring/investigate_false_positive.py \
  --env prod \
  --ip <customer-ip> \
  --hostname <customer-hostname> \
  --hours 24
```

### Severity

| Level | Criteria | Response time |
|---|---|---|
| P1 Critical | Complete customer outage | < 15 min |
| P2 High | Partial functionality lost | < 1 hour |
| P3 Medium | Minor impact, workaround available | < 4 hours |

### P1/P2 Emergency Override

**Option A — Override specific CRS rule to COUNT (recommended):**
```hcl
# In terraform/modules/waf/main.tf, add to the CRS managed_rule_group_statement:
rule_action_override {
  action_to_use { count {} }
  name = "<rule-name>"
}
```
Deploy via emergency Terraform apply (bypass standard PR review, retroactive PR within 24h).

**Option B — Emergency IP allowlist (if customer has static IP):**
Temporarily add customer IP to their allowlist in `terraform.tfvars`.

### Post-Resolution

1. Conduct root cause analysis
2. Implement permanent fix (rule override in tfvars)
3. Remove temporary emergency measures
4. Document in this runbook
5. Schedule quarterly override review

---

## Drift Detection

Drift = AWS resource differs from Terraform state (indicates manual change).

**Automated:** Runs daily at 09:00 UTC via GitHub Actions. Alerts Slack on detection.

**Manual check:**
```bash
./scripts/monitoring/detect_drift.sh --env all --slack-webhook <url>
```

**If drift is detected:**
1. Check AWS CloudTrail for the manual change source
2. If emergency fix: update Terraform to match, create retroactive PR
3. If unauthorized: revert via `terraform apply`, file security incident
4. All manual changes require post-incident review

---

## Emergency WAF Disable

> ⚠️ **Last resort only.** This disables a security control.

```bash
# Get ALB ARN
ALB_ARN=$(aws elbv2 describe-load-balancers --names <alb-name> \
  --query 'LoadBalancers[0].LoadBalancerArn' --output text)

# Disassociate WAF
aws wafv2 disassociate-web-acl --resource-arn "$ALB_ARN" --region <region>

# For Ingress:
kubectl annotate ingress <name> alb.ingress.kubernetes.io/wafv2-acl-arn- -n <namespace>
```

**Required actions after disable:**
- Create P1 incident ticket immediately
- Notify Security Team Lead
- Root cause analysis + fix
- Re-enable WAF with fix
- Post-incident review (PIR) within 5 business days

---

## Updating Global Rule Set

**When:** AWS releases new managed rule, or security team requests change.

**Process:**
1. Get security team approval for the change
2. Update `terraform/modules/waf/main.tf`
3. New rules: always start in `count {}` mode
4. Deploy to nonprod, monitor 48–72h
5. If clean, deploy to prod
6. Switch from COUNT to BLOCK after monitoring period (separate PR)

---

## SIEM Integration

WAF logs stream to SIEM in real-time via CloudWatch Logs subscription filter.

**Setup/update:**
```bash
./scripts/siem/setup_siem_integration.sh \
  --env prod \
  --region us-east-1 \
  --destination-type lambda \
  --destination-arn arn:aws:lambda:us-east-1:ACCOUNT:function:siem-ingest
```

**Correlation key:** `requestId` (present in both WAF logs and ALB access logs)

**Saved CloudWatch Insights queries:**

```sql
-- Daily block summary
fields terminatingRuleId, action
| filter action = "BLOCK"
| stats count() as block_count by terminatingRuleId
| sort block_count desc

-- Top blocked IPs (last 24h)
fields httpRequest.clientIp, httpRequest.country
| filter action = "BLOCK"
| stats count() as blocks by httpRequest.clientIp, httpRequest.country
| sort blocks desc | limit 20

-- Investigate specific IP
fields @timestamp, httpRequest.uri, terminatingRuleId, terminatingRuleMatchDetails
| filter httpRequest.clientIp = "X.X.X.X"
| filter action = "BLOCK"
| sort @timestamp desc

-- Customer-specific blocks
fields @timestamp, httpRequest.uri, terminatingRuleId
| filter httpRequest.headers.0.value = "customer.metricstream.com"
| filter action = "BLOCK"
| stats count() by terminatingRuleId
```

---

## Day-2 Operations Checklist

| Task | Frequency | Tool |
|---|---|---|
| Review WAF block logs for false positives | Daily | `investigate_false_positive.py --summary` |
| Check AllowedRequests metric for drops | Daily | CloudWatch dashboard |
| Process customer IP whitelist requests | As needed | PR workflow |
| Verify SIEM receiving WAF logs | Daily | SIEM dashboard |
| Drift detection | Daily (automated) | GitHub Actions |
| Review rule overrides (still needed?) | Quarterly | Terraform state |
| Review AWS managed rule updates | Monthly | AWS Security Bulletins |
| Validate WAF association after Ingress changes | Per deployment | `post_deploy_verify.sh` |

---

## Contact Escalation

| Role | When to Contact |
|---|---|
| On-call Platform Engineer | P1/P2 incidents outside business hours |
| Infrastructure Team Lead | All WAF configuration changes |
| Security Team Lead | Rule changes, false positive overrides, security incidents |
