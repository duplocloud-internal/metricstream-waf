# MetricStream WAF — Infrastructure as Code

AWS WAF v2 (Regional) implementation for MetricStream using DuploCloud.  
Two shared WAFs (prod + nonprod) with global managed rules and IP-whitelisting scope-down rules per customer.

## Project Structure

```
metricstream-waf/
├── terraform/
│   ├── modules/
│   │   ├── waf/           # Core WAF Web ACL + rules
│   │   ├── ip-sets/       # Customer IP allowlist sets
│   │   ├── logging/       # S3 bucket + CloudWatch + KMS
│   │   └── kms/           # MetricStream-managed KMS key
│   └── environments/
│       ├── prod/          # Production environment root
│       └── nonprod/       # Nonproduction environment root
├── scripts/
│   ├── validation/        # Pre/post deploy checks
│   ├── deployment/        # Deployment helpers
│   ├── monitoring/        # Drift detection, log queries
│   └── siem/              # SIEM integration helpers
├── github/
│   └── workflows/         # CI/CD pipeline definitions
└── docs/                  # Runbooks and decision records
```

## Quick Start

### 1. Prerequisites
- Terraform >= 1.5.0
- AWS CLI configured with sufficient permissions
- S3 backend bucket pre-created (see `docs/bootstrap.md`)

### 2. Deploy Nonprod WAF

```bash
cd terraform/environments/nonprod
terraform init
terraform plan -out=nonprod.tfplan
terraform apply nonprod.tfplan
```

### 3. Deploy Prod WAF

```bash
cd terraform/environments/prod
terraform init
terraform plan -out=prod.tfplan
# Requires PR approval before apply
terraform apply prod.tfplan
```

### 4. Register WAF ARNs in DuploCloud

After deployment, note the output ARNs:
```bash
terraform output waf_arn
```
Then register in DuploCloud: **Administrator → Plans → WAF tab → Add**

## Adding a Customer IP Whitelist

Edit the relevant `terraform.tfvars`:

```hcl
customer_ip_whitelists = {
  "new-customer" = {
    hostname         = "new-customer.metricstream.com"
    allowed_ip_cidrs = ["203.0.113.0/24"]
    priority_offset  = 5   # Results in WAF priority 15 (10 + offset)
  }
}
```

Then run the deployment workflow. See `docs/runbook.md` for full checklist.

## Key Design Decisions

| Decision | Rationale |
|---|---|
| Two WAFs (prod + nonprod) | Environment isolation, $10/month vs per-tenant cost |
| Scope-down = IP whitelist only | Reduces false-positive risk from custom rules |
| Global rules start in COUNT mode | Safe rollout; switch to BLOCK after log review |
| SSE-KMS on WAF log bucket | MetricStream security requirement |
| S3 Object Lock on log bucket | Tamper-proof audit trail |

## Managed Rules — Initial Modes

| Rule Group | Priority | Initial Mode | Switch to BLOCK after |
|---|---|---|---|
| AmazonIpReputationList | 1 | **BLOCK** | Immediate |
| AnonymousIpList | 2 | COUNT | 1–2 weeks of log review |
| KnownBadInputsRuleSet | 3 | **BLOCK** | Immediate |
| CommonRuleSet (CRS) | 4 | COUNT | 1–2 weeks + false-positive analysis |

## Cost Estimate

| Component | Monthly |
|---|---|
| 2 Web ACLs | $10.00 |
| 8 global rules (4 per WAF) | $8.00 |
| IP whitelist rules (varies) | $1.00 per rule/WAF |
| Requests ($0.60/M) | Traffic-based |

## Contacts

- Infrastructure Lead — approve all WAF PRs  
- Security Team Lead — approve rule changes  
- On-call Platform Engineer — P1 incidents
