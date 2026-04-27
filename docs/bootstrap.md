# Bootstrap Guide — Pre-Requisites Before First Deploy

These resources must exist before running `terraform init` in any environment.

## 1. Terraform State Backend

Create the S3 bucket and DynamoDB table for Terraform state:

```bash
# Set your account ID
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
REGION="us-east-1"

# Create state bucket
aws s3api create-bucket \
  --bucket metricstream-terraform-state \
  --region $REGION

# Enable versioning
aws s3api put-bucket-versioning \
  --bucket metricstream-terraform-state \
  --versioning-configuration Status=Enabled

# Enable encryption
aws s3api put-bucket-encryption \
  --bucket metricstream-terraform-state \
  --server-side-encryption-configuration '{
    "Rules": [{
      "ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}
    }]
  }'

# Block public access
aws s3api put-public-access-block \
  --bucket metricstream-terraform-state \
  --public-access-block-configuration \
    "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

# Create DynamoDB table for state locking
aws dynamodb create-table \
  --table-name metricstream-terraform-locks \
  --attribute-definitions AttributeName=LockID,AttributeType=S \
  --key-schema AttributeName=LockID,KeyType=HASH \
  --billing-mode PAY_PER_REQUEST \
  --region $REGION
```

## 2. IAM Roles for CI/CD (GitHub Actions OIDC)

Create IAM roles for GitHub Actions to assume via OIDC (no long-lived credentials):

```bash
# Trust policy for GitHub Actions OIDC
cat > /tmp/gh-actions-trust.json << EOF
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "Federated": "arn:aws:iam::${ACCOUNT_ID}:oidc-provider/token.actions.githubusercontent.com"
    },
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": {
        "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
      },
      "StringLike": {
        "token.actions.githubusercontent.com:sub": "repo:metricstream/metricstream-waf:*"
      }
    }
  }]
}
EOF

# Create prod role
aws iam create-role \
  --role-name MetricStreamWAFDeployProd \
  --assume-role-policy-document file:///tmp/gh-actions-trust.json

# Create nonprod role  
aws iam create-role \
  --role-name MetricStreamWAFDeployNonprod \
  --assume-role-policy-document file:///tmp/gh-actions-trust.json

# Attach WAF management policy to both roles (create policy first)
# Minimum required permissions:
#   wafv2:* (Create/Update/Delete Web ACLs, IP Sets, Logging)
#   s3:* on aws-waf-logs-* buckets
#   logs:* on /aws/waf/metricstream-* log groups
#   kms:* on metricstream-waf-* keys
#   cloudwatch:PutMetricAlarm, cloudwatch:DeleteAlarms
#   iam:PassRole (for CloudWatch → Kinesis if used)
```

## 3. SNS Topics for Alerts

```bash
# Security alerts (WAF blocks, anomalies)
aws sns create-topic --name security-alerts --region $REGION

# Platform alerts (deployment notifications)
aws sns create-topic --name platform-alerts --region $REGION

# Subscribe on-call email to security-alerts
aws sns subscribe \
  --topic-arn arn:aws:sns:${REGION}:${ACCOUNT_ID}:security-alerts \
  --protocol email \
  --notification-endpoint security-oncall@metricstream.com
```

## 4. GitHub Repository Secrets

In GitHub repo settings → Secrets and variables → Actions, add:

| Secret | Value |
|---|---|
| `AWS_ROLE_ARN_PROD` | `arn:aws:iam::<ACCOUNT>:role/MetricStreamWAFDeployProd` |
| `AWS_ROLE_ARN_NONPROD` | `arn:aws:iam::<ACCOUNT>:role/MetricStreamWAFDeployNonprod` |
| `SLACK_WEBHOOK` | Your Slack incoming webhook URL |

## 5. GitHub Environment Protection Rules

In GitHub repo settings → Environments:

**nonprod:** No approval required (auto-deploy on merge to main)

**prod:** Required reviewers:
- Infrastructure Team Lead
- Security Team Lead

Deployment branches: `main` only

## 6. GitHub OIDC Provider (one-time per AWS account)

```bash
aws iam create-open-id-connect-provider \
  --url https://token.actions.githubusercontent.com \
  --client-id-list sts.amazonaws.com \
  --thumbprint-list 6938fd4d98bab03faadb97b34396831e3780aea1
```

---

After completing these steps, you can run `terraform init` and begin deploying.
See the main README for next steps.
