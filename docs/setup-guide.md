# MetricStream WAF — Test Account Setup Guide

Step-by-step guide to stand up the WAF automation in a test AWS account
and verify every workflow end-to-end.

**Your values used throughout this guide:**

| Item | Value |
|---|---|
| AWS Account ID | `419707449206` |
| AWS CLI Profile | `test27` |
| AWS Region | `us-east-1` |
| GitHub Repo | `duplocloud-internal/metricstream-waf` |

---

## Phase 1 — Update Config for Your Test Account

Edit `config/deployments.yaml`. Replace both placeholder account IDs with
your real account ID `419707449206`. Since this is a test, both prod and
nonprod point to the same account.

```yaml
deployments:

  prod-us-east-1:
    account_id: "419707449206"    # ← was 123456789012
    region:     "us-east-1"
    environment: "prod"
    # ... rest unchanged

  nonprod-us-east-1:
    account_id: "419707449206"    # ← was 987654321098
    region:     "us-east-1"
    environment: "nonprod"
    # ... rest unchanged
```

Save the file — do not commit yet.

---

## Phase 2 — Bootstrap AWS Resources

Run all commands with `--profile test27`. These are one-time setup steps.

### 2-A. Variables (run once, used in all commands below)

```bash
export AWS_PROFILE=test27
export ACCOUNT_ID=419707449206
export REGION=us-east-1
export STATE_BUCKET=metricstream-terraform-state-${ACCOUNT_ID}
export LOCK_TABLE=metricstream-terraform-locks
export GITHUB_REPO=duplocloud-internal/metricstream-waf
export ROLE_NAME=MetricStreamWAFDeploy
```

> **Note:** The state bucket name includes the account ID to make it globally
> unique on S3. Each AWS account gets its own dedicated bucket — no cross-account
> IAM is required and blast radius is isolated per account.

After setting the variables, update `config/deployments.yaml`'s `state_backends`
map to include this account:

```yaml
state_backends:
  "419707449206":                              # your test account
    bucket:         "metricstream-terraform-state-419707449206"
    region:         "us-east-1"
    dynamodb_table: "metricstream-terraform-locks"
```

When you later add a second AWS account (e.g., prod account `111122223333`),
add another entry:

```yaml
  "111122223333":
    bucket:         "metricstream-terraform-state-111122223333"
    region:         "us-east-1"
    dynamodb_table: "metricstream-terraform-locks"
```

### 2-B. Terraform State S3 Bucket

```bash
# Create bucket (us-east-1 does NOT use LocationConstraint)
aws s3api create-bucket \
  --bucket "$STATE_BUCKET" \
  --region "$REGION"

# Enable versioning
aws s3api put-bucket-versioning \
  --bucket "$STATE_BUCKET" \
  --versioning-configuration Status=Enabled

# Enable encryption
aws s3api put-bucket-encryption \
  --bucket "$STATE_BUCKET" \
  --server-side-encryption-configuration '{
    "Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]
  }'

# Block all public access
aws s3api put-public-access-block \
  --bucket "$STATE_BUCKET" \
  --public-access-block-configuration \
    "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

# Verify
aws s3api get-bucket-versioning --bucket "$STATE_BUCKET"
```

### 2-C. DynamoDB State Lock Table

```bash
aws dynamodb create-table \
  --table-name "$LOCK_TABLE" \
  --attribute-definitions AttributeName=LockID,AttributeType=S \
  --key-schema AttributeName=LockID,KeyType=HASH \
  --billing-mode PAY_PER_REQUEST \
  --region "$REGION"

# Verify (wait ~10 seconds for ACTIVE status)
aws dynamodb describe-table --table-name "$LOCK_TABLE" \
  --query "Table.TableStatus" --output text
```

### 2-D. GitHub OIDC Provider (one-time per AWS account)

```bash
# Check if it already exists first
aws iam list-open-id-connect-providers \
  --query "OpenIDConnectProviderList[*].Arn" --output text

# If not listed, create it
aws iam create-open-id-connect-provider \
  --url https://token.actions.githubusercontent.com \
  --client-id-list sts.amazonaws.com \
  --thumbprint-list 6938fd4d98bab03faadb97b34396831e3780aea1

# Verify
aws iam list-open-id-connect-providers \
  --query "OpenIDConnectProviderList[*].Arn" --output text
```

### 2-E. IAM Role Trust Policy

```bash
cat > /tmp/waf-trust-policy.json << EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
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
          "token.actions.githubusercontent.com:sub": "repo:${GITHUB_REPO}:*"
        }
      }
    }
  ]
}
EOF

aws iam create-role \
  --role-name "$ROLE_NAME" \
  --assume-role-policy-document file:///tmp/waf-trust-policy.json \
  --description "GitHub Actions OIDC role for MetricStream WAF deployment"

echo "Role ARN: arn:aws:iam::${ACCOUNT_ID}:role/${ROLE_NAME}"
```

### 2-F. IAM Permission Policy

This policy covers every AWS action Terraform performs during WAF deployment.

```bash
cat > /tmp/waf-deploy-policy.json << EOF
{
  "Version": "2012-10-17",
  "Statement": [

    {
      "Sid": "WAFv2FullAccess",
      "Effect": "Allow",
      "Action": ["wafv2:*"],
      "Resource": "*"
    },

    {
      "Sid": "WAFLogBucketAccess",
      "Effect": "Allow",
      "Action": [
        "s3:Get*",
        "s3:List*",
        "s3:CreateBucket",
        "s3:DeleteBucket",
        "s3:PutBucketEncryption",
        "s3:PutBucketObjectLockConfiguration",
        "s3:PutBucketOwnershipControls",
        "s3:PutBucketPolicy",
        "s3:PutBucketPublicAccessBlock",
        "s3:PutBucketTagging",
        "s3:PutBucketVersioning",
        "s3:PutLifecycleConfiguration",
        "s3:PutObject",
        "s3:DeleteObject"
      ],
      "Resource": [
        "arn:aws:s3:::aws-waf-logs-metricstream-*",
        "arn:aws:s3:::aws-waf-logs-metricstream-*/*"
      ]
    },

    {
      "Sid": "TerraformStateBucketAccess",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:PutObject",
        "s3:DeleteObject",
        "s3:ListBucket",
        "s3:GetBucketVersioning"
      ],
      "Resource": [
        "arn:aws:s3:::${STATE_BUCKET}",
        "arn:aws:s3:::${STATE_BUCKET}/*"
      ]
    },

    {
      "Sid": "TerraformStateLock",
      "Effect": "Allow",
      "Action": [
        "dynamodb:GetItem",
        "dynamodb:PutItem",
        "dynamodb:DeleteItem",
        "dynamodb:DescribeTable"
      ],
      "Resource": "arn:aws:dynamodb:${REGION}:${ACCOUNT_ID}:table/${LOCK_TABLE}"
    },

    {
      "Sid": "CloudWatchLogsDescribe",
      "Effect": "Allow",
      "Action": [
        "logs:DescribeLogGroups"
      ],
      "Resource": "*"
    },

    {
      "Sid": "CloudWatchLogsAccess",
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:DeleteLogGroup",
        "logs:PutRetentionPolicy",
        "logs:ListTagsLogGroup",
        "logs:ListTagsForResource",
        "logs:TagLogGroup",
        "logs:TagResource",
        "logs:UntagLogGroup",
        "logs:AssociateKmsKey",
        "logs:DisassociateKmsKey"
      ],
      "Resource": "arn:aws:logs:*:${ACCOUNT_ID}:log-group:/aws/waf/metricstream-*"
    },

    {
      "Sid": "KMSAccess",
      "Effect": "Allow",
      "Action": [
        "kms:CreateKey",
        "kms:CreateAlias",
        "kms:DeleteAlias",
        "kms:DescribeKey",
        "kms:EnableKeyRotation",
        "kms:GetKeyPolicy",
        "kms:GetKeyRotationStatus",
        "kms:ListAliases",
        "kms:ListResourceTags",
        "kms:PutKeyPolicy",
        "kms:ScheduleKeyDeletion",
        "kms:TagResource",
        "kms:UntagResource",
        "kms:UpdateAlias"
      ],
      "Resource": "*"
    },

    {
      "Sid": "CloudWatchAlarmsAccess",
      "Effect": "Allow",
      "Action": [
        "cloudwatch:DeleteAlarms",
        "cloudwatch:DescribeAlarms",
        "cloudwatch:ListTagsForResource",
        "cloudwatch:PutMetricAlarm",
        "cloudwatch:TagResource"
      ],
      "Resource": "arn:aws:cloudwatch:*:${ACCOUNT_ID}:alarm:WAF-*"
    }

  ]
}
EOF

aws iam put-role-policy \
  --role-name "$ROLE_NAME" \
  --policy-name "MetricStreamWAFDeployPolicy" \
  --policy-document file:///tmp/waf-deploy-policy.json

echo "Policy attached to role ${ROLE_NAME}"
```

### 2-G. Verify Role

```bash
aws iam get-role --role-name "$ROLE_NAME" \
  --query "Role.Arn" --output text

aws iam get-role-policy \
  --role-name "$ROLE_NAME" \
  --policy-name "MetricStreamWAFDeployPolicy" \
  --query "PolicyDocument.Statement[*].Sid" \
  --output text
```

---

## Phase 3 — Configure GitHub Repository

### 3-A. Create GitHub Environments

Go to: **https://github.com/duplocloud-internal/metricstream-waf/settings/environments**

Create two environments:

**Environment 1: `nonprod`**
- Click **New environment** → name: `nonprod`
- Deployment branches: `main` only
- No required reviewers (auto-deploys on merge)
- Click **Save protection rules**

**Environment 2: `prod`**
- Click **New environment** → name: `prod`
- Deployment branches: `main` only
- Required reviewers: add **yourself** (for testing, you will self-approve)
- Click **Save protection rules**

### 3-B. Add Repository Secret (optional for first test)

Go to: **https://github.com/duplocloud-internal/metricstream-waf/settings/secrets/actions**

For now, add a placeholder so the Slack notification steps don't fail:

| Secret name | Value |
|---|---|
| `SLACK_WEBHOOK` | `https://hooks.slack.com/placeholder` |

> You can add a real Slack webhook later. The placeholder prevents the curl
> command from erroring but the notification will silently fail — that's fine
> for testing.

---

## Phase 4 — Push Code to GitHub

```bash
# Navigate to the project root (the directory with .github/ and terraform/)
cd /Users/raj/duplocloud/metricstream/waf-automation/metricstream-waf

# Initialize git
git init
git branch -M main

# Add remote (if not already added — run from this directory)
git remote add origin https://github.com/duplocloud-internal/metricstream-waf.git

# Stage everything
git add .
git status   # review what will be committed

# Initial commit
git commit -m "feat: initial MetricStream WAF automation setup"

# Push
git push -u origin main
```

After pushing, go to:
**https://github.com/duplocloud-internal/metricstream-waf/actions**

You should see the **MetricStream WAF** workflow triggered by the push to `main`.

---

## Phase 5 — Watch the First Deployment

### What CI does automatically on push to `main`

1. **`setup-matrix` job** — reads `deployments.yaml`, generates two matrices
   (one for nonprod, one for prod)

2. **`deploy-nonprod` job** — runs automatically, no approval needed
   - Assumes role `arn:aws:iam::419707449206:role/MetricStreamWAFDeploy`
   - Runs `terraform init + apply` for `nonprod-us-east-1`
   - Takes ~3–5 minutes

3. **`deploy-prod` job** — pauses, waiting for your approval
   - You receive an email from GitHub: "Deployment to prod is waiting"
   - Go to the Actions run → click **Review deployments** → approve
   - CI then applies `prod-us-east-1`

### Monitoring the run

```
https://github.com/duplocloud-internal/metricstream-waf/actions
```

Click the running workflow → expand each job to see Terraform output.

### If a job fails

The most common causes and fixes:

| Error | Cause | Fix |
|---|---|---|
| `could not load credentials` | OIDC trust policy wrong repo name | Check `repo:duplocloud-internal/metricstream-waf:*` in trust policy |
| `AccessDenied` on S3 state bucket | State bucket ARN mismatch in IAM policy | Confirm bucket name in policy matches `deployments.yaml` |
| `Error creating S3 Bucket: BucketAlreadyOwnedByYou` | Bucket already exists | Safe to ignore — Terraform will use the existing bucket |
| `AccessDenied on kms:CreateKey` | Missing KMS permission | Verify 2-F policy was attached correctly |

---

## Phase 6 — Verify Deployment in AWS Console

After both deployments succeed:

```bash
# List WAF Web ACLs in your account
aws wafv2 list-web-acls \
  --scope REGIONAL \
  --region us-east-1 \
  --profile test27 \
  --query "WebACLs[?starts_with(Name,'metricstream')].{Name:Name,ARN:ARN}" \
  --output table
```

You should see two WAFs:
```
metricstream-waf-nonprod-us-east-1
metricstream-waf-prod-us-east-1
```

```bash
# Check rules on the nonprod WAF
WAF_NAME=metricstream-waf-nonprod-us-east-1
WAF_ID=$(aws wafv2 list-web-acls --scope REGIONAL --region us-east-1 \
  --profile test27 \
  --query "WebACLs[?Name=='${WAF_NAME}'].Id" --output text)

aws wafv2 get-web-acl \
  --name "$WAF_NAME" --id "$WAF_ID" --scope REGIONAL \
  --region us-east-1 --profile test27 \
  --query "WebACL.Rules[*].{Name:Name,Priority:Priority}" \
  --output table
```

Expected output — 5 rules (4 managed + 1 rate limit):
```
Priority  Name
1         AWSManagedRulesAmazonIpReputationList
2         AWSManagedRulesAnonymousIpList
3         AWSManagedRulesKnownBadInputsRuleSet
4         AWSManagedRulesCommonRuleSet
5         GlobalRateLimit
```

```bash
# Check the S3 log bucket was created
aws s3 ls --profile test27 | grep waf-logs-metricstream

# Check the CloudWatch log group
aws logs describe-log-groups \
  --log-group-name-prefix "/aws/waf/metricstream" \
  --region us-east-1 --profile test27 \
  --query "logGroups[*].logGroupName" --output text
```

---

## Phase 7 — Test a PR-Based Change

Test the end-to-end PR flow by switching the `AnonymousIpList` rule to block mode
on the nonprod deployment.

```bash
cd /Users/raj/duplocloud/metricstream/waf-automation/metricstream-waf

# Create a feature branch
git checkout -b test/switch-anonymous-ip-to-block

# Edit config/deployments.yaml:
# Under nonprod-us-east-1 > managed_rule_modes, change:
#   AnonymousIpList: "count"
# to:
#   AnonymousIpList: "block"
```

Edit the file, then:

```bash
git add config/deployments.yaml
git commit -m "test: switch AnonymousIpList to block on nonprod"
git push -u origin test/switch-anonymous-ip-to-block
```

Now open a pull request:
```
https://github.com/duplocloud-internal/metricstream-waf/compare/test/switch-anonymous-ip-to-block
```

**What CI does on the PR:**
1. `validate` — checks YAML, runs `terraform validate`
2. `plan-nonprod` — posts Terraform plan as a PR comment
3. `plan-prod` — posts Terraform plan as a PR comment

Review the plan comment on the PR — it should show the `AnonymousIpList`
rule changing from `count` to `none` (block).

Merge the PR → CI auto-deploys nonprod, then waits for prod approval.

---

## Phase 8 — Test Workflow_dispatch Forms (No File Editing)

### Test 8-A: Switch a rule mode via GitHub UI

1. Go to: **https://github.com/duplocloud-internal/metricstream-waf/actions/workflows/manage-waf-rules.yml**
2. Click **Run workflow**
3. Fill in:
   - Operation: `switch-rule-mode`
   - Deployment ID: `nonprod-us-east-1`
   - Rule: `CommonRuleSet`
   - Mode: `block`
   - Reason: `Testing workflow_dispatch automation`
4. Click **Run workflow**

The workflow will:
- Update `deployments.yaml` automatically
- Create a branch `waf-config/Switch-CommonRuleSet-block-...`
- Open a PR with the change and description
- CI plans it automatically

Review the auto-created PR at:
```
https://github.com/duplocloud-internal/metricstream-waf/pulls
```

### Test 8-B: Add a customer IP whitelist via GitHub UI

1. Go to: **https://github.com/duplocloud-internal/metricstream-waf/actions/workflows/manage-customer-ip.yml**
2. Click **Run workflow**
3. Fill in:
   - Operation: `add-or-update`
   - Deployment ID: `nonprod-us-east-1`
   - Customer key: `test-customer`
   - Hostname: `test-customer.metricstream.com`
   - Allowed IPs: `1.2.3.4/32` *(use your own public IP for a real test)*
   - Priority offset: `0`
   - Reason: `Testing IP whitelist automation`
4. Click **Run workflow**

An auto-generated PR appears. After merging:

```bash
# Verify the IP set was created
aws wafv2 list-ip-sets \
  --scope REGIONAL --region us-east-1 --profile test27 \
  --query "IPSets[?starts_with(Name,'metricstream-test-customer')].{Name:Name}" \
  --output table
```

### Test 8-C: Add a new deployment via GitHub UI

1. Go to: **https://github.com/duplocloud-internal/metricstream-waf/actions/workflows/add-deployment.yml**
2. Click **Run workflow**
3. Fill in:
   - Deployment ID: `test-us-west-2`
   - Account ID: `419707449206`
   - Region: `us-west-2`
   - Environment: `nonprod`
   - Reason: `Testing multi-region deployment`
4. Click **Run workflow**

Review the auto-created PR → the plan will show a new WAF, S3 bucket, KMS key,
and CloudWatch log group being created in `us-west-2`.

> **Note:** Merging this PR creates real AWS resources in `us-west-2`.
> After testing, manually delete the resources or run `terraform destroy`
> locally to avoid ongoing costs.

---

## Phase 9 — Register WAF in DuploCloud (final step)

After the prod deployment succeeds, get the WAF ARN from the CI output or:

```bash
aws wafv2 list-web-acls \
  --scope REGIONAL --region us-east-1 --profile test27 \
  --query "WebACLs[?Name=='metricstream-waf-prod-us-east-1'].ARN" \
  --output text
```

Then in the DuploCloud portal:
1. **Administrator → Plans → [Your Plan] → WAF tab**
2. Click **Add**
3. Paste the ARN
4. Click **Create**

DuploCloud will use this ARN when associating ALBs with the WAF — and as
confirmed in the implementation, Terraform will never touch those associations.

---

## Quick Reference — Cost of Test Resources

Resources created by this test setup (all in `us-east-1`):

| Resource | Monthly cost |
|---|---|
| 2 WAF Web ACLs | $10.00 |
| 8 managed rules (4 per WAF) | $8.00 |
| 2 KMS keys | $2.00 |
| 2 S3 log buckets (minimal data) | ~$0.01 |
| CloudWatch log groups | ~$0.00 |
| **Total** | **~$20/month** |

To clean up after testing, run `terraform destroy` — but note the S3 log bucket
has `prevent_destroy = true`. You'll need to manually delete the bucket first
(after removing Object Lock, which requires AWS Support for COMPLIANCE mode
buckets), or set `object_lock_retention_days = 1` before destroying.

---

## Troubleshooting Checklist

```bash
# 1. Confirm role exists and trust policy is correct
aws iam get-role --role-name MetricStreamWAFDeploy \
  --profile test27 --query "Role.AssumeRolePolicyDocument" --output json

# 2. Confirm state bucket exists
aws s3api head-bucket \
  --bucket metricstream-terraform-state-419707449206 \
  --profile test27 && echo "EXISTS"

# 3. Confirm DynamoDB lock table exists
aws dynamodb describe-table \
  --table-name metricstream-terraform-locks \
  --profile test27 --query "Table.TableStatus" --output text

# 4. Confirm OIDC provider exists
aws iam list-open-id-connect-providers \
  --profile test27 \
  --query "OpenIDConnectProviderList[*].Arn" --output text

# 5. Test that the role can be assumed from your local machine
aws sts assume-role \
  --role-arn arn:aws:iam::419707449206:role/MetricStreamWAFDeploy \
  --role-session-name test-local \
  --profile test27 \
  --query "Credentials.AccessKeyId" --output text
```
