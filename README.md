# aws-preflight

![AWS](https://img.shields.io/badge/AWS_Services-80-FF8C00.svg?style=flat&logo=amazon-aws&logoColor=white)
![Commands](https://img.shields.io/badge/Commands-367-1A73E8.svg?style=flat)
![Checks](https://img.shields.io/badge/Security_Checks-426-00C853.svg?style=flat)
![Python](https://img.shields.io/badge/Python-3.10+-3776AB.svg?style=flat&logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-blue.svg?style=flat)

**Lint AWS CLI commands before they run. Stop security leaks, policy violations, and accidental deletions before they hit your cloud.**

aws-preflight parses your commands locally, evaluates them against 425+ security checks mapped to AWS best practices, and returns actionable findings with severity ratings and remediated command suggestions. Nothing is ever executed. No credentials required. Fully offline.

```
aws-preflight> aws rds create-db-instance --db-instance-identifier prod-db --engine mysql

─────────────────────────────────────────────────────────────────────────────────────────
Command: aws rds create-db-instance
  ⚠️  Issues detected:

  [HIGH]   🔴 RDS storage encryption not enabled
  ℹ  Unencrypted RDS snapshots can be shared or copied to another account,
     exposing your entire database. Encryption cannot be enabled after creation.
  → Add: --storage-encrypted

  [MEDIUM] 🟡 Deletion protection not enabled
  ℹ  Without this, a single delete command permanently destroys your database.
  → Add: --deletion-protection

  [MEDIUM] 🟡 Backup retention period not specified
  ℹ  Default retention is 1 day. Set to at least 7 for production workloads.
  → Add: --backup-retention-period 7

  [MEDIUM] 🟡 CloudWatch log exports not configured
  ℹ  Without log exports, no visibility into queries, errors, or suspicious logins.
  → Add: --enable-cloudwatch-logs-exports '["error","audit"]'

  💡  Suggested command:

  aws rds create-db-instance \
    --db-instance-identifier prod-db \
    --engine mysql \
    --storage-encrypted \
    --deletion-protection \
    --backup-retention-period 7 \
    --enable-cloudwatch-logs-exports '["error","audit"]'
```

---

## Why This Exists:

The AWS CLI has no guardrails. A single command can:

- Expose an S3 bucket to the public internet with `--acl public-read`.
- Launch an EC2 instance without IMDSv2, leaking IAM credentials to any process on the box.
- Create a publicly accessible RDS instance with no encryption and a 1-day backup window.
- Attach `AdministratorAccess` to any role, user, or group.
- Stop CloudTrail logging, delete a KMS key, or remove S3 Block Public Access in one line.

These misconfigurations are the root cause of the majority of cloud breaches. AWS Config, GuardDuty, and Security Hub detect them *after* the resource exists. aws-preflight catches them *before the command runs*.

---

## Quick Start:

```bash
git clone https://github.com/gabrielPav/aws-preflight.git
cd aws-preflight
chmod +x aws-preflight
./aws-preflight
```

**Requirements:** Python 3.10+. No pip install. No external packages. No build step.

Zero install. Zero dependencies. Zero supply chain risk. Just clone and run it.

---

## Usage:

### Interactive Mode

```bash
./aws-preflight
```

Type AWS CLI commands as you normally would. They are analyzed, never executed:

```
aws-preflight> aws ec2 run-instances --image-id ami-0123abc123abc123c --count 1
aws-preflight> aws iam attach-role-policy --role-name ec2-dev --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
aws-preflight> aws s3 sync . s3://prod-bucket/ --delete --acl public-read
```

To execute a command against AWS without leaving the shell:

```
aws-preflight> run aws s3 ls
aws-preflight> !aws sts get-caller-identity
```

| Command | Action |
|---|---|
| `aws <...>` | Lint only. Not executed. |
| `run <...>` or `!<...>` | Bypass linter, execute against AWS |
| `help` | Show available commands |
| `exit` / `quit` / `Ctrl+C` | Leave the shell |

### Single Command

```bash
./aws-preflight "aws s3api create-bucket --bucket prod-bucket"
```

### Pipe / Batch Mode

```bash
# Lint every AWS command in a deploy script
grep '^aws ' deploy.sh | ./aws-preflight

# Lint a runbook or command list
cat commands.txt | ./aws-preflight
```

### JSON Output (CI/CD)

```bash
# Structured JSON output for pipeline integration
./aws-preflight --json "aws ec2 run-instances --image-id ami-0123abc123abc123c"
```

```json
{
  "command": "aws ec2 run-instances",
  "service": "ec2",
  "operation": "run-instances",
  "passed": false,
  "findings": [
    {
      "severity": "HIGH",
      "message": "IMDSv2 not enforced",
      "context": "Without this, any process running on the instance can steal IAM role credentials with a single curl command.",
      "suggestion": "--metadata-options HttpTokens=required"
    },
    {
      "severity": "HIGH",
      "message": "Root volume encryption not specified",
      "context": "Unencrypted EBS volumes can be detached and mounted on another instance, exposing all data at rest.",
      "suggestion": "--block-device-mappings '[{\"DeviceName\":\"/dev/xvda\",\"Ebs\":{\"Encrypted\":true}}]'"
    }
  ],
  "summary": {
    "total": 3,
    "high": 2,
    "medium": 0,
    "low": 1,
    "info": 0
  },
  "suggested_command": "aws ec2 run-instances ..."
}
```

### Exit Code Gating

Control which severity levels fail your pipeline:

```bash
# Fail only on HIGH severity findings (exit code 1)
./aws-preflight --json --min-severity HIGH "aws ec2 run-instances --image-id ami-0123abc123abc123c"

# Fail on MEDIUM and above (default)
./aws-preflight --json --min-severity MEDIUM "aws s3api create-bucket --bucket test"

# Fail on any finding including LOW and INFO
./aws-preflight --json --min-severity INFO "aws s3 cp data.csv s3://prod-bucket/"
```

| `--min-severity` | Fails on |
|---|---|
| `HIGH` | HIGH only |
| `MEDIUM` (default) | HIGH + MEDIUM |
| `LOW` | HIGH + MEDIUM + LOW |
| `INFO` | All findings |

### Pipeline Examples

```bash
# GitHub Actions. Fail deployment on HIGH findings
- name: Security lint
  run: |
    grep '^aws ' deploy.sh | ./aws-preflight --json --min-severity HIGH

# GitLab CI. Gate on any MEDIUM+ issue
security-lint:
  script:
    - cat deploy-commands.txt | ./aws-preflight --json --min-severity MEDIUM

# Parse with jq
./aws-preflight --json "aws iam create-access-key" | jq '.summary'
```

---

## Coverage

**367 commands | 426 checks | 80 AWS services | 0 dependencies**

| Category | Services | Key Checks |
|---|---|---|
| **Compute** | EC2, Lambda, Batch, Lightsail, Elastic Beanstalk, Auto Scaling, WorkSpaces | IMDSv2, EBS encryption, SG open ports, execution role scoping, instance lifecycle |
| **Storage** | S3, S3 Access Points, EBS, EFS, FSx, Glacier, Backup | Block Public Access, ACL restrictions, encryption at rest, MFA Delete, access point policies |
| **Databases** | RDS, Aurora, DynamoDB, ElastiCache, Redshift, Neptune, DocumentDB, QLDB, DMS | Storage encryption, public access, deletion protection, backup retention, parameter groups |
| **Networking** | VPC, ALB/NLB/CLB, API Gateway v1/v2, CloudFront, WAF, Direct Connect, Transit Gateway, Global Accelerator, Route 53, Network Firewall, App Mesh | HTTPS enforcement, 0.0.0.0/0 rules, TLS policy, access logging, route table safety |
| **Security** | IAM, KMS, Secrets Manager, Cognito, ACM, GuardDuty, Shield, Inspector, RAM | Admin policy detection, wildcard principals, key rotation, MFA enforcement, resource sharing |
| **AI/ML** | Bedrock, SageMaker, Rekognition, Comprehend, Lex, Polly, Translate, Forecast | KMS encryption, VPC deployment, direct internet access, PII handling, model customization |
| **Containers** | ECR, ECS, EKS | Image scanning, secrets encryption, control plane logging, privileged mode |
| **Serverless** | Lambda, Step Functions, EventBridge, AppSync | Tracing, execution logging, wildcard invocation, auth type validation, function URLs |
| **Management** | CloudFormation, CloudTrail, CloudWatch, Organizations, SSM, Transfer, Proton | Multi-region trails, log integrity, termination protection, SCP governance, Run Command |
| **Messaging** | SNS, SQS, MQ | KMS encryption, policy wildcard detection, HTTPS enforcement, broker security |
| **Analytics** | Athena, EMR, Kinesis, Firehose, Glue, Elasticsearch | Query encryption, security configs, stream encryption, role scoping, domain access policies |

---

## Detection Engine

### Check Types

| Type | Triggers When | Example |
|---|---|---|
| `missing_flag` | A required security flag is absent or has the wrong value | `ec2 run-instances` without `--metadata-options HttpTokens=required` |
| `forbidden_value` | A flag has a known-dangerous value | `--acl public-read`, `--cidr 0.0.0.0/0`, `--policy-arn arn:aws:iam::aws:policy/AdministratorAccess` |
| `always_warn` | The operation itself is inherently risky | `cloudtrail stop-logging`, `kms schedule-key-deletion` |

### Severity Levels

| Level | Icon | Meaning |
|---|---|---|
| `HIGH` | 🔴 | Immediate security exposure or irreversible data loss. 229 checks |
| `MEDIUM` | 🟡 | Significant risk that should be addressed before production. 136 checks |
| `LOW` | 🔵 | Best-practice gap with low immediate impact. 7 checks |
| `INFO` | ℹ️ | Advisory guidance. Worth reviewing, not blocking. 54 checks |

---

## Example Outputs

**IAM privilege escalation:**
```
aws-preflight> aws iam attach-role-policy --role-name lambda-role \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

  [HIGH] 🔴 Attaching AdministratorAccess (full AWS access granted)
  ℹ  AdministratorAccess is the most powerful policy in AWS. If this role is
     ever compromised, the attacker owns your entire account.
```

**Public S3 upload:**
```
aws-preflight> aws s3 cp data.csv s3://prod-bucket/ --acl public-read

  [HIGH] 🔴 File uploaded with public-read ACL
  ℹ  This object will be accessible to anyone with the URL (no credentials needed).
  → Add: --acl private
```

**EKS cluster missing security controls:**
```
aws-preflight> aws eks create-cluster --name prod --role-arn arn:aws:iam::123456789012:role/eks

  [HIGH] 🔴 EKS secrets encryption not configured
  ℹ  Kubernetes secrets are stored in etcd in base64, not encrypted.

  [HIGH] 🔴 EKS control plane logging not enabled
  ℹ  Without audit logs, no visibility into who accessed the Kubernetes API.

  [MEDIUM] 🟡 Public endpoint access. Verify that IP restrictions are in place.
```

**Dangerous operations caught:**
```
aws-preflight> aws s3api delete-public-access-block --bucket prod-data

  [HIGH] 🔴 Removing Block Public Access (bucket may become publicly accessible)
  ℹ  Any existing public ACLs or bucket policies will immediately take effect,
     potentially exposing data to the Internet.
```

**Clean command (no issues):**
```
aws-preflight> aws s3api put-bucket-versioning --bucket prod-bucket \
  --versioning-configuration Status=Enabled

  ✅  No obvious security issues detected
```

---

## Adding Custom Rules

Drop a `.json` file in `rules/` or add entries to any existing file. The engine loads all rule files automatically.

```json
[
  {
    "command": "ec2 run-instances",
    "checks": [
      {
        "type": "missing_flag",
        "flag": "--metadata-options",
        "expected_value": "HttpTokens=required",
        "severity": "HIGH",
        "message": "IMDSv2 not enforced",
        "context": "Any process on the instance can steal IAM credentials via IMDS without authentication.",
        "suggestion": "--metadata-options HttpTokens=required"
      }
    ]
  }
]
```

Rules from multiple files for the same command are merged automatically.

### Rule Schema

| Field | Required | Description |
|---|---|---|
| `command` | Yes | AWS CLI subcommand, e.g. `s3api create-bucket` |
| `checks[].type` | Yes | `missing_flag`, `forbidden_value`, or `always_warn` |
| `checks[].flag` | For `missing_flag`/`forbidden_value` | The CLI flag to inspect |
| `checks[].expected_value` | Optional | Substring the flag value must contain |
| `checks[].forbidden_value` | For `forbidden_value` | Value that triggers the finding |
| `checks[].severity` | Yes | `HIGH`, `MEDIUM`, `LOW`, or `INFO` |
| `checks[].message` | Yes | One-line finding description |
| `checks[].context` | Recommended | Detailed explanation of the risk |
| `checks[].suggestion` | Optional | Flag to add to the remediated command |

---

## Architecture

```
aws-preflight/
├── aws-preflight       # Shell wrapper entry point
├── main.py             # CLI arg parsing, interactive REPL, JSON/text output routing
├── parser.py           # shlex-based tokenizer. Handles --flag value and --flag=value
├── engine.py           # Rule loader + evaluator (missing_flag, forbidden_value, always_warn)
├── formatter.py        # Human-readable + JSON formatters, exit code logic
├── rules/              # 51 JSON rule files, one per service group
│   ├── ec2.json        #   36 commands, 39 checks
│   ├── iam.json        #   26 commands, 28 checks
│   ├── s3.json         #   16 commands, 20 checks
│   ├── networking.json #   16 commands, 17 checks
│   ├── rds.json        #   12 commands, 19 checks
│   ├── ml.json         #   16 commands, 17 checks
│   ├── lightsail.json  #   13 commands, 14 checks
│   └── ... (44 more)
└── README.md
```

---
