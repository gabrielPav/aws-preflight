# aws-preflight

![Checks](https://img.shields.io/badge/Security_Checks-663-00C853.svg?style=flat)
![Commands](https://img.shields.io/badge/Commands-560-1A73E8.svg?style=flat)
![AWS](https://img.shields.io/badge/AWS_Services-91-FF8C00.svg?style=flat&logo=amazon-aws&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.10+-5B86B3.svg?style=flat&logo=python&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-blue.svg?style=flat)

**Security linter for AWS CLI commands. Catches misconfigurations before they hit your cloud.**

660+ security checks across 91 AWS services. Findings include severity ratings and a remediated command.

```
aws-preflight> aws rds create-db-instance --db-instance-identifier prod-db --db-instance-class db.m5.large --engine mysql --allocated-storage 50 --master-username <dba-name> --master-user-password <dba-password>

────────────────────────────────────────────────────────────
Command: aws rds create-db-instance

  ⚠️ Issues detected:

  [HIGH] 🔴 RDS storage encryption not enabled
  ℹ️  Unencrypted RDS snapshots can be shared or copied to another account,
     exposing your entire database. Encryption cannot be enabled after
     creation, you'd need to snapshot, restore, and migrate.
  → Add: --storage-encrypted

  [HIGH] 🔴 Public accessibility not explicitly disabled. RDS may default to publicly accessible
  ℹ️  Depending on VPC and subnet group configuration, RDS instances can
     default to publicly accessible. Always explicitly set
     --no-publicly-accessible to ensure the database is not reachable
     from the Internet.
  → Add: --no-publicly-accessible

  [MEDIUM] 🟡 Deletion protection not enabled
  ℹ️  Without this, a single 'rds delete-db-instance' command permanently
     destroys your database.
  → Add: --deletion-protection

  [MEDIUM] 🟡 Backup retention period not specified
  ℹ️  Default retention is 1 day. Set to at least 7 for production workloads.
  → Add: --backup-retention-period 7

  [MEDIUM] 🟡 CloudWatch log exports not configured
  ℹ️  Without log exports, no visibility into errors or
     suspicious login attempts.
  → Add: --enable-cloudwatch-logs-exports '["error"]'

  [MEDIUM] 🟡 IAM database authentication not enabled
  ℹ️  IAM authentication lets applications connect using short-lived tokens
     instead of static database passwords.
  → Add: --enable-iam-database-authentication

 ⚡ Suggested command:

aws rds create-db-instance \
  --db-instance-identifier prod-db \
  --db-instance-class db.m5.large \
  --engine mysql \
  --allocated-storage 50 \
  --master-username '<dba-name>' \
  --master-user-password '<dba-password>' \
  --storage-encrypted \
  --deletion-protection \
  --no-publicly-accessible \
  --backup-retention-period 7 \
  --enable-cloudwatch-logs-exports '["error"]' \
  --enable-iam-database-authentication
```

---

## The Problem

The AWS CLI has no guardrails. A single command can:

- Launch an EC2 instance without IMDSv2, leaking IAM credentials to any process on the box.
- Create a publicly accessible RDS instance with no encryption and a 1-day backup window.
- Expose an S3 bucket to the public internet with `--acl public-read`.
- Attach `AdministratorAccess` to any role, user, or group.
- Stop CloudTrail logging, delete a KMS key, or remove S3 Block Public Access in one line.

AWS Config, GuardDuty, and Security Hub catch these *after* the resource exists. aws-preflight catches them *before the command runs*.

---

## Examples

**IAM privilege escalation:**
```
aws-preflight> aws iam attach-role-policy --role-name lambda-role \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

  [HIGH] 🔴 Attaching AdministratorAccess — full AWS access granted
  ℹ️  AdministratorAccess is the most powerful policy in AWS. If this role is
     ever compromised, the attacker owns your entire account. Grant only the
     specific actions and resources the role actually needs.
```

**EKS cluster missing security controls:**
```
aws-preflight> aws eks create-cluster --name prod \
  --role-arn arn:aws:iam::123456789012:role/eks-service-role \
  --resources-vpc-config subnetIds=subnet-0abc123abc123abca,subnet-0123abc123abc123c

  [HIGH] 🔴 EKS control plane logging not enabled
  ℹ️  Without control plane logs (api, audit, authenticator,
     controllerManager, scheduler), you have no visibility into who
     accessed the Kubernetes API or what changes were made.

  [HIGH] 🔴 EKS secrets encryption not configured
  ℹ️  Without envelope encryption, Kubernetes secrets are stored in etcd
     in base64 only - not encrypted. Use a KMS key to encrypt secrets
     at rest.

  [MEDIUM] 🟡 Verify the cluster endpoint is not publicly accessible
     without IP restrictions
  ℹ️  By default, the EKS API server endpoint is publicly accessible.
     Restrict access using publicAccessCidrs or disable public access.
```

**Dangerous operation caught:**
```
aws-preflight> aws s3api delete-public-access-block --bucket prod-data

  [HIGH] 🔴 Removing Block Public Access - bucket may become publicly accessible
  ℹ️  Deleting the public access block removes all four protections.
     Any existing public ACLs or bucket policies will immediately take
     effect, potentially exposing data to the Internet.
```

**Clean command - all security flags present:**
```
aws-preflight> aws cloudtrail create-trail --name prod-trail \
  --s3-bucket-name trail-logs --is-multi-region-trail \
  --enable-log-file-validation --kms-key-id alias/cloudtrail-key

  ✅  No obvious security issues detected
```

---

## Quick Start

```bash
git clone https://github.com/gabrielPav/aws-preflight.git
cd aws-preflight
chmod +x aws-preflight
./aws-preflight
```

**Requirements:** Python 3.10+. No pip install, no build step, no dependencies. Zero supply chain risk.

---

## Usage

### Interactive Mode

```bash
./aws-preflight
```

Type AWS CLI commands as you normally would. They are analyzed, never executed:

```
aws-preflight> aws ec2 run-instances --image-id ami-0abc123abc123abca --instance-type t3.medium
aws-preflight> aws iam attach-role-policy --role-name dev-role --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
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
./aws-preflight --json "aws ec2 run-instances --image-id ami-0123abc123abc123c --instance-type t3.micro --subnet-id subnet-0abc123abc123abca"
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
      "context": "Without this, any process running on the instance (including malware) can steal the attached IAM role credentials with a single curl command - no authentication required.",
      "suggestion": "--metadata-options HttpTokens=required"
    },
    {
      "severity": "HIGH",
      "message": "Root volume encryption not specified",
      "context": "Unencrypted EBS volumes can be detached and mounted on another instance, exposing all data at rest. Encryption is free and has no performance impact on modern instance types.",
      "suggestion": "--block-device-mappings '[{\"DeviceName\":\"/dev/xvda\",\"Ebs\":{\"Encrypted\":true}}]'"
    },
    {
      "severity": "HIGH",
      "message": "Public IP association not explicitly disabled",
      "context": "Without explicitly setting --no-associate-public-ip-address, instances in a default VPC or a subnet with auto-assign public IP enabled will receive a public IP.",
      "suggestion": "--no-associate-public-ip-address"
    },
    {
      "severity": "LOW",
      "message": "Detailed monitoring not enabled",
      "context": "Without detailed monitoring, CloudWatch metrics are only available at 5-minute intervals.",
      "suggestion": "--monitoring Enabled=true"
    }
  ],
  "summary": {
    "total": 4,
    "high": 3,
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
# Fail only on HIGH findings
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
# GitHub Actions - fail deployment on HIGH findings
- name: Security lint
  run: grep '^aws ' deploy.sh | ./aws-preflight --json --min-severity HIGH

# GitLab CI - gate on MEDIUM+
security-lint:
  script: cat deploy-commands.txt | ./aws-preflight --json --min-severity MEDIUM

# Parse with jq
./aws-preflight --json "aws iam create-access-key" | jq '.summary'
```

---

## Coverage

**560 commands | 663 checks | 91 AWS services | 0 dependencies**

| Category | Services | Key Checks |
|---|---|---|
| **Compute** | EC2, Lambda, Batch, Lightsail, Elastic Beanstalk, Auto Scaling, WorkSpaces | IMDSv2, EBS encryption, security group open ports, execution role scoping |
| **Storage** | S3, S3 Access Points, EBS, EFS, FSx, Glacier, Backup | Block Public Access, ACL restrictions, encryption at rest, MFA Delete |
| **Databases** | RDS, Aurora, DynamoDB, ElastiCache, Redshift, Neptune, DocumentDB, QLDB, DMS | Storage encryption, public access, deletion protection, backup retention, PITR |
| **Networking** | VPC, ALB/NLB/CLB, API Gateway v1/v2, CloudFront, WAF, Direct Connect, Transit Gateway, Route 53, Network Firewall, OpenSearch | HTTPS enforcement, 0.0.0.0/0 rules, TLS policy, access logging |
| **Security** | IAM, KMS, Secrets Manager, Cognito, ACM, GuardDuty, Shield, Inspector, RAM, Macie | Admin policy detection, wildcard principals, key rotation, MFA enforcement |
| **AI/ML** | Bedrock, SageMaker, Rekognition, Comprehend, Lex, Polly, Translate, Forecast | KMS encryption, VPC deployment, direct internet access, PII handling |
| **Containers** | ECR, ECS, EKS | Image scanning, tag mutability, secrets encryption, control plane logging |
| **Serverless** | Lambda, Step Functions, EventBridge, AppSync | Tracing, execution logging, auth type validation, function URLs |
| **Management** | CloudFormation, CloudTrail, CloudWatch, Organizations, SSM, Transfer, Proton, AWS Config | Multi-region trails, log integrity, termination protection, session logging |
| **Messaging** | SNS, SQS, MQ | KMS encryption, policy wildcard detection, HTTPS enforcement |
| **Analytics** | Athena, EMR, Kinesis, Firehose, Glue, OpenSearch | Query encryption, stream encryption, domain access policies |
| **DevTools** | CodeCommit, CodeBuild, CodePipeline, CodeDeploy, CodeArtifact | Secrets in env vars, approval gates, deployment rollback |

### Severity Levels

| Level | Icon | Meaning | Count |
|---|---|---|---|
| `HIGH` | 🔴 | Immediate security exposure or irreversible data loss | 366 |
| `MEDIUM` | 🟡 | Significant risk - address before production | 210 |
| `LOW` | 🔵 | Best-practice gap, low immediate impact | 7 |
| `INFO` | ℹ️ | Advisory - worth reviewing, not blocking | 80 |

---

## Adding Custom Rules

Drop a `.json` file in `rules/` or add entries to any existing file. Rules for the same command are merged automatically.

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

### Check Types

| Type | Triggers When | Example |
|---|---|---|
| `missing_flag` | A required security flag is absent or has the wrong value | `ec2 run-instances` without `--metadata-options HttpTokens=required` |
| `forbidden_value` | A flag has a known-dangerous value | `--acl public-read`, `--cidr 0.0.0.0/0`, `--policy-arn ...AdministratorAccess` |
| `always_warn` | The operation itself is inherently risky | `cloudtrail stop-logging`, `kms schedule-key-deletion` |

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
├── aws-preflight         # Shell wrapper entry point
├── main.py               # CLI arg parsing, interactive REPL, JSON/text output routing
├── cli_parser.py         # shlex-based tokenizer. Handles --flag value and --flag=value
├── engine.py             # Rule loader + evaluator (missing_flag, forbidden_value, always_warn)
├── formatter.py          # Human-readable + JSON formatters, exit code logic
└── rules/                # 64 JSON rule files, one per service group
```
