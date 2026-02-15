"""
Module 6: IAM Policy Analyzer & Detection Validation

Analyzes MWAA execution role IAM policies to identify the vulnerable
SQS wildcard configuration and generates detection artifacts.

Capabilities:
  - Analyze an IAM role for the vulnerable SQS policy pattern
  - Enumerate MWAA environments and their execution roles
  - Validate whether detection controls (CloudTrail, Config Rules) are in place
  - Generate AWS Config Guard rules for detection
  - Generate CloudWatch/EventBridge detection rules
"""

import json
import re
import textwrap
from typing import Optional

from ..config import AttackerConfig, TargetConfig, MWAA_SQS_ACTIONS
from ..utils import (
    get_iam_client,
    get_mwaa_client,
    get_sts_client,
    print_section,
    print_success,
    print_fail,
    print_info,
    print_warn,
    print_result,
    logger,
)

# Regex patterns for detecting the vulnerable resource ARN
VULNERABLE_ARN_PATTERNS = [
    r"arn:aws:sqs:[^:]*:\*:airflow-celery-\*",
    r"arn:aws:sqs:\*:\*:airflow-celery-\*",
    r"arn:aws:sqs:[^:]*:\*:\*",
    r"arn:aws:sqs:\*:\*:\*",
]


def analyze_policy_document(policy_doc: dict) -> list:
    """
    Analyze an IAM policy document for vulnerable SQS statements.

    Returns a list of findings.
    """
    findings = []

    for stmt in policy_doc.get("Statement", []):
        if stmt.get("Effect") != "Allow":
            continue

        actions = stmt.get("Action", [])
        if isinstance(actions, str):
            actions = [actions]

        # Check if any SQS actions are present
        sqs_actions = [a for a in actions if a.startswith("sqs:") or a == "sqs:*"]
        if not sqs_actions:
            continue

        resources = stmt.get("Resource", [])
        if isinstance(resources, str):
            resources = [resources]

        for resource in resources:
            for pattern in VULNERABLE_ARN_PATTERNS:
                if re.match(pattern, resource):
                    severity = "CRITICAL"
                    # Determine specific risks
                    risks = []
                    action_set = set(sqs_actions)

                    if "sqs:SendMessage" in action_set or "sqs:*" in action_set:
                        risks.append("Data Exfiltration")
                        risks.append("Cross-Account Event Injection")
                        risks.append("DoS (Message Flooding)")

                    if "sqs:ReceiveMessage" in action_set or "sqs:*" in action_set:
                        risks.append("C2 Command Reception")
                        risks.append("DoS (Message Consumption)")

                    if ("sqs:SendMessage" in action_set and "sqs:ReceiveMessage" in action_set) or "sqs:*" in action_set:
                        risks.append("Full C2 Channel")

                    if "sqs:DeleteMessage" in action_set or "sqs:*" in action_set:
                        risks.append("Permanent Message Deletion")

                    if "sqs:GetQueueUrl" in action_set or "sqs:*" in action_set:
                        risks.append("Infrastructure Reconnaissance")

                    findings.append({
                        "severity": severity,
                        "resource": resource,
                        "actions": sqs_actions,
                        "risks": risks,
                        "statement": stmt,
                    })
                    break  # One finding per resource

    return findings


def analyze_role(
    role_name: str,
    region: str = "us-east-1",
    profile: Optional[str] = None,
) -> dict:
    """
    Analyze an IAM role for the vulnerable MWAA SQS policy.

    Checks both inline policies and attached managed policies.
    """
    print_section(f"IAM Policy Analysis: {role_name}")

    iam = get_iam_client(region, profile)
    all_findings = []

    # Check inline policies
    print_info("Checking inline policies...")
    try:
        inline_policies = iam.list_role_policies(RoleName=role_name)
        for policy_name in inline_policies.get("PolicyNames", []):
            policy = iam.get_role_policy(RoleName=role_name, PolicyName=policy_name)
            doc = policy["PolicyDocument"]
            if isinstance(doc, str):
                doc = json.loads(doc)
            findings = analyze_policy_document(doc)
            for f in findings:
                f["policy_name"] = policy_name
                f["policy_type"] = "inline"
            all_findings.extend(findings)
            if findings:
                print_warn(f"  VULNERABLE: Inline policy '{policy_name}'")
            else:
                print_info(f"  OK: Inline policy '{policy_name}'")
    except Exception as e:
        print_fail(f"Failed to check inline policies: {e}")

    # Check attached managed policies
    print_info("Checking attached managed policies...")
    try:
        attached = iam.list_attached_role_policies(RoleName=role_name)
        for policy_meta in attached.get("AttachedPolicies", []):
            policy_arn = policy_meta["PolicyArn"]
            policy_name = policy_meta["PolicyName"]

            # Get the policy version
            policy = iam.get_policy(PolicyArn=policy_arn)
            version_id = policy["Policy"]["DefaultVersionId"]
            version = iam.get_policy_version(PolicyArn=policy_arn, VersionId=version_id)
            doc = version["PolicyVersion"]["Document"]
            if isinstance(doc, str):
                doc = json.loads(doc)

            findings = analyze_policy_document(doc)
            for f in findings:
                f["policy_name"] = policy_name
                f["policy_type"] = "managed"
                f["policy_arn"] = policy_arn
            all_findings.extend(findings)
            if findings:
                print_warn(f"  VULNERABLE: Managed policy '{policy_name}'")
            else:
                print_info(f"  OK: Managed policy '{policy_name}'")
    except Exception as e:
        print_fail(f"Failed to check managed policies: {e}")

    # Summary
    print_section("Analysis Results")
    if all_findings:
        print_warn(f"Found {len(all_findings)} vulnerable SQS policy statement(s)!")
        for i, f in enumerate(all_findings):
            print()
            print_result(f"Finding #{i+1}", f["severity"])
            print_result("Policy", f"{f['policy_type']}: {f['policy_name']}")
            print_result("Resource ARN", f["resource"])
            print_result("SQS Actions", ", ".join(f["actions"]))
            print_result("Attack Vectors", ", ".join(f["risks"]))
    else:
        print_success("No vulnerable SQS policy patterns found.")

    return {
        "role_name": role_name,
        "findings": all_findings,
        "vulnerable": bool(all_findings),
    }


def enumerate_mwaa_environments(
    region: str = "us-east-1",
    profile: Optional[str] = None,
) -> list:
    """List all MWAA environments and their execution roles."""
    print_section("MWAA Environment Enumeration")

    mwaa = get_mwaa_client(region, profile)
    environments = []

    try:
        paginator = mwaa.get_paginator("list_environments")
        for page in paginator.paginate():
            for env_name in page.get("Environments", []):
                try:
                    detail = mwaa.get_environment(Name=env_name)
                    env = detail["Environment"]
                    env_info = {
                        "name": env_name,
                        "status": env.get("Status"),
                        "execution_role_arn": env.get("ExecutionRoleArn"),
                        "source_bucket_arn": env.get("SourceBucketArn"),
                        "dag_s3_path": env.get("DagS3Path"),
                        "airflow_version": env.get("AirflowVersion"),
                        "environment_class": env.get("EnvironmentClass"),
                    }
                    environments.append(env_info)

                    print_result(env_name, env.get("Status", "unknown"))
                    print_result("  Execution Role", env.get("ExecutionRoleArn", "?"))
                    print_result("  DAG Bucket", env.get("SourceBucketArn", "?"))
                    print_result("  DAG Path", env.get("DagS3Path", "?"))
                except Exception as e:
                    print_fail(f"  Failed to get details for {env_name}: {e}")

    except Exception as e:
        print_fail(f"Failed to list MWAA environments: {e}")

    print()
    print_result("Total environments", str(len(environments)))
    return environments


def full_assessment(
    region: str = "us-east-1",
    profile: Optional[str] = None,
) -> dict:
    """
    Run a full assessment: enumerate MWAA environments, then analyze
    each execution role for the vulnerable SQS policy.
    """
    print_section("Full MWAA Security Assessment")

    environments = enumerate_mwaa_environments(region, profile)
    results = []

    for env in environments:
        role_arn = env.get("execution_role_arn")
        if not role_arn:
            continue

        # Extract role name from ARN
        role_name = role_arn.split("/")[-1]
        analysis = analyze_role(role_name, region, profile)
        results.append({
            "environment": env,
            "analysis": analysis,
        })

    # Final summary
    print_section("Assessment Summary")
    vulnerable_count = sum(1 for r in results if r["analysis"]["vulnerable"])
    print_result("Environments assessed", str(len(results)))
    print_result("Vulnerable", str(vulnerable_count))

    if vulnerable_count > 0:
        print_warn(f"\n  {vulnerable_count} environment(s) have the vulnerable SQS policy.")
        print_warn("  This is expected for standard MWAA configurations.")
        print_warn("  See the research documentation for mitigation strategies.")

    return {"environments": results}


def generate_config_guard_rule() -> str:
    """Generate an AWS Config Guard rule for detecting the vulnerable pattern."""
    rule = textwrap.dedent("""\
        # AWS Config Guard Rule: Detect MWAA SQS Wildcard Policy
        # Detects IAM roles with SQS policies containing wildcard account IDs

        let sqs_wildcard_resources = Resources.*[
            Type == "AWS::IAM::Role"
        ]

        rule detect_mwaa_sqs_wildcard when %sqs_wildcard_resources !empty {
            %sqs_wildcard_resources {
                Properties.Policies[*] {
                    PolicyDocument.Statement[*] {
                        when Effect == "Allow" {
                            when Action[*] in [
                                "sqs:SendMessage", "sqs:ReceiveMessage",
                                "sqs:DeleteMessage", "sqs:GetQueueUrl",
                                "sqs:GetQueueAttributes", "sqs:ChangeMessageVisibility",
                                "sqs:*"
                            ] {
                                Resource != /arn:aws:sqs:[^:]*:\\*:airflow-celery-\\*/
                                    <<VIOLATION: IAM role has SQS policy with wildcard account ID
                                    in resource ARN (arn:aws:sqs:*:*:airflow-celery-*).
                                    This enables cross-account data exfiltration, C2 channels,
                                    and other attack vectors via the MWAA execution role.>>
                            }
                        }
                    }
                }
            }
        }
    """)
    return rule


def generate_cloudwatch_detection_queries() -> dict:
    """Generate CloudWatch Insights queries for detecting exploitation."""
    return {
        "cross_account_sqs_send": textwrap.dedent("""\
            # Detect SQS SendMessage to external accounts
            fields @timestamp, eventName, requestParameters.queueUrl, userIdentity.arn
            | filter eventSource = "sqs.amazonaws.com"
            | filter eventName = "SendMessage"
            | filter requestParameters.queueUrl not like /YOUR_ACCOUNT_ID/
            | sort @timestamp desc
            | limit 100
        """),
        "cross_account_sqs_receive": textwrap.dedent("""\
            # Detect SQS ReceiveMessage from external accounts
            fields @timestamp, eventName, requestParameters.queueUrl, userIdentity.arn
            | filter eventSource = "sqs.amazonaws.com"
            | filter eventName = "ReceiveMessage"
            | filter requestParameters.queueUrl not like /YOUR_ACCOUNT_ID/
            | sort @timestamp desc
            | limit 100
        """),
        "sqs_getqueueurl_enumeration": textwrap.dedent("""\
            # Detect SQS GetQueueUrl used for reconnaissance
            fields @timestamp, eventName, requestParameters.queueName,
                   requestParameters.queueOwnerAWSAccountNumber, userIdentity.arn
            | filter eventSource = "sqs.amazonaws.com"
            | filter eventName = "GetQueueUrl"
            | filter requestParameters.queueOwnerAWSAccountNumber != "YOUR_ACCOUNT_ID"
            | stats count() as attempts by requestParameters.queueOwnerAWSAccountNumber
            | sort attempts desc
        """),
        "high_volume_sqs_activity": textwrap.dedent("""\
            # Detect unusually high SQS activity (potential DoS or exfiltration)
            fields @timestamp, eventName, requestParameters.queueUrl, userIdentity.arn
            | filter eventSource = "sqs.amazonaws.com"
            | filter eventName in ["SendMessage", "ReceiveMessage", "DeleteMessage"]
            | stats count() as total by bin(5m), userIdentity.arn, eventName
            | filter total > 100
            | sort total desc
        """),
    }
