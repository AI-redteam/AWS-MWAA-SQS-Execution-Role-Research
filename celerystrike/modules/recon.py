"""
Module 5: Infrastructure Reconnaissance

Tests the ability to enumerate SQS queues across AWS accounts using
sqs:GetQueueUrl and sqs:GetQueueAttributes permissions from the
MWAA execution role.

This module probes for the existence of airflow-celery-* queues across
a list of target account IDs to map out MWAA environments and similarly
named services.
"""

import json
import time
import concurrent.futures
from typing import Optional

from ..config import (
    AttackerConfig,
    RECON_ENVIRONMENTS,
    REQUIRED_QUEUE_PREFIX,
)
from ..utils import (
    get_sqs_client,
    print_section,
    print_success,
    print_fail,
    print_info,
    print_warn,
    print_result,
    logger,
)


def probe_queue(
    sqs_client,
    account_id: str,
    queue_name: str,
    region: str,
) -> dict:
    """
    Probe for the existence of a specific queue in a target account.

    Uses GetQueueUrl which returns the URL if the queue exists and is
    accessible, or raises an error if it doesn't.
    """
    queue_url = f"https://sqs.{region}.amazonaws.com/{account_id}/{queue_name}"
    result = {
        "account_id": account_id,
        "queue_name": queue_name,
        "region": region,
        "exists": False,
        "queue_url": None,
        "attributes": None,
        "error": None,
    }

    try:
        response = sqs_client.get_queue_url(
            QueueName=queue_name,
            QueueOwnerAWSAccountNumber=account_id,
        )
        result["exists"] = True
        result["queue_url"] = response["QueueUrl"]

        # Try to get queue attributes for additional intelligence
        try:
            attrs_response = sqs_client.get_queue_attributes(
                QueueUrl=response["QueueUrl"],
                AttributeNames=[
                    "ApproximateNumberOfMessages",
                    "ApproximateNumberOfMessagesNotVisible",
                    "CreatedTimestamp",
                    "LastModifiedTimestamp",
                    "QueueArn",
                ],
            )
            result["attributes"] = attrs_response.get("Attributes", {})
        except Exception:
            pass  # Attributes access may be separately restricted

    except Exception as e:
        error_code = getattr(e, "response", {}).get("Error", {}).get("Code", "Unknown")
        result["error"] = error_code
        # AWS.SimpleQueueService.NonExistentQueue means the queue doesn't exist
        # AccessDenied means we can't access it (but it might exist)

    return result


def scan_account(
    sqs_client,
    account_id: str,
    region: str,
    queue_names: Optional[list] = None,
) -> list:
    """Scan a single account for all queue name variants."""
    if queue_names is None:
        queue_names = [
            f"airflow-celery-{env}" for env in RECON_ENVIRONMENTS
        ]

    results = []
    for qname in queue_names:
        result = probe_queue(sqs_client, account_id, qname, region)
        results.append(result)

    return results


def run_recon(
    account_ids: list,
    region: str = "us-east-1",
    queue_names: Optional[list] = None,
    source_profile: Optional[str] = None,
    source_region: Optional[str] = None,
    threads: int = 5,
) -> dict:
    """
    Run infrastructure reconnaissance across multiple accounts.

    Probes for airflow-celery-* queues across a list of target account IDs
    to identify other MWAA environments.
    """
    print_section("Infrastructure Reconnaissance")

    if queue_names is None:
        queue_names = [f"airflow-celery-{env}" for env in RECON_ENVIRONMENTS]

    sqs = get_sqs_client(source_region or region, source_profile)

    total_probes = len(account_ids) * len(queue_names)
    print_info(f"Target accounts: {len(account_ids)}")
    print_info(f"Queue patterns:  {len(queue_names)}")
    print_info(f"Total probes:    {total_probes}")
    print_info(f"Threads:         {threads}")
    print()

    discovered = []
    access_denied = []
    not_found = 0
    probed = 0

    def _probe_task(account_id, queue_name):
        return probe_queue(sqs, account_id, queue_name, region)

    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {}
        for acct in account_ids:
            for qname in queue_names:
                f = executor.submit(_probe_task, acct, qname)
                futures[f] = (acct, qname)

        for future in concurrent.futures.as_completed(futures):
            acct, qname = futures[future]
            probed += 1

            try:
                result = future.result()
            except Exception as e:
                logger.debug("Probe error for %s/%s: %s", acct, qname, e)
                not_found += 1
                continue

            if result["exists"]:
                discovered.append(result)
                print_success(
                    f"FOUND: {acct}/{qname} -> {result['queue_url']}"
                )
                if result["attributes"]:
                    msg_count = result["attributes"].get("ApproximateNumberOfMessages", "?")
                    print_info(f"  Messages in queue: {msg_count}")
                    arn = result["attributes"].get("QueueArn", "?")
                    print_info(f"  ARN: {arn}")
            elif result["error"] == "AccessDenied":
                access_denied.append(result)
                logger.debug("Access denied: %s/%s (may exist)", acct, qname)
            else:
                not_found += 1

            if probed % 50 == 0:
                print_info(f"Progress: {probed}/{total_probes} probed")

    # Summary
    print_section("Reconnaissance Results")
    print_result("Total probes", str(total_probes))
    print_result("Queues discovered", str(len(discovered)))
    print_result("Access denied (may exist)", str(len(access_denied)))
    print_result("Not found", str(not_found))

    if discovered:
        print()
        print_warn("Discovered queues:")
        for d in discovered:
            print_result(
                f"  {d['account_id']}",
                f"{d['queue_name']} ({d['queue_url']})",
            )

    if access_denied:
        print()
        print_info("Access-denied responses (queues may exist with restricted policies):")
        for d in access_denied[:10]:
            print_result(f"  {d['account_id']}", d["queue_name"])
        if len(access_denied) > 10:
            print_info(f"  ... and {len(access_denied) - 10} more")

    return {
        "discovered": discovered,
        "access_denied": access_denied,
        "not_found": not_found,
        "total_probes": total_probes,
    }


def scan_account_range(
    start_account: int,
    count: int = 100,
    region: str = "us-east-1",
    queue_names: Optional[list] = None,
    source_profile: Optional[str] = None,
    source_region: Optional[str] = None,
    threads: int = 5,
) -> dict:
    """
    Scan a numeric range of AWS account IDs.

    Generates account IDs as zero-padded 12-digit numbers starting from
    start_account for count iterations.
    """
    print_section("Account Range Scan")

    account_ids = [str(start_account + i).zfill(12) for i in range(count)]
    print_info(f"Scanning account range: {account_ids[0]} - {account_ids[-1]}")

    return run_recon(
        account_ids=account_ids,
        region=region,
        queue_names=queue_names,
        source_profile=source_profile,
        source_region=source_region,
        threads=threads,
    )


def test_recon_capability(
    attacker: AttackerConfig,
    source_profile: Optional[str] = None,
    source_region: Optional[str] = None,
) -> bool:
    """
    Test that GetQueueUrl works cross-account by probing the attacker's own queue.

    Creates a temporary queue, then probes for it to verify the capability.
    """
    print_section("Recon Capability Test")

    from ..utils import create_test_queue, delete_test_queue, set_queue_policy_allow_cross_account

    sqs_attacker = get_sqs_client(attacker.region, attacker.profile)
    queue_name = "airflow-celery-recon-test"
    queue_url = create_test_queue(sqs_attacker, queue_name)
    attrs = sqs_attacker.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])
    set_queue_policy_allow_cross_account(sqs_attacker, queue_url, attrs["Attributes"]["QueueArn"])

    # Probe using source credentials
    source_sqs = get_sqs_client(
        source_region or attacker.region,
        source_profile,
    )

    result = probe_queue(source_sqs, attacker.account_id, queue_name, attacker.region)

    if result["exists"]:
        print_success("FINDING: GetQueueUrl succeeded cross-account.")
        print_warn("Queue enumeration across accounts is possible via the MWAA execution role.")
        if result["attributes"]:
            print_success("GetQueueAttributes also succeeded - full queue metadata accessible.")
    else:
        print_fail(f"GetQueueUrl failed: {result['error']}")

    # Cleanup
    delete_test_queue(sqs_attacker, queue_url)

    return result["exists"]
