"""
Shared utilities for the MWAA security testing tool.
"""

import json
import logging
import sys
import time
from typing import Optional

import boto3
import botocore.exceptions

from .config import REQUIRED_QUEUE_PREFIX

logger = logging.getLogger("mwaa_security_tool")


def setup_logging(verbose: bool = False) -> None:
    """Configure logging for the tool."""
    level = logging.DEBUG if verbose else logging.INFO
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(
        logging.Formatter("[%(levelname)s] %(name)s: %(message)s")
    )
    root = logging.getLogger("mwaa_security_tool")
    root.setLevel(level)
    root.addHandler(handler)


def get_sqs_client(region: str, profile: Optional[str] = None):
    """Create a boto3 SQS client."""
    session_kwargs = {}
    if profile:
        session_kwargs["profile_name"] = profile
    session = boto3.Session(region_name=region, **session_kwargs)
    return session.client("sqs")


def get_s3_client(region: str, profile: Optional[str] = None):
    """Create a boto3 S3 client."""
    session_kwargs = {}
    if profile:
        session_kwargs["profile_name"] = profile
    session = boto3.Session(region_name=region, **session_kwargs)
    return session.client("s3")


def get_iam_client(region: str, profile: Optional[str] = None):
    """Create a boto3 IAM client."""
    session_kwargs = {}
    if profile:
        session_kwargs["profile_name"] = profile
    session = boto3.Session(region_name=region, **session_kwargs)
    return session.client("iam")


def get_sts_client(region: str, profile: Optional[str] = None):
    """Create a boto3 STS client."""
    session_kwargs = {}
    if profile:
        session_kwargs["profile_name"] = profile
    session = boto3.Session(region_name=region, **session_kwargs)
    return session.client("sts")


def get_mwaa_client(region: str, profile: Optional[str] = None):
    """Create a boto3 MWAA client."""
    session_kwargs = {}
    if profile:
        session_kwargs["profile_name"] = profile
    session = boto3.Session(region_name=region, **session_kwargs)
    return session.client("mwaa")


def validate_queue_name(queue_name: str) -> bool:
    """Check that a queue name matches the vulnerable pattern."""
    return queue_name.startswith(REQUIRED_QUEUE_PREFIX)


def create_test_queue(
    sqs_client,
    queue_name: str,
    message_retention: int = 345600,
) -> str:
    """Create an SQS queue for testing and return its URL."""
    if not validate_queue_name(queue_name):
        raise ValueError(
            f"Queue name must start with '{REQUIRED_QUEUE_PREFIX}'. "
            f"Got: {queue_name}"
        )

    logger.info("Creating SQS queue: %s", queue_name)
    response = sqs_client.create_queue(
        QueueName=queue_name,
        Attributes={
            "MessageRetentionPeriod": str(message_retention),
            "VisibilityTimeout": "30",
        },
    )
    queue_url = response["QueueUrl"]
    logger.info("Queue created: %s", queue_url)
    return queue_url


def set_queue_policy_allow_cross_account(sqs_client, queue_url: str, queue_arn: str) -> None:
    """Set a permissive policy on a queue to allow cross-account SendMessage."""
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowCrossAccountSend",
                "Effect": "Allow",
                "Principal": {"AWS": "*"},
                "Action": ["sqs:SendMessage", "sqs:ReceiveMessage", "sqs:DeleteMessage",
                           "sqs:GetQueueAttributes", "sqs:GetQueueUrl"],
                "Resource": queue_arn,
            }
        ],
    }
    sqs_client.set_queue_attributes(
        QueueUrl=queue_url,
        Attributes={"Policy": json.dumps(policy)},
    )
    logger.info("Set cross-account policy on queue: %s", queue_url)


def delete_test_queue(sqs_client, queue_url: str) -> None:
    """Delete a test queue."""
    logger.info("Deleting SQS queue: %s", queue_url)
    sqs_client.delete_queue(QueueUrl=queue_url)
    logger.info("Queue deleted.")


def receive_messages(
    sqs_client,
    queue_url: str,
    max_messages: int = 10,
    wait_seconds: int = 5,
    delete_after: bool = False,
) -> list:
    """Receive messages from an SQS queue."""
    response = sqs_client.receive_message(
        QueueUrl=queue_url,
        MaxNumberOfMessages=min(max_messages, 10),
        WaitTimeSeconds=wait_seconds,
        MessageAttributeNames=["All"],
    )
    messages = response.get("Messages", [])

    if delete_after:
        for msg in messages:
            sqs_client.delete_message(
                QueueUrl=queue_url,
                ReceiptHandle=msg["ReceiptHandle"],
            )

    return messages


def send_message(sqs_client, queue_url: str, body: str, attributes: Optional[dict] = None) -> dict:
    """Send a message to an SQS queue."""
    kwargs = {"QueueUrl": queue_url, "MessageBody": body}
    if attributes:
        kwargs["MessageAttributes"] = attributes
    return sqs_client.send_message(**kwargs)


def print_banner():
    """Print the tool banner."""
    from .config import BANNER
    print(BANNER)


def print_section(title: str) -> None:
    """Print a formatted section header."""
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}\n")


def print_result(label: str, value: str, indent: int = 2) -> None:
    """Print a labeled result."""
    prefix = " " * indent
    print(f"{prefix}[*] {label}: {value}")


def print_success(msg: str) -> None:
    print(f"  [+] {msg}")


def print_fail(msg: str) -> None:
    print(f"  [-] {msg}")


def print_info(msg: str) -> None:
    print(f"  [i] {msg}")


def print_warn(msg: str) -> None:
    print(f"  [!] {msg}")
