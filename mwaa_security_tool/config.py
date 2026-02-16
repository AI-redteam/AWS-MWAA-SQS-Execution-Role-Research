"""
Shared configuration and constants for the MWAA security testing tool.
"""

import dataclasses
from typing import Optional


# The vulnerable IAM policy resource pattern from AWS documentation
VULNERABLE_RESOURCE_PATTERN = "arn:aws:sqs:{region}:*:airflow-celery-*"

# SQS queue name prefix required by the wildcard policy
REQUIRED_QUEUE_PREFIX = "airflow-celery-"

# SQS actions granted by the default MWAA execution role
MWAA_SQS_ACTIONS = [
    "sqs:ChangeMessageVisibility",
    "sqs:DeleteMessage",
    "sqs:GetQueueAttributes",
    "sqs:GetQueueUrl",
    "sqs:ReceiveMessage",
    "sqs:SendMessage",
]

# Default queue names used in testing
DEFAULT_C2_CMD_QUEUE = "airflow-celery-c2-commands"
DEFAULT_C2_RESULTS_QUEUE = "airflow-celery-c2-results"
DEFAULT_RECON_QUEUE_NAMES = [
    "airflow-celery-prod",
    "airflow-celery-dev",
    "airflow-celery-staging",
    "airflow-celery-test",
    "airflow-celery-default",
]

# Common queue name patterns to probe during recon
RECON_QUEUE_PATTERNS = [
    "airflow-celery-{env}",
]
RECON_ENVIRONMENTS = [
    "prod", "production", "dev", "development", "staging",
    "stage", "test", "testing", "uat", "qa", "demo",
    "sandbox", "default", "main", "primary",
]

BANNER = r"""
╔══════════════════════════════════════════════════════════════╗
║         MWAA SQS Security Tool v2.0                         ║
║                                                              ║
║  AWS MWAA Default IAM Policy Exploitation Toolkit            ║
║  For authorized security testing and research only.          ║
╚══════════════════════════════════════════════════════════════╝
"""


@dataclasses.dataclass
class AttackerConfig:
    """Configuration for the attacker-controlled AWS resources."""
    account_id: str
    region: str = "us-east-1"
    profile: Optional[str] = None

    def queue_url(self, queue_name: str) -> str:
        return f"https://sqs.{self.region}.amazonaws.com/{self.account_id}/{queue_name}"


@dataclasses.dataclass
class TargetConfig:
    """Configuration for the target MWAA environment."""
    mwaa_env_name: Optional[str] = None
    s3_dag_bucket: Optional[str] = None
    s3_dag_prefix: str = "dags/"
    region: str = "us-east-1"
    profile: Optional[str] = None
