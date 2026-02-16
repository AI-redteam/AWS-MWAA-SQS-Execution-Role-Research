"""
CeleryStrike — AWS MWAA Execution Role Exploitation Toolkit

Weaponizes the default MWAA execution role's wildcard SQS policy
(arn:aws:sqs:*:*:airflow-celery-*) for C2, recon, injection, and DoS.

For authorized security testing, penetration testing engagements,
and defensive validation only.
"""

__version__ = "2.0.0"
