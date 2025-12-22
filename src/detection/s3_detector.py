"""S3 misconfiguration detector."""

from typing import Optional, List

from src.models.finding import (
    Finding,
    FindingSeverity,
    ResourceType,
)
from src.models.event import SecurityEvent
from src.models.remediation_plan import RemediationAction


class S3Detector:
    """Detects S3 misconfigurations from events."""

    def __init__(self, aws_client):
        self.aws_client = aws_client  # Mock or real AWS client

    def detect_misconfigurations(
        self, event: SecurityEvent
    ) -> Optional[List[Finding]]:
        """Main detection entry point."""
        findings: List[Finding] = []

        # Route to appropriate detector based on event source
        if event.event_source == "s3.amazonaws.com":
            findings.extend(self._detect_from_cloudtrail(event))
        elif getattr(event.source, "value", None) == "aws.config":
            findings.extend(self._detect_from_config(event))

        return findings if findings else None

    def _detect_from_cloudtrail(self, event: SecurityEvent) -> List[Finding]:
        """Detect misconfigurations from CloudTrail events."""
        findings: List[Finding] = []

        # Check for PutBucketPolicy events that create public access
        if event.event_name == "PutBucketPolicy":
            bucket_name = event.request_parameters.get("bucketName")
            policy = event.request_parameters.get("policy", {})

            if bucket_name and self._is_public_policy(policy):
                findings.append(
                    self._create_public_access_finding(
                        resource_arn=f"arn:aws:s3:::{bucket_name}",
                        account_id=event.aws_account_id,
                        region=event.aws_region,
                        event=event,
                    )
                )

        # Check for DeletePublicAccessBlock events
        elif event.event_name == "DeletePublicAccessBlock":
            bucket_name = event.request_parameters.get("bucketName")

            if bucket_name:
                findings.append(
                    self._create_public_access_finding(
                        resource_arn=f"arn:aws:s3:::{bucket_name}",
                        account_id=event.aws_account_id,
                        region=event.aws_region,
                        event=event,
                        reason="Public access block was deleted",
                    )
                )

        return findings

    def _detect_from_config(self, event: SecurityEvent) -> List[Finding]:
        """Detect misconfigurations from AWS Config events."""
        # MVP placeholder — handled in later iterations
        return []

    def _is_public_policy(self, policy: dict) -> bool:
        """Check if an S3 bucket policy allows public access."""
        if not policy or "Statement" not in policy:
            return False

        statements = policy["Statement"]
        if not isinstance(statements, list):
            statements = [statements]

        for statement in statements:
            effect = statement.get("Effect", "Deny")
            principal = statement.get("Principal")

            if effect != "Allow":
                continue

            # Public principals
            if principal == "*":
                return True
            if isinstance(principal, dict) and principal.get("AWS") == "*":
                return True
            if isinstance(principal, str) and principal == "*":
                return True

        return False

    def _create_public_access_finding(
        self,
        resource_arn: str,
        account_id: str,
        region: str,
        event: SecurityEvent,
        reason: str = "Bucket policy allows public access",
    ) -> Finding:
        """Create a standardized finding for S3 public access."""

        # Simulated current configuration (MVP)
        current_config = {
            "bucket_name": resource_arn.split(":")[-1],
            "policy_status": {"IsPublic": True},
            "public_access_block": None,
        }

        return Finding(
            resource_arn=resource_arn,
            resource_type=ResourceType.S3_BUCKET,
            account_id=account_id,
            region=region,
            rule_id="S3-PUBLIC-ACCESS-001",
            title="S3 Bucket has Public Access",
            description=f"S3 bucket allows public access. {reason}",
            severity=FindingSeverity.HIGH,
            raw_event=event.raw_event,
            current_config=current_config,
            remediation_action=RemediationAction.ENABLE_S3_PUBLIC_ACCESS_BLOCK.value,
        )

    def get_bucket_public_access_state(self, bucket_name: str) -> dict:
        """Get current public access configuration for a bucket."""
        try:
            response = (
                self.aws_client
                .get_s3_client()
                .get_public_access_block(Bucket=bucket_name)
            )
            return response.get("PublicAccessBlockConfiguration", {})
        except Exception:
            # Simulate bucket without a public access block
            return {
                "BlockPublicAcls": False,
                "IgnorePublicAcls": False,
                "BlockPublicPolicy": False,
                "RestrictPublicBuckets": False,
            }
