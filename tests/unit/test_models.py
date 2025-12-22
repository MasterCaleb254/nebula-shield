"""Unit tests for core data models."""

import sys
import os
import json
from datetime import datetime

# Add src folder to module search path (works on Windows + Git Bash + venv)
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../src')))

from models.finding import Finding, FindingSeverity, FindingState, ResourceType
from models.event import SecurityEvent, EventSource
from models.remediation_plan import RemediationPlan, RemediationAction, ExecutionMode, APICall

def test_finding_creation():
    """Test that a Finding can be created with all required fields."""
    finding = Finding(
        resource_arn="arn:aws:s3:::test-bucket",
        resource_type=ResourceType.S3_BUCKET,
        account_id="123456789012",
        region="us-east-1",
        rule_id="S3-PUBLIC-ACCESS-001",
        title="S3 Bucket has public access",
        description="Bucket policy allows public GetObject access",
        severity=FindingSeverity.HIGH
    )
    
    assert finding.finding_id.startswith("FINDING#")
    assert finding.resource_arn == "arn:aws:s3:::test-bucket"
    assert finding.severity == FindingSeverity.HIGH
    assert finding.state == FindingState.DETECTED
    assert finding.correlation_id is not None

def test_finding_dynamodb_conversion():
    """Test that Finding can convert to and from DynamoDB format."""
    finding = Finding(
        resource_arn="arn:aws:s3:::test-bucket",
        resource_type=ResourceType.S3_BUCKET,
        account_id="123456789012",
        region="us-east-1",
        rule_id="S3-PUBLIC-ACCESS-001",
        title="S3 Public Access",
        description="Test",
        severity=FindingSeverity.HIGH
    )
    
    item = finding.to_dynamodb_item()
    assert item["PK"] == finding.finding_id
    assert item["SK"] == "RESOURCE#arn:aws:s3:::test-bucket"
    assert item["resource_type"] == "AWS::S3::Bucket"
    assert item["state"] == "DETECTED"
    
    restored_finding = Finding.from_dynamodb_item(item)
    assert restored_finding.finding_id == finding.finding_id
    assert restored_finding.resource_arn == finding.resource_arn
    assert restored_finding.state == finding.state

def test_security_event_from_cloudtrail():
    """Test creating SecurityEvent from CloudTrail event."""
    with open("events/cloudtrail/s3_put_bucket_policy.json", "r") as f:
        cloudtrail_event = json.load(f)
    
    event = SecurityEvent.from_cloudtrail(cloudtrail_event)
    assert event.source == EventSource.CLOUDTRAIL
    assert event.event_name == "PutBucketPolicy"
    assert event.event_source == "s3.amazonaws.com"
    assert event.aws_account_id == "123456789012"
    assert event.aws_region == "us-east-1"
    assert event.user_identity["userName"] == "developer"

def test_remediation_plan_intent_logging():
    """Test that RemediationPlan generates proper intent logs."""
    plan = RemediationPlan(
        finding_id="FINDING#123",
        correlation_id="corr-123",
        action=RemediationAction.ENABLE_S3_PUBLIC_ACCESS_BLOCK,
        target_resource_arn="arn:aws:s3:::test-bucket",
        rule_id="S3-PUBLIC-ACCESS-001",
        justification="Block public access to prevent data leakage"
    )
    
    plan.add_api_call(
        service="s3",
        operation="PutPublicAccessBlock",
        parameters={
            "Bucket": "test-bucket",
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True
            }
        }
    )
    
    plan.add_rollback_call(
        service="s3",
        operation="PutPublicAccessBlock",
        parameters={
            "Bucket": "test-bucket",
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": False,
                "IgnorePublicAcls": False,
                "BlockPublicPolicy": False,
                "RestrictPublicBuckets": False
            }
        }
    )
    
    intent_log = plan.get_intent_log()
    assert intent_log["action"] == "EnableS3PublicAccessBlock"
    assert intent_log["target_resource"] == "arn:aws:s3:::test-bucket"
    assert len(intent_log["proposed_api_calls"]) == 1
    assert len(intent_log["rollback_plan"]) == 1
    assert intent_log["proposed_api_calls"][0]["operation"] == "PutPublicAccessBlock"

def test_state_machine_transitions():
    """Test that Finding states follow proper transitions."""
    finding = Finding(
        resource_arn="arn:aws:s3:::test-bucket",
        resource_type=ResourceType.S3_BUCKET,
        account_id="123456789012",
        region="us-east-1",
        rule_id="S3-PUBLIC-ACCESS-001",
        title="Test",
        description="Test",
        severity=FindingSeverity.HIGH
    )
    
    assert finding.state == FindingState.DETECTED
    finding.state = FindingState.AUTO_REMEDIATE
    assert finding.state == FindingState.AUTO_REMEDIATE
    finding.state = FindingState.REMEDIATED
    assert finding.state == FindingState.REMEDIATED

if __name__ == "__main__":
    test_finding_creation()
    print("✓ test_finding_creation passed")
    
    test_finding_dynamodb_conversion()
    print("✓ test_finding_dynamodb_conversion passed")
    
    test_security_event_from_cloudtrail()
    print("✓ test_security_event_from_cloudtrail passed")
    
    test_remediation_plan_intent_logging()
    print("✓ test_remediation_plan_intent_logging passed")
    
    test_state_machine_transitions()
    print("✓ test_state_machine_transitions passed")
    
    print("\n✅ All core model tests passed!")
