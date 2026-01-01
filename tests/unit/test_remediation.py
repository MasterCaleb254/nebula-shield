"""Unit tests for remediation engine."""
import json
from datetime import datetime
import pytest

from src.remediation.base_remediator import BaseRemediator, RemediationError
from src.remediation.s3_remediator import S3Remediator
from src.remediation.iam_remediator import IAMRemediator
from src.remediation.security_group_remediator import SecurityGroupRemediator
from src.remediation.orchestrator import RemediationOrchestrator
from src.models.finding import Finding, FindingSeverity, ResourceType
from src.models.remediation_plan import RemediationPlan, RemediationAction, ExecutionMode
from simulation.aws_mock_enhanced import MockAWSClientsEnhanced

def test_s3_remediator_creation():
    """Test S3Remediator initialization."""
    aws_client = MockAWSClientsEnhanced()
    remediator = S3Remediator(aws_client, dry_run=True)
    
    assert remediator.dry_run == True
    assert remediator.aws_client == aws_client

def test_s3_remediator_can_remediate():
    """Test S3Remediator can_remediate method."""
    aws_client = MockAWSClientsEnhanced()
    remediator = S3Remediator(aws_client)
    
    s3_finding = Finding(
        resource_arn="arn:aws:s3:::test-bucket",
        resource_type=ResourceType.S3_BUCKET,
        account_id="123456789012",
        region="us-east-1",
        rule_id="S3-PUBLIC-ACCESS-001",
        title="Test",
        description="Test",
        severity=FindingSeverity.HIGH
    )
    
    iam_finding = Finding(
        resource_arn="arn:aws:iam::123456789012:role/TestRole",
        resource_type=ResourceType.IAM_ROLE,
        account_id="123456789012",
        region="us-east-1",
        rule_id="IAM-OVER-PERMISSIVE-001",
        title="Test",
        description="Test",
        severity=FindingSeverity.HIGH
    )
    
    assert remediator.can_remediate(s3_finding) == True
    assert remediator.can_remediate(iam_finding) == False

def test_s3_public_access_plan_creation():
    """Test S3 public access remediation plan creation."""
    aws_client = MockAWSClientsEnhanced()
    remediator = S3Remediator(aws_client)
    
    finding = Finding(
        resource_arn="arn:aws:s3:::test-bucket",
        resource_type=ResourceType.S3_BUCKET,
        account_id="123456789012",
        region="us-east-1",
        rule_id="S3-PUBLIC-ACCESS-001",
        title="S3 Bucket has Public Access",
        description="Bucket policy allows public access",
        severity=FindingSeverity.HIGH,
        current_config={
            "public_access_block": {
                "BlockPublicAcls": False,
                "IgnorePublicAcls": False,
                "BlockPublicPolicy": False,
                "RestrictPublicBuckets": False
            }
        }
    )
    
    plan = remediator.create_remediation_plan(finding)
    
    assert plan is not None
    assert plan.action == RemediationAction.ENABLE_S3_PUBLIC_ACCESS_BLOCK
    assert plan.target_resource_arn == finding.resource_arn
    assert len(plan.api_calls) == 1
    assert len(plan.rollback_calls) == 1
    assert plan.api_calls[0].operation == "PutPublicAccessBlock"
    assert plan.rollback_calls[0].operation == "PutPublicAccessBlock"

def test_iam_remediator_detach_policy_plan():
    """Test IAM policy detach plan creation."""
    aws_client = MockAWSClientsEnhanced()
    remediator = IAMRemediator(aws_client)
    
    finding = Finding(
        resource_arn="arn:aws:iam::123456789012:role/TestRole",
        resource_type=ResourceType.IAM_ROLE,
        account_id="123456789012",
        region="us-east-1",
        rule_id="IAM-OVER-PERMISSIVE-001",
        title="IAM Role has Overly Permissive Policy",
        description="Role has AdministratorAccess policy",
        severity=FindingSeverity.CRITICAL,
        current_config={
            "attached_policies": [
                {
                    "policy_name": "AdministratorAccess",
                    "policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess"
                }
            ]
        }
    )
    
    plan = remediator.create_remediation_plan(finding)
    
    assert plan is not None
    assert plan.action == RemediationAction.DETACH_IAM_POLICY
    assert plan.requires_approval == True
    assert len(plan.api_calls) > 0
    assert plan.api_calls[0].operation == "DetachRolePolicy"

def test_security_group_remediator_revoke_ingress_plan():
    """Test Security Group revoke ingress plan creation."""
    aws_client = MockAWSClientsEnhanced()
    remediator = SecurityGroupRemediator(aws_client)
    
    finding = Finding(
        resource_arn="arn:aws:ec2:us-east-1:123456789012:security-group/sg-12345678",
        resource_type=ResourceType.SECURITY_GROUP,
        account_id="123456789012",
        region="us-east-1",
        rule_id="SG-OPEN-PORTS-001",
        title="Security Group Open to Internet",
        description="Security group allows SSH from 0.0.0.0/0",
        severity=FindingSeverity.HIGH,
        current_config={
            "ingress_rules": [
                {
                    "ip_protocol": "tcp",
                    "from_port": 22,
                    "to_port": 22,
                    "ip_ranges": [{"cidr_ip": "0.0.0.0/0"}]
                }
            ]
        }
    )
    
    plan = remediator.create_remediation_plan(finding)
    
    assert plan is not None
    assert plan.action == RemediationAction.REVOKE_SECURITY_GROUP_INGRESS
    assert plan.requires_approval == True
    assert len(plan.api_calls) > 0
    assert plan.api_calls[0].operation == "RevokeSecurityGroupIngress"

def test_orchestrator_routing():
    """Test RemediationOrchestrator routes findings correctly."""
    aws_client = MockAWSClientsEnhanced()
    orchestrator = RemediationOrchestrator(aws_client)
    
    s3_finding = Finding(
        resource_arn="arn:aws:s3:::test-bucket",
        resource_type=ResourceType.S3_BUCKET,
        account_id="123456789012",
        region="us-east-1",
        rule_id="S3-PUBLIC-ACCESS-001",
        title="Test",
        description="Test",
        severity=FindingSeverity.HIGH
    )
    
    iam_finding = Finding(
        resource_arn="arn:aws:iam::123456789012:role/TestRole",
        resource_type=ResourceType.IAM_ROLE,
        account_id="123456789012",
        region="us-east-1",
        rule_id="IAM-OVER-PERMISSIVE-001",
        title="Test",
        description="Test",
        severity=FindingSeverity.HIGH
    )
    
    sg_finding = Finding(
        resource_arn="arn:aws:ec2:us-east-1:123456789012:security-group/sg-12345678",
        resource_type=ResourceType.SECURITY_GROUP,
        account_id="123456789012",
        region="us-east-1",
        rule_id="SG-OPEN-PORTS-001",
        title="Test",
        description="Test",
        severity=FindingSeverity.HIGH
    )
    
    # Test get_remediator
    s3_remediator = orchestrator.get_remediator(s3_finding)
    iam_remediator = orchestrator.get_remediator(iam_finding)
    sg_remediator = orchestrator.get_remediator(sg_finding)
    
    assert isinstance(s3_remediator, S3Remediator)
    assert isinstance(iam_remediator, IAMRemediator)
    assert isinstance(sg_remediator, SecurityGroupRemediator)

def test_orchestrator_remediate_dry_run():
    """Test orchestrator remediation in dry-run mode."""
    aws_client = MockAWSClientsEnhanced()
    orchestrator = RemediationOrchestrator(aws_client, dry_run=True)
    
    finding = Finding(
        resource_arn="arn:aws:s3:::test-bucket",
        resource_type=ResourceType.S3_BUCKET,
        account_id="123456789012",
        region="us-east-1",
        rule_id="S3-PUBLIC-ACCESS-001",
        title="S3 Bucket has Public Access",
        description="Bucket policy allows public access",
        severity=FindingSeverity.HIGH,
        current_config={
            "public_access_block": {
                "BlockPublicAcls": False,
                "IgnorePublicAcls": False,
                "BlockPublicPolicy": False,
                "RestrictPublicBuckets": False
            }
        }
    )
    
    success, result, plan = orchestrator.remediate(finding)
    
    assert success == True  # Dry-run should always succeed
    assert plan is not None
    assert "intent_logs" in result.get("result", {})
    assert finding.state.value == "REMEDIATED"  # State updated

def test_batch_remediation():
    """Test batch remediation of multiple findings."""
    aws_client = MockAWSClientsEnhanced()
    orchestrator = RemediationOrchestrator(aws_client, dry_run=True)
    
    findings = [
        Finding(
            resource_arn="arn:aws:s3:::test-bucket-1",
            resource_type=ResourceType.S3_BUCKET,
            account_id="123456789012",
            region="us-east-1",
            rule_id="S3-PUBLIC-ACCESS-001",
            title="S3 Bucket Public Access 1",
            description="Test",
            severity=FindingSeverity.HIGH,
            current_config={
                "public_access_block": {"BlockPublicAcls": False}
            }
        ),
        Finding(
            resource_arn="arn:aws:s3:::test-bucket-2",
            resource_type=ResourceType.S3_BUCKET,
            account_id="123456789012",
            region="us-east-1",
            rule_id="S3-PUBLIC-ACCESS-001",
            title="S3 Bucket Public Access 2",
            description="Test",
            severity=FindingSeverity.HIGH,
            current_config={
                "public_access_block": {"BlockPublicAcls": False}
            }
        )
    ]
    
    results = orchestrator.batch_remediate(findings)
    
    assert results["total"] == 2
    assert results["successful"] == 2
    assert len(results["details"]) == 2

if __name__ == "__main__":
    # Run all tests
    test_s3_remediator_creation()
    print("✓ test_s3_remediator_creation")
    
    test_s3_remediator_can_remediate()
    print("✓ test_s3_remediator_can_remediate")
    
    test_s3_public_access_plan_creation()
    print("✓ test_s3_public_access_plan_creation")
    
    test_iam_remediator_detach_policy_plan()
    print("✓ test_iam_remediator_detach_policy_plan")
    
    test_security_group_remediator_revoke_ingress_plan()
    print("✓ test_security_group_remediator_revoke_ingress_plan")
    
    test_orchestrator_routing()
    print("✓ test_orchestrator_routing")
    
    test_orchestrator_remediate_dry_run()
    print("✓ test_orchestrator_remediate_dry_run")
    
    test_batch_remediation()
    print("✓ test_batch_remediation")
    
    print("\n✅ All remediation tests passed!")