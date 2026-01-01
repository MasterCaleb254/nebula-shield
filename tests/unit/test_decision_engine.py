"""Unit tests for Decision Engine."""
import json
from datetime import datetime
import pytest

from src.decision_engine.state_machine import DecisionEngine, TransitionResult
from src.decision_engine.rule_evaluator import RuleEvaluator, RuleDefinition
from src.models.finding import Finding, FindingSeverity, FindingState, ResourceType
from src.models.remediation_plan import RemediationPlan, RemediationAction, ExecutionMode

def test_decision_engine_initialization():
    """Test that DecisionEngine initializes correctly."""
    engine = DecisionEngine()
    
    assert engine.config is not None
    assert "auto_remediate_low_risk" in engine.config
    assert len(engine.transitions) > 0
    assert len(engine.risk_rules) > 0

def test_rule_evaluator_initialization():
    """Test that RuleEvaluator loads rules correctly."""
    evaluator = RuleEvaluator()
    
    rules = evaluator.list_rules()
    assert len(rules) > 0
    
    # Check default rules are loaded
    rule_ids = [rule.id for rule in rules]
    assert "S3-PUBLIC-ACCESS-001" in rule_ids
    assert "IAM-OVER-PERMISSIVE-001" in rule_ids
    assert "SG-OPEN-PORTS-001" in rule_ids

def test_s3_public_access_auto_remediation():
    """Test S3 public access finding gets auto-remediated."""
    engine = DecisionEngine({
        "dry_run_mode": False,  # Disable dry run for this test
        "enabled_rules": ["S3-PUBLIC-ACCESS-001"]
    })
    
    finding = Finding(
        resource_arn="arn:aws:s3:::test-bucket",
        resource_type=ResourceType.S3_BUCKET,
        account_id="123456789012",
        region="us-east-1",
        rule_id="S3-PUBLIC-ACCESS-001",
        title="S3 Bucket has Public Access",
        description="Bucket policy allows public GetObject access",
        severity=FindingSeverity.HIGH
    )
    
    result = engine.evaluate_finding(finding)
    
    assert result.success
    assert result.new_state == FindingState.AUTO_REMEDIATE
    assert result.plan is not None
    assert result.plan.action == RemediationAction.ENABLE_S3_PUBLIC_ACCESS_BLOCK

def test_iam_policy_requires_approval():
    """Test IAM policy finding requires approval."""
    engine = DecisionEngine({
        "dry_run_mode": False,
        "enabled_rules": ["IAM-OVER-PERMISSIVE-001"]
    })
    
    finding = Finding(
        resource_arn="arn:aws:iam::123456789012:role/TestRole",
        resource_type=ResourceType.IAM_ROLE,
        account_id="123456789012",
        region="us-east-1",
        rule_id="IAM-OVER-PERMISSIVE-001",
        title="IAM Role has Overly Permissive Policy",
        description="Role has AdministratorAccess policy attached",
        severity=FindingSeverity.CRITICAL
    )
    
    result = engine.evaluate_finding(finding)
    
    # In MVP, since we don't have approval workflow, it stays in DETECTED
    # When approval workflow is implemented, this would go to PENDING_APPROVAL
    assert result.success
    assert result.new_state == FindingState.PENDING_APPROVAL

def test_dry_run_mode():
    """Test that dry run mode prevents auto-remediation."""
    engine = DecisionEngine({
        "dry_run_mode": True,  # Enable dry run
        "enabled_rules": ["S3-PUBLIC-ACCESS-001"]
    })
    
    finding = Finding(
        resource_arn="arn:aws:s3:::test-bucket",
        resource_type=ResourceType.S3_BUCKET,
        account_id="123456789012",
        region="us-east-1",
        rule_id="S3-PUBLIC-ACCESS-001",
        title="S3 Bucket has Public Access",
        description="Bucket policy allows public GetObject access",
        severity=FindingSeverity.HIGH
    )
    
    result = engine.evaluate_finding(finding)
    
    # In dry run mode, findings should stay in DETECTED
    assert result.success
    assert result.new_state == FindingState.DETECTED

def test_state_transition_validation():
    """Test that invalid state transitions are rejected."""
    engine = DecisionEngine()
    
    finding = Finding(
        resource_arn="arn:aws:s3:::test-bucket",
        resource_type=ResourceType.S3_BUCKET,
        account_id="123456789012",
        region="us-east-1",
        rule_id="S3-PUBLIC-ACCESS-001",
        title="Test",
        description="Test",
        severity=FindingSeverity.HIGH,
        state=FindingState.REMEDIATED  # Already remediated
    )
    
    # Try to transition from REMEDIATED to AUTO_REMEDIATE (invalid)
    result = engine.evaluate_finding(finding)
    
    # Should stay in current state
    assert result.new_state == FindingState.REMEDIATED

def test_rollback_plan_creation():
    """Test rollback plan creation for failed remediations."""
    engine = DecisionEngine()
    
    finding = Finding(
        resource_arn="arn:aws:s3:::test-bucket",
        resource_type=ResourceType.S3_BUCKET,
        account_id="123456789012",
        region="us-east-1",
        rule_id="S3-PUBLIC-ACCESS-001",
        title="S3 Bucket has Public Access",
        description="Bucket policy allows public GetObject access",
        severity=FindingSeverity.HIGH,
        state=FindingState.FAILED  # Remediation failed
def test_valid_transitions():
    """Test getting valid transitions from a state."""
    engine = DecisionEngine()
    
    valid_from_detected = engine.get_valid_transitions(FindingState.DETECTED)
    assert FindingState.AUTO_REMEDIATE in valid_from_detected
    assert FindingState.PENDING_APPROVAL in valid_from_detected
    assert FindingState.SUPPRESSED in valid_from_detected

def test_rule_definition_serialization():
    """Test RuleDefinition serialization/deserialization."""
    rule_data = {
        "id": "TEST-RULE-001",
        "name": "Test Rule",
        "description": "A test rule",
        "resource_types": ["AWS::S3::Bucket"],
        "severity": "HIGH",
        "detection_logic": {"triggers": ["PutBucketPolicy"]},
        "remediation": {"action": "EnableS3PublicAccessBlock"},
        "risk_assessment": {"impact": "HIGH"}
    }
    
    rule = RuleDefinition.from_dict(rule_data)
    
    assert rule.id == "TEST-RULE-001"
    assert rule.severity == FindingSeverity.HIGH
    
    # Convert back to dict
    rule_dict = rule.to_dict()
    assert rule_dict["id"] == "TEST-RULE-001"
    assert rule_dict["severity"] == "HIGH"

if __name__ == "__main__":
    # Run tests
    test_decision_engine_initialization()
    print("✓ test_decision_engine_initialization")
    
    test_rule_evaluator_initialization()
    print("✓ test_rule_evaluator_initialization")
    
    test_s3_public_access_auto_remediation()
    print("✓ test_s3_public_access_auto_remediation")
    
    test_iam_policy_requires_approval()
    print("✓ test_iam_policy_requires_approval")
    
    test_dry_run_mode()
    print("✓ test_dry_run_mode")
    
    test_state_transition_validation()
    print("✓ test_state_transition_validation")
    
    test_rollback_plan_creation()
    print("✓ test_rollback_plan_creation")
    
    test_valid_transitions()
    print("✓ test_valid_transitions")
    
    test_rule_definition_serialization()
    print("✓ test_rule_definition_serialization")
    
    print("\n✅ All Decision Engine tests passed!")
