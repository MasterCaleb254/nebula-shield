"""Remediation plan models for intent-based execution."""
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import List, Optional, Dict, Any
import uuid

class RemediationAction(str, Enum):
    """Predefined remediation actions (MVP scope)"""
    # S3 Actions
    ENABLE_S3_PUBLIC_ACCESS_BLOCK = "EnableS3PublicAccessBlock"
    DISABLE_S3_BUCKET_POLICY_STATEMENT = "DisableS3BucketPolicyStatement"
    
    # IAM Actions
    DETACH_IAM_POLICY = "DetachIAMPolicy"
    DEACTIVATE_IAM_ACCESS_KEY = "DeactivateIAMAccessKey"
    
    # Security Group Actions
    REVOKE_SECURITY_GROUP_INGRESS = "RevokeSecurityGroupIngress"
    
    # Rollback Actions
    ROLLBACK_S3_PUBLIC_ACCESS = "RollbackS3PublicAccess"
    
    # Utility Actions
    NO_OP = "NoOp"
    MANUAL_INTERVENTION_REQUIRED = "ManualInterventionRequired"

class ExecutionMode(str, Enum):
    DRY_RUN = "DRY_RUN"
    INTENT_ONLY = "INTENT_ONLY"  # Log intent, no execution
    EXECUTE_WITH_ROLLBACK = "EXECUTE_WITH_ROLLBACK"

@dataclass
class APICall:
    """Represents a single AWS API call"""
    service: str  # e.g., "s3", "iam", "ec2"
    operation: str  # e.g., "PutPublicAccessBlock"
    parameters: Dict[str, Any]
    effect: str  # "Allow" or "Deny" - for intent logging
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "service": self.service,
            "operation": self.operation,
            "parameters": self.parameters,
            "effect": self.effect
        }

@dataclass
class RemediationPlan:
    """Complete plan for remediation with rollback capability"""
    # Required fields (no defaults) come first
    finding_id: str
    correlation_id: str
    action: RemediationAction
    target_resource_arn: str
    rule_id: str
    justification: str

    # Optional / defaulted fields come after
    plan_id: str = field(default_factory=lambda: f"PLAN#{uuid.uuid4()}")
    created_at: datetime = field(default_factory=datetime.utcnow)
    api_calls: List[APICall] = field(default_factory=list)
    rollback_calls: List[APICall] = field(default_factory=list)
    execution_mode: ExecutionMode = ExecutionMode.DRY_RUN
    requires_approval: bool = False
    approval_token: Optional[str] = None

    def add_api_call(self, service: str, operation: str, parameters: Dict[str, Any], effect: str = "Allow"):
        """Add an API call to the plan"""
        self.api_calls.append(
            APICall(service=service, operation=operation, parameters=parameters, effect=effect)
        )
    
    def add_rollback_call(self, service: str, operation: str, parameters: Dict[str, Any], effect: str = "Allow"):
        """Add a rollback API call"""
        self.rollback_calls.append(
            APICall(service=service, operation=operation, parameters=parameters, effect=effect)
        )
    
    def get_intent_log(self) -> Dict[str, Any]:
        """Generate intent log for dry-run mode"""
        return {
            "plan_id": self.plan_id,
            "finding_id": self.finding_id,
            "correlation_id": self.correlation_id,
            "action": self.action.value,
            "target_resource": self.target_resource_arn,
            "execution_mode": self.execution_mode.value,
            "requires_approval": self.requires_approval,
            "proposed_api_calls": [call.to_dict() for call in self.api_calls],
            "rollback_plan": [call.to_dict() for call in self.rollback_calls],
            "justification": self.justification
        }
