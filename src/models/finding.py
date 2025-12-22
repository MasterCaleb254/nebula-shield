"""Finding data model - the core entity that flows through the system."""
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional, Dict, Any
import uuid

class FindingSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class FindingState(str, Enum):
    """State machine for findings as per SPEC-1"""
    DETECTED = "DETECTED"
    AUTO_REMEDIATE = "AUTO_REMEDIATE"
    PENDING_APPROVAL = "PENDING_APPROVAL"
    APPROVED = "APPROVED"
    REMEDIATED = "REMEDIATED"
    FAILED = "FAILED"
    ROLLED_BACK = "ROLLED_BACK"
    SUPPRESSED = "SUPPRESSED"

class ResourceType(str, Enum):
    S3_BUCKET = "AWS::S3::Bucket"
    IAM_ROLE = "AWS::IAM::Role"
    IAM_USER = "AWS::IAM::User"
    IAM_POLICY = "AWS::IAM::Policy"
    SECURITY_GROUP = "AWS::EC2::SecurityGroup"

@dataclass
class Finding:
    """Immutable finding record - audit guarantees in SPEC-1"""

    # Resource information (required fields first)
    resource_arn: str
    resource_type: ResourceType
    account_id: str
    region: str

    # Finding details
    rule_id: str  # e.g., "S3-PUBLIC-ACCESS-001"
    title: str
    description: str
    severity: FindingSeverity

    # Core identifiers (with defaults)
    finding_id: str = field(default_factory=lambda: f"FINDING#{uuid.uuid4()}")
    correlation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    
    # State management
    state: FindingState = FindingState.DETECTED
    detected_at: datetime = field(default_factory=datetime.utcnow)
    last_updated_at: datetime = field(default_factory=datetime.utcnow)
    
    # Enrichment data
    raw_event: Optional[Dict[str, Any]] = None
    current_config: Optional[Dict[str, Any]] = None
    
    # Remediation tracking
    remediation_action: Optional[str] = None  # e.g., "PutPublicAccessBlock"
    remediation_params: Optional[Dict[str, Any]] = None
    rollback_plan: Optional[Dict[str, Any]] = None
    
    # Approval tracking (for Phase 2)
    approval_actor: Optional[str] = None
    approval_comment: Optional[str] = None

    def to_dynamodb_item(self) -> Dict[str, Any]:
        """Convert to DynamoDB item format (as per SPEC-1 schema)"""
        return {
            "PK": self.finding_id,
            "SK": f"RESOURCE#{self.resource_arn}",
            "resource_type": self.resource_type.value,
            "account_id": self.account_id,
            "region": self.region,
            "rule_id": self.rule_id,
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "state": self.state.value,
            "detected_at": self.detected_at.isoformat(),
            "last_updated_at": self.last_updated_at.isoformat(),
            "remediation_action": self.remediation_action,
            "remediation_params": self.remediation_params,
            "rollback_plan": self.rollback_plan,
            "correlation_id": self.correlation_id,
            "approval_actor": self.approval_actor,
            "approval_comment": self.approval_comment,
            "raw_event": self.raw_event,
            "current_config": self.current_config
        }
    
    @classmethod
    def from_dynamodb_item(cls, item: Dict[str, Any]) -> "Finding":
        """Create Finding from DynamoDB item"""
        return cls(
            resource_arn=item["SK"].replace("RESOURCE#", ""),
            resource_type=ResourceType(item["resource_type"]),
            account_id=item["account_id"],
            region=item["region"],
            rule_id=item["rule_id"],
            title=item["title"],
            description=item["description"],
            severity=FindingSeverity(item["severity"]),
            finding_id=item["PK"],
            correlation_id=item.get("correlation_id"),
            state=FindingState(item["state"]),
            detected_at=datetime.fromisoformat(item["detected_at"]),
            last_updated_at=datetime.fromisoformat(item["last_updated_at"]),
            remediation_action=item.get("remediation_action"),
            remediation_params=item.get("remediation_params"),
            rollback_plan=item.get("rollback_plan"),
            approval_actor=item.get("approval_actor"),
            approval_comment=item.get("approval_comment"),
            raw_event=item.get("raw_event"),
            current_config=item.get("current_config")
        )
