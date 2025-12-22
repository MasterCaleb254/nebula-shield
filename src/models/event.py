"""Event models for CloudTrail and AWS Config events."""
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Dict, Any, Optional

class EventSource(str, Enum):
    CLOUDTRAIL = "aws.cloudtrail"
    AWS_CONFIG = "aws.config"
    GUARDDUTY = "aws.guardduty"  # Future expansion

@dataclass
class SecurityEvent:
    """Normalized security event from any source"""
    source: EventSource
    raw_event: Dict[str, Any]
    event_time: datetime
    event_name: str
    event_source: str  # e.g., "s3.amazonaws.com"
    aws_region: str
    aws_account_id: str
    
    # Common fields from CloudTrail
    user_identity: Optional[Dict[str, Any]] = None
    request_parameters: Optional[Dict[str, Any]] = None
    response_elements: Optional[Dict[str, Any]] = None
    resources: Optional[list] = None
    error_code: Optional[str] = None
    error_message: Optional[str] = None
    
    @classmethod
    def from_cloudtrail(cls, event: Dict[str, Any]) -> "SecurityEvent":
        """Create from CloudTrail event"""
        detail = event.get("detail", {})
        return cls(
            source=EventSource.CLOUDTRAIL,
            raw_event=event,
            event_time=datetime.fromisoformat(detail.get("eventTime", "")),
            event_name=detail.get("eventName", ""),
            event_source=detail.get("eventSource", ""),
            aws_region=detail.get("awsRegion", ""),
            aws_account_id=detail.get("recipientAccountId", ""),
            user_identity=detail.get("userIdentity"),
            request_parameters=detail.get("requestParameters"),
            response_elements=detail.get("responseElements"),
            resources=detail.get("resources"),
            error_code=detail.get("errorCode"),
            error_message=detail.get("errorMessage")
        )
    
    @classmethod
    def from_config(cls, event: Dict[str, Any]) -> "SecurityEvent":
        """Create from AWS Config event"""
        detail = event.get("detail", {})
        return cls(
            source=EventSource.AWS_CONFIG,
            raw_event=event,
            event_time=datetime.fromisoformat(event.get("time", "")),
            event_name=detail.get("messageType", ""),
            event_source="config.amazonaws.com",
            aws_region=detail.get("awsRegion", ""),
            aws_account_id=detail.get("awsAccountId", "")
        )
