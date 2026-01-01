"""Base remediation framework with safety controls and rollback."""
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional, Tuple, List
import logging
from datetime import datetime

from src.models.finding import Finding, FindingState
from src.models.remediation_plan import RemediationPlan, APICall, ExecutionMode
from simulation.aws_mock import MockAWSClients

logger = logging.getLogger(__name__)

class RemediationError(Exception):
    """Custom exception for remediation failures."""
    pass

class BaseRemediator(ABC):
    """Abstract base class for all remediators."""
    
    def __init__(self, aws_client: MockAWSClients, dry_run: bool = True):
        self.aws_client = aws_client
        self.dry_run = dry_run
        self.execution_mode = ExecutionMode.DRY_RUN if dry_run else ExecutionMode.EXECUTE_WITH_ROLLBACK
    
    @abstractmethod
    def can_remediate(self, finding: Finding) -> bool:
        """Check if this remediator can handle the finding."""
        pass
    
    @abstractmethod
    def create_remediation_plan(self, finding: Finding) -> RemediationPlan:
        """Create a remediation plan for the finding."""
        pass
    
    @abstractmethod
    def execute_remediation(self, plan: RemediationPlan) -> Dict[str, Any]:
        """Execute the remediation plan."""
        pass
    
    @abstractmethod
    def execute_rollback(self, plan: RemediationPlan) -> Dict[str, Any]:
        """Execute rollback plan."""
        pass
    
    def safe_execute(self, plan: RemediationPlan) -> Tuple[bool, Dict[str, Any], Optional[Dict[str, Any]]]:
        """
        Safely execute remediation with rollback capability.
        Returns (success, result, rollback_result)
        """
        logger.info(f"Executing remediation plan {plan.plan_id} in {self.execution_mode.value} mode")
        
        try:
            # Execute remediation
            result = self.execute_remediation(plan)
            
            # Verify remediation succeeded
            if not self._verify_remediation(plan, result):
                raise RemediationError("Remediation verification failed")
            
            # If in dry-run mode, just return success
            if self.dry_run:
                logger.info(f"Dry-run completed for plan {plan.plan_id}")
                return True, {"mode": "dry_run", "message": "Would have executed successfully"}, None
            
            logger.info(f"Remediation completed successfully for plan {plan.plan_id}")
            return True, result, None
            
        except Exception as e:
            logger.error(f"Remediation failed for plan {plan.plan_id}: {str(e)}")
            
            # Execute rollback if we have rollback plan
            rollback_result = None
            if plan.rollback_calls:
                try:
                    logger.info(f"Attempting rollback for failed plan {plan.plan_id}")
                    rollback_result = self.execute_rollback(plan)
                    logger.info(f"Rollback completed for plan {plan.plan_id}")
                except Exception as rollback_error:
                    logger.error(f"Rollback also failed for plan {plan.plan_id}: {str(rollback_error)}")
                    raise RemediationError(f"Remediation and rollback failed: {str(e)}") from e
            
            return False, {"error": str(e)}, rollback_result
    
    def _verify_remediation(self, plan: RemediationPlan, result: Dict[str, Any]) -> bool:
        """Verify that remediation was successful."""
        # Basic verification - check HTTP status code in mock response
        if "ResponseMetadata" in result and "HTTPStatusCode" in result["ResponseMetadata"]:
            return result["ResponseMetadata"]["HTTPStatusCode"] == 200
        
        # Additional verification logic can be added by subclasses
        return self._specific_verification(plan, result)
    
    def _specific_verification(self, plan: RemediationPlan, result: Dict[str, Any]) -> bool:
        """Service-specific verification logic."""
        # Override in subclasses
        return True
    
    def _log_intent(self, service: str, operation: str, params: Dict[str, Any]):
        """Log intent for AWS API call."""
        logger.info(f"[INTENT] {service}.{operation}: {params}")
        
        # Store in remediation plan log
        return {
            "timestamp": datetime.utcnow().isoformat(),
            "service": service,
            "operation": operation,
            "parameters": params,
            "dry_run": self.dry_run
        }