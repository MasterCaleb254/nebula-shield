"""Remediation orchestrator that routes findings to appropriate remediators."""
from typing import Dict, Any, Optional, List, Tuple
import logging

from src.models.finding import Finding, FindingState
from src.models.remediation_plan import RemediationPlan
from simulation.aws_mock import MockAWSClients

from .base_remediator import BaseRemediator
from .s3_remediator import S3Remediator
from .iam_remediator import IAMRemediator
from .security_group_remediator import SecurityGroupRemediator

logger = logging.getLogger(__name__)

class RemediationOrchestrator:
    """Orchestrates remediation across different services."""
    
    def __init__(self, aws_client: MockAWSClients, dry_run: bool = True):
        self.aws_client = aws_client
        self.dry_run = dry_run
        
        # Initialize all remediators
        self.remediators: List[BaseRemediator] = [
            S3Remediator(aws_client, dry_run),
            IAMRemediator(aws_client, dry_run),
            SecurityGroupRemediator(aws_client, dry_run)
        ]
    
    def get_remediator(self, finding: Finding) -> Optional[BaseRemediator]:
        """Get appropriate remediator for a finding."""
        for remediator in self.remediators:
            if remediator.can_remediate(finding):
                return remediator
        return None
    
    def remediate(self, finding: Finding) -> Tuple[bool, Dict[str, Any], Optional[RemediationPlan]]:
        """
        Remediate a finding.
        Returns (success, result, plan)
        """
        logger.info(f"Attempting to remediate finding {finding.finding_id}")
        
        # Get appropriate remediator
        remediator = self.get_remediator(finding)
        if not remediator:
            logger.error(f"No remediator found for finding {finding.finding_id}")
            return False, {"error": "No suitable remediator found"}, None
        
        # Create remediation plan
        try:
            plan = remediator.create_remediation_plan(finding)
            logger.info(f"Created remediation plan {plan.plan_id} for finding {finding.finding_id}")
        except Exception as e:
            logger.error(f"Failed to create remediation plan: {str(e)}")
            return False, {"error": f"Failed to create plan: {str(e)}"}, None
        
        # Execute remediation
        try:
            success, result, rollback_result = remediator.safe_execute(plan)
            
            # Update finding state based on result
            if success:
                finding.state = FindingState.REMEDIATED
                logger.info(f"Remediation successful for finding {finding.finding_id}")
            else:
                finding.state = FindingState.FAILED
                logger.error(f"Remediation failed for finding {finding.finding_id}")
                
                if rollback_result:
                    finding.state = FindingState.ROLLED_BACK
                    logger.info(f"Rollback successful for finding {finding.finding_id}")
            
            result["rollback_result"] = rollback_result
            return success, result, plan
            
        except Exception as e:
            logger.error(f"Remediation execution failed: {str(e)}")
            finding.state = FindingState.FAILED
            return False, {"error": f"Execution failed: {str(e)}"}, plan
    
    def batch_remediate(self, findings: List[Finding]) -> Dict[str, Any]:
        """Remediate multiple findings."""
        results = {
            "total": len(findings),
            "successful": 0,
            "failed": 0,
            "rolled_back": 0,
            "no_remediator": 0,
            "details": []
        }
        
        for finding in findings:
            success, result, plan = self.remediate(finding)
            
            result_detail = {
                "finding_id": finding.finding_id,
                "resource_arn": finding.resource_arn,
                "rule_id": finding.rule_id,
                "success": success,
                "state": finding.state.value,
                "result": result
            }
            
            if plan:
                result_detail["plan_id"] = plan.plan_id
                result_detail["action"] = plan.action.value
            
            results["details"].append(result_detail)
            
            if success:
                results["successful"] += 1
            elif finding.state == FindingState.ROLLED_BACK:
                results["rolled_back"] += 1
            elif "No suitable remediator" in str(result.get("error", "")):
                results["no_remediator"] += 1
            else:
                results["failed"] += 1
        
        logger.info(f"Batch remediation completed: {results['successful']} successful, {results['failed']} failed")
        return results