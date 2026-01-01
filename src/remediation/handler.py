"""Lambda handler for remediation execution."""
import json
import os
import logging
from typing import Dict, Any

from src.models.finding import Finding
from src.models.remediation_plan import RemediationPlan
from simulation.aws_mock import MockAWSClients
from .orchestrator import RemediationOrchestrator

logger = logging.getLogger()
logger.setLevel(logging.INFO)

def lambda_handler(event: Dict[str, Any], context) -> Dict[str, Any]:
    """Lambda handler for remediation execution."""
    logger.info(f"Received remediation event: {json.dumps(event, default=str)}")
    
    try:
        # Parse event
        plan_data = event.get("detail", event)
        
        # Check if this is a remediation plan
        if "plan_id" not in plan_data:
            return {
                "statusCode": 400,
                "body": json.dumps({"error": "Invalid event: no plan_id found"})
            }
        
        # Parse remediation plan from event
        plan = RemediationPlan(
            finding_id=plan_data.get("finding_id", ""),
            correlation_id=plan_data.get("correlation_id", ""),
            action=plan_data.get("action", ""),
            target_resource_arn=plan_data.get("target_resource", ""),
            rule_id=plan_data.get("rule_id", ""),
            justification=plan_data.get("justification", ""),
            execution_mode=plan_data.get("execution_mode", "DRY_RUN"),
            requires_approval=plan_data.get("requires_approval", False)
        )
        
        # Parse finding from event if available
        finding_data = plan_data.get("finding", {})
        finding = None
        
        if finding_data:
            finding = Finding.from_dynamodb_item(finding_data)
        else:
            # Create minimal finding from plan
            finding = Finding(
                resource_arn=plan.target_resource_arn,
                resource_type="",  # Will be determined by remediator
                account_id="",  # From context if available
                region="",  # From context if available
                rule_id=plan.rule_id,
                title=f"Remediation for {plan.action}",
                description=plan.justification,
                severity="HIGH"  # Default
            )
            finding.finding_id = plan.finding_id
            finding.correlation_id = plan.correlation_id
        
        # Initialize orchestrator
        dry_run = os.getenv("DRY_RUN_MODE", "true").lower() == "true"
        aws_client = MockAWSClients(mode="dry_run" if dry_run else "execute")
        orchestrator = RemediationOrchestrator(aws_client, dry_run)
        
        # Execute remediation
        success, result, executed_plan = orchestrator.remediate(finding)
        
        # Prepare response
        response = {
            "status": "success" if success else "failed",
            "plan_id": plan.plan_id,
            "finding_id": finding.finding_id,
            "resource_arn": finding.resource_arn,
            "action": plan.action.value if hasattr(plan.action, 'value') else plan.action,
            "execution_mode": plan.execution_mode.value,
            "dry_run": dry_run,
            "result": result,
            "finding_state": finding.state.value
        }
        
        # Add AWS intent logs if available
        if hasattr(aws_client, 'get_logs'):
            response["aws_intent_logs"] = aws_client.get_logs()
        
        status_code = 200 if success else 500
        
        return {
            "statusCode": status_code,
            "body": json.dumps(response, default=str)
        }
        
    except Exception as e:
        logger.error(f"Remediation failed with error: {str(e)}", exc_info=True)
        
        return {
            "statusCode": 500,
            "body": json.dumps({
                "error": str(e),
                "message": "Remediation execution failed"
            })
        }

def local_test(plan_data: Dict[str, Any], dry_run: bool = True) -> Dict[str, Any]:
    """Test remediation locally."""
    logger.info(f"Testing remediation locally with dry_run={dry_run}")
    
    # Mock context
    class MockContext:
        aws_request_id = "local-test-request-id"
    
    # Set environment variable
    os.environ["DRY_RUN_MODE"] = str(dry_run).lower()
    
    # Create event
    event = {
        "detail": plan_data
    }
    
    return lambda_handler(event, MockContext())