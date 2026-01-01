"""Lambda handler for the Decision Engine."""
import json
import logging
import os
from typing import Dict, Any, List
from datetime import datetime

from src.models.finding import Finding, FindingState
from src.models.remediation_plan import RemediationPlan
from .state_machine import DecisionEngine
from .rule_evaluator import RuleEvaluator

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Global instances for reuse across Lambda invocations
decision_engine = None
rule_evaluator = None

def initialize_engine():
    """Initialize the decision engine and rule evaluator."""
    global decision_engine, rule_evaluator
    
    if decision_engine is None:
        config = {
            "auto_remediate_low_risk": os.getenv("AUTO_REMEDIATE_LOW_RISK", "false").lower() == "true",
            "auto_remediate_medium_risk": os.getenv("AUTO_REMEDIATE_MEDIUM_RISK", "false").lower() == "true",
            "require_approval_high_risk": os.getenv("REQUIRE_APPROVAL_HIGH_RISK", "true").lower() == "true",
            "dry_run_mode": os.getenv("DRY_RUN_MODE", "true").lower() == "true",
            "enabled_rules": json.loads(os.getenv("ENABLED_RULES", '["S3-PUBLIC-ACCESS-001"]'))
        }
        
        decision_engine = DecisionEngine(config)
        logger.info(f"Decision Engine initialized with config: {config}")
    
    if rule_evaluator is None:
        rule_evaluator = RuleEvaluator()
        logger.info(f"Rule Evaluator initialized with {len(rule_evaluator.list_rules())} rules")

def lambda_handler(event: Dict[str, Any], context) -> Dict[str, Any]:
    """Lambda handler for processing findings."""
    logger.info(f"Received event: {json.dumps(event, default=str)}")
    
    # Initialize engine
    initialize_engine()
    
    try:
        # Parse findings from event
        findings = parse_findings_from_event(event)
        
        if not findings:
            logger.warning("No findings found in event")
            return {
                "statusCode": 200,
                "body": json.dumps({"message": "No findings to process"})
            }
        
        results = []
        plans = []
        
        for finding in findings:
            result = process_finding(finding)
            results.append(result)
            
            if result.get("plan"):
                plans.append(result["plan"])
        
        # Log summary
        logger.info(f"Processed {len(findings)} findings, generated {len(plans)} plans")
        
        return {
            "statusCode": 200,
            "body": json.dumps({
                "results": results,
                "summary": {
                    "total_findings": len(findings),
                    "plans_generated": len(plans),
                    "timestamp": datetime.utcnow().isoformat()
                }
            })
        }
    
    except Exception as e:
        logger.error(f"Error processing findings: {str(e)}", exc_info=True)
        return {
            "statusCode": 500,
            "body": json.dumps({
                "error": str(e),
                "message": "Failed to process findings"
            })
        }

def parse_findings_from_event(event: Dict[str, Any]) -> List[Finding]:
    """Parse findings from Lambda event."""
    findings = []
    
    # Check for direct finding in event (from Detection Lambda)
    if "findings" in event:
        for finding_data in event["findings"]:
            try:
                finding = Finding.from_dynamodb_item(finding_data)
                findings.append(finding)
            except Exception as e:
                logger.error(f"Failed to parse finding: {e}")
    
    # Check for EventBridge event format
    elif "detail" in event and "findings" in event["detail"]:
        for finding_data in event["detail"]["findings"]:
            try:
                finding = Finding.from_dynamodb_item(finding_data)
                findings.append(finding)
            except Exception as e:
    elif "finding" in event:
        try:
            finding = Finding.from_dynamodb_item(event["finding"])
            findings.append(finding)
        except Exception as e:
            logger.error(f"Failed to parse finding: {e}")
    
    return findings

def process_finding(finding: Finding) -> Dict[str, Any]:
    """Process a single finding through the decision engine."""
    logger.info(f"Processing finding {finding.finding_id} ({finding.rule_id})")
    
    # Evaluate against rules
    rule = rule_evaluator.evaluate_finding_against_rules(finding)
    if not rule:
        logger.warning(f"No matching rule for finding {finding.rule_id}")
        return {
            "finding_id": finding.finding_id,
            "status": "NO_MATCHING_RULE",
            "message": f"No rule matches {finding.rule_id}"
        }
    
    # Evaluate with decision engine
    result = decision_engine.evaluate_finding(finding)
    
    response = {
        "finding_id": finding.finding_id,
        "rule_id": finding.rule_id,
        "current_state": finding.state.value,
        "proposed_state": result.new_state.value,
        "success": result.success,
        "message": result.message,
        "timestamp": datetime.utcnow().isoformat()
    }
    
    if result.plan:
        response["plan"] = result.plan.get_intent_log()
        
        # Update finding state if transition was successful
        if result.success:
            finding.state = result.new_state
            finding.last_updated_at = datetime.utcnow()
            response["updated_finding"] = finding.to_dynamodb_item()
    
    return response

# Local testing function
def local_test(finding_data: Dict[str, Any]) -> Dict[str, Any]:
    """Test the decision engine locally."""
    initialize_engine()
    
    finding = Finding.from_dynamodb_item(finding_data)
    result = process_finding(finding)
    
    return result
