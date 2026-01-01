"""Security Group-specific remediation implementation."""
import logging
from typing import Dict, Any

from src.remediation.base_remediator import BaseRemediator, RemediationError
from src.models.finding import Finding, ResourceType
from src.models.remediation_plan import RemediationPlan, RemediationAction

logger = logging.getLogger(__name__)

class SecurityGroupRemediator(BaseRemediator):
    """Remediator for Security Group misconfigurations."""
    
    def can_remediate(self, finding: Finding) -> bool:
        """Check if this is a Security Group finding."""
        return finding.resource_type == ResourceType.SECURITY_GROUP
    
    def create_remediation_plan(self, finding: Finding) -> RemediationPlan:
        """Create remediation plan for Security Group finding."""
        
        if finding.rule_id == "SG-OPEN-PORTS-001":
            return self._create_revoke_ingress_plan(finding)
        else:
            raise ValueError(f"Unsupported Security Group rule: {finding.rule_id}")
    
    def _create_revoke_ingress_plan(self, finding: Finding) -> RemediationPlan:
        """Create plan to revoke overly permissive security group ingress."""
        resource_arn = finding.resource_arn
        
        # Extract security group ID from ARN
        arn_parts = resource_arn.split(":")
        sg_id = arn_parts[-1] if len(arn_parts) > 5 else ""
        
        plan = RemediationPlan(
            finding_id=finding.finding_id,
            correlation_id=finding.correlation_id,
            action=RemediationAction.REVOKE_SECURITY_GROUP_INGRESS,
            target_resource_arn=resource_arn,
            rule_id=finding.rule_id,
            justification="Revoke overly permissive security group ingress rules to reduce attack surface",
            execution_mode=self.execution_mode,
            requires_approval=True  # Security group changes require approval
        )
        
        # Get current ingress rules from finding details
        current_config = finding.current_config or {}
        ingress_rules = current_config.get("ingress_rules", [])
        
        # Find overly permissive rules (open to 0.0.0.0/0 on sensitive ports)
        overly_permissive_rules = []
        for rule in ingress_rules:
            # Simplified logic: check for 0.0.0.0/0 on ports 22 or 3389
            ip_ranges = rule.get("ip_ranges", [])
            from_port = rule.get("from_port")
            to_port = rule.get("to_port")
            
            for ip_range in ip_ranges:
                if ip_range.get("cidr_ip") == "0.0.0.0/0":
                    if from_port in [22, 3389] or to_port in [22, 3389]:
                        overly_permissive_rules.append(rule)
                    elif from_port is None and to_port is None:  # All ports
                        overly_permissive_rules.append(rule)
        
        # Create API calls for each overly permissive rule
        for rule in overly_permissive_rules:
            plan.add_api_call(
                service="ec2",
                operation="RevokeSecurityGroupIngress",
                parameters={
                    "GroupId": sg_id,
                    "IpPermissions": [
                        {
                            "IpProtocol": rule.get("ip_protocol", "tcp"),
                            "FromPort": rule.get("from_port", 22),
                            "ToPort": rule.get("to_port", 22),
                            "IpRanges": [
                                {"CidrIp": ip_range.get("cidr_ip", "0.0.0.0/0")}
                                for ip_range in rule.get("ip_ranges", [])
                            ]
                        }
                    ]
                },
                effect="Allow"
            )
            
            # Rollback: Re-add the rule
            plan.add_rollback_call(
                service="ec2",
                operation="AuthorizeSecurityGroupIngress",
                parameters={
                    "GroupId": sg_id,
                    "IpPermissions": [
                        {
                            "IpProtocol": rule.get("ip_protocol", "tcp"),
                            "FromPort": rule.get("from_port", 22),
                            "ToPort": rule.get("to_port", 22),
                            "IpRanges": [
                                {"CidrIp": ip_range.get("cidr_ip", "0.0.0.0/0")}
                                for ip_range in rule.get("ip_ranges", [])
                            ]
                        }
                    ]
                },
                effect="Allow"
            )
        
        return plan
    
    def execute_remediation(self, plan: RemediationPlan) -> Dict[str, Any]:
        """Execute Security Group remediation plan."""
        logger.info(f"Executing Security Group remediation plan: {plan.action.value}")
        
        results = []
        intent_logs = []
        
        for api_call in plan.api_calls:
            # Log intent
            intent_log = self._log_intent(
                api_call.service,
                api_call.operation,
                api_call.parameters
            )
            intent_logs.append(intent_log)
            
            # Execute via mock AWS client
            if api_call.service == "ec2":
                if api_call.operation == "RevokeSecurityGroupIngress":
                    # Create mock EC2 client
                    class MockEC2Client:
                        def __init__(self, parent):
                            self.parent = parent
                        
                        def revoke_security_group_ingress(self, **kwargs):
                            return self.parent.aws_client.log_intent("ec2", "RevokeSecurityGroupIngress", kwargs)
                    
                    result = MockEC2Client(self).revoke_security_group_ingress(
                        **api_call.parameters
                    )
                    results.append(result)
                else:
                    raise RemediationError(f"Unsupported EC2 operation: {api_call.operation}")
        
        return {
            "success": True,
            "results": results,
            "intent_logs": intent_logs,
            "plan_id": plan.plan_id
        }
    
    def execute_rollback(self, plan: RemediationPlan) -> Dict[str, Any]:
        """Execute Security Group rollback plan."""
        logger.info(f"Executing Security Group rollback plan for {plan.plan_id}")
        
        results = []
        intent_logs = []
        
        for api_call in plan.rollback_calls:
            # Log intent
            intent_log = self._log_intent(
                api_call.service,
                api_call.operation,
                api_call.parameters
            )
            intent_logs.append(intent_log)
            
            # Execute via mock AWS client
            if api_call.service == "ec2":
                if api_call.operation == "AuthorizeSecurityGroupIngress":
                    # Create mock EC2 client
                    class MockEC2Client:
                        def __init__(self, parent):
                            self.parent = parent
                        
                        def authorize_security_group_ingress(self, **kwargs):
                            return self.parent.aws_client.log_intent("ec2", "AuthorizeSecurityGroupIngress", kwargs)
                    
                    result = MockEC2Client(self).authorize_security_group_ingress(
                        **api_call.parameters
                    )
                    results.append(result)
                else:
                    raise RemediationError(f"Unsupported EC2 rollback operation: {api_call.operation}")
        
        return {
            "success": True,
            "results": results,
            "intent_logs": intent_logs,
            "plan_id": plan.plan_id
        }