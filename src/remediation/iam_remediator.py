"""IAM-specific remediation implementation."""
import logging
from typing import Dict, Any, List

from src.remediation.base_remediator import BaseRemediator, RemediationError
from src.models.finding import Finding, ResourceType
from src.models.remediation_plan import RemediationPlan, RemediationAction

logger = logging.getLogger(__name__)

class IAMRemediator(BaseRemediator):
    """Remediator for IAM misconfigurations."""
    
    def can_remediate(self, finding: Finding) -> bool:
        """Check if this is an IAM finding."""
        return finding.resource_type in [
            ResourceType.IAM_ROLE,
            ResourceType.IAM_USER,
            ResourceType.IAM_POLICY
        ]
    
    def create_remediation_plan(self, finding: Finding) -> RemediationPlan:
        """Create remediation plan for IAM finding."""
        
        if finding.rule_id == "IAM-OVER-PERMISSIVE-001":
            return self._create_detach_policy_plan(finding)
        elif finding.rule_id == "IAM-UNUSED-CREDENTIALS-001":
            return self._create_deactivate_key_plan(finding)
        else:
            raise ValueError(f"Unsupported IAM rule: {finding.rule_id}")
    
    def _create_detach_policy_plan(self, finding: Finding) -> RemediationPlan:
        """Create plan to detach over-permissive IAM policy."""
        resource_arn = finding.resource_arn
        
        # Extract resource type and name from ARN
        arn_parts = resource_arn.split(":")
        resource_type = arn_parts[2]  # iam
        resource_id = arn_parts[5] if len(arn_parts) > 5 else ""
        
        plan = RemediationPlan(
            finding_id=finding.finding_id,
            correlation_id=finding.correlation_id,
            action=RemediationAction.DETACH_IAM_POLICY,
            target_resource_arn=resource_arn,
            rule_id=finding.rule_id,
            justification="Detach over-permissive IAM policy to reduce privilege escalation risk",
            execution_mode=self.execution_mode,
            requires_approval=True  # IAM changes require approval
        )
        
        # Get policy ARN from finding details
        current_config = finding.current_config or {}
        attached_policies = current_config.get("attached_policies", [])
        
        # Find the over-permissive policy (simplified logic)
        over_permissive_policy = None
        for policy in attached_policies:
            if isinstance(policy, dict) and policy.get("policy_name") == "AdministratorAccess":
                over_permissive_policy = policy
                break
        
        if not over_permissive_policy and attached_policies:
            # Use first policy as example
            over_permissive_policy = attached_policies[0]
        
        if over_permissive_policy:
            policy_arn = over_permissive_policy.get("policy_arn", "arn:aws:iam::aws:policy/AdministratorAccess")
            
            if "role" in resource_id:
                # Detach from role
                role_name = resource_id.split("/")[-1]
                plan.add_api_call(
                    service="iam",
                    operation="DetachRolePolicy",
                    parameters={
                        "RoleName": role_name,
                        "PolicyArn": policy_arn
                    },
                    effect="Allow"
                )
                
                # Rollback: Re-attach policy
                plan.add_rollback_call(
                    service="iam",
                    operation="AttachRolePolicy",
                    parameters={
                        "RoleName": role_name,
                        "PolicyArn": policy_arn
                    },
                    effect="Allow"
                )
                
            elif "user" in resource_id:
                # Detach from user
                user_name = resource_id.split("/")[-1]
                plan.add_api_call(
                    service="iam",
                    operation="DetachUserPolicy",
                    parameters={
                        "UserName": user_name,
                        "PolicyArn": policy_arn
                    },
                    effect="Allow"
                )
                
                # Rollback: Re-attach policy
                plan.add_rollback_call(
                    service="iam",
                    operation="AttachUserPolicy",
                    parameters={
                        "UserName": user_name,
                        "PolicyArn": policy_arn
                    },
                    effect="Allow"
                )
        
        return plan
    
    def _create_deactivate_key_plan(self, finding: Finding) -> RemediationPlan:
        """Create plan to deactivate unused IAM access key."""
        resource_arn = finding.resource_arn
        
        plan = RemediationPlan(
            finding_id=finding.finding_id,
            correlation_id=finding.correlation_id,
            action=RemediationAction.DEACTIVATE_IAM_ACCESS_KEY,
            target_resource_arn=resource_arn,
            rule_id=finding.rule_id,
            justification="Deactivate unused IAM access key to reduce security risk",
            execution_mode=self.execution_mode,
            requires_approval=True  # Access key changes require approval
        )
        
        # Extract user name from ARN
        arn_parts = resource_arn.split(":")
        if len(arn_parts) > 5:
            user_name = arn_parts[5].split("/")[-1]
            
            # Get access key ID from finding details
            current_config = finding.current_config or {}
            access_keys = current_config.get("access_keys", [])
            
            if access_keys:
                # Use first unused key
                key_id = access_keys[0].get("access_key_id", "EXAMPLEKEYID")
                
                plan.add_api_call(
                    service="iam",
                    operation="UpdateAccessKey",
                    parameters={
                        "UserName": user_name,
                        "AccessKeyId": key_id,
                        "Status": "Inactive"
                    },
                    effect="Allow"
                )
                
                # Rollback: Reactivate key
                plan.add_rollback_call(
                    service="iam",
                    operation="UpdateAccessKey",
                    parameters={
                        "UserName": user_name,
                        "AccessKeyId": key_id,
                        "Status": "Active"
                    },
                    effect="Allow"
                )
        
        return plan
    
    def execute_remediation(self, plan: RemediationPlan) -> Dict[str, Any]:
        """Execute IAM remediation plan."""
        logger.info(f"Executing IAM remediation plan: {plan.action.value}")
        
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
            if api_call.service == "iam":
                if api_call.operation == "DetachRolePolicy":
                    result = self.aws_client.get_iam_client().detach_role_policy(
                        **api_call.parameters
                    )
                    results.append(result)
                elif api_call.operation == "DetachUserPolicy":
                    result = self.aws_client.get_iam_client().detach_user_policy(
                        **api_call.parameters
                    )
                    results.append(result)
                elif api_call.operation == "UpdateAccessKey":
                    result = self.aws_client.get_iam_client().update_access_key(
                        **api_call.parameters
                    )
                    results.append(result)
                else:
                    raise RemediationError(f"Unsupported IAM operation: {api_call.operation}")
        
        return {
            "success": True,
            "results": results,
            "intent_logs": intent_logs,
            "plan_id": plan.plan_id
        }
    
    def execute_rollback(self, plan: RemediationPlan) -> Dict[str, Any]:
        """Execute IAM rollback plan."""
        logger.info(f"Executing IAM rollback plan for {plan.plan_id}")
        
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
            if api_call.service == "iam":
                if api_call.operation == "AttachRolePolicy":
                    result = self.aws_client.get_iam_client().attach_role_policy(
                        **api_call.parameters
                    )
                    results.append(result)
                elif api_call.operation == "AttachUserPolicy":
                    result = self.aws_client.get_iam_client().attach_user_policy(
                        **api_call.parameters
                    )
                    results.append(result)
                elif api_call.operation == "UpdateAccessKey":
                    result = self.aws_client.get_iam_client().update_access_key(
                        **api_call.parameters
                    )
                    results.append(result)
                else:
                    raise RemediationError(f"Unsupported IAM rollback operation: {api_call.operation}")
        
        return {
            "success": True,
            "results": results,
            "intent_logs": intent_logs,
            "plan_id": plan.plan_id
        }