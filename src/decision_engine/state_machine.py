"""State machine for Nebula Shield findings."""
from enum import Enum
from typing import Dict, Any, Optional, Callable
from dataclasses import dataclass
from datetime import datetime
import logging

from src.models.finding import Finding, FindingState, FindingSeverity
from src.models.remediation_plan import RemediationPlan, RemediationAction, ExecutionMode

logger = logging.getLogger(__name__)

class TransitionResult:
    """Result of a state transition."""
    
    def __init__(self, success: bool, new_state: FindingState, 
                 message: str = "", plan: Optional[RemediationPlan] = None):
        self.success = success
        self.new_state = new_state
        self.message = message
        self.plan = plan
    
    def __repr__(self):
        return f"TransitionResult(success={self.success}, state={self.new_state}, message={self.message})"

@dataclass
class StateTransition:
    """Defines a valid state transition."""
    from_state: FindingState
    to_state: FindingState
    condition: Callable[[Finding], bool]
    action: Callable[[Finding], Optional[RemediationPlan]]
    description: str

class DecisionEngine:
    """Core decision engine implementing the state machine."""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {
            "auto_remediate_low_risk": True,
            "auto_remediate_medium_risk": False,
            "require_approval_high_risk": True,
            "dry_run_mode": True,  # Default to safe mode
            "enabled_rules": ["S3-PUBLIC-ACCESS-001"]
        }
        
        # Initialize state transitions
        self.transitions = self._initialize_transitions()
        
        # Rule definitions for risk assessment
        self.risk_rules = {
            "S3-PUBLIC-ACCESS-001": {
                "severity": FindingSeverity.HIGH,
                "auto_remediate": True,  # S3 public access is critical
                "requires_approval": False,  # Auto-remediate by default
                "remediation_action": RemediationAction.ENABLE_S3_PUBLIC_ACCESS_BLOCK,
                "timeout_minutes": 5
            },
            "IAM-OVER-PERMISSIVE-001": {
                "severity": FindingSeverity.CRITICAL,
                "auto_remediate": False,  # IAM changes require approval
                "requires_approval": True,
                "remediation_action": RemediationAction.DETACH_IAM_POLICY,
                "timeout_minutes": 30
            },
            "SG-OPEN-PORTS-001": {
                "severity": FindingSeverity.HIGH,
                "auto_remediate": False,  # Security group changes require approval
                "requires_approval": True,
                "remediation_action": RemediationAction.REVOKE_SECURITY_GROUP_INGRESS,
                "timeout_minutes": 15
            }
        }
    
    def _initialize_transitions(self) -> Dict[str, StateTransition]:
        """Initialize all valid state transitions."""
        transitions = []
        
        # DETECTED -> AUTO_REMEDIATE (for low-risk auto-remediate findings)
        transitions.append(StateTransition(
            from_state=FindingState.DETECTED,
            to_state=FindingState.AUTO_REMEDIATE,
            condition=lambda f: self._should_auto_remediate(f),
            action=self._create_remediation_plan,
            description="Finding qualifies for automatic remediation"
        ))
        
        # DETECTED -> PENDING_APPROVAL (for high-risk findings)
        transitions.append(StateTransition(
            from_state=FindingState.DETECTED,
            to_state=FindingState.PENDING_APPROVAL,
            condition=lambda f: self._requires_approval(f),
            action=self._create_pending_approval_plan,
            description="Finding requires manual approval"
        ))
        
        # PENDING_APPROVAL -> APPROVED (manual approval granted)
        transitions.append(StateTransition(
            from_state=FindingState.PENDING_APPROVAL,
            to_state=FindingState.APPROVED,
            condition=lambda f: True,  # Any PENDING_APPROVAL can be approved
            action=self._create_remediation_plan,
            description="Approval granted, create remediation plan"
        ))
        
        # AUTO_REMEDIATE/APPROVED -> REMEDIATED
        transitions.append(StateTransition(
            from_state=FindingState.AUTO_REMEDIATE,
            to_state=FindingState.REMEDIATED,
            condition=lambda f: True,
            action=None,  # No action needed, remediation happened
            description="Remediation completed successfully"
        ))
        
        transitions.append(StateTransition(
            from_state=FindingState.APPROVED,
            to_state=FindingState.REMEDIATED,
            condition=lambda f: True,
            action=None,
            description="Approved remediation completed successfully"
        ))
        
        # AUTO_REMEDIATE/APPROVED -> FAILED
        transitions.append(StateTransition(
            from_state=FindingState.AUTO_REMEDIATE,
            to_state=FindingState.FAILED,
            condition=lambda f: True,
            action=self._create_rollback_plan,
            description="Remediation failed, create rollback plan"
        ))
        
        transitions.append(StateTransition(
            from_state=FindingState.APPROVED,
            to_state=FindingState.FAILED,
            condition=lambda f: True,
            action=self._create_rollback_plan,
            description="Approved remediation failed, create rollback plan"
        ))
        
        # FAILED -> ROLLED_BACK
        transitions.append(StateTransition(
            from_state=FindingState.FAILED,
            to_state=FindingState.ROLLED_BACK,
            condition=lambda f: True,
            action=None,
            description="Rollback completed successfully"
        ))
        
        # Any -> SUPPRESSED (for false positives)
        for state in FindingState:
            if state not in [FindingState.SUPPRESSED, FindingState.ROLLED_BACK]:
                transitions.append(StateTransition(
                    from_state=state,
                    to_state=FindingState.SUPPRESSED,
                    condition=lambda f: self._can_suppress(f),
                    action=None,
                    description="Finding suppressed as false positive"
                ))
        
        # Create lookup dictionary
        transition_map = {}
        for transition in transitions:
            key = f"{transition.from_state.value}->{transition.to_state.value}"
            transition_map[key] = transition
        
        return transition_map
    
    def evaluate_finding(self, finding: Finding) -> TransitionResult:
        """Evaluate a finding and determine next state."""
        logger.info(f"Evaluating finding {finding.finding_id} in state {finding.state}")
        
        # Check if rule is enabled
        if finding.rule_id not in self.config["enabled_rules"]:
            return TransitionResult(
                success=False,
                new_state=finding.state,
                message=f"Rule {finding.rule_id} is disabled in configuration"
            )
        
        # Determine target state based on risk assessment
        target_state = self._determine_target_state(finding)
        
        # Check if transition is valid
        transition_key = f"{finding.state.value}->{target_state.value}"
        
        if transition_key not in self.transitions:
            return TransitionResult(
                success=False,
                new_state=finding.state,
                message=f"No valid transition from {finding.state} to {target_state}"
            )
        
        transition = self.transitions[transition_key]
        
        # Check if condition is met
        if not transition.condition(finding):
            return TransitionResult(
                success=False,
                new_state=finding.state,
                message=f"Transition condition not met: {transition.description}"
            )
        
        # Execute transition action if any
        plan = transition.action(finding) if transition.action else None
        
        return TransitionResult(
            success=True,
            new_state=target_state,
            message=transition.description,
            plan=plan
        )
    
    def _determine_target_state(self, finding: Finding) -> FindingState:
        """Determine the target state based on finding risk and rules."""
        rule_config = self.risk_rules.get(finding.rule_id, {})
        
        # Check if auto-remediation is disabled globally
        if self.config.get("dry_run_mode", True):
            logger.info("Dry run mode enabled, findings will not be auto-remediated")
            return FindingState.DETECTED  # Stay in detected for observation
        
        # Check if this specific rule requires approval
        requires_approval = rule_config.get("requires_approval", True)
        auto_remediate = rule_config.get("auto_remediate", False)
        
        if finding.state == FindingState.DETECTED:
            if auto_remediate and not requires_approval:
                return FindingState.AUTO_REMEDIATE
            elif requires_approval:
                return FindingState.PENDING_APPROVAL
            else:
                return FindingState.DETECTED  # Stay for observation
        
        # If already in a state, transition to next logical state
        if finding.state == FindingState.PENDING_APPROVAL:
            # In MVP, we don't have approval workflow yet
            # So we'll either auto-remediate or stay in approval
            if not requires_approval:
                return FindingState.AUTO_REMEDIATE
            else:
                return FindingState.PENDING_APPROVAL
        
        # For other states, stay the same unless explicitly changed
        return finding.state
    
    def _should_auto_remediate(self, finding: Finding) -> bool:
        """Determine if a finding should be auto-remediated."""
        rule_config = self.risk_rules.get(finding.rule_id, {})
        
        # Check global settings
        if not self.config.get("auto_remediate_low_risk", False) and finding.severity == FindingSeverity.LOW:
            return False
        
        # Check rule-specific settings
        return rule_config.get("auto_remediate", False)
    
    def _requires_approval(self, finding: Finding) -> bool:
        """Determine if a finding requires approval."""
        rule_config = self.risk_rules.get(finding.rule_id, {})
        return rule_config.get("requires_approval", True)
    
    def _can_suppress(self, finding: Finding) -> bool:
        """Determine if a finding can be suppressed."""
        # In production, this would check against suppression rules
        # For MVP, we'll allow suppression of low severity findings only
        return finding.severity in [FindingSeverity.LOW, FindingSeverity.MEDIUM]
    
    def _create_remediation_plan(self, finding: Finding) -> RemediationPlan:
        """Create a remediation plan for the finding."""
        rule_config = self.risk_rules.get(finding.rule_id, {})
        
        # Determine execution mode
        execution_mode = ExecutionMode.DRY_RUN if self.config.get("dry_run_mode", True) else ExecutionMode.EXECUTE_WITH_ROLLBACK
        
        # Create plan
        plan = RemediationPlan(
            finding_id=finding.finding_id,
            correlation_id=finding.correlation_id,
            action=rule_config.get("remediation_action", RemediationAction.NO_OP),
            target_resource_arn=finding.resource_arn,
            rule_id=finding.rule_id,
            justification=f"Auto-remediation for {finding.title}",
            execution_mode=execution_mode,
            requires_approval=rule_config.get("requires_approval", True)
        )
        
        # Add specific API calls based on resource type and rule
        if finding.rule_id == "S3-PUBLIC-ACCESS-001":
            self._add_s3_public_access_remediation(plan, finding)
        elif finding.rule_id == "IAM-OVER-PERMISSIVE-001":
            self._add_iam_policy_remediation(plan, finding)
        elif finding.rule_id == "SG-OPEN-PORTS-001":
            self._add_sg_remediation(plan, finding)
        
        return plan
    
    def _create_pending_approval_plan(self, finding: Finding) -> Optional[RemediationPlan]:
        """Create a plan that requires approval."""
        # For MVP, we'll create a plan but mark it as requiring approval
        plan = self._create_remediation_plan(finding)
        plan.requires_approval = True
        plan.execution_mode = ExecutionMode.INTENT_ONLY  # Don't execute until approved
        
        # Add approval required note
        plan.justification = f"APPROVAL REQUIRED: {plan.justification}"
        
        return plan
    
    def _create_rollback_plan(self, finding: Finding) -> RemediationPlan:
        """Create a rollback plan for a failed remediation."""
        plan = RemediationPlan(
            finding_id=finding.finding_id,
            correlation_id=finding.correlation_id,
            action=RemediationAction.ROLLBACK_S3_PUBLIC_ACCESS,
            target_resource_arn=finding.resource_arn,
            rule_id=finding.rule_id,
            justification=f"Rollback for failed remediation of {finding.title}",
            execution_mode=ExecutionMode.EXECUTE_WITH_ROLLBACK,
            requires_approval=False  # Rollbacks are automatic
        )
        
        # Add rollback API calls
        if finding.rule_id == "S3-PUBLIC-ACCESS-001":
            bucket_name = finding.resource_arn.split(":")[-1]
            plan.add_api_call(
                service="s3",
                operation="PutPublicAccessBlock",
                parameters={
                    "Bucket": bucket_name,
                    "PublicAccessBlockConfiguration": {
                        "BlockPublicAcls": False,
                        "IgnorePublicAcls": False,
                        "BlockPublicPolicy": False,
                        "RestrictPublicBuckets": False
                    }
                },
                effect="Allow"
            )
        
        return plan
    
    def _add_s3_public_access_remediation(self, plan: RemediationPlan, finding: Finding):
        """Add S3 public access remediation API calls."""
        bucket_name = finding.resource_arn.split(":")[-1]
        
        # Main remediation: Enable public access block
        plan.add_api_call(
            service="s3",
            operation="PutPublicAccessBlock",
            parameters={
                "Bucket": bucket_name,
                "PublicAccessBlockConfiguration": {
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": True
                }
            },
            effect="Allow"
        )
        
        # Rollback: Restore original configuration
        current_config = finding.current_config or {}
        public_access_config = current_config.get("public_access_block", {})
        
        plan.add_rollback_call(
            service="s3",
            operation="PutPublicAccessBlock",
            parameters={
                "Bucket": bucket_name,
                "PublicAccessBlockConfiguration": {
                    "BlockPublicAcls": public_access_config.get("BlockPublicAcls", False),
                    "IgnorePublicAcls": public_access_config.get("IgnorePublicAcls", False),
                    "BlockPublicPolicy": public_access_config.get("BlockPublicPolicy", False),
                    "RestrictPublicBuckets": public_access_config.get("RestrictPublicBuckets", False)
                }
            },
            effect="Allow"
        )
    
    def _add_iam_policy_remediation(self, plan: RemediationPlan, finding: Finding):
        """Add IAM policy remediation API calls."""
        # Extract role name from ARN
        arn_parts = finding.resource_arn.split(":")
        if len(arn_parts) >= 6:
            resource_path = arn_parts[5]
            resource_name = resource_path.split("/")[-1]
            
            # In a real scenario, we'd have the policy ARN in finding.current_config
            # For MVP, we'll use a placeholder
            policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
            
            plan.add_api_call(
                service="iam",
                operation="DetachRolePolicy",
                parameters={
                    "RoleName": resource_name,
                    "PolicyArn": policy_arn
                },
                effect="Allow"
            )
    
    def _add_sg_remediation(self, plan: RemediationPlan, finding: Finding):
        """Add security group remediation API calls."""
        # Extract security group ID from ARN
        arn_parts = finding.resource_arn.split(":")
        if len(arn_parts) >= 6:
            sg_id = arn_parts[-1]
            
            # In a real scenario, we'd have the ingress rule details in finding.current_config
            # For MVP, we'll use placeholders for port 22 SSH access
            plan.add_api_call(
                service="ec2",
                operation="RevokeSecurityGroupIngress",
                parameters={
                    "GroupId": sg_id,
                    "IpPermissions": [{
                        "IpProtocol": "tcp",
                        "FromPort": 22,
                        "ToPort": 22,
                        "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
                    }]
                },
                effect="Allow"
            )

    def get_valid_transitions(self, current_state: FindingState) -> list[FindingState]:
        """Get all valid transitions from a given state."""
        valid_states = []
        for transition_key, transition in self.transitions.items():
            if transition.from_state == current_state:
                valid_states.append(transition.to_state)
        return valid_states
