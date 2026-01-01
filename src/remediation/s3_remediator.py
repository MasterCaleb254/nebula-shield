"""S3-specific remediation implementation."""
import json
from typing import Dict, Any, Optional
import logging

from src.remediation.base_remediator import BaseRemediator, RemediationError
from src.models.finding import Finding, ResourceType
from src.models.remediation_plan import RemediationPlan, RemediationAction

logger = logging.getLogger(__name__)

class S3Remediator(BaseRemediator):
    """Remediator for S3 misconfigurations."""
    
    def can_remediate(self, finding: Finding) -> bool:
        """Check if this is an S3 finding."""
        return finding.resource_type == ResourceType.S3_BUCKET
    
    def create_remediation_plan(self, finding: Finding) -> RemediationPlan:
        """Create remediation plan for S3 finding."""
        
        if finding.rule_id == "S3-PUBLIC-ACCESS-001":
            return self._create_public_access_plan(finding)
        elif finding.rule_id == "S3-ENCRYPTION-001":
            return self._create_encryption_plan(finding)
        else:
            raise ValueError(f"Unsupported S3 rule: {finding.rule_id}")
    
    def _create_public_access_plan(self, finding: Finding) -> RemediationPlan:
        """Create plan to enable S3 public access block."""
        bucket_name = finding.resource_arn.split(":")[-1]
        
        plan = RemediationPlan(
            finding_id=finding.finding_id,
            correlation_id=finding.correlation_id,
            action=RemediationAction.ENABLE_S3_PUBLIC_ACCESS_BLOCK,
            target_resource_arn=finding.resource_arn,
            rule_id=finding.rule_id,
            justification="Enable S3 public access block to prevent accidental public access",
            execution_mode=self.execution_mode,
            requires_approval=False  # Auto-remediate for S3 public access
        )
        
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
        
        # Store current configuration for rollback
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
        
        return plan
    
    def _create_encryption_plan(self, finding: Finding) -> RemediationPlan:
        """Create plan to enable S3 bucket encryption."""
        bucket_name = finding.resource_arn.split(":")[-1]
        
        plan = RemediationPlan(
            finding_id=finding.finding_id,
            correlation_id=finding.correlation_id,
            action=RemediationAction.ENABLE_S3_PUBLIC_ACCESS_BLOCK,  # Using same action for now
            target_resource_arn=finding.resource_arn,
            rule_id=finding.rule_id,
            justification="Enable default encryption for S3 bucket",
            execution_mode=self.execution_mode,
            requires_approval=True  # Encryption changes should be approved
        )
        
        # Main remediation: Enable bucket encryption
        plan.add_api_call(
            service="s3",
            operation="PutBucketEncryption",
            parameters={
                "Bucket": bucket_name,
                "ServerSideEncryptionConfiguration": {
                    "Rules": [
                        {
                            "ApplyServerSideEncryptionByDefault": {
                                "SSEAlgorithm": "AES256"
                            },
                            "BucketKeyEnabled": True
                        }
                    ]
                }
            },
            effect="Allow"
        )
        
        return plan
    
    def execute_remediation(self, plan: RemediationPlan) -> Dict[str, Any]:
        """Execute S3 remediation plan."""
        logger.info(f"Executing S3 remediation plan: {plan.action.value}")
        
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
            if api_call.service == "s3" and api_call.operation == "PutPublicAccessBlock":
                result = self.aws_client.get_s3_client().put_public_access_block(
                    **api_call.parameters
                )
                results.append(result)
            elif api_call.service == "s3" and api_call.operation == "PutBucketEncryption":
                result = self.aws_client.get_s3_client().put_bucket_encryption(
                    **api_call.parameters
                )
                results.append(result)
            elif api_call.service == "s3" and api_call.operation == "PutBucketPolicy":
                result = self.aws_client.get_s3_client().put_bucket_policy(
                    **api_call.parameters
                )
                results.append(result)
            else:
                raise RemediationError(f"Unsupported S3 operation: {api_call.operation}")
        
        # Return combined results
        return {
            "success": True,
            "results": results,
            "intent_logs": intent_logs,
            "plan_id": plan.plan_id
        }
    
    def execute_rollback(self, plan: RemediationPlan) -> Dict[str, Any]:
        """Execute S3 rollback plan."""
        logger.info(f"Executing S3 rollback plan for {plan.plan_id}")
        
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
            if api_call.service == "s3" and api_call.operation == "PutPublicAccessBlock":
                result = self.aws_client.get_s3_client().put_public_access_block(
                    **api_call.parameters
                )
                results.append(result)
            else:
                raise RemediationError(f"Unsupported S3 rollback operation: {api_call.operation}")
        
        return {
            "success": True,
            "results": results,
            "intent_logs": intent_logs,
            "plan_id": plan.plan_id
        }
    
    def _specific_verification(self, plan: RemediationPlan, result: Dict[str, Any]) -> bool:
        """Verify S3 remediation was successful."""
        # For S3 public access block, we can verify by checking the new state
        if plan.action == RemediationAction.ENABLE_S3_PUBLIC_ACCESS_BLOCK:
            bucket_name = plan.target_resource_arn.split(":")[-1]
            
            try:
                # Get current public access block configuration
                response = self.aws_client.get_s3_client().get_public_access_block(
                    Bucket=bucket_name
                )
                
                config = response.get("PublicAccessBlockConfiguration", {})
                
                # Check if all blocking options are enabled
                if all([
                    config.get("BlockPublicAcls", False),
                    config.get("IgnorePublicAcls", False),
                    config.get("BlockPublicPolicy", False),
                    config.get("RestrictPublicBuckets", False)
                ]):
                    logger.info(f"Verified S3 public access block enabled for {bucket_name}")
                    return True
                else:
                    logger.warning(f"S3 public access block not fully enabled for {bucket_name}")
                    return False
                    
            except Exception as e:
                logger.error(f"Failed to verify S3 remediation: {str(e)}")
                return False
        
        return True