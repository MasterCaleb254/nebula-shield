"""Remediation infrastructure stack."""
from aws_cdk import (
    Stack,
    Duration,
    aws_lambda as lambda_,
    aws_events as events,
    aws_events_targets as targets,
    aws_iam as iam,
    aws_dynamodb as dynamodb,
    CfnOutput,
)
from constructs import Construct


class RemediationStack(Stack):
    """Remediation infrastructure for Nebula Shield."""
    
    def __init__(self, scope: Construct, construct_id: str, 
                 core_stack, detection_stack, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        
        # Get context
        environment = self.node.try_get_context("environment") or "dev"
        dry_run_mode = self.node.try_get_context("dry_run_mode") or "true"
        enabled_rules = self.node.try_get_context("enabled_rules") or []
        enable_auto_remediation = self.node.try_get_context("enable_auto_remediation") or "false"
        
        # Import resources
        findings_table = core_stack.findings_table
        event_bus = core_stack.event_bus
        decision_role = core_stack.decision_role
        
        # Create Decision Engine Lambda
        decision_lambda = lambda_.Function(
            self, "DecisionEngineLambda",
            runtime=lambda_.Runtime.PYTHON_3_11,
            handler="handler.lambda_handler",
            code=lambda_.Code.from_asset("src/decision_engine"),
            timeout=Duration.seconds(60),
            memory_size=512,
            role=decision_role,
            environment={
                "FINDINGS_TABLE_NAME": findings_table.table_name,
                "ENVIRONMENT": environment,
                "DRY_RUN_MODE": dry_run_mode,
                "ENABLED_RULES": str(enabled_rules),
                "AUTO_REMEDIATE_LOW_RISK": "false",
                "AUTO_REMEDIATE_MEDIUM_RISK": "false",
                "REQUIRE_APPROVAL_HIGH_RISK": "true",
                "POWERTOOLS_SERVICE_NAME": "nebula-shield-decision",
                "LOG_LEVEL": "INFO"
            },
            tracing=lambda_.Tracing.ACTIVE,
        )
        
        # Create remediation roles (service-specific, least privilege)
        # S3 remediation role
        s3_remediation_role = iam.Role(
            self, "S3RemediationRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            description="Role for S3 remediation functions",
            role_name=f"nebulashield-remediation-s3-{environment}",
        )
        
        # IAM remediation role
        iam_remediation_role = iam.Role(
            self, "IAMRemediationRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            description="Role for IAM remediation functions",
            role_name=f"nebulashield-remediation-iam-{environment}",
        )
        
        # EC2 remediation role
        ec2_remediation_role = iam.Role(
            self, "EC2RemediationRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            description="Role for EC2 remediation functions",
            role_name=f"nebulashield-remediation-ec2-{environment}",
        )
        
        # Base Lambda execution policy
        lambda_base_policy = iam.ManagedPolicy.from_aws_managed_policy_name(
            "service-role/AWSLambdaBasicExecutionRole"
        )
        
        s3_remediation_role.add_managed_policy(lambda_base_policy)
        iam_remediation_role.add_managed_policy(lambda_base_policy)
        ec2_remediation_role.add_managed_policy(lambda_base_policy)
        
        # S3 remediation permissions (narrowly scoped)
        s3_remediation_role.add_to_policy(
            iam.PolicyStatement(
                actions=[
                    "s3:PutPublicAccessBlock",
                    "s3:GetPublicAccessBlock",
                    "s3:GetBucketPolicy",
                    "s3:PutBucketPolicy",
                    "s3:DeleteBucketPolicy"
                ],
                resources=["arn:aws:s3:::*"],
                conditions={
                    "StringEquals": {
                        "aws:CalledVia": ["nebula-shield"]
                    }
                }
            )
        )
        
        # IAM remediation permissions (narrowly scoped)
        iam_remediation_role.add_to_policy(
            iam.PolicyStatement(
                actions=[
                    "iam:DetachRolePolicy",
                    "iam:DetachUserPolicy",
                    "iam:DeletePolicyVersion",
                    "iam:UpdateAssumeRolePolicy",
                    "iam:GetRole",
                    "iam:GetUser",
                    "iam:GetPolicy",
                    "iam:GetPolicyVersion",
                    "iam:ListAttachedRolePolicies",
                    "iam:ListAttachedUserPolicies"
                ],
                resources=["*"],
                conditions={
                    "StringEquals": {
                        "aws:CalledVia": ["nebula-shield"]
                    }
                }
            )
        )
        
        # EC2 remediation permissions (narrowly scoped)
        ec2_remediation_role.add_to_policy(
            iam.PolicyStatement(
                actions=[
                    "ec2:RevokeSecurityGroupIngress",
                    "ec2:RevokeSecurityGroupEgress",
                    "ec2:DescribeSecurityGroups",
                    "ec2:DescribeSecurityGroupRules"
                ],
                resources=["*"],
                conditions={
                    "StringEquals": {
                        "aws:CalledVia": ["nebula-shield"]
                    }
                }
            )
        )
        
        # Explicit deny for permission expansion on all remediation roles
        for role in [s3_remediation_role, iam_remediation_role, ec2_remediation_role]:
            role.add_to_policy(
                iam.PolicyStatement(
                    effect=iam.Effect.DENY,
                    actions=["iam:*", "organizations:*"],
                    resources=["*"]
                )
            )
        
        # Create remediation Lambda functions
        s3_remediation_lambda = lambda_.Function(
            self, "S3RemediationLambda",
            runtime=lambda_.Runtime.PYTHON_3_11,
            handler="handler.lambda_handler",
            code=lambda_.Code.from_asset("src/remediation/s3"),
            timeout=Duration.seconds(30),
            memory_size=256,
            role=s3_remediation_role,
            environment={
                "FINDINGS_TABLE_NAME": findings_table.table_name,
                "ENVIRONMENT": environment,
                "DRY_RUN_MODE": dry_run_mode,
                "POWERTOOLS_SERVICE_NAME": "nebula-shield-remediation-s3",
                "LOG_LEVEL": "INFO"
            },
            tracing=lambda_.Tracing.ACTIVE,
        )
        
        iam_remediation_lambda = lambda_.Function(
            self, "IAMRemediationLambda",
            runtime=lambda_.Runtime.PYTHON_3_11,
            handler="handler.lambda_handler",
            code=lambda_.Code.from_asset("src/remediation/iam"),
            timeout=Duration.seconds(30),
            memory_size=256,
            role=iam_remediation_role,
            environment={
                "FINDINGS_TABLE_NAME": findings_table.table_name,
                "ENVIRONMENT": environment,
                "DRY_RUN_MODE": dry_run_mode,
                "POWERTOOLS_SERVICE_NAME": "nebula-shield-remediation-iam",
                "LOG_LEVEL": "INFO"
            },
            tracing=lambda_.Tracing.ACTIVE,
        )
        
        sg_remediation_lambda = lambda_.Function(
            self, "SecurityGroupRemediationLambda",
            runtime=lambda_.Runtime.PYTHON_3_11,
            handler="handler.lambda_handler",
            code=lambda_.Code.from_asset("src/remediation/security_group"),
            timeout=Duration.seconds(30),
            memory_size=256,
            role=ec2_remediation_role,
            environment={
                "FINDINGS_TABLE_NAME": findings_table.table_name,
                "ENVIRONMENT": environment,
                "DRY_RUN_MODE": dry_run_mode,
                "POWERTOOLS_SERVICE_NAME": "nebula-shield-remediation-sg",
                "LOG_LEVEL": "INFO"
            },
            tracing=lambda_.Tracing.ACTIVE,
        )
        
        # Grant DynamoDB permissions to remediation functions
        findings_table.grant_read_write_data(s3_remediation_lambda)
        findings_table.grant_read_write_data(iam_remediation_lambda)
        findings_table.grant_read_write_data(sg_remediation_lambda)
        
        # Create EventBridge rule for findings that need decision
        findings_rule = events.Rule(
            self, "FindingsRule",
            event_bus=event_bus,
            event_pattern=events.EventPattern(
                source=["nebula.shield"],
                detail_type=["Security Finding"],
                detail={
                    "state": ["DETECTED"]
                }
            )
        )
        findings_rule.add_target(targets.LambdaFunction(decision_lambda))
        
        # Create EventBridge rule for auto-remediation actions
        auto_remediate_rule = events.Rule(
            self, "AutoRemediateRule",
            event_bus=event_bus,
            event_pattern=events.EventPattern(
                source=["nebula.shield"],
                detail_type=["Remediation Plan"],
                detail={
                    "execution_mode": ["EXECUTE_WITH_ROLLBACK"],
                    "requires_approval": [False]
                }
            ),
            enabled=enable_auto_remediation.lower() == "true"
        )
        
        # Add multiple targets based on resource type
        auto_remediate_rule.add_target(
            targets.LambdaFunction(
                s3_remediation_lambda,
                event=events.RuleTargetInput.from_object({
                    "source": events.EventField.from_path("$.source"),
                    "detail-type": events.EventField.from_path("$.detail-type"),
                    "detail": events.EventField.from_path("$.detail"),
                    "resource-type-filter": ["AWS::S3::Bucket"]
                })
            )
        )
        
        auto_remediate_rule.add_target(
            targets.LambdaFunction(
                iam_remediation_lambda,
                event=events.RuleTargetInput.from_object({
                    "source": events.EventField.from_path("$.source"),
                    "detail-type": events.EventField.from_path("$.detail-type"),
                    "detail": events.EventField.from_path("$.detail"),
                    "resource-type-filter": ["AWS::IAM::Role", "AWS::IAM::User", "AWS::IAM::Policy"]
                })
            )
        )
        
        auto_remediate_rule.add_target(
            targets.LambdaFunction(
                sg_remediation_lambda,
                event=events.RuleTargetInput.from_object({
                    "source": events.EventField.from_path("$.source"),
                    "detail-type": events.EventField.from_path("$.detail-type"),
                    "detail": events.EventField.from_path("$.detail"),
                    "resource-type-filter": ["AWS::EC2::SecurityGroup"]
                })
            )
        )
        
        # Create EventBridge rule for approved remediations
        approved_remediate_rule = events.Rule(
            self, "ApprovedRemediateRule",
            event_bus=event_bus,
            event_pattern=events.EventPattern(
                source=["nebula.shield"],
                detail_type=["Remediation Plan"],
                detail={
                    "execution_mode": ["EXECUTE_WITH_ROLLBACK"],
                    "requires_approval": [True],
                    "approval_token": {"exists": True}
                }
            )
        )
        
        # Add targets for approved remediations
        approved_remediate_rule.add_target(
            targets.LambdaFunction(
                s3_remediation_lambda,
                event=events.RuleTargetInput.from_object({
                    "source": events.EventField.from_path("$.source"),
                    "detail-type": events.EventField.from_path("$.detail-type"),
                    "detail": events.EventField.from_path("$.detail"),
                    "resource-type-filter": ["AWS::S3::Bucket"]
                })
            )
        )
        
        approved_remediate_rule.add_target(
            targets.LambdaFunction(
                iam_remediation_lambda,
                event=events.RuleTargetInput.from_object({
                    "source": events.EventField.from_path("$.source"),
                    "detail-type": events.EventField.from_path("$.detail-type"),
                    "detail": events.EventField.from_path("$.detail"),
                    "resource-type-filter": ["AWS::IAM::Role", "AWS::IAM::User", "AWS::IAM::Policy"]
                })
            )
        )
        
        approved_remediate_rule.add_target(
            targets.LambdaFunction(
                sg_remediation_lambda,
                event=events.RuleTargetInput.from_object({
                    "source": events.EventField.from_path("$.source"),
                    "detail-type": events.EventField.from_path("$.detail-type"),
                    "detail": events.EventField.from_path("$.detail"),
                    "resource-type-filter": ["AWS::EC2::SecurityGroup"]
                })
            )
        )
        
        # Store references
        self.decision_lambda = decision_lambda
        self.s3_remediation_lambda = s3_remediation_lambda
        self.iam_remediation_lambda = iam_remediation_lambda
        self.sg_remediation_lambda = sg_remediation_lambda
        self.s3_remediation_role = s3_remediation_role
        self.iam_remediation_role = iam_remediation_role
        self.ec2_remediation_role = ec2_remediation_role
        
        # Outputs
        CfnOutput(self, "DecisionLambdaArn",
                  value=decision_lambda.function_arn,
                  description="Decision Engine Lambda ARN")
        
        CfnOutput(self, "S3RemediationLambdaArn",
                  value=s3_remediation_lambda.function_arn,
                  description="S3 remediation Lambda ARN")
        
        CfnOutput(self, "IAMRemediationLambdaArn",
                  value=iam_remediation_lambda.function_arn,
                  description="IAM remediation Lambda ARN")
        
        CfnOutput(self, "SecurityGroupRemediationLambdaArn",
                  value=sg_remediation_lambda.function_arn,
                  description="Security Group remediation Lambda ARN")