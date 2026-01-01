"""Detection infrastructure stack."""
from aws_cdk import (
    Stack,
    Duration,
    aws_lambda as lambda_,
    aws_events as events,
    aws_events_targets as targets,
    aws_iam as iam,
    aws_s3 as s3,
    CfnOutput,
)
from constructs import Construct
import os


class DetectionStack(Stack):
    """Detection infrastructure for Nebula Shield."""
    
    def __init__(self, scope: Construct, construct_id: str, 
                 core_stack, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        
        # Get context
        environment = self.node.try_get_context("environment") or "dev"
        retention_days = int(self.node.try_get_context("retention_days") or 30)
        
        # Import resources from CoreStack
        findings_table = core_stack.findings_table
        event_bus = core_stack.event_bus
        detection_role = core_stack.detection_role
        
        # Create S3 bucket for Lambda code (simulation only - would be CodePipeline in production)
        code_bucket = s3.Bucket(
            self, "LambdaCodeBucket",
            versioned=True,
            encryption=s3.BucketEncryption.S3_MANAGED,
            removal_policy=core_stack.removal_policy,
            lifecycle_rules=[
                s3.LifecycleRule(
                    expiration=Duration.days(retention_days * 2),
                    noncurrent_version_expiration=Duration.days(retention_days)
                )
            ]
        )
        
        # Create Detection Lambda function
        detection_lambda = lambda_.Function(
            self, "DetectionLambda",
            runtime=lambda_.Runtime.PYTHON_3_11,
            handler="handler.lambda_handler",
            code=lambda_.Code.from_asset("src/detection"),
            timeout=Duration.seconds(30),
            memory_size=256,
            role=detection_role,
            environment={
                "FINDINGS_TABLE_NAME": findings_table.table_name,
                "EVENT_BUS_NAME": event_bus.event_bus_name,
                "ENVIRONMENT": environment,
                "POWERTOOLS_SERVICE_NAME": "nebula-shield-detection",
                "LOG_LEVEL": "INFO"
            },
            tracing=lambda_.Tracing.ACTIVE,
        )
        
        # Grant additional permissions
        findings_table.grant_read_write_data(detection_lambda)
        event_bus.grant_put_events_to(detection_lambda)
        
        # Create EventBridge rules for CloudTrail events
        # Rule for S3 events
        s3_rule = events.Rule(
            self, "S3DetectionRule",
            event_bus=event_bus,
            event_pattern=events.EventPattern(
                source=["aws.s3"],
                detail_type=["AWS API Call via CloudTrail"],
                detail={
                    "eventSource": ["s3.amazonaws.com"],
                    "eventName": [
                        "PutBucketPolicy",
                        "PutBucketAcl",
                        "DeletePublicAccessBlock",
                        "PutBucketWebsite",
                        "PutBucketCors"
                    ]
                }
            )
        )
        s3_rule.add_target(targets.LambdaFunction(detection_lambda))
        
        # Rule for IAM events
        iam_rule = events.Rule(
            self, "IAMDetectionRule",
            event_bus=event_bus,
            event_pattern=events.EventPattern(
                source=["aws.iam"],
                detail_type=["AWS API Call via CloudTrail"],
                detail={
                    "eventSource": ["iam.amazonaws.com"],
                    "eventName": [
                        "AttachRolePolicy",
                        "PutRolePolicy",
                        "PutUserPolicy",
                        "CreatePolicy",
                        "CreatePolicyVersion"
                    ]
                }
            )
        )
        iam_rule.add_target(targets.LambdaFunction(detection_lambda))
        
        # Rule for EC2 Security Group events
        sg_rule = events.Rule(
            self, "SecurityGroupDetectionRule",
            event_bus=event_bus,
            event_pattern=events.EventPattern(
                source=["aws.ec2"],
                detail_type=["AWS API Call via CloudTrail"],
                detail={
                    "eventSource": ["ec2.amazonaws.com"],
                    "eventName": [
                        "AuthorizeSecurityGroupIngress",
                        "AuthorizeSecurityGroupEgress",
                        "RevokeSecurityGroupIngress",
                        "RevokeSecurityGroupEgress"
                    ]
                }
            )
        )
        sg_rule.add_target(targets.LambdaFunction(detection_lambda))
        
        # Rule for AWS Config compliance events
        config_rule = events.Rule(
            self, "ConfigDetectionRule",
            event_bus=event_bus,
            event_pattern=events.EventPattern(
                source=["aws.config"],
                detail_type=["Config Rules Compliance Change"],
                detail={
                    "messageType": ["ComplianceChangeNotification"]
                }
            )
        )
        config_rule.add_target(targets.LambdaFunction(detection_lambda))
        
        # Create CloudWatch Events rule to forward CloudTrail to our custom bus
        # This rule forwards relevant CloudTrail events to our custom bus
        cloudtrail_forward_rule = events.Rule(
            self, "CloudTrailForwardRule",
            event_pattern=events.EventPattern(
                source=["aws.s3", "aws.iam", "aws.ec2", "aws.config"],
                detail_type=["AWS API Call via CloudTrail"]
            )
        )
        cloudtrail_forward_rule.add_target(
            targets.EventBus(
                event_bus,
                event=events.RuleTargetInput.from_event_path("$.detail")
            )
        )
        
        # Create scheduled rule for periodic drift detection (safety net)
        drift_detection_rule = events.Rule(
            self, "DriftDetectionRule",
            schedule=events.Schedule.rate(Duration.hours(24)),  # Daily
            event_bus=event_bus,
            event_pattern=events.EventPattern(
                source=["nebula.shield"],
                detail_type=["ScheduledDriftDetection"]
            )
        )
        drift_detection_rule.add_target(targets.LambdaFunction(detection_lambda))
        
        # Store references
        self.detection_lambda = detection_lambda
        self.code_bucket = code_bucket
        
        # Outputs
        CfnOutput(self, "DetectionLambdaArn",
                  value=detection_lambda.function_arn,
                  description="Detection Lambda ARN")
        
        CfnOutput(self, "CodeBucketName",
                  value=code_bucket.bucket_name,
                  description="S3 bucket for Lambda code")