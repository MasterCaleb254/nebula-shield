"""Core Nebula Shield infrastructure stack."""
from aws_cdk import (
    Stack,
    RemovalPolicy,
    aws_dynamodb as dynamodb,
    aws_events as events,
    aws_iam as iam,
    aws_kms as kms,
    CfnOutput,
    Duration,
)
from constructs import Construct


class CoreStack(Stack):
    """Core Nebula Shield stack with shared resources."""
    
    def __init__(self, scope: Construct, construct_id: str, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        
        # Get context values
        environment = self.node.try_get_context("environment") or "dev"
        retention_days = int(self.node.try_get_context("retention_days") or 30)
        
        # Create KMS key for encryption
        kms_key = kms.Key(
            self, "NebulaShieldKmsKey",
            description="KMS key for Nebula Shield encryption",
            enable_key_rotation=True,
            removal_policy=RemovalPolicy.RETAIN,
            alias=f"alias/nebulashield/{environment}",
        )
        
        # Create DynamoDB table for findings (audit log)
        findings_table = dynamodb.Table(
            self, "FindingsTable",
            partition_key=dynamodb.Attribute(
                name="PK",
                type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(
                name="SK",
                type=dynamodb.AttributeType.STRING
            ),
            billing_mode=dynamodb.BillingMode.PAY_PER_REQUEST,
            encryption=dynamodb.TableEncryption.CUSTOMER_MANAGED,
            encryption_key=kms_key,
            point_in_time_recovery=True,
            removal_policy=RemovalPolicy.RETAIN if environment == "prod" else RemovalPolicy.DESTROY,
            stream=dynamodb.StreamViewType.NEW_IMAGE,
        )
        
        # Add Global Secondary Indexes for query patterns
        findings_table.add_global_secondary_index(
            index_name="GSI1-StateTimestamp",
            partition_key=dynamodb.Attribute(
                name="state",
                type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(
                name="detected_at",
                type=dynamodb.AttributeType.STRING
            ),
            projection_type=dynamodb.ProjectionType.INCLUDE,
            non_key_attributes=["resource_arn", "severity", "rule_id", "title"]
        )
        
        findings_table.add_global_secondary_index(
            index_name="GSI2-ResourceType",
            partition_key=dynamodb.Attribute(
                name="resource_type",
                type=dynamodb.AttributeType.STRING
            ),
            sort_key=dynamodb.Attribute(
                name="last_updated_at",
                type=dynamodb.AttributeType.STRING
            ),
            projection_type=dynamodb.ProjectionType.INCLUDE,
            non_key_attributes=["resource_arn", "state", "severity"]
        )
        
        # Create EventBridge custom bus for Nebula Shield events
        event_bus = events.EventBus(
            self, "NebulaShieldBus",
            event_bus_name=f"nebulashield-{environment}",
        )
        
        # Create IAM roles with least privilege
        # Detection role (read-only)
        detection_role = iam.Role(
            self, "DetectionRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            description="Role for Nebula Shield detection functions",
            role_name=f"nebulashield-detection-{environment}",
        )
        
        # Decision role (DynamoDB access)
        decision_role = iam.Role(
            self, "DecisionRole",
            assumed_by=iam.ServicePrincipal("lambda.amazonaws.com"),
            description="Role for Nebula Shield decision engine",
            role_name=f"nebulashield-decision-{environment}",
        )
        
        # Base Lambda execution policy
        lambda_base_policy = iam.ManagedPolicy.from_aws_managed_policy_name(
            "service-role/AWSLambdaBasicExecutionRole"
        )
        
        # Add policies to roles
        detection_role.add_managed_policy(lambda_base_policy)
        decision_role.add_managed_policy(lambda_base_policy)
        
        # DynamoDB write policy for decision role
        findings_table.grant_read_write_data(decision_role)
        
        # KMS decryption policy
        kms_key.grant_decrypt(detection_role)
        kms_key.grant_encrypt_decrypt(decision_role)
        
        # CloudWatch permissions for metrics
        detection_role.add_to_policy(
            iam.PolicyStatement(
                actions=[
                    "cloudwatch:PutMetricData",
                    "cloudwatch:GetMetricStatistics",
                    "cloudwatch:ListMetrics"
                ],
                resources=["*"],
                conditions={
                    "StringEquals": {
                        "cloudwatch:namespace": "NebulaShield"
                    }
                }
            )
        )
        
        decision_role.add_to_policy(
            iam.PolicyStatement(
                actions=[
                    "cloudwatch:PutMetricData",
                    "cloudwatch:GetMetricStatistics",
                    "cloudwatch:ListMetrics"
                ],
                resources=["*"],
                conditions={
                    "StringEquals": {
                        "cloudwatch:namespace": "NebulaShield"
                    }
                }
            )
        )
        
        # AWS Config read-only permissions for detection
        detection_role.add_to_policy(
            iam.PolicyStatement(
                actions=[
                    "config:Describe*",
                    "config:Get*",
                    "config:List*",
                    "config:SelectResourceConfig"
                ],
                resources=["*"]
            )
        )
        
        # CloudTrail read-only permissions
        detection_role.add_to_policy(
            iam.PolicyStatement(
                actions=[
                    "cloudtrail:LookupEvents",
                    "cloudtrail:GetEventSelectors",
                    "cloudtrail:DescribeTrails"
                ],
                resources=["*"]
            )
        )
        
        # S3 read-only permissions for detection
        detection_role.add_to_policy(
            iam.PolicyStatement(
                actions=[
                    "s3:GetBucketPolicy",
                    "s3:GetBucketPolicyStatus",
                    "s3:GetBucketAcl",
                    "s3:GetBucketPublicAccessBlock",
                    "s3:GetBucketTagging"
                ],
                resources=["arn:aws:s3:::*"]
            )
        )
        
        # IAM read-only permissions
        detection_role.add_to_policy(
            iam.PolicyStatement(
                actions=[
                    "iam:GetRole",
                    "iam:GetRolePolicy",
                    "iam:ListRolePolicies",
                    "iam:ListAttachedRolePolicies",
                    "iam:GetPolicy",
                    "iam:GetPolicyVersion",
                    "iam:ListEntitiesForPolicy",
                    "iam:ListPolicies",
                    "iam:GetUser",
                    "iam:GetUserPolicy",
                    "iam:ListUserPolicies",
                    "iam:ListAttachedUserPolicies",
                    "iam:ListAccessKeys",
                    "iam:GetAccessKeyLastUsed"
                ],
                resources=["*"]
            )
        )
        
        # EC2 read-only permissions for security groups
        detection_role.add_to_policy(
            iam.PolicyStatement(
                actions=[
                    "ec2:DescribeSecurityGroups",
                    "ec2:DescribeSecurityGroupRules",
                    "ec2:DescribeVpcs",
                    "ec2:DescribeSubnets"
                ],
                resources=["*"]
            )
        )
        
        # Explicit deny for write operations on detection role
        detection_role.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.DENY,
                actions=[
                    "s3:Put*",
                    "s3:Delete*",
                    "iam:*",
                    "ec2:*",
                    "dynamodb:DeleteItem",
                    "dynamodb:UpdateItem"
                ],
                resources=["*"]
            )
        )
        
        # Explicit deny for IAM permission expansion on decision role
        decision_role.add_to_policy(
            iam.PolicyStatement(
                effect=iam.Effect.DENY,
                actions=["iam:*", "organizations:*"],
                resources=["*"]
            )
        )
        
        # Store references as properties
        self.findings_table = findings_table
        self.event_bus = event_bus
        self.kms_key = kms_key
        self.detection_role = detection_role
        self.decision_role = decision_role
        
        # Outputs
        CfnOutput(self, "FindingsTableName",
                  value=findings_table.table_name,
                  description="DynamoDB findings table name")
        
        CfnOutput(self, "EventBusName",
                  value=event_bus.event_bus_name,
                  description="EventBridge bus name")
        
        CfnOutput(self, "DetectionRoleArn",
                  value=detection_role.role_arn,
                  description="Detection Lambda role ARN")
        
        CfnOutput(self, "DecisionRoleArn",
                  value=decision_role.role_arn,
                  description="Decision Engine role ARN")
        
        CfnOutput(self, "KmsKeyId",
                  value=kms_key.key_id,
                  description="KMS key ID for encryption")