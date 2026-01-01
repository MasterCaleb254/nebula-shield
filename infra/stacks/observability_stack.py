"""Observability infrastructure stack."""
from aws_cdk import (
    Stack,
    Duration,
    aws_cloudwatch as cloudwatch,
    aws_cloudwatch_actions as cloudwatch_actions,
    aws_sns as sns,
    aws_sns_subscriptions as subscriptions,
    aws_iam as iam,
    CfnOutput,
    RemovalPolicy,
)
from constructs import Construct


class ObservabilityStack(Stack):
    """Observability infrastructure for Nebula Shield."""
    
    def __init__(self, scope: Construct, construct_id: str,
                 core_stack, detection_stack, remediation_stack, **kwargs) -> None:
        super().__init__(scope, construct_id, **kwargs)
        
        # Get context
        environment = self.node.try_get_context("environment") or "dev"
        slack_webhook = self.node.try_get_context("notification_slack_webhook") or ""
        teams_webhook = self.node.try_get_context("notification_teams_webhook") or ""
        
        # Import resources
        findings_table = core_stack.findings_table
        detection_lambda = detection_stack.detection_lambda
        decision_lambda = remediation_stack.decision_lambda
        
        # Create SNS topics for alerts
        high_severity_topic = sns.Topic(
            self, "HighSeverityAlertsTopic",
            display_name=f"nebulashield-high-severity-{environment}",
            topic_name=f"nebulashield-high-severity-{environment}"
        )
        
        operational_alerts_topic = sns.Topic(
            self, "OperationalAlertsTopic",
            display_name=f"nebulashield-operational-{environment}",
            topic_name=f"nebulashield-operational-{environment}"
        )
        
        # Create CloudWatch dashboard
        dashboard = cloudwatch.Dashboard(
            self, "NebulaShieldDashboard",
            dashboard_name=f"nebula-shield-{environment}",
            period_override=cloudwatch.PeriodOverride.AUTO
        )
        
        # Create CloudWatch metrics for findings
        findings_namespace = "NebulaShield/Findings"
        
        # Metric for findings by severity
        findings_severity_metric = cloudwatch.Metric(
            namespace=findings_namespace,
            metric_name="FindingsBySeverity",
            dimensions_map={"Severity": "SEVERITY", "Environment": environment},
            statistic="Sum",
            period=Duration.hours(1)
        )
        
        # Metric for findings by state
        findings_state_metric = cloudwatch.Metric(
            namespace=findings_namespace,
            metric_name="FindingsByState",
            dimensions_map={"State": "STATE", "Environment": environment},
            statistic="Sum",
            period=Duration.hours(1)
        )
        
        # Metric for remediation success rate
        remediation_success_metric = cloudwatch.Metric(
            namespace="NebulaShield/Remediation",
            metric_name="SuccessRate",
            dimensions_map={"Environment": environment},
            statistic="Average",
            period=Duration.hours(1)
        )
        
        # Create CloudWatch alarms
        # Alarm for high number of critical findings
        critical_findings_alarm = cloudwatch.Alarm(
            self, "CriticalFindingsAlarm",
            metric=cloudwatch.Metric(
                namespace=findings_namespace,
                metric_name="FindingsBySeverity",
                dimensions_map={"Severity": "CRITICAL", "Environment": environment},
                statistic="Sum",
                period=Duration.minutes(5)
            ),
            threshold=1,
            evaluation_periods=1,
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
            alarm_description="Alarm when critical findings are detected"
        )
        
        # Alarm for remediation failure rate
        remediation_failure_alarm = cloudwatch.Alarm(
            self, "RemediationFailureAlarm",
            metric=cloudwatch.Metric(
                namespace="NebulaShield/Remediation",
                metric_name="FailureRate",
                dimensions_map={"Environment": environment},
                statistic="Average",
                period=Duration.minutes(5)
            ),
            threshold=0.1,  # 10% failure rate
            evaluation_periods=3,
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
            alarm_description="Alarm when remediation failure rate exceeds 10%"
        )
        
        # Alarm for Lambda errors
        lambda_error_alarm = cloudwatch.Alarm(
            self, "DetectionLambdaErrorAlarm",
            metric=detection_lambda.metric_errors(
                period=Duration.minutes(5)
            ),
            threshold=1,
            evaluation_periods=2,
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
            alarm_description="Alarm when Detection Lambda has errors"
        )
        
        # Alarm for decision engine latency
        decision_latency_alarm = cloudwatch.Alarm(
            self, "DecisionEngineLatencyAlarm",
            metric=decision_lambda.metric_duration(
                period=Duration.minutes(5)
            ),
            threshold=Duration.seconds(10).to_milliseconds(),
            evaluation_periods=3,
            comparison_operator=cloudwatch.ComparisonOperator.GREATER_THAN_THRESHOLD,
            alarm_description="Alarm when Decision Engine latency exceeds 10 seconds"
        )
        
        # Add actions to alarms
        critical_findings_alarm.add_alarm_action(
            cloudwatch_actions.SnsAction(high_severity_topic)
        )
        
        remediation_failure_alarm.add_alarm_action(
            cloudwatch_actions.SnsAction(operational_alerts_topic)
        )
        
        lambda_error_alarm.add_alarm_action(
            cloudwatch_actions.SnsAction(operational_alerts_topic)
        )
        
        decision_latency_alarm.add_alarm_action(
            cloudwatch_actions.SnsAction(operational_alerts_topic)
        )
        
        # Add OK actions
        critical_findings_alarm.add_ok_action(
            cloudwatch_actions.SnsAction(high_severity_topic)
        )
        
        # Create CloudWatch log groups for structured logging
        log_retention = cloudwatch.RetentionDays.ONE_MONTH
        
        # Add widgets to dashboard
        dashboard.add_widgets(
            cloudwatch.GraphWidget(
                title="Findings by Severity",
                left=[
                    cloudwatch.Metric(
                        namespace=findings_namespace,
                        metric_name="FindingsBySeverity",
                        dimensions_map={"Severity": "CRITICAL", "Environment": environment}
                    ).with_color("#ff0000"),
                    cloudwatch.Metric(
                        namespace=findings_namespace,
                        metric_name="FindingsBySeverity",
                        dimensions_map={"Severity": "HIGH", "Environment": environment}
                    ).with_color("#ff9900"),
                    cloudwatch.Metric(
                        namespace=findings_namespace,
                        metric_name="FindingsBySeverity",
                        dimensions_map={"Severity": "MEDIUM", "Environment": environment}
                    ).with_color("#ffff00"),
                    cloudwatch.Metric(
                        namespace=findings_namespace,
                        metric_name="FindingsBySeverity",
                        dimensions_map={"Severity": "LOW", "Environment": environment}
                    ).with_color("#00ff00"),
                ],
                width=24,
                height=6
            ),
            
            cloudwatch.GraphWidget(
                title="Findings by State",
                left=[
                    cloudwatch.Metric(
                        namespace=findings_namespace,
                        metric_name="FindingsByState",
                        dimensions_map={"State": "DETECTED", "Environment": environment}
                    ).with_color("#999999"),
                    cloudwatch.Metric(
                        namespace=findings_namespace,
                        metric_name="FindingsByState",
                        dimensions_map={"State": "AUTO_REMEDIATE", "Environment": environment}
                    ).with_color("#0066cc"),
                    cloudwatch.Metric(
                        namespace=findings_namespace,
                        metric_name="FindingsByState",
                        dimensions_map={"State": "PENDING_APPROVAL", "Environment": environment}
                    ).with_color("#ff9900"),
                    cloudwatch.Metric(
                        namespace=findings_namespace,
                        metric_name="FindingsByState",
                        dimensions_map={"State": "REMEDIATED", "Environment": environment}
                    ).with_color("#00cc00"),
                    cloudwatch.Metric(
                        namespace=findings_namespace,
                        metric_name="FindingsByState",
                        dimensions_map={"State": "FAILED", "Environment": environment}
                    ).with_color("#cc0000"),
                ],
                width=24,
                height=6
            ),
            
            cloudwatch.SingleValueWidget(
                title="Remediation Success Rate",
                metrics=[
                    cloudwatch.Metric(
                        namespace="NebulaShield/Remediation",
                        metric_name="SuccessRate",
                        dimensions_map={"Environment": environment}
                    )
                ],
                width=12,
                height=6
            ),
            
            cloudwatch.SingleValueWidget(
                title="Average Time to Remediate",
                metrics=[
                    cloudwatch.Metric(
                        namespace="NebulaShield/Remediation",
                        metric_name="TimeToRemediate",
                        dimensions_map={"Environment": environment},
                        statistic="Average"
                    )
                ],
                width=12,
                height=6
            ),
            
            cloudwatch.GraphWidget(
                title="Lambda Performance",
                left=[
                    detection_lambda.metric_invocations(
                        label="Detection Invocations"
                    ),
                    decision_lambda.metric_invocations(
                        label="Decision Invocations"
                    ),
                ],
                right=[
                    detection_lambda.metric_duration(
                        label="Detection Duration"
                    ),
                    decision_lambda.metric_duration(
                        label="Decision Duration"
                    ),
                ],
                width=24,
                height=6
            ),
            
            cloudwatch.GraphWidget(
                title="Lambda Errors",
                left=[
                    detection_lambda.metric_errors(
                        label="Detection Errors"
                    ),
                    decision_lambda.metric_errors(
                        label="Decision Errors"
                    ),
                ],
                width=24,
                height=6
            )
        )
        
        # Create IAM role for QuickSight integration
        quicksight_role = iam.Role(
            self, "QuickSightRole",
            assumed_by=iam.ServicePrincipal("quicksight.amazonaws.com"),
            description="Role for QuickSight to access Nebula Shield data",
            role_name=f"nebulashield-quicksight-{environment}",
        )
        
        # Grant permissions to QuickSight role
        findings_table.grant_read_data(quicksight_role)
        core_stack.kms_key.grant_decrypt(quicksight_role)
        
        # Store references
        self.dashboard = dashboard
        self.high_severity_topic = high_severity_topic
        self.operational_alerts_topic = operational_alerts_topic
        self.quicksight_role = quicksight_role
        
        # Outputs
        CfnOutput(self, "DashboardUrl",
                  value=f"https://console.aws.amazon.com/cloudwatch/home?region={self.region}#dashboards:name={dashboard.dashboard_name}",
                  description="CloudWatch Dashboard URL")
        
        CfnOutput(self, "HighSeverityTopicArn",
                  value=high_severity_topic.topic_arn,
                  description="High severity alerts SNS topic ARN")
        
        CfnOutput(self, "OperationalTopicArn",
                  value=operational_alerts_topic.topic_arn,
                  description="Operational alerts SNS topic ARN")
        
        CfnOutput(self, "QuickSightRoleArn",
                  value=quicksight_role.role_arn,
                  description="QuickSight integration role ARN")