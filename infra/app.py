"""Nebula Shield CDK application."""
import os
from aws_cdk import App, Environment

from stacks.core_stack import CoreStack
from stacks.detection_stack import DetectionStack
from stacks.remediation_stack import RemediationStack
from stacks.observability_stack import ObservabilityStack

app = App()

# Get context values
account = app.node.try_get_context("account") or os.environ.get("CDK_DEFAULT_ACCOUNT", "123456789012")
region = app.node.try_get_context("region") or os.environ.get("CDK_DEFAULT_REGION", "us-east-1")
environment = app.node.try_get_context("environment") or "dev"

# Create environment object
env = Environment(account=account, region=region)

print(f"Deploying Nebula Shield to {account}/{region} in {environment} environment")

# Create stacks with dependencies
core_stack = CoreStack(
    app, f"NebulaShieldCore-{environment}",
    env=env,
    description="Core Nebula Shield infrastructure"
)

detection_stack = DetectionStack(
    app, f"NebulaShieldDetection-{environment}",
    core_stack=core_stack,
    env=env,
    description="Detection infrastructure for Nebula Shield"
)

remediation_stack = RemediationStack(
    app, f"NebulaShieldRemediation-{environment}",
    core_stack=core_stack,
    detection_stack=detection_stack,
    env=env,
    description="Remediation infrastructure for Nebula Shield"
)

observability_stack = ObservabilityStack(
    app, f"NebulaShieldObservability-{environment}",
    core_stack=core_stack,
    detection_stack=detection_stack,
    remediation_stack=remediation_stack,
    env=env,
    description="Observability infrastructure for Nebula Shield"
)

# Add tags to all resources
for stack in [core_stack, detection_stack, remediation_stack, observability_stack]:
    tags = stack.tags
    tags.set_tag("Project", "NebulaShield")
    tags.set_tag("Environment", environment)
    tags.set_tag("ManagedBy", "CDK")
    tags.set_tag("SecurityTool", "true")
    tags.set_tag("Owner", "SecurityEngineering")

app.synth()