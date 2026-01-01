"""Script to synthesize CloudFormation templates."""
import subprocess
import json
import sys
import os
from pathlib import Path

def synthesize_stacks():
    """Synthesize all CDK stacks."""
    print("🔨 Synthesizing Nebula Shield CloudFormation templates...")
    
    # Change to infra directory
    infra_dir = Path(__file__).parent
    os.chdir(infra_dir)
    
    # Run CDK synth
    try:
        result = subprocess.run(
            ["cdk", "synth", "--all"],
            capture_output=True,
            text=True,
            check=True
        )
        
        print("✅ Synthesis completed successfully!")
        
        # Parse and display stack outputs
        output_dir = Path("cdk.out")
        if output_dir.exists():
            print(f"\n📁 Generated CloudFormation templates in: {output_dir}")
            
            # List all generated templates
            templates = list(output_dir.glob("*.template.json"))
            for template in templates:
                print(f"  - {template.name}")
        
        return True
        
    except subprocess.CalledProcessError as e:
        print(f"❌ Synthesis failed with error: {e.stderr}")
        return False
    except FileNotFoundError:
        print("❌ CDK CLI not found. Please install AWS CDK: npm install -g aws-cdk")
        return False

def validate_iam_policies():
    """Validate IAM policies for least privilege."""
    print("\n🔒 Validating IAM policies for least privilege...")
    
    # Load CDK output
    output_dir = Path("cdk.out")
    
    for template_file in output_dir.glob("*.template.json"):
        with open(template_file, 'r') as f:
            template = json.load(f)
        
        # Check for IAM resources
        resources = template.get("Resources", {})
        
        for resource_name, resource in resources.items():
            if resource.get("Type") == "AWS::IAM::Role":
                print(f"  Checking IAM Role: {resource_name}")
                
                # Check for permission boundaries
                properties = resource.get("Properties", {})
                permissions_boundary = properties.get("PermissionsBoundary")
                
                if not permissions_boundary:
                    print(f"    ⚠️  No permission boundary set for {resource_name}")
                
                # Check policies
                policies = properties.get("Policies", [])
                for policy in policies:
                    policy_doc = policy.get("PolicyDocument", {})
                    statements = policy_doc.get("Statement", [])
                    
                    for stmt in statements:
                        if stmt.get("Effect") == "Allow":
                            actions = stmt.get("Action", [])
                            resources_list = stmt.get("Resource", [])
                            
                            # Check for wildcards
                            if "*" in str(actions) or "*" in str(resources_list):
                                print(f"    ⚠️  Wildcard permissions found in {resource_name}")
    
    print("✅ IAM policy validation completed")

def generate_deployment_guide():
    """Generate deployment guide from synthesized templates."""
    print("\n📋 Generating deployment guide...")
    
    guide = """
# Nebula Shield Deployment Guide

## Prerequisites
1. AWS Account with appropriate permissions
2. AWS CDK installed (`npm install -g aws-cdk`)
3. Python 3.9+ and virtual environment
4. Git repository cloned

## Deployment Order (Safe Rollout)
1. **Core Stack**: DynamoDB, EventBus, IAM roles
2. **Detection Stack**: Event rules, Detection Lambda (observe-only)
3. **Observability Stack**: Dashboards, alarms, notifications
4. **Remediation Stack**: Decision Engine, Remediation Lambdas (dry-run mode)

## Step-by-Step Deployment

### 1. Set up environment
```bash
cd nebula-shield/infra
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\\Scripts\\activate
pip install -r requirements.txt