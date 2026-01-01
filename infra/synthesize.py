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
```

### 2. Configure context
Update `cdk.json` context values:
- `account`: Your AWS account ID
- `region`: Deployment region
- `environment`: dev/staging/prod
- `dry_run_mode`: true/false
- `enabled_rules`: List of rules to enable

### 3. Bootstrap CDK (first time only)
```bash
cdk bootstrap aws://ACCOUNT-NUMBER/REGION
```

### 4. Deploy in order
```bash
# Deploy Core Stack
cdk deploy NebulaShieldCore-dev --require-approval never

# Deploy Detection Stack
cdk deploy NebulaShieldDetection-dev --require-approval never

# Deploy Observability Stack
cdk deploy NebulaShieldObservability-dev --require-approval never

# Deploy Remediation Stack (initially in dry-run mode)
cdk deploy NebulaShieldRemediation-dev --require-approval never
```

## Safety Controls

### Dry Run Mode
By default, Nebula Shield runs in dry-run mode. This means:
- Findings are detected and logged
- Remediation plans are created
- No actual AWS resources are modified
- All intended API calls are logged

### Enable Auto-Remediation
To enable auto-remediation:
1. Update `cdk.json`: `"dry_run_mode": false`
2. Deploy with: `cdk deploy NebulaShieldRemediation-dev`
3. Monitor closely in CloudWatch

### Approval Workflow
For high-risk findings:
- Findings go to PENDING_APPROVAL state
- Manually approve via CLI/Console
- Remediation executes after approval

## Monitoring
- **CloudWatch Dashboard**: Shows findings, remediations, performance
- **SNS Topics**: High severity and operational alerts
- **CloudWatch Logs**: Detailed execution logs with correlation IDs

## Rollback Procedure
If issues occur:
1. Set `dry_run_mode` to true in `cdk.json`
2. Redeploy Remediation Stack
3. Nebula Shield will stop making changes
4. Review logs and fix configuration

## Security Notes
- IAM roles follow least privilege principle
- No permission expansion during remediation
- Audit logs are immutable
- Encryption at rest with KMS
"""

    with open("DEPLOYMENT_GUIDE.md", "w", encoding="utf-8") as f:
        f.write(guide)
    
    print("✅ Deployment guide generated: DEPLOYMENT_GUIDE.md")

if __name__ == "__main__":
    print("🚀 Nebula Shield CDK Synthesis Tool")
    print("=" * 50)
    
    if synthesize_stacks():
        validate_iam_policies()
        generate_deployment_guide()
        
        print("\n" + "=" * 50)
        print("🎉 Synthesis completed successfully!")
        print("\nNext steps:")
        print("1. Review CloudFormation templates in cdk.out/")
        print("2. Check deployment guide: DEPLOYMENT_GUIDE.md")
        print("3. Deploy to AWS when ready")
    else:
        sys.exit(1)