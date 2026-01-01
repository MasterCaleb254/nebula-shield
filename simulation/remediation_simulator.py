"""Comprehensive remediation simulation."""
import json
import sys
from pathlib import Path
from typing import Dict, Any, List
from datetime import datetime

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.remediation.orchestrator import RemediationOrchestrator
from src.remediation.handler import local_test
from simulation.aws_mock_enhanced import MockAWSClientsEnhanced
from src.models.finding import Finding, FindingSeverity, ResourceType

class RemediationSimulator:
    """Simulates remediation execution with different scenarios."""
    
    def __init__(self, mode: str = "dry_run"):
        self.mode = mode
        self.dry_run = mode == "dry_run"
        self.aws_client = MockAWSClientsEnhanced(mode=mode)
        self.orchestrator = RemediationOrchestrator(self.aws_client, self.dry_run)
        
        print(f"Initialized Remediation Simulator in {mode} mode")
    
    def run_scenario(self, scenario_name: str, findings: List[Finding]) -> Dict[str, Any]:
        """Run a remediation scenario."""
        print(f"\n🧪 Running Scenario: {scenario_name}")
        print("=" * 50)
        
        # Run batch remediation
        results = self.orchestrator.batch_remediate(findings)
        
        # Print summary
        print(f"Total Findings: {results['total']}")
        print(f"Successful: {results['successful']}")
        print(f"Failed: {results['failed']}")
        print(f"Rolled Back: {results['rolled_back']}")
        print(f"No Remediation Found: {results['no_remediator']}")
        
        # Print AWS intent logs
        print(f"\n🔧 AWS API Intent Logs ({self.mode} mode):")
        print("-" * 30)
        
        logs = self.aws_client.get_logs()
        if logs:
            for i, log in enumerate(logs, 1):
                print(f"{i}. {log['service']}.{log['operation']}")
                print(f"   Parameters: {json.dumps(log['parameters'], indent=2, default=str)}")
        else:
            print("No AWS API calls were triggered")
        
        return results
    
    def create_s3_public_access_scenario(self) -> List[Finding]:
        """Create S3 public access scenario."""
        findings = []
        
        for i in range(1, 4):
            finding = Finding(
                resource_arn=f"arn:aws:s3:::test-public-bucket-{i}",
                resource_type=ResourceType.S3_BUCKET,
                account_id="123456789012",
                region="us-east-1",
                rule_id="S3-PUBLIC-ACCESS-001",
                title=f"S3 Bucket {i} has Public Access",
                description="Bucket policy allows public GetObject access",
                severity=FindingSeverity.HIGH,
                current_config={
                    "public_access_block": {
                        "BlockPublicAcls": False,
                        "IgnorePublicAcls": False,
                        "BlockPublicPolicy": False,
                        "RestrictPublicBuckets": False
                    }
                }
            )
            findings.append(finding)
        
        return findings
    
    def create_mixed_scenario(self) -> List[Finding]:
        """Create mixed remediation scenario."""
        findings = []
        
        # S3 finding
        s3_finding = Finding(
            resource_arn="arn:aws:s3:::mixed-scenario-bucket",
            resource_type=ResourceType.S3_BUCKET,
            account_id="123456789012",
            region="us-east-1",
            rule_id="S3-PUBLIC-ACCESS-001",
            title="S3 Bucket with Public Access",
            description="Public bucket in mixed scenario",
            severity=FindingSeverity.HIGH,
            current_config={
                "public_access_block": {
                    "BlockPublicAcls": False,
                    "IgnorePublicAcls": False,
                    "BlockPublicPolicy": False,
                    "RestrictPublicBuckets": False
                }
            }
        )
        findings.append(s3_finding)
        
        # IAM finding
        iam_finding = Finding(
            resource_arn="arn:aws:iam::123456789012:role/MixedScenarioRole",
            resource_type=ResourceType.IAM_ROLE,
            account_id="123456789012",
            region="us-east-1",
            rule_id="IAM-OVER-PERMISSIVE-001",
            title="IAM Role with Overly Permissive Policy",
            description="Role has AdministratorAccess policy",
            severity=FindingSeverity.CRITICAL,
            current_config={
                "attached_policies": [
                    {
                        "policy_name": "AdministratorAccess",
                        "policy_arn": "arn:aws:iam::aws:policy/AdministratorAccess"
                    }
                ]
            }
        )
        findings.append(iam_finding)
        
        # Security Group finding
        sg_finding = Finding(
            resource_arn="arn:aws:ec2:us-east-1:123456789012:security-group/sg-mixed123",
            resource_type=ResourceType.SECURITY_GROUP,
            account_id="123456789012",
            region="us-east-1",
            rule_id="SG-OPEN-PORTS-001",
            title="Security Group Open to Internet",
            description="Allows SSH from 0.0.0.0/0",
            severity=FindingSeverity.HIGH,
            current_config={
                "ingress_rules": [
                    {
                        "ip_protocol": "tcp",
                        "from_port": 22,
                        "to_port": 22,
                        "ip_ranges": [{"cidr_ip": "0.0.0.0/0"}]
                    }
                ]
            }
        )
        findings.append(sg_finding)
        
        return findings
    
    def create_failure_scenario(self) -> List[Finding]:
        """Create scenario with remediation failures."""
        findings = []
        
        # Finding with no remediator (unknown resource type)
        unknown_finding = Finding(
            resource_arn="arn:aws:unknown::123456789012:resource/unknown",
            resource_type="AWS::Unknown::Resource",  # Unknown type
            account_id="123456789012",
            region="us-east-1",
            rule_id="UNKNOWN-RULE-001",
            title="Unknown Resource Type",
            description="This finding has no remediator",
            severity=FindingSeverity.MEDIUM
        )
        findings.append(unknown_finding)
        
        return findings
    
    def run_all_scenarios(self):
        """Run all predefined scenarios."""
        print("\n🚀 Starting Comprehensive Remediation Simulation")
        print("=" * 60)
        
        all_results = {
            "timestamp": datetime.utcnow().isoformat(),
            "mode": self.mode,
            "scenarios": {}
        }
        
        # Scenario 1: S3 Public Access
        print("\n📁 Scenario 1: S3 Public Access Remediation")
        s3_findings = self.create_s3_public_access_scenario()
        s3_results = self.run_scenario("S3 Public Access", s3_findings)
        all_results["scenarios"]["s3_public_access"] = s3_results
        
        # Clear AWS logs for next scenario
        self.aws_client.clear_logs()
        
        # Scenario 2: Mixed Resources
        print("\n🔀 Scenario 2: Mixed Resource Remediation")
        mixed_findings = self.create_mixed_scenario()
        mixed_results = self.run_scenario("Mixed Resources", mixed_findings)
        all_results["scenarios"]["mixed_resources"] = mixed_results
        
        # Clear AWS logs for next scenario
        self.aws_client.clear_logs()
        
        # Scenario 3: Failure Cases
        print("\n⚠️  Scenario 3: Failure Cases")
        failure_findings = self.create_failure_scenario()
        failure_results = self.run_scenario("Failure Cases", failure_findings)
        all_results["scenarios"]["failure_cases"] = failure_results
        
        # Save results
        output_file = f"remediation_simulation_{self.mode}.json"
        with open(output_file, 'w') as f:
            json.dump(all_results, f, indent=2, default=str)
        
        print(f"\n💾 All simulation results saved to: {output_file}")
        
        return all_results

def main():
    """Main entry point for remediation simulation."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Nebula Shield Remediation Simulator")
    parser.add_argument("--mode", choices=["dry_run", "execute"], 
                       default="dry_run", help="Execution mode")
    parser.add_argument("--scenario", 
                       choices=["s3", "mixed", "failure", "all"],
                       default="all", help="Scenario to run")
    
    args = parser.parse_args()
    
    simulator = RemediationSimulator(mode=args.mode)
    
    if args.scenario == "s3":
        findings = simulator.create_s3_public_access_scenario()
        simulator.run_scenario("S3 Public Access", findings)
    elif args.scenario == "mixed":
        findings = simulator.create_mixed_scenario()
        simulator.run_scenario("Mixed Resources", findings)
    elif args.scenario == "failure":
        findings = simulator.create_failure_scenario()
        simulator.run_scenario("Failure Cases", findings)
    else:
        simulator.run_all_scenarios()

if __name__ == "__main__":
    main()