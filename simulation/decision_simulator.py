"""Enhanced simulation with Decision Engine integration."""

import json
import sys
from pathlib import Path
from typing import Dict, Any, List
from datetime import datetime

# Ensure project root is in sys.path BEFORE any src imports
PROJECT_ROOT = Path(__file__).parent.parent.resolve()
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.decision_engine.state_machine import DecisionEngine
from src.decision_engine.rule_evaluator import RuleEvaluator
from src.decision_engine.handler import local_test
from simulation.event_simulator import EventSimulator


class DecisionSimulator:
    """Simulates the full detection → decision → remediation pipeline."""

    def __init__(self, mode: str = "dry_run"):
        self.mode = mode
        self.event_simulator = EventSimulator(mode=mode)
        self.decision_engine = DecisionEngine({
            "dry_run_mode": mode == "dry_run",
            "enabled_rules": [
                "S3-PUBLIC-ACCESS-001",
                "IAM-OVER-PERMISSIVE-001",
                "SG-OPEN-PORTS-001"
            ]
        })
        self.rule_evaluator = RuleEvaluator()

        print(f"Initialized Decision Simulator in {mode} mode")

    def run_full_pipeline(self, events_dir: str = "events/cloudtrail") -> List[Dict[str, Any]]:
        """Run the full pipeline: detection → decision → remediation planning."""
        print("\n🚀 Running Full Nebula Shield Pipeline")
        print("=" * 60)

        # Step 1: Run detection (from EventSimulator)
        print("\n🔍 Phase 1: Detection")
        print("-" * 30)
        findings = self.event_simulator.run_simulation(events_dir)

        if not findings:
            print("No findings detected, pipeline complete.")
            return []

        # Step 2: Run decision engine
        print("\n🧠 Phase 2: Decision Engine")
        print("-" * 30)
        decision_results = []

        for finding_data in findings:
            print(f"\nProcessing finding: {finding_data.get('title', 'Unknown')}")
            print(f" Rule: {finding_data.get('rule_id')}")
            resource = finding_data.get('SK', '').replace('RESOURCE#', '')
            print(f" Resource: {resource}")

            # Run decision engine via local_test handler
            result = local_test(finding_data)

            decision_results.append(result)

            # Print decision
            if result.get("success"):
                print(f" ✅ Decision: {result.get('message')}")
                print(f" State: {result.get('current_state')} → {result.get('proposed_state')}")

                if "plan" in result:
                    plan = result["plan"]
                    print(f" 📋 Plan: {plan.get('action', 'Unknown')}")
                    print(f" Mode: {plan.get('execution_mode', 'Unknown')}")
            else:
                print(f" ❌ Decision failed: {result.get('message')}")

        # Step 3: Generate summary
        print("\n📊 Phase 3: Pipeline Summary")
        print("-" * 30)

        total_findings = len(findings)
        auto_remediated = sum(
            1 for r in decision_results if r.get("proposed_state") == "AUTO_REMEDIATE"
        )
        pending_approval = sum(
            1 for r in decision_results if r.get("proposed_state") == "PENDING_APPROVAL"
        )
        plans_generated = sum(1 for r in decision_results if "plan" in r)

        print(f"Total Findings: {total_findings}")
        print(f"Auto-Remediate: {auto_remediated}")
        print(f"Pending Approval: {pending_approval}")
        print(f"Remediation Plans: {plans_generated}")
        print(f"Execution Mode: {self.mode.upper()}")

        # Correctly indented output dictionary
        output = {
            "timestamp": datetime.utcnow().isoformat(),
            "mode": self.mode,
            "findings": findings,
            "decisions": decision_results,
            "summary": {
                "total_findings": total_findings,
                "auto_remediated": auto_remediated,
                "pending_approval": pending_approval,
                "plans_generated": plans_generated
            }
        }

        output_file = f"pipeline_results_{self.mode}.json"
        with open(output_file, 'w') as f:
            json.dump(output, f, indent=2, default=str)

        print(f"\n💾 Full pipeline results saved to: {output_file}")

        return decision_results

    def test_specific_scenario(self, scenario_name: str, finding_data: Dict[str, Any]) -> Dict[str, Any]:
        """Test a specific scenario with custom finding data."""
        print(f"\n🧪 Testing Scenario: {scenario_name}")
        print("-" * 40)

        from src.models.finding import Finding

        finding = Finding(
            resource_arn=finding_data["resource_arn"],
            resource_type=finding_data["resource_type"],
            account_id=finding_data["account_id"],
            region=finding_data["region"],
            rule_id=finding_data["rule_id"],
            title=finding_data["title"],
            description=finding_data["description"],
            severity=finding_data["severity"]
        )

        result = self.decision_engine.evaluate_finding(finding)

        print(f"Finding: {finding.title}")
        print(f"Resource: {finding.resource_arn}")
        print(f"Severity: {finding.severity.value}")
        print(f"Current State: {finding.state.value}")
        print(f"Proposed State: {result.new_state.value}")
        print(f"Success: {result.success}")
        print(f"Message: {result.message}")

        if result.plan:
            print(f"\n📋 Remediation Plan:")
            intent_log = result.plan.get_intent_log()
            print(f" Action: {intent_log['action']}")
            print(f" Execution Mode: {intent_log['execution_mode']}")
            print(f" API Calls: {len(intent_log['proposed_api_calls'])}")

            for i, call in enumerate(intent_log['proposed_api_calls'], 1):
                print(f" {i}. {call['service']}.{call['operation']}")

        return {
            "scenario": scenario_name,
            "finding": finding.to_dynamodb_item(),
            "result": {
                "success": result.success,
                "new_state": result.new_state.value,
                "message": result.message,
                "plan": result.plan.get_intent_log() if result.plan else None
            }
        }


def main():
    """Main entry point for decision simulation."""
    import argparse

    parser = argparse.ArgumentParser(description="Nebula Shield Decision Simulator")
    parser.add_argument(
        "--mode",
        choices=["dry_run", "execute"],
        default="dry_run",
        help="Execution mode"
    )
    parser.add_argument(
        "--scenario",
        help="Run specific scenario test (e.g., s3_public_access)"
    )

    args = parser.parse_args()

    simulator = DecisionSimulator(mode=args.mode)

    if args.scenario:
        scenarios = {
            "s3_public_access": {
                "resource_arn": "arn:aws:s3:::test-public-bucket",
                "resource_type": "AWS::S3::Bucket",
                "account_id": "123456789012",
                "region": "us-east-1",
                "rule_id": "S3-PUBLIC-ACCESS-001",
                "title": "S3 Bucket has Public Access",
                "description": "Bucket policy allows public GetObject access",
                "severity": "HIGH"
            },
            "iam_over_permissive": {
                "resource_arn": "arn:aws:iam::123456789012:role/AdminRole",
                "resource_type": "AWS::IAM::Role",
                "account_id": "123456789012",
                "region": "global",
                "rule_id": "IAM-OVER-PERMISSIVE-001",
                "title": "IAM Role has Overly Permissive Policy",
                "description": "Role has AdministratorAccess policy attached",
                "severity": "CRITICAL"
            },
            "sg_open_ssh": {
                "resource_arn": "arn:aws:ec2:us-east-1:123456789012:security-group/sg-12345678",
                "resource_type": "AWS::EC2::SecurityGroup",
                "account_id": "123456789012",
                "region": "us-east-1",
                "rule_id": "SG-OPEN-PORTS-001",
                "title": "Security Group Open to Internet on SSH",
                "description": "Security group allows SSH (port 22) from 0.0.0.0/0",
                "severity": "HIGH"
            }
        }

        if args.scenario in scenarios:
            result = simulator.test_specific_scenario(args.scenario, scenarios[args.scenario])
            output_file = f"scenario_{args.scenario}.json"
            with open(output_file, 'w') as f:
                json.dump(result, f, indent=2, default=str)
            print(f"\n💾 Scenario result saved to: {output_file}")
        else:
            print(f"Unknown scenario: {args.scenario}")
            print(f"Available scenarios: {', '.join(scenarios.keys())}")
    else:
        simulator.run_full_pipeline()


if __name__ == "__main__":
    main()
