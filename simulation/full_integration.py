"""Full system integration test from detection to remediation."""
import json
import sys
from pathlib import Path
from typing import Dict, Any, List
from datetime import datetime

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from simulation.event_simulator import EventSimulator
from simulation.decision_simulator import DecisionSimulator
from simulation.remediation_simulator import RemediationSimulator
from src.models.finding import Finding

class FullIntegrationTest:
    """Test the full Nebula Shield pipeline."""
    
    def __init__(self, mode: str = "dry_run"):
        self.mode = mode
        self.dry_run = mode == "dry_run"
        
        # Initialize all simulators
        self.event_simulator = EventSimulator(mode=mode)
        self.decision_simulator = DecisionSimulator(mode=mode)
        self.remediation_simulator = RemediationSimulator(mode=mode)
        
        print(f"🚀 Initializing Full Nebula Shield Integration Test ({mode} mode)")
    
    def run_full_pipeline(self) -> Dict[str, Any]:
        """Run the full pipeline: detection → decision → remediation."""
        print("\n" + "=" * 70)
        print("🌌 NEBULA SHIELD - FULL PIPELINE INTEGRATION TEST")
        print("=" * 70)
        
        pipeline_results = {
            "timestamp": datetime.utcnow().isoformat(),
            "mode": self.mode,
            "phases": {}
        }
        
        # Phase 1: Detection
        print("\n🔍 PHASE 1: DETECTION")
        print("-" * 40)
        
        # Simulate event processing
        findings = self.event_simulator.run_simulation()
        pipeline_results["phases"]["detection"] = {
            "findings_count": len(findings),
            "findings": findings
        }
        
        if not findings:
            print("No findings detected, pipeline complete.")
            return pipeline_results
        
        # Phase 2: Decision Engine
        print("\n🧠 PHASE 2: DECISION ENGINE")
        print("-" * 40)
        
        # Convert findings to Finding objects
        finding_objects = []
        for finding_data in findings:
            try:
                finding = Finding.from_dynamodb_item(finding_data)
                finding_objects.append(finding)
            except Exception as e:
                print(f"Error converting finding: {e}")
        
        # Run decision engine
        decision_results = []
        for finding in finding_objects:
            # Use the decision simulator's logic
            from src.decision_engine.state_machine import DecisionEngine
            from src.decision_engine.rule_evaluator import RuleEvaluator
            
            engine = DecisionEngine({
                "dry_run_mode": self.dry_run,
                "enabled_rules": ["S3-PUBLIC-ACCESS-001"]
            })
            
            result = engine.evaluate_finding(finding)
            
            decision_results.append({
                "finding_id": finding.finding_id,
                "rule_id": finding.rule_id,
                "current_state": finding.state.value,
                "proposed_state": result.new_state.value,
                "success": result.success,
                "message": result.message,
                "plan": result.plan.get_intent_log() if result.plan else None
            })
            
            print(f"  {finding.rule_id}: {finding.state.value} → {result.new_state.value}")
        
        pipeline_results["phases"]["decision"] = {
            "decisions_count": len(decision_results),
            "decisions": decision_results
        }
        
        # Phase 3: Remediation
        print("\n🔧 PHASE 3: REMEDIATION")
        print("-" * 40)
        
        # Filter findings that are ready for remediation
        findings_to_remediate = []
        for i, finding in enumerate(finding_objects):
            decision = decision_results[i]
            if decision["proposed_state"] in ["AUTO_REMEDIATE", "APPROVED"]:
                findings_to_remediate.append(finding)
        
        if findings_to_remediate:
            print(f"Remediating {len(findings_to_remediate)} findings...")
            
            # Run remediation
            remediation_results = self.remediation_simulator.orchestrator.batch_remediate(
                findings_to_remediate
            )
            
            pipeline_results["phases"]["remediation"] = remediation_results
            
            # Print remediation summary
            print(f"\n📊 Remediation Summary:")
            print(f"  Total: {remediation_results['total']}")
            print(f"  Successful: {remediation_results['successful']}")
            print(f"  Failed: {remediation_results['failed']}")
            print(f"  Rolled Back: {remediation_results['rolled_back']}")
        else:
            print("No findings ready for remediation.")
            pipeline_results["phases"]["remediation"] = {
                "message": "No findings ready for remediation"
            }
        
        # Phase 4: Audit Trail
        print("\n📝 PHASE 4: AUDIT TRAIL")
        print("-" * 40)
        
        # Simulate audit trail generation
        audit_trail = self._generate_audit_trail(pipeline_results)
        pipeline_results["phases"]["audit"] = audit_trail
        
        print(f"Generated audit trail with {len(audit_trail)} entries")
        
        # Save full pipeline results
        output_file = f"full_pipeline_{self.mode}.json"
        with open(output_file, 'w') as f:
            json.dump(pipeline_results, f, indent=2, default=str)
        
        print(f"\n💾 Full pipeline results saved to: {output_file}")
        
        # Print final summary
        print("\n" + "=" * 70)
        print("🎉 PIPELINE EXECUTION COMPLETE")
        print("=" * 70)
        
        total_findings = len(findings)
        remediated = pipeline_results["phases"].get("remediation", {}).get("successful", 0)
        
        print(f"Total Findings Processed: {total_findings}")
        print(f"Successfully Remediated: {remediated}")
        print(f"Execution Mode: {self.mode.upper()}")
        
        return pipeline_results
    
    def _generate_audit_trail(self, pipeline_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate simulated audit trail."""
        audit_entries = []
        
        # Add detection entries
        if "detection" in pipeline_results["phases"]:
            for finding in pipeline_results["phases"]["detection"].get("findings", []):
                audit_entries.append({
                    "timestamp": datetime.utcnow().isoformat(),
                    "event_type": "DETECTION",
                    "finding_id": finding.get("PK", ""),
                    "resource_arn": finding.get("SK", "").replace("RESOURCE#", ""),
                    "rule_id": finding.get("rule_id", ""),
                    "severity": finding.get("severity", ""),
                    "state": "DETECTED"
                })
        
        # Add decision entries
        if "decision" in pipeline_results["phases"]:
            for decision in pipeline_results["phases"]["decision"].get("decisions", []):
                audit_entries.append({
                    "timestamp": datetime.utcnow().isoformat(),
                    "event_type": "DECISION",
                    "finding_id": decision.get("finding_id", ""),
                    "current_state": decision.get("current_state", ""),
                    "proposed_state": decision.get("proposed_state", ""),
                    "success": decision.get("success", False),
                    "message": decision.get("message", "")
                })
        
        # Add remediation entries
        if "remediation" in pipeline_results["phases"]:
            remediation = pipeline_results["phases"]["remediation"]
            if "details" in remediation:
                for detail in remediation["details"]:
                    audit_entries.append({
                        "timestamp": datetime.utcnow().isoformat(),
                        "event_type": "REMEDIATION",
                        "finding_id": detail.get("finding_id", ""),
                        "resource_arn": detail.get("resource_arn", ""),
                        "success": detail.get("success", False),
                        "state": detail.get("state", ""),
                        "plan_id": detail.get("plan_id", "")
                    })
        
        return audit_entries

def main():
    """Main entry point for full integration test."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Nebula Shield Full Integration Test")
    parser.add_argument("--mode", choices=["dry_run", "execute"], 
                       default="dry_run", help="Execution mode")
    
    args = parser.parse_args()
    
    test = FullIntegrationTest(mode=args.mode)
    test.run_full_pipeline()

if __name__ == "__main__":
    main()