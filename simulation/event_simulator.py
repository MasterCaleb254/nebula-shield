"""Event simulation harness for local testing."""

import json
import sys
from pathlib import Path
from typing import List, Dict, Any

# =============================================================================
# Ensure project root is in sys.path BEFORE any src imports
# =============================================================================
PROJECT_ROOT = Path(__file__).parent.parent.resolve()
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Now safe to import from src
from src.models.event import SecurityEvent
from src.detection.s3_detector import S3Detector
from simulation.aws_mock import MockAWSClients


class EventSimulator:
    """Simulates event processing for local testing."""
   
    def __init__(self, mode: str = "dry_run"):
        self.mode = mode
        self.aws_client = MockAWSClients(mode=mode)
        self.detectors = {
            "s3": S3Detector(self.aws_client)
        }
   
    def process_event_file(self, event_file_path: str) -> List[Dict[str, Any]]:
        """Process an event from a file and return findings."""
        print(f"\n🔍 Processing event file: {event_file_path}")
       
        # Load event
        with open(event_file_path, 'r') as f:
            event_data = json.load(f)
       
        # Convert to SecurityEvent based on source
        source = event_data.get("source", "")
        if "aws.s3" in source:
            event = SecurityEvent.from_cloudtrail(event_data)
            print(f" Event: {event.event_name} on {event.event_source}")
           
            # Route to appropriate detector
            if "s3" in event.event_source:
                detector = self.detectors["s3"]
                findings = detector.detect_misconfigurations(event)
               
                if findings:
                    print(f" 📢 Found {len(findings)} misconfiguration(s)")
                    for finding in findings:
                        print(f" - {finding.title} (Severity: {finding.severity.value})")
                   
                    # Convert findings to dict for output
                    return [finding.to_dynamodb_item() for finding in findings]
                else:
                    print(" ✅ No misconfigurations detected")
                    return []
       
        print(" ⚠️ No detector found for this event type")
        return []
   
    def run_simulation(self, events_dir: str = "events/cloudtrail"):
        """Run simulation on all event files in a directory."""
        events_path = Path(events_dir)
       
        if not events_path.exists():
            print(f"❌ Events directory not found: {events_dir}")
            return []
       
        all_findings = []
       
        print("🚀 Starting Nebula Shield Simulation")
        print("=" * 50)
       
        # Process each event file
        event_files = sorted(events_path.glob("*.json"))
        for event_file in event_files:
            findings = self.process_event_file(str(event_file))
            all_findings.extend(findings)
       
        # Print summary
        print("\n" + "=" * 50)
        print("📊 Simulation Summary")
        print(f" Total events processed: {len(event_files)}")
        print(f" Total findings detected: {len(all_findings)}")
       
        # Print intent logs from AWS mock
        print(f"\n🔧 AWS API Intent Logs ({self.mode} mode):")
        print("-" * 30)
       
        logs = self.aws_client.get_logs()
        if logs:
            for i, log in enumerate(logs, 1):
                print(f"{i}. {log['service']}.{log['operation']}")
                print(f" Parameters: {json.dumps(log['parameters'], indent=2, default=str)}")
        else:
            print("No AWS API calls were triggered")
       
        return all_findings


def main():
    """Main entry point for simulation."""
    import argparse
   
    parser = argparse.ArgumentParser(description="Nebula Shield Event Simulator")
    parser.add_argument("--mode", choices=["dry_run", "intent_only"],
                        default="dry_run", help="Execution mode")
    parser.add_argument("--event-file", help="Process single event file")
    parser.add_argument("--events-dir", default="events/cloudtrail",
                        help="Directory containing event files")
   
    args = parser.parse_args()
   
    simulator = EventSimulator(mode=args.mode)
   
    if args.event_file:
        findings = simulator.process_event_file(args.event_file)
    else:
        findings = simulator.run_simulation(args.events_dir)
   
    # Optionally save findings to file
    if findings:
        output_file = "simulation_findings.json"
        with open(output_file, 'w') as f:
            json.dump(findings, f, indent=2, default=str)
        print(f"\n💾 Findings saved to: {output_file}")


if __name__ == "__main__":
    main()
