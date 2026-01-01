"""Rule evaluation and configuration management."""

import json
from pathlib import Path
from typing import Dict, Any, List, Optional

import yaml
from dataclasses import dataclass

from src.models.finding import Finding, FindingSeverity


@dataclass
class RuleDefinition:
    """Definition of a detection and remediation rule."""
    id: str
    name: str
    description: str
    resource_types: List[str]
    severity: FindingSeverity
    detection_logic: Dict[str, Any]
    remediation: Dict[str, Any]
    risk_assessment: Dict[str, Any]

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RuleDefinition":
        """Create RuleDefinition from dictionary."""
        return cls(
            id=data["id"],
            name=data["name"],
            description=data["description"],
            resource_types=data.get("resource_types", []),
            severity=FindingSeverity(data["severity"]),
            detection_logic=data.get("detection_logic", {}),
            remediation=data.get("remediation", {}),
            risk_assessment=data.get("risk_assessment", {})
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "resource_types": self.resource_types,
            "severity": self.severity.value,
            "detection_logic": self.detection_logic,
            "remediation": self.remediation,
            "risk_assessment": self.risk_assessment
        }


class RuleEvaluator:
    """Evaluates findings against configured rules."""

    def __init__(self, rules_dir: str = "rules"):
        self.rules_dir = Path(rules_dir)
        self.rules: Dict[str, RuleDefinition] = {}
        self._load_rules()

    def _load_rules(self):
        """Load all rules from the rules directory."""
        if not self.rules_dir.exists():
            self.rules_dir.mkdir(parents=True, exist_ok=True)

        # Load all .json and .yaml files in the rules directory
        for rule_file in self.rules_dir.glob("*.json"):
            self._load_rule_file(rule_file)

        for rule_file in self.rules_dir.glob("*.yaml"):
            self._load_rule_file(rule_file)

        # Create default rules if none exist
        if not self.rules:
            self._create_default_rules()

    def _load_rule_file(self, rule_file: Path):
        """Load a single rule file."""
        try:
            if rule_file.suffix == ".json":
                with open(rule_file, 'r') as f:
                    data = json.load(f)
            else:  # .yaml
                with open(rule_file, 'r') as f:
                    data = yaml.safe_load(f)

            if isinstance(data, list):
                for rule_data in data:
                    rule = RuleDefinition.from_dict(rule_data)
                    self.rules[rule.id] = rule

        except Exception as e:
            print(f"Error loading rule file {rule_file}: {e}")

    def _create_default_rules(self):
        """Create default rules for MVP."""
        default_rules = [
            {
                "id": "S3-PUBLIC-ACCESS-001",
                "name": "S3 Bucket Public Access",
                "description": "Detects S3 buckets with public access enabled via bucket policies or ACLs",
                "resource_types": ["AWS::S3::Bucket"],
                "severity": "HIGH",
                "detection_logic": {
                    "triggers": ["PutBucketPolicy", "DeletePublicAccessBlock"],
                    "conditions": [
                        {
                            "field": "policy.Statement[*].Principal",
                            "operator": "equals",
                            "value": "*"
                        }
                    ]
                },
                "remediation": {
                    "action": "EnableS3PublicAccessBlock",
                    "parameters": {
                }
                "description": "Detects IAM policies with overly permissive statements",
                "resource_types": ["AWS::IAM::Role", "AWS::IAM::User", "AWS::IAM::Policy"],
                "severity": "CRITICAL",
                "detection_logic": {
                    "triggers": ["AttachRolePolicy", "PutUserPolicy"],
                    "conditions": [
                        {
                            "field": "policy.Statement[*].Action",
                            "operator": "contains",
                            "value": "*"
                        }
                    ]
                },
                "remediation": {
                    "action": "DetachIAMPolicy",
                    "parameters": {},
                    "auto_remediate": False,
                    "requires_approval": True
                },
                "risk_assessment": {
                    "impact": "CRITICAL",
                    "likelihood": "LOW",
                    "business_context": "Over-permissive policies can lead to privilege escalation"
                }
            },
            {
                "id": "SG-OPEN-PORTS-001",
                "name": "Security Group Open to Internet",
                "description": "Detects security groups with sensitive ports open to the internet (0.0.0.0/0)",
                "resource_types": ["AWS::EC2::SecurityGroup"],
                "severity": "HIGH",
                "detection_logic": {
                    "triggers": ["AuthorizeSecurityGroupIngress"],
                    "conditions": [
                        {
                            "field": "IpPermissions[*].IpRanges[*].CidrIp",
                            "operator": "equals",
                            "value": "0.0.0.0/0"
                        },
                        {
                            "field": "IpPermissions[*].FromPort",
                            "operator": "in",
                            "value": [22, 3389, 3306, 5432]
                        }
                    ]
                },
                "remediation": {
                    "action": "RevokeSecurityGroupIngress",
                    "parameters": {},
                    "auto_remediate": False,
                    "requires_approval": True
                },
                "risk_assessment": {
                    "impact": "HIGH",
                    "likelihood": "HIGH",
                    "business_context": "Open ports to internet increase attack surface"
                }
            }
        ]

        for rule_data in default_rules:
            rule = RuleDefinition.from_dict(rule_data)
            self.rules[rule.id] = rule

        self._save_default_rules()

    def _save_default_rules(self):
        """Save default rules to file for reference."""
        default_rules_path = self.rules_dir / "default_rules.json"
        default_rules = [rule.to_dict() for rule in self.rules.values()]

        with open(default_rules_path, 'w') as f:
            json.dump(default_rules, f, indent=2)

    def evaluate_finding_against_rules(self, finding: Finding) -> Optional[RuleDefinition]:
        """Evaluate if a finding matches any configured rule."""
        if finding.rule_id in self.rules:
            return self.rules[finding.rule_id]

        for rule in self.rules.values():
            if finding.resource_type in rule.resource_types:
                if any(keyword in finding.title.lower() for keyword in ["public", "open", "permissive"]):
                    return rule

        return None

    def get_rule(self, rule_id: str) -> Optional[RuleDefinition]:
        """Get a rule by ID."""
        return self.rules.get(rule_id)

    def list_rules(self) -> List[RuleDefinition]:
        """List all configured rules."""
        return list(self.rules.values())

    def get_rules_for_resource_type(self, resource_type: str) -> List[RuleDefinition]:
        """Get all rules that apply to a specific resource type."""
        return [rule for rule in self.rules.values() if resource_type in rule.resource_types]

    def add_rule(self, rule: RuleDefinition):
        """Add a new rule."""
        self.rules[rule.id] = rule
        self._save_rules_to_file()

    def update_rule(self, rule_id: str, updates: Dict[str, Any]):
        """Update an existing rule."""
        if rule_id in self.rules:
            current_rule = self.rules[rule_id]
            updated_dict = current_rule.to_dict()
            updated_dict.update(updates)
            self.rules[rule_id] = RuleDefinition.from_dict(updated_dict)
            self._save_rules_to_file()

    def delete_rule(self, rule_id: str):
        """Delete a rule."""
        if rule_id in self.rules:
            del self.rules[rule_id]
            self._save_rules_to_file()

    def _save_rules_to_file(self):
        """Save all rules to a file."""
        rules_file = self.rules_dir / "active_rules.json"
        rules_data = [rule.to_dict() for rule in self.rules.values()]

        with open(rules_file, 'w') as f:
            json.dump(rules_data, f, indent=2)                "name": "IAM Over-Permissive Policy",
                "id": "IAM-OVER-PERMISSIVE-001",
            },
            {
                        "BlockPublicAcls": True,
                        "IgnorePublicAcls": True,
                        "BlockPublicPolicy": True,
                        "RestrictPublicBuckets": True
                    },
                    "auto_remediate": True,
                    "requires_approval": False
                },
                "risk_assessment": {
                    "impact": "HIGH",
                    "likelihood": "MEDIUM",
                    "business_context": "Public buckets can lead to data leakage"
            print(f"Loaded rule: {rule_file.name}")
            else:
                self.rules[rule.id] = rule


