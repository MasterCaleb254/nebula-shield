# Nebula Shield Threat Model

## Overview
This document outlines potential threats to the Nebula Shield system and corresponding mitigations.

## System Boundaries
- **In scope**: Control plane components, IAM roles, Lambda functions, DynamoDB
- **Out of scope**: Customer workloads, network traffic, host-level security

## Assets
1. **Audit Logs (DynamoDB)**: Immutable record of security events
2. **Remediation Privileges**: IAM roles with write permissions
3. **Configuration State**: AWS Config and CloudTrail event streams
4. **Decision Logic**: Risk assessment and remediation rules

## Threat Actors

### 1. Malicious Cloud Administrator
**Capabilities**: Full AWS account access, ability to modify IAM roles
**Goals**: Suppress findings, falsify audit logs, escalate privileges
**Mitigations**:
- Immutable audit logs (append-only DynamoDB)
- Remediation roles cannot modify findings
- Separation of duties (detection vs remediation)
- Regular external audit of logs

### 2. Compromised Lambda Function
**Capabilities**: Execute code with assigned IAM role permissions
**Goals**: Extract credentials, modify resources beyond scope
**Mitigations**:
- Least privilege IAM roles per function
- No secret storage in environment variables
- Code signing and verification
- Regular dependency updates

### 3. External Attacker via AWS API
**Capabilities**: Attempt to exploit misconfigured AWS services
**Goals**: Gain unauthorized access, disrupt security operations
**Mitigations**:
- Private endpoints where possible
- API Gateway with WAF
- CloudTrail logging for all API calls
- Regular security review of IAM policies

### 4. Insider with Limited Access
**Capabilities**: Read-only access to some components
**Goals**: Exfiltrate sensitive findings, understand security posture
**Mitigations**:
- Encryption at rest and in transit
- Principle of least privilege
- Audit logging of data access
- Data classification and handling

## Attack Vectors

### A1: Audit Log Tampering
**Attack**: Modify or delete findings to hide security issues
**Mitigation**: 
- DynamoDB write-once pattern
- Remediation role deny on DeleteItem, UpdateItem for old items
- External SIEM integration for backup

### A2: Remediation Privilege Escalation
**Attack**: Use remediation role to broaden permissions
**Mitigation**:
- Explicit deny on iam:*, organizations:*
- Resource-level permissions only
- Regular permission boundary reviews

### A3: Event Source Compromise
**Attack**: Inject false events or suppress real ones
**Mitigation**:
- Validate event signatures (CloudTrail)
- Multi-source correlation (CloudTrail + Config)
- Periodic baseline validation

### A4: Decision Logic Manipulation
**Attack**: Modify rules to ignore serious misconfigurations
**Mitigation**:
- Code review and signing
- Versioned rule definitions
- Alert on rule changes

## Security Controls

### Preventive Controls
1. IAM permission boundaries
2. Resource policies (SCPs for multi-account)
3. VPC endpoints for AWS services
4. Encryption (KMS for DynamoDB, S3)

### Detective Controls
1. CloudTrail logging of all Nebula Shield API calls
2. Config rules monitoring Nebula Shield resources
3. GuardDuty for anomaly detection
4. Regular penetration testing

### Responsive Controls
1. Automated rollback on remediation failure
2. Alerting on suspicious patterns
3. Incident response playbooks
4. Forensic capabilities in audit logs

## Assumptions
1. AWS control plane integrity (CloudTrail, Config, IAM)
2. No physical access to AWS infrastructure
3. AWS account root user is properly secured
4. Dependency security (monitored via Dependabot)

## Risk Acceptance
Some risks are accepted due to trade-offs:
- Eventual consistency in detection (seconds to minutes)
- False positives in auto-remediation (mitigated by rollback)
- Dependency on AWS service health (mitigated by multi-region)
