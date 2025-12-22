# Nebula Shield Architecture

## Overview
Nebula Shield is an event-driven, control-plane security orchestration system built on AWS-native services. It autonomously detects and remediates cloud misconfigurations while maintaining strong auditability.

## Core Principles
1. **Control-plane only**: No agents, sidecars, or workload instrumentation
2. **Event-driven first**: CloudTrail + AWS Config as authoritative truth sources
3. **Separation of concerns**: Detection → Decision → Remediation layers
4. **Safety first**: All remediations are idempotent, reversible, and least-privilege

## High-Level Architecture
CloudTrail/Config Events → EventBridge → Detection Lambda → Decision Lambda → Remediation Lambda
↓ ↓ ↓ ↓
Raw Events Findings State Machine AWS API Calls
↓
DynamoDB (Audit)
CloudWatch (Metrics)


## Component Details

### 1. Detection Layer
**Purpose**: Convert raw AWS events into security findings
**Components**: Lambda functions, EventBridge rules
**Inputs**: CloudTrail events, AWS Config compliance events
**Outputs**: Normalized `Finding` objects

### 2. Decision Engine
**Purpose**: Evaluate findings and determine remediation action
**Components**: Lambda function, State machine
**Logic**: Risk assessment, approval gating, remediation planning
**Outputs**: `RemediationPlan` with rollback instructions

### 3. Remediation Layer
**Purpose**: Execute safe remediations and rollbacks
**Components**: Service-specific Lambda functions
**Safety**: Dry-run mode, intent logging, rollback verification
**Outputs**: Resource state changes, audit logs

### 4. Data Layer
**Purpose**: Immutable audit trail and state management
**Components**: DynamoDB table, CloudWatch Logs
**Schema**: Time-series findings with full event context
**Guarantees**: Append-only, protected from remediation role

### 5. Observability Layer
**Purpose**: Monitoring, alerting, and visualization
**Components**: CloudWatch Metrics/Dashboards, QuickSight
**Coverage**: Detection rates, remediation success, failure trends

## Event Flow
1. **Detection Trigger**: CloudTrail logs API call, EventBridge rule matches
2. **Finding Creation**: Detection Lambda enriches event, creates finding
3. **State Evaluation**: Decision Engine assesses risk, sets next state
4. **Remediation Planning**: If auto-remediate, creates plan with rollback
5. **Execution**: Remediation Lambda executes plan, verifies results
6. **Audit**: All steps logged to DynamoDB with correlation ID

## Security Boundaries
- **Detection Role**: Read-only access to AWS Config and describe APIs
- **Decision Role**: Read/write to DynamoDB, no resource mutation
- **Remediation Roles**: Narrow, service-specific write permissions
- **Audit Protection**: Remediation roles cannot modify audit logs

## Failure Modes & Recovery
1. **Detection Failure**: Event lost → Safety net via periodic scans
2. **Decision Failure**: Finding stuck in DETECTED → Alert, manual review
3. **Remediation Failure**: Rollback executed, finding moved to FAILED
4. **System Failure**: Degrade to alert-only mode, never worsen security



