# Serverless CloudWatch Guard

> Real-time AWS control plane monitoring with automated alerting for high-risk actions.

## Architecture
This project deploys a serverless security guard that watches for high-risk control plane changes in near real-time.

```mermaid
graph TD
    User((User / Attacker)) -->|1. High-risk API call| CloudTrail[AWS CloudTrail]
    CloudTrail -->|2. Logs event| EB[Amazon EventBridge]
    EB -->|3. Triggers rule| Lambda[AWS Lambda (Python)]
    Lambda -->|4. Parses & enriches| SNS[Amazon SNS]
    SNS -->|5. Delivers alert| Email((Security Admin))

    style Lambda fill:#f9f,stroke:#333,stroke-width:2px
    style SNS fill:#ff9,stroke:#333,stroke-width:2px
```

## The Problem
Modern AWS estates emit millions of CloudTrail records daily. Manual log review is infeasible for detecting rapid-threat actions such as privileged user creation or overly permissive security group changes. Delayed SIEM ingestion and batch analytics leave gaps where attackers can establish persistence or exfiltrate data before human review. Real-time, event-driven controls are required to identify and escalate risky API calls the moment they occur.

## The Solution
Serverless CloudWatch Guard uses Amazon EventBridge to subscribe to CloudTrail events for high-risk API calls (e.g., `CreateUser`, `AuthorizeSecurityGroupIngress`). When a matched event is emitted, EventBridge invokes an AWS Lambda function (`lambda_function.py`) that:
- Parses the event to extract actor identity, source IP, region, account, and request parameters.
- Constructs an analyst-ready alert with contextual details (event ID, timestamp, request parameters).
- Publishes the alert to an SNS topic (configured via the `SNS_TOPIC_ARN` environment variable) for downstream notification or SOAR workflows.
This pattern provides near-instant detection and automated triage without provisioning servers or maintaining polling logic.

## Deployment
1. Create or identify an SNS topic to receive alerts; note the topic ARN.
2. Deploy `lambda_function.py` as a Lambda function (Python 3.x runtime) and set the environment variable `SNS_TOPIC_ARN` to the SNS topic ARN. Required permissions: `sns:Publish` to the topic.
3. Create an EventBridge rule targeting CloudTrail `eventName` values `CreateUser` and `AuthorizeSecurityGroupIngress` (source `aws.iam` and `aws.ec2` respectively) and set the Lambda function as the target.
4. Optionally, add dead-letter queues or CloudWatch Logs retention policies to harden reliability and auditability.
5. Validate by invoking the Lambda locally with the provided dummy `CreateUser` event in `lambda_function.py`, or trigger a controlled test in a non-production account.

## Security Mapping (NIST CSF)
- **DETECT (DE.CM):** Continuous monitoring of control plane changes via EventBridge rules on CloudTrail events; real-time detection of high-risk API calls.
- **RESPOND (RS.AN, RS.CO):** Automated analysis and contextual alerting through Lambda; communication of incidents via SNS for downstream SOAR/IR playbooks and ticketing. The design supports rapid containment actions (e.g., automated remediation Lambda or playbooks) by extending the SNS subscription set.
