---
title: "Amazon CloudWatch and EventBridge: Security Monitoring and Log Exposure"
date: 2026-11-12 18:14:00 +0000
subcategory: aws
summary: "CloudWatch and EventBridge as detection (CIS alarms, rules, Logs Insights) and as exposure: secrets in logs, log sharing, public dashboards, tampering."
refs: [CloudWatch.1, CloudWatch.2, CloudWatch.3, CloudWatch.4, CloudWatch.5, CloudWatch.6, CloudWatch.7, CloudWatch.8, CloudWatch.9, CloudWatch.10, CloudWatch.11, CloudWatch.12, CloudWatch.13, CloudWatch.14, CloudWatch.15, CloudWatch.16, CloudWatch.17, EventBridge.3, SNS.1, SNS.4, "CIS AWS v1.4.0 4.1-4.15", "CIS AWS v1.2.0 3.1-3.14", "CIS AWS v3.0.0 4.1-4.15", T1685.002, T1552, T1654, T1537, T1538, T1078.004]
tags: [aws, cloudwatch, eventbridge, monitoring, logging, detection]
---

This note is part of our [AWS Security series](/cloud/aws-security-testing-guide/) and looks at Amazon CloudWatch and Amazon EventBridge from two directions. First as a **security control**: the place where CloudTrail events become alarms, where GuardDuty and Security Hub findings get routed to people, and where an investigator runs queries over CloudTrail, VPC Flow Logs and application logs. Then as an **attack surface**: log groups full of tokens and personal data, read permissions that are far broader than anyone intended, subscription filters and observability links that copy logs into other accounts, dashboards shared with "anyone with the link", Synthetics canaries carrying credentials, and a monitoring layer that an attacker with the wrong permissions can quietly switch off. We cover how the services fit together, the CIS monitoring recommendations with their exact metric filter patterns and the EventBridge equivalents, twelve tests, the IaC to fix what you find, and how to rate it. The audit trail itself (trails, data events, integrity, the log bucket) is in the [CloudTrail note](/cloud/aws-cloudtrail-logging/); GuardDuty, Security Hub, Config and VPC Flow Logs are in [detection and posture services](/cloud/aws-detection-posture-services/).

## Contents

- [How it works](#how-it-works)
  - [CloudWatch Logs: log groups, classes, retention and encryption](#cloudwatch-logs-log-groups-classes-retention-and-encryption)
  - [Who can read a log group](#who-can-read-a-log-group)
  - [Metric filters, alarms and SNS](#metric-filters-alarms-and-sns)
  - [The CIS monitoring filters](#the-cis-monitoring-filters)
  - [EventBridge: buses, rules, targets and CloudTrail events](#eventbridge-buses-rules-targets-and-cloudtrail-events)
  - [Why EventBridge is often the better choice](#why-eventbridge-is-often-the-better-choice)
  - [Logs Insights and Live Tail](#logs-insights-and-live-tail)
  - [Investigation queries](#investigation-queries)
  - [Cross-account flows: subscriptions, centralisation and OAM](#cross-account-flows-subscriptions-centralisation-and-oam)
  - [Data protection policies](#data-protection-policies)
  - [Dashboards, Synthetics, metric streams and the agent](#dashboards-synthetics-metric-streams-and-the-agent)
  - [Retention and cost trade-offs](#retention-and-cost-trade-offs)
- [What goes wrong](#what-goes-wrong)
  - [As a security control](#as-a-security-control)
  - [As an attack surface](#as-an-attack-surface)
- [Testing](#testing)
  - [Before you start](#before-you-start)
  - [GT-AWS-CW-1: CIS metric filter and alarm coverage](#gt-aws-cw-1-cis-metric-filter-and-alarm-coverage)
  - [GT-AWS-CW-2: Alarm actions and SNS delivery](#gt-aws-cw-2-alarm-actions-and-sns-delivery)
  - [GT-AWS-CW-3: EventBridge security rules and target health](#gt-aws-cw-3-eventbridge-security-rules-and-target-health)
  - [GT-AWS-CW-4: Event bus policies and cross-account routing](#gt-aws-cw-4-event-bus-policies-and-cross-account-routing)
  - [GT-AWS-CW-5: Log group retention, class, encryption and deletion protection](#gt-aws-cw-5-log-group-retention-class-encryption-and-deletion-protection)
  - [GT-AWS-CW-6: Secrets and personal data in log groups](#gt-aws-cw-6-secrets-and-personal-data-in-log-groups)
  - [GT-AWS-CW-7: Data protection policies and logs:Unmask](#gt-aws-cw-7-data-protection-policies-and-logsunmask)
  - [GT-AWS-CW-8: Who can read and write logs](#gt-aws-cw-8-who-can-read-and-write-logs)
  - [GT-AWS-CW-9: Subscription filters, exports and observability links](#gt-aws-cw-9-subscription-filters-exports-and-observability-links)
  - [GT-AWS-CW-10: Dashboard sharing](#gt-aws-cw-10-dashboard-sharing)
  - [GT-AWS-CW-11: Synthetics canaries, metric streams and the agent](#gt-aws-cw-11-synthetics-canaries-metric-streams-and-the-agent)
  - [GT-AWS-CW-12: Tamper prevention and alerting for the monitoring layer](#gt-aws-cw-12-tamper-prevention-and-alerting-for-the-monitoring-layer)
- [Hardening](#hardening)
- [Real-world cases](#real-world-cases)
- [Rating findings](#rating-findings)
- [Mapping](#mapping)
- [References](#references)

## How it works

CloudWatch is several services under one name: **metrics** (time series, `cloudwatch:` / `monitoring.amazonaws.com`), **alarms** on those metrics, **CloudWatch Logs** (`logs:`), **dashboards**, **Synthetics** canaries, **metric streams**, cross-account observability through the **Observability Access Manager** (`oam:`), and a growing list of add-ons. EventBridge (`events:`, formerly CloudWatch Events) is the event router: AWS services and CloudTrail publish events to it, rules match them, targets receive them. For security purposes the pipeline looks like this:

```text
API call ──► CloudTrail ──┬──► S3 (system of record, see the CloudTrail note)
                          ├──► CloudWatch Logs log group ──► metric filter ──► metric ──► alarm ──► SNS ──► people
                          │                               └─► subscription filter ──► Kinesis / Firehose / Lambda / other account
                          └──► EventBridge default bus ──► rule ──► SNS / Lambda / SQS / another account's bus / API destination

GuardDuty, Security Hub, Config, Health ──► EventBridge default bus ──► rule ──► ...
Applications, Lambda, VPC Flow Logs, EKS, API Gateway ──► CloudWatch Logs ──► Logs Insights, alarms, subscriptions
```

Every arrow is a configuration an administrator can break and an attacker can abuse, which is why this note has two halves.

### CloudWatch Logs: log groups, classes, retention and encryption

Logs live in **log groups** (one per application, function, service or trail) made of **log streams**. Properties that matter for security, all visible in `describe-log-groups`:

| Property | Default | Why it matters |
|---|---|---|
| `retentionInDays` | Absent, meaning **never expire** | Indefinite retention of secrets and personal data on one side; too-short retention destroys evidence on the other |
| `kmsKeyId` | Absent: logs are still encrypted at rest with AES-GCM under service-managed keys | With a customer managed key, reading needs the key too, and disabling the key makes the data unreadable |
| `logGroupClass` | `STANDARD` | **Essentials** (formerly Infrequent Access; the API still accepts `INFREQUENT_ACCESS`) has cheaper ingestion but **no metric filters, no subscription filters, no Live Tail, no `GetLogEvents`/`FilterLogEvents`**. Class cannot be changed after creation |
| `dataProtectionStatus`, `inheritedProperties` | No data protection policy | Shows whether masking applies, at log group level or inherited from an account policy |
| `deletionProtectionEnabled` | Off | A recent addition (`PutLogGroupDeletionProtection`): blocks deletion operations until explicitly turned off |
| `bearerTokenAuthenticationEnabled` | Off | Another recent addition; check what it is used for wherever it is on, because a bearer token used for ingestion is a credential that ends up in someone's configuration |

AWS's KMS documentation for CloudWatch Logs currently says that principals reading or writing a log group encrypted with a customer managed key need KMS permissions too (`kms:Decrypt` and related, typically constrained with `kms:ViaService` to `logs.<region>.amazonaws.com`), and recommends key policies conditioned on `kms:EncryptionContext:aws:logs:arn`. If that is how the client's keys are set up, the key policy is a second access-control layer for log reads; check the current documentation, as this area has changed over time.

### Who can read a log group

This is the question most clients have never asked. Reading log content is controlled by **identity policies** (CloudWatch Logs resource policies only govern AWS *service* principals writing logs; AWS states that resource policy statements for IAM users, roles or other accounts are not enforced). The actions that expose content:

| Action | What it returns |
|---|---|
| `logs:GetLogEvents`, `logs:FilterLogEvents` | Raw events from streams, filtered or not |
| `logs:StartQuery` + `logs:GetQueryResults` | Logs Insights queries across up to many log groups at once |
| `logs:GetLogRecord` | A single full record from a query result |
| `logs:StartLiveTail` | A streaming copy of new events |
| `logs:CreateExportTask` | A bulk copy to an S3 bucket (which can be in another account if its policy allows) |
| `logs:PutSubscriptionFilter`, `logs:PutAccountPolicy` | A continuous copy to Kinesis, Firehose, Lambda or a cross-account destination |
| `logs:Unmask` | The original values behind data protection masking |

And the AWS managed policies that grant them, as published at the time of writing:

| Managed policy | Reads log content? |
|---|---|
| `ReadOnlyAccess` | **Yes**: `logs:Get*`, `logs:FilterLogEvents`, `logs:StartQuery`, `logs:StartLiveTail` |
| `CloudWatchLogsReadOnlyAccess` | **Yes**: same set |
| `CloudWatchLogsFullAccess` | Yes, plus `logs:Unmask` and every write |
| `SecurityAudit` | No (describe and tag calls only) |
| `ViewOnlyAccess` | No |

The consequence: every human or tool with `ReadOnlyAccess` can read every application log in the account. "Read-only" sounds harmless to approvers; for logs that contain bearer tokens and customer data it is not. It also means your own `SecurityAudit` profile cannot run the secret scan in [GT-AWS-CW-6](#gt-aws-cw-6-secrets-and-personal-data-in-log-groups); you need an explicit, agreed grant.

### Metric filters, alarms and SNS

A **metric filter** watches one log group, matches each incoming event against a **filter pattern**, and emits a value (usually `1`) to a custom metric. For JSON logs such as CloudTrail, patterns look like `{ ($.eventName = "StopLogging") || ($.eventName = "DeleteTrail") }`: selectors start with `$.`, and you can combine terms with `&&`, `||`, `NOT EXISTS`, wildcards and comparisons. Filters only see events ingested **after** they are created, and only in Standard-class log groups.

An **alarm** watches the metric (for example `Sum` over 300 seconds `>= 1`) and, on state change, runs **actions**: SNS notifications, Auto Scaling, EC2 actions, Systems Manager OpsItems or incidents, Lambda functions. Two flags decide whether anything happens: `ActionsEnabled` (alarm actions can be switched off with `DisableAlarmActions` without deleting anything) and the action list itself. Security Hub CSPM checks both (`CloudWatch.15`, `CloudWatch.17`).

The **SNS topic** is where most chains break in practice: unconfirmed email subscriptions, subscriptions to people who left, topics encrypted with a KMS key whose policy does not let `cloudwatch.amazonaws.com` or `events.amazonaws.com` use it (publishing then fails silently from the user's point of view), or topic policies that let anyone subscribe.

### The CIS monitoring filters

The CIS AWS Foundations Benchmark section on monitoring asks for a metric filter and alarm for fifteen kinds of event. Security Hub CSPM implements fourteen of them as `CloudWatch.1` to `CloudWatch.14` and checks for the **exact** CIS pattern: in AWS's words, "additional fields or terms cannot be added to the metric filters". Security Hub CSPM maps these controls to CIS v1.2.0 (3.1–3.14) and v1.4.0 (4.3–4.14; `CloudWatch.2` and `CloudWatch.3` are mapped for v1.2.0 only, although v1.4.0 has the same requirements as 4.1 and 4.2); for CIS v3.0.0 and v5.0.0 it lists all of them as "Not supported – manual check", although the requirements remain in those versions as 4.1–4.15. The fifteenth, AWS Organizations changes (CIS v1.4.0 and v3.0.0 4.15), has no Security Hub CSPM control; Prowler checks it.

The patterns, as published in the Security Hub CSPM control documentation (and, for 4.15, Prowler's remediation text):

```text
# CloudWatch.1 root user usage (CIS v1.4.0 4.3)
{$.userIdentity.type="Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType !="AwsServiceEvent"}

# CloudWatch.2 unauthorised API calls (CIS v1.2.0 3.1; CIS v1.4.0 4.1 is not evaluated by Security Hub CSPM)
{($.errorCode="*UnauthorizedOperation") || ($.errorCode="AccessDenied*")}

# CloudWatch.3 console sign-in without MFA (CIS v1.2.0 3.2; CIS v1.4.0 4.2 is not evaluated by Security Hub CSPM)
{ ($.eventName = "ConsoleLogin") && ($.additionalEventData.MFAUsed != "Yes") && ($.userIdentity.type = "IAMUser") && ($.responseElements.ConsoleLogin = "Success") }

# CloudWatch.4 IAM policy changes (CIS v1.4.0 4.4)
{($.eventSource=iam.amazonaws.com) && (($.eventName=DeleteGroupPolicy) || ($.eventName=DeleteRolePolicy) || ($.eventName=DeleteUserPolicy) || ($.eventName=PutGroupPolicy) || ($.eventName=PutRolePolicy) || ($.eventName=PutUserPolicy) || ($.eventName=CreatePolicy) || ($.eventName=DeletePolicy) || ($.eventName=CreatePolicyVersion) || ($.eventName=DeletePolicyVersion) || ($.eventName=AttachRolePolicy) || ($.eventName=DetachRolePolicy) || ($.eventName=AttachUserPolicy) || ($.eventName=DetachUserPolicy) || ($.eventName=AttachGroupPolicy) || ($.eventName=DetachGroupPolicy))}

# CloudWatch.5 CloudTrail configuration changes (CIS v1.4.0 4.5)
{($.eventName=CreateTrail) || ($.eventName=UpdateTrail) || ($.eventName=DeleteTrail) || ($.eventName=StartLogging) || ($.eventName=StopLogging)}

# CloudWatch.6 console authentication failures (CIS v1.4.0 4.6)
{($.eventName=ConsoleLogin) && ($.errorMessage="Failed authentication")}

# CloudWatch.7 disabling or scheduled deletion of customer managed keys (CIS v1.4.0 4.7)
{($.eventSource=kms.amazonaws.com) && (($.eventName=DisableKey) || ($.eventName=ScheduleKeyDeletion))}

# CloudWatch.8 S3 bucket policy changes (CIS v1.4.0 4.8)
{($.eventSource=s3.amazonaws.com) && (($.eventName=PutBucketAcl) || ($.eventName=PutBucketPolicy) || ($.eventName=PutBucketCors) || ($.eventName=PutBucketLifecycle) || ($.eventName=PutBucketReplication) || ($.eventName=DeleteBucketPolicy) || ($.eventName=DeleteBucketCors) || ($.eventName=DeleteBucketLifecycle) || ($.eventName=DeleteBucketReplication))}

# CloudWatch.9 AWS Config configuration changes (CIS v1.4.0 4.9)
{($.eventSource=config.amazonaws.com) && (($.eventName=StopConfigurationRecorder) || ($.eventName=DeleteDeliveryChannel) || ($.eventName=PutDeliveryChannel) || ($.eventName=PutConfigurationRecorder))}

# CloudWatch.10 security group changes (CIS v1.4.0 4.10)
{($.eventName=AuthorizeSecurityGroupIngress) || ($.eventName=AuthorizeSecurityGroupEgress) || ($.eventName=RevokeSecurityGroupIngress) || ($.eventName=RevokeSecurityGroupEgress) || ($.eventName=CreateSecurityGroup) || ($.eventName=DeleteSecurityGroup)}

# CloudWatch.11 network ACL changes (CIS v1.4.0 4.11)
{($.eventName=CreateNetworkAcl) || ($.eventName=CreateNetworkAclEntry) || ($.eventName=DeleteNetworkAcl) || ($.eventName=DeleteNetworkAclEntry) || ($.eventName=ReplaceNetworkAclEntry) || ($.eventName=ReplaceNetworkAclAssociation)}

# CloudWatch.12 network gateway changes (CIS v1.4.0 4.12)
{($.eventName=CreateCustomerGateway) || ($.eventName=DeleteCustomerGateway) || ($.eventName=AttachInternetGateway) || ($.eventName=CreateInternetGateway) || ($.eventName=DeleteInternetGateway) || ($.eventName=DetachInternetGateway)}

# CloudWatch.13 route table changes (CIS v1.4.0 4.13)
{($.eventSource=ec2.amazonaws.com) && (($.eventName=CreateRoute) || ($.eventName=CreateRouteTable) || ($.eventName=ReplaceRoute) || ($.eventName=ReplaceRouteTableAssociation) || ($.eventName=DeleteRouteTable) || ($.eventName=DeleteRoute) || ($.eventName=DisassociateRouteTable))}

# CloudWatch.14 VPC changes (CIS v1.4.0 4.14)
{($.eventName=CreateVpc) || ($.eventName=DeleteVpc) || ($.eventName=ModifyVpcAttribute) || ($.eventName=AcceptVpcPeeringConnection) || ($.eventName=CreateVpcPeeringConnection) || ($.eventName=DeleteVpcPeeringConnection) || ($.eventName=RejectVpcPeeringConnection) || ($.eventName=AttachClassicLinkVpc) || ($.eventName=DetachClassicLinkVpc) || ($.eventName=DisableVpcClassicLink) || ($.eventName=EnableVpcClassicLink)}

# CIS 4.15 AWS Organizations changes (no Security Hub CSPM control; Prowler cloudwatch_log_metric_filter_aws_organizations_changes)
{ ($.eventSource = organizations.amazonaws.com) && (($.eventName = "AcceptHandshake") || ($.eventName = "AttachPolicy") || ($.eventName = "CancelHandshake") || ($.eventName = "CreateAccount") || ($.eventName = "CreateOrganization") || ($.eventName = "CreateOrganizationalUnit") || ($.eventName = "CreatePolicy") || ($.eventName = "DeclineHandshake") || ($.eventName = "DeleteOrganization") || ($.eventName = "DeleteOrganizationalUnit") || ($.eventName = "DeletePolicy") || ($.eventName = "EnableAllFeatures") || ($.eventName = "EnablePolicyType") || ($.eventName = "InviteAccountToOrganization") || ($.eventName = "LeaveOrganization") || ($.eventName = "DetachPolicy") || ($.eventName = "DisablePolicyType") || ($.eventName = "MoveAccount") || ($.eventName = "RemoveAccountFromOrganization") || ($.eventName = "UpdateOrganizationalUnit") || ($.eventName = "UpdatePolicy")) }
```

Read these as a **floor**, not a detection strategy. They were written years ago and it shows:

- The ClassicLink events in the VPC filter refer to EC2-Classic, which AWS has retired; they are harmless but useless.
- The security group filter does not include `ModifySecurityGroupRules`, a newer API that changes rules without any of the listed calls.
- The gateway filter covers customer and internet gateways only, not transit gateways, NAT gateways, egress-only internet gateways, VPC endpoints or VPN connections.
- The IAM filter is about *policies*. It does not fire on `CreateAccessKey`, `CreateLoginProfile`, `UpdateAssumeRolePolicy` or `PutRolePermissionsBoundary`, which are the calls that matter most after a credential compromise (see the [privilege escalation note](/cloud/aws-iam-privilege-escalation/)).
- The CloudTrail filter does not include `PutEventSelectors`, which can blind a trail as effectively as `StopLogging`.
- The unauthorised-calls filter is noisy in most real accounts (misconfigured tools generate denials all day) and is usually either muted or ignored.

Because Security Hub CSPM fails the control if the pattern is changed, the practical answer is to keep the exact CIS filters for compliance reporting and add **separate** filters or EventBridge rules for the extended coverage.

### EventBridge: buses, rules, targets and CloudTrail events

Each account has a **default event bus** per Region. AWS services publish to it (`source` values such as `aws.guardduty`, `aws.securityhub`, `aws.config`, `aws.health`), and CloudTrail publishes API activity to it with these detail-types:

| `detail-type` | Contents | Needs |
|---|---|---|
| `AWS API Call via CloudTrail` | Management and data events (`eventType` `AwsApiCall`) | A trail logging the relevant events; read-only management events only match rules in state `ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS` |
| `AWS Console Sign In via CloudTrail` | Console sign-in events | A trail logging management events |
| `AWS Service Event via CloudTrail` | Events created by AWS services, not direct API calls | A trail |
| `AWS Insight via CloudTrail` | CloudTrail Insights events | A trail with Insights |
| `AWS Network Activity Event via CloudTrail` | Network activity events | A trail with network activity selectors |

(AWS's EventBridge documentation also shows the console sign-in detail-type spelled "Signin"; match against a captured event before relying on either spelling.)

**Regions are the trap.** Events go to the default bus **in the Region where they occurred**. A rule in `eu-west-2` does not see `RunInstances` in `ap-southeast-3`. IAM and other global-service events surface in `us-east-1`. Console sign-in events are recorded in different Regions depending on user type and endpoint: AWS documents root sign-ins in `us-east-1`, `us-east-2` or `us-west-2`, and IAM user sign-ins via the global endpoint in `us-east-1`, `us-east-2`, `eu-north-1` or `ap-southeast-2` depending on cookies and latency. A sign-in alert rule deployed only in the client's home Region will miss most sign-ins. Deploy security rules in every enabled Region (StackSets), or forward everything to a central bus.

A **rule** has an event pattern (or a schedule), a state (`ENABLED`, `DISABLED`, `ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS`) and up to five **targets**. Targets include SNS, SQS, Lambda, Step Functions, Kinesis, Firehose, CloudWatch Logs, Systems Manager, another event bus (in the same or another account and Region) and **API destinations** (arbitrary HTTPS endpoints, with credentials held in an EventBridge **connection**). Each target can have a dead-letter queue and a retry policy. EventBridge reports per-rule metrics in `AWS/Events` (`MatchedEvents`, `Invocations`, `FailedInvocations`), which is how you prove a rule is working without triggering it.

**Event bus resource policies** decide which other accounts can put events on a bus, and, less obviously, which accounts can create rules (`events:PutRule`) and targets (`events:PutTargets`) on it. A rule created on your bus by another account can send *your* events to *their* targets. `describe-rule` shows `CreatedBy`; rules where that is not the bus owner deserve a question.

Events from AWS services carry `source` values beginning with `aws.`, and AWS does not accept those from customer `PutEvents` calls, so a rule matching `"source": ["aws.guardduty"]` cannot be fed fake findings by another account. Custom events on a shared bus are a different matter: match on the `account` field as well as `source`, or a member account can spoof another team's events.

### Why EventBridge is often the better choice

| | Metric filter + alarm | EventBridge rule |
|---|---|---|
| Latency | CloudTrail to CloudWatch Logs delivery (minutes) plus alarm period | Typically faster: events reach the bus directly |
| Context in the alert | A number: "metric `CloudTrailChanges` ≥ 1" | The full event: who, what, from where |
| Regions | One log group receives all Regions of a multi-Region trail | One rule per Region (or forward to a central bus) |
| Read-only events | Included if the trail records them | Only with `ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS` |
| Non-CloudTrail sources | No | GuardDuty, Security Hub, Config, Health, Access Analyzer, Macie, Inspector... |
| Routing | SNS, Lambda, Systems Manager | Any target, other accounts' buses, chat via SNS or Amazon Q Developer in chat applications, HTTPS endpoints |
| Compliance tooling | Security Hub CSPM `CloudWatch.1–14` pass | Security Hub CSPM still reports the CIS controls as failed |
| Events over 256 KB | Not delivered | Not delivered |

Clients with a SIEM often do neither: they ingest CloudTrail from S3 and alert there. That is a valid answer to CIS 4.x if the SIEM rules exist and work; ask to see them.

EventBridge equivalents of the most important CIS filters, plus routing for findings (all patterns are matched against the event envelope; `detail` holds the CloudTrail record):

```json
{
  "detail-type": ["AWS API Call via CloudTrail", "AWS Console Sign In via CloudTrail"],
  "detail": {
    "userIdentity": {
      "type": ["Root"]
    }
  }
}
```

```json
{
  "detail-type": ["AWS Console Sign In via CloudTrail"],
  "detail": {
    "eventName": ["ConsoleLogin"],
    "userIdentity": {
      "type": ["IAMUser"]
    },
    "additionalEventData": {
      "MFAUsed": ["No"]
    },
    "responseElements": {
      "ConsoleLogin": ["Success"]
    }
  }
}
```

```json
{
  "source": ["aws.iam"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventSource": ["iam.amazonaws.com"],
    "eventName": [
      "DeleteGroupPolicy", "DeleteRolePolicy", "DeleteUserPolicy", "PutGroupPolicy",
      "PutRolePolicy", "PutUserPolicy", "CreatePolicy", "DeletePolicy",
      "CreatePolicyVersion", "DeletePolicyVersion", "AttachRolePolicy", "DetachRolePolicy",
      "AttachUserPolicy", "DetachUserPolicy", "AttachGroupPolicy", "DetachGroupPolicy",
      "CreateAccessKey", "CreateLoginProfile", "UpdateAssumeRolePolicy", "PutRolePermissionsBoundary"
    ]
  }
}
```

```json
{
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventSource": ["ec2.amazonaws.com"],
    "eventName": [
      "AuthorizeSecurityGroupIngress", "AuthorizeSecurityGroupEgress", "RevokeSecurityGroupIngress",
      "RevokeSecurityGroupEgress", "CreateSecurityGroup", "DeleteSecurityGroup", "ModifySecurityGroupRules",
      "CreateNetworkAcl", "CreateNetworkAclEntry", "DeleteNetworkAcl", "DeleteNetworkAclEntry",
      "ReplaceNetworkAclEntry", "ReplaceNetworkAclAssociation",
      "CreateCustomerGateway", "DeleteCustomerGateway", "AttachInternetGateway", "CreateInternetGateway",
      "DeleteInternetGateway", "DetachInternetGateway",
      "CreateRoute", "CreateRouteTable", "ReplaceRoute", "ReplaceRouteTableAssociation",
      "DeleteRouteTable", "DeleteRoute", "DisassociateRouteTable",
      "CreateVpc", "DeleteVpc", "ModifyVpcAttribute", "AcceptVpcPeeringConnection",
      "CreateVpcPeeringConnection", "DeleteVpcPeeringConnection", "RejectVpcPeeringConnection"
    ]
  }
}
```

```json
{
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "errorCode": [{ "suffix": "UnauthorizedOperation" }, { "prefix": "AccessDenied" }]
  }
}
```

(Unauthorised calls: create this rule with state `ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS` if denied *read* calls should match too, and send it to a queue or a Lambda function that aggregates per principal rather than straight to people; on its own it is a pager-fatigue machine.)

```json
{
  "source": ["aws.guardduty"],
  "detail-type": ["GuardDuty Finding"],
  "detail": {
    "severity": [{ "numeric": [">=", 7] }]
  }
}
```

```json
{
  "source": ["aws.securityhub"],
  "detail-type": ["Security Hub Findings - Imported"],
  "detail": {
    "findings": {
      "Severity": {
        "Label": ["HIGH", "CRITICAL"]
      },
      "Workflow": {
        "Status": ["NEW"]
      },
      "RecordState": ["ACTIVE"]
    }
  }
}
```

The last pattern is for Security Hub CSPM (AWS renamed the original Security Hub to **Security Hub CSPM** in 2025; the new Security Hub, generally available since December 2025, emits OCSF findings with the detail-type `Findings Imported V2` and a different field layout, so rules need rewriting when clients move). The tamper pattern for the monitoring layer itself is in [GT-AWS-CW-12](#gt-aws-cw-12-tamper-prevention-and-alerting-for-the-monitoring-layer).

### Logs Insights and Live Tail

**CloudWatch Logs Insights** runs queries over one or more log groups (across accounts too, with OAM) in its own query language, OpenSearch PPL, or OpenSearch SQL. It discovers fields automatically for JSON logs (CloudTrail), VPC Flow Logs in the default format (`srcAddr`, `dstAddr`, `dstPort`, `action`, `bytes`...) and Lambda (`@type`, `@duration`, `@requestId`...). It is billed per GB scanned, so narrow the time range and log groups. Scheduled queries work in both log classes; field indexes, which reduce the data scanned, are Standard-class only.

**Live Tail** streams new events from up to ten log groups in the console (`aws logs start-live-tail` from the CLI), sessions last up to three hours, it is billed per session-minute, works only on Standard-class log groups, and **respects data protection masking**. During an incident it is the quickest way to watch an attacker's session in a Lambda function's logs or a trail's log group; during a review, note who holds `logs:StartLiveTail`, because it is a read path like any other.

### Investigation queries

Queries you can hand to a client's incident responders. All are read-only; run them only on the client's log groups within scope.

CloudTrail log group (fields are the CloudTrail JSON names):

```text
# Tamper attempts on logging and monitoring, successful or denied
fields @timestamp, eventSource, eventName, userIdentity.arn, sourceIPAddress, errorCode
| filter eventName in ["StopLogging","DeleteTrail","UpdateTrail","PutEventSelectors","DeleteLogGroup",
    "PutRetentionPolicy","DeleteSubscriptionFilter","DeleteAlarms","DisableAlarmActions",
    "DeleteRule","DisableRule","RemoveTargets","DeleteDetector","StopConfigurationRecorder"]
| sort @timestamp desc
```

```text
# Principals generating denials across many services (credential enumeration)
filter errorCode like /AccessDenied|UnauthorizedOperation/
| stats count(*) as denied, count_distinct(eventSource) as services by userIdentity.arn, sourceIPAddress
| filter services >= 5
| sort denied desc
| limit 25
```

```text
# Everything one access key did
filter userIdentity.accessKeyId = "<ACCESS_KEY_ID>"
| stats count(*) as calls, earliest(@timestamp) as first, latest(@timestamp) as last
    by eventSource, eventName, awsRegion, sourceIPAddress
| sort first asc
```

```text
# Write activity per Region (spot Regions the client does not use)
filter eventType = "AwsApiCall" and eventName not like /^(Get|List|Describe|Head|Lookup)/
| stats count(*) as writes by awsRegion
| sort writes desc
```

```text
# Console sign-ins: failures, no-MFA successes, root
filter eventName = "ConsoleLogin"
| fields @timestamp, userIdentity.type, userIdentity.arn, sourceIPAddress,
    responseElements.ConsoleLogin as result, additionalEventData.MFAUsed as mfa
| sort @timestamp desc
| limit 100
```

```text
# Who assumed which role from where (pivot from a role to the people behind it)
filter eventName in ["AssumeRole","AssumeRoleWithSAML","AssumeRoleWithWebIdentity"]
| stats count(*) by userIdentity.arn, requestParameters.roleArn, sourceIPAddress
```

VPC Flow Logs (default format):

```text
# Rejected connection attempts by source and port
filter action = "REJECT"
| stats count(*) as rejects by srcAddr, dstPort
| sort rejects desc
| limit 25
```

```text
# Accepted SSH or RDP from outside private ranges
filter action = "ACCEPT" and (dstPort = 22 or dstPort = 3389)
  and not isIpv4InSubnet(srcAddr, "10.0.0.0/8")
  and not isIpv4InSubnet(srcAddr, "172.16.0.0/12")
  and not isIpv4InSubnet(srcAddr, "192.168.0.0/16")
| stats count(*) by srcAddr, dstAddr, dstPort
```

```text
# Largest outbound flows to public addresses (exfiltration triage)
filter isIpv4InSubnet(srcAddr, "10.0.0.0/8") and not isIpv4InSubnet(dstAddr, "10.0.0.0/8")
| stats sum(bytes) as bytesOut by srcAddr, dstAddr, dstPort
| sort bytesOut desc
| limit 20
```

Lambda:

```text
# Invocation volume and duration per function log group, in 5-minute bins
filter @type = "REPORT"
| stats count(*) as invocations, max(@duration) as maxMs by @log, bin(5m)
| sort invocations desc
```

```text
# Errors, timeouts and unhandled exceptions
filter @message like /(?i)(error|exception|task timed out|access denied)/
| stats count(*) as n by @log, bin(1h)
| sort n desc
```

### Cross-account flows: subscriptions, centralisation and OAM

Log data leaves a log group in four ways, and every one of them is an exfiltration path to review:

1. **Subscription filters** (`PutSubscriptionFilter`): a continuous feed to Kinesis Data Streams, Firehose, Lambda, or a **CloudWatch Logs destination** (`arn:aws:logs:<region>:<account>:destination:<name>`) owned by another account. The destination owner controls who can send to it with a destination access policy; the sender only needs `logs:PutSubscriptionFilter` on its log group. A log group can have up to five subscription filters at the time of writing. Subscription filters are not available on Essentials-class log groups.
2. **Account-level subscription filter policies** (`PutAccountPolicy` with `--policy-type SUBSCRIPTION_FILTER_POLICY`): one policy that subscribes every log group in the account (with selection criteria) to a destination. Convenient for central logging; equally convenient for anyone who wants a copy of everything.
3. **Export tasks** (`CreateExportTask`): a one-off bulk copy to S3, possibly to a bucket in another account.
4. **Cross-account observability**: a source account creates an **OAM link** to a **sink** in a monitoring account, after which the monitoring account can query the source's metrics, log groups, traces and other telemetry (optionally filtered). Each source account can link to up to five monitoring accounts; links are managed from the source, sinks from the monitoring account, and the sink policy decides which accounts or organisations may link. There is also the older cross-account console feature, which works through an IAM role named `CloudWatch-CrossAccountSharingRole` trusted by monitoring accounts.

In 2025 AWS also added log **centralisation rules** (copying log events across accounts and Regions into a central account) and the ability to collect CloudTrail events into CloudWatch through service-linked channels, managed through CloudWatch's telemetry and centralisation settings. Ask whether either is in use and review where the copies land.

None of these are bad in themselves; central logging needs them. The test is whether every destination is an account the client owns, inside the organisation, controlled by the security or platform team, and whether creating new flows is restricted and alerted.

### Data protection policies

A **data protection policy** tells CloudWatch Logs to look for sensitive data in events **at ingestion** and mask it at every egress point, including Logs Insights, metric filters and subscription filters. A policy has two statements over the same list of data identifiers: an `Audit` operation (with optional findings destinations: a log group, Firehose or S3) and a `Deidentify` operation with an empty `MaskConfig`. Policies exist at log group level and at account level (`put-account-policy --policy-type DATA_PROTECTION_POLICY`); both apply if both exist. AWS publishes a `LogEventsWithFindings` metric in `AWS/Logs` when something matches, which is free and makes a good alarm.

Things clients get wrong:

- **Events ingested before the policy was created are not masked.** The policy does nothing about the last two years of tokens already sitting in the log group.
- **Managed identifiers are narrow.** The credentials category covers AWS secret access keys and SSH, PGP, PKCS and PuTTY private keys. Bearer tokens, session cookies, JWTs, database passwords and API keys for third-party services are not managed identifiers; they need **custom data identifiers** (regular expressions in the policy).
- **Masking is not deletion.** The original value is stored and anyone with `logs:Unmask` sees it: in the console (**Display**, **Unmask**), in Logs Insights with `unmask(@message)`, or with the `unmask` parameter on `GetLogEvents`/`FilterLogEvents`. `CloudWatchLogsFullAccess` includes `logs:Unmask`.

### Dashboards, Synthetics, metric streams and the agent

**Dashboard sharing.** CloudWatch can share a dashboard with up to five email addresses (each user sets a password), **publicly with anyone who has the link**, or for all dashboards through a SAML identity provider integrated with Amazon Cognito. Sharing creates Cognito resources in `us-east-1` and an IAM role (AWS's documented permissions reference roles under `service-role/` with names starting `CWDBSharing`) that viewers' sessions use. AWS warns that everyone the dashboard is shared with gets the role's permissions **for the account**, and that `cloudwatch:GetMetricData` and `ec2:DescribeTags` cannot be scoped: viewers can query *all* metrics and the names and tags of *all* EC2 instances, not just what the dashboard shows. Logs widgets, custom widgets (Lambda) and composite alarms are hidden unless someone adds `logs:StartQuery`/`logs:GetQueryResults`, `lambda:InvokeFunction` or `cloudwatch:DescribeAlarms` to that role, and AWS explicitly warns against doing so with `Resource: "*"`. A public dashboard whose sharing role has been given `logs:StartQuery` on `*` is unauthenticated read access to every log group in the account.

**Synthetics canaries** are scheduled scripts (Node.js or Python, Puppeteer, Playwright or Selenium) that run as Lambda functions, log in to applications and check APIs. They need credentials for what they test, they store artifacts (screenshots, HAR files, logs, reports) in an S3 bucket, and they run with an execution role. AWS's security guidance: do not put secrets in the script (use Secrets Manager), note that a script passed as a zip file is visible in CloudTrail, keep tight permissions on the artifact bucket, and use the redaction settings (`restrictedUrlParameters`; headers and bodies are not logged by default, but teams turn `includeRequestHeaders`, `includeResponseHeaders`, `includeRequestBody` and `includeResponseBody` on when debugging). Canary names appear in the user agent of the canary's requests, so names should not reveal anything sensitive.

**Metric streams** send metrics continuously to Firehose, often to third-party observability vendors. Metric data is usually low sensitivity, but names and dimensions describe the estate, and a stream to an unexpected destination is worth a question.

**The CloudWatch agent** on EC2 and on-premises servers ships logs and metrics. Two details matter for security. The AWS managed `CloudWatchAgentServerPolicy` grants, on `Resource: "*"`, `logs:PutLogEvents`, `logs:CreateLogGroup`, `logs:CreateLogStream` and **`logs:PutRetentionPolicy`**, plus `ssm:GetParameter` on `parameter/AmazonCloudWatch-*`: every instance with that policy can write events into *any* log group in the account (including the CloudTrail log group that the CIS alarms read) and change *any* log group's retention. And agent configuration is commonly stored in Systems Manager parameters named `AmazonCloudWatch-*` and pushed with the `AmazonCloudWatch-ManageAgent` document, so whoever can write those parameters decides which files on the hosts get shipped to CloudWatch Logs. On-premises agents often authenticate with IAM user access keys in a credentials file on the server; IAM Roles Anywhere or Systems Manager hybrid activations avoid long-term keys.

### Retention and cost trade-offs

| Decision | Security effect | Cost effect |
|---|---|---|
| Never expire (default) | Evidence kept; so are secrets and personal data, indefinitely, against data-minimisation duties | Storage grows forever |
| Short retention (days) | Investigations beyond that window are impossible from CloudWatch | Cheapest |
| 365 days or more on security log groups | Meets most regulatory expectations and Security Hub CSPM `CloudWatch.16` (default 365) | Moderate |
| Essentials class | No metric filters, subscriptions, Live Tail or `GetLogEvents`; fine for forensic archives queried by Logs Insights, wrong for anything that drives alarms | Lower ingestion price; same storage and query price |
| Archive to S3 (Firehose) and short CloudWatch retention | Long retention under S3 controls (Object Lock, lifecycle), but alarms and Live Tail only see the short window | Usually cheapest at scale |
| Logs Insights over wide ranges | Better investigations | Billed per GB scanned; field indexes reduce it |

A sensible default for clients: CloudTrail and security log groups Standard class, 365 days or more, KMS-encrypted, deletion protection on; application logs retention set by data classification (often 30–90 days) with data protection policies; long-term archive in the log-archive account's S3.

## What goes wrong

### As a security control

**The CIS alarms do not exist, or exist and lead nowhere.** Metric filters without alarms, alarms with `ActionsEnabled: false`, alarms pointing to an SNS topic with no confirmed subscriptions, or to a KMS-encrypted topic CloudWatch cannot use. The dashboard is green and nobody is ever paged.

**The filters are on the wrong log group.** The metric filter is attached to a log group the trail stopped writing to months ago (a renamed log group, a CloudTrail-to-CloudWatch delivery error, or a trail replaced by an organisation trail whose log group lives in the management account).

**EventBridge rules in one Region.** Rules for sign-ins and EC2 changes exist only in the home Region; IAM rules are missing from `us-east-1`; nobody noticed because the test was done in the home Region.

**Read-only events never match.** A rule meant to catch `GetSecretValue` storms or denied enumeration calls is in state `ENABLED`, so it never sees read-only management events.

**Targets fail silently.** Lambda targets throwing errors, SNS publish failures, API destinations returning 401; `FailedInvocations` climbing with no dead-letter queue and no alarm on the failures.

**Findings are generated and not routed.** GuardDuty and Security Hub are enabled and produce High findings that sit in the console because there is no EventBridge rule sending them anywhere.

**The monitoring layer can be switched off by the people it monitors.** Workload administrators can delete alarms, disable rules, unsubscribe the SNS topic, or shorten the retention of the CloudTrail log group, and none of those actions are alerted.

### As an attack surface

**Secrets in logs.** Lambda functions that log the whole incoming event (for API Gateway proxy integrations that includes the `Authorization` header, cookies and the request body), debug logging left on in production, SDK or HTTP client debug output that prints headers, stack traces with connection strings, API Gateway execution logging with data tracing on (API Gateway redacts authorization headers and API key values, but request and response payloads such as login bodies and returned tokens are logged), and Synthetics artifacts with HAR files. Each turns `logs:FilterLogEvents` into credential access.

**Personal data in logs.** Email addresses, names, phone numbers, card numbers, health data. A data protection problem first (retention, access, subject rights), a security problem second.

**Read access far wider than intended.** `ReadOnlyAccess` on every developer, third-party monitoring vendors with `CloudWatchLogsReadOnlyAccess`, a CI role with `logs:*`. Combined with secrets in logs this is a privilege escalation path: read a token from the logs, use it.

**Unexpected copies.** Subscription filters and destinations pointing to accounts outside the organisation, account-level subscription policies nobody remembers creating, export tasks to third-party buckets, OAM links from production to a sink in an account the security team does not own.

**Public dashboards.** Shared "temporarily" for a wall display or a vendor, still public a year later, with a sharing role that has been widened to make logs widgets work.

**Canary credentials.** Test-user passwords hard-coded in canary scripts or environment variables, HAR files with session cookies in an artifact bucket readable by many, canary execution roles with broad permissions.

**Log injection and forged evidence.** Any principal with `logs:PutLogEvents` on the CloudTrail log group (which `CloudWatchAgentServerPolicy` grants every agent instance) can write events that look like CloudTrail records. They will not be in S3 or pass integrity validation, but they can trigger or confuse alarms and mislead an analyst who only looks in CloudWatch.

## Testing

All tests assume an **authorised engagement against the client's own AWS accounts**, with written scope, and respect for the [AWS penetration testing policy](https://aws.amazon.com/security/penetration-testing/). They are read-only unless marked **lab or explicitly approved only**. Scanning log *content* for secrets reads client data: agree it in writing, run it only on the client's log groups, keep results inside the engagement environment, and **redact** any secret or personal data in the report (log group, stream, timestamp and type of secret are enough). **Outputs shown are illustrative.**

### Before you start

**Access.** `SecurityAudit` covers configuration (log groups, metric filters, alarms, rules, bus policies, subscription filters, OAM sinks and links, Synthetics, dashboards list) but **not log content**. For [GT-AWS-CW-6](#gt-aws-cw-6-secrets-and-personal-data-in-log-groups) you need an agreed, time-boxed grant of `logs:StartQuery`, `logs:GetQueryResults` and `logs:StopQuery` on the in-scope log groups (and `kms:Decrypt` via `logs` if they use customer managed keys). Do **not** ask for `logs:Unmask`; if masking hides something, that is the control working. You also need `sns:ListSubscriptionsByTopic` and `sns:GetTopicAttributes`, `events:List*`/`Describe*`, `oam:List*`/`Get*`, `synthetics:Describe*`, `cognito-identity:ListIdentityPools`/`DescribeIdentityPool` in `us-east-1`, and `iam:Get*`/`List*`.

**Inputs from the client.** Which log group(s) CloudTrail writes to, where alerts are supposed to go and who answers them, which accounts are allowed to receive logs (central logging, SIEM, vendors), and which applications handle credentials or personal data.

**Profiles, Regions and a log group inventory.**

```bash
export AWS_PROFILE=client-audit
REGIONS=$(aws ec2 describe-regions --query 'Regions[].RegionName' --output text)

for r in $REGIONS; do
  aws logs describe-log-groups --region "$r" --output json \
    | jq -r --arg r "$r" '.logGroups[] | [$r, .logGroupName, (.retentionInDays // "never"),
        (.kmsKeyId // "-"), (.logGroupClass // "STANDARD"), (.dataProtectionStatus // "-"),
        (.deletionProtectionEnabled // false), .storedBytes] | @tsv'
done > loggroups.tsv
wc -l loggroups.tsv
```

**Tools.** AWS CLI v2, `jq`, Python 3 with `boto3` for the coverage script; [Prowler](https://github.com/prowler-cloud/prowler) (`prowler aws --services cloudwatch eventbridge sns oam`); ScoutSuite; Steampipe for SQL over metric filters and alarms. Pacu's `cloudwatch__download_logs` module downloads log content with the current credentials: useful for showing what a compromised read role exposes, but it pulls client data in bulk, so use it only with explicit approval and a narrow scope. Prowler's `cloudwatch_log_group_no_secrets_in_logs` check also reads log events to look for secrets; treat it as content access and get the same approval.

### GT-AWS-CW-1: CIS metric filter and alarm coverage

*Guler Tech methodology.*

#### What it checks

For each of the fifteen CIS monitoring areas, whether a metric filter on the **live** CloudTrail log group covers it, whether an alarm watches the filter's metric, and whether that alarm has enabled actions pointing at an SNS topic with confirmed subscriptions. It checks coverage semantically (the right event names are in the pattern), not just the exact CIS string, and reports the exact-match question separately.

#### Prerequisites

`SecurityAudit` plus `sns:ListSubscriptionsByTopic` in the account and Region that own the trail's CloudWatch log group (for organisation trails, usually the management account or the delegated administrator).

#### Steps

First confirm which log group is live (see GT-AWS-CT-8 in the [CloudTrail note](/cloud/aws-cloudtrail-logging/)): `CloudWatchLogsLogGroupArn` on the trail and a recent `LatestCloudWatchLogsDeliveryTime`. Then run:

```python
#!/usr/bin/env python3
"""Read-only CIS CloudWatch monitoring coverage check.
Usage: python3 cis_cw_check.py <cloudtrail-log-group-name> [region]
"""
import re
import sys
import boto3

CIS = {
    "4.1 unauthorised API calls": ["UnauthorizedOperation", "AccessDenied"],
    "4.2 console sign-in without MFA": ["ConsoleLogin", "MFAUsed"],
    "4.3 root usage": ["Root", "invokedBy", "AwsServiceEvent"],
    "4.4 IAM policy changes": ["DeleteGroupPolicy", "DeleteRolePolicy", "DeleteUserPolicy",
        "PutGroupPolicy", "PutRolePolicy", "PutUserPolicy", "CreatePolicy", "DeletePolicy",
        "CreatePolicyVersion", "DeletePolicyVersion", "AttachRolePolicy", "DetachRolePolicy",
        "AttachUserPolicy", "DetachUserPolicy", "AttachGroupPolicy", "DetachGroupPolicy"],
    "4.5 CloudTrail changes": ["CreateTrail", "UpdateTrail", "DeleteTrail", "StartLogging", "StopLogging"],
    "4.6 console authentication failures": ["ConsoleLogin", "Failed authentication"],
    "4.7 CMK disable or deletion": ["kms.amazonaws.com", "DisableKey", "ScheduleKeyDeletion"],
    "4.8 S3 bucket policy changes": ["PutBucketAcl", "PutBucketPolicy", "PutBucketCors",
        "PutBucketLifecycle", "PutBucketReplication", "DeleteBucketPolicy", "DeleteBucketCors",
        "DeleteBucketLifecycle", "DeleteBucketReplication"],
    "4.9 AWS Config changes": ["StopConfigurationRecorder", "DeleteDeliveryChannel",
        "PutDeliveryChannel", "PutConfigurationRecorder"],
    "4.10 security group changes": ["AuthorizeSecurityGroupIngress", "AuthorizeSecurityGroupEgress",
        "RevokeSecurityGroupIngress", "RevokeSecurityGroupEgress", "CreateSecurityGroup",
        "DeleteSecurityGroup"],
    "4.11 NACL changes": ["CreateNetworkAcl", "CreateNetworkAclEntry", "DeleteNetworkAcl",
        "DeleteNetworkAclEntry", "ReplaceNetworkAclEntry", "ReplaceNetworkAclAssociation"],
    "4.12 network gateway changes": ["CreateCustomerGateway", "DeleteCustomerGateway",
        "AttachInternetGateway", "CreateInternetGateway", "DeleteInternetGateway",
        "DetachInternetGateway"],
    "4.13 route table changes": ["CreateRoute", "CreateRouteTable", "ReplaceRoute",
        "ReplaceRouteTableAssociation", "DeleteRouteTable", "DeleteRoute", "DisassociateRouteTable"],
    "4.14 VPC changes": ["CreateVpc", "DeleteVpc", "ModifyVpcAttribute", "AcceptVpcPeeringConnection",
        "CreateVpcPeeringConnection", "DeleteVpcPeeringConnection", "RejectVpcPeeringConnection"],
    "4.15 Organizations changes": ["organizations.amazonaws.com", "AttachPolicy", "CreateAccount",
        "DetachPolicy", "InviteAccountToOrganization", "LeaveOrganization", "MoveAccount",
        "RemoveAccountFromOrganization", "UpdatePolicy"],
}


def covers(pattern, tokens):
    return all(re.search(r"(?<![A-Za-z])" + re.escape(t) + r"(?![A-Za-z])", pattern) for t in tokens)


def topic_status(sns, arn):
    try:
        subs = []
        for page in sns.get_paginator("list_subscriptions_by_topic").paginate(TopicArn=arn):
            subs.extend(page["Subscriptions"])
    except Exception as exc:  # cross-account topic or missing permission
        return "UNKNOWN (" + type(exc).__name__ + ")"
    confirmed = [s for s in subs if s["SubscriptionArn"].startswith("arn:")]
    pending = len(subs) - len(confirmed)
    if not confirmed:
        return "NO CONFIRMED SUBSCRIPTIONS (pending: %d)" % pending
    protocols = sorted(set(s["Protocol"] for s in confirmed))
    return "OK %d confirmed %s" % (len(confirmed), ",".join(protocols))


def main():
    log_group = sys.argv[1]
    region = sys.argv[2] if len(sys.argv) > 2 else None
    logs = boto3.client("logs", region_name=region)
    cw = boto3.client("cloudwatch", region_name=region)
    sns = boto3.client("sns", region_name=region)

    filters = []
    for page in logs.get_paginator("describe_metric_filters").paginate(logGroupName=log_group):
        filters.extend(page["metricFilters"])
    print("%d metric filters on %s" % (len(filters), log_group))

    for control, tokens in CIS.items():
        matching = [f for f in filters if covers(f["filterPattern"], tokens)]
        if not matching:
            print("FAIL  %-36s no metric filter covers it" % control)
            continue
        verdict = "FAIL"
        for f in matching:
            for mt in f["metricTransformations"]:
                alarms = cw.describe_alarms_for_metric(
                    MetricName=mt["metricName"], Namespace=mt["metricNamespace"])["MetricAlarms"]
                if not alarms:
                    print("      %-36s filter %s: metric has no alarm" % (control, f["filterName"]))
                for a in alarms:
                    if not a.get("ActionsEnabled"):
                        print("      %-36s alarm %s: actions DISABLED" % (control, a["AlarmName"]))
                        continue
                    topics = [x for x in a.get("AlarmActions", []) if ":sns:" in x]
                    if not topics:
                        print("      %-36s alarm %s: no SNS action" % (control, a["AlarmName"]))
                    for t in topics:
                        status = topic_status(sns, t)
                        print("      %-36s alarm %s -> %s: %s" % (control, a["AlarmName"], t, status))
                        if status.startswith("OK"):
                            verdict = "PASS"
        print("%s  %s" % (verdict, control))


if __name__ == "__main__":
    main()
```

Run it per Region for every trail log group that is meant to drive alerts:

```bash
python3 cis_cw_check.py aws-cloudtrail-logs-org eu-west-2 | tee cis_cw.txt
```

For the exact-match question (what Security Hub CSPM reports), compare `aws logs describe-metric-filters --log-group-name <lg> --query 'metricFilters[].filterPattern'` with the patterns in [The CIS monitoring filters](#the-cis-monitoring-filters), or read the Security Hub CSPM findings for `CloudWatch.1`–`CloudWatch.14`. Prowler's `cloudwatch_log_metric_filter_*` and `cloudwatch_changes_to_*_alarm_configured` checks give a second opinion.

If the client uses EventBridge or a SIEM instead, ask for the rule definitions per CIS area and evaluate them in [GT-AWS-CW-3](#gt-aws-cw-3-eventbridge-security-rules-and-target-health).

#### Observation

```text
16 metric filters on aws-cloudtrail-logs-org
PASS  4.1 unauthorised API calls
      4.2 console sign-in without MFA     alarm CIS-NoMFASignIn -> arn:aws:sns:eu-west-2:111122223333:cis-alerts: NO CONFIRMED SUBSCRIPTIONS (pending: 1)
FAIL  4.2 console sign-in without MFA
PASS  4.3 root usage
      4.5 CloudTrail changes              alarm CIS-CloudTrailChanges: actions DISABLED
FAIL  4.5 CloudTrail changes
FAIL  4.15 Organizations changes         no metric filter covers it
...
```

(Illustrative.)

#### Evaluation

- **Pass** per area: a filter covering the events, on the live log group, an alarm with actions enabled, an SNS topic with at least one confirmed subscription to a monitored destination; or an equivalent EventBridge or SIEM rule proven in GT-AWS-CW-3.
- **Fail** per area: any broken link in that chain. Report the areas, not just a count; "no alert for CloudTrail configuration changes or root usage" is a different finding from "no alert for NACL changes".
- **False positives**: Security Hub CSPM shows `NO_DATA` for these controls in member accounts that use an organisation trail owned elsewhere, and `FAILED` where a perfectly good filter differs from the CIS string by one space. Base your finding on the chain, and mention the compliance-report impact separately.

#### Automated coverage

Security Hub CSPM `CloudWatch.1`–`CloudWatch.14` (exact CIS patterns), `CloudWatch.15`, `CloudWatch.17`; CIS AWS v1.4.0 4.1–4.15 (v3.0.0 4.1–4.15 are manual); Prowler `cloudwatch_log_metric_filter_unauthorized_api_calls`, `cloudwatch_log_metric_filter_sign_in_without_mfa`, `cloudwatch_log_metric_filter_root_usage`, `cloudwatch_log_metric_filter_policy_changes`, `cloudwatch_log_metric_filter_and_alarm_for_cloudtrail_configuration_changes_enabled`, `cloudwatch_log_metric_filter_authentication_failures`, `cloudwatch_log_metric_filter_disable_or_scheduled_deletion_of_kms_cmk`, `cloudwatch_log_metric_filter_for_s3_bucket_policy_changes`, `cloudwatch_log_metric_filter_and_alarm_for_aws_config_configuration_changes_enabled`, `cloudwatch_log_metric_filter_security_group_changes`, `cloudwatch_changes_to_network_acls_alarm_configured`, `cloudwatch_changes_to_network_gateways_alarm_configured`, `cloudwatch_changes_to_network_route_tables_alarm_configured`, `cloudwatch_changes_to_vpcs_alarm_configured`, `cloudwatch_log_metric_filter_aws_organizations_changes`.

#### Detection

`DeleteMetricFilter`, `PutMetricFilter` (a pattern quietly changed), `DeleteAlarms`, `DisableAlarmActions`, `PutMetricAlarm` (actions removed), SNS `Unsubscribe`, `DeleteTopic`, `SetTopicAttributes`.

### GT-AWS-CW-2: Alarm actions and SNS delivery

*Guler Tech methodology.*

#### What it checks

Beyond the CIS set: that security-relevant alarms in every Region have enabled actions, that their SNS topics deliver (subscriptions confirmed, encryption compatible, no failures), and that topic policies do not let outsiders subscribe or publish.

#### Prerequisites

`SecurityAudit`, `sns:ListSubscriptionsByTopic`, `sns:GetTopicAttributes`, `kms:GetKeyPolicy` on topic keys.

#### Steps

```bash
# Alarms without actions, or with actions disabled
for r in $REGIONS; do
  aws cloudwatch describe-alarms --region "$r" --alarm-types MetricAlarm CompositeAlarm --output json \
    | jq -r --arg r "$r" '(.MetricAlarms // [])[], (.CompositeAlarms // [])[]
        | select((.ActionsEnabled|not) or ((.AlarmActions // [])|length==0))
        | [$r, .AlarmName, .ActionsEnabled, ((.AlarmActions // [])|join(","))] | @tsv'
done

# Did alarm actions actually run, and did they fail?
aws cloudwatch describe-alarm-history --alarm-name CIS-RootUsage --history-item-type Action \
  --max-records 20 --query 'AlarmHistoryItems[].[Timestamp,HistorySummary]' --output text

# Topic health
T=arn:aws:sns:eu-west-2:111122223333:security-alerts
aws sns get-topic-attributes --topic-arn "$T" \
  --query 'Attributes.[SubscriptionsConfirmed,SubscriptionsPending,KmsMasterKeyId,Policy]' --output text
aws sns list-subscriptions-by-topic --topic-arn "$T" \
  --query 'Subscriptions[].[Protocol,Endpoint,SubscriptionArn]' --output text
aws cloudwatch get-metric-statistics --namespace AWS/SNS --metric-name NumberOfNotificationsFailed \
  --dimensions Name=TopicName,Value=security-alerts --statistics Sum --period 86400 \
  --start-time "$(date -u -v-30d +%FT%TZ 2>/dev/null || date -u -d '-30 days' +%FT%TZ)" --end-time "$(date -u +%FT%TZ)"
```

For KMS-encrypted topics, read the key policy: CloudWatch alarms and EventBridge need `kms:Decrypt` and `kms:GenerateDataKey*` for `cloudwatch.amazonaws.com` and `events.amazonaws.com` respectively, or publishing fails. For the topic policy, look for `"Principal": "*"` or `{"AWS": "*"}` on `sns:Subscribe`, `sns:Receive` or `sns:Publish` without an `aws:SourceAccount`, `aws:SourceArn` or `aws:PrincipalOrgID` condition.

**Active proof (lab or explicitly approved only):** set one alarm to `ALARM` briefly and confirm a human receives it, then let it return to its real state.

```bash
# Lab or explicitly approved only: changes alarm state and sends a real notification
aws cloudwatch set-alarm-state --alarm-name CIS-RootUsage --state-value ALARM \
  --state-reason "Guler Tech authorised alert-path test, ticket SEC-0000"
```

#### Observation

```text
eu-west-2  CIS-RootUsage   true   arn:aws:sns:eu-west-2:111122223333:cis-alerts
2026-09-14T03:12:09Z  Failed to execute action arn:aws:sns:eu-west-2:111122223333:cis-alerts. Received error: "CloudWatch Alarms does not have authorization to access the SNS topic encryption key."
```

(Illustrative: a KMS-encrypted topic whose key policy omits the CloudWatch service principal.)

#### Evaluation

- **Pass**: every security alarm has enabled actions; topics have confirmed subscriptions to monitored destinations (a team mailbox, an on-call tool, a chat channel with an owner), no notification failures, compatible key policies, and topic policies limited to the account or organisation.
- **Fail**: disabled actions, no actions, only pending subscriptions, delivery failures, or individual mailboxes of people who have left. Topic policy allowing anyone to subscribe is its own finding (alert content leaks: resource names, principals, IPs) and allowing anyone to publish lets outsiders flood or spoof the alert channel.

#### Automated coverage

Security Hub CSPM `CloudWatch.15`, `CloudWatch.17`, `SNS.1`, `SNS.4`; Prowler `cloudwatch_alarm_actions_enabled`, `cloudwatch_alarm_actions_alarm_state_configured`, `sns_topics_not_publicly_accessible`, `sns_topics_kms_encryption_at_rest_enabled`, `sns_subscription_not_using_http_endpoints`.

#### Detection

`DisableAlarmActions`, `DeleteAlarms`, `PutMetricAlarm`, `SetAlarmState` (outside approved tests), SNS `Unsubscribe`, `Subscribe` (a new endpoint on the security topic), `SetTopicAttributes`, `DeleteTopic`.

### GT-AWS-CW-3: EventBridge security rules and target health

*Guler Tech methodology.*

#### What it checks

That EventBridge rules exist for the security events the client relies on (GuardDuty and Security Hub findings, root and no-MFA sign-ins, IAM and logging changes), in every Region where those events occur, with the right state, and that their targets are actually invoked without failures.

#### Prerequisites

`SecurityAudit` (includes `events:List*`/`Describe*`), `cloudwatch:GetMetricStatistics`.

#### Steps

```bash
for r in $REGIONS; do
  aws events list-rules --region "$r" --output json \
    | jq -r --arg r "$r" '.Rules[] | [$r, .Name, .State, (.EventBusName // "default"), (.EventPattern // "-" | gsub("\\s";""))] | @tsv'
done > rules.tsv

# Coverage questions, answered from rules.tsv
grep -c 'aws.guardduty' rules.tsv
grep 'us-east-1' rules.tsv | grep -c 'iam.amazonaws.com\|aws.iam'
grep -c 'AWS Console Sign' rules.tsv
grep -c 'ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS' rules.tsv

# Targets, DLQs and recent failures for one rule
aws events list-targets-by-rule --rule guardduty-high-to-sns --region eu-west-2 \
  --query 'Targets[].[Id,Arn,RoleArn,DeadLetterConfig.Arn]' --output text
for m in MatchedEvents Invocations FailedInvocations; do
  echo "$m: $(aws cloudwatch get-metric-statistics --namespace AWS/Events --metric-name $m \
    --dimensions Name=RuleName,Value=guardduty-high-to-sns --statistics Sum --period 2592000 \
    --start-time "$(date -u -v-30d +%FT%TZ 2>/dev/null || date -u -d '-30 days' +%FT%TZ)" \
    --end-time "$(date -u +%FT%TZ)" --region eu-west-2 --query 'Datapoints[0].Sum' --output text)"
done
```

Test patterns without sending any events: `test-event-pattern` evaluates a pattern against a sample event locally in the service and changes nothing.

```bash
aws events test-event-pattern --event-pattern file://root-usage-pattern.json \
  --event file://sample-root-consolelogin.json
# {"Result": true}
```

(The sample event needs the envelope fields `id`, `detail-type`, `source`, `account`, `time`, `region`, `resources` and a `detail` object; build it from the AWS sign-in event example with documentation account IDs.)

Also check that GuardDuty is publishing to EventBridge at the frequency the client expects (its finding publishing frequency setting affects updates to existing findings) and, for the new Security Hub, that rules use `Findings Imported V2` if the client has migrated.

#### Observation

GuardDuty rule present only in `eu-west-2` although GuardDuty is enabled in all Regions; no rules in `us-east-1` at all; sign-in rule in `eu-west-2` only; one rule with `FailedInvocations` > 0 and no dead-letter queue.

#### Evaluation

- **Pass**: for each security event type the client depends on, a rule in every Region where the event can occur (or forwarding from every Region to a central bus with rules there), correct state for read-only events where needed, targets with zero or explained `FailedInvocations`, dead-letter queues on targets where loss matters, and an owner for each destination.
- **Fail**: missing Regions (especially `us-east-1` for IAM and the sign-in Regions listed above), findings not routed, targets failing, rules `DISABLED`.
- GuardDuty with a delegated administrator: findings from member accounts appear in the administrator account's Region; routing there is enough for those findings, but not for CloudTrail-based rules, which are per account.

#### Automated coverage

None directly; Prowler `eventbridge_*` checks cover bus exposure, not rule coverage. Security Hub CSPM `EventBridge.4` covers global endpoint replication only.

#### Detection

`DeleteRule`, `DisableRule`, `PutRule` (pattern changed), `RemoveTargets`, `PutTargets` (target swapped), `DeleteEventBus`, `DeleteConnection`, `DeleteApiDestination`; `FailedInvocations` alarms.

### GT-AWS-CW-4: Event bus policies and cross-account routing

*Guler Tech methodology.*

#### What it checks

That event bus resource policies only admit accounts in the organisation, that no other account can create rules on the client's buses, and that rules do not route events to accounts or HTTPS endpoints outside the client's control.

#### Prerequisites

`SecurityAudit`; the client's list of their account IDs and organisation ID.

#### Steps

```bash
for r in $REGIONS; do
  aws events list-event-buses --region "$r" --output json \
    | jq -r --arg r "$r" '.EventBuses[] | [$r, .Name, (.Policy // "-")] | @tsv'
done

# Rules created by other accounts, and targets in other accounts (default bus;
# repeat with --event-bus-name for each custom bus)
ME=$(aws sts get-caller-identity --query Account --output text)
for r in $REGIONS; do
  for rule in $(aws events list-rules --region "$r" --query 'Rules[].Name' --output text); do
    aws events describe-rule --name "$rule" --region "$r" --query '[Name,CreatedBy,ManagedBy]' --output text
    aws events list-targets-by-rule --rule "$rule" --region "$r" --query 'Targets[].Arn' --output text \
      | tr '\t' '\n' | awk -F: -v me="$ME" -v r="$r" -v rule="$rule" '$5!=me && $5!="" {print "  external target:", r, rule, $0}'
  done
done

# API destinations (events sent to arbitrary HTTPS endpoints)
aws events list-api-destinations --query 'ApiDestinations[].[Name,InvocationEndpoint,ConnectionArn]' --output text
aws events list-connections --query 'Connections[].[Name,AuthorizationType,ConnectionState]' --output text
```

Review each bus policy statement: `Principal` `*` without `aws:PrincipalOrgID`; `events:PutRule`/`events:PutTargets` granted to other accounts; account principals that are not on the client's list.

#### Observation

A central security bus that accepts `PutEvents` from `"Principal": "*"` with no condition; a rule on a workload account's default bus forwarding all `aws.guardduty` events to a bus in an account not in the organisation (a former MSSP).

#### Evaluation

- **Pass**: bus policies scoped by `aws:PrincipalOrgID` or named accounts; no cross-account `PutRule`/`PutTargets` unless designed and conditioned; every external target and API destination identified and owned by the client or a contracted provider under current agreement.
- **Fail**: open `PutEvents` (spoofed custom events, cost abuse, rule-triggered automation fed by outsiders); cross-account rule creation (another account can copy the client's events); events routed to accounts or endpoints that nobody can explain. Rate by what flows: CloudTrail and findings forwarded to an unknown account is a High data exposure.

#### Automated coverage

Security Hub CSPM `EventBridge.3` (custom buses should have a resource policy attached); Prowler `eventbridge_bus_cross_account_access`, `eventbridge_bus_exposed`, `eventbridge_schema_registry_cross_account_access`.

#### Detection

`PutPermission`, `RemovePermission`, `CreateEventBus` with policy, `PutTargets` with cross-account ARNs, `CreateApiDestination`, `CreateConnection` (the connection's secret is stored in Secrets Manager; see the [Secrets Manager note](/cloud/aws-secrets-manager-parameter-store-kms/)). Map events copied to other accounts to [T1537](https://attack.mitre.org/techniques/T1537/).

### GT-AWS-CW-5: Log group retention, class, encryption and deletion protection

*Guler Tech methodology.*

#### What it checks

That security-relevant log groups keep data long enough, in the right class, encrypted with a key the client controls, and protected from deletion; and that application log groups do not keep sensitive data forever.

#### Prerequisites

`loggroups.tsv` from [Before you start](#before-you-start); `kms:GetKeyPolicy` on referenced keys.

#### Steps

```bash
# Security log groups (CloudTrail, VPC Flow Logs, Route 53 resolver, EKS audit, WAF, GuardDuty exports...)
grep -E -i 'cloudtrail|flow|vpc|resolver|eks|waf|security|audit' loggroups.tsv

# Retention below 365 days on those, or "never" on application groups
awk -F'\t' '$3!="never" && $3<365' loggroups.tsv
awk -F'\t' '$3=="never"' loggroups.tsv | wc -l

# No customer managed key / no deletion protection / Essentials class on alert-driving groups
awk -F'\t' '$4=="-"' loggroups.tsv | wc -l
awk -F'\t' '$7=="false"' loggroups.tsv | grep -i -E 'cloudtrail|flow|audit'
awk -F'\t' '$5!="STANDARD"' loggroups.tsv

# Key policy for a log group key
aws kms get-key-policy --key-id arn:aws:kms:eu-west-2:111122223333:key/EXAMPLE-KEY-ID \
  --policy-name default --output text | jq '.Statement[] | select(.Principal.Service // "" | test("logs"))'
```

#### Observation

CloudTrail log group with 14-day retention (the alarms work, but the investigation window in CloudWatch is two weeks), no KMS key, no deletion protection; 600 Lambda log groups set to never expire.

#### Evaluation

- **Pass**: security log groups ≥ 365 days (or shorter with a documented archive elsewhere), Standard class where they drive alarms or subscriptions, customer managed key whose policy uses the `kms:EncryptionContext:aws:logs:arn` condition, deletion protection on; application log groups with retention aligned to data classification.
- **Fail**: short retention on security groups without an archive; Essentials class on the CloudTrail log group (metric filters silently impossible); keys administered by workload admins; never-expiring groups holding personal data (data protection issue, report to the client's DPO as well).

#### Automated coverage

Security Hub CSPM `CloudWatch.16` (default minimum 365 days); Prowler `cloudwatch_log_group_retention_policy_specific_days_enabled`, `cloudwatch_log_group_kms_encryption_enabled`.

#### Detection

`PutRetentionPolicy`, `DeleteLogGroup`, `DeleteLogStream`, `DisassociateKmsKey`, `PutLogGroupDeletionProtection` (protection turned off), KMS `DisableKey`/`ScheduleKeyDeletion` on log keys.

### GT-AWS-CW-6: Secrets and personal data in log groups

*Guler Tech methodology.*

#### What it checks

Whether the client's log groups contain credentials (bearer tokens, API keys, AWS keys, private keys, passwords, session cookies) or personal data, which would turn any log read permission into credential access or a data breach.

#### Prerequisites

Written approval for content access; the scoped Logs Insights grant described in [Before you start](#before-you-start); an agreed list of log groups (start with API Gateway execution logs, Lambda functions that sit behind APIs or handle authentication, application logs at `DEBUG`, Synthetics, and anything named `*auth*`, `*login*`, `*payment*`). Agree a time window (seven days is usually enough) because Logs Insights bills per GB scanned.

#### Steps

Run one query per batch of log groups; the query returns **counts per log stream and pattern**, not the matched values.

```bash
cat > secret-scan.insights <<'Q'
fields @log, @logStream
| filter @message like /(?i)(authorization["']?\s*[:=]\s*["']?bearer\s|x-api-key|api[_-]?key["']?\s*[:=]|client_secret|secret[_-]?access[_-]?key|"password"\s*:|passwd=|set-cookie:|-----BEGIN [A-Z ]*PRIVATE KEY-----|A[KS]IA[0-9A-Z]{16}|[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,})/
| stats count(*) as hits by @log, @logStream
| sort hits desc
| limit 100
Q

START=$(( $(date +%s) - 7*24*3600 )); END=$(date +%s)
QID=$(aws logs start-query --region eu-west-2 \
  --log-group-names /aws/lambda/auth-handler API-Gateway-Execution-Logs_a1b2c3d4e5/prod \
  --start-time "$START" --end-time "$END" --query-string "$(cat secret-scan.insights)" \
  --query queryId --output text)
sleep 20   # poll until status is Complete
aws logs get-query-results --query-id "$QID" --region eu-west-2 --output json \
  | jq -r '.status, (.results[] | map({(.field): .value}) | add | [.["@log"], .["@logStream"], .hits] | @tsv)'
```

For each log group with hits, confirm **one** example by hand (a Logs Insights query with `fields @timestamp, @message | limit 1` on that stream and pattern), classify the secret type, and record log group, stream, timestamp and type. Do not copy the value into notes or the report. If the secret is live and high impact (AWS keys, production API keys, admin tokens), stop and tell the client's contact immediately so they can rotate it; do not test whether it works unless the client explicitly asks you to (and then only `sts get-caller-identity` or the equivalent harmless identity call).

Personal data: run a second query with patterns for email addresses and the client's own identifiers (customer numbers, national identifiers relevant to them) and report counts per log group.

Then look at the *sources*:

```bash
# API Gateway stages with execution logging at INFO and full request/response data
aws apigateway get-stages --rest-api-id a1b2c3d4e5 \
  --query 'item[].[stageName, methodSettings."*/*".loggingLevel, methodSettings."*/*".dataTraceEnabled]' --output text

# Lambda functions with debug-style log levels (advanced logging controls)
aws lambda list-functions --query 'Functions[].[FunctionName, LoggingConfig.ApplicationLogLevel, LoggingConfig.LogGroup]' --output text
```

`dataTraceEnabled: true` on an API Gateway stage logs full request and response data. API Gateway redacts authorization headers, API key values and similar request parameters, but payloads (passwords in login bodies, tokens returned by token endpoints, personal data) are logged, and AWS recommends not using data tracing for production APIs. Stages that use CloudWatch Logs delivery for execution logs keep events of up to 1 MB rather than 1 KB, so more of each payload survives. See the [API Gateway note](/cloud/aws-api-gateway-sns-sqs-security/) and the [Lambda note](/cloud/aws-lambda-serverless-security/).

#### Observation

```text
/aws/lambda/auth-handler                         2026/10/29/[$LATEST]5f1c...   412
API-Gateway-Execution-Logs_a1b2c3d4e5/prod       0d8c1e...                     1730
```

(Illustrative: an authorisation Lambda that logs incoming events with `Authorization` headers, and an API stage with data tracing on.)

#### Evaluation

- **Pass**: no credentials found in the sample; personal data only where the client's records of processing expect it, with retention and masking to match.
- **Fail**: any live credential in logs. Rate by what the credential grants and by who can read the log group ([GT-AWS-CW-8](#gt-aws-cw-8-who-can-read-and-write-logs)): an admin token in a log group readable by every `ReadOnlyAccess` user is a privilege escalation path (High); a test-environment API key readable only by the owning team is Low–Medium.
- **False positives**: the generic three-part token pattern also matches some opaque IDs and base64 data; confirm before reporting. Masked values (`****`) mean a data protection policy is working; report the source anyway, since the value is stored and visible to anyone with `logs:Unmask`.

#### Automated coverage

Prowler `cloudwatch_log_group_no_secrets_in_logs` (reads events; needs approval); Amazon Macie does not scan CloudWatch Logs directly. No Security Hub CSPM control.

#### Detection

Abuse looks like `FilterLogEvents`, `GetLogEvents`, `StartQuery`, `GetQueryResults`, `StartLiveTail` and `CreateExportTask` from principals that do not normally read logs. AWS lists all of these as recorded by CloudTrail; most are read-only calls, so the trail must record read events. Reading credentials from logs maps to [T1552](https://attack.mitre.org/techniques/T1552/); reading logs to learn the environment maps to [T1654](https://attack.mitre.org/techniques/T1654/).

### GT-AWS-CW-7: Data protection policies and logs:Unmask

*Guler Tech methodology.*

#### What it checks

Whether log groups that may receive sensitive data have data protection policies (account level or log group level), whether those policies cover the data types actually present (including custom identifiers for tokens), and who holds `logs:Unmask`.

#### Prerequisites

`SecurityAudit` plus `logs:GetDataProtectionPolicy`, `logs:DescribeAccountPolicies`, `iam:GetAccountAuthorizationDetails`.

#### Steps

```bash
aws logs describe-account-policies --policy-type DATA_PROTECTION_POLICY --output json \
  | jq -r '.accountPolicies[] | .policyName, (.policyDocument | fromjson | .Statement[].DataIdentifier[])'

for lg in $(awk -F'\t' '$6=="ACTIVATED" {print $2}' loggroups.tsv); do
  echo "== $lg"
  aws logs get-data-protection-policy --log-group-identifier "$lg" \
    --query policyDocument --output text | jq -r '.Statement[] | .Sid, .DataIdentifier[]'
done

# Who can unmask? Customer managed policies, then inline role policies, granting logs:Unmask, logs:* or *
aws iam get-account-authorization-details --output json > gaad.json
jq -r '.Policies[] | . as $p | (.PolicyVersionList[] | select(.IsDefaultVersion) | .Document.Statement)
       | (if type=="array" then .[] else . end) | select(.Effect=="Allow")
       | ((.Action // []) | if type=="string" then [.] else . end) as $a
       | select($a | any(. == "*" or . == "logs:*" or . == "logs:Unmask"))
       | [$p.PolicyName, $p.AttachmentCount, ($a | join(","))] | @tsv' gaad.json | sort -u
jq -r '.RoleDetailList[] | . as $r | (.RolePolicyList // [])[] | .PolicyDocument.Statement
       | (if type=="array" then .[] else . end) | select(.Effect=="Allow")
       | ((.Action // []) | if type=="string" then [.] else . end) as $a
       | select($a | any(. == "*" or . == "logs:*" or . == "logs:Unmask"))
       | [$r.RoleName, ($a | join(","))] | @tsv' gaad.json | sort -u
aws iam list-entities-for-policy --policy-arn arn:aws:iam::aws:policy/CloudWatchLogsFullAccess \
  --query '[PolicyRoles[].RoleName, PolicyUsers[].UserName, PolicyGroups[].GroupName]' --output text
```

Spot-check principals with `simulate-principal-policy` (identity policies only; SCPs and permission boundaries need separate review):

```bash
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::111122223333:role/DeveloperReadOnly \
  --action-names logs:Unmask logs:StartQuery logs:FilterLogEvents \
  --query 'EvaluationResults[].[EvalActionName,EvalDecision]' --output text
```

#### Observation

An account-level policy masking `EmailAddress` and `AwsSecretKey` only; GT-AWS-CW-6 found bearer tokens, which no managed identifier covers; `logs:Unmask` held by 14 roles via `CloudWatchLogsFullAccess`, including a CI deployment role.

#### Evaluation

- **Pass**: log groups that may contain sensitive data are covered (an account-level policy is the simplest way), identifiers match what GT-AWS-CW-6 found (custom identifiers for the client's token formats), the `LogEventsWithFindings` metric is alarmed, and `logs:Unmask` is limited to a small, named group with a reason to see raw values.
- **Fail**: no policy where sensitive data exists; policies that miss the data types actually present; `logs:Unmask` broadly held (often through `CloudWatchLogsFullAccess` or `*`).
- Remember the limits: masking applies from policy creation onwards, so historic data needs separate clean-up (shortening retention or deleting streams, with the client's agreement and legal hold considered).

#### Automated coverage

Prowler `cloudwatch_log_group_no_secrets_in_logs` (indirect). No Security Hub CSPM control.

#### Detection

`DeleteDataProtectionPolicy`, `PutDataProtectionPolicy`, `PutAccountPolicy`, `DeleteAccountPolicy`. Unmasking is not a separate API call: it is the `unmask` parameter on `GetLogEvents`/`FilterLogEvents` and the `unmask()` function in queries. Check in a lab whether the client's CloudTrail events for those calls show the parameter or query string in `requestParameters` (some fields are redacted in CloudTrail records); if they do, match on it.

### GT-AWS-CW-8: Who can read and write logs

*Guler Tech methodology.*

#### What it checks

The effective set of principals that can read log content in each account (and from other accounts via roles or OAM), whether that matches intent, and who can write into security log groups.

#### Prerequisites

`gaad.json` from GT-AWS-CW-7; IAM Access Analyzer if enabled; PMapper or a similar graph tool helps.

#### Steps

```bash
# Customer managed policies that grant log content reads (repeat for RoleDetailList inline policies as in GT-AWS-CW-7)
jq -r '.Policies[] | . as $p | (.PolicyVersionList[] | select(.IsDefaultVersion) | .Document.Statement)
       | (if type=="array" then .[] else . end) | select(.Effect=="Allow")
       | ((.Action // []) | if type=="string" then [.] else . end) as $a
       | select($a | any(test("^(\\*|logs:\\*|logs:Get|logs:FilterLogEvents|logs:StartQuery|logs:StartLiveTail|logs:CreateExportTask)")))
       | [$p.PolicyName, $p.AttachmentCount, ($a | join(","))] | @tsv' gaad.json | sort -u

# AWS managed read policies in use
for p in ReadOnlyAccess CloudWatchLogsReadOnlyAccess CloudWatchLogsFullAccess AdministratorAccess PowerUserAccess; do
  echo "== $p"
  aws iam list-entities-for-policy --policy-arn arn:aws:iam::aws:policy/$p \
    --query '[PolicyRoles[].RoleName, PolicyUsers[].UserName, PolicyGroups[].GroupName]' --output text
done

# Who can WRITE into the CloudTrail log group or change its retention?
aws iam list-entities-for-policy --policy-arn arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy \
  --query 'PolicyRoles[].RoleName' --output text

# Log group resource policies (service principals writing logs)
aws logs describe-resource-policies --query 'resourcePolicies[].[policyName,policyDocument]' --output text
```

For each role that can read logs, check its trust policy: roles assumable by third parties (monitoring vendors, MSSPs) or by every SSO user carry the read permission with them. See the [STS note](/cloud/aws-sts-cross-account-trust-federation/).

In log group resource policies, look for service-principal grants without `aws:SourceAccount`/`aws:SourceArn` (a confused-deputy path that lets the same service, acting for another account, write into the client's log groups) and for statements naming non-service principals (AWS does not enforce those, but they show a misunderstanding worth correcting).

#### Observation

`ReadOnlyAccess` attached to the SSO permission set used by all 120 engineers; a vendor role with `CloudWatchLogsReadOnlyAccess` assumable by the vendor's account without an external ID; `CloudWatchAgentServerPolicy` on 40 instance roles in the account that hosts the organisation trail's log group.

#### Evaluation

- **Pass**: log content readable only by the owning team for application logs and by security for security logs; vendor access scoped to specific log groups with `sts:ExternalId`; agent roles use a custom policy scoped to their own log group prefixes without `logs:PutRetentionPolicy` (or an SCP denies it outside a platform role); no agent roles in the account that holds the CloudTrail log group.
- **Fail**: broad `ReadOnlyAccess` combined with secrets or personal data in logs (rate together with GT-AWS-CW-6); `CloudWatchAgentServerPolicy` in the security or management account (instances can write forged events into, or shorten retention of, the CloudTrail log group).

#### Automated coverage

Prowler `cloudwatch_log_group_not_publicly_accessible` (resource policies); IAM Access Analyzer (external access findings do not cover identity-policy reads within the account). No Security Hub CSPM control for read breadth.

#### Detection

Unusual `StartQuery`/`FilterLogEvents`/`GetLogEvents` volume per principal; `PutRetentionPolicy` from instance roles. `PutLogEvents` is **not** in AWS's list of CloudWatch Logs actions recorded by CloudTrail, so forged events cannot be spotted from CloudTrail directly; `CreateLogStream` is recorded, so alert on `CreateLogStream` in the CloudTrail log group by anything other than the CloudTrail delivery role, and treat the S3 copy with integrity validation as the source of truth.

### GT-AWS-CW-9: Subscription filters, exports and observability links

*Guler Tech methodology.*

#### What it checks

Every path by which log data leaves a log group or an account: subscription filters, account-level subscription policies, CloudWatch Logs destinations, export tasks, OAM links and sinks, the legacy cross-account sharing role, and centralisation rules.

#### Prerequisites

`SecurityAudit` plus `logs:DescribeSubscriptionFilters`, `logs:DescribeDestinations`, `logs:DescribeExportTasks`, `oam:List*`/`Get*`; the client's list of their accounts and organisation ID.

#### Steps

```bash
ORG_ACCOUNTS=$(aws organizations list-accounts --query 'Accounts[].Id' --output text 2>/dev/null)

# 1. Subscription filters on every log group
for r in $REGIONS; do
  for lg in $(aws logs describe-log-groups --region "$r" --query 'logGroups[].logGroupName' --output text); do
    aws logs describe-subscription-filters --region "$r" --log-group-name "$lg" \
      --query 'subscriptionFilters[].[logGroupName,filterName,destinationArn,roleArn]' --output text
  done
done | tee subscriptions.tsv
awk '{split($3,a,":"); print a[5]}' subscriptions.tsv | sort | uniq -c   # destination account IDs

# 2. Account-level subscription policies and destinations this account offers to others
aws logs describe-account-policies --policy-type SUBSCRIPTION_FILTER_POLICY
aws logs describe-destinations --query 'destinations[].[destinationName,targetArn,accessPolicy]' --output text

# 3. Export tasks (bulk copies to S3)
aws logs describe-export-tasks --query 'exportTasks[].[taskName,logGroupName,destination,status.code]' --output text

# 4. Observability Access Manager: links from this account, sinks in this account
for r in $REGIONS; do
  aws oam list-links --region "$r" --query 'Items[].[Arn,SinkArn,ResourceTypes]' --output text
  for s in $(aws oam list-sinks --region "$r" --query 'Items[].Arn' --output text); do
    echo "== sink $s"
    aws oam get-sink-policy --sink-identifier "$s" --region "$r" --query Policy --output text | jq .
    aws oam list-attached-links --sink-identifier "$s" --region "$r" --query 'Items[].[Label,LinkArn]' --output text
  done
done

# 5. Legacy cross-account console sharing
aws iam get-role --role-name CloudWatch-CrossAccountSharingRole \
  --query 'Role.AssumeRolePolicyDocument' 2>/dev/null
```

For every destination ARN, sink ARN and export bucket, record the owning account and check it against the organisation's account list. For Kinesis/Firehose/Lambda destinations in the same account, follow the data one hop further (where does the Firehose deliver?).

#### Observation

```text
     37 444455556666     # central logging account (in the organisation)
      3 210987654321     # not in the organisation: former SIEM vendor
arn:aws:oam:eu-west-2:111122223333:link/EXAMPLE  arn:aws:oam:eu-west-2:999988887777:sink/EXAMPLE  AWS::Logs::LogGroup AWS::CloudWatch::Metric
```

(Illustrative.)

#### Evaluation

- **Pass**: all destinations, sinks and export buckets in client-owned accounts inside the organisation (or a current, contracted provider documented as such); sink policies conditioned on `aws:PrincipalOrgID` and `oam:ResourceTypes`; OAM links filtered to the log groups the monitoring account needs; creation of new subscriptions, destinations and links restricted (SCP) and alerted.
- **Fail**: any flow to an account that is not the client's or a current provider (High when security logs or logs with secrets/personal data flow there: it is a live exfiltration channel, possibly an attacker's persistence); a sink policy open to `*` without organisation conditions (Low–Medium: others can push telemetry to it, which pollutes the monitoring account's view); OAM links from production to monitoring accounts that workload teams control.
- **Context**: the same mechanisms are how good central logging works. The finding is about *who* receives the copy and who can create new ones.

#### Automated coverage

Prowler `oam_sink_not_publicly_accessible`, `cloudwatch_cross_account_sharing_disabled`. No Security Hub CSPM control.

#### Detection

`PutSubscriptionFilter`, `DeleteSubscriptionFilter`, `PutAccountPolicy` (`SUBSCRIPTION_FILTER_POLICY`), `PutDestination`, `PutDestinationPolicy`, `CreateExportTask`, OAM `CreateLink`, `UpdateLink`, `DeleteLink`, `CreateSink`, `PutSinkPolicy`; IAM `CreateRole`/`UpdateAssumeRolePolicy` on `CloudWatch-CrossAccountSharingRole`. Map new external flows to [T1537](https://attack.mitre.org/techniques/T1537/).

### GT-AWS-CW-10: Dashboard sharing

*Guler Tech methodology.*

#### What it checks

Whether any CloudWatch dashboard is shared publicly or with external email addresses or an SSO provider, and what the sharing role actually allows.

#### Prerequisites

`SecurityAudit` plus `cognito-identity:ListIdentityPools` and `cognito-identity:DescribeIdentityPool` in `us-east-1`. The CloudWatch console's **Dashboards → Shared dashboards** view is the authoritative list; the CLI steps below find the underlying resources.

#### Steps

```bash
# Sharing roles created by CloudWatch (documented ARN pattern role/service-role/CWDBSharing*)
aws iam list-roles --path-prefix /service-role/ \
  --query "Roles[?starts_with(RoleName, 'CWDBSharing')].[RoleName,Arn,CreateDate]" --output text

for role in $(aws iam list-roles --path-prefix /service-role/ \
    --query "Roles[?starts_with(RoleName, 'CWDBSharing')].RoleName" --output text); do
  echo "== $role"
  aws iam get-role --role-name "$role" --query 'Role.AssumeRolePolicyDocument' | jq .
  for p in $(aws iam list-attached-role-policies --role-name "$role" --query 'AttachedPolicies[].PolicyArn' --output text); do
    v=$(aws iam get-policy --policy-arn "$p" --query Policy.DefaultVersionId --output text)
    aws iam get-policy-version --policy-arn "$p" --version-id "$v" --query PolicyVersion.Document | jq .
  done
done

# Cognito identity pools in us-east-1 and whether they allow unauthenticated identities
for id in $(aws cognito-identity list-identity-pools --max-results 60 --region us-east-1 \
    --query 'IdentityPools[].IdentityPoolId' --output text); do
  aws cognito-identity describe-identity-pool --identity-pool-id "$id" --region us-east-1 \
    --query '[IdentityPoolName,AllowUnauthenticatedIdentities]' --output text
done
```

In the trust policy, a condition on `cognito-identity.amazonaws.com:amr` of `unauthenticated` together with an identity pool that allows unauthenticated identities indicates public sharing; `authenticated` indicates email or SSO sharing. In the role's permissions, start from AWS's documented baseline (`cloudwatch:GetInsightRuleReport`, `cloudwatch:GetMetricData`, `cloudwatch:DescribeAlarms`, `ec2:DescribeTags`) and look for additions: `logs:StartQuery`, `logs:GetQueryResults`, `logs:FilterLogEvents`, `lambda:InvokeFunction`, `cloudwatch:DescribeAlarms` on `*`.

Do **not** obtain credentials from the identity pool or call APIs as the sharing role yourself unless the client explicitly approves it; the configuration review proves the exposure.

#### Observation

A role `CWDBSharing-...` trusted by an identity pool with unauthenticated identities allowed, created 14 months ago, with an inline addition granting `logs:StartQuery` and `logs:GetQueryResults` on `*`.

#### Evaluation

- **Critical**: public sharing whose role can read log content broadly (`logs:*Query*`/`FilterLogEvents` on `*`) or invoke Lambda functions broadly; anyone with the link can read all logs or run code paths.
- **Medium**: public sharing with the default permissions: every metric in the account and the names and tags of every EC2 instance are readable by anyone with the link (useful reconnaissance; tags often hold owner names, environment and sometimes more).
- **Low**: sharing with named email addresses or SSO, default permissions, documented business need.
- **Pass**: no sharing, or SSO-based sharing with default permissions and an owner.

#### Automated coverage

None in Security Hub CSPM or Prowler at the time of writing; see the [Cognito note](/cloud/aws-cognito-security/) for identity pool review.

#### Detection

Dashboard sharing setup appears in CloudTrail as IAM (`CreateRole`, `CreatePolicy`, `AttachRolePolicy` on `CWDBSharing*`) and Cognito (`CreateIdentityPool`, `SetIdentityPoolRoles`, `CreateUserPool`) events in `us-east-1`. Viewer activity appears as calls by the sharing role's sessions. Public dashboard reconnaissance maps to [T1538, Cloud Service Dashboard](https://attack.mitre.org/techniques/T1538/).

### GT-AWS-CW-11: Synthetics canaries, metric streams and the agent

*Guler Tech methodology.*

#### What it checks

Credentials and sensitive data in Synthetics canaries (scripts, environment, artifacts), the canaries' execution roles, metric stream destinations, and how the CloudWatch agent is authorised and configured.

#### Prerequisites

`SecurityAudit` plus `synthetics:Describe*`/`Get*`, and read access to the artifact buckets' configuration. Reading canary code or environment variables is reading client secrets: agree it first, and redact.

#### Steps

```bash
for r in $REGIONS; do
  aws synthetics describe-canaries --region "$r" --output json \
    | jq -r --arg r "$r" '.Canaries[] | [$r, .Name, .Status.State, .ExecutionRoleArn, .ArtifactS3Location,
        (.ArtifactConfig.S3Encryption.EncryptionMode // "default"), (.VpcConfig.VpcId // "-"),
        .Code.SourceLocationArn, (.EngineArn // "-")] | @tsv'
done > canaries.tsv

# Artifact buckets: public access and policy
for b in $(cut -f5 canaries.tsv | sed -E 's#^s3://##; s#/.*##' | sort -u); do
  echo "== $b"
  aws s3api get-public-access-block --bucket "$b"
  aws s3api get-bucket-policy --bucket "$b" --query Policy --output text 2>/dev/null | jq .
done

# Execution role permissions for one canary
aws iam list-attached-role-policies --role-name CloudWatchSyntheticsRole-checkout-canary
aws iam list-role-policies --role-name CloudWatchSyntheticsRole-checkout-canary

# Environment variables on the canary's underlying Lambda function (approved scope only; values are secrets)
aws lambda get-function-configuration --function-name <ENGINE_ARN> \
  --query 'Environment.Variables' | jq 'with_entries(.value = "<redacted>")'

# Metric streams and their destinations
aws cloudwatch list-metric-streams --query 'Entries[].[Name,FirehoseArn,State,OutputFormat]' --output text

# Agent configuration parameters and who can change them
aws ssm describe-parameters --parameter-filters Key=Name,Option=BeginsWith,Values=AmazonCloudWatch- \
  --query 'Parameters[].[Name,Type,LastModifiedUser]' --output text
```

The `jq 'with_entries(...)'` step prints variable **names** only. Names like `PASSWORD`, `TOKEN`, `API_KEY` or `SECRET` are the finding; you do not need the values. If the script itself must be reviewed, ask the client to provide it rather than downloading the layer.

Check in the scripts (or ask the owners) whether canaries call `getSanitizedUrl`/`restrictedUrlParameters`, and whether `includeRequestHeaders`, `includeResponseHeaders`, `includeRequestBody` or `includeResponseBody` are enabled: if they are, HAR files and reports in the artifact bucket contain headers (cookies, `Authorization`) and bodies.

#### Observation

A login canary with `USERNAME` and `PASSWORD` environment variables for a production test account that has admin rights in the application; artifacts in a bucket readable by the whole engineering account through a broad bucket policy; HAR files with session cookies; execution role with `s3:*` on `*`.

#### Evaluation

- **Pass**: canary credentials from Secrets Manager (role scoped to that secret), least-privilege test accounts, artifacts encrypted and readable only by the owning team, header and body logging off or redacted, execution roles scoped to the artifact location, logs and metrics; metric streams to known destinations; agent policies scoped and agent parameters writable only by the platform team; on-premises agents without long-term IAM user keys.
- **Fail**: secrets in canary code or environment, broadly readable artifacts with sessions or credentials, over-privileged execution roles (a compromised canary script, or the third-party site it visits, then reaches far more than it should, as AWS's own guidance warns), long-term IAM user keys on on-premises agent hosts.

#### Automated coverage

None specific in Security Hub CSPM or Prowler for Synthetics at the time of writing; S3 controls (`S3.1`, `S3.8`) apply to the artifact bucket.

#### Detection

`CreateCanary`/`UpdateCanary` (the script zip is visible in CloudTrail when passed inline), `StartCanary`/`StopCanary`/`DeleteCanary`, `GetObject` on artifact prefixes by unexpected principals (needs S3 data events), `PutMetricStream`/`DeleteMetricStream`/`StopMetricStreams`, `PutParameter` on `AmazonCloudWatch-*`, `SendCommand` with `AmazonCloudWatch-ManageAgent`.

### GT-AWS-CW-12: Tamper prevention and alerting for the monitoring layer

*Guler Tech methodology.*

#### What it checks

That administrators of workload accounts cannot silently disable the monitoring that watches them (delete or shorten log groups, remove metric filters, disable alarms, disable or delete rules, unsubscribe topics, break subscriptions or OAM links), and that attempts are alerted from somewhere they cannot reach.

#### Prerequisites

Organizations read access (SCPs) as in GT-AWS-CT-9 of the [CloudTrail note](/cloud/aws-cloudtrail-logging/); `SecurityAudit` in member accounts.

#### Steps

1. Read the SCPs attached to workload OUs and check for denies on the actions in the table below, scoped to the security resources (by name prefix or tag such as `aws:ResourceTag/owner = security`), with an exception for the platform or security role.
2. Check that monitoring resources are deployed and owned by the security or platform team (StackSets with service-managed permissions, Control Tower, Terraform from a pipeline the workload team cannot change) and tagged in a way the SCP can use.
3. Check that an alert fires on these actions, from a rule that lives in an account the workload admins cannot touch (a central bus in the security account, or the SIEM). Rules that live in the same account as the attacker can be deleted together with the alarm they protect.

| Service | Tamper actions to deny and alert |
|---|---|
| CloudWatch Logs | `DeleteLogGroup`, `DeleteLogStream`, `PutRetentionPolicy`, `DeleteMetricFilter`, `PutMetricFilter`, `DeleteSubscriptionFilter`, `PutSubscriptionFilter`, `DeleteDataProtectionPolicy`, `DisassociateKmsKey`, `PutLogGroupDeletionProtection`, `DeleteResourcePolicy`, `PutAccountPolicy`, `DeleteAccountPolicy`, `DeleteDestination` |
| CloudWatch | `DeleteAlarms`, `DisableAlarmActions`, `PutMetricAlarm`, `SetAlarmState`, `DeleteDashboards`, `DeleteMetricStream`, `StopMetricStreams` |
| EventBridge | `DeleteRule`, `DisableRule`, `PutRule`, `RemoveTargets`, `PutTargets`, `DeleteEventBus`, `RemovePermission`, `PutPermission`, `DeleteArchive` |
| SNS | `DeleteTopic`, `Unsubscribe`, `SetTopicAttributes`, `RemovePermission` |
| OAM | `DeleteLink`, `UpdateLink`, `DeleteSink`, `PutSinkPolicy` |
| Synthetics | `StopCanary`, `DeleteCanary`, `UpdateCanary` |

The detection pattern for the central bus (forward from every Region of every account):

```json
{
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventSource": [
      "logs.amazonaws.com", "monitoring.amazonaws.com", "events.amazonaws.com",
      "sns.amazonaws.com", "oam.amazonaws.com", "synthetics.amazonaws.com", "cloudtrail.amazonaws.com"
    ],
    "eventName": [
      "DeleteLogGroup", "PutRetentionPolicy", "DeleteMetricFilter", "DeleteSubscriptionFilter",
      "PutSubscriptionFilter", "DeleteDataProtectionPolicy", "DisassociateKmsKey",
      "PutLogGroupDeletionProtection", "PutAccountPolicy", "DeleteAccountPolicy",
      "DeleteAlarms", "DisableAlarmActions", "DeleteMetricStream", "StopMetricStreams",
      "DeleteRule", "DisableRule", "RemoveTargets", "DeleteEventBus", "PutPermission",
      "DeleteTopic", "Unsubscribe", "DeleteLink", "UpdateLink", "PutSinkPolicy",
      "StopCanary", "DeleteCanary",
      "StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors"
    ]
  }
}
```

Two caveats. Some recently added actions (for example `PutLogGroupDeletionProtection`) may not yet appear in AWS's published list of CloudWatch Logs actions recorded by CloudTrail; confirm in a lab that each action you rely on produces an event. And exclude the platform pipeline's role in the consuming Lambda function or SIEM rule rather than in the pattern (EventBridge supports `anything-but`, but a pattern-level exclusion is easy to abuse if the role is compromised). If the client's alerting for GuardDuty and Security Hub tampering lives elsewhere, check it is in the same central place: see [detection and posture services](/cloud/aws-detection-posture-services/) for `DeleteDetector`, `DisableSecurityHub`, `StopConfigurationRecorder` and friends.

**Active proof (lab or explicitly approved only):** in a sandbox account under the same OU, try `aws logs put-retention-policy --log-group-name <security-test-group> --retention-in-days 1` and `aws events disable-rule --name <test-rule>` with a workload-admin test role. Expected: `AccessDeniedException` citing an SCP, and an alert from the central rule for the denied attempt.

#### Observation

No SCP for the monitoring layer; the CIS alarms, the EventBridge rules and the SNS topic all live in each workload account and are created by the workload team's own Terraform.

#### Evaluation

- **Pass**: SCP denies on the security-owned monitoring resources across workload OUs, central alerting on attempts (successful or denied) from an account workload admins cannot reach, and evidence of a recent test.
- **Fail (Medium; High when combined with no CloudTrail protection or when it covers the CloudTrail log group and its alarms)**: workload admins can disable monitoring without prevention or an independent alert.

#### Automated coverage

None evaluates SCP content for this; Security Hub CSPM `CloudWatch.15`/`CloudWatch.17` notice disabled alarm actions after the fact.

#### Detection

The pattern above. ATT&CK maps this to [T1685.002, Disable or Modify Cloud Log](https://attack.mitre.org/techniques/T1685/002/) (formerly T1562.008) for the logging parts and to T1685 Disable or Modify Tools for alarms and rules.

## Hardening

**Architecture.** CloudTrail (organisation trail) to CloudWatch Logs in the security tooling or management account for CIS metric filters, *and* EventBridge rules in every Region of every account forwarding security events to a **central security bus** in the security account, where rules route to SNS, a ticketing integration, chat and automation. Monitoring resources deployed by the platform team, tagged, and protected by SCP. GuardDuty and Security Hub with delegated administrators routing findings from the administrator account.

**Terraform: CIS metric filters and alarms from one map** (in the account and Region that own the CloudTrail log group):

```hcl
locals {
  cis_filters = {
    RootUsage = <<-EOT
      {$.userIdentity.type="Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType !="AwsServiceEvent"}
    EOT
    CloudTrailChanges = <<-EOT
      {($.eventName=CreateTrail) || ($.eventName=UpdateTrail) || ($.eventName=DeleteTrail) || ($.eventName=StartLogging) || ($.eventName=StopLogging)}
    EOT
    ConsoleSignInNoMFA = <<-EOT
      { ($.eventName = "ConsoleLogin") && ($.additionalEventData.MFAUsed != "Yes") && ($.userIdentity.type = "IAMUser") && ($.responseElements.ConsoleLogin = "Success") }
    EOT
    KmsKeyDisableOrDelete = <<-EOT
      {($.eventSource=kms.amazonaws.com) && (($.eventName=DisableKey) || ($.eventName=ScheduleKeyDeletion))}
    EOT
    # ...the remaining CIS patterns from "The CIS monitoring filters", copied exactly
  }
}

resource "aws_cloudwatch_log_metric_filter" "cis" {
  for_each       = local.cis_filters
  name           = "CIS-${each.key}"
  log_group_name = aws_cloudwatch_log_group.cloudtrail.name
  pattern        = trimspace(each.value)

  metric_transformation {
    name          = each.key
    namespace     = "LogMetrics"
    value         = "1"
    default_value = "0"
  }
}

resource "aws_cloudwatch_metric_alarm" "cis" {
  for_each            = local.cis_filters
  alarm_name          = "CIS-${each.key}"
  namespace           = "LogMetrics"
  metric_name         = each.key
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  actions_enabled     = true
  alarm_actions       = [aws_sns_topic.security_alerts.arn]
}
```

The same with the CLI, for one filter:

```bash
LG=aws-cloudtrail-logs-org
TOPIC=arn:aws:sns:eu-west-2:111122223333:security-alerts
aws logs put-metric-filter --log-group-name "$LG" --filter-name CIS-RootUsage \
  --filter-pattern '{$.userIdentity.type="Root" && $.userIdentity.invokedBy NOT EXISTS && $.eventType !="AwsServiceEvent"}' \
  --metric-transformations metricName=RootUsage,metricNamespace=LogMetrics,metricValue=1,defaultValue=0
aws cloudwatch put-metric-alarm --alarm-name CIS-RootUsage --namespace LogMetrics --metric-name RootUsage \
  --statistic Sum --period 300 --evaluation-periods 1 --threshold 1 \
  --comparison-operator GreaterThanOrEqualToThreshold --treat-missing-data notBreaching \
  --alarm-actions "$TOPIC"
```

**SNS topic for alerts**, encrypted with a key CloudWatch and EventBridge can use, publishable only by those services from the client's own resources:

```hcl
resource "aws_sns_topic" "security_alerts" {
  name              = "security-alerts"
  kms_master_key_id = aws_kms_key.alerts.arn
}

data "aws_iam_policy_document" "security_alerts" {
  statement {
    sid     = "CloudWatchAlarms"
    actions = ["sns:Publish"]
    principals {
      type        = "Service"
      identifiers = ["cloudwatch.amazonaws.com"]
    }
    resources = [aws_sns_topic.security_alerts.arn]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }

  statement {
    sid     = "EventBridgeRules"
    actions = ["sns:Publish"]
    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
    resources = [aws_sns_topic.security_alerts.arn]
    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = ["arn:aws:events:*:${data.aws_caller_identity.current.account_id}:rule/*"]
    }
  }
}

resource "aws_sns_topic_policy" "security_alerts" {
  arn    = aws_sns_topic.security_alerts.arn
  policy = data.aws_iam_policy_document.security_alerts.json
}
```

The KMS key policy for `aws_kms_key.alerts` needs a statement allowing `cloudwatch.amazonaws.com` and `events.amazonaws.com` to call `kms:Decrypt` and `kms:GenerateDataKey*`.

**Central security bus** (security account) and forwarding (every Region of every member account, deployed by StackSets):

```hcl
# Security account
resource "aws_cloudwatch_event_bus" "security" {
  name = "security-central"
}

data "aws_iam_policy_document" "security_bus" {
  statement {
    sid     = "OrgPutEvents"
    actions = ["events:PutEvents"]
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    resources = [aws_cloudwatch_event_bus.security.arn]
    condition {
      test     = "StringEquals"
      variable = "aws:PrincipalOrgID"
      values   = ["o-exampleorgid"]
    }
  }
}

resource "aws_cloudwatch_event_bus_policy" "security" {
  event_bus_name = aws_cloudwatch_event_bus.security.name
  policy         = data.aws_iam_policy_document.security_bus.json
}

# Member account, every Region: findings by source...
resource "aws_cloudwatch_event_rule" "forward_findings" {
  name  = "forward-security-findings"
  state = "ENABLED"
  event_pattern = jsonencode({
    source = ["aws.guardduty", "aws.securityhub"]
  })
}

# ...and CloudTrail activity by detail-type (write management events and sign-ins)
resource "aws_cloudwatch_event_rule" "forward_cloudtrail" {
  name  = "forward-cloudtrail-activity"
  state = "ENABLED"
  event_pattern = jsonencode({
    "detail-type" = ["AWS API Call via CloudTrail", "AWS Console Sign In via CloudTrail"]
  })
}

resource "aws_cloudwatch_event_target" "findings_to_central" {
  rule     = aws_cloudwatch_event_rule.forward_findings.name
  arn      = "arn:aws:events:eu-west-2:444455556666:event-bus/security-central"
  role_arn = aws_iam_role.eventbridge_forwarder.arn
}

resource "aws_cloudwatch_event_target" "cloudtrail_to_central" {
  rule     = aws_cloudwatch_event_rule.forward_cloudtrail.name
  arn      = "arn:aws:events:eu-west-2:444455556666:event-bus/security-central"
  role_arn = aws_iam_role.eventbridge_forwarder.arn
}
```

(Forwarding broadly and filtering centrally keeps the member-account rules simple and out of the workload team's hands; events delivered to another account's bus are billed, so narrow the CloudTrail rule with `detail.eventSource` if volume is a concern. If the central rules need read-only management events, both the forwarding rule and the central rule must use state `ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS`.)

**Log groups**: retention, KMS key and deletion protection for security groups; an account-level data protection policy for the rest.

```hcl
resource "aws_cloudwatch_log_group" "cloudtrail" {
  name              = "aws-cloudtrail-logs-org"
  retention_in_days = 400
  kms_key_id        = aws_kms_key.logs.arn
  log_group_class   = "STANDARD"
}
```

```bash
# Deletion protection (recent API; check your provider and CLI versions for support)
aws logs put-log-group-deletion-protection --log-group-identifier aws-cloudtrail-logs-org --deletion-protection-enabled

# Account-wide data protection policy (masks from now on, for all log groups)
aws logs put-account-policy --policy-name account-data-protection \
  --policy-type DATA_PROTECTION_POLICY --scope ALL --policy-document file://dpp.json
```

`dpp.json`, auditing to a findings log group and masking the same identifiers (add custom data identifiers for the client's token formats):

```json
{
  "Name": "account-data-protection",
  "Description": "Mask credentials and common personal data",
  "Version": "2021-06-01",
  "Statement": [
    {
      "Sid": "audit-policy",
      "DataIdentifier": [
        "arn:aws:dataprotection::aws:data-identifier/AwsSecretKey",
        "arn:aws:dataprotection::aws:data-identifier/OpenSshPrivateKey",
        "arn:aws:dataprotection::aws:data-identifier/PkcsPrivateKey",
        "arn:aws:dataprotection::aws:data-identifier/EmailAddress"
      ],
      "Operation": {
        "Audit": {
          "FindingsDestination": {
            "CloudWatchLogs": {
              "LogGroup": "/security/data-protection-findings"
            }
          }
        }
      }
    },
    {
      "Sid": "redact-policy",
      "DataIdentifier": [
        "arn:aws:dataprotection::aws:data-identifier/AwsSecretKey",
        "arn:aws:dataprotection::aws:data-identifier/OpenSshPrivateKey",
        "arn:aws:dataprotection::aws:data-identifier/PkcsPrivateKey",
        "arn:aws:dataprotection::aws:data-identifier/EmailAddress"
      ],
      "Operation": {
        "Deidentify": {
          "MaskConfig": {}
        }
      }
    }
  ]
}
```

**Stop secrets reaching logs in the first place.** Lambda: never log the raw event for API-facing functions, use structured logging with an allow-list of fields, set `ApplicationLogLevel` to `INFO` or higher in production. API Gateway: execution logging at `ERROR`, `dataTraceEnabled` off in production, access logs with a chosen format instead. Synthetics: credentials from Secrets Manager, `restrictedUrlParameters`, header and body logging off. SDKs and HTTP clients: debug wire logging off in production.

**SCP protecting the monitoring layer** (attach to workload OUs; adapt the tag or name conditions to how the client marks security-owned resources):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ProtectSecurityLogGroups",
      "Effect": "Deny",
      "Action": [
        "logs:DeleteLogGroup", "logs:DeleteLogStream", "logs:PutRetentionPolicy",
        "logs:DeleteMetricFilter", "logs:PutMetricFilter", "logs:DeleteSubscriptionFilter",
        "logs:DeleteDataProtectionPolicy", "logs:DisassociateKmsKey", "logs:PutLogGroupDeletionProtection"
      ],
      "Resource": [
        "arn:aws:logs:*:*:log-group:aws-cloudtrail-logs-*",
        "arn:aws:logs:*:*:log-group:/security/*"
      ],
      "Condition": {
        "ArnNotLike": { "aws:PrincipalArn": "arn:aws:iam::*:role/PlatformSecurityAdmin" }
      }
    },
    {
      "Sid": "ProtectSecurityAlarmsRulesTopics",
      "Effect": "Deny",
      "Action": [
        "cloudwatch:DeleteAlarms", "cloudwatch:DisableAlarmActions", "cloudwatch:PutMetricAlarm",
        "events:DeleteRule", "events:DisableRule", "events:PutRule", "events:RemoveTargets", "events:PutTargets",
        "sns:DeleteTopic", "sns:SetTopicAttributes", "sns:RemovePermission"
      ],
      "Resource": "*",
      "Condition": {
        "StringEquals": { "aws:ResourceTag/owner": "security" },
        "ArnNotLike": { "aws:PrincipalArn": "arn:aws:iam::*:role/PlatformSecurityAdmin" }
      }
    },
    {
      "Sid": "RestrictLogCopiesAndLinks",
      "Effect": "Deny",
      "Action": [
        "logs:PutSubscriptionFilter", "logs:PutAccountPolicy", "logs:PutDestination",
        "logs:PutDestinationPolicy", "logs:CreateExportTask", "oam:CreateLink", "oam:UpdateLink"
      ],
      "Resource": "*",
      "Condition": {
        "ArnNotLike": { "aws:PrincipalArn": "arn:aws:iam::*:role/PlatformSecurityAdmin" }
      }
    },
    {
      "Sid": "NoDashboardSharingRoles",
      "Effect": "Deny",
      "Action": ["iam:CreateRole", "iam:AttachRolePolicy", "iam:PutRolePolicy", "iam:UpdateAssumeRolePolicy"],
      "Resource": "arn:aws:iam::*:role/service-role/CWDBSharing*",
      "Condition": {
        "ArnNotLike": { "aws:PrincipalArn": "arn:aws:iam::*:role/PlatformSecurityAdmin" }
      }
    }
  ]
}
```

Notes on that SCP: tag-based conditions only work for resources and actions that support `aws:ResourceTag` (check the service authorization reference for each action, and note that SNS `Unsubscribe` acts on a subscription, not the topic); `Unsubscribe` and `Subscribe` on the security topic are better controlled through the topic policy. The last statement blocks dashboard sharing (all three modes) by denying creation and modification of roles matching the `service-role/CWDBSharing*` pattern that AWS documents for sharing, so sharing becomes a platform-team request; it also stops anyone widening an existing sharing role's permissions.

**Least privilege for log readers.** Replace `ReadOnlyAccess` for humans with permission sets that exclude `logs:GetLogEvents`, `logs:FilterLogEvents`, `logs:StartQuery` and `logs:StartLiveTail` except on the team's own log group prefixes; keep `logs:Unmask` for a small group; replace `CloudWatchAgentServerPolicy` with a scoped custom policy (own log group prefix, no `logs:PutRetentionPolicy`).

**AWS Config rules** behind the Security Hub CSPM controls: `cloudwatch-alarm-action-check` (`CloudWatch.15`), `cw-loggroup-retention-period-check` (`CloudWatch.16`), plus `cloudwatch-alarm-action-enabled-check` and `cloudwatch-log-group-encrypted` for alarm action activation and log group encryption.

## Real-world cases

- **Plaintext passwords in internal logs.** In 2018 Twitter disclosed that a bug had written users' passwords unmasked to an internal log before hashing, and in 2019 Facebook disclosed that some user passwords had been stored "in a readable format within our internal data storage systems", affecting hundreds of millions of Facebook Lite users and tens of millions of others. Neither involved CloudWatch, but both are exactly the failure GT-AWS-CW-6 and GT-AWS-CW-7 look for: a logging statement that captures more than intended and a log store that many employees can search. [Twitter (Krebs on Security)](https://krebsonsecurity.com/2018/05/twitter-to-all-users-change-your-password-now/); [Meta](https://about.fb.com/news/2019/03/keeping-passwords-secure/).
- **Logging gaps and the limits of one data source.** The [CloudTrail note](/cloud/aws-cloudtrail-logging/) covers the Datadog `iamadmin` logging bypass and the SCARLETEEL case, in which exfiltration to a non-AWS service never appeared in the victim's CloudTrail. Both argue for the layered approach here: CloudTrail-based alarms plus findings routing (GuardDuty) plus VPC Flow Logs and application logs queried in Logs Insights.
- For incidents where alerting (or its absence) shaped the outcome, see [AWS security incidents and write-ups](/cloud/aws-security-incidents-and-writeups/).

## Rating findings

| Finding | Typical severity | Reasoning |
|---|---|---|
| Public dashboard sharing with log read or Lambda invoke on `*` | Critical | Unauthenticated read of all logs (and whatever secrets they contain) or code invocation, from a link that may already be in chat history or a wiki |
| Live production credentials in logs readable by broad groups (`ReadOnlyAccess` users, vendors) | High–Critical | Any read-only principal becomes whatever the credential grants; Critical when the credential is an AWS admin key or equivalent |
| Security logs or CloudTrail events flowing to an account outside the client's control (subscription, destination, export, OAM link, cross-account rule) | High | Ongoing exfiltration of a map of the estate and possibly of data; may be an attacker's persistence |
| Monitoring layer can be disabled by workload admins, no SCP, no independent alert | Medium–High | Turns any admin compromise into a silent one; High when it covers the CloudTrail log group and its alarms |
| CIS monitoring absent or broken (no filters, alarms without actions, unconfirmed SNS, failing EventBridge targets) | Medium | Logging exists but nobody is told; rate up for root usage, CloudTrail changes and IAM changes, which matter most |
| Security rules only in one Region (no `us-east-1` IAM rules, sign-ins missed) | Medium | Large blind spots that look covered in testing |
| GuardDuty / Security Hub findings not routed anywhere | Medium | Detection exists and is wasted |
| Public dashboard sharing with default permissions | Medium | Unauthenticated reconnaissance of all metrics and EC2 names and tags |
| Credentials in Synthetics code, environment or artifacts | Medium–High | Depends on what the test account can do and who can read the artifacts |
| `CloudWatchAgentServerPolicy` in the account holding the CloudTrail log group | Medium | Every agent instance can forge CloudTrail-looking events or shorten retention there |
| Personal data in logs without masking, never-expiring retention | Medium | Data protection exposure and breach scope; rate with the client's DPO |
| `logs:Unmask` broadly held | Low–Medium | Masking only protects against those without it |
| Event bus open to `PutEvents` from any account | Low–Medium | Spoofed custom events and cost abuse; AWS service sources cannot be spoofed |
| Security log groups with short retention, no KMS key or no deletion protection | Low–Medium | Evidence loss and weaker access control; Medium when retention is shorter than incident detection times |
| SNS topic policy allowing anyone to subscribe | Low–Medium | Alert content leaks to outsiders |
| CIS filters that differ from the exact Security Hub CSPM string but cover the events | Info | Compliance-report noise only |

## Mapping

| Test | Security Hub CSPM | CIS AWS Foundations | ATT&CK |
|---|---|---|---|
| GT-AWS-CW-1 | CloudWatch.1–CloudWatch.14, CloudWatch.15, CloudWatch.17 | v1.4.0 4.1–4.15 (v1.2.0 3.1–3.14; v3.0.0 4.1–4.15 manual) | T1685.002, T1078.004 |
| GT-AWS-CW-2 | CloudWatch.15, CloudWatch.17, SNS.1, SNS.4 | — | T1685.002 |
| GT-AWS-CW-3 | — | v3.0.0 4.x (when EventBridge implements them) | T1685.002, T1078.004 |
| GT-AWS-CW-4 | EventBridge.3 | — | T1537 |
| GT-AWS-CW-5 | CloudWatch.16 | — | T1685.002, T1485 |
| GT-AWS-CW-6 | — | — | T1552, T1654 |
| GT-AWS-CW-7 | — | — | T1552 |
| GT-AWS-CW-8 | — | — | T1654, T1552 |
| GT-AWS-CW-9 | — | — | T1537 |
| GT-AWS-CW-10 | — | — | T1538 |
| GT-AWS-CW-11 | S3.1, S3.8 (artifact buckets) | — | T1552, T1537 |
| GT-AWS-CW-12 | CloudWatch.15, CloudWatch.17 | v1.4.0 4.5 | T1685.002 |

CIS numbers come from the Security Hub CSPM CIS mapping table and, for 4.15 and the v3.0.0 manual items, from Prowler's CIS compliance mappings. T1685.002 replaced T1562.008 in ATT&CK v20.

## References

- AWS Security Hub CSPM: [CloudWatch controls](https://docs.aws.amazon.com/securityhub/latest/userguide/cloudwatch-controls.html), [CIS AWS Foundations Benchmark](https://docs.aws.amazon.com/securityhub/latest/userguide/cis-aws-foundations-benchmark.html), [EventBridge controls](https://docs.aws.amazon.com/securityhub/latest/userguide/eventbridge-controls.html), [SNS controls](https://docs.aws.amazon.com/securityhub/latest/userguide/sns-controls.html)
- CloudWatch Logs: [Log classes](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CloudWatch_Logs_Log_Classes.html), [Encrypt log data using AWS KMS](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/encrypt-log-data-kms.html), [Live Tail](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CloudWatchLogs_LiveTail.html), [Cross-account cross-Region subscriptions](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/CrossAccountSubscriptions.html), [Quotas](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/cloudwatch_limits_cwl.html)
- CloudWatch Logs data protection: [Help protect sensitive log data with masking](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/mask-sensitive-log-data.html), [View unmasked data](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/mask-sensitive-log-data-viewunmasked.html), [Credential data identifiers](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/protect-sensitive-log-data-types-credentials.html)
- CloudWatch Logs API: [PutResourcePolicy](https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_PutResourcePolicy.html), [PutLogGroupDeletionProtection](https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_PutLogGroupDeletionProtection.html), [LogGroup](https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/API_LogGroup.html)
- CloudWatch: [Sharing CloudWatch dashboards](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/cloudwatch-dashboard-sharing.html), [Cross-account observability](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch-Unified-Cross-Account.html), [Security considerations for Synthetics canaries](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/servicelens_canaries_security.html)
- EventBridge: [AWS service events delivered via CloudTrail](https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-service-event-cloudtrail.html), [Permissions for event buses](https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-event-bus-perms.html), [Using resource-based policies](https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-use-resource-based.html), [Content filtering operators](https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-create-pattern-operators.html)
- CloudTrail: [AWS Management Console sign-in events](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-aws-console-sign-in-events.html), [Sending events to CloudWatch Logs](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/send-cloudtrail-events-to-cloudwatch-logs.html)
- AWS Security Hub: [EventBridge event formats (new Security Hub)](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-v2-cwe-event-formats.html)
- AWS managed policies: [ReadOnlyAccess](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/ReadOnlyAccess.html), [CloudWatchLogsReadOnlyAccess](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/CloudWatchLogsReadOnlyAccess.html), [CloudWatchAgentServerPolicy](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/CloudWatchAgentServerPolicy.html), [SecurityAudit](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/SecurityAudit.html)
- MITRE ATT&CK: [T1685.002](https://attack.mitre.org/techniques/T1685/002/), [T1552](https://attack.mitre.org/techniques/T1552/), [T1654](https://attack.mitre.org/techniques/T1654/), [T1537](https://attack.mitre.org/techniques/T1537/), [T1538](https://attack.mitre.org/techniques/T1538/)
- Tools: [Prowler](https://github.com/prowler-cloud/prowler), [ScoutSuite](https://github.com/nccgroup/ScoutSuite), [Pacu](https://github.com/RhinoSecurityLabs/pacu)
