---
title: "AWS CloudTrail: Audit Logging Done Right"
date: 2026-11-12 18:13:00 +0000
subcategory: aws
summary: "Testing CloudTrail coverage and tamper resistance: org trails, data and network events, validation, log bucket and KMS hardening, Athena queries."
refs: [CloudTrail.1, CloudTrail.2, CloudTrail.3, CloudTrail.4, CloudTrail.5, CloudTrail.6, CloudTrail.7, CloudTrail.10, S3.22, S3.23, "CIS AWS v3.0.0 3.1", "CIS AWS v3.0.0 3.2", "CIS AWS v3.0.0 3.4", "CIS AWS v3.0.0 3.5", "CIS AWS v3.0.0 3.8", "CIS AWS v3.0.0 3.9", "CIS AWS v1.4.0 3.4", T1685.002, T1078.004, T1530, T1654]
tags: [aws, cloudtrail, logging, audit, detection, athena]
---

This note is part of our [AWS Security series](/cloud/aws-security-testing-guide/) and covers AWS CloudTrail, the audit log for the AWS API. Almost every other note in the series ends with a **Detection** line that names CloudTrail `eventName`s, and every one of those lines assumes something this note has to prove: that a trail exists in every account and Region, that it records the event categories the investigation will need, that nobody below the security team can switch it off or edit what it wrote, and that someone can actually query it at 3 a.m. We cover how CloudTrail is built (event history, trails, CloudTrail Lake and its 2026 availability change, management, data, network activity and Insights events, selectors, delivery, integrity validation, encryption, organisation trails), what it does not record, how to read an event, eleven tests from coverage to Athena readiness, the SCPs and bucket policies that make the log tamper-resistant, and how to rate what you find. Turning CloudTrail into alarms is the subject of the companion note on [CloudWatch and EventBridge](/cloud/aws-cloudwatch-eventbridge-monitoring/); GuardDuty, Security Hub and Config live in [detection and posture services](/cloud/aws-detection-posture-services/).

## Contents

- [How it works](#how-it-works)
  - [Event history, trails and CloudTrail Lake](#event-history-trails-and-cloudtrail-lake)
  - [Event categories](#event-categories)
  - [Basic and advanced event selectors](#basic-and-advanced-event-selectors)
  - [Delivery: S3, CloudWatch Logs and EventBridge](#delivery-s3-cloudwatch-logs-and-eventbridge)
  - [Integrity validation and encryption](#integrity-validation-and-encryption)
  - [Multi-Region and organisation trails](#multi-region-and-organisation-trails)
  - [What CloudTrail does not record](#what-cloudtrail-does-not-record)
  - [Reading an event](#reading-an-event)
- [What goes wrong](#what-goes-wrong)
- [Testing](#testing)
  - [Before you start](#before-you-start)
  - [GT-AWS-CT-1: Trail coverage across Regions and accounts](#gt-aws-ct-1-trail-coverage-across-regions-and-accounts)
  - [GT-AWS-CT-2: Management events and event selectors](#gt-aws-ct-2-management-events-and-event-selectors)
  - [GT-AWS-CT-3: Data events for sensitive resources](#gt-aws-ct-3-data-events-for-sensitive-resources)
  - [GT-AWS-CT-4: Network activity events and Insights](#gt-aws-ct-4-network-activity-events-and-insights)
  - [GT-AWS-CT-5: Log file integrity validation](#gt-aws-ct-5-log-file-integrity-validation)
  - [GT-AWS-CT-6: Log bucket hardening and the log-archive account](#gt-aws-ct-6-log-bucket-hardening-and-the-log-archive-account)
  - [GT-AWS-CT-7: SSE-KMS encryption and the key policy](#gt-aws-ct-7-sse-kms-encryption-and-the-key-policy)
  - [GT-AWS-CT-8: Delivery health and CloudWatch Logs integration](#gt-aws-ct-8-delivery-health-and-cloudwatch-logs-integration)
  - [GT-AWS-CT-9: Tamper prevention with SCPs](#gt-aws-ct-9-tamper-prevention-with-scps)
  - [GT-AWS-CT-10: Alerting on tamper events](#gt-aws-ct-10-alerting-on-tamper-events)
  - [GT-AWS-CT-11: Investigation readiness with Athena](#gt-aws-ct-11-investigation-readiness-with-athena)
- [Hardening](#hardening)
- [Real-world cases](#real-world-cases)
- [Rating findings](#rating-findings)
- [Mapping](#mapping)
- [References](#references)

## How it works

CloudTrail records requests to AWS APIs: who called, from where, with which credentials, against what, and whether it worked. It is on by default in a limited form, and everything useful beyond that limited form is something the account owner has to configure. Most findings in this area are about the gap between "CloudTrail is on" (always true) and "CloudTrail is recording what we need, somewhere an attacker cannot reach" (often not).

### Event history, trails and CloudTrail Lake

There are three ways to keep CloudTrail events, and clients regularly confuse them.

| | Event history | Trail | CloudTrail Lake event data store |
|---|---|---|---|
| Enabled by | Always on, no setup | You create it | You create it |
| Content | **Management events only**: no data, Insights or network activity events | Management, data, network activity and Insights events, as selected | Same categories plus Config items and non-AWS events |
| Retention | **90 days**, then gone | As long as the S3 bucket keeps the objects | Configurable retention per data store |
| Scope | One account, one Region per lookup | One Region, all Regions, or a whole organisation | One account or an organisation, one or more Regions |
| Query | `lookup-events`, one attribute filter at a time | Athena, CloudWatch Logs Insights, a SIEM | SQL in Lake |
| Can be disabled or edited? | No | Yes: `StopLogging`, `DeleteTrail`, `UpdateTrail`, `PutEventSelectors` | Yes: `StopEventDataStoreIngestion`, `UpdateEventDataStore`, `DeleteEventDataStore` |

AWS describes event history as "viewable, searchable, downloadable, and immutable", and that immutability is useful: even if an attacker stops every trail, the last 90 days of management events are still there in each Region. It is not a substitute for a trail. It has no data events, no organisation view, cannot be exported automatically, and anything older than 90 days, which is most breach dwell times, is gone.

**CloudTrail Lake availability change.** AWS's documentation states that CloudTrail Lake is closed to new customers from **31 May 2026**; existing customers can keep using it, but it will receive only critical bug fixes and security updates. Organisation event data stores keep covering new member accounts; organisations that only have account-level event data stores do not get ingestion for accounts added later. AWS's recommended path is CloudWatch (it added an import from Lake event data stores, and in December 2025 a way to collect CloudTrail events into CloudWatch through service-linked channels without a trail). Trails, Insights and aggregated events are not affected. For a reviewer this means two things: a client who signed up before the cut-off may still rely on Lake and its tamper events still matter, and a client planning a new deployment should be steered towards trails plus CloudWatch or a SIEM, not Lake. Check the [availability change page](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-lake-service-availability-change.html) for the current state.

### Event categories

| Category | What it records | Default on a trail | Notes for testing |
|---|---|---|---|
| **Management events** | Control-plane operations: `CreateUser`, `PutBucketPolicy`, `RunInstances`, `AssumeRole`, `ConsoleLogin`. Split into read (`Describe*`, `List*`, `Get*`) and write | On (read and write) | The first copy of management events per Region is free; the rest of CloudTrail is billed |
| **Data events** | Resource-level operations: S3 object `GetObject`/`PutObject`/`DeleteObject`, Lambda `Invoke`, DynamoDB item operations, and many more resource types | **Off** | High volume, billed per event. Without them you cannot tell which objects were read or which functions were invoked |
| **Network activity events** | API calls that pass through a VPC endpoint, recorded for the **VPC endpoint owner**, including calls made by principals from other accounts and calls denied by the endpoint policy (`errorCode` `VpceAccessDenied`) | **Off** | Preview September 2024, generally available February 2025; the list of supported event sources has grown well beyond the original five |
| **Insights events** | Anomalies in API call rate or API error rate compared with a learned baseline | **Off** | Management-event Insights need write management events (call rate) or read/write (error rate); data-event Insights are supported on trails only |

AWS also added **aggregated events** for data events in November 2025 (summaries over short time windows, delivered to a separate prefix), which help with volume but are not a replacement for the underlying records during an investigation.

### Basic and advanced event selectors

A trail's event selectors decide what it records. Basic selectors (`EventSelectors`) offer read/write type, management on/off, a list of excluded management event sources, and a resource list for a few data event types. Advanced event selectors (`AdvancedEventSelectors`) filter on fields such as `eventCategory`, `eventSource`, `eventName`, `readOnly`, `resources.type`, `resources.ARN`, `errorCode` and, for trails, `userIdentity.arn`, with operators like `Equals`, `StartsWith`, `NotEquals` and `NotStartsWith`. A trail uses one style or the other, never both.

Selectors are where coverage silently disappears. Three common ways:

- `ExcludeManagementEventSources` set to `kms.amazonaws.com` or `rdsdata.amazonaws.com` to cut cost, which removes every KMS `Decrypt`, `GenerateDataKey` and `ScheduleKeyDeletion` (or every RDS Data API call) from the trail.
- `ReadWriteType: WriteOnly` (or an advanced selector `readOnly` `Equals` `false`), which drops all reconnaissance: `ListBuckets`, `GetSecretValue`, `DescribeInstances`, `GetCallerIdentity`.
- Advanced selectors with `NotEquals` or `NotStartsWith` on `userIdentity.arn` or `eventName` that exclude "noisy" principals, which is exactly the exclusion an attacker who lands on that principal benefits from.

Changing selectors is itself a logged management event (`PutEventSelectors`), and it is one of the tamper events we test for in [GT-AWS-CT-10](#gt-aws-ct-10-alerting-on-tamper-events).

### Delivery: S3, CloudWatch Logs and EventBridge

A trail always writes gzip-compressed JSON files to an S3 bucket under `AWSLogs/<account-id>/CloudTrail/<region>/YYYY/MM/DD/` (or `AWSLogs/<o-org-id>/<account-id>/...` for organisation trails), typically within an average of about five minutes of the call. Optionally it also:

- **Sends events to a CloudWatch Logs log group** in the trail's account, using an IAM role that CloudTrail assumes (`CloudTrail_CloudWatchLogs_Role` by default) with `logs:CreateLogStream` and `logs:PutLogEvents`. This is what the CIS metric filters and alarms hang off; see the [CloudWatch note](/cloud/aws-cloudwatch-eventbridge-monitoring/).
- **Publishes an SNS notification** for each log file delivered (useful for pipelines, not for alerting on content).

Separately, CloudTrail events reach **EventBridge** in the Region where they happened, as `AWS API Call via CloudTrail` and related detail-types. AWS's EventBridge documentation says an enabled trail is required for this. Write management events match rules in the normal `ENABLED` state; read-only management events only match rules in the `ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS` state.

One limitation matters for detection engineering: **CloudWatch Logs and EventBridge accept events up to 256 KB**; CloudTrail does not send larger events to either. They still land in S3. A detection pipeline that only reads CloudWatch Logs or EventBridge can therefore miss a small number of very large events that the S3 copy has.

### Integrity validation and encryption

With **log file integrity validation** on, CloudTrail writes a digest file every hour that lists the SHA-256 hash of each log file delivered in that hour and the hash of the previous digest, and signs the digest with a private key that AWS holds per Region. `aws cloudtrail validate-logs` walks the chain backwards and reports any log file that was modified or deleted and any digest that is missing, moved or has a bad signature. Validation tells you *whether* the log was changed after delivery; it does not prevent the change. Prevention is the bucket's job (versioning, Object Lock, a separate account).

**Encryption**: log files are encrypted with SSE-S3 by default. With SSE-KMS, CloudTrail encrypts with a KMS key you choose, which adds a second gate: reading the logs then needs both `s3:GetObject` and `kms:Decrypt` on that key. The key policy must let `cloudtrail.amazonaws.com` call `kms:GenerateDataKey*` (AWS recommends an `aws:SourceArn` condition naming the trail and a `kms:EncryptionContext:aws:cloudtrail:arn` condition), and must give `kms:Decrypt` only to the people and tools that read logs. If the key is disabled or its policy breaks, **CloudTrail stops delivering**, so the key is part of the tamper surface too.

### Multi-Region and organisation trails

A **multi-Region trail** records events from every enabled Region into one bucket, and automatically covers Regions enabled later. Trails created in the console are multi-Region; a single-Region trail is only possible from the CLI or API, and a single-Region trail in `eu-west-2` sees nothing an attacker does in `ap-southeast-3`. Global service events (IAM, STS global endpoint, CloudFront, Route 53 and so on) are recorded as occurring in `us-east-1`; a multi-Region trail includes them by default.

An **organisation trail** is created in the management account or a CloudTrail delegated administrator account and applies to every member account. Member accounts can see it in `describe-trails` but cannot stop it, delete it, or change its selectors; new accounts are added automatically and removed accounts drop off (their past logs stay in the bucket). By default only the management account can read the bucket. Two edge cases to remember: if the organisation trail's home Region is an opt-in Region, only member accounts that enabled that Region send events; and the management account itself is exempt from SCPs, so the protections in [GT-AWS-CT-9](#gt-aws-ct-9-tamper-prevention-with-scps) do not cover it.

The pattern AWS and most landing zones (Control Tower among them) converge on: one multi-Region organisation trail, delivering to a bucket in a dedicated **log-archive account**, encrypted with a KMS key in that account, with CloudWatch Logs or SIEM integration on top, plus whatever account-local trails teams need for their own data events.

### What CloudTrail does not record

Be precise with clients here; overstating gaps is as unhelpful as ignoring them.

- **Anything inside your workloads.** Commands run on an EC2 instance, SQL run against RDS, Kubernetes API calls to an EKS cluster (those are EKS control plane audit logs, delivered to CloudWatch Logs if enabled), application logins, traffic inside a VPC (VPC Flow Logs). CloudTrail sees the AWS API, not the operating system or the network.
- **Data plane operations that are not enabled as data events.** Without S3 data events there is no record of which objects were downloaded; without Lambda data events there is no record of who invoked a function. Each service's "Logging ... with CloudTrail" page lists which operations are data events.
- **Unsupported services and APIs.** AWS states that services in preview, not yet generally available, or without public APIs are not considered supported, and lists unsupported services on the [supported services page](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-aws-service-specific-topics.html). Individual service pages also note specific actions that are not logged. Check the service pages for the services the client actually uses rather than assuming.
- **Events larger than 256 KB in CloudWatch Logs and EventBridge** (they are in S3).
- **Traffic to non-AWS endpoints.** An attacker who uses stolen credentials against a non-AWS, S3-compatible service, or exfiltrates over the internet from a compromised instance, generates no CloudTrail events in your account.
- **Historic logging gaps.** Researchers have found APIs that did not produce CloudTrail events and reported them to AWS, which fixed them (see [Real-world cases](#real-world-cases)). Treat CloudTrail as very good, not perfect, and do not build a control that fails open if one event is missing.

### Reading an event

The fields you use in every investigation:

```json
{
  "eventVersion": "1.10",
  "userIdentity": {
    "type": "AssumedRole",
    "principalId": "AROAEXAMPLEID:jane.doe@example.com",
    "arn": "arn:aws:sts::111122223333:assumed-role/AdminSSO/jane.doe@example.com",
    "accountId": "111122223333",
    "accessKeyId": "<ACCESS_KEY_ID>",
    "sessionContext": {
      "sessionIssuer": {
        "type": "Role",
        "arn": "arn:aws:iam::111122223333:role/AdminSSO",
        "accountId": "111122223333",
        "userName": "AdminSSO"
      },
      "attributes": {
        "creationDate": "2026-11-02T09:14:07Z",
        "mfaAuthenticated": "false"
      },
      "sourceIdentity": "jane.doe@example.com"
    }
  },
  "eventTime": "2026-11-02T09:31:55Z",
  "eventSource": "cloudtrail.amazonaws.com",
  "eventName": "StopLogging",
  "awsRegion": "eu-west-2",
  "sourceIPAddress": "203.0.113.24",
  "userAgent": "aws-cli/2.x Python/3.x",
  "errorCode": "AccessDenied",
  "errorMessage": "User: ... is not authorized to perform: cloudtrail:StopLogging ... with an explicit deny in a service control policy",
  "requestParameters": { "name": "arn:aws:cloudtrail:eu-west-2:111122223333:trail/org-trail" },
  "responseElements": null,
  "readOnly": false,
  "eventType": "AwsApiCall",
  "managementEvent": true,
  "recipientAccountId": "111122223333",
  "eventCategory": "Management"
}
```

(Illustrative event; values shortened.)

- **`userIdentity.type`**: `Root`, `IAMUser`, `AssumedRole`, `FederatedUser`, `IdentityCenterUser`, `AWSService`, `AWSAccount` and a few others. `AssumedRole` is the common case; the role is in `sessionContext.sessionIssuer.arn` and the *person* is usually in the session name (the part after the last `/` in `arn`) or in `sourceIdentity` if the client sets it. Investigations that stop at the role name lose the human.
- **`userIdentity.accessKeyId`**: `AKIA...` prefixes are long-term IAM user keys, `ASIA...` are temporary credentials. Pivot on it to find every call made with one leaked key.
- **`sessionContext.attributes.mfaAuthenticated`**: whether the session was created with MFA. Federated sessions show `false` even when the IdP enforced MFA, which is why the CIS "console sign-in without MFA" filter restricts itself to `IAMUser`.
- **`invokedBy`** and **`sourceIPAddress`**: when an AWS service calls on the principal's behalf, `sourceIPAddress` is a service name such as `cloudformation.amazonaws.com` and `invokedBy` is set. A real IP that is not from the client's ranges, a VPN, or a known CI provider is worth a second look; `AWS Internal` also appears.
- **`errorCode`**: `AccessDenied`, `*UnauthorizedOperation`, `VpceAccessDenied`, `NoSuchEntity`. A burst of denied calls across many services from one principal is the classic signature of someone enumerating what stolen credentials can do.
- **`requestParameters` / `responseElements`**: what was asked for and what came back. Secrets are not logged in plaintext here for APIs that return them (`GetSecretValue` responses are not recorded), but request parameters can include things like user data, tags and policy documents.
- **`recipientAccountId`** vs **`userIdentity.accountId`**: different values mean cross-account access.
- **`vpcEndpointId`**: present when the call came through an interface or gateway endpoint.

## What goes wrong

**No trail, or a trail in one Region.** Event history covers the last 90 days of management events and nothing else. A single-Region trail misses activity in every other enabled Region, and attackers who mine cryptocurrency with stolen keys favour Regions the client never uses, precisely because nobody looks there.

**Organisation coverage gaps.** Accounts outside the organisation (acquisitions, "temporary" accounts, the old production account that was never migrated), an organisation trail whose home Region is an opt-in Region, or a management account that has its own trail switched off. Each is an account in which an attacker's actions leave only event history.

**Write-only or filtered management events.** Cost-cutting selectors that drop read events or KMS events remove the reconnaissance phase and the "who decrypted what" record, which are often the most useful parts of an investigation.

**No data events for the data that matters.** The bucket with customer exports, the Lambda function that issues refunds, the DynamoDB table with session tokens. Without data events, the answer to "what did the attacker read?" is "we cannot tell", which in a breach notification usually means "assume everything".

**Logs stored where the attacker can reach them.** The trail writes to a bucket in the same account the attacker controls, with no versioning, no Object Lock and a bucket policy that admins can rewrite. An administrator-level compromise can then delete or rewrite history, set a one-day lifecycle rule, or just remove the bucket policy statement so delivery fails.

**No integrity validation.** Without digest files you cannot show that the logs you hand to a regulator or a court are the logs CloudTrail wrote.

**Readable by too many people.** CloudTrail logs are a map of the estate (account IDs, role names, resource ARNs, IP ranges, request parameters). A log bucket readable by every developer, shared cross-account without conditions, or (worst case) public is a reconnaissance gift. Security Hub CSPM rates `CloudTrail.6` (public log bucket) Critical.

**Nobody is watching.** The trail is perfect and nothing consumes it: no CloudWatch Logs integration, no EventBridge rules, no SIEM. Tamper events such as `StopLogging` are recorded, and the record is read weeks later.

**Tampering is possible.** Any principal with `cloudtrail:*` (including every role with `AdministratorAccess`) can stop or reconfigure an account-local trail unless an SCP says otherwise. Organisation trails cannot be changed from member accounts, but the bucket, the KMS key and the CloudWatch Logs delivery can still be broken from the account that owns them.

**Delivery silently broken.** A changed bucket policy, a disabled KMS key or a deleted CloudWatch Logs role leaves `IsLogging: true` while `LatestDeliveryError` fills with `AccessDenied`. CloudTrail retries S3 delivery for a while, but a broken key or role is effectively a logging outage that no dashboard shows unless someone checks `get-trail-status`.

## Testing

All tests assume an **authorised engagement against the client's own AWS accounts**, with written scope, and respect for the [AWS penetration testing policy](https://aws.amazon.com/security/penetration-testing/). The tests are read-only unless marked otherwise, and **outputs shown are illustrative**, not captured from a real account.

### Before you start

**Access.** Read-only credentials in every account in scope: `SecurityAudit` (or `ViewOnlyAccess` plus `cloudtrail:Get*`, `cloudtrail:Describe*`, `cloudtrail:List*`), and in the management or log-archive account read access to the log bucket and `kms:Decrypt` on the trail key for [GT-AWS-CT-5](#gt-aws-ct-5-log-file-integrity-validation) and [GT-AWS-CT-11](#gt-aws-ct-11-investigation-readiness-with-athena). For organisation-wide checks you need `organizations:List*`/`Describe*` in the management account or a delegated administrator. Athena queries need `athena:StartQueryExecution`, `glue:CreateTable` (or an existing table) and a results bucket; agree this with the client, because creating a Glue table is a (harmless) write.

**Inputs from the client.** The list of accounts and Regions in scope, which Regions they use, which resources hold sensitive data (bucket names, functions, tables), the intended logging architecture, and who is supposed to receive alerts.

**Profiles and a Region loop.**

```bash
export AWS_PROFILE=client-audit          # SecurityAudit in the member account
aws sts get-caller-identity

# Enabled Regions only (opt-in Regions that are disabled are not returned)
REGIONS=$(aws ec2 describe-regions --query 'Regions[].RegionName' --output text)
for r in $REGIONS; do
  echo "== $r"
  aws cloudtrail describe-trails --region "$r" \
    --query 'trailList[].[Name,HomeRegion,IsMultiRegionTrail,IsOrganizationTrail]' --output text
done
```

**Tools.** AWS CLI v2 and `jq`; [Prowler](https://github.com/prowler-cloud/prowler) (`prowler aws --services cloudtrail` and `prowler aws --compliance cis_3.0_aws`); [ScoutSuite](https://github.com/nccgroup/ScoutSuite) for a second opinion; Steampipe (`aws_cloudtrail_trail` table) for SQL over the configuration; Pacu's `detection__enum_services` module, which enumerates CloudTrail, GuardDuty, Config and related services from a set of credentials and is a good way to see what an attacker holding those credentials would learn. For tamper-alert validation in a lab, [Stratus Red Team](https://stratus-red-team.cloud/) has CloudTrail techniques designed for exactly that purpose.

### GT-AWS-CT-1: Trail coverage across Regions and accounts

*Guler Tech methodology.*

#### What it checks

That every account in scope has at least one trail that is logging, multi-Region, and delivering, ideally an organisation trail, and that no account in the estate falls outside it.

#### Prerequisites

Read-only access in each member account, plus the management account or CloudTrail delegated administrator for the organisation view.

#### Steps

```bash
# 1. All trails visible from this account, including shadow copies of
#    multi-Region and organisation trails
aws cloudtrail describe-trails --include-shadow-trails --output json > trails.json
jq -r '.trailList[] | [.Name, .HomeRegion, .IsMultiRegionTrail, .IsOrganizationTrail,
       .LogFileValidationEnabled, (.KmsKeyId // "-"), (.CloudWatchLogsLogGroupArn // "-"),
       .S3BucketName] | @tsv' trails.json | sort -u

# 2. Is each distinct trail actually logging? Query it in its home Region.
for arn in $(jq -r '.trailList[].TrailARN' trails.json | sort -u); do
  home=$(echo "$arn" | cut -d: -f4)
  echo "== $arn"
  aws cloudtrail get-trail-status --name "$arn" --region "$home" \
    --query '[IsLogging, LatestDeliveryTime, LatestDeliveryError, LatestDigestDeliveryTime]' --output text
done

# 3. Organisation view (management account or delegated admin)
aws organizations describe-organization --query 'Organization.Id' --output text
aws organizations list-delegated-administrators --service-principal cloudtrail.amazonaws.com
aws organizations list-accounts --query 'Accounts[?Status==`ACTIVE`].[Id,Name]' --output text > accounts.txt
```

Then, for any account in the client's inventory that is **not** in `accounts.txt` (acquisitions, standalone accounts), repeat steps 1 and 2 in that account. For Regions, compare the enabled Region list in each account with the trail's coverage; a multi-Region trail covers all enabled Regions, a single-Region trail covers one.

Prowler: `prowler aws --checks cloudtrail_multi_region_enabled cloudtrail_multi_region_enabled_logging_management_events`.

#### Observation

```text
org-trail   eu-west-2   true   true   true   arn:aws:kms:eu-west-2:444455556666:key/EXAMPLE   arn:aws:logs:eu-west-2:111122223333:log-group:aws-cloudtrail-logs-org   org-cloudtrail-logs-444455556666
== arn:aws:cloudtrail:eu-west-2:111122223333:trail/org-trail
True    2026-11-02T10:05:12+00:00    None    2026-11-02T09:47:31+00:00
```

(Illustrative.)

#### Evaluation

- **Pass**: an organisation trail (or, in non-Organizations estates, an account trail) that is multi-Region, `IsLogging: True`, recent `LatestDeliveryTime`, no `LatestDeliveryError`, and every in-scope account is a member of that organisation.
- **Fail**: no trail; only single-Region trails; `IsLogging: False`; delivery errors; accounts outside the organisation with no trail of their own; organisation trail homed in an opt-in Region that some accounts have not enabled.
- **Note** a common false positive: Security Hub CSPM reports `CloudTrail.1` as `NO_DATA` (not failed) in member accounts that rely on an organisation trail owned by another account, and in Regions other than the trail's home Region. That is expected; confirm coverage from the trail owner's account.

#### Automated coverage

Security Hub CSPM `CloudTrail.1`, `CloudTrail.3`; CIS AWS v3.0.0 3.1 (v1.4.0 3.1); Prowler `cloudtrail_multi_region_enabled`, `cloudtrail_multi_region_enabled_logging_management_events`.

#### Detection

`StopLogging`, `DeleteTrail`, `UpdateTrail` (for example `IsMultiRegionTrail` turned off); GuardDuty `Stealth:IAMUser/CloudTrailLoggingDisabled`.

### GT-AWS-CT-2: Management events and event selectors

*Guler Tech methodology.*

#### What it checks

That the trail records **read and write** management events, without excluded event sources or principal exclusions that create blind spots.

#### Prerequisites

As GT-AWS-CT-1; run against the trail's home Region.

#### Steps

```bash
aws cloudtrail get-event-selectors --trail-name org-trail --region eu-west-2 > selectors.json

# Basic selectors: look for ReadWriteType and exclusions
jq '.EventSelectors[]? | {ReadWriteType, IncludeManagementEvents, ExcludeManagementEventSources}' selectors.json

# Advanced selectors: print every management selector and its fields
jq '.AdvancedEventSelectors[]? | select(any(.FieldSelectors[]; .Field=="eventCategory" and (.Equals|index("Management"))))' selectors.json
```

Read each advanced selector. A management selector with only `eventCategory Equals Management` records everything. Any additional field narrows it: `readOnly Equals false` drops reads; `eventSource NotEquals kms.amazonaws.com` drops KMS; `userIdentity.arn NotStartsWith ...` drops a principal.

#### Observation

```json
{
  "ReadWriteType": "WriteOnly",
  "IncludeManagementEvents": true,
  "ExcludeManagementEventSources": ["kms.amazonaws.com"]
}
```

(Illustrative: a trail that misses every read call and every KMS call.)

#### Evaluation

- **Pass**: management events, read and write, no excluded sources, no principal exclusions; or exclusions that are documented, justified, and covered by another trail or event data store.
- **Fail**: `WriteOnly`, `ReadOnly`, `ExcludeManagementEventSources` non-empty without compensating coverage, or exclusions on `userIdentity.arn` or `eventName` for principals that hold meaningful permissions. Explain the consequence concretely: "a compromised developer role enumerating Secrets Manager and decrypting with KMS would leave no trail record".

#### Automated coverage

Security Hub CSPM `CloudTrail.1` (it requires read and write management events on at least one multi-Region trail); Prowler `cloudtrail_multi_region_enabled_logging_management_events`.

#### Detection

`PutEventSelectors`, `UpdateTrail`. Datadog and other SIEM vendors ship rules for "CloudTrail disabled through event selectors"; check the client's SIEM has an equivalent.

### GT-AWS-CT-3: Data events for sensitive resources

*Guler Tech methodology.*

#### What it checks

That data events are recorded for the buckets, functions and tables the client classifies as sensitive, so an investigation can answer "what was read, written or invoked, and by whom".

#### Prerequisites

The client's list of sensitive resources (or tags that identify them). Read access to the trail's selectors and, for the optional proof, an approved test bucket.

#### Steps

```bash
# Which data event resource types and ARNs does each trail cover?
jq -r '.AdvancedEventSelectors[]? | select(any(.FieldSelectors[]; .Field=="eventCategory" and (.Equals|index("Data"))))
       | [.Name, (.FieldSelectors | map("\(.Field) \(.Equals // .StartsWith // .NotEquals // .NotStartsWith | tostring)") | join("; "))] | @tsv' selectors.json

# Basic selectors use DataResources instead
jq '.EventSelectors[]?.DataResources' selectors.json
```

Compare the result with the sensitive resource list. A selector with `resources.type Equals AWS::S3::Object` and no ARN filter covers all buckets; one with `resources.ARN StartsWith arn:aws:s3:::finance-exports/` covers one. Check Lambda (`AWS::Lambda::Function`) and DynamoDB (`AWS::DynamoDB::Table`) the same way, and any other resource type the client relies on (the CloudTrail data events page lists the supported types).

**Optional proof (lab or explicitly approved only):** write a harmless marker object to an approved test bucket that should be covered, wait 15 minutes, and look for the `PutObject` data event in the trail's S3 prefix or CloudWatch log group. Event history will not show it; data events are never in event history.

```bash
# Lab or explicitly approved only: writes one object
echo "guler-tech-ct-test $(date -u +%FT%TZ)" > marker.txt
aws s3 cp marker.txt s3://approved-test-bucket-example/guler-tech/marker.txt
```

#### Observation

Either a selector that clearly covers the sensitive resources, or, commonly, no `Data` selector at all.

#### Evaluation

- **Pass**: read and write data events for every resource the client classifies as sensitive, on a trail whose logs are protected as in GT-AWS-CT-6.
- **Fail**: no data events, or data events for write only on buckets whose main risk is exfiltration (reads). For S3, the CIS benchmark asks for object-level logging of both writes and reads.
- **Context**: "all S3 data events for all buckets" is expensive in busy accounts; a targeted selector on the sensitive buckets is a good answer. Do not mark cost-driven scoping as a failure if the sensitive set is covered.

#### Automated coverage

Security Hub CSPM `S3.22` (object-level write events) and `S3.23` (object-level read events); CIS AWS v3.0.0 3.8 and 3.9; Prowler `cloudtrail_s3_dataevents_write_enabled`, `cloudtrail_s3_dataevents_read_enabled`.

#### Detection

Data events themselves are the detection source for [T1530](https://attack.mitre.org/techniques/T1530/) (data from cloud storage): bursts of `GetObject` from one principal, `GetObject` from an unfamiliar IP or outside the client's VPC endpoints. GuardDuty S3 Protection (`Exfiltration:S3/AnomalousBehavior`, `Discovery:S3/AnomalousBehavior`) analyses S3 data events whether or not the client's trail records them.

### GT-AWS-CT-4: Network activity events and Insights

*Guler Tech methodology.*

#### What it checks

Two optional but valuable capabilities: **network activity events** on the client's VPC endpoints for key services (who used our endpoints, including principals from other accounts, and what was denied by the endpoint policy) and **Insights** on management events (unusual call or error rates).

#### Prerequisites

As GT-AWS-CT-2. A list of the client's VPC endpoints (see the [VPC note](/cloud/aws-vpc-edge-dns-security/)).

#### Steps

```bash
# Network activity selectors
jq '.AdvancedEventSelectors[]? | select(any(.FieldSelectors[]; .Field=="eventCategory" and (.Equals|index("NetworkActivity"))))' selectors.json

# VPC endpoints that exist, per Region
for r in $REGIONS; do
  aws ec2 describe-vpc-endpoints --region "$r" \
    --query 'VpcEndpoints[].[VpcEndpointId,ServiceName,VpcEndpointType]' --output text
done

# Insights
aws cloudtrail get-insight-selectors --trail-name org-trail --region eu-west-2
```

`get-insight-selectors` returns `InsightNotEnabledException` when Insights is off. When on, it lists `ApiCallRateInsight` and/or `ApiErrorRateInsight` and, for trails, the `EventCategories` (`Management`, `Data`).

#### Observation

Typically: no network activity selectors even though the client has interface endpoints for STS, KMS, Secrets Manager and S3 gateway endpoints; Insights off.

#### Evaluation

These are **improvements, not baseline failures**, unless the client's own standard requires them. Recommend network activity events (at least the `VpceAccessDenied` template) for endpoints in front of `kms.amazonaws.com`, `secretsmanager.amazonaws.com`, `sts.amazonaws.com` and `s3.amazonaws.com` where VPC endpoint policies are part of the data perimeter: denied calls are direct evidence of someone using credentials from outside the perimeter. Recommend `ApiErrorRateInsight` on management events as a cheap signal for credential enumeration. Remember that network activity events are recorded in the **endpoint owner's** account, which in hub-and-spoke networks is often a shared networking account, not the workload account.

#### Automated coverage

Prowler `cloudtrail_insights_exist`. No Security Hub CSPM control covers network activity events at the time of writing.

#### Detection

`errorCode` `VpceAccessDenied` in network activity events; EventBridge detail-type `AWS Network Activity Event via CloudTrail`; Insights events (`AWS Insight via CloudTrail`).

### GT-AWS-CT-5: Log file integrity validation

*Guler Tech methodology.*

#### What it checks

That log file validation is enabled and that the delivered logs actually validate, so the client can prove the logs were not altered after delivery.

#### Prerequisites

Read access to the log bucket (`s3:ListBucket`, `s3:GetObject`, `s3:GetBucketLocation`), `kms:Decrypt` on the trail key if SSE-KMS is used, and the trail ARN. For organisation trails you need `--account-id` for each account you validate.

#### Steps

```bash
# Configuration
jq -r '.trailList[] | [.Name, .LogFileValidationEnabled] | @tsv' trails.json | sort -u

# Validate one week for one member account of an organisation trail
aws cloudtrail validate-logs \
  --trail-arn arn:aws:cloudtrail:eu-west-2:111122223333:trail/org-trail \
  --account-id 444455556666 \
  --start-time 2026-10-26T00:00:00Z --end-time 2026-11-02T00:00:00Z \
  --region eu-west-2
```

`validate-logs` is Region-specific and only checks files referenced by digest files. Run it per Region you care about (at minimum the home Region and the client's main Regions).

#### Observation

```text
Results requested for 2026-10-26T00:00:00Z to 2026-11-02T00:00:00Z
Results found for 2026-10-26T00:47:31Z to 2026-11-02T00:47:31Z:

168/168 digest files valid
2214/2214 log files valid
```

(Illustrative.)

#### Evaluation

- **Pass**: validation enabled on every trail that is the system of record; `validate-logs` reports all digests and log files valid for a sample window.
- **Fail**: validation disabled (Security Hub CSPM rates this Low on its own, but raise it to Medium where the logs are the client's evidence for regulators); any `INVALID: hash value doesn't match`, `INVALID: not found` for log files, or gaps in the digest chain without an explanation (a trail that was stopped, which should itself show as `StopLogging`/`StartLogging` events). Treat any unexplained invalid result as a potential incident, not a configuration finding, and escalate under the engagement's incident clause.

#### Automated coverage

Security Hub CSPM `CloudTrail.4`; CIS AWS v3.0.0 3.2; Prowler `cloudtrail_log_file_validation_enabled`. Neither tool runs `validate-logs`; that step is manual.

#### Detection

`UpdateTrail` with `enableLogFileValidation` set to `false`; S3 `DeleteObject` or `PutObject` on the `CloudTrail-Digest/` prefix by anyone other than CloudTrail (needs S3 data events or server access logs on the log bucket).

### GT-AWS-CT-6: Log bucket hardening and the log-archive account

*Guler Tech methodology.*

#### What it checks

That the S3 bucket holding the logs cannot be read broadly, written by anything except CloudTrail for the right trail, or used to delete or rewrite history, and that it lives in an account that workload administrators do not control.

#### Prerequisites

Read access to the bucket's configuration in the account that owns it.

#### Steps

```bash
B=org-cloudtrail-logs-444455556666
aws s3api get-bucket-location --bucket "$B"
aws s3api get-bucket-policy --bucket "$B" --query Policy --output text | jq .
aws s3api get-public-access-block --bucket "$B"
aws s3api get-bucket-ownership-controls --bucket "$B"
aws s3api get-bucket-versioning --bucket "$B"
aws s3api get-object-lock-configuration --bucket "$B"
aws s3api get-bucket-lifecycle-configuration --bucket "$B"
aws s3api get-bucket-logging --bucket "$B"
aws s3api get-bucket-encryption --bucket "$B"
aws s3api get-bucket-replication --bucket "$B"
```

Review the bucket policy line by line:

1. **CloudTrail write statements** have `Principal` `cloudtrail.amazonaws.com`, `s3:PutObject` scoped to `AWSLogs/...`, `s3:x-amz-acl` `bucket-owner-full-control`, and an **`aws:SourceArn` condition naming the trail(s)** (AWS recommends this for all trails; it stops another account's trail from writing into the client's bucket).
2. **Read access** is limited to named roles (security, incident response, the SIEM ingestion role), not `arn:aws:iam::<account>:root` of every member account and never `*` without a tight condition.
3. **Deny statements** for non-TLS access (`aws:SecureTransport` `false`) and for deletion and policy changes except by a break-glass role.

Then check where the bucket lives: it should be in a dedicated log-archive account, not in a workload account and ideally not in the management account.

#### Observation

```json
{
  "Sid": "AWSCloudTrailWrite20150319",
  "Effect": "Allow",
  "Principal": { "Service": "cloudtrail.amazonaws.com" },
  "Action": "s3:PutObject",
  "Resource": "arn:aws:s3:::org-cloudtrail-logs-444455556666/AWSLogs/*",
  "Condition": { "StringEquals": { "s3:x-amz-acl": "bucket-owner-full-control" } }
}
```

(Illustrative: no `aws:SourceArn`, and `AWSLogs/*` instead of the account or organisation prefix.)

#### Evaluation

- **Critical**: bucket or objects publicly readable (Block Public Access off and a public policy or ACL).
- **High**: logs in the same account as the workloads with no versioning or Object Lock and no deny on deletion, so any administrator compromise can erase the record; or read access granted to all member accounts' root principals (every admin in every account can read the whole organisation's logs).
- **Medium**: missing `aws:SourceArn` on the CloudTrail statements; versioning without Object Lock or MFA delete; short lifecycle expiry that conflicts with the client's retention requirement; no server access logging on the bucket (you cannot see who read the logs).
- **Pass**: dedicated log-archive account; Block Public Access on; ACLs disabled (`BucketOwnerEnforced`); write statements scoped by `aws:SourceArn`; reads limited to named roles; versioning with **Object Lock** (compliance or governance mode with a default retention the client can justify); TLS enforced; access logging on.

Object Lock note: AWS's CloudTrail documentation does not discuss Object Lock in depth; buckets with Object Lock and a default retention period accept CloudTrail deliveries, but test in a lab first, and remember that compliance mode cannot be shortened by anyone, including the client.

#### Automated coverage

Security Hub CSPM `CloudTrail.6` (CIS v1.4.0 3.3), `CloudTrail.7` (CIS AWS v3.0.0 3.4), `S3.1`, `S3.5`, `S3.8`, `S3.14`, `S3.15`, `S3.20`; Prowler `cloudtrail_logs_s3_bucket_is_not_publicly_accessible`, `cloudtrail_logs_s3_bucket_access_logging_enabled`, `cloudtrail_bucket_requires_mfa_delete`. See also the [S3 note](/cloud/aws-s3-security/).

#### Detection

`PutBucketPolicy`, `DeleteBucketPolicy`, `PutBucketLifecycle` / `PutBucketLifecycleConfiguration`, `PutBucketVersioning`, `PutObjectLockConfiguration`, `DeleteBucket`, `PutPublicAccessBlock` / `DeletePublicAccessBlock` on the log bucket; GuardDuty `Policy:S3/BucketBlockPublicAccessDisabled`, `Stealth:S3/ServerAccessLoggingDisabled`.

### GT-AWS-CT-7: SSE-KMS encryption and the key policy

*Guler Tech methodology.*

#### What it checks

That the trail encrypts with a customer managed KMS key whose policy lets CloudTrail encrypt for the right trail only, and lets only intended readers decrypt.

#### Prerequisites

`kms:GetKeyPolicy` and `kms:DescribeKey` on the trail key (in the key's account).

#### Steps

```bash
KEY=$(jq -r '.trailList[] | select(.Name=="org-trail") | .KmsKeyId' trails.json | head -1)
aws kms describe-key --key-id "$KEY" --query 'KeyMetadata.[KeyState,KeyManager,MultiRegion]'
aws kms get-key-policy --key-id "$KEY" --policy-name default --output text | jq .
aws kms get-key-rotation-status --key-id "$KEY"
aws kms list-grants --key-id "$KEY" --query 'Grants[].[GranteePrincipal,Operations]'
```

In the key policy, look for:

- `cloudtrail.amazonaws.com` allowed `kms:GenerateDataKey*` with `aws:SourceArn` equal to the trail ARN and `kms:EncryptionContext:aws:cloudtrail:arn` limited to the client's accounts.
- `kms:Decrypt` granted to specific roles, with the `kms:EncryptionContext:aws:cloudtrail:arn` `Null` `false` condition AWS uses in its examples, and not to `arn:aws:iam::<account>:root` of many accounts.
- Who can `kms:PutKeyPolicy`, `kms:DisableKey` and `kms:ScheduleKeyDeletion`. Those principals can stop log delivery.

#### Observation

A key in the log-archive account, rotation enabled, CloudTrail encrypt statement without `aws:SourceArn`, and `kms:Decrypt` granted to the root principal of the log-archive account (which delegates to every IAM principal there with a matching identity policy).

#### Evaluation

- **Pass**: customer managed key, enabled, rotation on, encrypt scoped to the trail, decrypt limited to the people and tools that read logs, key administration limited to a small security role set.
- **Fail (Medium)**: SSE-S3 only on a trail that is the system of record (anyone with `s3:GetObject` reads the logs); key policy that lets broad sets of principals decrypt or administer the key.
- **Context**: SSE-KMS is about *who can read*; it adds a second permission check. It does not stop deletion. A key that workload admins can disable is a tamper path (delivery stops) and should be reported with GT-AWS-CT-9.

#### Automated coverage

Security Hub CSPM `CloudTrail.2` (CIS AWS v3.0.0 3.5), `CloudTrail.10` (Lake event data stores with customer managed keys), `KMS.4`; Prowler `cloudtrail_kms_encryption_enabled`.

#### Detection

`DisableKey`, `ScheduleKeyDeletion`, `PutKeyPolicy`, `CreateGrant` on the trail key; CloudTrail `LatestDeliveryError` mentioning KMS. See the [Secrets Manager, Parameter Store and KMS note](/cloud/aws-secrets-manager-parameter-store-kms/) for key policy review in depth.

### GT-AWS-CT-8: Delivery health and CloudWatch Logs integration

*Guler Tech methodology.*

#### What it checks

That logs are actually arriving everywhere they are supposed to (S3, digest files, CloudWatch Logs), and that the CloudWatch Logs integration exists so real-time detection is possible.

#### Prerequisites

As GT-AWS-CT-1, plus `logs:DescribeLogGroups` in the trail's account.

#### Steps

```bash
aws cloudtrail get-trail-status --name org-trail --region eu-west-2 --output json \
  | jq '{IsLogging, LatestDeliveryTime, LatestDeliveryError, LatestDigestDeliveryTime,
         LatestDigestDeliveryError, LatestCloudWatchLogsDeliveryTime, LatestCloudWatchLogsDeliveryError}'

LG=$(jq -r '.trailList[] | select(.Name=="org-trail") | .CloudWatchLogsLogGroupArn' trails.json | head -1)
echo "$LG"
aws logs describe-log-groups --log-group-name-prefix aws-cloudtrail-logs \
  --query 'logGroups[].[logGroupName,retentionInDays,kmsKeyId,logGroupClass]' --output text
```

Confirm the IAM role named in `CloudWatchLogsRoleArn` still exists and that its policy allows `logs:CreateLogStream` and `logs:PutLogEvents` on the log group (for organisation trails, on log streams prefixed with the organisation ID as well).

#### Observation

```json
{
  "IsLogging": true,
  "LatestDeliveryTime": "2026-11-02T10:05:12+00:00",
  "LatestDeliveryError": null,
  "LatestDigestDeliveryTime": "2026-11-02T09:47:31+00:00",
  "LatestDigestDeliveryError": null,
  "LatestCloudWatchLogsDeliveryTime": "2026-10-03T22:11:40+00:00",
  "LatestCloudWatchLogsDeliveryError": "AccessDeniedException"
}
```

(Illustrative: S3 delivery healthy, CloudWatch Logs delivery broken for a month. Every metric filter and alarm built on that log group has been blind for a month.)

#### Evaluation

- **Pass**: no delivery errors; recent delivery times for S3, digests and CloudWatch Logs; the CloudWatch log group has a retention policy and (ideally) a KMS key; or an equivalent real-time pipeline (EventBridge rules, SIEM ingestion from S3) that the client can show working.
- **Fail**: any delivery error; CloudWatch Logs integration absent and no alternative real-time consumer; CloudWatch Logs delivery older than a day on an active account.
- CIS v3.0.0 and v5.0.0 dropped the "integrated with CloudWatch Logs" requirement (Security Hub CSPM shows `CloudTrail.5` as "Not supported – CIS removed this requirement" for those versions), so a client with a SIEM reading S3 and EventBridge can pass without it. The requirement is to have *a* real-time consumer, and to prove it is receiving.

#### Automated coverage

Security Hub CSPM `CloudTrail.5` (CIS v1.4.0 3.4); Prowler `cloudtrail_cloudwatch_logging_enabled`. Neither checks `LatestCloudWatchLogsDeliveryError`; that is manual.

#### Detection

`UpdateTrail` removing `CloudWatchLogsLogGroupArn`; `DeleteLogGroup`, `PutRetentionPolicy` on the CloudTrail log group; IAM changes to the delivery role (`DeleteRole`, `PutRolePolicy`, `DetachRolePolicy`). See the [CloudWatch note](/cloud/aws-cloudwatch-eventbridge-monitoring/) for alerting on these.

### GT-AWS-CT-9: Tamper prevention with SCPs

*Guler Tech methodology.*

#### What it checks

That service control policies prevent member-account principals, including administrators, from stopping, deleting or reconfiguring the logging the organisation depends on, and from breaking it indirectly through the bucket, the key or the CloudWatch Logs delivery.

#### Prerequisites

Management account or delegated administrator read access to Organizations policies; `iam:SimulatePrincipalPolicy` in a member account for the simulation step (simulation does not evaluate SCPs; see below).

#### Steps

```bash
aws organizations list-policies --filter SERVICE_CONTROL_POLICY \
  --query 'Policies[].[Id,Name]' --output text
aws organizations describe-policy --policy-id p-examplescp1 \
  --query Policy.Content --output text | jq .
aws organizations list-targets-for-policy --policy-id p-examplescp1
```

Look for a `Deny` that covers at least:

| Area | Actions |
|---|---|
| Trails | `cloudtrail:StopLogging`, `cloudtrail:DeleteTrail`, `cloudtrail:UpdateTrail`, `cloudtrail:PutEventSelectors`, `cloudtrail:PutInsightSelectors` |
| Lake (if used) | `cloudtrail:DeleteEventDataStore`, `cloudtrail:UpdateEventDataStore`, `cloudtrail:StopEventDataStoreIngestion` |
| Delivery path | `logs:DeleteLogGroup`, `logs:PutRetentionPolicy` on the CloudTrail log group; IAM changes to the CloudTrail CloudWatch Logs role |
| Bucket and key | Deletion, policy and lifecycle changes on the log bucket; `kms:DisableKey`, `kms:ScheduleKeyDeletion`, `kms:PutKeyPolicy` on the trail key (usually enforced in the log-archive account) |

with a narrowly scoped exception (a break-glass or platform role via `aws:PrincipalArn`), attached to the root or every OU that contains workload accounts.

**How to verify without changing anything.** `simulate-principal-policy` does not evaluate SCPs, so it cannot prove the deny works. Read the SCP and its attachment points instead, and check CloudTrail for real denials: an `errorCode` of `AccessDenied` with an `errorMessage` mentioning "service control policy" on any of these actions shows the SCP has blocked someone.

```bash
aws cloudtrail lookup-events --region eu-west-2 \
  --lookup-attributes AttributeKey=EventName,AttributeValue=StopLogging \
  --start-time 2026-08-01T00:00:00Z \
  --query 'Events[].CloudTrailEvent' --output text | jq -r '[.eventTime, .userIdentity.arn, .errorCode, .errorMessage] | @tsv'
```

**Active proof (lab or explicitly approved only):** in a sandbox account under the same OU, create a throwaway trail (or use a test role) and call `aws cloudtrail stop-logging --name <test-trail>`; the expected result is `AccessDeniedException` with an explicit deny in a service control policy, and an alert from GT-AWS-CT-10. Never call it against the production or organisation trail.

#### Observation

Commonly: no SCP at all; or an SCP that denies `StopLogging` and `DeleteTrail` but not `PutEventSelectors` or `UpdateTrail`, which achieve the same result.

#### Evaluation

- **Pass**: an SCP that covers the trail, Lake (if used) and the delivery path, attached across all workload OUs, with a narrow exception; organisation trail used, so member accounts cannot alter it anyway; management account used only by a very small set of principals (SCPs do not apply to it).
- **Fail (Medium; High where the account-local trail is the only trail or covers the management account)**: no SCP and account-local trails that any administrator can stop; SCP with gaps that allow equivalent tampering.

#### Automated coverage

None of the CSPM tools evaluate SCP content for this. Prowler and Security Hub CSPM report the trail configuration, not whether it can be changed. See the [Organizations note](/cloud/aws-organizations-multi-account-security/) for SCP review.

#### Detection

`StopLogging`, `DeleteTrail`, `UpdateTrail`, `PutEventSelectors`, `PutInsightSelectors`, `DeleteEventDataStore`, `UpdateEventDataStore`, `StopEventDataStoreIngestion` (successful or denied), Organizations `DetachPolicy`, `UpdatePolicy`, `DeletePolicy` on the SCP. Denied attempts are as important as successes: a denied `StopLogging` from a workload role means someone tried.

### GT-AWS-CT-10: Alerting on tamper events

*Guler Tech methodology.*

#### What it checks

That a tamper event on CloudTrail produces an alert that reaches a human within minutes, in every Region where it can happen.

#### Prerequisites

Read access to CloudWatch metric filters and alarms, EventBridge rules, SNS subscriptions, and (if used) GuardDuty and the client's SIEM rule list.

#### Steps

Check the three usual mechanisms; the client needs at least one that works end to end.

```bash
# 1. CIS-style metric filter on the CloudTrail log group (CloudWatch.5 pattern)
aws logs describe-metric-filters --log-group-name aws-cloudtrail-logs-org \
  --query 'metricFilters[].[filterName,filterPattern,metricTransformations[0].metricName]' --output text \
  | grep -i -E 'StopLogging|DeleteTrail|UpdateTrail'

# 2. EventBridge rules on CloudTrail events, per Region
for r in $REGIONS; do
  aws events list-rules --region "$r" --query 'Rules[].[Name,State,EventPattern]' --output text \
    | grep -i -E 'cloudtrail' && echo "   ^ $r"
done

# 3. GuardDuty enabled per Region (finding Stealth:IAMUser/CloudTrailLoggingDisabled)
for r in $REGIONS; do
  echo "$r $(aws guardduty list-detectors --region "$r" --query 'DetectorIds' --output text)"
done
```

For each mechanism, follow the chain to the end: metric filter → alarm with `ActionsEnabled: true` → SNS topic → **confirmed** subscription (not `PendingConfirmation`) to a monitored destination. The [CloudWatch note](/cloud/aws-cloudwatch-eventbridge-monitoring/) has a script that does this for all CIS filters.

Ask the client for the last alert raised for a CloudTrail configuration change and how long it took to be acknowledged. If there has never been one, propose a lab or approved test from GT-AWS-CT-9.

#### Observation

A metric filter matching the CIS pattern exists, but its alarm's SNS topic has one subscription, to the email address of someone who left the company.

#### Evaluation

- **Pass**: at least one mechanism that fires on `StopLogging`, `DeleteTrail`, `UpdateTrail`, `PutEventSelectors` (and Lake tamper events if Lake is used), in every Region where the trails or data stores live, ending at a confirmed, monitored destination, with evidence of a recent test.
- **Fail (Medium; High where tampering is also not prevented by SCP)**: no mechanism, or a broken chain.
- Note that the CIS `CloudWatch.5` pattern lists `CreateTrail`, `UpdateTrail`, `DeleteTrail`, `StartLogging` and `StopLogging` only; it does **not** include `PutEventSelectors`. Recommend extending it (outside the CIS exact-match check, so put it in a separate filter or an EventBridge rule).

#### Automated coverage

Security Hub CSPM `CloudWatch.5` (CIS v1.4.0 4.5); Prowler `cloudwatch_log_metric_filter_and_alarm_for_cloudtrail_configuration_changes_enabled`.

#### Detection

This test *is* the detection. ATT&CK maps tampering with cloud logs to [T1685.002, Disable or Modify Cloud Log](https://attack.mitre.org/techniques/T1685/002/) (ATT&CK v20 revoked T1562.008 and moved it there, under the new Defense Impairment tactic; older references still use T1562.008).

### GT-AWS-CT-11: Investigation readiness with Athena

*Guler Tech methodology.*

#### What it checks

That the client can answer basic incident questions from the trail within an hour: what did this access key do, who called this API, what happened in this Region, what did this IP touch.

#### Prerequisites

Agreement to create an Athena table (a Glue Data Catalog write) and a results location, or an existing table. Read access to the log bucket and `kms:Decrypt` on the key.

#### Steps

Create a table with partition projection over an organisation trail (adapt the account and Region lists; for a single-account trail drop the `account` partition and the organisation ID from the path):

```sql
CREATE EXTERNAL TABLE cloudtrail_org (
  eventversion STRING,
  useridentity STRUCT<
    type: STRING, principalid: STRING, arn: STRING, accountid: STRING,
    invokedby: STRING, accesskeyid: STRING, username: STRING,
    sessioncontext: STRUCT<
      attributes: STRUCT<mfaauthenticated: STRING, creationdate: STRING>,
      sessionissuer: STRUCT<type: STRING, principalid: STRING, arn: STRING, accountid: STRING, username: STRING>,
      sourceidentity: STRING>>,
  eventtime STRING,
  eventsource STRING,
  eventname STRING,
  awsregion STRING,
  sourceipaddress STRING,
  useragent STRING,
  errorcode STRING,
  errormessage STRING,
  requestparameters STRING,
  responseelements STRING,
  additionaleventdata STRING,
  requestid STRING,
  eventid STRING,
  readonly STRING,
  resources ARRAY<STRUCT<arn: STRING, accountid: STRING, type: STRING>>,
  eventtype STRING,
  recipientaccountid STRING,
  sharedeventid STRING,
  vpcendpointid STRING,
  eventcategory STRING
)
PARTITIONED BY (account STRING, region STRING, `timestamp` STRING)
ROW FORMAT SERDE 'org.apache.hive.hcatalog.data.JsonSerDe'
STORED AS INPUTFORMAT 'com.amazon.emr.cloudtrail.CloudTrailInputFormat'
OUTPUTFORMAT 'org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat'
LOCATION 's3://org-cloudtrail-logs-444455556666/AWSLogs/o-exampleorgid/'
TBLPROPERTIES (
  'projection.enabled'='true',
  'projection.account.type'='enum',
  'projection.account.values'='111122223333,444455556666,123456789012',
  'projection.region.type'='enum',
  'projection.region.values'='eu-west-2,eu-west-1,us-east-1',
  'projection.timestamp.type'='date',
  'projection.timestamp.format'='yyyy/MM/dd',
  'projection.timestamp.interval'='1',
  'projection.timestamp.interval.unit'='DAYS',
  'projection.timestamp.range'='2025/01/01,NOW',
  'storage.location.template'='s3://org-cloudtrail-logs-444455556666/AWSLogs/o-exampleorgid/${account}/CloudTrail/${region}/${timestamp}'
);
```

The column list follows AWS's [Athena CloudTrail table](https://docs.aws.amazon.com/athena/latest/ug/create-cloudtrail-table-partition-projection.html) with fields trimmed for readability; use AWS's full definition in practice. Always filter on the partition columns, or Athena scans (and bills for) the whole bucket.

Then run a few questions the client should be able to answer:

```sql
-- 1. Everything one access key did (leaked-key triage)
SELECT eventtime, account, region, eventsource, eventname, errorcode, sourceipaddress, useragent
FROM cloudtrail_org
WHERE useridentity.accesskeyid = '<ACCESS_KEY_ID>'
  AND "timestamp" BETWEEN '2026/10/01' AND '2026/11/02'
ORDER BY eventtime;

-- 2. Tamper attempts on logging, successful or denied
SELECT eventtime, account, region, useridentity.arn, eventname, errorcode, sourceipaddress
FROM cloudtrail_org
WHERE eventsource = 'cloudtrail.amazonaws.com'
  AND eventname IN ('StopLogging','DeleteTrail','UpdateTrail','PutEventSelectors',
                    'PutInsightSelectors','DeleteEventDataStore','UpdateEventDataStore',
                    'StopEventDataStoreIngestion')
  AND "timestamp" >= '2026/08/01'
ORDER BY eventtime;

-- 3. Principals with many denied calls across many services (enumeration)
SELECT useridentity.arn, count(*) AS denied, count(DISTINCT eventsource) AS services,
       array_agg(DISTINCT sourceipaddress) AS ips
FROM cloudtrail_org
WHERE errorcode IN ('AccessDenied','Client.UnauthorizedOperation','UnauthorizedOperation')
  AND "timestamp" >= '2026/10/26'
GROUP BY useridentity.arn
HAVING count(DISTINCT eventsource) >= 5
ORDER BY denied DESC
LIMIT 50;

-- 4. Activity in Regions the client says it does not use
SELECT region, eventsource, eventname, useridentity.arn, count(*) AS n
FROM cloudtrail_org
WHERE region NOT IN ('eu-west-2','eu-west-1','us-east-1')
  AND eventtype = 'AwsApiCall' AND readonly = 'false'
  AND "timestamp" >= '2026/10/01'
GROUP BY 1,2,3,4
ORDER BY n DESC;

-- 5. Console sign-ins without MFA by IAM users and all root activity
SELECT eventtime, account, useridentity.type, useridentity.arn, eventname, sourceipaddress,
       json_extract_scalar(additionaleventdata, '$.MFAUsed') AS mfa
FROM cloudtrail_org
WHERE "timestamp" >= '2026/10/01'
  AND ((eventname = 'ConsoleLogin' AND useridentity.type = 'IAMUser'
        AND json_extract_scalar(additionaleventdata, '$.MFAUsed') = 'No')
       OR useridentity.type = 'Root')
ORDER BY eventtime;
```

(For query 4, add the Regions the client does not use to `projection.region.values`; projection only reads the partitions you enumerate.)

#### Observation

Time to first answer, whether the queries return what you expect, and whether the analyst running them had to ask for new permissions.

#### Evaluation

- **Pass**: the client (not just you) can run these within an hour, against logs covering at least the retention their regulator or contracts require, with access limited to the incident response roles.
- **Fail (Low to Medium)**: no prepared table or SIEM equivalent; queries time out or cost too much because nothing is partitioned; nobody in the client's team holds `kms:Decrypt` on the trail key outside office hours.

#### Automated coverage

None; this is a readiness exercise.

#### Detection

Athena and Glue calls on the log bucket are themselves logged (`StartQueryExecution`, `GetTable`); an attacker querying the client's CloudTrail to learn the estate is [T1654, Log Enumeration](https://attack.mitre.org/techniques/T1654/). Restrict and monitor who can read the logs.

## Hardening

**Architecture.** One multi-Region organisation trail created by a CloudTrail delegated administrator (usually the security tooling account), management and data events as required, log file validation on, delivering to a bucket in a dedicated log-archive account, encrypted with a customer managed key in that account, with CloudWatch Logs or SIEM ingestion for real-time detection. Teams that need their own data events can add account trails; they do not replace the organisation trail.

**Terraform for the organisation trail** (in the management account or delegated administrator; trimmed):

```hcl
resource "aws_cloudtrail" "org" {
  name                          = "org-trail"
  s3_bucket_name                = "org-cloudtrail-logs-444455556666"
  kms_key_id                    = "arn:aws:kms:eu-west-2:444455556666:key/EXAMPLE-KEY-ID"
  is_multi_region_trail         = true
  is_organization_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true
  cloud_watch_logs_group_arn    = "${aws_cloudwatch_log_group.ct.arn}:*"
  cloud_watch_logs_role_arn     = aws_iam_role.ct_to_cwl.arn

  advanced_event_selector {
    name = "All management events"
    field_selector {
      field  = "eventCategory"
      equals = ["Management"]
    }
  }

  advanced_event_selector {
    name = "S3 data events for sensitive buckets"
    field_selector {
      field  = "eventCategory"
      equals = ["Data"]
    }
    field_selector {
      field  = "resources.type"
      equals = ["AWS::S3::Object"]
    }
    field_selector {
      field       = "resources.ARN"
      starts_with = ["arn:aws:s3:::finance-exports-example/", "arn:aws:s3:::customer-data-example/"]
    }
  }

  insight_selector {
    insight_type = "ApiErrorRateInsight"
  }
}
```

**Log bucket policy** (log-archive account): CloudTrail writes scoped by `aws:SourceArn`, reads limited to named roles, TLS enforced, deletion and policy changes denied except for a break-glass role.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AWSCloudTrailAclCheck",
      "Effect": "Allow",
      "Principal": { "Service": "cloudtrail.amazonaws.com" },
      "Action": "s3:GetBucketAcl",
      "Resource": "arn:aws:s3:::org-cloudtrail-logs-444455556666",
      "Condition": {
        "StringEquals": { "aws:SourceArn": "arn:aws:cloudtrail:eu-west-2:111122223333:trail/org-trail" }
      }
    },
    {
      "Sid": "AWSCloudTrailOrgWrite",
      "Effect": "Allow",
      "Principal": { "Service": "cloudtrail.amazonaws.com" },
      "Action": "s3:PutObject",
      "Resource": [
        "arn:aws:s3:::org-cloudtrail-logs-444455556666/AWSLogs/111122223333/*",
        "arn:aws:s3:::org-cloudtrail-logs-444455556666/AWSLogs/o-exampleorgid/*"
      ],
      "Condition": {
        "StringEquals": {
          "s3:x-amz-acl": "bucket-owner-full-control",
          "aws:SourceArn": "arn:aws:cloudtrail:eu-west-2:111122223333:trail/org-trail"
        }
      }
    },
    {
      "Sid": "DenyNonTLS",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::org-cloudtrail-logs-444455556666",
        "arn:aws:s3:::org-cloudtrail-logs-444455556666/*"
      ],
      "Condition": { "Bool": { "aws:SecureTransport": "false" } }
    },
    {
      "Sid": "DenyTamperExceptBreakGlass",
      "Effect": "Deny",
      "Principal": "*",
      "Action": [
        "s3:DeleteObject", "s3:DeleteObjectVersion", "s3:DeleteBucket",
        "s3:PutBucketPolicy", "s3:DeleteBucketPolicy", "s3:PutLifecycleConfiguration",
        "s3:PutBucketVersioning", "s3:PutBucketObjectLockConfiguration"
      ],
      "Resource": [
        "arn:aws:s3:::org-cloudtrail-logs-444455556666",
        "arn:aws:s3:::org-cloudtrail-logs-444455556666/*"
      ],
      "Condition": {
        "ArnNotLike": { "aws:PrincipalArn": "arn:aws:iam::444455556666:role/LogArchiveBreakGlass" }
      }
    }
  ]
}
```

Add versioning and **Object Lock** with a default retention matching the client's requirement, Block Public Access, `BucketOwnerEnforced` object ownership, and server access logging to a separate bucket. Lifecycle transitions to cheaper storage classes are fine; expiry should only happen after the retention period.

**SCP protecting logging** (attach to the root or all workload OUs; it does not apply to the management account):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ProtectCloudTrail",
      "Effect": "Deny",
      "Action": [
        "cloudtrail:StopLogging",
        "cloudtrail:DeleteTrail",
        "cloudtrail:UpdateTrail",
        "cloudtrail:PutEventSelectors",
        "cloudtrail:PutInsightSelectors",
        "cloudtrail:DeleteEventDataStore",
        "cloudtrail:UpdateEventDataStore",
        "cloudtrail:StopEventDataStoreIngestion"
      ],
      "Resource": "*",
      "Condition": {
        "ArnNotLike": { "aws:PrincipalArn": "arn:aws:iam::*:role/PlatformSecurityAdmin" }
      }
    },
    {
      "Sid": "ProtectCloudTrailLogGroup",
      "Effect": "Deny",
      "Action": [
        "logs:DeleteLogGroup",
        "logs:PutRetentionPolicy",
        "logs:DeleteSubscriptionFilter",
        "logs:DisassociateKmsKey"
      ],
      "Resource": "arn:aws:logs:*:*:log-group:aws-cloudtrail-logs-*",
      "Condition": {
        "ArnNotLike": { "aws:PrincipalArn": "arn:aws:iam::*:role/PlatformSecurityAdmin" }
      }
    }
  ]
}
```

If the client uses AWS Control Tower, its mandatory controls already protect the Control Tower trail and log-archive resources; check they are still in place rather than duplicating them. A **resource control policy** on the log bucket and key (S3 and KMS are supported RCP services) can add a data-perimeter layer: deny access from principals outside the organisation, excluding AWS service principals with `aws:PrincipalIsAWSService`. See the [Organizations note](/cloud/aws-organizations-multi-account-security/).

**KMS key policy** essentials: CloudTrail `kms:GenerateDataKey*` with `aws:SourceArn` and `kms:EncryptionContext:aws:cloudtrail:arn`; `kms:DescribeKey` for CloudTrail; `kms:Decrypt` for named reader roles only; key administration (`kms:PutKeyPolicy`, `kms:DisableKey`, `kms:ScheduleKeyDeletion`) for a security admin role only. Enable rotation.

**Detection on top.** Alarms or EventBridge rules for every tamper event above, GuardDuty in every Region, and a monthly `get-trail-status` and `validate-logs` check scripted into the client's operations. The [CloudWatch note](/cloud/aws-cloudwatch-eventbridge-monitoring/) has the patterns.

**AWS Config rules** that support continuous checking: `multi-region-cloudtrail-enabled`, `cloud-trail-encryption-enabled`, `cloud-trail-log-file-validation-enabled`, `cloud-trail-cloud-watch-logs-enabled`, `cloudtrail-enabled` (the managed rules behind `CloudTrail.1` to `CloudTrail.5`).

## Real-world cases

- **Logging bypass in IAM via an undocumented endpoint (2022–2023).** Datadog Security Labs found that some IAM API calls made through the undocumented `iamadmin` service did not produce CloudTrail events; AWS fixed it in October 2022 and the research was published in January 2023. The lesson for clients is not the technique (it no longer works) but the principle that CloudTrail coverage has gaps that are found and closed over time. [Datadog Security Labs](https://securitylabs.datadoghq.com/articles/iamadmin-cloudtrail-bypass/).
- **SCARLETEEL 2.0 (2023): what never reaches the trail.** Sysdig's write-up of an AWS intrusion notes that the attacker's traffic to an S3-compatible service outside AWS was, in its words, "not logged in the victim's CloudTrail", because it never touched AWS endpoints in the victim's account. CloudTrail answers questions about the AWS API; exfiltration over other paths needs VPC Flow Logs, DNS logs and host telemetry. [Sysdig](https://sysdig.com/blog/scarleteel-2-0/).
- **S3 ransomware with SSE-C (2025).** Halcyon described attackers using stolen keys to re-encrypt S3 objects with customer-provided keys (SSE-C) and set short lifecycle rules. The object-level writes that show this happening are S3 **data events**; the lifecycle change is a management event (`PutBucketLifecycle`). A client without S3 data events would see the second and not the first. [Halcyon](https://www.halcyon.ai/blog/abusing-aws-native-services-ransomware-encrypting-s3-buckets-with-sse-c); AWS's response: [Preventing unintended encryption of Amazon S3 objects](https://aws.amazon.com/blogs/security/preventing-unintended-encryption-of-amazon-s3-objects/).
- More incident write-ups, many of which hinge on what the victim's CloudTrail did or did not contain, are collected in [AWS security incidents and write-ups](/cloud/aws-security-incidents-and-writeups/).

## Rating findings

| Finding | Typical severity | Reasoning |
|---|---|---|
| Log bucket publicly readable | Critical | Unauthenticated read of a full map of the estate (accounts, roles, resources, IPs, request parameters); Security Hub CSPM rates `CloudTrail.6` Critical |
| No trail in an account (event history only), or trails stopped | High | 90 days of management events at best, no data events, nothing protected from an account admin; any incident in that account is largely uninvestigable. High rather than Critical because it enables no attack by itself |
| Logs in the workload account, deletable by account admins, no Object Lock and no SCP | High | An administrator-level compromise (one privilege escalation away for many roles) can erase evidence; blast radius is the account's whole history |
| Tampering not prevented by SCP, account-local trail only | Medium–High | Any admin can stop logging; High when it covers the management account or the only trail |
| Single-Region trail, or organisation coverage gaps | Medium | Blind spots in specific Regions or accounts; attackers use unused Regions for exactly this reason |
| Management events write-only or with excluded sources | Medium | Reconnaissance and KMS decrypt history missing; investigations cannot reconstruct what an attacker learned |
| No data events for sensitive buckets, functions or tables | Medium | Cannot tell what data was accessed; in a breach the client must assume all of it was |
| No alerting on tamper events, or broken alert chain | Medium (High with no SCP) | Tampering is recorded but nobody sees it in time |
| Delivery errors (S3, CloudWatch Logs) | Medium | A silent logging outage; severity follows what depends on the broken path |
| Log file validation disabled | Low–Medium | Logs cannot be proven intact; Medium where logs are regulatory or legal evidence |
| SSE-S3 instead of SSE-KMS; key or bucket readable by broad sets of principals | Low–Medium | Reconnaissance value to insiders and to anyone holding a broad read role |
| Missing `aws:SourceArn` on CloudTrail bucket or key statements | Low | Confused-deputy hardening; exploitation requires another account's trail to target the bucket and gains write of junk logs, not read |
| No network activity events or Insights | Info–Low | Improvement opportunity; raise to Low where VPC endpoint policies are a key control and nobody can see their denials |
| No prepared Athena/SIEM queries | Low | Readiness gap that lengthens investigations |

Rate up when the gap affects the management account, a log-archive account, or production accounts holding regulated data; rate down when a compensating control (a SIEM that ingests S3 directly, Control Tower guardrails) demonstrably covers it.

## Mapping

| Test | Security Hub CSPM | CIS AWS Foundations | ATT&CK |
|---|---|---|---|
| GT-AWS-CT-1 | CloudTrail.1, CloudTrail.3 | v3.0.0 3.1 (v1.4.0 3.1) | T1685.002, T1078.004 |
| GT-AWS-CT-2 | CloudTrail.1 | v3.0.0 3.1 | T1685.002 |
| GT-AWS-CT-3 | S3.22, S3.23 | v3.0.0 3.8, 3.9 (v1.4.0 3.10, 3.11) | T1530 |
| GT-AWS-CT-4 | — | — | T1078.004, T1530 |
| GT-AWS-CT-5 | CloudTrail.4 | v3.0.0 3.2 (v1.4.0 3.2) | T1685.002 |
| GT-AWS-CT-6 | CloudTrail.6, CloudTrail.7, S3.1, S3.5, S3.8, S3.14, S3.15, S3.20 | v3.0.0 3.4; v1.4.0 3.3, 3.6 | T1685.002, T1654, T1485 |
| GT-AWS-CT-7 | CloudTrail.2, CloudTrail.10, KMS.4 | v3.0.0 3.5 (v1.4.0 3.7) | T1685.002, T1654 |
| GT-AWS-CT-8 | CloudTrail.5 | v1.4.0 3.4 (removed in v3.0.0) | T1685.002 |
| GT-AWS-CT-9 | — | — | T1685.002 |
| GT-AWS-CT-10 | CloudWatch.5 | v1.4.0 4.5 (v3.0.0 4.5, manual) | T1685.002 |
| GT-AWS-CT-11 | — | — | T1654, T1078.004 |

CIS numbers come from the Security Hub CSPM CIS mapping table; v3.0.0 section 4 items are manual checks that Security Hub CSPM does not evaluate. T1685.002 replaced T1562.008 in ATT&CK v20.

## References

- AWS CloudTrail User Guide: [Working with CloudTrail event history](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/view-cloudtrail-events.html)
- AWS: [CloudTrail Lake availability change](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-lake-service-availability-change.html)
- AWS: [Logging network activity events](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-network-events-with-cloudtrail.html)
- AWS: [Working with CloudTrail Insights](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-insights-events-with-cloudtrail.html) and [Logging Insights events with the AWS CLI](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/insights-events-CLI-enable.html)
- AWS: [Validating CloudTrail log file integrity with the AWS CLI](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-log-file-validation-cli.html)
- AWS: [Amazon S3 bucket policy for CloudTrail](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/create-s3-bucket-policy-for-cloudtrail.html)
- AWS: [Configure AWS KMS key policies for CloudTrail](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/create-kms-key-policy-for-cloudtrail.html)
- AWS: [Sending events to CloudWatch Logs](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/send-cloudtrail-events-to-cloudwatch-logs.html)
- AWS: [Creating a trail for an organization](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/creating-trail-organization.html)
- AWS: [CloudTrail userIdentity element](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-user-identity.html) and [AWS Management Console sign-in events](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-aws-console-sign-in-events.html)
- AWS: [CloudTrail supported services and integrations](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-aws-service-specific-topics.html)
- AWS: [AWS service events delivered via CloudTrail (EventBridge)](https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-service-event-cloudtrail.html)
- Amazon Athena: [Create the table for CloudTrail logs using partition projection](https://docs.aws.amazon.com/athena/latest/ug/create-cloudtrail-table-partition-projection.html)
- AWS Security Hub CSPM: [CloudTrail controls](https://docs.aws.amazon.com/securityhub/latest/userguide/cloudtrail-controls.html), [CIS AWS Foundations Benchmark](https://docs.aws.amazon.com/securityhub/latest/userguide/cis-aws-foundations-benchmark.html)
- Amazon GuardDuty: [IAM finding types](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html)
- MITRE ATT&CK: [T1685.002 Disable or Modify Cloud Log](https://attack.mitre.org/techniques/T1685/002/), [T1530 Data from Cloud Storage](https://attack.mitre.org/techniques/T1530/), [T1654 Log Enumeration](https://attack.mitre.org/techniques/T1654/), [T1078.004 Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/)
- Tools: [Prowler](https://github.com/prowler-cloud/prowler), [ScoutSuite](https://github.com/nccgroup/ScoutSuite), [Pacu](https://github.com/RhinoSecurityLabs/pacu), [Stratus Red Team](https://stratus-red-team.cloud/)
- Research: [Datadog Security Labs, iamadmin CloudTrail bypass](https://securitylabs.datadoghq.com/articles/iamadmin-cloudtrail-bypass/)
