---
title: "AWS Detection and Posture Services: GuardDuty, Security Hub, Config and Friends"
date: 2026-11-12 18:15:00 +0000
subcategory: aws
summary: "Reviewing GuardDuty, Security Hub CSPM, Config, Inspector, Macie, Access Analyzer and flow logs: coverage, suppression, routing and detection validation."
refs: [GuardDuty.1, GuardDuty.5, GuardDuty.6, GuardDuty.7, GuardDuty.8, GuardDuty.9, GuardDuty.10, GuardDuty.11, Config.1, Inspector.1, Inspector.2, Inspector.3, Inspector.4, Macie.1, Macie.2, IAM.28, EC2.6, "CIS AWS v3.0.0 3.3", "CIS AWS v3.0.0 3.7", "CIS AWS v3.0.0 1.20", "CIS AWS v5.0.0 3.3", "CIS AWS v5.0.0 3.7", "CIS AWS v5.0.0 1.19", T1685, T1685.002, T1535, T1078.004, T1530, T1580]
tags: [aws, guardduty, security-hub, aws-config, detection, purple-team]
---

This note is part of our [AWS security testing guide](/cloud/aws-security-testing-guide/) and covers the AWS services whose job is to notice things: Amazon GuardDuty (threat detection), AWS Security Hub CSPM and the newer unified Security Hub (posture and aggregation), AWS Config (configuration recording), Amazon Inspector (vulnerabilities), Amazon Macie (sensitive data in S3), Amazon Detective (investigation), IAM Access Analyzer (external, internal and unused access), VPC Flow Logs, Route 53 Resolver query logs and, briefly, Amazon Security Lake. None of these services stops an attack. What they decide is whether anybody finds out, and how quickly. A review of them is therefore a review of *coverage* (every account, every Region, every relevant data source), of *tuning* (suppression rules, trusted lists and automation rules that quietly remove signal), and of *routing* (does a finding reach a human who acts on it). We also look at them from the other side: as evidence sources you can read during an assessment, and as controls you can validate in a purple-team way without touching production. CloudTrail itself has its own note ([CloudTrail and logging](/cloud/aws-cloudtrail-logging/)), alarm and event plumbing is in [CloudWatch and EventBridge monitoring](/cloud/aws-cloudwatch-eventbridge-monitoring/), and the organisation-level guardrails that should protect all of this are in [AWS Organizations and multi-account security](/cloud/aws-organizations-multi-account-security/).

## Contents

- [How it works](#how-it-works)
  - [The stack at a glance](#the-stack-at-a-glance)
  - [Amazon GuardDuty](#amazon-guardduty)
  - [Security Hub CSPM and the new Security Hub](#security-hub-cspm-and-the-new-security-hub)
  - [AWS Config](#aws-config)
  - [Amazon Inspector](#amazon-inspector)
  - [Amazon Macie](#amazon-macie)
  - [Amazon Detective](#amazon-detective)
  - [IAM Access Analyzer](#iam-access-analyzer)
  - [VPC Flow Logs](#vpc-flow-logs)
  - [Route 53 Resolver query logs](#route-53-resolver-query-logs)
  - [Amazon Security Lake](#amazon-security-lake)
  - [Delegated administrators for security services](#delegated-administrators-for-security-services)
  - [Reading these services as evidence](#reading-these-services-as-evidence)
- [What goes wrong](#what-goes-wrong)
- [Testing](#testing)
  - [Before you start](#before-you-start)
  - [GT-AWS-DET-1: GuardDuty enabled in every account and Region](#gt-aws-det-1-guardduty-enabled-in-every-account-and-region)
  - [GT-AWS-DET-2: GuardDuty protection plans and organisation auto-enable](#gt-aws-det-2-guardduty-protection-plans-and-organisation-auto-enable)
  - [GT-AWS-DET-3: GuardDuty suppression rules, trusted lists and threat lists](#gt-aws-det-3-guardduty-suppression-rules-trusted-lists-and-threat-lists)
  - [GT-AWS-DET-4: Findings are routed to a human](#gt-aws-det-4-findings-are-routed-to-a-human)
  - [GT-AWS-DET-5: Security Hub CSPM coverage, standards and automation rules](#gt-aws-det-5-security-hub-cspm-coverage-standards-and-automation-rules)
  - [GT-AWS-DET-6: AWS Config recorder coverage and aggregation](#gt-aws-det-6-aws-config-recorder-coverage-and-aggregation)
  - [GT-AWS-DET-7: Inspector and Macie coverage](#gt-aws-det-7-inspector-and-macie-coverage)
  - [GT-AWS-DET-8: IAM Access Analyzer coverage and open findings](#gt-aws-det-8-iam-access-analyzer-coverage-and-open-findings)
  - [GT-AWS-DET-9: VPC Flow Logs and Resolver query log coverage](#gt-aws-det-9-vpc-flow-logs-and-resolver-query-log-coverage)
  - [GT-AWS-DET-10: Delegated administrators and protection of security tooling](#gt-aws-det-10-delegated-administrators-and-protection-of-security-tooling)
  - [GT-AWS-DET-11: Detection validation in a lab or approved account](#gt-aws-det-11-detection-validation-in-a-lab-or-approved-account)
- [Hardening](#hardening)
- [Real-world cases](#real-world-cases)
- [Rating findings](#rating-findings)
- [Mapping](#mapping)
- [References](#references)

## How it works

### The stack at a glance

Each service answers a different question and has a different idea of what "enabled" means. Most of them are **Regional**: enabling one in `eu-west-2` tells you nothing about `ap-southeast-3`. Most of them also support **AWS Organizations** with a **delegated administrator** account, which is how you get one place to look at findings for every account.

| Service | Question it answers | What it reads | Do you have to turn the source on first? | Scope |
|---|---|---|---|---|
| GuardDuty | Is someone attacking or abusing this account right now? | CloudTrail management events, VPC flow data, DNS query data; optional plans add S3 data events, EKS audit logs, runtime events, RDS logins, Lambda network data, AI service events, EBS and S3 malware scans | No for the foundational sources (independent streams); plans are switched on per feature | Regional detector per account |
| Security Hub CSPM | Is this account configured to a standard, and where are all my findings? | Service-linked AWS Config rules, plus findings imported from GuardDuty, Inspector, Macie, Access Analyzer, partners | Yes: needs AWS Config recording (or the service-linked recorder, see below) | Regional, with cross-Region aggregation |
| Security Hub (2025) | Which combinations of weaknesses and threats actually expose something? | Signals from Security Hub CSPM, Inspector, GuardDuty, Macie | Needs Security Hub CSPM and Inspector for the correlation features | Organisation-wide, multi-Region |
| AWS Config | What did this resource look like, when, and does it comply with a rule? | Resource configuration via service APIs | Yes: a configuration recorder per Region | Regional recorder, aggregator for org view |
| Inspector | Which workloads have known vulnerabilities or unintended network reachability? | SSM inventory or EBS snapshots (EC2), ECR images, Lambda functions and layers | Enable scan types; agent-based EC2 scanning needs SSM-managed instances | Regional |
| Macie | Where is the sensitive data in S3, and is that bucket exposed? | S3 bucket metadata and sampled objects | Enable Macie and automated discovery | Regional |
| Detective | What happened around this finding? | CloudTrail, VPC flow data, GuardDuty findings, optional EKS audit logs and security findings | No separate logging, but builds from GuardDuty and its own ingest | Regional behaviour graph |
| IAM Access Analyzer | Who outside (or inside) my zone of trust can reach this resource? What access is unused? | Resource-based policies, IAM last-accessed data, identity and resource policies | Create analyzers | External and internal analyzers are Regional; unused access is not |
| VPC Flow Logs | Which IP flows happened on this interface, and were they accepted? | ENI-level flow metadata | Yes: create a flow log per VPC, subnet or ENI | Regional |
| Resolver query logs | Which names did workloads in this VPC resolve? | Queries handled by the Route 53 VPC Resolver | Yes: query logging configuration plus VPC associations | Regional |
| Security Lake | Where do I keep normalised security logs for the long term? | CloudTrail, VPC flow, Resolver, EKS audit, WAF, Security Hub CSPM findings | Collects through its own streams except CloudTrail management events | Organisation, chosen Regions |

The ATT&CK view of this whole note is the defender's mirror of "Impair Defenses". Note that MITRE re-numbered that area in **ATT&CK v20**: the old T1562 and T1562.008 pages now redirect to **T1685 Disable or Modify Tools** and **T1685.002 Disable or Modify Cloud Log**. Older reports and tooling still use the T1562 IDs; we use the current ones and mention the old ones where it helps.

### Amazon GuardDuty

#### Foundational data sources

When you enable GuardDuty in a Region it immediately starts analysing three **foundational data sources**: CloudTrail management events, VPC flow data from EC2 instances, and Route 53 Resolver DNS query data. The detail that matters for reviewers is that GuardDuty consumes all three through **independent, duplicated streams**:

- It does **not** need your CloudTrail trail. Deleting or stopping a trail does not blind GuardDuty's management-event analysis (and stopping a trail is itself a finding, `Stealth:IAMUser/CloudTrailLoggingDisabled`).
- It does **not** need your VPC Flow Logs. A VPC without flow logs is still analysed by GuardDuty; but GuardDuty discards the logs after extracting what it needs, so you get findings, not evidence. You still need your own flow logs for investigation (see [VPC Flow Logs](#vpc-flow-logs)).
- It sees DNS **only if workloads use the AWS-provided resolver**. Instances pointed at their own DNS servers, or at a public resolver, are invisible to GuardDuty's DNS analysis. That is a coverage gap, and the client usually does not know it exists.

GuardDuty also replicates **global service events** (IAM, STS, and similar) into every Region where it is enabled, so that it can build per-Region profiles. AWS's own recommendation is to enable GuardDuty in **all Regions**, including ones you do not use, because an attacker with stolen credentials will happily launch resources in a Region nobody watches (ATT&CK [T1535 Unused/Unsupported Cloud Regions](https://attack.mitre.org/techniques/T1535/)).

#### Protection plans

On top of the foundational sources, GuardDuty sells **use-case focused protection plans** (called *features* in the API). At the time of writing:

| Protection plan | API feature name | What it adds |
|---|---|---|
| S3 Protection | `S3_DATA_EVENTS` | CloudTrail S3 data events (object-level reads, writes, deletes) for exfiltration and destruction detection |
| EKS Protection | `EKS_AUDIT_LOGS` | Kubernetes audit logs from EKS control planes |
| Runtime Monitoring | `RUNTIME_MONITORING` (with agent management for EKS, ECS Fargate and EC2) | OS-level process, file and network events from a security agent |
| EKS Runtime Monitoring (legacy) | `EKS_RUNTIME_MONITORING` | The older EKS-only runtime feature; you cannot configure it together with `RUNTIME_MONITORING` |
| Malware Protection for EC2 | `EBS_MALWARE_PROTECTION` | Agentless scans of EBS volumes when GuardDuty sees suspicious behaviour, plus on-demand scans |
| Malware Protection for S3 | (separate malware protection plan per bucket) | Scans newly uploaded objects; can be used without enabling GuardDuty itself |
| Malware Protection for AWS Backup | (separate) | Scans EBS snapshots, AMIs and Backup recovery points |
| RDS Protection | `RDS_LOGIN_EVENTS` | Login activity for supported Aurora and RDS engines |
| Lambda Protection | `LAMBDA_NETWORK_LOGS` | Network activity of Lambda functions |
| AI Protection | `AI_PROTECTION` | CloudTrail data events from Bedrock, Bedrock AgentCore and SageMaker AI |

According to AWS, a **new** GuardDuty account gets every plan except Runtime Monitoring enabled automatically for the 30-day trial; an **existing** customer does not get a plan that launches later. In practice, long-lived GuardDuty estates are the ones with gaps: GuardDuty switched on in 2018, S3 Protection never enabled, Runtime Monitoring never rolled out. Each plan has a Security Hub CSPM control (GuardDuty.5 to GuardDuty.13) and a Prowler check.

#### Extended Threat Detection

**Extended Threat Detection** (launched at re:Invent 2024, since expanded) correlates individual findings and weaker signals (API calls that are not findings on their own) within one account over a rolling **24-hour** window and emits an **attack sequence** finding. All attack sequence types are **Critical**:

- `AttackSequence:IAM/CompromisedCredentials`: a series of suspicious API calls with the same credentials.
- `AttackSequence:S3/CompromisedData`: a sequence pointing at exfiltration or destruction of S3 data (needs S3 Protection for the data-plane part).
- `AttackSequence:EKS/CompromisedCluster`: needs EKS Protection or Runtime Monitoring.
- `AttackSequence:ECS/CompromisedCluster`: needs Runtime Monitoring for ECS.
- `AttackSequence:EC2/CompromisedInstanceGroup`: groups of instances sharing an Auto Scaling group, instance profile, launch template, AMI or VPC; better with Runtime Monitoring.

It is on by default and costs nothing extra, but it only correlates what GuardDuty can see. Two consequences for a review. First, protection plans matter more than they look: without S3 Protection there is no S3 data-plane signal to correlate. Second, and more subtle: **findings archived by suppression rules are not used as signals for attack sequences**. AWS says so explicitly, and gives the example of a rule that suppresses all EKS findings breaking EKS attack sequence detection. A broad suppression rule therefore does not just hide one finding type; it also removes the evidence the correlator needs.

#### Findings, suppression and lists

GuardDuty findings have a type in the form `ThreatPurpose:ResourceType/ThreatFamily.Variant!Artifact`, a severity from 1 to 10 (Low, Medium, High, Critical bands), and are kept for **90 days**. They are sent to Amazon EventBridge in near real time when new; repeat occurrences are aggregated and re-sent at the *finding publishing frequency* (15 minutes, 1 hour, or the default 6 hours), which only the administrator account can change. You can also export them to S3 through a *publishing destination*.

Three tuning mechanisms change what you see:

- **Suppression rules** are saved filters with the action `ARCHIVE`. Matching findings are still generated but automatically archived, and they are **not** sent to EventBridge, Security Hub CSPM, S3 export or Detective. If Malware Protection for EC2 is on, a suppressed finding does not trigger a scan either. In a multi-account setup only the GuardDuty administrator can create them. AWS's guidance is to create them *reactively*, for findings that are repeatedly false positives, and to keep them specific (finding type plus a narrow second criterion such as a scanner's instance tag or the on-premises egress IP).
- **Trusted lists** (the legacy *trusted IP list*, and the newer *trusted entity list* that can also hold domains) stop GuardDuty generating findings for activity involving those entries. Only **one** trusted list of each kind is allowed per account per Region, IPv4 only, and entries apply only to public addresses and domains. An IP list affects CloudTrail and VPC-flow findings; an entity list also affects DNS findings. Trusted entries win over threat entries.
- **Threat lists** (IP or entity, up to six per account per Region) add findings such as `UnauthorizedAccess:IAMUser/MaliciousIPCaller.Custom` for activity involving known-bad indicators. Threat entity lists can also carry SHA-256 file hashes.

In a multi-account environment, only the GuardDuty **administrator** manages lists and suppression rules, and they apply to all members. That centralisation is good for governance and bad for blast radius: one overly broad trusted list in the delegated administrator silences detections across the whole organisation.

#### Organisation-wide enablement

With AWS Organizations, the management account designates a **delegated GuardDuty administrator** (normally a dedicated security tooling account) per Region with `enable-organization-admin-account`. The administrator then sets the organisation configuration: `AutoEnableOrganizationMembers` of `ALL` (every member, existing and new), `NEW` (only accounts that join later) or `NONE`, and a per-feature `AutoEnable` of the same values. `NEW` is a classic gap: it looks like "auto-enable is on", but accounts that existed when it was set may still have GuardDuty off. AWS Organizations also has a newer **GuardDuty policy** type (`GUARDDUTY_POLICY`) that enables GuardDuty and named protection plans per OU and Region from the organisation, and takes precedence over the per-Region auto-enable settings when used; check whether the client uses it before concluding anything from the Regional settings alone.

#### Finding types that matter for this series

| Finding type | Severity (default) | Why you care | Related note |
|---|---|---|---|
| `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS` | High | EC2 role credentials used from outside AWS: the IMDS/SSRF story | [EC2, IMDS, EBS and SSM](/cloud/aws-ec2-imds-ebs-ssm-security/) |
| `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.InsideAWS` | High (Medium if affiliated account) | Same, used from another AWS account | [EC2, IMDS, EBS and SSM](/cloud/aws-ec2-imds-ebs-ssm-security/) |
| `UnauthorizedAccess:IAMUser/ResourceCredentialExfiltration.OutsideAWS` | High | Lambda or ECS task credentials used outside AWS | [Lambda](/cloud/aws-lambda-serverless-security/), [containers](/cloud/aws-containers-ecs-eks-ecr-security/) |
| `CredentialAccess:IAMUser/CompromisedCredentials` | High | Amazon threat intelligence believes a key is compromised and it is being used | [Unauthenticated recon](/cloud/aws-unauthenticated-recon/) |
| `PrivilegeEscalation:IAMUser/AnomalousBehavior`, `Persistence:IAMUser/AnomalousBehavior` | Medium | ML-flagged IAM changes typical of escalation and persistence | [Privilege escalation](/cloud/aws-iam-privilege-escalation/) |
| `Discovery:IAMUser/AnomalousBehavior` | Low | Unusual enumeration: what your own assessment looks like | This note |
| `DefenseEvasion:IAMUser/AnomalousBehavior` | Medium | Anomalous `DeleteFlowLogs`, `StopLogging`, `DisableAlarmActions` and similar | [CloudTrail](/cloud/aws-cloudtrail-logging/) |
| `Stealth:IAMUser/CloudTrailLoggingDisabled` | Low | A trail was stopped, deleted or its bucket removed (Low by default, which is why routing by severity alone fails) | [CloudTrail](/cloud/aws-cloudtrail-logging/) |
| `Policy:IAMUser/RootCredentialUsage`, `Policy:IAMUser/ShortTermRootCredentialUsage` | Low | Root user activity, or a centralised root session | [Organizations](/cloud/aws-organizations-multi-account-security/) |
| `Policy:S3/BucketBlockPublicAccessDisabled`, `Policy:S3/BucketAnonymousAccessGranted`, `Policy:S3/BucketPublicAccessGranted` | Low to High | A bucket was opened up | [S3](/cloud/aws-s3-security/) |
| `PenTest:IAMUser/KaliLinux` (also `ParrotLinux`, `PentooLinux`) | Medium | API calls from a penetration-testing distribution: expect it during your own test | This note |
| `AttackSequence:*` | Critical | Correlated multi-stage activity | This note |

### Security Hub CSPM and the new Security Hub

#### The naming change

Be precise in reports, because clients are confused by this. In 2025 AWS renamed the original service, the one with security standards, controls such as `S3.1` and findings in the **AWS Security Finding Format (ASFF)**, to **AWS Security Hub CSPM** (cloud security posture management). The name **AWS Security Hub** now refers to a new, broader service, previewed at re:Inforce in June 2025 and **generally available on 2 December 2025**, which correlates signals from GuardDuty, Inspector, Macie and Security Hub CSPM into **exposure findings** and attack paths, uses the **OCSF** schema rather than ASFF, and has its own pricing model. Enabling the new Security Hub enables Security Hub CSPM; its correlation features need Security Hub CSPM and Inspector, and GuardDuty is enabled separately. The control IDs this series cites (`GuardDuty.1`, `Config.1`, `IAM.28` and so on) are **Security Hub CSPM controls**. The CLI still uses the `securityhub` namespace for both; the new service's operations carry a `V2` suffix (for example `describe-security-hub-v2`).

#### Standards, controls and their dependency on Config

Security Hub CSPM evaluates controls against standards: **AWS Foundational Security Best Practices (FSBP)**, the **CIS AWS Foundations Benchmark** (v1.2.0, v1.4.0, v3.0.0 and v5.0.0 are supported at the time of writing), **NIST SP 800-53 Rev. 5**, NIST SP 800-171 Rev. 2, **PCI DSS** (v3.2.1 and v4.0.1), the CRI Profile, and a resource tagging standard. Most controls run as **service-linked AWS Config rules** (named `securityhub-<rule>-<id>`). That has two consequences:

- When only Security Hub CSPM is enabled, **you** must run AWS Config recording for the resource types the controls check. Without it, controls report `WARNING` rather than `FAILED`, and Config.1 fails.
- When both Security Hub CSPM and the new Security Hub are enabled, Security Hub CSPM creates a **service-linked configuration recorder** named `AWSConfigurationRecorderForSecurityHubCSPM` and does not use the customer-managed recorder. AWS documents that **Config.1 then always passes**. A green Config.1 in that mode does **not** mean the client has a customer-managed recorder with history they can use in an investigation, and a service-linked recorder with an internal recording scope does not deliver configuration items to a delivery channel. Check the recorders directly (GT-AWS-DET-6).

Controls can be disabled per standard (with a reason) or centrally through **central configuration** policies applied from the delegated administrator to OUs and accounts. A disabled control produces no findings; the reason field is the only trace.

#### Aggregation and automation rules

**Cross-Region aggregation** links Regions to a *home Region* so that findings, insights and control status from linked Regions appear in one place. It is configured in the administrator account with a finding aggregator whose `RegionLinkingMode` is `ALL_REGIONS`, `ALL_REGIONS_EXCEPT_SPECIFIED` or `SPECIFIED_REGIONS`. `SPECIFIED_REGIONS` is the gap to look for: new Regions are not linked automatically.

**Automation rules** (administrator account only, up to 100 per administrator, Regional) change findings as they are ingested: raise or lower `Severity`, add a `Note`, set `Workflow.Status` to `SUPPRESSED`, and so on, for findings that match criteria such as `ProductName`, `AwsAccountId`, `ResourceId` or `SeverityLabel`. They are useful for routing and context, and dangerous for the same reason as GuardDuty suppression rules: a rule such as "suppress every GuardDuty finding from account X" or "set severity to INFORMATIONAL for the sandbox OU" removes signal before any human sees it. AWS recommends disabling a control rather than suppressing its findings with a rule, which at least leaves an auditable reason.

### AWS Config

AWS Config records **configuration items** (CIs) for supported resources and evaluates them against **Config rules**. The pieces a reviewer cares about:

- **Configuration recorder** (one customer-managed recorder per account per Region, plus any **service-linked recorders** created by other services). Its *recording strategy* is one of `ALL_SUPPORTED_RESOURCE_TYPES`, `INCLUSION_BY_RESOURCE_TYPES` or `EXCLUSION_BY_RESOURCE_TYPES`; its *recording frequency* is `CONTINUOUS` or `DAILY`. Daily recording delays change-triggered rule results by up to a day.
- **Global resources.** The IAM resource types onboarded before February 2022 (`AWS::IAM::User`, `AWS::IAM::Group`, `AWS::IAM::Role`, `AWS::IAM::Policy`) can be recorded in any Region where Config existed before February 2022, but not in Regions added after it. AWS recommends recording them **once**, in one Region (your Security Hub CSPM home Region if you aggregate), to avoid duplicates. Newer global types (Route 53 hosted zones, CloudFront distributions, WAFv2 web ACLs and others) are recorded only in their **home Region**, mostly `us-east-1`. So "global resources off in this Region" is often correct, and "global resources off everywhere" is a finding: nobody is recording IAM changes.
- **Delivery channel**: the S3 bucket (and optional SNS topic) that receives configuration history and snapshots. Without it, history exists only inside Config for its retention period.
- **Recorder status**: a recorder can exist and be stopped (`StopConfigurationRecorder`), or be running and failing (`lastStatus: FAILURE`, often a role or bucket permission problem).
- **Rules and conformance packs**: AWS managed rules (for example `vpc-flow-logs-enabled`, `guardduty-enabled-centralized`, `iam-root-access-key-check`) and custom rules, deployed individually, as organisation rules, or as **conformance packs** (a YAML bundle of rules and remediations, deployable organisation-wide).
- **Aggregators** collect CIs and compliance from many accounts and Regions into one account. An **organisation aggregator** with `AllAwsRegions: true` in the delegated administrator account is what gives you one query surface (`select-aggregate-resource-config` with SQL-like queries) for the whole estate.

### Amazon Inspector

Amazon Inspector (the current service, API namespace `inspector2`; the "Classic" assessment-template service is retired) continuously scans:

- **EC2 instances** for OS and language-package CVEs and for network reachability. Package scanning is **agent-based** through the SSM Agent (the instance must be an SSM managed instance in the same account) or **agentless** through EBS snapshots that Inspector creates, reads with the EBS direct APIs and deletes. In **hybrid** mode, unmanaged instances on supported OSes and file systems are scanned agentlessly about every 24 hours. The AWS documentation is inconsistent about which mode is the default for a new account, so read the account's setting rather than assume.
- **ECR images** with enhanced scanning (on push and continuous re-scan for a configurable duration).
- **Lambda functions and layers** (standard scanning for dependencies, plus optional **Lambda code scanning** for code issues).
- Optionally, **machine images (AMIs)** and **code repositories** (Code Security).

Coverage is visible per resource with `list-coverage`, which returns a `scanStatus` with a status code and a reason (for example an unmanaged instance, an unsupported OS, or a resource excluded by tag). Instances tagged with the key `InspectorEc2Exclusion` (case-insensitive) are excluded and produce no findings, which is a legitimate cost control and an easy way to hide a host from vulnerability management. Security Hub CSPM controls Inspector.1 to Inspector.4 check that EC2, ECR, Lambda standard and Lambda code scanning are enabled.

### Amazon Macie

Macie inventories S3 general purpose buckets (public access settings, encryption, sharing, replication) and finds sensitive data in objects. **Automated sensitive data discovery** samples objects from every bucket daily, scores bucket sensitivity and produces *sensitive data findings*; **classification jobs** do targeted, full scans. Macie also emits *policy findings* when a bucket becomes public, unencrypted or shared outside the account. For a reviewer the interesting parts are scope and blind spots:

- Automated discovery can be disabled per member account by the Macie administrator, and buckets can be **excluded** (log buckets are reasonable; a "do not scan" list that includes the customer-data bucket is not).
- Macie can only analyse what it can read. Buckets whose policies deny the Macie service-linked role, and objects encrypted with KMS keys Macie is not allowed to use, end up as unclassifiable. The bucket inventory reports these.
- Macie.1 and Macie.2 in Security Hub CSPM check that Macie and automated discovery are enabled. In the CIS mappings Security Hub publishes, Macie.1 appears only as a *manual* check.

The detail of S3 exposure is in the [S3 note](/cloud/aws-s3-security/); here we only care that Macie is on, scoped sensibly, and that its findings go somewhere.

### Amazon Detective

Detective builds a **behaviour graph** per Region from CloudTrail management events, VPC flow data and GuardDuty findings, with optional packages for EKS audit logs and AWS security findings, and keeps the data for up to a year. It is an **investigation** tool: given a finding, a role or an IP, it shows what else that entity did and how it differs from its baseline. It does not detect anything on its own. In a review its presence is a maturity signal (and a time saver for incident response), and its absence is rarely more than Informational. Check that the behaviour graph covers the member accounts you think it covers.

### IAM Access Analyzer

IAM Access Analyzer provides several distinct capabilities, and clients often have only the first:

- **External access analyzers** (`ACCOUNT` or `ORGANIZATION` type) use automated reasoning over resource-based policies to report resources shared outside the **zone of trust** (the account or the organisation): S3 buckets and directory buckets, IAM role trust policies, KMS keys, Lambda functions and layers, SQS queues, Secrets Manager secrets, SNS topics, EBS and RDS snapshots, ECR repositories, EFS file systems, DynamoDB tables and streams. They are **Regional**: an analyzer only covers resources in its own Region, so you need one per Region in use. Policy changes are analysed within about 30 minutes, with a periodic rescan within 24 hours.
- **Internal access analyzers** (`ACCOUNT_INTERNAL_ACCESS` or `ORGANIZATION_INTERNAL_ACCESS`, announced June 2025) report which principals **inside** the zone of trust can reach selected critical resources (S3, RDS snapshots, DynamoDB at the time of writing), taking SCPs and RCPs into account. They are paid per monitored resource and their findings are returned only by the `ListFindingsV2` API.
- **Unused access analyzers** (`ACCOUNT_UNUSED_ACCESS` or `ORGANIZATION_UNUSED_ACCESS`) report unused roles, unused access keys and passwords, and unused services and actions on active principals, over a tracking period you choose. They are paid per IAM principal analysed and are not Regional.
- **Policy validation** (`validate-policy`) and **custom policy checks**: `check-no-new-access` (does this policy grant more than the previous version?), `check-access-not-granted` (does it allow any of these sensitive actions or resources?) and `check-no-public-access` (would this resource policy make the resource public?). These are built for CI pipelines; see the [CI/CD and IaC note](/cloud/aws-cicd-iac-security/).
- **Archive rules** auto-archive findings that match criteria, the Access Analyzer equivalent of a suppression rule, with the same failure mode.

Security Hub CSPM control **IAM.28** checks that an external access analyzer exists; it maps to CIS v3.0.0 1.20 and CIS v5.0.0 1.19.

### VPC Flow Logs

A flow log captures metadata (not payload) for IP flows on network interfaces, and can be attached to a **VPC**, a **subnet**, a **network interface**, or a **transit gateway** (and its attachments). Records are aggregated over a maximum interval of 10 minutes (default) or 1 minute; Nitro-based instances always aggregate at 1 minute or less. Delivery is best effort: typically about 5 minutes to CloudWatch Logs and 10 minutes to S3. Destinations are **CloudWatch Logs**, **Amazon S3** (plain text or Parquet) and **Amazon Data Firehose**. The `TrafficType` is `ACCEPT`, `REJECT` or `ALL`; a `REJECT`-only flow log is useful for troubleshooting and nearly useless for investigating exfiltration.

The **default format** contains only the **version 2** fields:

```text
${version} ${account-id} ${interface-id} ${srcaddr} ${dstaddr} ${srcport} ${dstport} ${protocol} ${packets} ${bytes} ${start} ${end} ${action} ${log-status}
```

A **custom format** lets you add later fields, and the record's version becomes the highest version among the fields you chose. The fields that make investigations possible:

| Version | Fields | Why they help |
|---|---|---|
| 3 | `vpc-id`, `subnet-id`, `instance-id`, `tcp-flags`, `type`, `pkt-srcaddr`, `pkt-dstaddr` | Attribute the flow to an instance; see the real source and destination behind a NAT gateway or for EKS pods; distinguish connection attempts (SYN) from established flows |
| 4 | `region`, `az-id`, `sublocation-type`, `sublocation-id` | Location context |
| 5 | `pkt-src-aws-service`, `pkt-dst-aws-service`, `flow-direction`, `traffic-path` | Tell flows to AWS services (for example `S3`) from flows to the internet; ingress versus egress; which path egress took (internet gateway, gateway endpoint, peering, and so on) |
| 7 | `ecs-*` fields | Attribute flows to ECS clusters, services and tasks |
| 8 | `reject-reason` | Shows rejections caused by VPC Block Public Access or encryption controls |
| 10 and 11 | `encryption-status`, tag fields, `interface-type`, `next-hop-*` | Newer context fields; check availability in the client's Regions |

When you review a flow log, therefore, look at more than its existence: scope (all VPCs?), traffic type (`ALL`), format (at least the v3 and v5 fields for egress analysis), destination and retention (a CloudWatch log group with a 3-day retention is not an investigation source), and `DeliverLogsStatus`.

### Route 53 Resolver query logs

Resolver query logging records DNS queries that VPC resources send to the Route 53 VPC Resolver (the `.2` address), queries arriving through inbound endpoints, queries forwarded through outbound endpoints, and DNS Firewall actions. Each record carries the VPC, the source IP and instance ID, the query name and type, the response code and the answers. Logs go to CloudWatch Logs, S3 or Firehose, and a query logging configuration is **associated with VPCs** one by one (or shared through AWS RAM). Two caveats: only **unique** queries are logged, so answers served from the resolver cache within the TTL do not appear; and workloads that use their own DNS servers do not go through the VPC Resolver at all. Do not confuse this with **public hosted zone query logging** (Security Hub CSPM control Route53.2), which logs queries that the internet sends to the client's authoritative zones; that is useful, but it says nothing about what the client's workloads resolved.

### Amazon Security Lake

Security Lake collects CloudTrail management and data events, EKS audit logs, Resolver query logs, Security Hub CSPM findings, VPC Flow Logs and WAF logs into S3 in your account, normalised to **OCSF** and stored as Parquet, with subscribers (SIEMs, analytics) reading from it. Except for CloudTrail management events, it pulls data through its own duplicated streams, so you do not have to enable flow logs or Resolver logging separately for Security Lake. Its relevance here: it is often the long-term evidence store, so its sources, Regions, accounts and retention are part of "can we investigate". Its buckets are also a high-value target: Security Lake (`securitylake`) is one of the services supported by RCPs, which is one way to protect it from outside access.

### Delegated administrators for security services

Every service in this note supports a **delegated administrator**: a member account, registered by the management account, that manages the service for the organisation (enables members, sets organisation configuration, owns suppression rules and lists, sees all findings). AWS's guidance, and ours, is that this should be a dedicated **security tooling** account, **not** the management account. The reasons are covered in the [Organizations note](/cloud/aws-organizations-multi-account-security/): SCPs do not apply to the management account, so tooling administered from there cannot be protected by guardrails, and every extra role in the management account increases the blast radius of the account that owns the organisation. Conversely, whoever administers the delegated administrator account can disable members, add suppression rules and trusted lists, and archive findings for everyone. That account deserves the same protection as a production payments account.

### Reading these services as evidence

During an authorised assessment these services are among the most useful read-only sources you have, and reading them is cheap:

- **Access Analyzer external findings** are a ready-made inventory of cross-account and public trust (role trust policies, KMS key policies, shared snapshots). Start your [cross-account trust review](/cloud/aws-sts-cross-account-trust-federation/) here.
- **Macie bucket inventory** (`describe-buckets`) lists public, shared, unencrypted and replicated buckets, with sensitivity scores, across the organisation from one account.
- **Inspector findings** filtered to internet-reachable instances with exploitable CVEs give you priorities for the [EC2 work](/cloud/aws-ec2-imds-ebs-ssm-security/).
- **Config history** (`get-resource-config-history`) shows when a security group was opened, or a bucket policy changed, and by which change; the aggregator lets you query all accounts at once.
- **GuardDuty findings** tell you what has already happened (a pre-existing `InstanceCredentialExfiltration` finding is an incident, not a test result) and, during your test, whether your own activity was seen. Agree with the client up front that you will note which of your actions produced findings; that is a cheap, honest detection measurement.
- **Security Hub CSPM findings** give you the control baseline, so you do not spend days re-proving `S3.1`.

## What goes wrong

**Enabled in some Regions only.** GuardDuty, Security Hub CSPM, Config and Access Analyzer turned on in the two Regions the client uses. The attacker who steals a key spins up miners in a Region nobody watches. Why it matters: T1535, and the [Datadog ECS case](#real-world-cases) where miners were launched in at least 17 Regions.

**Enabled in some accounts only.** Auto-enable set to `NEW` after half the accounts already existed; accounts invited from outside never joined the GuardDuty organisation; sandbox OU excluded "for cost". Why: the attacker picks the least-watched account and moves laterally from there.

**Protection plans missing where the resources are.** S3 Protection off on an estate whose crown jewels are in S3; EKS Protection and Runtime Monitoring off on a large EKS fleet; RDS Protection off with internet-facing databases. Why: GuardDuty sees the control plane only, and Extended Threat Detection loses the data-plane signals it needs.

**Broad suppression and trusted lists.** A suppression rule that archives every `Recon:*` or every finding below High; a trusted IP list that contains the corporate VPN egress, a whole cloud provider range, or a `/8`. Why: findings for that activity are never generated or never leave GuardDuty, never reach EventBridge, Security Hub or the SIEM, and are not available to Extended Threat Detection. An attacker on the VPN (or on the same cloud provider) is invisible.

**Findings go nowhere.** GuardDuty enabled, EventBridge rule absent or pointing at an SNS topic with no confirmed subscriptions, or at a mailbox nobody reads; Security Hub CSPM findings never exported to the SIEM. High-severity findings months old and still `ACTIVE`. Why: detection without response is a dashboard, not a control.

**Severity-only routing.** Only High and Critical are paged. `Stealth:IAMUser/CloudTrailLoggingDisabled` (Low) and `Policy:IAMUser/RootCredentialUsage` (Low) are therefore never seen. Why: some of the most important early signals are rated Low by design.

**Automation rules that suppress.** Security Hub CSPM automation rules setting `Workflow.Status` to `SUPPRESSED` for whole products, accounts or severities. Why: same as GuardDuty suppression, one layer later.

**Config recording that only looks complete.** Recorder stopped; recording only a handful of types; IAM global types recorded nowhere; daily recording; no delivery channel; Config.1 green only because of a service-linked recorder. Why: no change history for investigations, and Security Hub CSPM controls silently degrade to `WARNING`.

**Inspector and Macie blind spots.** Instances not SSM-managed and agentless scanning off; `InspectorEc2Exclusion` tags on production hosts; ECR re-scan duration too short; Macie excluded from the buckets that matter or unable to read them because of bucket policies and KMS key policies.

**Access Analyzer in one Region, or account-scoped only.** External access in the other Regions goes unreported; an account-scoped analyzer treats other accounts in the organisation as external, which is noisy, so people archive everything, which is worse.

**Network and DNS evidence missing.** No flow logs on some VPCs; `REJECT`-only; default v2 format; 1-day retention; Resolver query logging not associated with production VPCs; workloads using custom DNS that GuardDuty cannot see.

**Delegated administrator in the management account.** Security tooling administered from the account SCPs cannot protect.

**Tooling not protected.** No SCP denies `guardduty:DeleteDetector`, `guardduty:CreateFilter`, `guardduty:CreateIPSet`, `securityhub:DisableSecurityHub`, `config:StopConfigurationRecorder`, `ec2:DeleteFlowLogs` and the like to everyone except a security role. Why: any member-account administrator, or anyone who escalates to one, can blind the account (ATT&CK T1685, T1685.002).

**Detection never tested.** Nobody has ever checked end to end that a finding reaches a human within an agreed time. Sample findings were generated once, at setup.

## Testing

### Before you start

**Authorisation.** Everything here assumes an authorised engagement against the client's own accounts, with written scope that names the accounts and Regions, and that you respect the [AWS penetration testing policy](https://aws.amazon.com/security/penetration-testing/). Tests GT-AWS-DET-1 to GT-AWS-DET-10 are read-only. GT-AWS-DET-4 has one optional state-changing step and GT-AWS-DET-11 is entirely state-changing; both are marked **lab or explicitly approved only**. Command outputs in this note are **illustrative**: we ran nothing against AWS to produce them.

**Access.** You need read access in two places:

1. The **delegated administrator** (security tooling) account for each service, because that is where organisation configuration, suppression rules, automation rules and aggregated findings live. Ask for a read-only role there.
2. A sample of **member accounts**, plus the **management account** (read-only) for `organizations` calls. If you cannot get management-account access, ask the client to run the `organizations list-delegated-administrators` and `list-aws-service-access-for-organization` commands for you.

The AWS managed **`SecurityAudit`** policy covers almost everything below (`guardduty:Get*`/`List*`, `securityhub:Get*`/`List*`/`Describe*`, `config:Describe*`/`Get*`/`List*`/`Select*`, `inspector2:List*` and related reads, `access-analyzer` reads, `organizations:Describe*`/`List*`, `route53resolver:Get*`/`List*`). It is thin on Macie (`macie2:ListFindings` only at the time of writing): add `macie2:GetMacieSession`, `macie2:GetAutomatedDiscoveryConfiguration`, `macie2:DescribeBuckets` and `macie2:GetClassificationScope` to the audit role, or use `ViewOnlyAccess` plus those actions.

**Profiles and the Region loop.** Every per-Region test uses the same loop. `describe-regions` returns only Regions enabled for the account; use `--all-regions` to see opt-in Regions that are disabled (and therefore unusable by an attacker too, unless they can call `account:EnableRegion`).

```bash
export AWS_PROFILE=client-sec-audit          # read-only role in the security tooling account
aws sts get-caller-identity
REGIONS=$(aws ec2 describe-regions --query 'Regions[].RegionName' --output text)
echo "$REGIONS" | tr '\t' '\n' | wc -l
```

**Tools.** [Prowler](https://github.com/prowler-cloud/prowler) covers most of the enablement checks in one run (`prowler aws --services guardduty securityhub config inspector2 macie accessanalyzer vpc organizations`); [ScoutSuite](https://github.com/nccgroup/ScoutSuite) and Steampipe's AWS plugin are good for cross-checking; `jq` for everything else. For GT-AWS-DET-11, the [GuardDuty tester](https://github.com/awslabs/amazon-guardduty-tester) and [Stratus Red Team](https://github.com/DataDog/stratus-red-team), **in a lab or approved account only**.

**Tell the SOC.** Your own enumeration will produce findings such as `Discovery:IAMUser/AnomalousBehavior` and, if you test from Kali, `PenTest:IAMUser/KaliLinux`. Agree in advance that the SOC will treat these normally and report them to you. Do **not** ask the client to add your IP to a trusted list or suppression rule: that is the anti-pattern this note warns about, and it removes the cheapest detection measurement you have.

### GT-AWS-DET-1: GuardDuty enabled in every account and Region

*Guler Tech methodology.*

#### What it checks

That a GuardDuty detector exists and is `ENABLED` in every enabled Region of every account, that all accounts are members of the organisation's GuardDuty administrator, and that the administrator is a dedicated account.

#### Prerequisites

Read-only access to the GuardDuty delegated administrator account; `organizations:ListAccounts` (from the management account or via the client).

#### Steps

1. Per Region, in the administrator account: detector status and organisation auto-enable.

   ```bash
   for r in $REGIONS; do
     d=$(aws guardduty list-detectors --region "$r" --query 'DetectorIds[0]' --output text)
     if [ "$d" = "None" ]; then echo "$r NO_DETECTOR"; continue; fi
     st=$(aws guardduty get-detector --region "$r" --detector-id "$d" --query 'Status' --output text)
     ae=$(aws guardduty describe-organization-configuration --region "$r" --detector-id "$d" \
          --query 'AutoEnableOrganizationMembers' --output text 2>/dev/null)
     echo "$r $d status=$st autoEnable=$ae"
   done
   ```

2. Per Region, compare GuardDuty members with the organisation's accounts:

   ```bash
   aws organizations list-accounts --query 'Accounts[?Status==`ACTIVE`].Id' --output text \
     | tr '\t' '\n' | sort > org-accounts.txt
   for r in $REGIONS; do
     d=$(aws guardduty list-detectors --region "$r" --query 'DetectorIds[0]' --output text)
     [ "$d" = "None" ] && continue
     aws guardduty list-members --region "$r" --detector-id "$d" --only-associated false \
       --query 'Members[].[AccountId,RelationshipStatus]' --output text \
       | awk -v r="$r" '{print r, $1, $2}'
   done > gd-members.txt
   # accounts with no ENABLED relationship in a given Region
   for r in $REGIONS; do
     grep "^$r " gd-members.txt | awk '$3=="Enabled"{print $2}' | sort > enabled.tmp
     comm -23 org-accounts.txt enabled.tmp | sed "s/^/$r MISSING /"
   done
   ```

   The administrator account itself is not listed as a member; account for it separately.

3. Who is the administrator? Run from the management account (or ask the client):

   ```bash
   aws organizations describe-organization --query 'Organization.MasterAccountId' --output text
   aws guardduty list-organization-admin-accounts --region eu-west-2
   ```

4. Check whether a `GUARDDUTY_POLICY` organisation policy manages enablement (it overrides Regional auto-enable):

   ```bash
   aws organizations list-policies --filter GUARDDUTY_POLICY --query 'Policies[].[Id,Name]' --output text
   ```

5. Spot-check one member account directly (`list-detectors`, `get-detector`) to confirm what the administrator reports.

#### Observation

Illustrative:

```text
eu-west-2 12abc34d567e8fa901bc2d34eEXAMPLE status=ENABLED autoEnable=ALL
us-east-1 98fed76c543b2a109fe8d76c5EXAMPLE status=ENABLED autoEnable=NEW
ap-southeast-3 NO_DETECTOR
us-east-1 MISSING 444455556666
```

#### Evaluation

**Pass:** a detector with `Status: ENABLED` in every enabled Region; every active organisation account is an `Enabled` member in every Region; `AutoEnableOrganizationMembers` is `ALL` (or a `GUARDDUTY_POLICY` covers the root with a `default` block); the administrator is not the management account. **Fail:** any Region without a detector or with a `DISABLED` detector; any account missing from any Region; auto-enable `NEW` or `NONE` with existing accounts not enabled; administrator equals management account (also report under GT-AWS-DET-10). Note Regions the client has deliberately disabled at the account level: those are not a GuardDuty gap.

#### Automated coverage

Security Hub CSPM **GuardDuty.1**. Prowler `guardduty_is_enabled`, `guardduty_centrally_managed`, `guardduty_delegated_admin_enabled_all_regions`.

#### Detection

Tampering with GuardDuty itself: CloudTrail `eventName` `DeleteDetector`, `UpdateDetector` (with `enable: false` or features disabled), `DisassociateFromAdministratorAccount`, `DisassociateMembers`, `StopMonitoringMembers`, `DeleteMembers`, `DisableOrganizationAdminAccount`, `UpdateOrganizationConfiguration`; on the organisation side `DisableAWSServiceAccess` for `guardduty.amazonaws.com`. GuardDuty may raise `DefenseEvasion:IAMUser/AnomalousBehavior`. These events should alert in the CloudWatch/EventBridge layer (see [monitoring](/cloud/aws-cloudwatch-eventbridge-monitoring/)) and be prevented by SCP (GT-AWS-DET-10).

### GT-AWS-DET-2: GuardDuty protection plans and organisation auto-enable

*Guler Tech methodology.*

#### What it checks

That the protection plans relevant to the resources actually in use (S3, EKS, ECS, EC2, RDS, Lambda, AI services) are enabled for every account, and that new and existing accounts get them automatically.

#### Prerequisites

As GT-AWS-DET-1. A resource inventory (Config aggregator or Prowler output) to know which resource types exist.

#### Steps

1. Feature status of the administrator detector, per Region:

   ```bash
   for r in $REGIONS; do
     d=$(aws guardduty list-detectors --region "$r" --query 'DetectorIds[0]' --output text)
     [ "$d" = "None" ] && continue
     echo "== $r"
     aws guardduty get-detector --region "$r" --detector-id "$d" \
       --query 'Features[].[Name,Status]' --output text
   done
   ```

2. Organisation auto-enable per feature:

   ```bash
   aws guardduty describe-organization-configuration --region eu-west-2 --detector-id "$d" \
     --query 'Features[].[Name,AutoEnable]' --output text
   ```

3. Per member, what is actually enabled (the administrator can read member detectors):

   ```bash
   aws guardduty get-member-detectors --region eu-west-2 --detector-id "$d" \
     --account-ids 444455556666 123456789012 \
     --query 'MemberDataSourceConfigurations[].{acct:AccountId,features:Features[].[Name,Status]}'
   ```

4. Runtime Monitoring agent coverage, where Runtime Monitoring is on:

   ```bash
   aws guardduty list-coverage --region eu-west-2 --detector-id "$d" \
     --query 'Resources[?CoverageStatus==`UNHEALTHY`].[AccountId,ResourceDetails.ResourceType,Issue]' \
     --output text
   ```

5. Cross-reference with what exists: EKS clusters (`eks list-clusters`), ECS clusters, RDS/Aurora instances, Lambda functions, Bedrock usage. A plan is only a finding if the resource type it protects is in use.

#### Observation

Illustrative:

```text
CLOUD_TRAIL       ENABLED
DNS_LOGS          ENABLED
FLOW_LOGS         ENABLED
S3_DATA_EVENTS    DISABLED
EKS_AUDIT_LOGS    ENABLED
RUNTIME_MONITORING DISABLED
RDS_LOGIN_EVENTS  ENABLED
LAMBDA_NETWORK_LOGS ENABLED
```

#### Evaluation

**Pass:** for each resource type in use, the matching feature is `ENABLED` in every account and Region where that resource exists, and organisation `AutoEnable` for it is `ALL`; Runtime Monitoring coverage shows no unexplained `UNHEALTHY` resources. **Fail:** `S3_DATA_EVENTS` disabled where S3 holds sensitive data; `EKS_AUDIT_LOGS` and `RUNTIME_MONITORING` both disabled where EKS is used; `RDS_LOGIN_EVENTS` disabled with supported engines; per-feature auto-enable `NEW` or `NONE`. Explain the specific consequence: for example, without S3 Protection there are no S3 data-event findings and no `AttackSequence:S3/CompromisedData`.

#### Automated coverage

Security Hub CSPM **GuardDuty.5** (EKS audit logs), **GuardDuty.6** (Lambda), **GuardDuty.7** (EKS Runtime Monitoring), **GuardDuty.8** (Malware Protection for EC2), **GuardDuty.9** (RDS), **GuardDuty.10** (S3), **GuardDuty.11** (Runtime Monitoring), **GuardDuty.12** (ECS Runtime Monitoring), **GuardDuty.13** (EC2 Runtime Monitoring). Prowler `guardduty_s3_protection_enabled`, `guardduty_eks_audit_log_enabled`, `guardduty_eks_runtime_monitoring_enabled`, `guardduty_runtime_monitoring_enabled`, `guardduty_ec2_malware_protection_enabled`, `guardduty_rds_protection_enabled`, `guardduty_lambda_protection_enabled`, `guardduty_ai_protection_enabled`.

#### Detection

`UpdateDetector`, `UpdateMemberDetectors` and `UpdateOrganizationConfiguration` calls that set a feature to `DISABLED` or `NONE`. Treat a protection plan being switched off outside a change window as a security event.

### GT-AWS-DET-3: GuardDuty suppression rules, trusted lists and threat lists

*Guler Tech methodology.*

#### What it checks

That suppression rules, trusted IP and entity lists, and threat lists are narrow, justified and owned, and that none of them silences whole classes of findings or whole networks an attacker could use.

#### Prerequisites

Read access to the GuardDuty administrator account in each Region; `s3:GetObject` on the list files (or ask the client for copies).

#### Steps

1. Suppression rules (filters with action `ARCHIVE`), per Region:

   ```bash
   for r in $REGIONS; do
     d=$(aws guardduty list-detectors --region "$r" --query 'DetectorIds[0]' --output text)
     [ "$d" = "None" ] && continue
     for f in $(aws guardduty list-filters --region "$r" --detector-id "$d" --query 'FilterNames[]' --output text); do
       aws guardduty get-filter --region "$r" --detector-id "$d" --filter-name "$f" \
         --query '{name:Name,action:Action,rank:Rank,criteria:FindingCriteria.Criterion}' --output json \
         | jq --arg r "$r" '. + {region: $r}'
     done
   done > gd-filters.json
   jq -c 'select(.action=="ARCHIVE")' gd-filters.json
   ```

2. Trusted and threat lists, both the legacy IP sets and the newer entity sets:

   ```bash
   for r in $REGIONS; do
     d=$(aws guardduty list-detectors --region "$r" --query 'DetectorIds[0]' --output text)
     [ "$d" = "None" ] && continue
     for id in $(aws guardduty list-ip-sets --region "$r" --detector-id "$d" --query 'IpSetIds[]' --output text); do
       aws guardduty get-ip-set --region "$r" --detector-id "$d" --ip-set-id "$id" \
         --query '[Name,Status,Format,Location]' --output text | sed "s/^/$r TRUSTED_IPSET /"
     done
     for id in $(aws guardduty list-trusted-entity-sets --region "$r" --detector-id "$d" --query 'TrustedEntitySetIds[]' --output text); do
       aws guardduty get-trusted-entity-set --region "$r" --detector-id "$d" --trusted-entity-set-id "$id" \
         --query '[Name,Status,Format,Location]' --output text | sed "s/^/$r TRUSTED_ENTITYSET /"
     done
     aws guardduty list-threat-intel-sets --region "$r" --detector-id "$d" --output text | sed "s/^/$r THREAT /"
     aws guardduty list-threat-entity-sets --region "$r" --detector-id "$d" --output text | sed "s/^/$r THREAT_ENTITY /"
   done
   ```

   If the output field names differ in your CLI version, run the `get-*` command once without `--query` and adjust.

3. Download each **active** trusted list from its `Location` and review the entries: size of ranges, owner of each range, whether it includes shared egress (VPN, proxy, CI runners, a whole cloud provider), whether it includes the scanner hosts only.

   ```bash
   aws s3 cp s3://example-gd-lists/trusted.txt - | awk -F/ 'NF==2 && $2<24 {print "WIDE", $0}'
   ```

4. Look at what the suppression rules are hiding right now: count archived findings by type over the last 90 days.

   ```bash
   cat > archived.json <<'EOF'
   {
     "Criterion": {
       "service.archived": { "Eq": ["true"] }
     }
   }
   EOF
   aws guardduty get-findings-statistics --region eu-west-2 --detector-id "$d" \
     --finding-statistic-types COUNT_BY_SEVERITY --finding-criteria file://archived.json
   aws guardduty list-findings --region eu-west-2 --detector-id "$d" \
     --finding-criteria file://archived.json --query 'FindingIds[]' --output text \
     | tr '\t' '\n' | head -50 \
     | xargs aws guardduty get-findings --region eu-west-2 --detector-id "$d" --finding-ids \
     | jq -r '.Findings[] | [.Type, .Severity, .Service.Count] | @tsv' | sort | uniq -c | sort -rn | head
   ```

5. For each rule and list, ask the client: who created it, when, for which recurring false positive, and when it was last reviewed. CloudTrail `CreateFilter`/`UpdateFilter`/`CreateIPSet`/`CreateTrustedEntitySet` events give you the who and when if the client cannot.

#### Observation

Illustrative suppression rule that should fail:

```json
{
  "name": "quiet-recon",
  "action": "ARCHIVE",
  "rank": 1,
  "criteria": {
    "type": { "Eq": ["Recon:IAMUser/MaliciousIPCaller", "Discovery:IAMUser/AnomalousBehavior", "PenTest:IAMUser/KaliLinux"] }
  },
  "region": "eu-west-2"
}
```

And one that is fine: finding type `Recon:EC2/Portscan` **and** `resource.instanceDetails.tags.value` equal to the vulnerability scanner's tag.

#### Evaluation

**Pass:** every `ARCHIVE` rule combines a finding type with at least one narrow criterion identifying the known-benign source (instance ID or tag, specific remote account, specific `/32` or small owned range), has a recorded reason and owner, and none covers `AttackSequence:*`, `CredentialAccess:*`, `Stealth:*`, `*CredentialExfiltration*`, `PrivilegeEscalation:*` or `Policy:IAMUser/RootCredentialUsage` without such a narrow criterion; trusted lists contain only owned, fixed addresses that no third party or user population shares. **Fail:** any rule suppressing a finding type for all resources; severity-based suppression (`severity Lt 7`); a trusted list including user-facing VPN or proxy egress, CI/CD runner ranges on a shared provider, wide ranges (shorter than `/24` should be justified individually), or ranges the client cannot attribute; trusted lists in a Region where nobody knows why they exist. Rate according to what is hidden (see [Rating findings](#rating-findings)).

#### Automated coverage

None for scope; Security Hub CSPM **GuardDuty.2** and **GuardDuty.3** only check that filters and IP sets are tagged. Prowler has no check for suppression scope. This is a manual test.

#### Detection

CloudTrail `CreateFilter`, `UpdateFilter`, `DeleteFilter`, `CreateIPSet`, `UpdateIPSet`, `CreateTrustedEntitySet`, `UpdateTrustedEntitySet`, `UpdateThreatIntelSet`, `DeleteThreatIntelSet`, `DeleteThreatEntitySet`; and `s3:PutObject` on the list file location (a list's content can change without any GuardDuty API call; GuardDuty only reads it again on re-activation, which is an `UpdateIPSet`/`UpdateTrustedEntitySet` call). These changes should require approval and alert.

### GT-AWS-DET-4: Findings are routed to a human

*Guler Tech methodology.*

#### What it checks

That GuardDuty and Security Hub findings (and Inspector, Macie and Access Analyzer findings, directly or through Security Hub) reach a monitored queue, pager or SIEM with a named owner, across all accounts and Regions, including Low-severity finding types that matter.

#### Prerequisites

Read access to the administrator accounts and the Security Hub aggregation Region; EventBridge, SNS and (if used) SIEM configuration. A conversation with the SOC.

#### Steps

1. EventBridge rules that match GuardDuty or Security Hub, in each Region of the administrator account (GuardDuty sends member findings to the administrator's event bus):

   ```bash
   for r in $REGIONS; do
     aws events list-rules --region "$r" --output json \
       | jq -r --arg r "$r" '.Rules[] | select((.EventPattern // "") | test("aws.guardduty|aws.securityhub|aws.inspector2|aws.macie|aws.access-analyzer")) | [$r, .Name, .State, .EventPattern] | @tsv'
   done
   ```

2. For each rule, its targets, and for SNS targets, whether anyone is subscribed:

   ```bash
   aws events list-targets-by-rule --region eu-west-2 --rule gd-high-to-soc --query 'Targets[].Arn' --output text
   aws sns list-subscriptions-by-topic --region eu-west-2 \
     --topic-arn arn:aws:sns:eu-west-2:444455556666:soc-alerts \
     --query 'Subscriptions[].[Protocol,Endpoint,SubscriptionArn]' --output text
   ```

   A `SubscriptionArn` of `PendingConfirmation` means the email was never confirmed.

3. Read the event pattern. Does it filter on severity? If so, which important Low-severity types are excluded (`Stealth:IAMUser/CloudTrailLoggingDisabled`, `Policy:IAMUser/RootCredentialUsage`, `Policy:IAMUser/ShortTermRootCredentialUsage`)?
4. GuardDuty export and frequency: `list-publishing-destinations` and the detector's `FindingPublishingFrequency`.
5. Security Hub CSPM to SIEM: the SIEM integration, or an EventBridge rule on `detail-type` `Security Hub Findings - Imported` in the aggregation Region; and cross-Region aggregation (GT-AWS-DET-5).
6. Backlog: high-severity GuardDuty findings that are still active.

   ```bash
   cat > high-active.json <<'EOF'
   {
     "Criterion": {
       "severity": { "Gte": 7 },
       "service.archived": { "Eq": ["false"] }
     }
   }
   EOF
   aws guardduty list-findings --region eu-west-2 --detector-id "$d" --finding-criteria file://high-active.json \
     --sort-criteria AttributeName=updatedAt,OrderBy=ASC --max-items 20 --query 'FindingIds' --output text
   ```

7. **Lab or explicitly approved only (state-changing):** generate one sample finding in an agreed member account and Region, and time its arrival at the human end. Sample findings are titled `[SAMPLE]` and carry `"sample": true` in the finding details, so they are clearly distinguishable. Archive it afterwards.

   ```bash
   aws guardduty create-sample-findings --region eu-west-2 --detector-id "$MEMBER_DETECTOR" \
     --finding-types 'Stealth:IAMUser/CloudTrailLoggingDisabled'
   ```

   Sample findings test the **routing**, not the detection. GT-AWS-DET-11 tests detection.

#### Observation

The rule list, target and subscription state, the event pattern, the count and age of active high findings, and (if approved) the time from sample creation to a ticket or page.

#### Evaluation

**Pass:** in every Region (or via aggregation, every Region reaches the home Region), an enabled rule routes GuardDuty findings, including the named Low-severity types, to a target with confirmed, monitored subscribers or a SIEM with an owner; Security Hub CSPM findings reach the same place; there are no high-severity findings older than the client's own SLA; an approved sample arrives within the agreed time. **Fail:** no rule; rule disabled; target with no confirmed subscription; Regions not covered; severity filter excluding the named types; a backlog of active high findings (escalate any that look like genuine compromise straight away rather than waiting for the report).

#### Automated coverage

None in Security Hub CSPM or CIS (the CIS CloudWatch alarm controls are about CloudTrail metric filters, a different layer; see [monitoring](/cloud/aws-cloudwatch-eventbridge-monitoring/)). Prowler `guardduty_no_high_severity_findings` flags the backlog.

#### Detection

`DeleteRule`, `DisableRule`, `PutRule`, `RemoveTargets`, `PutTargets` on the routing rules; `Unsubscribe`, `DeleteTopic`, `SetTopicAttributes` on the SNS topic; `DeletePublishingDestination` and `UpdateDetector` changing `FindingPublishingFrequency` in GuardDuty.

### GT-AWS-DET-5: Security Hub CSPM coverage, standards and automation rules

*Guler Tech methodology.*

#### What it checks

That Security Hub CSPM is enabled in every account and Region with relevant standards, that findings are aggregated to one home Region, that disabled controls are justified, and that automation rules do not suppress meaningful findings. It also records whether the new Security Hub is enabled.

#### Prerequisites

Read access to the Security Hub delegated administrator account.

#### Steps

1. Per Region, hub status and enabled standards:

   ```bash
   for r in $REGIONS; do
     if aws securityhub describe-hub --region "$r" >/dev/null 2>&1; then
       echo "== $r enabled"
       aws securityhub get-enabled-standards --region "$r" \
         --query 'StandardsSubscriptions[].[StandardsArn,StandardsStatus]' --output text
     else
       echo "== $r NOT ENABLED"
     fi
   done
   ```

2. Organisation configuration and members:

   ```bash
   aws securityhub describe-organization-configuration --region eu-west-2
   aws securityhub list-members --region eu-west-2 --only-associated \
     --query 'Members[].[AccountId,MemberStatus]' --output text | sort > sh-members.txt
   ```

   `OrganizationConfiguration.ConfigurationType` of `CENTRAL` means central configuration policies; list them with `list-configuration-policies` and `list-configuration-policy-associations`.

3. Cross-Region aggregation:

   ```bash
   aws securityhub list-finding-aggregators --region eu-west-2
   aws securityhub get-finding-aggregator --region eu-west-2 \
     --finding-aggregator-arn arn:aws:securityhub:eu-west-2:444455556666:finding-aggregator/EXAMPLE
   ```

4. Disabled controls and their reasons, per standard subscription:

   ```bash
   for s in $(aws securityhub get-enabled-standards --region eu-west-2 --query 'StandardsSubscriptions[].StandardsSubscriptionArn' --output text); do
     aws securityhub describe-standards-controls --region eu-west-2 --standards-subscription-arn "$s" \
       --query 'Controls[?ControlStatus==`DISABLED`].[ControlId,DisabledReason]' --output text
   done
   ```

5. Automation rules and what they do:

   ```bash
   arns=$(aws securityhub list-automation-rules --region eu-west-2 --query 'AutomationRulesMetadata[].RuleArn' --output text)
   aws securityhub batch-get-automation-rules --region eu-west-2 --automation-rules-arns $arns \
     | jq '.Rules[] | {name: .RuleName, order: .RuleOrder, status: .RuleStatus, criteria: .Criteria, actions: .Actions}'
   ```

6. New Security Hub status (where the CLI supports it): `aws securityhub describe-security-hub-v2 --region eu-west-2`.

#### Observation

Illustrative automation rule that should fail:

```json
{
  "name": "sandbox-noise",
  "order": 1,
  "status": "ENABLED",
  "criteria": { "AwsAccountId": [ { "Value": "123456789012", "Comparison": "EQUALS" } ] },
  "actions": [ { "Type": "FINDING_FIELDS_UPDATE", "FindingFieldsUpdate": { "Workflow": { "Status": "SUPPRESSED" } } } ]
}
```

#### Evaluation

**Pass:** enabled in every enabled Region of every account; at least AWS FSBP and the client's chosen compliance standard enabled; a finding aggregator with `ALL_REGIONS` (or `ALL_REGIONS_EXCEPT_SPECIFIED` with a documented exception list); disabled controls each have a reason that stands up (resource type not used, compensating control); automation rules only enrich, re-prioritise narrowly or suppress specific known-benign resources. **Fail:** Regions or accounts missing; `SPECIFIED_REGIONS` aggregation missing Regions in use; controls disabled with empty or "noise" reasons; automation rules suppressing by account, product, standard or severity band; Config prerequisites not met (results in `WARNING`, see GT-AWS-DET-6).

#### Automated coverage

No Security Hub CSPM control checks Security Hub itself. Prowler `securityhub_enabled`, `securityhub_delegated_admin_enabled_all_regions`.

#### Detection

`DisableSecurityHub`, `DisableSecurityHubV2`, `BatchDisableStandards`, `UpdateStandardsControl`/`UpdateSecurityControl`/`BatchUpdateStandardsControlAssociations` (disabling controls), `CreateAutomationRule`/`BatchUpdateAutomationRules`, `DeleteFindingAggregator`/`UpdateFindingAggregator`, `DisassociateFromAdministratorAccount`, `DisableImportFindingsForProduct`.

### GT-AWS-DET-6: AWS Config recorder coverage and aggregation

*Guler Tech methodology.*

#### What it checks

That a configuration recorder is running in every account and Region, records all supported resource types continuously, records the IAM global types exactly once per account, delivers to a protected bucket, and that an organisation aggregator covers all Regions.

#### Prerequisites

Read access in member accounts (or the aggregator account plus a sample of members); `config:Describe*`.

#### Steps

1. Per Region, recorders (customer-managed and service-linked), their scope and status:

   ```bash
   for r in $REGIONS; do
     echo "== $r"
     aws configservice describe-configuration-recorders --region "$r" \
       --query 'ConfigurationRecorders[].{name:name,all:recordingGroup.allSupported,global:recordingGroup.includeGlobalResourceTypes,strategy:recordingGroup.recordingStrategy.useOnly,freq:recordingMode.recordingFrequency}' \
       --output table
     aws configservice describe-configuration-recorder-status --region "$r" \
       --query 'ConfigurationRecordersStatus[].[name,recording,lastStatus]' --output text
     aws configservice describe-delivery-channels --region "$r" \
       --query 'DeliveryChannels[].[name,s3BucketName,snsTopicARN]' --output text
   done
   aws configservice list-configuration-recorders --region eu-west-2   # shows service-linked recorders and their scope
   ```

2. Which Region records IAM global types, in each account? Exactly one Region should show `includeGlobalResourceTypes: true` (or an explicit inclusion of the `AWS::IAM::*` types).
3. Exclusions: with `EXCLUSION_BY_RESOURCE_TYPES`, read `recordingGroup.exclusionByResourceTypes.resourceTypes` and ask why each is excluded.
4. Aggregator, in the Config delegated administrator account:

   ```bash
   aws configservice describe-configuration-aggregators \
     --query 'ConfigurationAggregators[].{name:ConfigurationAggregatorName,org:OrganizationAggregationSource}'
   aws configservice describe-configuration-aggregator-sources-status \
     --configuration-aggregator-name org-aggregator \
     --query 'AggregatedSourceStatusList[?LastUpdateStatus!=`SUCCEEDED`]'
   ```

5. Conformance packs and organisation rules in place:

   ```bash
   aws configservice describe-organization-conformance-packs --query 'OrganizationConformancePacks[].OrganizationConformancePackName'
   aws configservice describe-conformance-packs --region eu-west-2 --query 'ConformancePackDetails[].ConformancePackName'
   ```

6. Use the aggregator as evidence: for example, a count of recorded resource types per account, which also shows you accounts whose recorders capture almost nothing.

   ```bash
   aws configservice select-aggregate-resource-config --configuration-aggregator-name org-aggregator \
     --expression "SELECT accountId, resourceType, COUNT(*) GROUP BY accountId, resourceType"
   ```

   Property filters (for example on security group rules) work too, but check the exact field paths against your own `SELECT configuration` output before relying on a `WHERE` clause; some fields are not searchable.

#### Observation

Illustrative:

```text
== eu-west-2
| name    | all  | global | strategy                      | freq       |
| default | True | True   | ALL_SUPPORTED_RESOURCE_TYPES  | CONTINUOUS |
default True SUCCESS
== us-east-1
default False FAILURE
== ap-southeast-3
(no recorder)
```

#### Evaluation

**Pass:** a running recorder (`recording: true`, `lastStatus: SUCCESS`) in every enabled Region of every account; `ALL_SUPPORTED_RESOURCE_TYPES`, or exclusions limited to justified ephemeral types; continuous recording for production; IAM global types recorded in exactly one Region per account; a delivery channel to a bucket in a log archive account; an organisation aggregator with all Regions and all sources `SUCCEEDED`. **Fail:** no recorder or stopped recorder in any Region; `lastStatus: FAILURE`; IAM global types recorded nowhere; production on daily recording; no delivery channel; aggregator missing or partial. Where Config.1 passes because of the service-linked recorder only, report that the client has no customer-controlled configuration history (Low to Medium, depending on their investigation needs).

#### Automated coverage

Security Hub CSPM **Config.1** (CIS v3.0.0 **3.3**, CIS v5.0.0 **3.3**, CIS v1.4.0 3.5). Prowler `config_recorder_all_regions_enabled`, `config_recorder_using_aws_service_role`, `config_delegated_admin_and_org_aggregator_all_regions`.

#### Detection

`StopConfigurationRecorder`, `DeleteConfigurationRecorder`, `PutConfigurationRecorder` (narrowing scope), `DeleteDeliveryChannel`, `PutDeliveryChannel`, `DeleteConfigurationAggregator`, `DeleteConfigRule`, `DeleteConformancePack`, `DeleteOrganizationConformancePack`, `PutRetentionConfiguration`. CIS v1.4.0 4.9 (Security Hub CloudWatch.9) is the classic metric filter and alarm for Config changes.

### GT-AWS-DET-7: Inspector and Macie coverage

*Guler Tech methodology.*

#### What it checks

That Inspector scans the EC2, ECR and Lambda resources in use without unexplained gaps or exclusions, and that Macie is enabled with automated discovery whose scope includes the buckets that hold sensitive data.

#### Prerequisites

Read access to the Inspector and Macie delegated administrator accounts (the Macie actions listed in [Before you start](#before-you-start)).

#### Steps

1. Inspector account status and organisation auto-enable:

   ```bash
   aws inspector2 batch-get-account-status --region eu-west-2 --account-ids 444455556666 123456789012 \
     --query 'accounts[].{acct:accountId,state:state.status,ec2:resourceState.ec2.status,ecr:resourceState.ecr.status,lambda:resourceState.lambda.status,lambdaCode:resourceState.lambdaCode.status}'
   aws inspector2 describe-organization-configuration --region eu-west-2
   ```

2. Coverage gaps, grouped by reason:

   ```bash
   aws inspector2 list-coverage-statistics --region eu-west-2 --group-by SCAN_STATUS_REASON
   cat > inactive.json <<'EOF'
   {
     "scanStatusCode": [ { "comparison": "EQUALS", "value": "INACTIVE" } ]
   }
   EOF
   aws inspector2 list-coverage --region eu-west-2 --filter-criteria file://inactive.json \
     --query 'coveredResources[].[accountId,resourceType,resourceId,scanStatus.reason]' --output text
   ```

3. Exclusion tags on instances and KMS keys:

   ```bash
   aws ec2 describe-tags --region eu-west-2 --filters Name=key,Values=InspectorEc2Exclusion,inspectorec2exclusion \
     --query 'Tags[].[ResourceId,Value]' --output text
   ```

   The tag key is case-insensitive for Inspector but the EC2 filter is not; also search with Steampipe or the Config aggregator if case varies.

4. EC2 scan mode (agent-based or hybrid) and ECR re-scan duration: `aws inspector2 get-configuration --region eu-west-2`.
5. Macie session and automated discovery:

   ```bash
   aws macie2 get-macie-session --region eu-west-2 --query '[status,findingPublishingFrequency]' --output text
   aws macie2 get-automated-discovery-configuration --region eu-west-2
   aws macie2 list-automated-discovery-accounts --region eu-west-2 \
     --query 'items[?status!=`ENABLED`]' --output text
   ```

6. Macie scope and blind spots: the classification scope's excluded buckets, and buckets Macie cannot analyse.

   ```bash
   scope=$(aws macie2 get-automated-discovery-configuration --region eu-west-2 --query 'classificationScopeId' --output text)
   aws macie2 get-classification-scope --region eu-west-2 --id "$scope" --query 's3.excludes.bucketNames'
   aws macie2 describe-buckets --region eu-west-2 \
     --query 'buckets[?errorCode!=null].[accountId,bucketName,errorCode]' --output text
   ```

#### Observation

Coverage statistics by reason, the list of inactive resources with reasons, excluded instances, Macie status, excluded buckets and buckets with errors.

#### Evaluation

**Pass:** Inspector EC2, ECR and Lambda scanning enabled in every account and Region where those resources exist, with organisation auto-enable on; inactive resources limited to unsupported platforms, each known; no exclusion tags on internet-facing or production instances without a recorded reason; Macie enabled with automated discovery in accounts that hold personal or regulated data; exclusions limited to log buckets; buckets Macie cannot read are understood (and that is usually a deliberate KMS or bucket-policy design). **Fail:** scan types disabled where the resources exist; many `INACTIVE` resources such as unmanaged EC2 instances with hybrid scanning off; exclusion tags on production; Macie disabled, or automated discovery disabled for accounts holding customer data; sensitive buckets excluded.

#### Automated coverage

Security Hub CSPM **Inspector.1** (EC2), **Inspector.2** (ECR), **Inspector.3** (Lambda code), **Inspector.4** (Lambda standard), **Macie.1**, **Macie.2** (Macie.1 is a manual check in the CIS mappings). Prowler `inspector2_is_enabled`, `inspector2_coverage_scan_status_active`, `inspector2_coverage_recently_scanned`, `inspector2_active_findings_exist`, `macie_is_enabled`, `macie_automated_sensitive_data_discovery_enabled`.

#### Detection

Inspector `Disable`, `UpdateOrganizationConfiguration`, `UpdateConfiguration`, `DisableDelegatedAdminAccount`; `CreateTags` adding `InspectorEc2Exclusion`. Macie `DisableMacie`, `UpdateMacieSession` (pausing), `UpdateAutomatedDiscoveryConfiguration`, `UpdateClassificationScope`, `DisableOrganizationAdminAccount`.

### GT-AWS-DET-8: IAM Access Analyzer coverage and open findings

*Guler Tech methodology.*

#### What it checks

That an organisation-scoped external access analyzer exists in every Region in use, that its active findings are triaged and archive rules are narrow, and whether unused-access and internal-access analysis is in place.

#### Prerequisites

Read access to the Access Analyzer delegated administrator account.

#### Steps

1. Analyzers per Region:

   ```bash
   for r in $REGIONS; do
     aws accessanalyzer list-analyzers --region "$r" \
       --query 'analyzers[].[name,type,status]' --output text | sed "s/^/$r /"
   done
   ```

2. Active external findings (use a file for the filter):

   ```bash
   cat > active.json <<'EOF'
   {
     "status": { "eq": ["ACTIVE"] }
   }
   EOF
   aws accessanalyzer list-findings-v2 --region eu-west-2 \
     --analyzer-arn arn:aws:access-analyzer:eu-west-2:444455556666:analyzer/org-external \
     --filter file://active.json \
     --query 'findings[].[resourceType,resource,resourceOwnerAccount,findingType]' --output text
   ```

3. Archive rules (auto-archive criteria):

   ```bash
   aws accessanalyzer list-archive-rules --region eu-west-2 --analyzer-name org-external
   ```

4. Use custom policy checks as a quick proof on a policy you are reviewing elsewhere (read-only API calls, no change to the account):

   ```bash
   aws accessanalyzer check-no-public-access --region eu-west-2 \
     --policy-document file://bucket-policy.json --resource-type AWS::S3::Bucket
   aws accessanalyzer check-access-not-granted --region eu-west-2 \
     --policy-document file://role-policy.json --policy-type IDENTITY_POLICY \
     --access '[{"actions":["iam:PassRole","iam:CreateAccessKey"]}]'
   ```

#### Observation

Illustrative:

```text
eu-west-2 org-external ORGANIZATION ACTIVE
eu-west-2 org-unused ORGANIZATION_UNUSED_ACCESS ACTIVE
us-east-1 acct-external ACCOUNT ACTIVE
ap-southeast-3                                   (no analyzer)
AWS::IAM::Role arn:aws:iam::444455556666:role/vendor-integration 444455556666 ExternalAccess
```

#### Evaluation

**Pass:** an `ORGANIZATION` external access analyzer in every Region with resources; every active finding either remediated or archived with a narrow rule tied to a documented, intended external principal; an unused access analyzer exists (or the client has another equivalent process). **Fail:** no analyzer in Regions with resources; only `ACCOUNT`-scoped analyzers with a culture of archiving everything; archive rules matching by resource type or by `isPublic` alone; active public findings untriaged. Each active finding is also a lead for the [S3](/cloud/aws-s3-security/), [KMS](/cloud/aws-secrets-manager-parameter-store-kms/) and [cross-account trust](/cloud/aws-sts-cross-account-trust-federation/) notes, and is rated there.

#### Automated coverage

Security Hub CSPM **IAM.28** (CIS v3.0.0 **1.20**, CIS v5.0.0 **1.19**). Prowler `accessanalyzer_enabled`, `accessanalyzer_enabled_without_findings`.

#### Detection

`DeleteAnalyzer`, `CreateArchiveRule`, `UpdateArchiveRule`, `ApplyArchiveRule`, `UpdateFindings` (bulk archiving). On the organisation side, `DisableAWSServiceAccess` for `access-analyzer.amazonaws.com` (seen in the [Datadog case](#real-world-cases)).

### GT-AWS-DET-9: VPC Flow Logs and Resolver query log coverage

*Guler Tech methodology.*

#### What it checks

That every VPC has a flow log capturing `ALL` traffic with useful fields, delivered to a destination with adequate retention, and that Resolver query logging is associated with every VPC that runs workloads.

#### Prerequisites

Read access to member accounts (`ec2:Describe*`, `logs:DescribeLogGroups`, `route53resolver:List*`).

#### Steps

1. VPCs without a VPC-level flow log, per Region:

   ```bash
   for r in $REGIONS; do
     aws ec2 describe-vpcs --region "$r" --query 'Vpcs[].VpcId' --output text | tr '\t' '\n' | sort > vpcs.tmp
     aws ec2 describe-flow-logs --region "$r" --query 'FlowLogs[].ResourceId' --output text | tr '\t' '\n' | sort -u > fl.tmp
     comm -23 vpcs.tmp fl.tmp | sed "s/^/$r NO_VPC_FLOW_LOG /"
   done
   ```

   Subnet- or ENI-level flow logs may cover part of a VPC; treat those VPCs as partial, not absent.

2. Quality of each flow log:

   ```bash
   aws ec2 describe-flow-logs --region eu-west-2 \
     --query 'FlowLogs[].{res:ResourceId,traffic:TrafficType,dest:LogDestinationType,where:LogDestination || LogGroupName,fmt:LogFormat,agg:MaxAggregationInterval,status:DeliverLogsStatus}' \
     --output json
   ```

3. Retention of CloudWatch Logs destinations:

   ```bash
   aws logs describe-log-groups --region eu-west-2 --log-group-name-prefix /vpc/flow \
     --query 'logGroups[].[logGroupName,retentionInDays]' --output text
   ```

   For S3 destinations, read the bucket lifecycle configuration and Object Lock settings (see the [S3 note](/cloud/aws-s3-security/)).

4. Resolver query logging associations:

   ```bash
   for r in $REGIONS; do
     aws route53resolver list-resolver-query-log-config-associations --region "$r" \
       --query 'ResolverQueryLogConfigAssociations[?Status==`ACTIVE`].ResourceId' --output text \
       | tr '\t' '\n' | sort > rq.tmp
     aws ec2 describe-vpcs --region "$r" --query 'Vpcs[].VpcId' --output text | tr '\t' '\n' | sort > vpcs.tmp
     comm -23 vpcs.tmp rq.tmp | sed "s/^/$r NO_RESOLVER_QUERY_LOG /"
   done
   ```

5. Custom DNS: DHCP option sets with `domain-name-servers` other than `AmazonProvidedDNS` mean workloads bypass the VPC Resolver (and GuardDuty DNS analysis).

   ```bash
   aws ec2 describe-dhcp-options --region eu-west-2 --output json \
     | jq -r '.DhcpOptions[] | [.DhcpOptionsId, ([.DhcpConfigurations[] | select(.Key=="domain-name-servers") | .Values[].Value] | join(","))] | @tsv'
   aws ec2 describe-vpcs --region eu-west-2 --query 'Vpcs[].[VpcId,DhcpOptionsId]' --output text
   ```

#### Observation

Illustrative flow log entry that should fail on quality:

```json
{
  "res": "vpc-0a1b2c3d4e5f60718",
  "traffic": "REJECT",
  "dest": "cloud-watch-logs",
  "where": "/vpc/flow/prod",
  "fmt": "${version} ${account-id} ${interface-id} ${srcaddr} ${dstaddr} ${srcport} ${dstport} ${protocol} ${packets} ${bytes} ${start} ${end} ${action} ${log-status}",
  "agg": 600,
  "status": "SUCCESS"
}
```

#### Evaluation

**Pass:** every VPC that hosts workloads has a VPC-level flow log with `TrafficType: ALL`, a custom format including at least `vpc-id`, `instance-id`, `pkt-srcaddr`, `pkt-dstaddr`, `tcp-flags`, `flow-direction`, `traffic-path` and `pkt-dst-aws-service`, delivering successfully to a destination with retention that meets the client's investigation window (we suggest at least 90 days hot, a year in archive, but the client's policy wins); Resolver query logging is associated with the same VPCs; custom DNS is either absent or logs equivalently. **Fail:** VPCs without flow logs; `REJECT`-only; default v2 format in production; retention of days; `DeliverLogsStatus` failing; no Resolver query logging on production VPCs; custom DNS servers with no logging. Empty default VPCs with no ENIs are Informational.

#### Automated coverage

Security Hub CSPM **EC2.6** (CIS v3.0.0 **3.7**, CIS v5.0.0 **3.7**, CIS v1.4.0 3.9). Route53.2 is about public hosted zone logging, not Resolver query logging. Prowler `vpc_flow_logs_enabled`.

#### Detection

`DeleteFlowLogs` (GuardDuty may raise `DefenseEvasion:IAMUser/AnomalousBehavior`), `DeleteLogGroup`, `PutRetentionPolicy`, `DeleteResolverQueryLogConfig`, `DisassociateResolverQueryLogConfig`, `AssociateDhcpOptions` and `CreateDhcpOptions` switching to custom DNS. ATT&CK T1685.002 (formerly T1562.008).

### GT-AWS-DET-10: Delegated administrators and protection of security tooling

*Guler Tech methodology.*

#### What it checks

That each security service is administered from a dedicated security account rather than the management account, and that SCPs stop member-account principals (other than a named security role) from disabling, re-scoping or tuning the tooling.

#### Prerequisites

Management account read-only access (or client assistance) for `organizations` calls; read access to SCPs; one ordinary admin-level role in a member account to simulate against.

#### Steps

1. Delegated administrators and the services they hold:

   ```bash
   aws organizations describe-organization --query 'Organization.MasterAccountId' --output text
   for a in $(aws organizations list-delegated-administrators --query 'DelegatedAdministrators[].Id' --output text); do
     echo "== $a"
     aws organizations list-delegated-services-for-account --account-id "$a" \
       --query 'DelegatedServices[].ServicePrincipal' --output text
   done
   aws organizations list-aws-service-access-for-organization \
     --query 'EnabledServicePrincipals[].ServicePrincipal' --output text
   ```

   Some services report their administrator through their own API rather than Organizations; cross-check with `guardduty list-organization-admin-accounts`, `securityhub list-organization-admin-accounts`, `inspector2 get-delegated-admin-account`, `macie2 list-organization-admin-accounts`, `detective list-organization-admin-accounts`.

2. Find SCPs that protect tooling (the full SCP review is in the [Organizations note](/cloud/aws-organizations-multi-account-security/)):

   ```bash
   for p in $(aws organizations list-policies --filter SERVICE_CONTROL_POLICY --query 'Policies[].Id' --output text); do
     aws organizations describe-policy --policy-id "$p" --query 'Policy.Content' --output text \
       | jq -r --arg p "$p" '.Statement[] | select(.Effect=="Deny") | [$p, (.Action|tostring)] | @tsv' \
       | grep -Ei 'guardduty|securityhub|config:|access-analyzer|DeleteFlowLogs|macie2|inspector2|cloudtrail'
   done
   ```

3. Prove the effect for a realistic member-account administrator role with the IAM policy simulator, which evaluates SCPs (but not RCPs) and does not perform the actions:

   ```bash
   aws iam simulate-principal-policy \
     --policy-source-arn arn:aws:iam::123456789012:role/WorkloadAdmin \
     --action-names guardduty:DeleteDetector guardduty:UpdateDetector guardduty:CreateFilter \
       guardduty:CreateIPSet guardduty:CreateTrustedEntitySet guardduty:DisassociateFromAdministratorAccount \
       securityhub:DisableSecurityHub config:StopConfigurationRecorder config:DeleteDeliveryChannel \
       ec2:DeleteFlowLogs access-analyzer:DeleteAnalyzer macie2:DisableMacie inspector2:Disable \
     --query 'EvaluationResults[].[EvalActionName,EvalDecision,OrganizationsDecisionDetail.AllowedByOrganizations]' \
     --output text
   ```

#### Observation

Illustrative:

```text
== 111122223333            (management account)
guardduty.amazonaws.com    securityhub.amazonaws.com
guardduty:DeleteDetector                 allowed   True
config:StopConfigurationRecorder         allowed   True
ec2:DeleteFlowLogs                       allowed   True
```

#### Evaluation

**Pass:** every security service has a delegated administrator that is a dedicated security tooling account (not the management account, not a workload account); for an ordinary member-account administrator role, the simulator shows `explicitDeny` with `AllowedByOrganizations: False` for the tooling-impairment actions, with an exception only for a named security role. **Fail:** the management account is the delegated administrator (or administers services directly); no SCP protects the tooling, so any account administrator can blind the account; SCP exceptions so broad (for example any role whose name contains `Admin`) that they protect nothing.

#### Automated coverage

No Security Hub CSPM control. Prowler `organizations_delegated_administrators`, `organizations_security_services_delegated_admin_not_management_account`.

#### Detection

Organizations `RegisterDelegatedAdministrator`, `DeregisterDelegatedAdministrator`, `DisableAWSServiceAccess`, `DetachPolicy`, `UpdatePolicy`, `DeletePolicy` (logged in `us-east-1`); service-specific `DisableOrganizationAdminAccount` and `EnableOrganizationAdminAccount`. ATT&CK T1685 (Disable or Modify Tools).

### GT-AWS-DET-11: Detection validation in a lab or approved account

*Guler Tech methodology.* **Lab or explicitly approved only.** Every step in this test changes state.

#### What it checks

Whether specific, realistic attacker behaviours produce the expected findings and alerts, end to end, within an agreed time. This is detection validation in a purple-team sense: the defenders know it is happening, the techniques are benign by construction, and the output is a coverage matrix, not a compromise.

#### Prerequisites

- A **dedicated lab or sandbox account** inside the client's organisation (so that organisation-level GuardDuty, Security Hub, SCPs and routing apply), with written approval naming the account, Region, techniques and time window.
- The SOC briefed, with a contact on call during the window.
- GuardDuty and the relevant protection plans enabled in that account; for Extended Threat Detection, the plans the technique needs.
- [GuardDuty tester](https://github.com/awslabs/amazon-guardduty-tester) (CDK, Docker, npm, Session Manager plugin, Kali Marketplace subscription) and/or [Stratus Red Team](https://github.com/DataDog/stratus-red-team).

#### Steps

1. **Routing only, cheapest first:** sample findings for the finding types you care about (see GT-AWS-DET-4). This proves the pipe, not the sensor.
2. **GuardDuty tester** (AWS's own tool, which AWS recommends running in a dedicated non-production account). It deploys a CDK stack (`GuardDutyTesterStack`), tags its instances `CreatedBy: GuardDuty Test Script`, and generates real findings from real activity, including `AttackSequence:EKS/CompromisedCluster` and `AttackSequence:S3/CompromisedData`. It may temporarily enable protection plans it needs and disables them afterwards.

   ```bash
   git clone https://github.com/awslabs/amazon-guardduty-tester && cd amazon-guardduty-tester
   npm install && cdk bootstrap && cdk deploy
   # then, in an SSM session on the tester driver host:
   python3 guardduty_tester.py --s3
   python3 guardduty_tester.py --tactics discovery
   # afterwards
   cdk destroy
   ```

3. **Stratus Red Team** for API-level techniques that map to the series. Each technique has a warm-up (creates prerequisites), a detonation, and a clean-up. Stratus documents the expected CloudTrail events and, where they exist, GuardDuty finding types for each.

   ```bash
   stratus list --platform aws
   stratus warmup aws.defense-evasion.cloudtrail-stop
   stratus detonate aws.defense-evasion.cloudtrail-stop
   stratus cleanup aws.defense-evasion.cloudtrail-stop
   ```

4. Record, per technique: time of detonation, expected signals, which signals appeared, where (GuardDuty, Security Hub, SIEM, pager), and when. Build the matrix with the client:

   | Technique (Stratus ID) | Expected signal | Expected route | Observed |
   |---|---|---|---|
   | `aws.defense-evasion.cloudtrail-stop` | CloudTrail `StopLogging`; GuardDuty `Stealth:IAMUser/CloudTrailLoggingDisabled` (Low) | Pager, despite Low severity | |
   | `aws.defense-evasion.vpc-remove-flow-logs` | CloudTrail `DeleteFlowLogs`; possibly `DefenseEvasion:IAMUser/AnomalousBehavior` | SIEM rule on the event | |
   | `aws.defense-evasion.organizations-leave` | CloudTrail `LeaveOrganization` failing with an SCP denial | SIEM rule; proves the SCP | |
   | `aws.credential-access.ec2-steal-instance-credentials` | GuardDuty `InstanceCredentialExfiltration.OutsideAWS` or `.InsideAWS` (depending on where the credentials are used) | Pager | |
   | `aws.exfiltration.s3-backdoor-bucket-policy` | CloudTrail `PutBucketPolicy`; Access Analyzer external access finding; GuardDuty S3 policy findings where applicable | SIEM, Access Analyzer triage | |
   | `aws.persistence.iam-create-admin-user` | CloudTrail `CreateUser`, `AttachUserPolicy`; possibly `Persistence:IAMUser/AnomalousBehavior` | SIEM rule | |
   | `aws.discovery.ec2-enumerate-from-instance` | Possibly `Discovery:IAMUser/AnomalousBehavior` | Low-priority queue | |

5. Clean up (`stratus cleanup`, `cdk destroy`), archive generated findings, and confirm with the SOC that the lab account is back to baseline.

#### Observation

The completed matrix, with timestamps.

#### Evaluation

This test is measured rather than pass/fail. A technique is **detected** if the expected signal reached the agreed human route within the agreed time; **detected late** if it arrived outside that time; **visible only** if it exists in a console or log store but alerted nobody; **missed** if no signal exists. Each *missed* or *visible only* result on a technique the client considers in scope is a finding under GT-AWS-DET-4, DET-2 or the [monitoring note](/cloud/aws-cloudwatch-eventbridge-monitoring/). Remember that GuardDuty's ML-based `AnomalousBehavior` findings depend on a baseline, which a brand-new lab account does not have: do not read their absence as a product failure, read it as "the client needs a rule-based detection for this event too".

#### Automated coverage

Not applicable; this is the test of the automation.

#### Detection

By design, everything in this test should be detected. The technique-specific CloudTrail events and GuardDuty finding types are listed in the matrix.

## Hardening

**Turn everything on, everywhere, from a security account.** Register a dedicated security tooling account as delegated administrator for GuardDuty, Security Hub, Config, Inspector, Macie, Detective and Access Analyzer. Use organisation auto-enable `ALL` (or GuardDuty and Security Hub organisation policies) so that existing and future accounts and Regions are covered. In Terraform (one provider alias per Region; shown for one Region):

```hcl
resource "aws_guardduty_organization_admin_account" "this" {
  admin_account_id = "444455556666"
}

# In the security tooling account
resource "aws_guardduty_detector" "admin" {
  enable                       = true
  finding_publishing_frequency = "FIFTEEN_MINUTES"
}

resource "aws_guardduty_organization_configuration" "this" {
  detector_id                      = aws_guardduty_detector.admin.id
  auto_enable_organization_members = "ALL"
}

resource "aws_guardduty_organization_configuration_feature" "s3" {
  detector_id = aws_guardduty_detector.admin.id
  name        = "S3_DATA_EVENTS"
  auto_enable = "ALL"
}

resource "aws_guardduty_organization_configuration_feature" "runtime" {
  detector_id = aws_guardduty_detector.admin.id
  name        = "RUNTIME_MONITORING"
  auto_enable = "ALL"

  additional_configuration {
    name        = "EKS_ADDON_MANAGEMENT"
    auto_enable = "ALL"
  }
  additional_configuration {
    name        = "ECS_FARGATE_AGENT_MANAGEMENT"
    auto_enable = "ALL"
  }
}
```

Repeat the feature resource for `EKS_AUDIT_LOGS`, `EBS_MALWARE_PROTECTION`, `RDS_LOGIN_EVENTS`, `LAMBDA_NETWORK_LOGS` and `AI_PROTECTION` as appropriate.

**Protect the tooling with an SCP.** Attach to the root (or every workload OU) a deny for the impairment actions, excepting only the security role. Verify each action name against the Service Authorization Reference for your services; the ones below were current at the time of writing.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ProtectSecurityTooling",
      "Effect": "Deny",
      "Action": [
        "guardduty:DeleteDetector",
        "guardduty:UpdateDetector",
        "guardduty:DisassociateFromAdministratorAccount",
        "guardduty:DisassociateMembers",
        "guardduty:StopMonitoringMembers",
        "guardduty:CreateFilter",
        "guardduty:UpdateFilter",
        "guardduty:CreateIPSet",
        "guardduty:UpdateIPSet",
        "guardduty:CreateTrustedEntitySet",
        "guardduty:UpdateTrustedEntitySet",
        "guardduty:DeletePublishingDestination",
        "securityhub:DisableSecurityHub",
        "securityhub:DisassociateFromAdministratorAccount",
        "securityhub:BatchDisableStandards",
        "securityhub:CreateAutomationRule",
        "securityhub:BatchUpdateAutomationRules",
        "config:StopConfigurationRecorder",
        "config:DeleteConfigurationRecorder",
        "config:DeleteDeliveryChannel",
        "access-analyzer:DeleteAnalyzer",
        "access-analyzer:CreateArchiveRule",
        "macie2:DisableMacie",
        "inspector2:Disable",
        "detective:DisassociateMembership",
        "ec2:DeleteFlowLogs",
        "route53resolver:DeleteResolverQueryLogConfig",
        "route53resolver:DisassociateResolverQueryLogConfig"
      ],
      "Resource": "*",
      "Condition": {
        "ArnNotLike": {
          "aws:PrincipalArn": "arn:aws:iam::*:role/SecurityToolingAdmin"
        }
      }
    }
  ]
}
```

Keep the exception tight (one role name, created only by the platform pipeline), and remember the SCP does not apply in the management account, which is one more reason not to administer tooling from there.

**Govern tuning like code.** Store GuardDuty suppression rules, trusted and threat lists, Security Hub automation rules and Access Analyzer archive rules in IaC, require review, and give each an owner, reason and review date (tags on filters and IP sets also satisfy GuardDuty.2 and GuardDuty.3). A good suppression rule names the finding type and the specific benign source:

```json
{
  "Criterion": {
    "type": { "Eq": ["Recon:EC2/Portscan"] },
    "resource.instanceDetails.tags.value": { "Eq": ["approved-vuln-scanner"] }
  }
}
```

**Route findings to people, by type as well as severity.** Create the rule in the administrator account in each Region (or the aggregation Region for Security Hub). In CloudFormation:

```yaml
Resources:
  GuardDutyToSoc:
    Type: AWS::Events::Rule
    Properties:
      Name: guardduty-to-soc
      State: ENABLED
      EventPattern:
        source:
          - aws.guardduty
        detail-type:
          - GuardDuty Finding
        detail:
          $or:
            - severity:
                - numeric: [">=", 7]
            - type:
                - prefix: "Stealth:"
                - prefix: "AttackSequence:"
                - "Policy:IAMUser/RootCredentialUsage"
                - "Policy:IAMUser/ShortTermRootCredentialUsage"
      Targets:
        - Id: soc-topic
          Arn: !Ref SocTopic
```

Check that your EventBridge version supports `$or` and `prefix` matching in the Region; otherwise create two rules. Then confirm the subscription, and test it (GT-AWS-DET-4 step 7).

**Record configuration properly.** One customer-managed recorder per account per Region, all supported types, continuous, IAM global types in the home Region only, delivering to the log archive account; plus an organisation aggregator.

```hcl
resource "aws_config_configuration_recorder" "this" {
  name     = "default"
  role_arn = "arn:aws:iam::123456789012:role/aws-service-role/config.amazonaws.com/AWSServiceRoleForConfig"

  recording_group {
    all_supported                 = true
    include_global_resource_types = var.is_home_region   # true in exactly one Region per account
  }

  recording_mode {
    recording_frequency = "CONTINUOUS"
  }
}

resource "aws_config_configuration_aggregator" "org" {
  name = "org-aggregator"

  organization_aggregation_source {
    all_regions = true
    role_arn    = aws_iam_role.config_aggregator.arn
  }
}
```

**Flow logs with useful fields.** In Terraform, escape the `${field}` placeholders as `$${field}` so Terraform does not try to interpolate them:

```hcl
resource "aws_flow_log" "vpc" {
  vpc_id                   = aws_vpc.main.id
  traffic_type             = "ALL"
  log_destination_type     = "s3"
  log_destination          = "arn:aws:s3:::example-log-archive-flowlogs"
  max_aggregation_interval = 60
  log_format = join(" ", [
    "$${version}", "$${account-id}", "$${vpc-id}", "$${subnet-id}", "$${instance-id}", "$${interface-id}",
    "$${srcaddr}", "$${dstaddr}", "$${pkt-srcaddr}", "$${pkt-dstaddr}", "$${srcport}", "$${dstport}",
    "$${protocol}", "$${tcp-flags}", "$${packets}", "$${bytes}", "$${start}", "$${end}", "$${action}",
    "$${flow-direction}", "$${traffic-path}", "$${pkt-src-aws-service}", "$${pkt-dst-aws-service}", "$${log-status}"
  ])
}

resource "aws_route53_resolver_query_log_config" "this" {
  name            = "vpc-dns"
  destination_arn = "arn:aws:s3:::example-log-archive-dns"
}

resource "aws_route53_resolver_query_log_config_association" "vpc" {
  resolver_query_log_config_id = aws_route53_resolver_query_log_config.this.id
  resource_id                  = aws_vpc.main.id
}
```

**Access Analyzer at organisation scope.** One external analyzer per Region in the delegated administrator account, one unused access analyzer, and custom policy checks in CI:

```hcl
resource "aws_accessanalyzer_analyzer" "org_external" {
  analyzer_name = "org-external"
  type          = "ORGANIZATION"
}

resource "aws_accessanalyzer_analyzer" "org_unused" {
  analyzer_name = "org-unused"
  type          = "ORGANIZATION_UNUSED_ACCESS"

  configuration {
    unused_access {
      unused_access_age = 90
    }
  }
}
```

**Back it with Config rules.** Organisation Config rules or a conformance pack with at least `guardduty-enabled-centralized`, `securityhub-enabled`, `vpc-flow-logs-enabled` and `iam-root-access-key-check` give you a second, independent view of coverage that does not depend on the services checking themselves.

**Test it on a schedule.** Run GT-AWS-DET-11 at least yearly and after significant changes, and keep the matrix.

## Real-world cases

- **SCARLETEEL (Sysdig, February 2023).** Attackers exploited an exposed workload in a self-managed Kubernetes cluster, took the node role's credentials through IMDSv1, stole more than 1 TB from S3 including Terraform state with an IAM key, and tried to disable CloudTrail logging, succeeding partially. Sysdig also notes that S3 data events were not enabled, which limited what they could reconstruct. It is a clean illustration of why GuardDuty's independent streams, S3 Protection and protected log pipelines matter. [Sysdig: SCARLETEEL](https://sysdig.com/blog/cloud-breach-terraform-data-theft/)
- **ECS crypto mining across Regions (Datadog Security Labs, January 2024).** Leaked IAM user keys were used to create ECS Fargate clusters running XMRig in at least 17 Regions, plus admin users for persistence. Datadog's recommendations include alerting on cluster and instance creation in unused Regions and watching for cost spikes: the case for GuardDuty and Runtime Monitoring in every Region, and for routing. [Datadog: ECS crypto mining](https://securitylabs.datadoghq.com/articles/tales-from-the-cloud-trenches-ecs-crypto-mining/)
- **Disabling organisation integrations from a management account (Datadog Security Labs, May 2025).** An attacker with a leaked long-term key for an IAM user in an organisation management account disabled trusted access for several AWS services in Organizations, including IAM Access Analyzer, and created an IAM Identity Center user for persistence. Datadog lists `DisableAWSServiceAccess` as a detection. It shows why tooling should not be administered from, and keys should not exist in, the management account. [Datadog: The attacker doth persist too much](https://securitylabs.datadoghq.com/articles/tales-from-the-cloud-trenches-the-attacker-doth-persist-too-much/)

## Rating findings

Missing logging or alerting controls are Medium by default under our series rule, High where they cover CloudTrail itself or the management account, and higher where the gap hides an active, demonstrated attack path.

| Finding | Typical severity | Reasoning |
|---|---|---|
| GuardDuty disabled organisation-wide, or in the management account | High | No threat detection where it matters most; an attacker with credentials is undetected unless other controls exist |
| GuardDuty missing in some accounts or Regions | Medium | Attackers choose unwatched Regions and accounts (T1535); raise to High where those accounts hold production data |
| Protection plan disabled where the resource type holds sensitive data or production workloads (S3, EKS, RDS) | Medium | Data-plane and runtime attacks go unseen and attack sequences cannot form |
| Suppression rule or trusted list hiding credential, exfiltration, evasion or attack-sequence findings broadly, or trusting shared egress | High | Converts detection into silence for exactly the scenarios that matter, across all member accounts; Medium if scope is limited to low-value finding types |
| Findings not routed to any monitored destination, or unconfirmed subscriptions | Medium to High | The control exists but nobody acts; High where active high-severity findings are found unactioned |
| Active high-severity findings indicating possible compromise | Report immediately; rate as an incident | Not a configuration finding; escalate under the engagement's incident procedure |
| Security Hub CSPM automation rules suppressing by account, product or severity | Medium | Removes signal before triage; usually affects many findings |
| Security Hub CSPM missing in Regions or accounts, or aggregation partial | Low to Medium | Posture visibility lost; detection is unaffected if GuardDuty routing is direct |
| Config recorder missing, stopped or partial; IAM global types recorded nowhere | Medium | No configuration history for investigation; Security Hub controls degrade silently |
| Inspector coverage gaps on internet-facing or production workloads; exclusion tags on production | Medium | Known-vulnerable hosts not tracked; Low for internal non-production |
| Macie disabled or excluded where regulated data lives | Low to Medium | Sensitive data and exposure not discovered; context-dependent |
| No external access analyzer, or only in some Regions | Low to Medium | Cross-account and public sharing goes unreported; CIS recommendation |
| VPC Flow Logs missing, `REJECT`-only or short retention on production VPCs | Medium | Network evidence unavailable for investigation and exfiltration analysis |
| Resolver query logging missing; custom DNS bypassing the VPC Resolver | Low to Medium | DNS evidence missing; custom DNS also blinds GuardDuty DNS analysis |
| Delegated administrator is the management account | Medium | Tooling cannot be protected by SCPs; increases management account exposure |
| No SCP protecting security tooling | Medium | Any member-account admin, or anyone who escalates to one, can blind the account; High in combination with demonstrated privilege escalation |
| Detection validation shows key techniques *missed* or *visible only* | Medium (per gap) | Rate the specific undetected behaviour by what it enables |
| Detective not enabled | Informational | Investigation convenience, not a control |

## Mapping

| Test | Security Hub CSPM | CIS (version) | ATT&CK |
|---|---|---|---|
| GT-AWS-DET-1 | GuardDuty.1 | Not mapped | T1535, T1685 |
| GT-AWS-DET-2 | GuardDuty.5, .6, .7, .8, .9, .10, .11, .12, .13 | Not mapped | T1530, T1496.004 |
| GT-AWS-DET-3 | GuardDuty.2, GuardDuty.3 (tagging only) | Not mapped | T1685 |
| GT-AWS-DET-4 | None | Not mapped | T1685 |
| GT-AWS-DET-5 | None (Security Hub does not check itself) | Not mapped | T1685 |
| GT-AWS-DET-6 | Config.1 | v3.0.0 3.3; v5.0.0 3.3; v1.4.0 3.5 | T1685 |
| GT-AWS-DET-7 | Inspector.1, .2, .3, .4; Macie.1, Macie.2 | Macie.1 manual check only | T1190, T1530 |
| GT-AWS-DET-8 | IAM.28 | v3.0.0 1.20; v5.0.0 1.19 | T1078.004, T1530 |
| GT-AWS-DET-9 | EC2.6 (Route53.2 related, different scope) | v3.0.0 3.7; v5.0.0 3.7; v1.4.0 3.9 | T1685.002, T1071.004 |
| GT-AWS-DET-10 | None | Not mapped | T1685 |
| GT-AWS-DET-11 | None | Not mapped | Technique-specific (T1685.002, T1552.005, T1530, T1098.003, T1580) |

ATT&CK note: T1685 and T1685.002 are the ATT&CK v20 IDs for what was T1562.001/T1562 and T1562.008.

## References

- AWS GuardDuty User Guide: [foundational data sources](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_data-sources.html), [features and protection plans](https://docs.aws.amazon.com/guardduty/latest/ug/what-is-guardduty.html), [Extended Threat Detection](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty-extended-threat-detection.html), [attack sequence finding types](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty-attack-sequence-finding-types.html), [IAM finding types](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html), [suppression rules](https://docs.aws.amazon.com/guardduty/latest/ug/findings_suppression-rule.html), [entity lists and IP lists](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_upload-lists.html), [EventBridge](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_findings_eventbridge.html), [sample findings](https://docs.aws.amazon.com/guardduty/latest/ug/sample_findings.html), [tester in dedicated accounts](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_findings-scripts.html)
- AWS CLI: [guardduty update-organization-configuration](https://docs.aws.amazon.com/cli/latest/reference/guardduty/update-organization-configuration.html)
- AWS Organizations: [GuardDuty policies](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_guardduty.html), [Security Hub policies](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_security_hub.html)
- AWS Security Hub: [controls reference](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-controls-reference.html), [CIS AWS Foundations Benchmark in Security Hub CSPM](https://docs.aws.amazon.com/securityhub/latest/userguide/cis-aws-foundations-benchmark.html), [AWS Config for Security Hub CSPM](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-prereq-config.html), [automation rules](https://docs.aws.amazon.com/securityhub/latest/userguide/automation-rules.html), [Security Hub FAQs](https://aws.amazon.com/security-hub/faqs/), [Security Hub GA announcement (December 2025)](https://aws.amazon.com/about-aws/whats-new/2025/12/security-hub-near-real-time-risk-analytics/), [AWS News Blog on GA](https://aws.amazon.com/blogs/aws/aws-security-hub-now-generally-available-with-near-real-time-analytics-and-risk-prioritization/)
- AWS Config: [recording resources and global resource types](https://docs.aws.amazon.com/config/latest/developerguide/select-resources.html)
- Amazon Inspector: [scan types](https://docs.aws.amazon.com/inspector/latest/user/scanning-resources.html), [EC2 scanning](https://docs.aws.amazon.com/inspector/latest/user/scanning-ec2.html)
- Amazon Macie: [automated sensitive data discovery](https://docs.aws.amazon.com/macie/latest/user/discovery-asdd.html)
- IAM Access Analyzer: [overview](https://docs.aws.amazon.com/IAM/latest/UserGuide/what-is-access-analyzer.html), [internal access announcement](https://aws.amazon.com/about-aws/whats-new/2025/06/iam-access-analyzer-aws-organization-access-resources)
- Amazon VPC: [flow log records](https://docs.aws.amazon.com/vpc/latest/userguide/flow-log-records.html)
- Amazon Route 53: [Resolver query logging](https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resolver-query-logs.html)
- Amazon Security Lake: [AWS log sources](https://docs.aws.amazon.com/security-lake/latest/userguide/internal-sources.html)
- IAM: [policy simulator and SCPs](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_testing-policies.html)
- AWS: [penetration testing policy](https://aws.amazon.com/security/penetration-testing/)
- Tools: [Prowler](https://github.com/prowler-cloud/prowler), [ScoutSuite](https://github.com/nccgroup/ScoutSuite), [amazon-guardduty-tester](https://github.com/awslabs/amazon-guardduty-tester), [Stratus Red Team](https://github.com/DataDog/stratus-red-team) and [its documentation](https://stratus-red-team.cloud/)
- MITRE ATT&CK: [T1685 Disable or Modify Tools](https://attack.mitre.org/techniques/T1685/), [T1685.002 Disable or Modify Cloud Log](https://attack.mitre.org/techniques/T1685/002/), [T1535](https://attack.mitre.org/techniques/T1535/), [T1078.004](https://attack.mitre.org/techniques/T1078/004/), [T1530](https://attack.mitre.org/techniques/T1530/), [T1580](https://attack.mitre.org/techniques/T1580/)
- Research: [Sysdig SCARLETEEL](https://sysdig.com/blog/cloud-breach-terraform-data-theft/), [Datadog Security Labs: ECS crypto mining](https://securitylabs.datadoghq.com/articles/tales-from-the-cloud-trenches-ecs-crypto-mining/), [Datadog Security Labs: The attacker doth persist too much](https://securitylabs.datadoghq.com/articles/tales-from-the-cloud-trenches-the-attacker-doth-persist-too-much/)
