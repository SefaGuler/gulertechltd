---
title: "AWS Organizations and Multi-Account Security"
date: 2026-11-12 18:16:00 +0000
subcategory: aws
summary: "Reviewing an AWS organisation: management account blast radius, SCPs, RCPs, declarative policies, delegated admins, root access and Identity Center."
refs: [Account.1, Account.2, IAM.4, IAM.6, IAM.9, EC2.8, "CIS AWS v3.0.0 1.2", "CIS AWS v3.0.0 1.4", "CIS AWS v3.0.0 1.5", "CIS AWS v3.0.0 1.6", "CIS AWS v5.0.0 1.2", "CIS AWS v5.0.0 1.3", "CIS AWS v5.0.0 1.4", "CIS AWS v5.0.0 1.5", T1078.004, T1078.001, T1199, T1666, T1484, T1484.002, T1098.003, T1136.003, T1580, T1087.004, T1535]
tags: [aws, organizations, scp, rcp, identity-center, multi-account]
---

This note is part of our [AWS security testing guide](/cloud/aws-security-testing-guide/) and covers the layer above individual accounts: AWS Organizations, the management account, organisational units, the policy types that constrain every member account (service control policies, resource control policies and declarative policies), data perimeters, delegated administrators, centralised root access management, IAM Identity Center, AWS Control Tower, account vending, break-glass access, account contacts and cost signals. Most AWS estates of any size are multi-account, and the organisation is where a single mistake has the widest blast radius: whoever controls the management account controls every account in it, and a guardrail that is missing at the root is missing everywhere. It is also where reviews most often stop at "SCPs exist". The useful questions are sharper: which principals can reach the management account, which roles in member accounts trust it, which member accounts have been given organisation-wide powers as delegated administrators, what the effective guardrails are for a given account (AWS does not compute that for SCPs; you have to), and which gaps the guardrails cannot cover by design. Individual IAM evaluation is in [IAM fundamentals and policy evaluation](/cloud/aws-iam-fundamentals-policy-evaluation/), cross-account roles in [STS, cross-account trust and federation](/cloud/aws-sts-cross-account-trust-federation/), and the security services administered at organisation level in [Detection and posture services](/cloud/aws-detection-posture-services/).

## Contents

- [How it works](#how-it-works)
  - [Organisation structure](#organisation-structure)
  - [The management account](#the-management-account)
  - [OrganizationAccountAccessRole and other member-account roles](#organizationaccountaccessrole-and-other-member-account-roles)
  - [OU design](#ou-design)
  - [Service control policies](#service-control-policies)
  - [Resource control policies](#resource-control-policies)
  - [Declarative and management policies](#declarative-and-management-policies)
  - [Data perimeters](#data-perimeters)
  - [Trusted access and delegated administrators](#trusted-access-and-delegated-administrators)
  - [Root users and centralised root access management](#root-users-and-centralised-root-access-management)
  - [IAM Identity Center and the management account](#iam-identity-center-and-the-management-account)
  - [Control Tower, account vending and break-glass](#control-tower-account-vending-and-break-glass)
  - [Account contacts and cost signals](#account-contacts-and-cost-signals)
  - [Defaults and how they changed](#defaults-and-how-they-changed)
- [What goes wrong](#what-goes-wrong)
- [Testing](#testing)
  - [Before you start](#before-you-start)
  - [GT-AWS-ORG-1: Enumerate the organisation and its policy attachments](#gt-aws-org-1-enumerate-the-organisation-and-its-policy-attachments)
  - [GT-AWS-ORG-2: Workloads and access in the management account](#gt-aws-org-2-workloads-and-access-in-the-management-account)
  - [GT-AWS-ORG-3: OrganizationAccountAccessRole trust and who can assume it](#gt-aws-org-3-organizationaccountaccessrole-trust-and-who-can-assume-it)
  - [GT-AWS-ORG-4: SCP guardrail coverage and effect](#gt-aws-org-4-scp-guardrail-coverage-and-effect)
  - [GT-AWS-ORG-5: RCPs and the data perimeter](#gt-aws-org-5-rcps-and-the-data-perimeter)
  - [GT-AWS-ORG-6: Declarative policies and account-level baselines](#gt-aws-org-6-declarative-policies-and-account-level-baselines)
  - [GT-AWS-ORG-7: Delegated administrators and trusted access](#gt-aws-org-7-delegated-administrators-and-trusted-access)
  - [GT-AWS-ORG-8: Root credential status across the organisation](#gt-aws-org-8-root-credential-status-across-the-organisation)
  - [GT-AWS-ORG-9: IAM Identity Center permission sets and management-account assignments](#gt-aws-org-9-iam-identity-center-permission-sets-and-management-account-assignments)
  - [GT-AWS-ORG-10: Contacts, break-glass and cost anomaly signals](#gt-aws-org-10-contacts-break-glass-and-cost-anomaly-signals)
- [Hardening](#hardening)
- [Real-world cases](#real-world-cases)
- [Rating findings](#rating-findings)
- [Mapping](#mapping)
- [References](#references)

## How it works

### Organisation structure

An organisation has one **root**, under which sit **organisational units (OUs)**, nested up to five levels deep, and **accounts**. One account is the **management account** (the API still calls it `Master` in places, for example `MasterAccountId`); every other account is a **member**. Members are either **created** by the organisation (`CreateAccount`) or **invited** (`InviteAccountToOrganization`), and the difference matters for which roles exist in them.

An organisation runs with either **all features** or **consolidated billing** only. Every guardrail in this note (SCPs, RCPs, declarative and other management policies) needs **all features**. Each policy type also has to be **enabled on the root** before it can be attached; `list-roots` shows which are.

AWS Organizations is a global service hosted in **`us-east-1`**. Its CloudTrail events (`CreateAccount`, `AttachPolicy`, `LeaveOrganization` and the rest) are recorded in `us-east-1` of the management account (and in organisation trails), so detections must look there regardless of where the client's workloads run.

### The management account

The management account is special in four ways, and each one is a reason to keep it almost empty:

1. **It is not subject to SCPs or RCPs.** AWS states plainly that SCPs do not affect users or roles in the management account, and RCPs do not affect its resources. Nothing you put at the root constrains it.
2. **It owns the organisation.** Only it can create, invite and remove accounts, enable policy types and trusted access, register delegated administrators, and (unless delegated) write and attach policies. It can also close member accounts.
3. **Member accounts trust it.** Accounts created through Organizations contain `OrganizationAccountAccessRole`, an administrator role that trusts the management account; Control Tower-enrolled accounts contain `AWSControlTowerExecution`; Identity Center's organisation instance lives in the management account and provisions roles into every member it is assigned to; CloudFormation StackSets with service-managed permissions deploy from it into OUs.
4. **It pays the bills.** Billing, Cost Explorer and consolidated invoices live here, so finance teams often have access, and access granted for billing is easily broader than intended.

The consequence: **compromise of the management account is compromise of the organisation.** Any principal there that can assume `OrganizationAccountAccessRole`, create an Identity Center assignment, deploy a service-managed StackSet, or detach an SCP has a path to administrator in every member account. AWS's own guidance is to use the management account only for tasks that require it, keep workloads and resources out of it, restrict and regularly review who has access (including the root user's email, phone and MFA), and delegate service administration to member accounts. ATT&CK frames the attacker side as [T1078.004 Valid Accounts: Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/) plus [T1199 Trusted Relationship](https://attack.mitre.org/techniques/T1199/) for the pivot.

### OrganizationAccountAccessRole and other member-account roles

When the management account creates a member account, Organizations creates an IAM role in it, named **`OrganizationAccountAccessRole`** by default (the name can be changed at creation), with **full administrative permissions**, trusting the **management account**. It is **not** created for **invited** accounts; teams often create an identical one by hand. A typical trust policy (illustrative) trusts the whole management account:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": { "AWS": "arn:aws:iam::111122223333:root" },
      "Action": "sts:AssumeRole"
    }
  ]
}
```

Trusting `arn:aws:iam::111122223333:root` means *any* principal in the management account whose identity policy allows `sts:AssumeRole` on that role ARN can become administrator in the member account; with `AdministratorAccess` or a wildcard `sts:AssumeRole` in the management account, that is a lot of principals. Similar trust exists in `AWSControlTowerExecution` (Control Tower) and in roles created by account-vending pipelines. The [NetSPI research](#real-world-cases) and [Hacking the Cloud](https://hackingthe.cloud/aws/general-knowledge/aws_organizations_defaults/) both describe these roles as the default pivot from a compromised management account; the review question is how many principals can make that pivot, and whether any of them are long-lived keys.

### OU design

AWS's multi-account guidance groups accounts by **the controls they need**, not by the org chart: a Security OU (log archive, security tooling), an Infrastructure OU (networking, shared services), Workloads OUs split into production and non-production, a Sandbox OU, a Suspended OU for accounts being closed, and optionally a Policy Staging OU for testing guardrails and an Exceptions OU. Policies attach to OUs, so the OU tree *is* the control model. Common design faults: everything directly under the root (so every guardrail is all-or-nothing), production and sandbox in the same OU, a "legacy" OU with `FullAWSAccess` only that quietly holds production accounts, and an empty Suspended OU while closed accounts sit elsewhere.

### Service control policies

**What they are.** SCPs set the **maximum** permissions for IAM users and roles in member accounts, **including the member account's root user**. They never grant anything. A request from a member-account principal is allowed only if every level from the root down to the account allows it (via an `Allow` in some attached SCP) and no level denies it, and the identity policy, any permissions boundary and any session policy also allow it. When SCPs are enabled, the AWS managed `FullAWSAccess` policy is attached everywhere; removing it from a level without a replacement `Allow` denies everything below that level.

**Two styles.** A **deny list** keeps `FullAWSAccess` and adds `Deny` statements for specific actions; it is what most estates use, because new services are allowed by default. An **allow list** replaces `FullAWSAccess` with explicit `Allow` statements at each level; stronger, but every new service has to be added, and an allow at the root is not enough if an OU below does not also allow it.

**Limits.** At the time of writing an SCP can be up to **10,240 characters**, with up to **10 SCPs** attached directly to the root, each OU and each account (inherited policies do not count). Size is the usual reason organisations end up with one giant "guardrails" SCP that nobody can review.

**What SCPs do not affect.** This list is the most important part for a reviewer:

- **Anything in the management account.**
- **Service-linked roles.** Actions taken through a service-linked role are not restricted by SCPs.
- **Principals outside the organisation** accessing the organisation's resources through resource-based policies (an S3 bucket policy that grants another account access is not touched by the bucket owner's SCPs). That gap is what RCPs were created to close.
- A short list of root-only tasks (for example registering for the Enterprise support plan as root, CloudFront trusted signer functionality, reverse DNS for Lightsail and EC2 email as root) and a few non-AWS services.

**Common deny-list patterns.** Each of these appears in AWS's SCP examples, and each is a test in GT-AWS-ORG-4:

| Pattern | Mechanism | Why |
|---|---|---|
| Deny leaving the organisation and closing accounts | Deny `organizations:LeaveOrganization`, `account:CloseAccount` | An account that leaves sheds every guardrail ([T1666 Modify Cloud Resource Hierarchy](https://attack.mitre.org/techniques/T1666/)) |
| Region restriction | Deny with `StringNotEquals` on `aws:RequestedRegion`, using `NotAction` to exempt global services | Unused Regions are where miners and persistence go unnoticed ([T1535](https://attack.mitre.org/techniques/T1535/)) |
| Protect security tooling and logging | Deny `cloudtrail:StopLogging`, `guardduty:DeleteDetector`, `config:StopConfigurationRecorder`, `ec2:DeleteFlowLogs` and similar, except for a security role | Stops a member-account administrator blinding the account ([T1685](https://attack.mitre.org/techniques/T1685/), [T1685.002](https://attack.mitre.org/techniques/T1685/002/)) |
| Protect platform roles | Deny `iam:*` changes on `OrganizationAccountAccessRole`, `AWSControlTowerExecution`, the security audit role, except for the platform pipeline | Stops tampering with the roles the organisation relies on, or with their trust policies |
| Deny root user actions | Deny `*` where `aws:PrincipalArn` is like `arn:aws:iam::*:root` | Member root credentials should never be used (and, ideally, should not exist) |
| Require IMDSv2 | Deny `ec2:RunInstances` unless `ec2:MetadataHttpTokens` is `required`; deny any action with `ec2:RoleDelivery` below `2.0`; restrict `ec2:ModifyInstanceMetadataOptions` | Removes the IMDSv1 SSRF path to instance credentials (see [EC2 and IMDS](/cloud/aws-ec2-imds-ebs-ssm-security/)) |
| Deny long-term credentials | Deny `iam:CreateUser`, `iam:CreateAccessKey` except in named accounts | Leaked access keys remain the commonest initial access |

**Testing SCPs.** The IAM policy simulator (`simulate-principal-policy`) **does** evaluate SCPs, including condition keys and resource scoping in deny statements, and returns whether Organizations allowed the action, without performing it. It does not show which SCP statement matched, and it does **not** evaluate RCPs. `describe-effective-policy` works only for management policy types (tag, backup, declarative and so on), **not** for SCPs or RCPs: you compute the effective SCP set yourself by walking from the account up to the root.

### Resource control policies

**Resource control policies (RCPs)**, launched in **November 2024**, are the resource-side counterpart: they set the maximum permissions **on resources** in member accounts, whoever the caller is, including principals from outside the organisation and root users. They are written like resource policies (`Principal` must be `"*"`), the default `RCPFullAWSAccess` is attached everywhere when the type is enabled and cannot be detached, and you add `Deny` statements. Their typical job is the **identity perimeter**: "only principals from my organisation (and named partners, and AWS services acting for me) may access my S3 buckets, KMS keys, STS roles, SQS queues and secrets", which a member account cannot override with a permissive bucket policy.

RCPs apply only to **supported services**. The initial list was S3, STS, KMS, SQS and Secrets Manager; it has since grown to dozens, including Cognito, DynamoDB, ECR, CloudWatch Logs, OpenSearch Serverless, EventBridge, SNS, Security Lake and others. Check the [current list](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_rcps.html#rcp-supported-services) against the services the client uses; an RCP that names `s3:*` does nothing for a Lambda function URL or an API Gateway resource policy. RCPs do **not** apply to resources in the management account, to calls by service-linked roles, to AWS managed KMS keys, or to `kms:RetireGrant`. Limits: **5,120 characters** per RCP and **5** attached per target (the mandatory `RCPFullAWSAccess` counts towards the five).

### Declarative and management policies

**Declarative policies** (introduced in **December 2024**, starting with EC2) are a different kind of control. Instead of filtering API calls, they **set a service attribute** for every account in scope and keep it set: the service's control plane enforces the declared configuration, account administrators cannot change it, it applies to service-linked roles too, and it persists when the service adds new APIs. Detaching the policy rolls the attribute back to its previous state. The EC2 declarative policy type (`DECLARATIVE_POLICY_EC2`) supports, at the time of writing:

| Attribute | Example value | Effect |
|---|---|---|
| `instance_metadata_defaults` | `http_tokens: required`, `http_tokens_enforced: enabled` | IMDSv2 by default for new launches, and refusal of IMDSv1 launches or changes |
| `snapshot_block_public_access` | `block_all_sharing` | EBS snapshots cannot be public (and existing public ones become private) |
| `image_block_public_access` | `block_new_sharing` | AMIs cannot be newly shared publicly |
| `vpc_block_public_access` | `block_ingress` or `block_bidirectional` | Internet gateway traffic blocked except for allowed exclusions |
| `serial_console_access` | `disabled` | EC2 serial console unavailable |
| `allowed_images_settings` | `enabled` or `audit_mode` with criteria | Only AMIs from approved providers or names can be discovered and used |
| `vpc_encryption_control`, `networking_flex_cost_allocation` | | Newer attributes; check availability |

Declarative policies support a custom `exception_message` (so a blocked user sees "see wiki page X"), and an **account status report** (`start-declarative-policies-report`) shows the current state of every attribute across accounts in scope. They are the right tool for "this setting must be on everywhere": an SCP can deny `ec2:DisableSnapshotBlockPublicAccess`, but only a declarative policy turns it on in accounts that never enabled it.

Organizations now has many other **management policy** types in the same family: tag, backup, AI services opt-out, chat applications, and policies that centrally enable or configure security services (`SECURITYHUB_POLICY`, `GUARDDUTY_POLICY`, `INSPECTOR_POLICY` and others). Their effective content per account is available with `describe-effective-policy`. They matter here because they decide whether new accounts get detection automatically (see the [detection note](/cloud/aws-detection-posture-services/)).

### Data perimeters

A **data perimeter** is AWS's term for a set of coarse, organisation-wide guardrails that ensure only **trusted identities** access **trusted resources** from **expected networks**. The three policy types divide the work:

| Perimeter goal | Typical control | Condition keys |
|---|---|---|
| Only my organisation's identities (plus named partners and AWS services) can access my resources | **RCP** (or resource policies) | `aws:PrincipalOrgID`, `aws:PrincipalAccount`, `aws:PrincipalIsAWSService` |
| My identities can only access resources that belong to my organisation | **SCP** | `aws:ResourceOrgID`, `aws:ResourceAccount` |
| My resources can only be reached from my networks | RCP, SCP or VPC endpoint policies | `aws:SourceVpce`, `aws:VpceOrgID`, `aws:SourceVpc`, `aws:SourceIp`, `aws:ViaAWSService` |
| AWS services acting on my behalf cannot be used as a confused deputy by another account | RCP or resource policies | `aws:SourceOrgID`, `aws:SourceAccount`, `aws:SourceArn` |

The resource perimeter (SCP with `aws:ResourceOrgID`) needs careful exceptions, because workloads legitimately read AWS-owned resources (for example buckets that host package repositories or SSM agent updates) and third-party resources. AWS publishes maintained examples in [data-perimeter-policy-examples](https://github.com/aws-samples/data-perimeter-policy-examples); use those as the reference, not hand-rolled policies.

### Trusted access and delegated administrators

**Trusted access** lets an AWS service operate across the organisation (creating service-linked roles in member accounts, reading the account list). A **delegated administrator** is a member account that the management account registers for a specific service, giving it organisation-wide powers for that service. Delegation is the right way to keep work out of the management account, but each delegation creates an account whose compromise has organisation-wide effect for that service. SCPs **do** apply to delegated administrator accounts, which is one reason delegation beats doing the work from the management account.

| Delegated service (principal) | What a compromised delegated administrator can do |
|---|---|
| IAM, for centralised root access (`iam.amazonaws.com`) | Delete or allow recovery of root credentials in any member account; open privileged root sessions to unlock S3 bucket and SQS queue policies |
| IAM Identity Center (`sso.amazonaws.com`) | Create permission sets and assign them to users in any member account, except permission sets provisioned to the management account |
| CloudFormation StackSets (service-managed) | Deploy stacks, including IAM roles, into every account in target OUs: effectively administrator across them |
| Organizations policy management (resource-based delegation policy) | Whatever the delegation policy grants: potentially create, update, attach and detach SCPs and RCPs |
| Security services (GuardDuty, Security Hub, Config, Inspector, Macie, Detective, Access Analyzer) | Disable members, add suppression rules and trusted lists, archive findings; enumerate the organisation's external trust |
| Account Management (`account.amazonaws.com`) | Change member accounts' alternate contacts and Region opt-in |
| Backup, Firewall Manager, Systems Manager and others | Service-specific, often including deployment of configuration into member accounts |

The [NetSPI research](#real-world-cases) shows concrete pivots: a delegated Access Analyzer administrator enumerating an organisation and finding roles that trust any principal; a management account creating Identity Center users and assigning administrator permission sets to member accounts. The [Datadog case](#real-world-cases) shows the inverse: an attacker in the management account switching trusted access *off* for several services.

### Root users and centralised root access management

Every AWS account has a root user. Historically each member account's root user had a password that could be recovered by whoever controlled the account's email address, and organisations either set MFA on hundreds of root users or relied on SCPs that deny root actions.

**Centralised root access management** (launched **November 2024**) changes that for **member accounts**:

- **Root credentials management** (`RootCredentialsManagement`) lets the management account or an IAM delegated administrator **delete** member root credentials (password, access keys, signing certificates, MFA devices) and, when needed, **allow password recovery** again. New accounts created in the organisation then have **no root credentials** by default.
- **Privileged root actions** (`RootSessions`) let the same accounts call **`sts:AssumeRoot`** against a member account with a **task policy** that scopes the session: `IAMAuditRootUserCredentials`, `IAMCreateRootUserPassword`, `IAMDeleteRootUserCredentials`, `S3UnlockBucketPolicy` or `SQSUnlockQueuePolicy`. Sessions are short-lived (the documented example uses 900 seconds), must be requested from a **Regional** STS endpoint, cannot be requested with root credentials, and can be constrained with the `sts:TaskPolicyArn` condition key. Their use shows up in GuardDuty as `Policy:IAMUser/ShortTermRootCredentialUsage`.

Enabling it requires trusted access for IAM in Organizations and all features. It does **not** cover the **management account's own root user**: that one still needs a strong, managed password, hardware or passkey MFA, no access keys, and monitoring (Security Hub CSPM IAM.4, IAM.6, IAM.9). Because a privileged root session acts as the member account's root user, check that any deny-root SCP the client has does not also block the centralised tasks they rely on, and add a narrow exception if it does.

### IAM Identity Center and the management account

IAM Identity Center's **organisation instance** is created in the **management account** and stays there; administration can be delegated to a member account. Identity Center provisions **permission sets** as IAM roles (named `AWSReservedSSO_<PermissionSetName>_<suffix>`) into every account where an assignment exists, and users from the identity source (Identity Center directory, Active Directory, or an external IdP via SAML and SCIM) assume them through the access portal. Four review points follow from that design:

- **The delegated administrator cannot alter permission sets provisioned to the management account**, and AWS recommends **dedicated permission sets** for the management account, assigned to **users directly, not groups**: anyone who can change group membership in the IdP can otherwise grant themselves management-account access.
- **The IdP is part of the trust boundary.** If Okta or Entra ID groups drive assignments, the IdP administrators effectively hold AWS access (see [STS and federation](/cloud/aws-sts-cross-account-trust-federation/)). SCIM bearer tokens (`sso-directory:CreateBearerToken`) let a holder create users and group memberships; AWS suggests an SCP to stop the delegated administrator creating them outside planned rotations.
- **Permission sets are policies like any other.** Inline policies granting `iam:*`, `sso:*` or `identitystore:*` in the Identity Center delegated administrator account let a user escalate by editing their own permission set or group. Session duration (default one hour, up to 12) is part of the risk.
- **Account instances** of Identity Center (standalone, per account) can exist alongside the organisation instance. They are for applications, but are worth noting.

### Control Tower, account vending and break-glass

**AWS Control Tower** builds a **landing zone** on top of Organizations: a Security OU with log archive and audit accounts, an organisation CloudTrail trail, Config, Identity Center, and **controls** (formerly *guardrails*) applied per OU. Controls are **preventive** (implemented as SCPs, RCPs or declarative policies), **detective** (Config rules) or **proactive** (CloudFormation hooks that check resources before deployment), with guidance levels **mandatory**, **strongly recommended** and **elective**. Control Tower's own documentation is explicit that the management account is exempt from controls. Enrolled accounts contain the `AWSControlTowerExecution` role, trusted by the management account.

**Account vending** (Control Tower Account Factory, Account Factory for Terraform, or a custom pipeline) is where baselines should be applied: correct OU, security services enrolled, centralised logging, root credentials deleted, contacts set, no IAM users. A review of the vending pipeline (its role, who can trigger it, what it deploys) is part of the [CI/CD note](/cloud/aws-cicd-iac-security/); here we check its output.

**Break-glass** access is the planned way in when Identity Center or the IdP fails: typically one or two IAM users or a role in the management account (or a dedicated account) with hardware MFA, sealed credentials, documented procedure, and an alarm on every use. Break-glass that is undocumented, untested, unmonitored or used routinely is a finding; break-glass that does not exist is also a finding (an IdP outage becomes an AWS outage, and people improvise).

### Account contacts and cost signals

Each account has **alternate contacts** for **billing**, **operations** and **security** (`aws account get-alternate-contact`). AWS sends security notifications (abuse reports, exposed credential notices) to the security contact; if it is empty or points to a departed employee, those notices are lost. With trusted access for AWS Account Management, the management account or a delegated administrator can set contacts for every member. Security Hub CSPM **Account.1** checks the security contact (CIS v3.0.0 and v5.0.0 recommendation **1.2**).

**Cost is a security signal.** Cryptomining, model abuse and resource hijacking ([T1496.004](https://attack.mitre.org/techniques/T1496/004/)) show up on the bill before they show up anywhere else if detection is weak. AWS Cost Anomaly Detection monitors and subscriptions (and budgets) that alert a technical owner, not only finance, are a cheap compensating detection.

### Defaults and how they changed

| When | Change | Effect on a review |
|---|---|---|
| November 2024 | Resource control policies | Identity and network perimeters on resources became enforceable centrally |
| November 2024 | Centralised root access management | Member root credentials can be deleted; new accounts can be created without them |
| December 2024 | Declarative policies (EC2 first) | Account-level settings such as IMDS defaults and snapshot public access can be enforced organisation-wide |
| At the time of writing | SCP size raised to 10,240 characters and 10 per target | Older advice ("5,120 characters, 5 SCPs") is out of date |
| July 2026 | Organisations created in the **console** after 10 July 2026 automatically get an SCP at the root denying `organizations:LeaveOrganization` and `account:CloseAccount` | Not applied to existing organisations or to organisations created via CLI, SDK or CloudFormation: check, do not assume |

## What goes wrong

**Workloads and people in the management account.** Production applications, CI/CD runners, data, IAM users with access keys, or broad Identity Center access in the account that SCPs cannot constrain. Why: any compromise there is organisation-wide, and the guardrails the client relies on do not apply.

**Over-broad trust into member accounts.** `OrganizationAccountAccessRole` (or hand-made equivalents in invited accounts) trusting the whole management account, combined with many management-account principals able to call `sts:AssumeRole` on `*`. Why: a single compromised management-account identity is administrator everywhere ([T1199](https://attack.mitre.org/techniques/T1199/)).

**Guardrails that are not where people think.** SCPs attached to some OUs but not others; production accounts left directly under the root; allow-list SCPs with a gap at one level; `FullAWSAccess` only on the OU that holds the payments accounts. Why: the effective policy is the intersection along the path, and nobody computed it.

**Missing basic denies.** No deny on `LeaveOrganization`, no Region restriction, no protection for logging and security tooling, no protection for platform roles. Why: a member-account administrator (or an attacker who escalates to one) can leave, blind or reconfigure the account.

**Region restrictions with holes.** `NotAction` lists copied years ago that exempt `ec2:*` or `iam:*` wholesale, or conditions on `aws:RequestedRegion` that miss new Regions. Why: an exemption meant for global services becomes a bypass for Regional ones.

**Over-broad SCP exceptions.** `ArnNotLike aws:PrincipalArn arn:aws:iam::*:role/*Admin*`. Why: any role that an account administrator can create with a matching name bypasses the guardrail.

**No resource-side perimeter.** No RCPs, and resource policies that grant `"Principal": "*"` with weak conditions, or grant partner accounts broadly. Why: SCPs cannot stop an outside principal using a permissive bucket or key policy ([T1530](https://attack.mitre.org/techniques/T1530/), [T1537](https://attack.mitre.org/techniques/T1537/)).

**Settings that are denied but never turned on.** An SCP denies `ec2:DisableSnapshotBlockPublicAccess`, but most accounts never enabled it in the first place. Why: preventing change is not the same as enforcing state; that is the gap declarative policies close.

**Delegated administrators everywhere, or nowhere.** Every service delegated to a general-purpose "shared services" account full of workloads; or nothing delegated, so security teams work from the management account. Why: either creates an account whose compromise is organisation-wide.

**Root credentials still present.** Member accounts with root passwords recoverable by whoever controls a shared mailbox; root access keys; management-account root with virtual MFA on a personal phone. Why: root bypasses everything except SCPs, and the management account's root is bypassed by nothing.

**Identity Center misassignments.** `AdministratorAccess` assigned to a large IdP group across all accounts including the management account; group-based assignments to management-account permission sets; delegated Identity Center administrators who can edit their own permission sets. Why: the IdP becomes the real control plane for AWS ([T1098.003](https://attack.mitre.org/techniques/T1098/003/), [T1484.002](https://attack.mitre.org/techniques/T1484/002/)).

**No break-glass, or uncontrolled break-glass.**

**Security contact empty; cost alerts go only to finance.**

## Testing

### Before you start

**Authorisation.** All tests assume an authorised engagement against the client's own organisation, with written scope that explicitly includes the management account (most of this note is pointless without read access there), and that you follow the [AWS penetration testing policy](https://aws.amazon.com/security/penetration-testing/). The tests are **read-only** unless a step is marked **lab or explicitly approved only**. Command outputs shown are **illustrative**; we ran nothing against AWS to produce them.

**Access.** Ask for:

- A read-only role in the **management account** with `SecurityAudit` (which includes `organizations:Describe*` and `organizations:List*`, `sso` and `identitystore` reads, `account:GetAlternateContact` and IAM reads). Add `ce:GetAnomalyMonitors`, `ce:GetAnomalySubscriptions` and `budgets:ViewBudget` for GT-AWS-ORG-10.
- The same in the **delegated administrator** accounts (security tooling, Identity Center if delegated, IAM root access if delegated).
- A read-only role in a sample of **member accounts**, ideally one per OU.

**Organisation calls go to `us-east-1`.** The CLI handles this for `organizations`, but set `--region us-east-1` explicitly in scripts.

```bash
export AWS_PROFILE=client-mgmt-audit
export AWS_REGION=us-east-1
aws sts get-caller-identity
aws organizations describe-organization \
  --query 'Organization.[Id,FeatureSet,MasterAccountId]' --output text
```

**Tools.** [Prowler](https://github.com/prowler-cloud/prowler) (`prowler aws --services organizations account iam`), [Pacu](https://github.com/RhinoSecurityLabs/pacu) module `organizations__enum` for a quick structural dump, [PMapper](https://github.com/nccgroup/PMapper) for "who can assume what" inside the management account, [CloudFox](https://github.com/BishopFox/cloudfox) for role trust inventories in member accounts, and `jq`. For practice, AWS's [SCP](https://github.com/aws-samples/service-control-policy-examples), [RCP](https://github.com/aws-samples/resource-control-policy-examples) and [data perimeter](https://github.com/aws-samples/data-perimeter-policy-examples) example repositories are the reference designs to compare against.

### GT-AWS-ORG-1: Enumerate the organisation and its policy attachments

*Guler Tech methodology.*

#### What it checks

The structure of the organisation (OUs and accounts), the policy types enabled, and which SCPs, RCPs and declarative policies attach to which targets, so that every later test can compute effective guardrails per account.

#### Prerequisites

Management account read-only access (or a delegated administrator for Organizations policy management).

#### Steps

1. Organisation and enabled policy types:

   ```bash
   aws organizations describe-organization --region us-east-1
   aws organizations list-roots --region us-east-1 \
     --query 'Roots[].[Id,PolicyTypes[].[Type,Status]]' --output json
   ```

2. Walk the tree, printing each OU and account with the SCPs and RCPs attached directly to it:

   ```bash
   pols() {
     for t in SERVICE_CONTROL_POLICY RESOURCE_CONTROL_POLICY DECLARATIVE_POLICY_EC2; do
       aws organizations list-policies-for-target --region us-east-1 --target-id "$1" --filter "$t" \
         --query 'Policies[].Name' --output text 2>/dev/null | sed "s/^/[$t] /"
     done | tr '\n' ' '
   }
   walk() {
     local parent="$1" indent="$2"
     for a in $(aws organizations list-accounts-for-parent --region us-east-1 --parent-id "$parent" --query 'Accounts[].Id' --output text); do
       name=$(aws organizations describe-account --region us-east-1 --account-id "$a" --query 'Account.Name' --output text)
       echo "${indent}ACCOUNT $a $name :: $(pols "$a")"
     done
     for ou in $(aws organizations list-organizational-units-for-parent --region us-east-1 --parent-id "$parent" --query 'OrganizationalUnits[].Id' --output text); do
       name=$(aws organizations describe-organizational-unit --region us-east-1 --organizational-unit-id "$ou" --query 'OrganizationalUnit.Name' --output text)
       echo "${indent}OU $ou $name :: $(pols "$ou")"
       walk "$ou" "$indent  "
     done
   }
   ROOT=$(aws organizations list-roots --region us-east-1 --query 'Roots[0].Id' --output text)
   echo "ROOT $ROOT :: $(pols "$ROOT")"
   walk "$ROOT" "  " | tee org-tree.txt
   ```

3. Save every policy document for offline review:

   ```bash
   mkdir -p policies
   for t in SERVICE_CONTROL_POLICY RESOURCE_CONTROL_POLICY DECLARATIVE_POLICY_EC2; do
     for p in $(aws organizations list-policies --region us-east-1 --filter "$t" --query 'Policies[].Id' --output text); do
       aws organizations describe-policy --region us-east-1 --policy-id "$p" \
         --query 'Policy.Content' --output text | jq . > "policies/$t-$p.json"
       aws organizations list-targets-for-policy --region us-east-1 --policy-id "$p" \
         --query 'Targets[].[Type,TargetId,Name]' --output text | sed "s/^/$p /" >> policies/targets.txt
     done
   done
   ```

4. For any account of interest, compute the effective SCP chain (there is no API for this):

   ```bash
   chain() {
     local id="$1"
     while :; do
       echo "== $id"; pols "$id"; echo
       p=$(aws organizations list-parents --region us-east-1 --child-id "$id" --query 'Parents[0].Id' --output text)
       [ -z "$p" ] || [ "$p" = "None" ] && break
       id="$p"
       case "$id" in r-*) echo "== $id"; pols "$id"; echo; break;; esac
     done
   }
   chain 444455556666
   ```

5. Optionally, Pacu's `organizations__enum` gives the same structure in one step; Prowler's organizations checks give a quick pass/fail baseline.

#### Observation

Illustrative:

```text
ROOT r-ab12 :: [SERVICE_CONTROL_POLICY] FullAWSAccess deny-leave-org
  ACCOUNT 111122223333 org-management ::
  OU ou-ab12-11111111 Security :: [SERVICE_CONTROL_POLICY] FullAWSAccess
  OU ou-ab12-22222222 Workloads :: [SERVICE_CONTROL_POLICY] FullAWSAccess guardrails-v3
    OU ou-ab12-33333333 Prod :: [SERVICE_CONTROL_POLICY] FullAWSAccess
      ACCOUNT 444455556666 payments-prod :: [SERVICE_CONTROL_POLICY] FullAWSAccess
  ACCOUNT 123456789012 legacy-data :: [SERVICE_CONTROL_POLICY] FullAWSAccess
```

Here the `legacy-data` account sits directly under the root and gets only `deny-leave-org`; it misses `guardrails-v3`.

#### Evaluation

This test is mostly inventory, but it produces findings in its own right. **Pass:** all features enabled; SCP (and, where used, RCP and declarative) policy types enabled on the root; every account in an OU whose path carries the baseline guardrails; no accounts other than the management account directly under the root without a reason. **Fail:** consolidated-billing-only organisation; SCPs not enabled; accounts (especially production or data accounts) outside the OUs that carry guardrails; policies attached but empty or `FullAWSAccess` only on sensitive OUs.

#### Automated coverage

Security Hub CSPM **Account.2** (account is part of an organisation). Prowler `organizations_account_part_of_organizations`.

#### Detection

Enumeration of this kind is normal for administrators but unusual for workload roles: `ListAccounts`, `ListRoots`, `ListPoliciesForTarget`, `DescribePolicy`, `ListOrganizationalUnitsForParent` bursts from a member account or an unfamiliar principal. GuardDuty may raise `Discovery:IAMUser/AnomalousBehavior`. ATT&CK [T1580](https://attack.mitre.org/techniques/T1580/), [T1087.004](https://attack.mitre.org/techniques/T1087/004/).

### GT-AWS-ORG-2: Workloads and access in the management account

*Guler Tech methodology.*

#### What it checks

That the management account contains only what must be there (organisation management, billing, Identity Center, possibly the organisation trail or Control Tower), and that the set of people and principals who can act in it is small, known and strongly authenticated.

#### Prerequisites

Read-only access to the management account.

#### Steps

1. Resource sweep per Region (illustrative selection; Prowler or a Config query covers more):

   ```bash
   for r in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text); do
     n_ec2=$(aws ec2 describe-instances --region "$r" --query 'length(Reservations[].Instances[])' --output text)
     n_fn=$(aws lambda list-functions --region "$r" --query 'length(Functions)' --output text)
     n_db=$(aws rds describe-db-instances --region "$r" --query 'length(DBInstances)' --output text)
     n_stk=$(aws cloudformation list-stacks --region "$r" --stack-status-filter CREATE_COMPLETE UPDATE_COMPLETE --query 'length(StackSummaries)' --output text)
     echo "$r ec2=$n_ec2 lambda=$n_fn rds=$n_db stacks=$n_stk"
   done
   aws s3api list-buckets --query 'Buckets[].Name' --output text | tr '\t' '\n'
   ```

2. IAM users and long-term keys (the [Datadog case](#real-world-cases) started with exactly this):

   ```bash
   aws iam generate-credential-report >/dev/null; sleep 5
   aws iam get-credential-report --query 'Content' --output text | base64 -d \
     | awk -F, 'NR==1 || $9=="true" || $14=="true" {print $1","$4","$8","$9","$11","$14}'
   ```

   (`generate-credential-report` creates a report object in IAM; it is routinely accepted as read-only, but mention it in your plan.)

3. Who has administrative or organisation-level permissions: roles and users with `AdministratorAccess`, `organizations:*`, `sts:AssumeRole` on `*`, or `iam:PassRole` broadly.

   ```bash
   aws iam get-account-authorization-details --output json > mgmt-auth.json
   jq -r '.RoleDetailList[] | select(.AttachedManagedPolicies[]?.PolicyName=="AdministratorAccess") | .Arn' mgmt-auth.json
   jq -r '.UserDetailList[] | select(.AttachedManagedPolicies[]?.PolicyName=="AdministratorAccess") | .Arn' mgmt-auth.json
   ```

4. Who arrives through Identity Center (details in GT-AWS-ORG-9) and through roles trusted by third parties: list roles whose trust policy names a principal outside the organisation.

   ```bash
   jq -r '.RoleDetailList[] | [.Arn, (.AssumeRolePolicyDocument.Statement[].Principal | tostring)] | @tsv' mgmt-auth.json \
     | grep -v 'amazonaws.com' | grep -v ':111122223333:'
   ```

5. Is any security service administered from here rather than delegated? (See GT-AWS-ORG-7.)

#### Observation

Illustrative:

```text
eu-west-2 ec2=3 lambda=12 rds=1 stacks=27
user,password_enabled,password_last_used,access_key_1_active,access_key_1_last_used_date,access_key_2_active
ci-deployer,false,N/A,true,2026-11-01T09:12:00+00:00,false
arn:aws:iam::111122223333:role/vendor-billing-tool   {"AWS":"arn:aws:iam::<third-party-account-id>:root"}
```

#### Evaluation

**Pass:** no application workloads, data stores or CI/CD in the management account; no IAM users with active access keys (break-glass users, if any, have console access with hardware MFA only); a small, named set of administrators reaching the account through dedicated Identity Center permission sets or break-glass; third-party trust limited to vetted billing or governance tools with `sts:ExternalId` and least privilege. **Fail:** workloads, data or pipelines present; IAM users with active keys; administrator access through large groups; third-party roles with administrative or organisation permissions. Rate by what the identity can reach: anything that can reach the management account can reach the organisation.

#### Automated coverage

No Security Hub CSPM control targets the management account specifically; IAM.4 (root access key) applies here too. Prowler `iam_user_accesskey_unused`, `iam_role_administratoraccess_policy` (run against the management account).

#### Detection

In the management account, any `CreateAccessKey`, `CreateUser`, `CreateLoginProfile`, `AttachUserPolicy`, `AttachRolePolicy`, `UpdateAssumeRolePolicy`; `ConsoleLogin` from unexpected networks; use of long-term keys at all. GuardDuty `CredentialAccess:IAMUser/CompromisedCredentials`, `Persistence:IAMUser/AnomalousBehavior`. These deserve a higher severity in the management account than anywhere else.

### GT-AWS-ORG-3: OrganizationAccountAccessRole trust and who can assume it

*Guler Tech methodology.*

#### What it checks

Which member accounts contain `OrganizationAccountAccessRole` (or `AWSControlTowerExecution`, or vending-pipeline equivalents), what they trust, what they can do, and which principals in the management account can assume them.

#### Prerequisites

Read access in member accounts (or a role that can read IAM across them) and in the management account.

#### Steps

1. In each member account, the role, its trust and its permissions:

   ```bash
   for role in OrganizationAccountAccessRole AWSControlTowerExecution; do
     aws iam get-role --role-name "$role" \
       --query '[Role.Arn,Role.AssumeRolePolicyDocument]' --output json 2>/dev/null
     aws iam list-attached-role-policies --role-name "$role" \
       --query 'AttachedPolicies[].PolicyName' --output text 2>/dev/null
   done
   ```

   Run per account with a profile per account, or use CloudFox (`cloudfox aws --profile <member-profile> role-trusts`) per account for a wider trust inventory.

2. In the management account, which principals can call `sts:AssumeRole` on those roles. PMapper builds the graph and answers the question directly:

   ```bash
   pmapper --profile client-mgmt-audit graph create
   pmapper --profile client-mgmt-audit query \
     'who can do sts:AssumeRole with arn:aws:iam::444455556666:role/OrganizationAccountAccessRole'
   ```

   Cross-check specific principals with the simulator:

   ```bash
   aws iam simulate-principal-policy \
     --policy-source-arn arn:aws:iam::111122223333:role/FinanceAnalyst \
     --action-names sts:AssumeRole \
     --resource-arns arn:aws:iam::444455556666:role/OrganizationAccountAccessRole \
     --query 'EvaluationResults[].[EvalActionName,EvalDecision]' --output text
   ```

3. Check whether the member-account roles are protected by SCP from modification (search the policy dump from GT-AWS-ORG-1 for the role name).
4. **Lab or explicitly approved only:** from one approved management-account principal, assume the role in one approved member account and prove access benignly.

   ```bash
   aws sts assume-role --role-arn arn:aws:iam::444455556666:role/OrganizationAccountAccessRole \
     --role-session-name gt-approved-proof --query 'Credentials.Expiration'
   # with the returned credentials exported:
   aws sts get-caller-identity
   ```

#### Observation

The list of accounts with each role, their trust principals and attached policies; the PMapper result listing management-account principals able to assume; the simulator decision for named principals.

#### Evaluation

**Pass:** the role either does not exist outside the vending process, or trusts a specific management-account role (not `:root`) that only a small break-glass or platform group can assume, ideally with an MFA condition; few management-account principals can assume it; an SCP prevents member-account administrators from changing it. **Fail:** trust to the management account root combined with many management-account principals holding `sts:AssumeRole` on `*` or `AdministratorAccess`; long-term keys among those principals; hand-made copies in invited accounts trusting broader principals; no protection against modification. Raise severity when the principals that can assume include CI/CD, third-party tools or IAM users with keys.

#### Automated coverage

None directly. Prowler `iam_role_administratoraccess_policy` flags the role's `AdministratorAccess`; `iam_no_custom_policy_permissive_role_assumption` flags wildcard `sts:AssumeRole` grants in the management account.

#### Detection

In member accounts, `AssumeRole` events where `requestParameters.roleArn` ends in `/OrganizationAccountAccessRole` or `/AWSControlTowerExecution`, with the source identity from the management account; alert on any use outside approved automation. `UpdateAssumeRolePolicy`, `AttachRolePolicy`, `PutRolePolicy` on these roles. ATT&CK [T1199](https://attack.mitre.org/techniques/T1199/), [T1078.004](https://attack.mitre.org/techniques/T1078/004/).

### GT-AWS-ORG-4: SCP guardrail coverage and effect

*Guler Tech methodology.*

#### What it checks

That the effective SCPs for each sensitive account include the expected deny-list guardrails (leave organisation, Region restriction, protection of logging and security tooling, protection of platform roles, root denial, IMDSv2), that their conditions and exceptions are sound, and that they actually deny the actions for an ordinary member-account administrator.

#### Prerequisites

The policy dump and chains from GT-AWS-ORG-1; a typical administrator role in each sample member account to simulate against.

#### Steps

1. Review each SCP in the chain for each pattern in the [SCP section](#service-control-policies): presence, scope (`Resource`, `Condition`), and exceptions. Flag `NotAction` statements, exception conditions on `aws:PrincipalArn` with wildcards, and `StringNotEquals` on `aws:RequestedRegion` without the client's newer Regions.
2. Prove each guardrail with the simulator (it evaluates SCPs and their condition keys; it does not perform any action):

   ```bash
   ROLE=arn:aws:iam::444455556666:role/WorkloadAdmin
   aws iam simulate-principal-policy --policy-source-arn "$ROLE" \
     --action-names organizations:LeaveOrganization account:CloseAccount \
       cloudtrail:StopLogging cloudtrail:DeleteTrail guardduty:DeleteDetector \
       config:StopConfigurationRecorder ec2:DeleteFlowLogs iam:CreateUser iam:CreateAccessKey \
     --query 'EvaluationResults[].[EvalActionName,EvalDecision,OrganizationsDecisionDetail.AllowedByOrganizations]' \
     --output text

   # Region restriction: supply the Region as context
   aws iam simulate-principal-policy --policy-source-arn "$ROLE" \
     --action-names ec2:RunInstances \
     --context-entries ContextKeyName=aws:RequestedRegion,ContextKeyValues=ap-southeast-3,ContextKeyType=string \
     --query 'EvaluationResults[].[EvalActionName,EvalDecision,OrganizationsDecisionDetail.AllowedByOrganizations]' \
     --output text

   # IMDSv2: an instance launch with tokens optional should be denied
   aws iam simulate-principal-policy --policy-source-arn "$ROLE" \
     --action-names ec2:RunInstances \
     --resource-arns 'arn:aws:ec2:eu-west-2:444455556666:instance/*' \
     --context-entries ContextKeyName=ec2:MetadataHttpTokens,ContextKeyValues=optional,ContextKeyType=string \
     --query 'EvaluationResults[].[EvalActionName,EvalDecision,OrganizationsDecisionDetail.AllowedByOrganizations]' \
     --output text
   ```

3. Check that exceptions cannot be self-granted: if an SCP exempts `arn:aws:iam::*:role/SecurityAdmin`, can the member-account administrator create a role with that name? (Simulate `iam:CreateRole` for that role ARN; a good design also denies creating or modifying roles matching the exception pattern.)
4. **Lab or explicitly approved only:** in a sandbox account under the same OU path, attempt one denied action benignly and capture the `AccessDenied` message, which names "service control policy" as the reason (for example `aws ec2 describe-instances --region ap-southeast-3` if Region restriction is in place, or a `LeaveOrganization` attempt via Stratus Red Team's `aws.defense-evasion.organizations-leave`, which expects the call to fail).

#### Observation

Illustrative:

```text
organizations:LeaveOrganization     explicitDeny   False
account:CloseAccount                allowed        True
cloudtrail:StopLogging              explicitDeny   False
guardduty:DeleteDetector            allowed        True
ec2:RunInstances (ap-southeast-3)   allowed        True
ec2:RunInstances (tokens optional)  allowed        True
```

#### Evaluation

**Pass:** for each production and data account, the effective SCPs deny leaving the organisation and closing the account, restrict Regions to the approved list with a narrow global-services exemption, deny impairment of CloudTrail, Config, GuardDuty, Security Hub, flow logs and the other tooling, protect platform roles, deny root user actions (or root credentials are deleted, GT-AWS-ORG-8), require IMDSv2, and every exception names specific roles that member administrators cannot create or assume. **Fail:** any of those missing for production accounts; exceptions with wildcards that member administrators can satisfy; `NotAction` exemptions that include Regional services. Each missing guardrail is reported with the concrete abuse it allows.

#### Automated coverage

No Security Hub CSPM control evaluates SCP content. Prowler `organizations_scp_check_deny_regions` (Region restriction only). EC2.8 checks IMDSv2 on instances, not the SCP.

#### Detection

`AttachPolicy`, `DetachPolicy`, `UpdatePolicy`, `DeletePolicy`, `DisablePolicyType`, `MoveAccount` (moving an account to a less-guarded OU), `EnablePolicyType`; and in member accounts `AccessDenied` errors citing service control policies, which are a useful signal of someone probing guardrails. ATT&CK [T1484](https://attack.mitre.org/techniques/T1484/), [T1666](https://attack.mitre.org/techniques/T1666/).

### GT-AWS-ORG-5: RCPs and the data perimeter

*Guler Tech methodology.*

#### What it checks

Whether RCPs (and, for the resource perimeter, SCPs) enforce an identity and network perimeter on the client's sensitive resource types, which services they cover compared with the services in use, and whether exceptions are narrow.

#### Prerequisites

The policy dump from GT-AWS-ORG-1; an inventory of services in use (Config aggregator or Security Hub resource inventory); VPC endpoint policies from sample accounts.

#### Steps

1. Is the RCP type enabled, and what is attached where?

   ```bash
   aws organizations list-roots --region us-east-1 \
     --query 'Roots[0].PolicyTypes[?Type==`RESOURCE_CONTROL_POLICY`]'
   ls policies/RESOURCE_CONTROL_POLICY-*.json
   ```

2. For each RCP, extract the actions covered and the conditions:

   ```bash
   for f in policies/RESOURCE_CONTROL_POLICY-*.json; do
     jq -r --arg f "$f" '.Statement[] | select(.Effect=="Deny") | [$f, .Sid, (.Action|tostring), (.Condition|keys|tostring)] | @tsv' "$f"
   done
   ```

   Look for `aws:PrincipalOrgID` with `aws:PrincipalIsAWSService` (identity perimeter), `aws:SourceVpce`/`aws:VpceOrgID`/`aws:SourceIp` (network perimeter), `aws:SourceOrgID`/`aws:SourceAccount` (confused deputy), and exceptions keyed on account IDs or tags. Compare the action prefixes with services in use and with the [supported list](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_rcps.html#rcp-supported-services).

3. Resource perimeter in SCPs: search for `aws:ResourceOrgID`.

   ```bash
   grep -l 'aws:ResourceOrgID' policies/SERVICE_CONTROL_POLICY-*.json
   ```

4. Network perimeter on the VPC side, in sample accounts:

   ```bash
   aws ec2 describe-vpc-endpoints --region eu-west-2 \
     --query 'VpcEndpoints[].[VpcEndpointId,ServiceName,PolicyDocument]' --output text
   ```

5. Note that the IAM policy simulator does not evaluate RCPs. Where the client has an internal access analyzer, its findings take RCPs into account; otherwise reason from the policy text.
6. **Lab or explicitly approved only:** from an AWS account that **you** own (never anyone else's), attempt to read a harmless marker object that the client has placed in an approved test bucket with a bucket policy granting your account access. With an identity-perimeter RCP in place the request fails despite the bucket policy:

   ```bash
   aws s3api get-object --bucket example-approved-rcp-test --key marker.txt /dev/stdout --profile tester-own-account
   ```

#### Observation

Illustrative extract:

```text
policies/RESOURCE_CONTROL_POLICY-p-rcp1.json  EnforceOrgIdentities  ["s3:*","sts:AssumeRole","kms:*","sqs:*","secretsmanager:*"]  ["BoolIfExists","StringNotEqualsIfExists"]
```

#### Evaluation

**Pass:** an identity-perimeter RCP covers the supported services that hold the client's sensitive data and trust (at least S3, STS, KMS, Secrets Manager, and any of SQS, DynamoDB, ECR, CloudWatch Logs and others in use), with exceptions limited to named partner accounts and AWS service principals; confused-deputy protections for services that act on the client's resources; where the client's risk model needs it, a network perimeter via endpoint policies or RCP conditions; a resource-perimeter SCP based on AWS's maintained examples. **Fail:** no RCPs and permissive resource policies found elsewhere in the assessment (public or broadly cross-account buckets, keys or roles); RCPs that cover S3 only while secrets and keys are exposed; exceptions such as `aws:PrincipalAccount` lists that include accounts the client cannot identify. Absence of RCPs alone, with clean resource policies, is Low; absence combined with a demonstrated permissive resource policy inherits that finding's severity.

#### Automated coverage

None in Security Hub CSPM. Access Analyzer external access findings (IAM.28) show the resource policies that an RCP would constrain.

#### Detection

`CreatePolicy`, `UpdatePolicy`, `AttachPolicy`, `DetachPolicy` and `DisablePolicyType` with `RESOURCE_CONTROL_POLICY`; in member accounts, `AccessDenied` from external principals on S3, KMS or STS (data events for S3 must be on to see object-level denials). ATT&CK [T1530](https://attack.mitre.org/techniques/T1530/), [T1537](https://attack.mitre.org/techniques/T1537/).

### GT-AWS-ORG-6: Declarative policies and account-level baselines

*Guler Tech methodology.*

#### What it checks

Whether account-level EC2 settings (IMDS defaults, snapshot and AMI public sharing, VPC Block Public Access, serial console, allowed AMIs) are enforced organisation-wide with declarative policies, and what the actual state is in accounts where they are not.

#### Prerequisites

Management account read access; read-only access in sample member accounts.

#### Steps

1. Policy type enabled and policies attached:

   ```bash
   aws organizations list-roots --region us-east-1 \
     --query 'Roots[0].PolicyTypes[?Type==`DECLARATIVE_POLICY_EC2`]'
   aws organizations describe-effective-policy --region us-east-1 \
     --policy-type DECLARATIVE_POLICY_EC2 --target-id 444455556666 \
     --query 'EffectivePolicy.PolicyContent' --output text | jq .
   ```

2. Actual account-level state in a sample of accounts and Regions:

   ```bash
   r=eu-west-2
   aws ec2 get-instance-metadata-defaults --region $r
   aws ec2 get-snapshot-block-public-access-state --region $r
   aws ec2 get-image-block-public-access-state --region $r
   aws ec2 get-serial-console-access-status --region $r
   aws ec2 describe-vpc-block-public-access-options --region $r
   aws ec2 get-allowed-images-settings --region $r
   ```

   Recent API versions indicate when a setting is managed by a declarative policy; check the output fields in your CLI version.

3. Existing account status reports (read-only listing):

   ```bash
   aws ec2 describe-declarative-policies-reports --region us-east-1
   ```

4. **Lab or explicitly approved only:** generating a fresh account status report writes a report object to an S3 bucket you name; agree the bucket with the client first.

   ```bash
   aws ec2 start-declarative-policies-report --region us-east-1 \
     --target-id ou-ab12-22222222 --s3-bucket example-approved-reports-bucket
   ```

#### Observation

Illustrative. An account where nobody set IMDS defaults returns an empty `AccountLevel`; an account governed by a declarative policy shows `ManagedBy`:

```json
{
  "AccountLevel": {}
}
```

```json
{
  "AccountLevel": {
    "HttpTokens": "required",
    "HttpPutResponseHopLimit": 2,
    "HttpTokensEnforced": "enabled",
    "ManagedBy": "declarative-policy",
    "ManagedExceptionMessage": "Blocked by organisation policy. See the platform security baseline page."
  }
}
```

#### Evaluation

**Pass:** a declarative policy (or, at minimum, consistently applied account settings plus SCPs denying their change) enforces IMDSv2 defaults, blocks public snapshot and AMI sharing, and disables the serial console unless needed, across all workload OUs; VPC Block Public Access and allowed AMIs where the client's design supports them. **Fail:** settings left at defaults in production accounts, or SCPs that only deny changing settings that were never turned on. Severity follows the exposure the setting would have prevented (for example a public snapshot found elsewhere in the assessment).

#### Automated coverage

Security Hub CSPM **EC2.8** (instances use IMDSv2; CIS v3.0.0 5.6, v5.0.0 5.7) checks the instance outcome rather than the policy. Prowler `ec2_instance_account_imdsv2_enabled`, `ec2_ebs_snapshot_account_block_public_access`, `ec2_ami_account_block_public_access`.

#### Detection

`CreatePolicy`, `AttachPolicy`, `DetachPolicy` with `DECLARATIVE_POLICY_EC2` (detaching rolls settings back); in accounts without the policy, `ModifyInstanceMetadataDefaults`, `DisableSnapshotBlockPublicAccess`, `DisableImageBlockPublicAccess`, `EnableSerialConsoleAccess`, `ModifyVpcBlockPublicAccessOptions`.

### GT-AWS-ORG-7: Delegated administrators and trusted access

*Guler Tech methodology.*

#### What it checks

Which services have trusted access, which member accounts are delegated administrators for what, whether those accounts are dedicated and protected, and whether Organizations policy management itself has been delegated and to what extent.

#### Prerequisites

Management account read access.

#### Steps

1. Trusted access and delegated administrators:

   ```bash
   aws organizations list-aws-service-access-for-organization --region us-east-1 \
     --query 'EnabledServicePrincipals[].ServicePrincipal' --output text | tr '\t' '\n'
   for a in $(aws organizations list-delegated-administrators --region us-east-1 --query 'DelegatedAdministrators[].Id' --output text); do
     echo "== $a $(aws organizations describe-account --region us-east-1 --account-id "$a" --query 'Account.Name' --output text)"
     aws organizations list-delegated-services-for-account --region us-east-1 --account-id "$a" \
       --query 'DelegatedServices[].ServicePrincipal' --output text | tr '\t' '\n'
   done
   ```

2. The Organizations resource-based delegation policy, if any:

   ```bash
   aws organizations describe-resource-policy --region us-east-1 \
     --query 'ResourcePolicy.Content' --output text | jq .
   ```

3. For each delegated administrator account: what else runs there (workloads? CI?), who can access it (Identity Center assignments, GT-AWS-ORG-9), and whether SCPs protect its sensitive configuration.
4. Map each delegation to impact using the [table above](#trusted-access-and-delegated-administrators). Pay special attention to `iam.amazonaws.com` (root access), `sso.amazonaws.com`, `member.org.stacksets.cloudformation.amazonaws.com` and any delegation policy that allows `organizations:AttachPolicy`, `DetachPolicy` or `UpdatePolicy`.

#### Observation

Illustrative:

```text
== 444455556666 shared-services
sso.amazonaws.com
member.org.stacksets.cloudformation.amazonaws.com
guardduty.amazonaws.com
```

A workload-bearing shared-services account holding Identity Center, StackSets and GuardDuty delegation is three organisation-wide powers in one account that also runs applications.

#### Evaluation

**Pass:** delegations exist for the services the client uses, held by dedicated accounts (security tooling, identity, deployment) without unrelated workloads; access to those accounts is restricted and monitored; the delegation policy grants only the policy actions the team needs, ideally scoped by policy type; trusted access is enabled only for services in use. **Fail:** delegated administrators in workload accounts; many powerful delegations concentrated in one account with broad access; a delegation policy allowing attach and detach of SCPs to a non-security team; trusted access left enabled for unused services. Delegations that should exist but do not (security services run from the management account) are reported under GT-AWS-ORG-2 and the [detection note](/cloud/aws-detection-posture-services/).

#### Automated coverage

No Security Hub CSPM control. Prowler `organizations_delegated_administrators` (compares against a trusted list you configure), `organizations_security_services_delegated_admin_not_management_account`.

#### Detection

`RegisterDelegatedAdministrator`, `DeregisterDelegatedAdministrator`, `EnableAWSServiceAccess`, `DisableAWSServiceAccess` (the [Datadog case](#real-world-cases)), `PutResourcePolicy`, `DeleteResourcePolicy`. ATT&CK [T1484](https://attack.mitre.org/techniques/T1484/).

### GT-AWS-ORG-8: Root credential status across the organisation

*Guler Tech methodology.*

#### What it checks

Whether centralised root access management is enabled; whether member accounts still have root passwords, access keys or MFA devices; and whether the management account's root user is protected with no access keys and hardware or passkey MFA.

#### Prerequisites

Management account read access; read-only roles in member accounts (or the IAM delegated administrator).

#### Steps

1. Organisation features:

   ```bash
   aws iam list-organizations-features
   ```

2. Per member account, root credential presence, from a read-only role in that account (`get-account-summary` reports root-user state):

   ```bash
   aws iam get-account-summary \
     --query 'SummaryMap.{password:AccountPasswordPresent,keys:AccountAccessKeysPresent,mfa:AccountMFAEnabled,certs:AccountSigningCertificatesPresent}'
   ```

3. **Lab or explicitly approved only (privileged session):** where the client prefers it, the management account or IAM delegated administrator can audit a member through a root session scoped to the read-only audit task policy. It is read-only in effect but it is a root session; agree it in writing.

   ```bash
   aws sts assume-root --region eu-west-2 --target-principal 444455556666 \
     --task-policy-arn arn=arn:aws:iam::aws:policy/root-task/IAMAuditRootUserCredentials \
     --duration-seconds 900
   # with the returned credentials:
   aws iam get-login-profile ; aws iam list-access-keys ; aws iam list-mfa-devices
   ```

4. Management account root: summary plus the credential report root row, and whether the root MFA is virtual (a virtual root MFA device appears in `list-virtual-mfa-devices` with the serial `arn:aws:iam::111122223333:mfa/root-account-mfa-device`):

   ```bash
   aws iam get-account-summary --query 'SummaryMap.[AccountMFAEnabled,AccountAccessKeysPresent,AccountPasswordPresent]'
   aws iam list-virtual-mfa-devices --assignment-status Assigned \
     --query 'VirtualMFADevices[?ends_with(SerialNumber, `root-account-mfa-device`)].SerialNumber'
   ```

#### Observation

Illustrative:

```text
{"OrganizationId": "o-exampleorg1", "EnabledFeatures": ["RootCredentialsManagement", "RootSessions"]}
444455556666 password=0 keys=0 mfa=0 certs=0
123456789012 password=1 keys=1 mfa=0 certs=0
```

#### Evaluation

**Pass:** `RootCredentialsManagement` (and, if used, `RootSessions`) enabled; member accounts show no root password, keys or certificates; the management account root has no access keys, MFA enabled (hardware or passkey for IAM.6), and its email and phone controlled by a small group. **Fail:** feature not enabled and member root users with passwords and no MFA; any root access key anywhere (Critical in the management account, High in a member); management account root with virtual MFA only (IAM.6) or no MFA (IAM.9). Member root passwords without MFA, recoverable via a mailbox many people can read, are High.

#### Automated coverage

Security Hub CSPM **IAM.4** (CIS v3.0.0 **1.4**, v5.0.0 **1.3**), **IAM.6** (v3.0.0 **1.6**, v5.0.0 **1.5**), **IAM.9** (v3.0.0 **1.5**, v5.0.0 **1.4**). Prowler `iam_root_credentials_management_enabled`, `iam_no_root_access_key`, `iam_root_mfa_enabled`, `iam_root_hardware_mfa_enabled`, `iam_avoid_root_usage`.

#### Detection

`ConsoleLogin` with `userIdentity.type` `Root`; `AssumeRoot` (CloudTrail, `sts.amazonaws.com`) and the task policy in the request; `DisableOrganizationsRootCredentialsManagement`, `DisableOrganizationsRootSessions`; `CreateLoginProfile` in a privileged root session (password recovery being enabled). GuardDuty `Policy:IAMUser/RootCredentialUsage` and `Policy:IAMUser/ShortTermRootCredentialUsage`, both Low by default, so route them by type (see the [detection note](/cloud/aws-detection-posture-services/)). ATT&CK [T1078.001](https://attack.mitre.org/techniques/T1078/001/).

### GT-AWS-ORG-9: IAM Identity Center permission sets and management-account assignments

*Guler Tech methodology.*

#### What it checks

Who can reach the management account and other sensitive accounts through Identity Center, through which permission sets, assigned to users or groups; whether permission sets are least privilege; and whether the Identity Center delegated administrator can escalate itself.

#### Prerequisites

Read access in the management account or the Identity Center delegated administrator (Identity Center is Regional: use the Region where the instance lives).

#### Steps

1. Instance and delegated administrator:

   ```bash
   SSO_REGION=eu-west-2
   read INSTANCE STORE <<< "$(aws sso-admin list-instances --region $SSO_REGION --query 'Instances[0].[InstanceArn,IdentityStoreId]' --output text)"
   aws organizations list-delegated-administrators --region us-east-1 --service-principal sso.amazonaws.com
   ```

2. Permission sets provisioned to the management account, and who is assigned:

   ```bash
   MGMT=111122223333
   for ps in $(aws sso-admin list-permission-sets-provisioned-to-account --region $SSO_REGION \
                --instance-arn "$INSTANCE" --account-id $MGMT --query 'PermissionSets[]' --output text); do
     name=$(aws sso-admin describe-permission-set --region $SSO_REGION --instance-arn "$INSTANCE" \
            --permission-set-arn "$ps" --query 'PermissionSet.[Name,SessionDuration]' --output text)
     echo "== $name"
     aws sso-admin list-account-assignments --region $SSO_REGION --instance-arn "$INSTANCE" \
       --account-id $MGMT --permission-set-arn "$ps" \
       --query 'AccountAssignments[].[PrincipalType,PrincipalId]' --output text
   done
   ```

3. Resolve groups to members (and note who administers those groups in the IdP):

   ```bash
   aws identitystore list-group-memberships --region $SSO_REGION --identity-store-id "$STORE" \
     --group-id 0123456789-abcd1234-ab12-cd34-ef56-0123456789ab \
     --query 'GroupMemberships[].MemberId.UserId' --output text
   ```

4. Every permission set's policies, for privilege review:

   ```bash
   for ps in $(aws sso-admin list-permission-sets --region $SSO_REGION --instance-arn "$INSTANCE" --query 'PermissionSets[]' --output text); do
     aws sso-admin describe-permission-set --region $SSO_REGION --instance-arn "$INSTANCE" --permission-set-arn "$ps" \
       --query 'PermissionSet.[Name,SessionDuration]' --output text
     aws sso-admin list-managed-policies-in-permission-set --region $SSO_REGION --instance-arn "$INSTANCE" \
       --permission-set-arn "$ps" --query 'AttachedManagedPolicies[].Name' --output text
     aws sso-admin get-inline-policy-for-permission-set --region $SSO_REGION --instance-arn "$INSTANCE" \
       --permission-set-arn "$ps" --query 'InlinePolicy' --output text | jq . 2>/dev/null
     aws sso-admin list-accounts-for-provisioned-permission-set --region $SSO_REGION --instance-arn "$INSTANCE" \
       --permission-set-arn "$ps" --query 'length(AccountIds)' --output text
   done
   ```

5. In the delegated administrator account, check the permission sets that the Identity Center administrators themselves use: `sso:*`, `identitystore:*` and `sso-directory:CreateBearerToken` mean they can grant themselves access anywhere except the management account. Review MFA and identity source settings in the console (not all are exposed through the public API).

#### Observation

Illustrative:

```text
== AdministratorAccess  PT12H
GROUP 0123456789-abcd1234-ab12-cd34-ef56-0123456789ab
== Billing  PT1H
USER  0123456789-11111111-2222-3333-4444-5555aaaabbbb
```

#### Evaluation

**Pass:** management-account access through dedicated permission sets, assigned to named users (not groups), a handful of people, short sessions; administrator permission sets in other accounts assigned to small, purpose-specific groups whose membership is controlled in the IdP by a different team; inline policies free of IAM and Identity Center administration except for the identity team; SCPs or permission-set conditions stopping delegated administrators editing their own access. **Fail:** group assignments to management-account permission sets; `AdministratorAccess` assigned to broad groups across all accounts; 12-hour administrator sessions as the norm; Identity Center administrators able to modify their own permission sets or create SCIM tokens without control. Severity scales with the number of people and the reach: broad administrator access to the management account is High.

#### Automated coverage

None in Security Hub CSPM or Prowler for assignments. Run the [IAM privilege escalation](/cloud/aws-iam-privilege-escalation/) analysis on inline policies.

#### Detection

`CreatePermissionSet`, `UpdatePermissionSet`, `PutInlinePolicyToPermissionSet`, `AttachManagedPolicyToPermissionSet`, `CreateAccountAssignment`, `ProvisionPermissionSet` (event source `sso.amazonaws.com`); `CreateUser`, `CreateGroupMembership` (`identitystore.amazonaws.com`); identity source and MFA configuration changes. The [Datadog case](#real-world-cases) shows an attacker creating a user and group, assigning a permission set and relaxing MFA. ATT&CK [T1136.003](https://attack.mitre.org/techniques/T1136/003/), [T1098.003](https://attack.mitre.org/techniques/T1098/003/), [T1484.002](https://attack.mitre.org/techniques/T1484/002/).

### GT-AWS-ORG-10: Contacts, break-glass and cost anomaly signals

*Guler Tech methodology.*

#### What it checks

That every account has a monitored security contact, that break-glass access exists, is controlled and is alarmed, and that cost anomalies reach someone who would recognise abuse.

#### Prerequisites

Management account read access (with trusted access for Account Management, contacts for members can be read from there); `ce` and `budgets` read permissions; an interview with the platform team.

#### Steps

1. Security contact for every account:

   ```bash
   for a in $(aws organizations list-accounts --region us-east-1 --query 'Accounts[?Status==`ACTIVE`].Id' --output text); do
     c=$(aws account get-alternate-contact --account-id "$a" --alternate-contact-type SECURITY \
          --query 'AlternateContact.EmailAddress' --output text 2>/dev/null || echo MISSING)
     echo "$a $c"
   done
   ```

   For the management account itself, omit `--account-id`.

2. Break-glass: ask for the documented procedure, the identities used, how credentials are stored, when it was last tested, and the alarm on use; verify the identities exist with the stated MFA (`iam list-mfa-devices --user-name`) and find the alarm or EventBridge rule (see [monitoring](/cloud/aws-cloudwatch-eventbridge-monitoring/)).
3. Cost anomaly monitoring:

   ```bash
   aws ce get-anomaly-monitors --region us-east-1 \
     --query 'AnomalyMonitors[].[MonitorName,MonitorType,MonitorDimension]' --output text
   aws ce get-anomaly-subscriptions --region us-east-1 \
     --query 'AnomalySubscriptions[].[SubscriptionName,Frequency,Subscribers[].Address]' --output json
   aws budgets describe-budgets --account-id 111122223333 --query 'Budgets[].[BudgetName,BudgetLimit.Amount]' --output text
   ```

#### Observation

Contacts per account, break-glass evidence, monitors and who receives them.

#### Evaluation

**Pass:** every account has a security contact that is a monitored team address (not a person, not the billing mailbox); break-glass identities exist, use hardware MFA, are documented, tested within the last year, and every use alarms to the security team; a cost anomaly monitor covers all accounts (or services), with subscriptions reaching a technical owner at a threshold low enough to catch mining in a small account. **Fail:** missing or personal security contacts; no break-glass, or break-glass used routinely or unmonitored; cost alerts only to finance or not at all.

#### Automated coverage

Security Hub CSPM **Account.1** (CIS v3.0.0 **1.2**, v5.0.0 **1.2**, v1.4.0 1.2). Prowler `account_maintain_current_contact_details`, `account_security_contact_information_is_registered`, `account_maintain_different_contact_details_to_security_billing_and_operations`.

#### Detection

`PutAlternateContact`, `DeleteAlternateContact`, `PutContactInformation`, `StartPrimaryEmailUpdate` (redirecting AWS's security notices is an attacker move as well as a hygiene issue); break-glass `ConsoleLogin` events; `DeleteAnomalyMonitor`, `DeleteAnomalySubscription`, `UpdateAnomalySubscription`.

## Hardening

**Keep the management account empty.** Move workloads, data and pipelines out; remove IAM users with access keys; reach it only through dedicated Identity Center permission sets assigned to named users, plus documented break-glass. Delegate every service that supports it to dedicated accounts in a Security OU.

**Narrow `OrganizationAccountAccessRole`.** After vending, either delete it (if the platform uses Identity Center and its own deployment role) or narrow its trust to one management-account role that only break-glass and the platform pipeline can assume, with MFA required for humans:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": { "AWS": "arn:aws:iam::111122223333:role/OrgBreakGlass" },
      "Action": "sts:AssumeRole",
      "Condition": {
        "Bool": { "aws:MultiFactorAuthPresent": "true" }
      }
    }
  ]
}
```

**Baseline SCP at the root.** Combine the deny-list patterns. Test in a Policy Staging OU first, as AWS recommends, and keep each statement's exceptions to specific role names that member administrators cannot create (protect those names with a further deny on `iam:CreateRole`, `iam:UpdateAssumeRolePolicy` and policy attachment for matching ARNs).

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyLeaveAndClose",
      "Effect": "Deny",
      "Action": ["organizations:LeaveOrganization", "account:CloseAccount"],
      "Resource": "*"
    },
    {
      "Sid": "DenyRootUser",
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "StringLike": { "aws:PrincipalArn": "arn:aws:iam::*:root" }
      }
    },
    {
      "Sid": "ProtectPlatformRoles",
      "Effect": "Deny",
      "Action": [
        "iam:AttachRolePolicy", "iam:DeleteRole", "iam:DeleteRolePolicy", "iam:DetachRolePolicy",
        "iam:PutRolePolicy", "iam:UpdateAssumeRolePolicy", "iam:UpdateRole"
      ],
      "Resource": [
        "arn:aws:iam::*:role/OrganizationAccountAccessRole",
        "arn:aws:iam::*:role/AWSControlTowerExecution",
        "arn:aws:iam::*:role/SecurityAudit-ReadOnly"
      ],
      "Condition": {
        "ArnNotLike": { "aws:PrincipalArn": "arn:aws:iam::*:role/PlatformPipeline" }
      }
    },
    {
      "Sid": "RequireImdsV2OnLaunch",
      "Effect": "Deny",
      "Action": "ec2:RunInstances",
      "Resource": "arn:aws:ec2:*:*:instance/*",
      "Condition": {
        "StringNotEquals": { "ec2:MetadataHttpTokens": "required" }
      }
    },
    {
      "Sid": "DenyImdsV1Credentials",
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "NumericLessThan": { "ec2:RoleDelivery": "2.0" }
      }
    }
  ]
}
```

Add the security-tooling protection statement from the [detection note](/cloud/aws-detection-posture-services/) and a Region restriction based on AWS's current example (its `NotAction` list of global services changes over time; copy it from the [SCP examples repository](https://github.com/aws-samples/service-control-policy-examples) rather than from an old blog post). If centralised root sessions are used, test whether `DenyRootUser` blocks the tasks you rely on and add a narrow exception if needed.

**Identity perimeter RCP.** Start from AWS's maintained example and adapt the exceptions (partner accounts, tagged exclusions) to the client:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "EnforceOrgIdentities",
      "Effect": "Deny",
      "Principal": "*",
      "Action": ["s3:*", "sts:AssumeRole", "kms:*", "sqs:*", "secretsmanager:*"],
      "Resource": "*",
      "Condition": {
        "StringNotEqualsIfExists": {
          "aws:PrincipalOrgID": "o-exampleorg1",
          "aws:ResourceTag/dp:exclude:identity": "true"
        },
        "BoolIfExists": {
          "aws:PrincipalIsAWSService": "false"
        }
      }
    }
  ]
}
```

**Declarative policy for EC2 baselines.** Enforce IMDSv2, block public sharing of snapshots and AMIs, and disable the serial console unless a team needs it:

```json
{
  "ec2_attributes": {
    "exception_message": {
      "@@assign": "Blocked by organisation policy. See the platform security baseline page."
    },
    "instance_metadata_defaults": {
      "http_tokens": { "@@assign": "required" },
      "http_put_response_hop_limit": { "@@assign": "2" },
      "http_tokens_enforced": { "@@assign": "enabled" }
    },
    "snapshot_block_public_access": {
      "state": { "@@assign": "block_all_sharing" }
    },
    "image_block_public_access": {
      "state": { "@@assign": "block_new_sharing" }
    },
    "serial_console_access": {
      "status": { "@@assign": "disabled" }
    }
  }
}
```

Read AWS's warning before enabling `http_tokens_enforced`: launches that still request IMDSv1 will fail.

**Manage policies as code.** In Terraform (check that your provider version supports the policy type):

```hcl
resource "aws_organizations_policy" "baseline_scp" {
  name    = "baseline-guardrails"
  type    = "SERVICE_CONTROL_POLICY"
  content = file("${path.module}/policies/baseline-scp.json")
}

resource "aws_organizations_policy_attachment" "root_scp" {
  policy_id = aws_organizations_policy.baseline_scp.id
  target_id = data.aws_organizations_organization.this.roots[0].id
}

resource "aws_organizations_policy" "identity_rcp" {
  name    = "identity-perimeter"
  type    = "RESOURCE_CONTROL_POLICY"
  content = file("${path.module}/policies/identity-rcp.json")
}

resource "aws_organizations_policy" "ec2_baseline" {
  name    = "ec2-baseline"
  type    = "DECLARATIVE_POLICY_EC2"
  content = file("${path.module}/policies/ec2-declarative.json")
}
```

**Centralise root access.** Enable both features, delete member root credentials, and keep the management account root locked down. These commands change the organisation and are for the client to run under change control:

```bash
aws organizations enable-aws-service-access --service-principal iam.amazonaws.com
aws iam enable-organizations-root-credentials-management
aws iam enable-organizations-root-sessions
aws organizations register-delegated-administrator --service-principal iam.amazonaws.com --account-id 444455556666
```

**Constrain Identity Center administration.** Dedicated management-account permission sets assigned to users; in the delegated administrator account, deny the actions that let administrators grant themselves access through the identity store or SCIM (from AWS's guidance):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Action": ["identitystore:CreateGroupMembership", "sso-directory:CreateBearerToken"],
      "Resource": "*"
    }
  ]
}
```

**Set contacts centrally and watch cost.** Set the security contact for every account from the management account or the Account Management delegated administrator (`aws account put-alternate-contact --account-id <id> --alternate-contact-type SECURITY ...`), and create a cost anomaly monitor with a subscription to the security team:

```hcl
resource "aws_ce_anomaly_monitor" "services" {
  name              = "all-services"
  monitor_type      = "DIMENSIONAL"
  monitor_dimension = "SERVICE"
}

resource "aws_ce_anomaly_subscription" "security" {
  name             = "security-team"
  frequency        = "IMMEDIATE"
  monitor_arn_list = [aws_ce_anomaly_monitor.services.arn]

  subscriber {
    type    = "SNS"
    address = aws_sns_topic.security_alerts.arn
  }

  threshold_expression {
    dimension {
      key           = "ANOMALY_TOTAL_IMPACT_ABSOLUTE"
      match_options = ["GREATER_THAN_OR_EQUAL"]
      values        = ["100"]
    }
  }
}
```

**Use Control Tower controls, but know their limits.** Enable the strongly recommended preventive and detective controls on every OU, list them with `aws controltower list-enabled-controls --target-identifier <OU ARN>`, and remember they do not apply to the management account.

**Alert on the organisation's own control plane.** An EventBridge rule in `us-east-1` of the management account on `source: aws.organizations` for `LeaveOrganization`, `DetachPolicy`, `UpdatePolicy`, `DeletePolicy`, `DisablePolicyType`, `DisableAWSServiceAccess`, `RegisterDelegatedAdministrator`, `MoveAccount` and `CreateAccount`, plus Identity Center assignment events and `AssumeRoot`; details in the [monitoring note](/cloud/aws-cloudwatch-eventbridge-monitoring/).

## Real-world cases

- **Leaked management-account key, disabled trusted access and Identity Center persistence (Datadog Security Labs, May 2025).** A long-term access key for an IAM user in an organisation's management account was used from several IPs. The attacker disabled trusted access for several services in Organizations (including IAM Access Analyzer, IAM and CloudFormation StackSets), created an Identity Center user and group, assigned a permission set, relaxed MFA and extended session duration. Every review point in this note appears in it: an IAM user with keys in the management account, no protection on trusted access, and Identity Center as a persistence mechanism. [Datadog: The attacker doth persist too much](https://securitylabs.datadoghq.com/articles/tales-from-the-cloud-trenches-the-attacker-doth-persist-too-much/)
- **Pivoting through AWS Organizations (NetSPI, March 2023).** Research describing how management-account access becomes member-account access through `OrganizationAccountAccessRole` on account creation, trusted access and delegated administration (for example an organisation-wide Access Analyzer revealing roles that trust any principal), and Identity Center assignments, with a Pacu module for enumeration. [NetSPI: Pivoting Clouds in AWS Organizations, Part 1](https://www.netspi.com/blog/technical-blog/cloud-pentesting/pivoting-clouds-aws-organizations-part-1/) and [Part 2](https://www.netspi.com/blog/technical-blog/cloud-pentesting/pivoting-clouds-aws-organizations-part-2/)
- **AWS Organizations defaults (Hacking the Cloud).** A concise explanation of the default member-account role and why a compromised management account or delegated administrator reaches member accounts. [Hacking the Cloud: AWS Organizations defaults](https://hackingthe.cloud/aws/general-knowledge/aws_organizations_defaults/)
- **Crypto mining across Regions after a key leak (Datadog Security Labs, January 2024).** ECS clusters running miners in at least 17 Regions: the argument for Region restriction SCPs and for cost anomaly alerts to a technical owner. [Datadog: ECS crypto mining](https://securitylabs.datadoghq.com/articles/tales-from-the-cloud-trenches-ecs-crypto-mining/)

## Rating findings

| Finding | Typical severity | Reasoning |
|---|---|---|
| Root access key in the management account | Critical | Unrestricted, unscoped, long-lived credential for the account that controls the organisation |
| IAM users with active access keys, or workloads, in the management account | High | A single leaked key or compromised workload gives organisation-wide reach that SCPs cannot limit; Critical if the identity has administrator or organisation permissions and the key is exposed |
| Many management-account principals can assume `OrganizationAccountAccessRole` (or equivalents) | High | Each is a path to administrator in every member account; Medium if limited to a small, MFA-protected group |
| Broad Identity Center access to the management account (groups, many users, long sessions) | High | IdP group control becomes organisation control |
| Delegated administrator for IAM root access, Identity Center or StackSets in a workload account | High | Organisation-wide powers share a blast radius with applications |
| SCP type disabled, or production accounts outside guarded OUs | High | No guardrails apply to those accounts at all |
| Missing deny on `LeaveOrganization` | Medium | Lets an account shed all guardrails; requires account administrator first |
| Missing protection of logging and security tooling in SCPs | Medium | Any account administrator can blind detection; High combined with demonstrated privilege escalation |
| Missing Region restriction | Medium | Enables unnoticed abuse in unused Regions; Low where GuardDuty and alerting cover all Regions |
| SCP exceptions member administrators can satisfy | Medium to High | The guardrail exists on paper only; rate by what it was meant to stop |
| No RCP or other identity perimeter, with permissive resource policies found | Inherits the resource finding's severity | The perimeter would have contained it |
| No RCP, resource policies clean | Low | Defence in depth missing |
| Account-level EC2 baselines (IMDSv2 defaults, snapshot/AMI public access) not enforced | Low to Medium | Higher where a public snapshot or IMDSv1 workload is found |
| Member root credentials present without MFA, centralised root access not enabled | High | Password recovery via email bypasses identity controls; root is limited only by SCPs |
| Management account root without MFA | Critical | Account takeover of the organisation via password compromise |
| Management account root with virtual rather than hardware or passkey MFA | Low to Medium | CIS IAM.6; depends on device custody |
| Security contact missing or personal | Low | AWS security notices lost |
| No break-glass, or unmonitored break-glass | Medium | Operational and security risk during an IdP outage; unmonitored break-glass is an unwatched administrator path |
| No cost anomaly alerting to a technical owner | Low | Compensating detection for resource hijacking missing |

## Mapping

| Test | Security Hub CSPM | CIS (version) | ATT&CK |
|---|---|---|---|
| GT-AWS-ORG-1 | Account.2 | Not mapped | T1580, T1087.004, T1069.003 |
| GT-AWS-ORG-2 | IAM.4 (applies to the management account) | v3.0.0 1.4; v5.0.0 1.3 | T1078.004 |
| GT-AWS-ORG-3 | None | Not mapped | T1199, T1078.004 |
| GT-AWS-ORG-4 | None (EC2.8 related) | Not mapped | T1666, T1535, T1685, T1484 |
| GT-AWS-ORG-5 | None | Not mapped | T1530, T1537 |
| GT-AWS-ORG-6 | EC2.8 (outcome) | v3.0.0 5.6; v5.0.0 5.7 (EC2.8) | T1552.005 |
| GT-AWS-ORG-7 | None | Not mapped | T1484, T1078.004 |
| GT-AWS-ORG-8 | IAM.4, IAM.6, IAM.9 | v3.0.0 1.4, 1.6, 1.5; v5.0.0 1.3, 1.5, 1.4 | T1078.001 |
| GT-AWS-ORG-9 | None | Not mapped | T1136.003, T1098.003, T1484.002 |
| GT-AWS-ORG-10 | Account.1 | v3.0.0 1.2; v5.0.0 1.2; v1.4.0 1.2 | T1496.004 |

## References

- AWS Organizations User Guide: [service control policies](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html), [resource control policies and supported services](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_rcps.html), [declarative policies](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_declarative.html), [EC2 policy syntax](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_declarative_syntax.html), [quotas](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_reference_limits.html), [best practices for the management account](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_best-practices_mgmt-acct.html), [OrganizationAccountAccessRole](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_accounts_access-cross-account-role.html), [delegated administrator for Organizations](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_delegate_policies.html), [default security controls](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_security_default_controls.html), [GuardDuty policies](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_guardduty.html)
- AWS announcement: [Introducing resource control policies (November 2024)](https://aws.amazon.com/about-aws/whats-new/2024/11/resource-control-policies-restrict-access-aws-resources)
- IAM User Guide: [centralise root access for member accounts](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-enable-root-access.html), [perform a privileged task](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user-privileged-task.html), [policy simulator](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_testing-policies.html)
- IAM Identity Center: [delegated administration and best practices](https://docs.aws.amazon.com/singlesignon/latest/userguide/delegated-admin.html)
- AWS Control Tower: [about controls](https://docs.aws.amazon.com/controltower/latest/controlreference/controls.html)
- Security Hub: [CIS AWS Foundations Benchmark mappings](https://docs.aws.amazon.com/securityhub/latest/userguide/cis-aws-foundations-benchmark.html), [controls reference](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-controls-reference.html)
- Examples: [SCP examples](https://github.com/aws-samples/service-control-policy-examples), [RCP examples](https://github.com/aws-samples/resource-control-policy-examples), [data perimeter policy examples](https://github.com/aws-samples/data-perimeter-policy-examples)
- AWS: [penetration testing policy](https://aws.amazon.com/security/penetration-testing/)
- Tools: [Prowler](https://github.com/prowler-cloud/prowler), [Pacu](https://github.com/RhinoSecurityLabs/pacu), [PMapper](https://github.com/nccgroup/PMapper), [CloudFox](https://github.com/BishopFox/cloudfox), [CloudGoat](https://github.com/RhinoSecurityLabs/cloudgoat) for practice
- MITRE ATT&CK: [T1078.004](https://attack.mitre.org/techniques/T1078/004/), [T1078.001](https://attack.mitre.org/techniques/T1078/001/), [T1199](https://attack.mitre.org/techniques/T1199/), [T1666](https://attack.mitre.org/techniques/T1666/), [T1484](https://attack.mitre.org/techniques/T1484/), [T1484.002](https://attack.mitre.org/techniques/T1484/002/), [T1098.003](https://attack.mitre.org/techniques/T1098/003/), [T1136.003](https://attack.mitre.org/techniques/T1136/003/), [T1535](https://attack.mitre.org/techniques/T1535/)
- Research: [Datadog Security Labs: The attacker doth persist too much](https://securitylabs.datadoghq.com/articles/tales-from-the-cloud-trenches-the-attacker-doth-persist-too-much/), [NetSPI: Pivoting Clouds in AWS Organizations](https://www.netspi.com/blog/technical-blog/cloud-pentesting/pivoting-clouds-aws-organizations-part-1/), [Hacking the Cloud: AWS Organizations defaults](https://hackingthe.cloud/aws/general-knowledge/aws_organizations_defaults/), [Datadog Security Labs: ECS crypto mining](https://securitylabs.datadoghq.com/articles/tales-from-the-cloud-trenches-ecs-crypto-mining/)
