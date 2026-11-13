---
title: "AWS IAM Fundamentals and Policy Evaluation"
date: 2026-11-12 18:01:00 +0000
subcategory: aws
summary: "How AWS principals, credentials and policy evaluation really work, and how to test root hygiene, MFA, stale keys, over-broad policies and PassRole."
refs: [IAM.1, IAM.2, IAM.3, IAM.4, IAM.5, IAM.6, IAM.8, IAM.9, IAM.15, IAM.16, IAM.19, IAM.21, IAM.22, IAM.27, IAM.28, CloudWatch.1, "CIS AWS v5.0.0 1.3", "CIS AWS v5.0.0 1.4", "CIS AWS v5.0.0 1.5", "CIS AWS v5.0.0 1.9", "CIS AWS v5.0.0 1.11", "CIS AWS v5.0.0 1.13", "CIS AWS v5.0.0 1.14", "CIS AWS v1.4.0 1.16", T1078.004, T1098.001, T1098.003, T1548.005, T1087.004, T1110.003]
tags: [aws, iam, policy-evaluation, root-user, mfa, access-analyzer]
---

This note is part of our [AWS Security Testing Guide](/cloud/aws-security-testing-guide/) and covers the foundation every other AWS note stands on: who can act in an account (principals), what they authenticate with (credentials), and how AWS decides whether a request is allowed (policy evaluation). Almost every serious AWS finding is an IAM finding in disguise. A public bucket is a resource policy that allows `*`; a compromised EC2 instance matters because of the role attached to it; a CI pipeline compromise matters because of the trust policy on its deployment role. Getting the evaluation logic right is what separates "this policy contains `s3:*`" from "this role can read the customer database from outside the organisation". Below are the security model, the classes of mistake we see most, eleven tests (credential report, root, MFA, password policy, unused access, key rotation, over-broad policies, attachment sprawl, policy validation, `iam:PassRole`, and simulating sensitive actions), the guardrails that fix them, and how to rate what you find. Privilege escalation paths get their own note, [AWS IAM privilege escalation](/cloud/aws-iam-privilege-escalation/); role trust, cross-account access and federation are in [AWS STS, cross-account trust and federation](/cloud/aws-sts-cross-account-trust-federation/).

## Contents

- [How it works](#how-it-works)
- [What goes wrong](#what-goes-wrong)
- [Testing](#testing)
  - [Before you start](#before-you-start)
  - [GT-AWS-IAM-1: Credential report review](#gt-aws-iam-1-credential-report-review)
  - [GT-AWS-IAM-2: Root user credentials, MFA and usage](#gt-aws-iam-2-root-user-credentials-mfa-and-usage)
  - [GT-AWS-IAM-3: MFA coverage for human principals](#gt-aws-iam-3-mfa-coverage-for-human-principals)
  - [GT-AWS-IAM-4: Account password policy](#gt-aws-iam-4-account-password-policy)
  - [GT-AWS-IAM-5: Unused users, keys, roles and permissions](#gt-aws-iam-5-unused-users-keys-roles-and-permissions)
  - [GT-AWS-IAM-6: Access key age, rotation and long-lived key use](#gt-aws-iam-6-access-key-age-rotation-and-long-lived-key-use)
  - [GT-AWS-IAM-7: Over-broad policy statements](#gt-aws-iam-7-over-broad-policy-statements)
  - [GT-AWS-IAM-8: Inline and direct-attachment sprawl](#gt-aws-iam-8-inline-and-direct-attachment-sprawl)
  - [GT-AWS-IAM-9: Policy validation and condition logic](#gt-aws-iam-9-policy-validation-and-condition-logic)
  - [GT-AWS-IAM-10: iam:PassRole scope](#gt-aws-iam-10-iampassrole-scope)
  - [GT-AWS-IAM-11: Effective permissions for sensitive actions](#gt-aws-iam-11-effective-permissions-for-sensitive-actions)
- [Hardening](#hardening)
- [Real-world cases](#real-world-cases)
- [Rating findings](#rating-findings)
- [Mapping](#mapping)
- [References](#references)

## How it works

### Principals

A **principal** is anything that can make a request AWS evaluates. In a configuration review you will meet six kinds:

| Principal | What it is | How it authenticates | Notes for testers |
|---|---|---|---|
| **Root user** | The identity created with the account, tied to an email address | Password plus MFA; optionally (and wrongly) access keys | Implicitly allowed everything in its own account. SCPs restrict the root user of **member** accounts, never the management account. Cannot be limited by IAM policies. |
| **IAM user** | A long-lived identity inside one account | Console password and/or access keys, MFA devices, SSH keys and service-specific credentials for a few services, X.509 signing certificates | AWS now recommends IAM users only for cases federation cannot serve (third-party tools, emergency access). Every IAM user with an access key is a standing credential that can leak. |
| **IAM role** | An identity with no long-term credentials; you *assume* it and receive a session | Temporary credentials from AWS STS | Has a **trust policy** (who may assume it) and permissions policies (what the session can do). The ARN that makes requests is the session, `arn:aws:sts::111122223333:assumed-role/RoleName/SessionName`. |
| **Federated principal** | A workforce or workload identity from an external IdP (SAML 2.0 or OIDC) mapped onto a role | The IdP's assertion or token, exchanged with `AssumeRoleWithSAML` or `AssumeRoleWithWebIdentity` | Covered in depth in the [STS and federation note](/cloud/aws-sts-cross-account-trust-federation/). |
| **IAM Identity Center user** | A workforce user in Identity Center, given access to accounts via **permission sets** | Identity Center sign-in (its own directory or an external IdP), then a role session | Each permission set is provisioned into each assigned account as a role named `AWSReservedSSO_<PermissionSetName>_<suffix>` under the path `/aws-reserved/sso.amazonaws.com/`. You cannot edit those roles in IAM; change the permission set instead. |
| **Service principal** | An AWS service acting on your behalf, such as `lambda.amazonaws.com` or `cloudtrail.amazonaws.com` | Internal to AWS | Appears in role trust policies and resource policies. Granting a service principal access without `aws:SourceArn` / `aws:SourceAccount` is the cross-service confused deputy problem. |

Three role sub-types matter in reviews. A **service role** is an ordinary role a service assumes (an EC2 instance profile role, a Lambda execution role); you own and can edit it. A **service-linked role** is created by a service, lives under the path `/aws-service-role/<service>.amazonaws.com/`, has permissions you can view but not edit, cannot have a permissions boundary, and is not restricted by SCPs or RCPs. A **role created from a permission set** belongs to Identity Center. AWS has also introduced *account access manager*, which assigns ordinary IAM roles to Identity Center users and groups; at the time of writing it is new, so check the current documentation if you meet it.

The **anonymous** principal is real too: a resource policy with `"Principal": "*"` (or `{"AWS": "*"}`) and no restricting condition grants access to everyone on the internet, signed or not, for the services that accept unsigned requests (S3 being the classic one).

### Credentials

**Long-term credentials** never expire on their own: the root password and access keys, IAM user passwords and access keys, signing certificates. An access key is an access key ID plus a secret access key. Long-term access key IDs begin with the four characters AKIA, and the IAM unique ID prefixes tell you what other identifiers are (AIDA for a user, AROA for a role, ANPA for a managed policy, AGPA for a group).

**Temporary credentials** come from AWS STS and carry a third part, the session token. Their access key IDs begin with ASIA, which is the quickest way to tell, from a log line or a leaked `credentials` file, whether you are looking at a session or a standing key. The STS operations differ in who can call them and how long the result lasts:

| Operation | Caller | Lifetime (min / max / default) | Notes |
|---|---|---|---|
| `AssumeRole` | IAM user or role session | 15 min / role's maximum session duration (1 to 12 h) / 1 h | Role chaining (a session assuming another role) is capped at 1 h. |
| `AssumeRoleWithSAML`, `AssumeRoleWithWebIdentity` | Anyone holding a valid assertion or token | Same as `AssumeRole` | No AWS credentials needed to call them; the trust policy is the only gate. |
| `GetSessionToken` | IAM user or root | IAM user 15 min / 36 h / 12 h; root 15 min / 1 h / 1 h | Used to add MFA to CLI sessions. |
| `GetFederationToken` | IAM user or root | Same as above | Produces an STS federated user session; cannot call IAM APIs from the CLI or API. |
| `AssumeRoot` | Principal in the management account or IAM delegated administrator | Short, task-scoped | Centralised root access (see below). Regional STS endpoints only. |

Two practical consequences. First, the workloads you test (EC2 instance profiles, ECS tasks, Lambda, EKS pods) all receive temporary credentials, so a leaked key starting with ASIA usually points at a compromised workload rather than a forgotten user. Second, **temporary credentials outlive the event that should have killed them**: deleting a user's access key does not by itself stop sessions already minted from it, and sessions created by the root user with `GetSessionToken` or `GetFederationToken` cannot be restricted at all. Revocation is covered in the [STS note](/cloud/aws-sts-cross-account-trust-federation/).

You can find the owning account of any access key ID with `aws sts get-access-key-info --access-key-id <ACCESS_KEY_ID>`; it is an ordinary STS call made with your own credentials, it does not use the key, and it says nothing about whether the key is active, inactive or deleted. `aws sts get-caller-identity` needs no permissions and cannot be denied, which makes it the standard benign proof that a credential works.

### Policy types

| Type | Attached to | Grants? | What it does |
|---|---|---|---|
| **Identity-based** (AWS managed, customer managed, inline) | User, group, role | Yes | The ordinary permissions of a principal. Inline policies live and die with their principal. |
| **Resource-based** | S3 buckets, KMS keys, SQS queues, SNS topics, Lambda functions, Secrets Manager secrets, ECR repositories, role trust policies and many more | Yes | Names the principals that may act on the resource; the only way to grant cross-account access without a role. |
| **Permissions boundary** | User or role | No (limits only) | Maximum permissions identity policies can grant to that entity. Used to delegate IAM administration safely. |
| **Service control policy (SCP)** | Organisation root, OU or account | No | Maximum permissions for principals in member accounts, including their root users. |
| **Resource control policy (RCP)** | Organisation root, OU or account | No | Maximum permissions on resources in member accounts, whoever the caller is; launched in November 2024 for a subset of services (S3, STS, KMS, SQS and Secrets Manager first, many more since). |
| **Session policy** | Passed when the session is created | No | Narrows a role session or federated user session. |
| **ACLs** | S3 (legacy), a few others | Yes | Pre-IAM cross-account grants; disabled by default on new S3 buckets. |

Declarative policies (December 2024) also live in AWS Organizations, but they enforce service *configuration* (for example EC2 settings such as IMDS defaults) rather than taking part in request authorisation; see the [Organizations note](/cloud/aws-organizations-multi-account-security/).

### Policy evaluation logic

Every request starts as an implicit deny (the root user of an account is the exception inside its own account). AWS gathers the request context (principal, action, resource, condition keys) and evaluates every applicable policy. The order below is what the IAM documentation describes for a request within a single account:

```text
request
  |
  v
[1] Any explicit Deny in SCPs, RCPs, resource policy, identity policies,
    permissions boundary or session policy?  ------------------- yes --> DENY
  | no
  v
[2] RCPs on the resource's account allow it?  (RCPFullAWSAccess if nothing else) -- no --> DENY
  v
[3] SCPs on the principal's account allow it? (FullAWSAccess if nothing else) ----- no --> DENY
  v
[4] Resource-based policy allows it?  ---- yes, and it names the IAM user or the
  |                                         session ARN directly --> ALLOW
  |                                    ---- yes, naming the role ARN --> continue,
  |                                         but boundary and session policy still apply
  v
[5] Identity-based policy allows it? ------------------------------------- no --> DENY
  v                                       (unless step 4 already allowed it)
[6] Permissions boundary present and silent?  ----------------------------- yes --> DENY
  v
[7] Session principal with a session policy that is silent? --------------- yes --> DENY
  v
ALLOW
```

The same logic as a table, which is the version to keep next to you during a review:

| Step | Policy type | Scope | If it does not allow | If it explicitly denies |
|---|---|---|---|---|
| 1 | All of them | Request | (n/a) | Final **Deny**, nothing overrides it |
| 2 | RCPs | Resources in member accounts, supported services only | Deny | Deny |
| 3 | SCPs | Principals in member accounts | Deny | Deny |
| 4 | Resource-based policy | The resource | Continue | Deny |
| 5 | Identity-based policies | The principal (user policies + group policies, or role policies) | Deny, unless step 4 granted directly | Deny |
| 6 | Permissions boundary | The user or role, if set | Deny | Deny |
| 7 | Session policy | Role sessions and federated user sessions, if passed | Deny | Deny |

Details that decide real findings:

- **Same account, resource policy versus identity policy is a union.** If a bucket policy in the same account names an IAM user or a specific role session, that grant works even if the principal's identity policies say nothing, and neither a permissions boundary nor a session policy limits it. If it names the **role ARN** (or uses `aws:PrincipalArn` with the role ARN), boundaries and session policies still apply. This is why a permissions boundary is not a complete containment control on its own.
- **Role trust policies and KMS key policies are exceptions**: they must explicitly allow the principal. A key policy that does not mention the account cannot be bypassed by an identity policy, which is a common cause of "admin cannot decrypt" confusion.
- **Cross-account requests need both sides.** AWS evaluates the request in the trusted (caller's) account, where the identity policy, SCPs, boundary and session policy must allow it, and in the trusting (resource's) account, where the resource policy and RCPs must allow it. Both evaluations must return Allow.
- **SCPs and RCPs do not touch the management account, or service-linked roles.** An over-privileged principal in the management account is therefore unconstrained by everything you put in Organizations. RCPs also do not apply to AWS managed KMS keys.
- **SCPs restrict member-account root users; RCPs restrict access to resources whoever the caller is, including principals outside the organisation and root users.** RCPs are the right tool for "nobody outside my organisation can use my S3 buckets or assume my roles"; SCPs are the right tool for "my own principals cannot do X".

### Actions, resources and the negative elements

`Action` and `Resource` are allow-lists. `NotAction` and `NotResource` invert them, and inversion is where people get hurt:

- **`Allow` + `NotAction`** grants every action in every AWS service *except* the listed ones, including services that do not exist yet. The AWS managed `PowerUserAccess` policy is the canonical example: it allows everything except `iam:*`, `organizations:*` and `account:*` (plus a few IAM read and service-linked role actions). A custom copy of that pattern that forgets `sts:*`, `kms:*` or `lambda:*` is usually far broader than its author intended.
- **`Allow` + `NotResource`** grants the action on every resource except the listed ones, in every account a wildcard could match.
- **`Deny` + `NotAction`** is a legitimate and common guardrail: "deny everything except these actions unless MFA is present".
- **Wildcards** match within a segment and across colons in ARNs. `iam:*` is full IAM administration, which is account administration. `s3:*Object*` matches `s3:PutObjectAcl` and `s3:DeleteObjectVersion`. `arn:aws:s3:::prod*` matches `prod-logs` and `production-backups`. An incomplete ARN in an identity policy is completed with wildcards, so `arn:aws:sqs` behaves like `arn:aws:sqs:*:*:*`.

### Conditions

A condition block is a set of `Operator: { key: value(s) }` tests. Values listed for one key are OR'd; different keys and different operators are AND'd. The details that create findings:

| Construct | Behaviour | Pitfall |
|---|---|---|
| `StringEquals` vs `StringLike` | `StringLike` honours `*` and `?` | `StringEquals` with a `*` in the value matches a literal asterisk, so the condition silently never matches (Access Analyzer flags this). |
| `ArnLike` vs `StringLike` on ARN keys | Use the ARN operators for `aws:SourceArn`, `aws:PrincipalArn` | Access Analyzer reports `StringLike` on ARN keys as a security warning. |
| `...IfExists` | If the key is absent, the condition evaluates to **true** | Fine in a `Deny`; in an `Allow` it means "allowed whenever the key is missing". |
| `Null` | `"Null": {"key": "true"}` matches when the key is absent | The safe companion to set operators and `IfExists`. |
| `ForAllValues:` | True if every value in the request is in the policy's set, **and also true if the key is missing or empty** | `Allow` + `ForAllValues` without a `Null` check allows requests that omit the key entirely. |
| `ForAnyValue:` | True if at least one request value matches; false if the key is missing | `Deny` + `ForAnyValue` does not deny requests that omit the key. |
| Set operators on single-valued keys | AWS says do not do it | `ForAllValues` on a single-valued key such as `aws:PrincipalOrgID` or `aws:SourceVpc` is a classic over-permissive mistake; Access Analyzer reports it. |
| `aws:MultiFactorAuthPresent` | Absent for requests signed with long-term access keys | `"Bool": {"aws:MultiFactorAuthPresent": "false"}` in a `Deny` does not catch CLI requests made with an access key; use `BoolIfExists`. |
| `aws:SourceIp` | The caller's public IP | Absent when the request comes through a VPC endpoint and different when an AWS service calls on the principal's behalf; deny-by-IP policies need `aws:ViaAWSService` handling. |
| `aws:UserAgent`, `aws:Referer` | Supplied by the caller | Spoofable; Access Analyzer reports them as untrustworthy for access control. |

### iam:PassRole

Many services act with a role you give them: EC2 instance profiles, Lambda execution roles, ECS task roles, CloudFormation service roles, Glue jobs, SageMaker notebooks, Step Functions state machines. To give a role to a service you need `iam:PassRole` on that role. PassRole is a **permission, not an API call**: it is checked when you call `RunInstances`, `CreateFunction`, `CreateStack` and so on, and it never appears as its own CloudTrail event. Anyone who can pass a privileged role to compute they control can act as that role, so `iam:PassRole` on `"Resource": "*"` combined with any "create compute" action is a privilege escalation path. Scope it with the role ARN and the `iam:PassedToService` condition key (and `iam:AssociatedResourceArn` where the service supports it).

### The root user

The root user can do everything in its account, cannot be limited by IAM policies, and has a few tasks only it can perform (closing a standalone account, changing some account settings, restoring IAM permissions if an administrator locks everyone out, enabling S3 MFA delete). The current state of root controls:

- **MFA is enforced** for the root user of all account types (standalone, management, member). AWS states that users must register MFA within 14 days of their first console sign-in attempt if it is not already enabled; check the current documentation for the rollout details. Up to eight MFA devices can be registered; FIDO security keys (including passkeys) are supported.
- **No access keys.** AWS's guidance is unchanged: do not create them. For rare programmatic root tasks AWS now points to signing in with the `aws login` CLI command, which yields temporary credentials.
- **Centralised root access management** (November 2024) lets the management account or an IAM delegated administrator remove root credentials from member accounts, block their recovery, and run a small set of root-only tasks through short task-scoped sessions (`sts:AssumeRoot` with task policies such as `IAMAuditRootUserCredentials`, `IAMDeleteRootUserCredentials`, `IAMCreateRootUserPassword`, `S3UnlockBucketPolicy` and `SQSUnlockQueuePolicy`). Once enabled, new member accounts are created without root credentials.

### Where visibility comes from

| Source | What it tells you | Freshness |
|---|---|---|
| Credential report (`GenerateCredentialReport`) | Per-user CSV: password, MFA, two access key slots, last use, certificates; plus a `<root_account>` row | Regenerated at most every four hours |
| Last accessed data (`GenerateServiceLastAccessedDetails`) | Which services, and for some services which actions, a user, role, group or policy last used | 400-day tracking window; action-level data for a subset of services |
| `RoleLastUsed` on `GetRole` | Last time and Region a role was assumed and used | Approximately current |
| IAM Access Analyzer external access | Resources shared outside the zone of trust (account or organisation) | Continuous, free |
| IAM Access Analyzer internal access | Access paths from principals inside the zone of trust to selected resources | Continuous, charged per resource |
| IAM Access Analyzer unused access | Unused roles, unused user passwords and keys, unused service- and action-level permissions | Continuous, charged per principal |
| IAM Access Analyzer policy validation | Grammar errors, security warnings, suggestions for a policy document | On demand, free |
| IAM policy simulator (`SimulatePrincipalPolicy`) | Allow or deny for given actions and resources, including SCPs and boundaries | On demand; does not evaluate RCPs |

## What goes wrong

**Humans with long-lived access keys.** IAM users created for people "temporarily" years ago, with active keys sitting in laptops, CI variables and shell histories. Each is a standing credential that works from anywhere until someone deletes it. Leaked keys are the most common initial access in AWS incidents. Why it matters: no expiry, no device binding, often no MFA on API use.

**Root credentials that exist and get used.** Root access keys, root without MFA, root used for daily administration, or a root mailbox owned by one person who has left. Why it matters: root cannot be limited by IAM, and in the management account not even by SCPs.

**Missing MFA on console users.** Passwords alone, often reused, against a sign-in page that is the same for every AWS account. Why it matters: one phished or sprayed password becomes console access with that user's permissions.

**Over-broad allows.** `"Action": "*"` on `"Resource": "*"` outside break-glass roles, `iam:*` on workload roles, service-wide wildcards (`s3:*`, `kms:*`, `secretsmanager:*`) on `*`, and `Allow` + `NotAction` statements. Why it matters: the blast radius of any compromise of that principal becomes the whole account, and `iam:*` turns any foothold into administrator.

**Privilege-escalation-capable permissions without full admin.** `iam:CreatePolicyVersion`, `iam:AttachRolePolicy`, `iam:PutUserPolicy`, `iam:UpdateAssumeRolePolicy`, `iam:CreateAccessKey` on other users, `iam:PassRole` plus a compute create action, and dozens more. Why it matters: these are admin by another name. The full catalogue and how to verify each is in the [privilege escalation note](/cloud/aws-iam-privilege-escalation/).

**Condition logic that does not mean what it says.** `ForAllValues` in an `Allow` without a `Null` check, `IfExists` in an `Allow`, MFA conditions that skip access-key requests, IP conditions that break when traffic comes through a VPC endpoint, spoofable keys used as security controls. Why it matters: the policy reads as restricted in review and behaves as unrestricted in production.

**Sprawl.** Hundreds of inline policies, policies attached directly to users, near-duplicate customer managed policies with five versions each, and nobody who can say what a role is for. Why it matters: sprawl hides the dangerous statement, makes least privilege impossible to reason about, and slows incident response.

**Unused identities and permissions.** Roles not assumed in a year, users who left, keys never used, permissions granted "in case". Why it matters: every unused path is attack surface with no business value, and stale credentials are the ones nobody notices being used.

**No guardrails.** No SCPs beyond `FullAWSAccess`, no RCPs, no permissions boundaries on delegated administrators, no Access Analyzer. Why it matters: one mistake in one identity policy is the whole story, with nothing behind it.

**Weak password policy.** Short minimum length, no reuse prevention. Why it matters less than it used to (federation and MFA are the real fix), but it still decides how much a password spray is worth when IAM users with console access exist.

## Testing

*All tests assume an authorised engagement against the client's own AWS accounts, with written scope, and respect for AWS's [penetration testing policy](https://aws.amazon.com/security/penetration-testing/). Commands are read-only unless marked otherwise. Outputs shown are illustrative; we ran nothing against a real account to produce them.*

### Before you start

**Permissions.** Ask for a role with the AWS managed `SecurityAudit` and `ViewOnlyAccess` policies in every in-scope account, assumed from your own identity with MFA. If the audit role lacks them, request these additions explicitly: `iam:GenerateCredentialReport`, `iam:GetCredentialReport`, `iam:GenerateServiceLastAccessedDetails`, `iam:GetServiceLastAccessedDetails`, `iam:SimulatePrincipalPolicy`, `access-analyzer:ValidatePolicy`, `access-analyzer:ListAnalyzers`, `access-analyzer:ListFindingsV2`. For organisation-wide checks (SCPs, RCPs, centralised root access) you need read access in the management account or the relevant delegated administrator account.

**Profiles and identity check.**

```bash
export AWS_PROFILE=client-audit
aws sts get-caller-identity
aws iam list-account-aliases --query 'AccountAliases' --output text
```

**IAM is global; some related services are regional.** IAM, the credential report and the simulator are global. IAM Access Analyzer analyzers and CloudTrail event history are regional. Loop over enabled Regions where needed:

```bash
for r in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text); do
  echo "== $r"
  aws accessanalyzer list-analyzers --region "$r" \
    --query 'analyzers[].[name,type,status]' --output text
done
```

**One snapshot of everything IAM.** Most tests below read this file rather than calling the API hundreds of times:

```bash
aws iam get-account-authorization-details --output json > gaad.json
jq '{users: (.UserDetailList|length), groups: (.GroupDetailList|length),
     roles: (.RoleDetailList|length), policies: (.Policies|length)}' gaad.json
```

**Tools.** [Prowler](https://github.com/prowler-cloud/prowler) (`prowler aws --services iam`), [ScoutSuite](https://github.com/nccgroup/ScoutSuite), [cloudsplaining](https://github.com/salesforce/cloudsplaining) for least-privilege analysis of the GAAD output, [PMapper](https://github.com/nccgroup/PMapper) and [CloudFox](https://github.com/BishopFox/cloudfox) for graph and permission views, Pacu's read-only enumeration modules (`iam__enum_users_roles_policies_groups`, `iam__enum_permissions`, `iam__get_credential_report`), and Steampipe if the client prefers SQL. For hands-on practice before an engagement: [CloudGoat](https://github.com/RhinoSecurityLabs/cloudgoat), [IAM Vulnerable](https://github.com/BishopFox/iam-vulnerable) and [flaws.cloud](http://flaws.cloud/).

### GT-AWS-IAM-1: Credential report review

*Guler Tech methodology.*

#### What it checks

Every IAM user and the root user: who has a password, who has MFA, which access keys are active, how old they are, and when each was last used. It is the single most efficient IAM artefact and the starting point for tests 2 to 6.

#### Prerequisites

`iam:GenerateCredentialReport` and `iam:GetCredentialReport` (both in `SecurityAudit`).

#### Steps

```bash
aws iam generate-credential-report
# repeat until State is COMPLETE
aws iam generate-credential-report --query State --output text
aws iam get-credential-report --query Content --output text | base64 --decode > credreport.csv
head -1 credreport.csv | tr ',' '\n' | nl
```

Summarise it with a short script so you work by column name, not position:

```python
import csv, datetime as dt
now = dt.datetime.now(dt.timezone.utc)
def age(v):
    if v in ("N/A", "no_information", "not_supported", ""):
        return None
    return (now - dt.datetime.fromisoformat(v.replace("Z", "+00:00"))).days
for r in csv.DictReader(open("credreport.csv")):
    keys = []
    for n in ("1", "2"):
        if r[f"access_key_{n}_active"] == "true":
            keys.append(f"k{n}: rotated {age(r[f'access_key_{n}_last_rotated'])}d, "
                        f"used {age(r[f'access_key_{n}_last_used_date'])}d, "
                        f"svc {r[f'access_key_{n}_last_used_service']}")
    print(r["user"], "| pwd", r["password_enabled"], "last", age(r["password_last_used"]),
          "| mfa", r["mfa_active"], "|", "; ".join(keys) or "no active keys",
          "| extra", r.get("additional_credentials_info", ""))
```

Run it with `python3 -I summarise.py`. A user with more credentials than the report's two key slots and two certificate slots shows it in `additional_credentials_info`; use `aws iam list-access-keys --user-name <user>` for the full list.

#### Observation

Illustrative output:

```text
<root_account> | pwd not_supported last 3 | mfa true | no active keys | extra
ci-deploy | pwd false last None | mfa false | k1: rotated 1104d, used 0d, svc s3 | extra
j.smith | pwd true last 412 | mfa false | k1: rotated 690d, used 380d, svc iam | extra
breakglass-01 | pwd true last 201 | mfa true | no active keys | extra
```

#### Evaluation

Record, per user: console access without MFA (test 3), credentials unused for 45 days or more (test 5), active keys older than 90 days (test 6), human users with keys at all, and anything on the `<root_account>` row (test 2). The report itself is not a finding; each pattern is. A healthy account in 2026 has few or no IAM users: humans come in through Identity Center or another IdP, and the remaining users are documented exceptions (a third-party tool that cannot assume roles, a break-glass user with hardware MFA and no keys).

#### Automated coverage

Security Hub CSPM `IAM.3`, `IAM.5`, `IAM.8`, `IAM.22` (all built on the credential report via AWS Config). Prowler `iam_user_mfa_enabled_console_access`, `iam_user_accesskey_unused`, `iam_user_console_access_unused`, `iam_rotate_access_key_90_days`, `iam_user_two_active_access_key`, `iam_user_no_setup_initial_access_key`.

#### Detection

Generating and downloading the report are themselves logged (`GenerateCredentialReport`, `GetCredentialReport`) and are a common reconnaissance step after credential theft; alert on them from principals that are not your audit or security tooling roles.

### GT-AWS-IAM-2: Root user credentials, MFA and usage

*Guler Tech methodology.*

#### What it checks

Whether each account's root user has MFA (and, for the accounts that matter most, phishing-resistant or hardware MFA), has no access keys or signing certificates, is not being used for routine work, and whether the organisation has taken root credentials away from member accounts altogether.

#### Prerequisites

`SecurityAudit` in each account; read access to CloudTrail event history or the organisation trail; for the organisation-level check, the management account or IAM delegated administrator.

#### Steps

Account summary flags (per account):

```bash
aws iam get-account-summary --query 'SummaryMap.{MFA:AccountMFAEnabled,Keys:AccountAccessKeysPresent,Password:AccountPasswordPresent,Certs:AccountSigningCertificatesPresent}'
```

Is the root MFA a virtual device? A virtual device assigned to root shows the root ARN as its user:

```bash
aws iam list-virtual-mfa-devices --assignment-status Assigned --output json \
  | jq -r '.VirtualMFADevices[] | select(.User.Arn | endswith(":root")) | .SerialNumber'
```

Recent root activity (90 days of management events, per Region; console sign-ins for the root user typically appear in `us-east-1`):

```bash
for r in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text); do
  aws cloudtrail lookup-events --region "$r" --max-results 50 \
    --lookup-attributes AttributeKey=Username,AttributeValue=root --output json \
  | jq -r --arg r "$r" '.Events[].CloudTrailEvent | fromjson
      | select(.userIdentity.type == "Root")
      | [$r, .eventTime, .eventName, .sourceIPAddress, (.userAgent // "")] | @tsv'
done
```

For longer history, query the organisation trail in Athena or CloudTrail Lake for `userIdentity.type = 'Root'`.

Organisation-level: has centralised root access management been enabled, and which member accounts still have root credentials?

```bash
# from the management account or the IAM delegated administrator
aws iam list-organizations-features
```

To audit a member account's root credentials without anyone signing in as root, the privileged-session path exists, but it uses a highly privileged API; treat it as **explicitly approved only** even though the task policy is read-only:

```bash
aws sts assume-root --region eu-west-2 \
  --target-principal 111122223333 \
  --task-policy-arn arn=arn:aws:iam::aws:policy/root-task/IAMAuditRootUserCredentials \
  --duration-seconds 900
# with the returned credentials:
aws iam get-login-profile
aws iam list-access-keys
aws iam list-mfa-devices
```

#### Observation

Illustrative output for a weak account:

```text
{"MFA": 0, "Keys": 1, "Password": 1, "Certs": 0}
us-east-1  2026-10-02T08:14:51Z  ConsoleLogin  203.0.113.20  Mozilla/5.0 ...
eu-west-2  2026-10-02T08:19:03Z  RunInstances  203.0.113.20  console.amazonaws.com
```

And for a well-managed organisation: `EnabledFeatures` lists `RootCredentialsManagement` and `RootSessions`, member accounts show no root password, keys or MFA devices, and the only root events in a year are the management account's documented annual check.

#### Evaluation

- **Fail (Critical):** root access keys exist in any account (`AccountAccessKeysPresent: 1`). Treat as Critical regardless of whether they have been used: they are unrestricted, long-lived, and in the management account not even bounded by SCPs.
- **Fail (High):** root has no MFA, or root is used for routine actions (anything other than the documented root-only tasks).
- **Fail (Medium):** the management account root (or any account holding production data) uses only virtual MFA where the client's policy calls for hardware or phishing-resistant MFA; organisation exists but centralised root access is not enabled and member accounts keep root passwords.
- **Pass:** MFA on every root user that still has credentials, no keys or certificates, no unexplained root events, centralised root access enabled with member root credentials removed, and an alert on root use.

Do not attempt to sign in as root or test root password reset; ownership of the root mailbox and MFA is a process question for the client.

#### Automated coverage

Security Hub CSPM `IAM.4` (root access key), `IAM.9` (root MFA), `IAM.6` (hardware MFA for root), `CloudWatch.1` (metric filter and alarm for root use; CIS v1.4.0 4.3). Prowler `iam_no_root_access_key`, `iam_root_mfa_enabled`, `iam_root_hardware_mfa_enabled`, `iam_avoid_root_usage`, `iam_root_credentials_management_enabled`.

#### Detection

CloudTrail `userIdentity.type = "Root"` on any event, `ConsoleLogin` by root, `CreateAccessKey` or `DeactivateMFADevice` by root, `AssumeRoot` (privileged root sessions), `GetSessionToken` called by root. GuardDuty `Policy:IAMUser/RootCredentialUsage` and `Policy:IAMUser/ShortTermRootCredentialUsage` (the latter for restricted root sessions).

### GT-AWS-IAM-3: MFA coverage for human principals

*Guler Tech methodology.*

#### What it checks

That every human who can reach the console has MFA, and that privileged API actions by IAM users require MFA in practice, not just on paper.

#### Prerequisites

Credential report from test 1; GAAD snapshot.

#### Steps

Console users without MFA:

```bash
python3 -I - <<'EOF'
import csv
for r in csv.DictReader(open("credreport.csv")):
    if r["user"] != "<root_account>" and r["password_enabled"] == "true" and r["mfa_active"] == "false":
        print(r["user"], r["password_last_used"])
EOF
```

Users with any credential but no MFA (IAM.19's wider view), and the MFA device types in use:

```bash
aws iam list-users --query 'Users[].UserName' --output text | tr '\t' '\n' | while read -r u; do
  printf '%s\t%s\n' "$u" "$(aws iam list-mfa-devices --user-name "$u" --query 'length(MFADevices)')"
done
```

Then read the policies that are supposed to enforce MFA. Look for the self-service MFA pattern (deny everything except MFA enrolment when MFA is absent) and check its condition operator:

```bash
jq -r '.. | objects | select(has("Condition")) | select(.Condition | tostring | test("MultiFactorAuthPresent"))
       | {Effect, Condition}' gaad.json | head -50
```

#### Observation

A deny that uses `"Bool": {"aws:MultiFactorAuthPresent": "false"}` instead of `BoolIfExists` is the frequent finding: it blocks console sessions without MFA but lets every request signed with the user's long-term access key straight through, because that key is not present in such requests.

#### Evaluation

- **Fail:** any console-enabled IAM user without MFA; privileged IAM users (any with IAM write, `*:*`, or access to production data) without MFA; MFA enforcement policies that use `Bool` rather than `BoolIfExists` and therefore do not cover access keys.
- **Pass:** no console IAM users (all humans federated), or every console user has MFA and enforcement policies are correct.
- **Context:** IAM Identity Center MFA settings live in the Identity Center console (and in the external IdP when one is used); record them separately. An IdP with weak MFA undermines everything else in this test.

#### Automated coverage

Security Hub CSPM `IAM.5`, `IAM.19`. Prowler `iam_user_mfa_enabled_console_access`, `iam_user_hardware_mfa_enabled`, `iam_administrator_access_with_mfa`.

#### Detection

`DeactivateMFADevice`, `DeleteVirtualMFADevice`, `ResyncMFADevice`, `EnableMFADevice` (an attacker enrolling their own device on a compromised user); `ConsoleLogin` with `additionalEventData.MFAUsed = "No"` (Security Hub `CloudWatch.3` covers a metric filter for it, CIS v1.2.0 3.2). GuardDuty `UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B` and `InitialAccess:IAMUser/AnomalousBehavior`.

### GT-AWS-IAM-4: Account password policy

*Guler Tech methodology.*

#### What it checks

The IAM account password policy for IAM users with console passwords.

#### Prerequisites

`iam:GetAccountPasswordPolicy`.

#### Steps

```bash
aws iam get-account-password-policy
```

`NoSuchEntity` means no custom policy, so the default applies: 8 to 128 characters, at least three of four character classes, not equal to the account name or email, never expires.

#### Observation

```json
{
  "PasswordPolicy": {
    "MinimumPasswordLength": 8,
    "RequireSymbols": false,
    "RequireNumbers": true,
    "RequireUppercaseCharacters": true,
    "RequireLowercaseCharacters": true,
    "AllowUsersToChangePassword": true,
    "ExpirePasswords": false,
    "PasswordReusePrevention": 0
  }
}
```

#### Evaluation

- **Fail:** `MinimumPasswordLength` below 14 or no `PasswordReusePrevention` (CIS asks for 24) while console IAM users exist.
- **Low or Info:** the same weaknesses with no console IAM users (the policy then protects nothing today, but will the day someone creates a user).
- Mandatory expiry is a client-policy question; NIST SP 800-63B guidance no longer recommends periodic expiry, while Security Hub `IAM.17` (CIS v1.2.0) still checks for 90 days. Report the gap against whichever standard the client follows, and say which.

#### Automated coverage

Security Hub CSPM `IAM.7`, `IAM.10`, `IAM.11` to `IAM.17`. Prowler `iam_password_policy_minimum_length_14`, `iam_password_policy_reuse_24`, `iam_password_policy_uppercase`, `iam_password_policy_lowercase`, `iam_password_policy_number`, `iam_password_policy_symbol`, `iam_password_policy_expires_passwords_within_90_days_or_less`.

#### Detection

`UpdateAccountPasswordPolicy`, `DeleteAccountPasswordPolicy`. GuardDuty `Stealth:IAMUser/PasswordPolicyChange`.

### GT-AWS-IAM-5: Unused users, keys, roles and permissions

*Guler Tech methodology.*

#### What it checks

Credentials and identities that exist but are not used, and permissions that roles hold but never exercise.

#### Prerequisites

Credential report; `iam:GetRole`; `iam:GenerateServiceLastAccessedDetails`; IAM Access Analyzer read access. Creating a new unused access analyzer is **state-changing and billable: lab or explicitly approved only**.

#### Steps

Users with a password or active key unused for 45 days or more come straight from the credential report (test 1). Roles: `ListRoles` does not return `RoleLastUsed`, so call `GetRole` per role:

```bash
aws iam list-roles --query 'Roles[].RoleName' --output text | tr '\t' '\n' | while read -r role; do
  aws iam get-role --role-name "$role" \
    --query '[Role.RoleName, Role.Path, Role.RoleLastUsed.LastUsedDate, Role.RoleLastUsed.Region]' \
    --output text
done | sort -k3 > role-last-used.tsv
```

Service-level and action-level last accessed for a role or policy:

```bash
JOB=$(aws iam generate-service-last-accessed-details \
  --arn arn:aws:iam::111122223333:role/app-deployer --granularity ACTION_LEVEL \
  --query JobId --output text)
aws iam get-service-last-accessed-details --job-id "$JOB" \
  --query 'ServicesLastAccessed[].[ServiceNamespace,LastAuthenticated,TotalAuthenticatedEntities]' \
  --output table
```

If the client already runs an unused access analyzer, read its findings:

```bash
ARN=$(aws accessanalyzer list-analyzers --type ACCOUNT_UNUSED_ACCESS \
  --query 'analyzers[0].arn' --output text)
aws accessanalyzer list-findings-v2 --analyzer-arn "$ARN" \
  --query 'findings[?status==`ACTIVE`].[findingType,resource]' --output text | sort | uniq -c | sort -rn
```

Finding types are `UnusedIAMRole`, `UnusedIAMUserAccessKey`, `UnusedIAMUserPassword` and `UnusedPermission`. With approval, an analyzer can be created for the duration of the test:

```bash
# lab or explicitly approved only: creates a billable resource
aws accessanalyzer create-analyzer --analyzer-name gt-unused-90 \
  --type ACCOUNT_UNUSED_ACCESS --configuration '{"unusedAccess": {"unusedAccessAge": 90} }'
```

#### Observation

Typical results: roles under `/` with no `LastUsedDate` at all (created and never assumed), roles last used in another Region years ago, a deployment role whose last accessed data shows two services used out of forty allowed.

#### Evaluation

- **Fail:** IAM users with credentials unused for 45 days or more (Security Hub's threshold; CIS v5.0.0 1.11), roles unused for 90 days or more with privileged permissions or cross-account trust, users belonging to people who have left.
- **Observation (least privilege):** large gaps between granted and used services on privileged roles. These feed the remediation plan rather than standing as findings on their own, unless the unused permissions are escalation-capable.
- **False positives:** break-glass users and roles (should be unused, documented, alarmed), disaster recovery roles, roles used once a year by audit, service-linked roles. Last accessed data does not record use of permissions granted only by a resource policy.

#### Automated coverage

Security Hub CSPM `IAM.8` (90 days, CIS v1.2.0 1.3), `IAM.22` (45 days; CIS v1.4.0 1.12, v3.0.0 1.12, v5.0.0 1.11). Prowler `iam_user_accesskey_unused`, `iam_user_console_access_unused`. IAM Access Analyzer unused access findings.

#### Detection

First use of a long-dormant key or role is a strong signal: GuardDuty `InitialAccess:IAMUser/AnomalousBehavior` and `CredentialAccess:IAMUser/CompromisedCredentials`; in CloudTrail, any event from an access key ID whose previous use was months ago.

### GT-AWS-IAM-6: Access key age, rotation and long-lived key use

*Guler Tech methodology.*

#### What it checks

Whether active access keys are old, whether they belong to humans or workloads, where and for what they are used, and whether a workload could use a role instead.

#### Prerequisites

Credential report; `iam:ListAccessKeys`, `iam:GetAccessKeyLastUsed`.

#### Steps

```bash
aws iam list-users --query 'Users[].UserName' --output text | tr '\t' '\n' | while read -r u; do
  aws iam list-access-keys --user-name "$u" --output json \
  | jq -r --arg u "$u" '.AccessKeyMetadata[] | select(.Status=="Active") | [$u, .AccessKeyId, .CreateDate] | @tsv' \
  | while IFS=$'\t' read -r user kid created; do
      last=$(aws iam get-access-key-last-used --access-key-id "$kid" \
        --query '[AccessKeyLastUsed.LastUsedDate,AccessKeyLastUsed.ServiceName,AccessKeyLastUsed.Region]' --output text)
      printf '%s\t%s\t%s\t%s\n' "$user" "$created" "$last" "${kid:0:4}..."
    done
done
```

Print only the key ID prefix in your working notes and the report; the full ID is not secret, but there is no reason to spread it.

For each workload key, ask where it runs. If the answer is EC2, ECS, EKS, Lambda, CodeBuild, or GitHub Actions, it can use a role or OIDC federation instead; if it is on-premises, IAM Roles Anywhere is the usual replacement.

#### Observation

```text
ci-deploy     2023-11-02T10:04:00Z  2026-11-11T22:10:00Z  cloudformation  eu-west-2  AKIA...
j.smith       2024-12-19T09:00:00Z  2025-10-28T13:44:00Z  iam             us-east-1  AKIA...
```

#### Evaluation

- **Fail:** active keys older than 90 days (Security Hub `IAM.3`, CIS v5.0.0 1.13); human IAM users with active keys and no MFA-enforced use; keys on users with administrative or IAM-write permissions; keys created at the same time as the user (`iam_user_no_setup_initial_access_key`) and never rotated.
- **Higher severity:** an old key with `iam:*` or `*:*`, or a key whose last used service or Region does not fit its stated purpose (possible misuse; escalate to the client before going further).
- **Pass:** no long-lived keys for humans; workload keys exist only where no role-based option exists, are scoped tightly, rotated, and stored in a secrets manager.

Rotation is a mitigation, not a fix. A leaked key that is rotated every 90 days is still valid for up to 90 days; the fix is no long-lived key.

#### Automated coverage

Security Hub CSPM `IAM.3`. Prowler `iam_rotate_access_key_90_days`, `iam_user_two_active_access_key`, `iam_user_with_temporary_credentials`, `iam_user_no_setup_initial_access_key`. For keys leaked outside AWS, see the [unauthenticated recon note](/cloud/aws-unauthenticated-recon/) (trufflehog, gitleaks); for keys in mobile apps, [MASWE-0004](/mobile/maswe-0004-sensitive-data-hardcoded-app-package/).

#### Detection

`CreateAccessKey` (especially for a user other than the caller: `requestParameters.userName` differs from `userIdentity.userName`), `UpdateAccessKey`, `DeleteAccessKey`. GuardDuty `CredentialAccess:IAMUser/CompromisedCredentials`, `UnauthorizedAccess:IAMUser/MaliciousIPCaller`, `Persistence:IAMUser/AnomalousBehavior`, and the Extended Threat Detection sequence `AttackSequence:IAM/CompromisedCredentials`.

### GT-AWS-IAM-7: Over-broad policy statements

*Guler Tech methodology.*

#### What it checks

Allow statements that grant far more than any principal should need: full administrator, full IAM, service-wide wildcards, `NotAction` and `NotResource` allows.

#### Prerequisites

`gaad.json` from [Before you start](#before-you-start).

#### Steps

Customer managed policies (default version only), with attachment count:

```bash
jq -r '
  .Policies[] | . as $p
  | .PolicyVersionList[] | select(.IsDefaultVersion)
  | .Document.Statement | (if type=="array" then .[] else . end)
  | select(.Effect=="Allow")
  | select(
      has("NotAction") or has("NotResource")
      or ((.Action // []) | (if type=="string" then [.] else . end)
          | any(. == "*" or . == "iam:*" or test("^[A-Za-z0-9-]+:\\*$")))
    )
  | [$p.PolicyName, ($p.AttachmentCount|tostring),
     ((.Action // .NotAction)|tostring), ((.Resource // .NotResource)|tostring)] | @tsv
' gaad.json
```

Inline policies on users, groups and roles:

```bash
jq -r '
  ( .UserDetailList[]  | {who: .Arn, pols: (.UserPolicyList  // [])} ),
  ( .GroupDetailList[] | {who: .Arn, pols: (.GroupPolicyList // [])} ),
  ( .RoleDetailList[]  | {who: .Arn, pols: (.RolePolicyList  // [])} )
  | . as $e | $e.pols[]
  | .PolicyName as $n
  | .PolicyDocument.Statement | (if type=="array" then .[] else . end)
  | select(.Effect=="Allow")
  | select(has("NotAction") or ((.Action // []) | (if type=="string" then [.] else . end)
                                 | any(. == "*" or . == "iam:*" or test("^[A-Za-z0-9-]+:\\*$"))))
  | [$e.who, $n, ((.Action // .NotAction)|tostring), ((.Resource // .NotResource)|tostring)] | @tsv
' gaad.json
```

Who has the AWS managed high-privilege policies:

```bash
for p in AdministratorAccess IAMFullAccess PowerUserAccess AWSCloudShellFullAccess; do
  echo "== $p"
  aws iam list-entities-for-policy --policy-arn "arn:aws:iam::aws:policy/$p" \
    --query '{users:PolicyUsers[].UserName,groups:PolicyGroups[].GroupName,roles:PolicyRoles[].RoleName}' --output json
done
```

For a ranked view, run cloudsplaining on an exported snapshot: `cloudsplaining download --profile client-audit` then `cloudsplaining scan --input-file default.json`. It flags privilege escalation, resource exposure, data exfiltration and infrastructure modification actions per policy.

#### Observation

Illustrative:

```text
legacy-ops        3   ["*"]                    "*"
DeveloperAccess   12  ["iam","organizations"]  "*"        <- NotAction allow
app-deployer-inl  -   ["s3:*","kms:*"]          "*"
```

`DeveloperAccess` above is a hand-written copy of `PowerUserAccess` attached to twelve principals; because it is an `Allow` with `NotAction`, it also grants `sts:AssumeRole` on every role in the account, `lambda:*`, `ec2:*` and every service launched after it was written.

#### Evaluation

- **Fail (High to Critical):** `"*"` on `"*"` attached to workload roles, CI roles, or human users outside a documented break-glass or platform-admin role; `iam:*` or IAM write actions on `*` for non-IAM-admin principals; `Allow` + `NotAction` on `*` outside the AWS managed `PowerUserAccess` assigned to a known group. Severity depends on who can obtain the principal: a role assumable from a CI system or an internet-facing workload is worse than a human admin role behind MFA.
- **Fail (Medium):** service-wide wildcards (`s3:*`, `kms:*`, `secretsmanager:*`, `dynamodb:*`) on `"Resource": "*"` for application roles.
- **Pass:** full admin limited to break-glass and a small platform-admin role with MFA; workload roles scoped to their resources.
- Read every hit in context: a `Deny` + `NotAction` is usually a guardrail, and an admin policy behind a permissions boundary or an SCP is less severe than it looks, which is what test 11 confirms.

#### Automated coverage

Security Hub CSPM `IAM.1` (customer managed policies with `*` on `*`; CIS v1.2.0 1.22, v1.4.0 1.16; does not check inline or AWS managed policies), `IAM.21` (service-wide wildcards in customer managed policies), `IAM.27` (`AWSCloudShellFullAccess`). Prowler `iam_customer_attached_policy_no_administrative_privileges`, `iam_customer_unattached_policy_no_administrative_privileges`, `iam_inline_policy_no_administrative_privileges`, `iam_aws_attached_policy_no_administrative_privileges`, `iam_role_administratoraccess_policy`, `iam_user_administrator_access_policy`, `iam_group_administrator_access_policy`, `iam_policy_no_full_access_to_kms`, `iam_policy_no_full_access_to_cloudtrail`.

#### Detection

Changes that create or widen such statements: `CreatePolicy`, `CreatePolicyVersion`, `SetDefaultPolicyVersion`, `PutUserPolicy`, `PutRolePolicy`, `PutGroupPolicy`, `AttachUserPolicy`, `AttachRolePolicy`, `AttachGroupPolicy` (Security Hub `CloudWatch.4` covers a metric filter for IAM policy changes; CIS v1.4.0 4.4). GuardDuty `PrivilegeEscalation:IAMUser/AnomalousBehavior`, `Persistence:IAMUser/AnomalousBehavior`.

### GT-AWS-IAM-8: Inline and direct-attachment sprawl

*Guler Tech methodology.*

#### What it checks

How permissions are attached: directly to users rather than groups or roles, as inline policies rather than managed ones, in unattached or multi-version customer managed policies, and with no permissions boundary on principals that can create other principals.

#### Prerequisites

`gaad.json`.

#### Steps

```bash
# users with policies attached directly (IAM.2)
jq -r '.UserDetailList[] | select(((.UserPolicyList//[])|length) + ((.AttachedManagedPolicies//[])|length) > 0)
       | [.UserName, ((.UserPolicyList//[])|length), ((.AttachedManagedPolicies//[])|length)] | @tsv' gaad.json

# inline policy counts per principal type
jq '{user_inline: ([.UserDetailList[].UserPolicyList[]?]|length),
     group_inline: ([.GroupDetailList[].GroupPolicyList[]?]|length),
     role_inline: ([.RoleDetailList[].RolePolicyList[]?]|length)}' gaad.json

# customer managed policies that are unattached, or keep old versions
jq -r '.Policies[] | select(.AttachmentCount == 0 or (.PolicyVersionList|length) > 1)
       | [.PolicyName, .AttachmentCount, (.PolicyVersionList|length), .DefaultVersionId] | @tsv' gaad.json

# roles and users with a permissions boundary
jq -r '(.UserDetailList[], .RoleDetailList[]) | select(.PermissionsBoundary)
       | [.Arn, .PermissionsBoundary.PermissionsBoundaryArn] | @tsv' gaad.json
```

#### Observation

Unattached policies with admin statements and non-default versions matter more than they look: a principal with `iam:SetDefaultPolicyVersion` can switch an attached policy back to an old, broader version without creating anything new.

#### Evaluation

- **Fail (Low):** IAM users with directly attached or inline policies (Security Hub `IAM.2`; CIS v5.0.0 1.14).
- **Fail (Medium):** principals with IAM write permissions (creating users or roles, attaching policies) and no permissions boundary or equivalent SCP; old policy versions broader than the default version where any principal holds `iam:SetDefaultPolicyVersion`.
- **Observation:** inline-heavy estates, duplicated policies, no naming or tagging. Report as maintainability and review-ability risk with concrete counts.

#### Automated coverage

Security Hub CSPM `IAM.2`, `IAM.24` and `IAM.25` (tagging of roles and users). Prowler `iam_policy_attached_only_to_group_or_roles`, `iam_inline_policy_allows_privilege_escalation`.

#### Detection

`PutUserPolicy`, `PutRolePolicy`, `PutGroupPolicy`, `SetDefaultPolicyVersion`, `DeleteRolePermissionsBoundary`, `DeleteUserPermissionsBoundary`, `PutRolePermissionsBoundary`.

### GT-AWS-IAM-9: Policy validation and condition logic

*Guler Tech methodology.*

#### What it checks

Whether policies parse and behave as their authors think: Access Analyzer's grammar and security checks across every customer managed, inline and trust policy, followed by a manual read of condition blocks for the pitfalls in [Conditions](#conditions).

#### Prerequisites

`access-analyzer:ValidatePolicy` (free, does not store anything); `gaad.json`.

#### Steps

Validate every customer managed policy's default version:

```bash
mkdir -p pol
jq -c '.Policies[] | {n: .PolicyName, d: (.PolicyVersionList[] | select(.IsDefaultVersion) | .Document)}' gaad.json |
while read -r line; do
  name=$(jq -r .n <<<"$line"); jq .d <<<"$line" > "pol/$name.json"
  aws accessanalyzer validate-policy --policy-type IDENTITY_POLICY \
    --policy-document "file://pol/$name.json" \
    --query 'findings[?findingType==`SECURITY_WARNING` || findingType==`ERROR`].[findingType,issueCode]' \
    --output text | sed "s|^|$name\t|"
done
```

Validate role trust policies the same way, as resource policies of type `AWS::IAM::AssumeRolePolicyDocument`:

```bash
jq -c '.RoleDetailList[] | {n: .RoleName, d: .AssumeRolePolicyDocument}' gaad.json |
while read -r line; do
  name=$(jq -r .n <<<"$line"); jq .d <<<"$line" > "pol/trust-$name.json"
  aws accessanalyzer validate-policy --policy-type RESOURCE_POLICY \
    --validate-policy-resource-type AWS::IAM::AssumeRolePolicyDocument \
    --policy-document "file://pol/trust-$name.json" \
    --query 'findings[?findingType==`SECURITY_WARNING`].issueCode' --output text | sed "s|^|$name\t|"
done
```

Issue codes worth reading first: `PASS_ROLE_WITH_STAR_IN_RESOURCE` and the other PassRole variants, `ALLOW_WITH_NOT_PRINCIPAL`, `FORALLVALUES_WITH_SINGLE_VALUED_KEY`, `FORANYVALUE_WITH_AUDIENCE_CLAIM_TYPE`, `MISSING_CONDITION_KEY_FOR_OIDC_PRINCIPAL`, `MISSING_GITHUB_REPO_CONDITION_KEY`, `RESTRICT_ACCESS_TO_SERVICE_PRINCIPAL`, `UNTRUSTWORTHY_CONDITION_KEY`, `MISSING_PAIRED_CONDITION_KEYS`.

Then grep for the constructs the validator cannot judge, and read each in context:

```bash
jq -r '.. | objects | select(has("Condition")) | .Effect as $e | .Condition | keys[]
       | select(test("^ForAllValues|IfExists$")) | "\($e)\t\(.)"' gaad.json | sort | uniq -c
```

`Allow` + `ForAllValues:*` without a `Null` check, and `Allow` + `*IfExists`, are the two patterns to prove. Use the simulator with and without the key to show the difference:

```bash
aws iam simulate-custom-policy --policy-input-list file://pol/TagScopedAdmin.json \
  --action-names ec2:CreateTags --resource-arns 'arn:aws:ec2:eu-west-2:111122223333:instance/*' \
  --query 'EvaluationResults[].[EvalActionName,EvalDecision]' --output text
# returns "allowed" with no aws:TagKeys context at all -> the ForAllValues condition is vacuous
```

#### Observation

Illustrative validator output:

```text
ci-deploy-policy      SECURITY_WARNING  PASS_ROLE_WITH_STAR_IN_RESOURCE
OrgScopedRead         SECURITY_WARNING  FORALLVALUES_WITH_SINGLE_VALUED_KEY
trust-gh-deploy       SECURITY_WARNING  MISSING_GITHUB_REPO_CONDITION_KEY
```

#### Evaluation

- **Fail:** any security warning that you can show changes the effective decision (simulate with and without the key, or with a value outside the intended set). Severity follows what the statement grants.
- **Fail (trust policies):** OIDC or service-principal warnings on trust policies; take these straight to the [STS note's tests](/cloud/aws-sts-cross-account-trust-federation/).
- **Observation:** errors and general warnings that make a statement inert (a typo in an action name, an invalid condition key) are not exploitable, but they often mean a *Deny* the client relies on does nothing. Check every inert `Deny`.

#### Automated coverage

No Security Hub CSPM control runs policy validation. Access Analyzer can be wired into CI with custom policy checks (`check-no-new-access`, `check-access-not-granted`, `check-no-public-access`). Prowler and cloudsplaining cover parts of this (PassRole, admin and escalation patterns) but not condition semantics.

#### Detection

Not applicable as a runtime weakness; the detection is a pipeline gate. In CloudTrail, `ValidatePolicy` calls are noise.

### GT-AWS-IAM-10: iam:PassRole scope

*Guler Tech methodology.*

#### What it checks

Which principals can pass which roles to which services, and whether any of them can pass a role more privileged than themselves to compute they control.

#### Prerequisites

`gaad.json`; `iam:SimulatePrincipalPolicy`; optionally PMapper.

#### Steps

Find PassRole grants on wildcards or without `iam:PassedToService`:

```bash
jq -r '
  def stmts: (if type=="array" then .[] else . end);
  def acts: (.Action // []) | (if type=="string" then [.] else . end);
  ( .Policies[] | .PolicyName as $n | .PolicyVersionList[] | select(.IsDefaultVersion) | .Document.Statement | stmts | {n: $n, s: .} ),
  ( .RoleDetailList[] | .RoleName as $r | (.RolePolicyList // [])[] | .PolicyDocument.Statement | stmts | {n: ("inline:" + $r), s: .} ),
  ( .UserDetailList[] | .UserName as $u | (.UserPolicyList // [])[] | .PolicyDocument.Statement | stmts | {n: ("inline:" + $u), s: .} )
  | select(.s.Effect == "Allow")
  | select(.s | acts | any(. == "*" or . == "iam:*" or . == "iam:PassRole" or . == "iam:Pass*"))
  | [.n, (.s.Resource|tostring), ((.s.Condition // {})|tostring|test("PassedToService")|tostring)] | @tsv
' gaad.json
```

For each principal with PassRole on `*`, list the most privileged passable roles (those with admin or IAM write and a trust policy that trusts a compute service), and check whether the principal can also create or update that compute:

```bash
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::111122223333:role/ci-deploy \
  --action-names iam:PassRole \
  --resource-arns arn:aws:iam::111122223333:role/platform-admin \
  --context-entries "ContextKeyName=iam:PassedToService,ContextKeyValues=lambda.amazonaws.com,ContextKeyType=string" \
  --query 'EvaluationResults[].[EvalActionName,EvalResourceName,EvalDecision]' --output text

aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::111122223333:role/ci-deploy \
  --action-names lambda:CreateFunction lambda:UpdateFunctionConfiguration lambda:InvokeFunction \
                 ec2:RunInstances ecs:RunTask cloudformation:CreateStack glue:CreateDevEndpoint \
  --query 'EvaluationResults[].[EvalActionName,EvalDecision]' --output text
```

PMapper builds the same reasoning as a graph across all principals:

```bash
pmapper --profile client-audit graph create
pmapper --profile client-audit query 'who can do iam:PassRole with arn:aws:iam::111122223333:role/platform-admin'
pmapper --profile client-audit query -s 'preset privesc *'
```

The proof, if the client wants one, is **lab or explicitly approved only** and must stay benign: for example, create a Lambda function with the passed role whose only code calls `sts get-caller-identity` and returns the role ARN, invoke it once, then delete it. Never run anything that writes with the elevated role. The full method and variants are in the [privilege escalation note](/cloud/aws-iam-privilege-escalation/).

#### Observation

`allowed` for `iam:PassRole` on `platform-admin` with `lambda.amazonaws.com`, together with `allowed` for `lambda:CreateFunction` and `lambda:InvokeFunction`, means the CI role can run code as the platform admin role.

#### Evaluation

- **Fail (High to Critical):** a principal can pass a role with more privilege than it holds to a service where it can run or configure code. Critical when the source principal is reachable by an external party (CI from a public repository, an internet-facing workload, a third party).
- **Fail (Medium):** PassRole on `*` without `iam:PassedToService`, where no more privileged passable role exists today (a latent path that the next role creation will open).
- **Pass:** PassRole scoped to named role ARNs or a role path, with `iam:PassedToService` limiting the service.

#### Automated coverage

No Security Hub CSPM control. Access Analyzer validation security warnings (`PASS_ROLE_WITH_STAR_IN_RESOURCE` and variants). Prowler `iam_policy_allows_privilege_escalation`, `iam_inline_policy_allows_privilege_escalation`. PMapper, CloudFox `pmapper` and `iam-simulator` commands, Pacu `iam__privesc_scan` (enumeration only).

#### Detection

PassRole is not logged as its own event. Watch the calls that consume it, with the role in the request parameters: `RunInstances` (`iamInstanceProfile`), `AssociateIamInstanceProfile`, `ReplaceIamInstanceProfileAssociation`, `CreateFunction`, `UpdateFunctionConfiguration`, `RegisterTaskDefinition`, `CreateStack` and `UpdateStack` with `roleARN`, `CreateDevEndpoint`, `CreateNotebookInstance`. Alert when a privileged role appears in those parameters from an unexpected principal.

### GT-AWS-IAM-11: Effective permissions for sensitive actions

*Guler Tech methodology.*

#### What it checks

What a principal can actually do once identity policies, permissions boundaries and SCPs are all applied, for the actions that matter most. This turns test 7's "the policy looks broad" into "the principal can, or cannot, do these things".

#### Prerequisites

`iam:SimulatePrincipalPolicy`. Know the limits: the simulator evaluates identity policies, permissions boundaries and SCPs (without revealing the matching SCP statement), only includes a resource policy if you pass it with `--resource-policy`, does **not** evaluate RCPs, and uses only the context values you supply.

#### Steps

Define a sensitive action list once:

```bash
SENSITIVE="iam:CreateUser iam:CreateAccessKey iam:CreateLoginProfile iam:UpdateLoginProfile
iam:AttachUserPolicy iam:AttachRolePolicy iam:PutRolePolicy iam:CreatePolicyVersion iam:SetDefaultPolicyVersion
iam:UpdateAssumeRolePolicy iam:PassRole iam:DeleteRolePermissionsBoundary sts:AssumeRole
organizations:LeaveOrganization cloudtrail:StopLogging cloudtrail:DeleteTrail guardduty:DeleteDetector
kms:ScheduleKeyDeletion s3:PutBucketPolicy secretsmanager:GetSecretValue ec2:CreateSnapshot"
```

Simulate it for each role (or a chosen set):

```bash
jq -r '.RoleDetailList[] | select(.Path | startswith("/aws-service-role/") | not) | .Arn' gaad.json |
while read -r arn; do
  aws iam simulate-principal-policy --policy-source-arn "$arn" --action-names $SENSITIVE \
    --query 'EvaluationResults[?EvalDecision==`allowed`].EvalActionName' --output text \
  | sed "s|^|$arn\t|"
done > sensitive-allowed.tsv
```

Simulate with context where conditions matter, for example MFA or source VPC:

```bash
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::111122223333:user/j.smith \
  --action-names iam:CreateAccessKey \
  --resource-arns arn:aws:iam::111122223333:user/breakglass-01 \
  --context-entries "ContextKeyName=aws:MultiFactorAuthPresent,ContextKeyValues=false,ContextKeyType=boolean" \
  --query 'EvaluationResults[].[EvalActionName,EvalDecision,MatchedStatements[0].SourcePolicyId]' --output text
```

Cross-check with a second engine: `cloudfox aws --profile client-audit iam-simulator` and PMapper's `query`. When engines disagree, trust neither until you have read the policies.

#### Observation

Illustrative extract of `sensitive-allowed.tsv`:

```text
arn:aws:iam::111122223333:role/ci-deploy     iam:PassRole sts:AssumeRole iam:CreatePolicyVersion
arn:aws:iam::111122223333:role/support-ro    secretsmanager:GetSecretValue
arn:aws:iam::111122223333:role/app-api       (none)
```

#### Evaluation

- **Fail:** any non-administrative principal allowed an IAM write action that leads to admin (`CreatePolicyVersion`, `AttachRolePolicy`, `PutRolePolicy`, `UpdateAssumeRolePolicy`, `CreateAccessKey` on others, `DeleteRolePermissionsBoundary`), or allowed to disable logging and detection (`cloudtrail:StopLogging`, `cloudtrail:DeleteTrail`, `guardduty:DeleteDetector`) without an SCP stopping it. Rate per the [privilege escalation note](/cloud/aws-iam-privilege-escalation/) and the [CloudTrail note](/cloud/aws-cloudtrail-logging/).
- **Pass:** sensitive actions allowed only to the intended administrative roles, and denied by SCP for everyone else where the client has said they should be.
- **Report the method.** State that the simulator does not evaluate RCPs or resource policies you did not supply; a "denied" result is strong evidence, an "allowed" result for a resource with a restrictive resource policy or RCP may still fail in reality.

#### Automated coverage

None directly. Prowler `iam_policy_allows_privilege_escalation` approximates it from policy text. PMapper `preset privesc` and CloudFox `iam-simulator` cover it at scale.

#### Detection

`SimulatePrincipalPolicy` and `SimulateCustomPolicy` by unexpected principals, and `GetAccountAuthorizationDetails`, are classic reconnaissance after credential theft (ATT&CK T1087.004, T1069.003). GuardDuty `Discovery:IAMUser/AnomalousBehavior` covers unusual enumeration bursts.

## Hardening

**Federate humans, remove IAM users.** IAM Identity Center (or direct SAML/OIDC federation) for every person, with MFA enforced at the IdP; IAM users only for documented exceptions. Then make the exception hard to create, with an SCP on member accounts:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyIamUserCredentialsExceptPlatformAdmin",
      "Effect": "Deny",
      "Action": [
        "iam:CreateUser",
        "iam:CreateAccessKey",
        "iam:CreateLoginProfile",
        "iam:UpdateLoginProfile"
      ],
      "Resource": "*",
      "Condition": {
        "ArnNotLike": {
          "aws:PrincipalArn": "arn:aws:iam::*:role/platform-admin"
        }
      }
    }
  ]
}
```

**Lock root away.** Enable centralised root access management in the organisation, delete member root credentials, keep the management account root behind hardware or phishing-resistant MFA held by two people, and deny root actions in member accounts with an SCP:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyRootUserInMemberAccounts",
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "StringLike": {
          "aws:PrincipalArn": "arn:aws:iam::*:root"
        }
      }
    }
  ]
}
```

Alert on any root activity with an EventBridge rule on `userIdentity.type = Root` (see the [monitoring note](/cloud/aws-cloudwatch-eventbridge-monitoring/)).

**Enforce MFA for remaining IAM users correctly.** Use `BoolIfExists` so access-key requests are covered, and allow only MFA self-management without it:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyAllExceptMfaSetupWithoutMfa",
      "Effect": "Deny",
      "NotAction": [
        "iam:CreateVirtualMFADevice",
        "iam:EnableMFADevice",
        "iam:GetUser",
        "iam:ListMFADevices",
        "iam:ListVirtualMFADevices",
        "iam:ResyncMFADevice",
        "iam:ChangePassword",
        "sts:GetSessionToken"
      ],
      "Resource": "*",
      "Condition": {
        "BoolIfExists": {
          "aws:MultiFactorAuthPresent": "false"
        }
      }
    }
  ]
}
```

**Scope PassRole.**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "PassOnlyAppRolesToLambda",
      "Effect": "Allow",
      "Action": "iam:PassRole",
      "Resource": "arn:aws:iam::111122223333:role/app/*",
      "Condition": {
        "StringEquals": {
          "iam:PassedToService": "lambda.amazonaws.com"
        }
      }
    }
  ]
}
```

**Delegate IAM administration with permissions boundaries.** Teams that create roles must attach a boundary, and must not be able to remove it:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "CreateRolesOnlyWithBoundary",
      "Effect": "Allow",
      "Action": ["iam:CreateRole", "iam:PutRolePermissionsBoundary"],
      "Resource": "arn:aws:iam::111122223333:role/app/*",
      "Condition": {
        "StringEquals": {
          "iam:PermissionsBoundary": "arn:aws:iam::111122223333:policy/app-boundary"
        }
      }
    },
    {
      "Sid": "NoBoundaryRemovalOrBoundaryEdit",
      "Effect": "Deny",
      "Action": [
        "iam:DeleteRolePermissionsBoundary",
        "iam:CreatePolicyVersion",
        "iam:SetDefaultPolicyVersion",
        "iam:DeletePolicy"
      ],
      "Resource": [
        "arn:aws:iam::111122223333:role/app/*",
        "arn:aws:iam::111122223333:policy/app-boundary"
      ]
    }
  ]
}
```

**Password policy (for any remaining console users).**

```hcl
resource "aws_iam_account_password_policy" "this" {
  minimum_password_length        = 14
  require_lowercase_characters   = true
  require_uppercase_characters   = true
  require_numbers                = true
  require_symbols                = true
  allow_users_to_change_password = true
  password_reuse_prevention      = 24
}
```

**Run IAM Access Analyzer everywhere.** An organisation-wide external access analyzer in every Region you use (Security Hub `IAM.28`), plus an unused access analyzer:

```yaml
Resources:
  ExternalAccessAnalyzer:
    Type: AWS::AccessAnalyzer::Analyzer
    Properties:
      AnalyzerName: org-external-access
      Type: ORGANIZATION
  UnusedAccessAnalyzer:
    Type: AWS::AccessAnalyzer::Analyzer
    Properties:
      AnalyzerName: org-unused-access
      Type: ORGANIZATION_UNUSED_ACCESS
      AnalyzerConfiguration:
        UnusedAccessConfiguration:
          UnusedAccessAge: 90
```

Deploy these from the Access Analyzer delegated administrator account; check the CloudFormation reference for the current property set.

**Gate policies in CI.** Run `aws accessanalyzer validate-policy` and the custom checks `check-no-new-access` and `check-access-not-granted` (for example, "no policy may grant `iam:PassRole` on `*`") on every pull request that touches IAM. cfn-policy-validator and the Terraform equivalents wrap these calls.

**Use the managed Config rules** behind the Security Hub controls (`iam-policy-no-statements-with-admin-access`, `iam-policy-no-statements-with-full-access`, `iam-user-unused-credentials-check`, `access-keys-rotated`, `root-account-hardware-mfa-enabled`, `iam-root-access-key-check`, `mfa-enabled-for-iam-console-access`, `iam-user-no-policies-check`), aggregated in the audit account. Organisation-level guardrails (SCPs, RCPs, delegated administrators) are in the [Organizations note](/cloud/aws-organizations-multi-account-security/).

## Real-world cases

- **Capital One (2019).** An attacker used a server-side request forgery against a misconfigured web application firewall to obtain the temporary credentials of the role attached to it, and that role could list and read a large number of S3 buckets. The IAM lesson is blast radius: the workload's role had far more data access than the WAF needed. The US Department of Justice's [conviction announcement](https://www.justice.gov/usao-wdwa/pr/former-seattle-tech-worker-convicted-wire-fraud-and-computer-intrusions) summarises the case.
- **SCARLETEEL (Sysdig, February 2023).** After compromising a container, the attacker took the node role's credentials from IMDSv1; the role was meant to read one bucket but could read every bucket and Lambda function in the account. Plaintext IAM user keys found in Lambda environment variables, S3 and a Terraform state file then took them further. [Sysdig's write-up](https://sysdig.com/blog/cloud-breach-terraform-data-theft/) is a good illustration of over-broad roles plus long-lived keys.
- **Rhino Security Labs, AWS IAM privilege escalation methods.** The research that catalogued the permission combinations (PassRole plus compute, `CreatePolicyVersion`, `UpdateAssumeRolePolicy` and others) every tool now checks for: [AWS privilege escalation methods and mitigation](https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/).
- **Datadog, State of Cloud Security.** Datadog's yearly [report](https://www.datadoghq.com/state-of-cloud-security/) has tracked how common long-lived IAM user access keys, and IAM users for console access, remain across real AWS estates; useful when a client asks whether "everyone still has old keys".

For more public incidents across the series, see [AWS security incidents and write-ups](/cloud/aws-security-incidents-and-writeups/).

## Rating findings

| Finding | Typical severity | Reasoning |
|---|---|---|
| Root access keys exist | Critical | Unrestricted, long-lived credential; in the management account not even bounded by SCPs. A leak is account (or organisation) takeover. |
| Root without MFA, or root used routinely | High | Takeover from a single password or phish; routine use multiplies exposure of that password. Critical for the management account if combined with weak mailbox controls the client confirms. |
| Non-admin principal can reach admin via IAM write or PassRole | High to Critical | Privilege escalation to account administrator. Critical when the starting principal is reachable from outside (CI on public repositories, internet-facing workload, third party). |
| `*:*` or `iam:*` on workload, CI or general human roles | High | Any compromise of that principal is account takeover; no escalation step needed. Lower to Medium when limited to an MFA-protected admin group with a documented need. |
| `Allow` + `NotAction` custom policies | Medium to High | Usually grants far more than intended, including future services; rate on what the effective permissions include (often `sts:AssumeRole` and compute). |
| Console IAM users without MFA | Medium (High if privileged) | One password away from console access; privileged users raise it. |
| Active access keys older than 90 days, or on human users | Medium | Standing credential with a long exposure window; High if the key holds admin or IAM write, or shows anomalous use. |
| Credentials or roles unused for 45 or 90 days or more | Low to Medium | Attack surface without business value; Medium when privileged or cross-account trusted. |
| Service-wide wildcards (`s3:*`, `kms:*`) on application roles | Medium | Expands data access and destructive capability; depends on the data in the account. |
| Condition logic that silently allows (`ForAllValues` without `Null`, `IfExists` in Allow, `Bool` for MFA) | Medium to High | Rate by what the condition was meant to protect; prove it with the simulator. |
| Weak password policy with console IAM users present | Low to Medium | Helps password spraying; mitigated by MFA. Info when no console IAM users exist. |
| Direct user attachments, inline sprawl, missing boundaries on IAM delegates | Low to Medium | Hygiene and review-ability; Medium when missing boundaries leave IAM delegates able to create admin roles. |
| No external access analyzer | Medium | Loss of visibility on resource sharing outside the organisation; see the [detection services note](/cloud/aws-detection-posture-services/). |

## Mapping

| Test | Security Hub CSPM | CIS AWS Foundations (version/rec.) | MITRE ATT&CK |
|---|---|---|---|
| GT-AWS-IAM-1 | IAM.3, IAM.5, IAM.8, IAM.22 | v5.0.0 1.9, 1.11, 1.13 | T1078.004 |
| GT-AWS-IAM-2 | IAM.4, IAM.6, IAM.9, CloudWatch.1 | v5.0.0 1.3, 1.4, 1.5; v1.4.0 4.3 | T1078.004 |
| GT-AWS-IAM-3 | IAM.5, IAM.19, CloudWatch.3 | v5.0.0 1.9; v1.2.0 3.2 | T1078.004, T1110.003 |
| GT-AWS-IAM-4 | IAM.7, IAM.10, IAM.11 to IAM.17 | v5.0.0 1.7, 1.8 | T1110.003 |
| GT-AWS-IAM-5 | IAM.8, IAM.22 | v5.0.0 1.11; v1.2.0 1.3 | T1078.004 |
| GT-AWS-IAM-6 | IAM.3 | v5.0.0 1.13 | T1078.004, T1098.001 |
| GT-AWS-IAM-7 | IAM.1, IAM.21, IAM.27, CloudWatch.4 | v1.4.0 1.16; v5.0.0 1.21; v1.4.0 4.4 | T1078.004, T1098.003 |
| GT-AWS-IAM-8 | IAM.2, IAM.24, IAM.25 | v5.0.0 1.14 | T1098.003 |
| GT-AWS-IAM-9 | none (Access Analyzer validation) | none | T1078.004 |
| GT-AWS-IAM-10 | none | none | T1548.005 |
| GT-AWS-IAM-11 | none | none | T1548.005, T1098.003, T1087.004, T1069.003 |

CIS numbers are taken from the Security Hub CSPM control pages, which list the v1.2.0, v1.4.0, v3.0.0 and v5.0.0 mappings; numbering shifts between versions (root access keys are 1.12 in v1.2.0, 1.4 in v1.4.0 and v3.0.0, 1.3 in v5.0.0), so cite the version your client benchmarks against. Security Hub CSPM is the name AWS gave the original Security Hub product in 2025, when it launched the new, unified Security Hub; the control IDs above are the CSPM ones.

## References

- AWS: [Policy evaluation logic](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html), [How the enforcement code evaluates requests](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic_policy-eval-denyallow.html), [Cross-account policy evaluation](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic-cross-account.html)
- AWS: [IAM identifiers and unique ID prefixes](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html), [Compare AWS STS credentials](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_sts-comparison.html)
- AWS: [Principal element](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html), [NotAction](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_notaction.html), [NotResource](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_notresource.html), [Condition operators](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html), [Single-valued vs multivalued context keys](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-single-vs-multi-valued-context-keys.html), [Global condition keys](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html)
- AWS: [Pass a role to a service](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_passrole.html), [Service-linked roles](https://docs.aws.amazon.com/IAM/latest/UserGuide/using-service-linked-roles.html), [Roles terms and concepts](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_terms-and-concepts.html)
- AWS: [Root user](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html), [Root user best practices](https://docs.aws.amazon.com/IAM/latest/UserGuide/root-user-best-practices.html), [Centralise root access for member accounts](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-enable-root-access.html), [Perform a privileged task](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user-privileged-task.html)
- AWS: [Credential reports](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_getting-report.html), [Last accessed information](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_last-accessed-view-data.html), [Account password policy](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html), [Testing policies with the simulator](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_testing-policies.html)
- AWS: [IAM Access Analyzer findings](https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-findings.html), [Policy validation](https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-policy-validation.html), [Policy check reference](https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-reference-policy-checks.html)
- AWS Organizations: [SCPs](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html), [RCPs](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_rcps.html)
- AWS: [Security Hub CSPM IAM controls](https://docs.aws.amazon.com/securityhub/latest/userguide/iam-controls.html), [CloudWatch controls](https://docs.aws.amazon.com/securityhub/latest/userguide/cloudwatch-controls.html), [CIS AWS Foundations Benchmark in Security Hub CSPM](https://docs.aws.amazon.com/securityhub/latest/userguide/cis-aws-foundations-benchmark.html)
- AWS: [GuardDuty IAM finding types](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html), [Penetration testing policy](https://aws.amazon.com/security/penetration-testing/)
- IAM Identity Center: [Referencing permission sets in resource policies](https://docs.aws.amazon.com/singlesignon/latest/userguide/referencingpermissionsets.html)
- Tools: [Prowler](https://github.com/prowler-cloud/prowler), [ScoutSuite](https://github.com/nccgroup/ScoutSuite), [cloudsplaining](https://github.com/salesforce/cloudsplaining), [PMapper](https://github.com/nccgroup/PMapper), [CloudFox](https://github.com/BishopFox/cloudfox), [Pacu](https://github.com/RhinoSecurityLabs/pacu)
- Labs: [CloudGoat](https://github.com/RhinoSecurityLabs/cloudgoat), [IAM Vulnerable](https://github.com/BishopFox/iam-vulnerable), [flaws.cloud](http://flaws.cloud/)
- MITRE ATT&CK: [T1078.004](https://attack.mitre.org/techniques/T1078/004/), [T1098.001](https://attack.mitre.org/techniques/T1098/001/), [T1098.003](https://attack.mitre.org/techniques/T1098/003/), [T1548.005](https://attack.mitre.org/techniques/T1548/005/), [T1087.004](https://attack.mitre.org/techniques/T1087/004/), [T1069.003](https://attack.mitre.org/techniques/T1069/003/), [T1110.003](https://attack.mitre.org/techniques/T1110/003/)
- Research: [Rhino Security Labs, AWS privilege escalation methods](https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/), [Sysdig, SCARLETEEL](https://sysdig.com/blog/cloud-breach-terraform-data-theft/), [Datadog, State of Cloud Security](https://www.datadoghq.com/state-of-cloud-security/)
