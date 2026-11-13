---
title: "AWS IAM Privilege Escalation Paths"
date: 2026-11-12 18:02:00 +0000
subcategory: aws
summary: "The published AWS IAM privilege-escalation families: permission combinations, finding who holds them, benign lab proofs, fixes and detection."
refs: [IAM.1, IAM.2, IAM.21, CloudTrail.1, GuardDuty.1, "CIS AWS v1.4.0 1.16", "CIS AWS v5.0.0 1.14", "CIS AWS v5.0.0 3.1", T1078.004, T1098.001, T1098.003, T1548.005, T1648, T1651]
tags: [aws, iam, privilege-escalation, passrole, pmapper, pacu]
---

This note is part of our [AWS security testing guide](/cloud/aws-security-testing-guide/) and covers IAM privilege escalation: a principal that is not an administrator holds a permission, or a combination of permissions, that lets it give itself more access than it was meant to have. The classic example is `iam:CreatePolicyVersion` on a policy attached to yourself, which turns any principal into an administrator with one API call, but the larger and more interesting group in real accounts is `iam:PassRole` combined with a service that runs code (EC2, Lambda, ECS, CodeBuild, Glue, SageMaker, CloudFormation), plus the quieter cousins that modify compute which already runs as a powerful role. We group the publicly documented paths into families, following the research by Spencer Gietzen at Rhino Security Labs, Seth Art's IAM Vulnerable at Bishop Fox and pathfinding.cloud at Datadog, and HackTricks Cloud. For each family you get the permission combination, why it escalates, how to *find* principals that hold it without exploiting anything, a benign proof for a lab or an explicitly approved test, and the fix. The note assumes you know how IAM evaluates a request; if not, read [IAM fundamentals and policy evaluation](/cloud/aws-iam-fundamentals-policy-evaluation/) first. Role trust and cross-account assumption live in [STS, cross-account trust and federation](/cloud/aws-sts-cross-account-trust-federation/).

## Contents

- [How it works](#how-it-works)
  - [Why escalation exists at all](#why-escalation-exists-at-all)
  - [Where the path catalogue comes from](#where-the-path-catalogue-comes-from)
  - [The path families](#the-path-families)
  - [What actually stops a path](#what-actually-stops-a-path)
- [What goes wrong](#what-goes-wrong)
  - [Policy manipulation](#policy-manipulation)
  - [Credential creation for other users](#credential-creation-for-other-users)
  - [Trust policy manipulation and assumable roles](#trust-policy-manipulation-and-assumable-roles)
  - [PassRole to a service that runs code](#passrole-to-a-service-that-runs-code)
  - [Modifying or entering existing compute](#modifying-or-entering-existing-compute)
  - [Permission boundary and SCP gaps](#permission-boundary-and-scp-gaps)
  - [Summary of paths](#summary-of-paths)
- [Testing](#testing)
  - [Before you start](#before-you-start)
  - [Practising in deliberately vulnerable labs](#practising-in-deliberately-vulnerable-labs)
  - [GT-AWS-PRIVESC-1: Map escalation paths account-wide](#gt-aws-privesc-1-map-escalation-paths-account-wide)
  - [GT-AWS-PRIVESC-2: Policy manipulation permissions](#gt-aws-privesc-2-policy-manipulation-permissions)
  - [GT-AWS-PRIVESC-3: Credential creation on other users](#gt-aws-privesc-3-credential-creation-on-other-users)
  - [GT-AWS-PRIVESC-4: Trust policy manipulation and over-trusting roles](#gt-aws-privesc-4-trust-policy-manipulation-and-over-trusting-roles)
  - [GT-AWS-PRIVESC-5: PassRole scope and conditions](#gt-aws-privesc-5-passrole-scope-and-conditions)
  - [GT-AWS-PRIVESC-6: PassRole with new compute (EC2, Lambda, ECS, CodeBuild)](#gt-aws-privesc-6-passrole-with-new-compute-ec2-lambda-ecs-codebuild)
  - [GT-AWS-PRIVESC-7: PassRole with orchestration and data services](#gt-aws-privesc-7-passrole-with-orchestration-and-data-services)
  - [GT-AWS-PRIVESC-8: Modifying existing compute that runs as a stronger role](#gt-aws-privesc-8-modifying-existing-compute-that-runs-as-a-stronger-role)
  - [GT-AWS-PRIVESC-9: Command execution on running compute](#gt-aws-privesc-9-command-execution-on-running-compute)
  - [GT-AWS-PRIVESC-10: Permission boundary and delegated administration gaps](#gt-aws-privesc-10-permission-boundary-and-delegated-administration-gaps)
  - [GT-AWS-PRIVESC-11: Organisation guardrails against escalation](#gt-aws-privesc-11-organisation-guardrails-against-escalation)
  - [GT-AWS-PRIVESC-12: Detection coverage for escalation activity](#gt-aws-privesc-12-detection-coverage-for-escalation-activity)
- [Hardening](#hardening)
  - [Least privilege for IAM write actions](#least-privilege-for-iam-write-actions)
  - [Scoping PassRole](#scoping-passrole)
  - [Protecting compute that runs as a privileged role](#protecting-compute-that-runs-as-a-privileged-role)
  - [Permission boundaries that hold](#permission-boundaries-that-hold)
  - [SCP and RCP guardrails](#scp-and-rcp-guardrails)
  - [Preventive checks in the pipeline](#preventive-checks-in-the-pipeline)
- [Real-world cases](#real-world-cases)
- [Rating findings](#rating-findings)
- [Mapping](#mapping)
- [References](#references)

## How it works

### Why escalation exists at all

IAM has no concept of "rank". A request is allowed when an identity-based or resource-based policy allows it and nothing denies it: no SCP, RCP, permissions boundary or session policy, and no explicit `Deny` anywhere (the full order is in [IAM fundamentals](/cloud/aws-iam-fundamentals-policy-evaluation/)). IAM never asks whether the result of the call will leave the caller with *more* access than it had. So any permission whose effect is to change permissions, mint credentials, or make AWS run code under another identity is, by construction, a path to whatever that other identity can do.

That gives every escalation path the same shape:

1. **A starting principal** (user, role, or a session from Identity Center or a federated IdP) with some write permission.
2. **A lever**: an IAM write action (`iam:Put*`, `iam:Attach*`, `iam:CreatePolicyVersion`), a credential action (`iam:CreateAccessKey`), a trust change (`iam:UpdateAssumeRolePolicy`), or a service that will execute something as a role (`iam:PassRole` plus `lambda:CreateFunction`, or `lambda:UpdateFunctionCode` on a function that already has a role).
3. **A target identity** that has more than the starting principal: an admin user, an admin group, a privileged role, or a role attached to running compute.
4. **A way to use the result**: reading the new credentials, invoking the function, or having the code act directly.

When all four exist, the starting principal's real privilege is the target's privilege, whatever its own policy looks like. A security review that reads only "what does this role's policy allow?" misses this; the question that matters is "what can this role *become*?". That is a graph question, which is why the tooling below (PMapper, Pacu, cloudsplaining, Prowler) builds or approximates a graph of principals and edges.

Two details make the graph harder than it looks:

- **`iam:PassRole` is a permission, not an API.** AWS checks it when you hand a role ARN to another service (`RunInstances` with an instance profile, `CreateFunction` with `--role`, `CreateStack` with `--role-arn`). It produces no CloudTrail event of its own; the role shows up in the request parameters of the call that consumed it ([AWS docs](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_passrole.html)). Detection and review have to look at the consuming call.
- **The target is often a resource, not a principal.** `lambda:UpdateFunctionCode` on a function whose execution role is `AdministratorAccess` is an admin path even though no IAM action is involved. The edge goes through a Lambda function, an EC2 instance, an ECS task, a CodeBuild project or a CloudFormation stack.

### Where the path catalogue comes from

The paths in this note are public and well documented. We cite the sources rather than inventing new ones:

| Source | What it contributed |
|---|---|
| Spencer Gietzen, Rhino Security Labs, [AWS privilege escalation methods and mitigation](https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/) (2018) | The original 21 methods: policy versions, inline and attached policies, group membership, access keys and login profiles, trust policy updates, PassRole with EC2, Lambda (invoke and DynamoDB trigger), Glue dev endpoints, CloudFormation and Data Pipeline, and `lambda:UpdateFunctionCode` and `glue:UpdateDevEndpoint` on existing resources. |
| Rhino Security Labs, [Part 2](https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation-part-2/) and [the CodeStar research](https://rhinosecuritylabs.com/aws/escalating-aws-iam-privileges-undocumented-codestar-api/) | Lambda layers via `lambda:UpdateFunctionConfiguration`, SageMaker notebooks with PassRole, presigned URLs to existing notebooks, and an undocumented CodeStar API. |
| Pacu's [`iam__privesc_scan`](https://github.com/RhinoSecurityLabs/pacu) module | The same methods turned into a scanner, with extra variants (cross-account Lambda invoke via `lambda:AddPermission`, new versus existing DynamoDB tables). |
| Seth Art, Bishop Fox, [IAM Vulnerable](https://github.com/BishopFox/iam-vulnerable) | A Terraform playground with 31 paths in five groups (IAM permissions on other users, PassRole to service, permissions on policies, privilege escalation using AWS services, updating an AssumeRole policy), adding CodeBuild, SageMaker training and processing jobs, EC2 Instance Connect, CloudFormation `UpdateStack`, SSM `SendCommand` and `StartSession`, and `sts:AssumeRole`. |
| Seth Art, Datadog, [pathfinding.cloud](https://pathfinding.cloud/) ([repo](https://github.com/DataDog/pathfinding.cloud)) | A YAML catalogue with IDs per service (`iam-001` is `iam:CreatePolicyVersion`), five categories (self-escalation, principal access, new PassRole, existing PassRole, credential access), required permissions, prerequisites and which open-source tools detect each path. The [launch post](https://securitylabs.datadoghq.com/articles/introducing-pathfinding.cloud/) (December 2025) listed 65 paths and noted that 27 of them were not detected by any of the open-source tools evaluated. |
| [HackTricks Cloud, AWS privilege escalation](https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-privilege-escalation/index.html) | Per-service pages that track newer and niche variants. Treat it as a lead list and confirm each path against AWS docs before you report it. |

Use pathfinding.cloud as your checklist of record: it is versioned, has stable IDs you can cite in a report, and its service list (App Runner, Batch, Bedrock, CodeDeploy, EMR, Image Builder, Step Functions, EventBridge Scheduler and more) is broader than what the older tools model.

### The path families

We use five families that line up with the pathfinding.cloud categories and the IAM Vulnerable groups, plus a sixth for the guardrails that should have stopped them:

| Family | Lever | Typical target | pathfinding.cloud category |
|---|---|---|---|
| Policy manipulation | Write a policy that applies to you (or to a role you can assume) | Yourself | Self-escalation |
| Credential creation | Mint a key or password for another user | Another IAM user | Principal access |
| Trust manipulation | Rewrite a role's trust policy so you can assume it | A role | Principal access |
| PassRole to a service | Create compute that runs as a role you pass | A role | New PassRole |
| Existing compute | Change or enter compute that already runs as a role | A role | Existing PassRole |
| Boundary and SCP gaps | Remove or sidestep the guardrail | Whatever the guardrail was protecting | (cross-cutting) |

### What actually stops a path

Four controls block escalation reliably. Knowing which one blocks which family tells you what to test and what to recommend.

| Control | What it does | Blocks | Does not block |
|---|---|---|---|
| **Resource scoping** in the identity policy | Limits *which* policies, users, roles or functions the action applies to | Everything, if done precisely (for example `iam:PassRole` only on `role/app-*-lambda`) | Anything a wildcard `Resource` leaves open |
| **`iam:PassedToService`** condition | Limits *which service* a role may be passed to ([condition key](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_iam-condition-keys.html)) | Passing a Lambda role to EC2, CodeBuild or CloudFormation | Passing that role to the intended service in a way you did not intend (a new Lambda function with the same role) |
| **Permissions boundary** | Caps the maximum permissions of a user or role | Policy manipulation on bounded principals (the new policy is capped), and, with the right conditions, creating unbounded principals | Passing an *unbounded* existing role to a service; resource-based policy grants to an IAM user ARN in the same account ([AWS docs](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html)) |
| **SCP** | Caps every IAM principal in a member account | Any family, if the SCP denies the lever action (for example `iam:CreatePolicyVersion` outside an admin role) | The management account and service-linked roles ([AWS docs](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html)) |
| **RCP** | Caps access to resources of supported services, including STS | Outside-the-organisation principals added to a role trust policy (`sts:AssumeRole` is in scope) | Paths inside the organisation; IAM, Lambda, EC2 and SSM actions (not on the RCP service list at the time of writing; [check the list](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_rcps.html)) |

AWS warns against using `aws:ResourceTag` conditions to control who can pass which role, because the results are not reliable ([AWS docs](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_passrole.html)). Scope `iam:PassRole` by role ARN (a path or name prefix) instead.

## What goes wrong

### Policy manipulation

**Permissions:** any one of `iam:CreatePolicyVersion`, `iam:SetDefaultPolicyVersion`, `iam:PutUserPolicy`, `iam:PutGroupPolicy`, `iam:PutRolePolicy`, `iam:AttachUserPolicy`, `iam:AttachGroupPolicy`, `iam:AttachRolePolicy`, `iam:AddUserToGroup`, on a resource that affects the caller.

**Why it escalates:**

- `iam:CreatePolicyVersion` on a customer managed policy attached to you lets you write a new version with `"Action": "*"` and, with `--set-as-default`, make it active in the same call. You do not need `iam:SetDefaultPolicyVersion` for that (Rhino's method 1). A managed policy holds at most five versions, so a full policy also needs `iam:DeletePolicyVersion`.
- `iam:SetDefaultPolicyVersion` alone is enough when an older, more permissive version still exists. This is the CloudGoat `iam_privesc_by_rollback` scenario, and it is common in real accounts: someone tightened a policy by adding a version and never deleted the old one.
- `iam:Put*Policy` writes an inline policy; `iam:Attach*Policy` attaches any managed policy, including `arn:aws:iam::aws:policy/AdministratorAccess`. On your own user or a group you are in, the effect is immediate. On a role, it escalates you if you can assume that role or already are that role (a Lambda function whose role can `iam:PutRolePolicy` on itself is a self-escalating function).
- `iam:AddUserToGroup` lets you join a group that already has admin policies.

**What makes it worse:** the action is granted on `"Resource": "*"`, often through broad AWS managed policies (`IAMFullAccess`) or "power user" custom policies that allow `iam:*` with a short deny list. A deny list that forgets one of the nine actions above is still an admin path.

### Credential creation for other users

**Permissions:** `iam:CreateAccessKey`, `iam:CreateLoginProfile` or `iam:UpdateLoginProfile` on users other than yourself (plus `iam:DeleteAccessKey` if the target already has two keys, the maximum).

**Why it escalates:** you become the target user. `CreateAccessKey` gives you long-term API credentials for an admin user. `CreateLoginProfile` sets a console password for a user that had none (typically a service user with powerful policies). `UpdateLoginProfile` resets an existing password. Console access is still stopped by MFA if the target has an MFA device registered; API keys are not, unless the target's policies require MFA through `aws:MultiFactorAuthPresent` conditions.

**What makes it worse:** "helpdesk" policies that allow key and password management on `arn:aws:iam::*:user/*`. AWS's own delegation example in the permissions-boundary documentation allows `iam:CreateAccessKey` and `iam:UpdateLoginProfile` on every user except the named admin, which shows how easily one admin is excluded and another is not ([AWS docs](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html)). Name-based exclusions fail on case and naming drift; SCARLETEEL 2.0 (below) is a public example.

### Trust policy manipulation and assumable roles

**Permissions:** `iam:UpdateAssumeRolePolicy` on a role, plus the ability to call `sts:AssumeRole` on it. Separately, plain `sts:AssumeRole` on `"Resource": "*"` combined with roles whose trust policy trusts the whole account.

**Why it escalates:** the trust policy decides who may become the role. Rewriting it to trust your own principal makes the role yours. Rhino and Pacu list `sts:AssumeRole` as part of the requirement, but within one account a trust policy that names your principal's ARN directly is sufficient without an identity-based `sts:AssumeRole` grant (AWS Security Blog, [How to use trust policies with IAM roles](https://aws.amazon.com/blogs/security/how-to-use-trust-policies-with-iam-roles/)), so treat `iam:UpdateAssumeRolePolicy` on its own as a finding. By contrast, a trust policy that names the account root (`arn:aws:iam::111122223333:root`) delegates the decision to identity policies. So the second variant is passive: a role that trusts `:root` can be assumed by every principal in the account that has `sts:AssumeRole` on `*`, and many "developer" policies grant exactly that. IAM Vulnerable's `privesc-assumerole` and Prowler's `iam_no_custom_policy_permissive_role_assumption` cover it.

Cross-account trust, external IDs and confused deputies are in [STS, cross-account trust and federation](/cloud/aws-sts-cross-account-trust-federation/).

### PassRole to a service that runs code

**Permissions:** `iam:PassRole` on a role that is more privileged than you, plus permission to create a resource in a service that will run your code or template as that role:

| Service | Combination | How the role is used |
|---|---|---|
| EC2 | `iam:PassRole` + `ec2:RunInstances` (or `ec2:RequestSpotInstances`, or Auto Scaling launch configuration and template actions) | Instance profile credentials through IMDS; your user data or SSH session runs as the role |
| Lambda | `iam:PassRole` + `lambda:CreateFunction` + `lambda:InvokeFunction` | Function code runs with the execution role |
| Lambda (no invoke) | `iam:PassRole` + `lambda:CreateFunction` + `lambda:CreateEventSourceMapping` (+ `dynamodb:CreateTable`/`dynamodb:PutItem` for a new table) | An event source (DynamoDB stream, SQS, Kinesis) triggers the function |
| Lambda (cross-account) | `iam:PassRole` + `lambda:CreateFunction` + `lambda:AddPermission` | A resource policy lets another account invoke it |
| ECS | `iam:PassRole` + `ecs:RegisterTaskDefinition` + `ecs:RunTask` / `ecs:StartTask` / `ecs:CreateService` | The task role's credentials are exposed to the container |
| CodeBuild | `iam:PassRole` + `codebuild:CreateProject` + `codebuild:StartBuild` (or `StartBuildBatch`) | The buildspec runs as the service role |
| CloudFormation | `iam:PassRole` + `cloudformation:CreateStack` (or StackSets, or change sets) | The template creates resources as the stack role, including IAM resources |
| Glue | `iam:PassRole` + `glue:CreateDevEndpoint` (legacy), or `glue:CreateJob` + `glue:StartJobRun` / `glue:CreateTrigger` | Spark or Python code runs as the Glue role |
| SageMaker | `iam:PassRole` + `sagemaker:CreateNotebookInstance` + `sagemaker:CreatePresignedNotebookInstanceUrl`; or `CreateTrainingJob` / `CreateProcessingJob` | Jupyter or a container runs as the execution role |
| Data Pipeline | `iam:PassRole` + `datapipeline:CreatePipeline` + `datapipeline:PutPipelineDefinition` (+ activation) | Activities run on resources with the pipeline role |
| CodeStar | `codestar:CreateProject` + `iam:PassRole`, or the undocumented `codestar:CreateProjectFromTemplate` | Historical: AWS stopped supporting the creation of CodeStar projects on 31 July 2024 |

**Why it escalates:** the role's permissions, not yours, apply to whatever the service does. You only need enough permission to describe the resource, and the service does the rest.

**Status notes (verify at test time):** AWS Data Pipeline is no longer available to new customers, but existing customers can still use it, so the path matters only in accounts that already use the service. Glue development endpoints support only Glue 0.9 and 1.0, and the console experience was removed in March 2023, but AWS documents creation as still possible through the API and CLI. Glue jobs and interactive sessions are the current equivalents and carry the same risk.

**What makes it worse:** `iam:PassRole` on `"Resource": "*"`, which is the single most common escalation enabler we see. It hides in AWS managed "full access" policies for services, in CI roles, and in developer policies written so that "they can deploy Lambda functions".

### Modifying or entering existing compute

**Permissions** (no PassRole needed, because the role is already attached):

| Target | Permission(s) | Effect |
|---|---|---|
| Lambda function | `lambda:UpdateFunctionCode` (+ an invoke path or wait for the next event) | Your code runs as the function's role |
| Lambda function | `lambda:UpdateFunctionConfiguration` | Attach a layer that shadows a library the function imports (Rhino Part 2), or change the handler |
| EC2 instance | `ec2:ModifyInstanceAttribute` (user data) + `ec2:StopInstances` + `ec2:StartInstances` | New user data runs at boot as root on an instance with the profile |
| EC2 launch template | `ec2:CreateLaunchTemplateVersion` + `ec2:ModifyLaunchTemplate` | The next instances launched by Auto Scaling run your user data |
| EC2 instance | `ec2:AssociateIamInstanceProfile` / `ec2:ReplaceIamInstanceProfileAssociation` + `iam:PassRole` | Puts a stronger role on an instance you already control |
| CloudFormation stack | `cloudformation:UpdateStack`, or `CreateChangeSet` + `ExecuteChangeSet` | Updates run as the stack's existing service role |
| CodeBuild project | `codebuild:StartBuild` with a buildspec override, or `codebuild:UpdateProject` | Your commands run as the project's role |
| Glue dev endpoint or job | `glue:UpdateDevEndpoint` (add your SSH key), `glue:UpdateJob` + `glue:StartJobRun` | Your code runs as the Glue role |
| SageMaker notebook | `sagemaker:CreatePresignedNotebookInstanceUrl` on an existing notebook; or lifecycle configuration changes | A Jupyter session as the notebook's role |
| ECS task | `ecs:ExecuteCommand` (ECS Exec enabled on the task) | A shell in the container, with the task role |
| EC2 instance | `ssm:SendCommand`, `ssm:StartSession`, `ec2-instance-connect:SendSSHPublicKey` | A shell on the instance, with its role |
| App Runner service | `apprunner:UpdateService` | The new image or code runs as the instance role (pathfinding.cloud lists it) |

**Why it escalates:** the attacker borrows the privilege that a developer gave to a workload. Teams often give automation roles broad rights ("the bootstrap Lambda creates IAM users, so it needs IAM write") and then grant `lambda:*` to every developer. The Sysdig incident in [Real-world cases](#real-world-cases) went exactly this way.

### Permission boundary and SCP gaps

These are not paths on their own; they are why a path that *should* have been blocked still works.

- **Boundary not required on creation.** A principal can `iam:CreateRole` or `iam:CreateUser` without a condition on `iam:PermissionsBoundary`, so it creates an unbounded principal and attaches admin to it.
- **Boundary removable.** `iam:DeleteUserPermissionsBoundary`, `iam:DeleteRolePermissionsBoundary`, or `iam:PutUserPermissionsBoundary`/`iam:PutRolePermissionsBoundary` with a weaker policy.
- **Boundary policy editable.** `iam:CreatePolicyVersion` or `iam:SetDefaultPolicyVersion` on the boundary policy itself.
- **PassRole bypasses the boundary.** The boundary caps the bounded principal, not the role it passes. A bounded developer who can pass an unbounded admin role to Lambda is still an admin.
- **Resource-based grants.** Within one account, resource-based policies that grant to an IAM user ARN are not limited by an implicit deny in that user's boundary ([AWS docs](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html)).
- **SCP blind spots.** SCPs do not affect principals in the management account or service-linked roles. An SCP that denies IAM writes "except for roles matching `*admin*`" is only as strong as the ability to create a role with that name.
- **Deny lists that age.** A guardrail written against the 2018 list misses newer services (App Runner, Bedrock AgentCore, EMR Serverless, Step Functions, EventBridge Scheduler), all of which take a role.

### Summary of paths

The table lists the paths we test for, where they are documented, and which test covers them. "Rhino n" is the method number in the 2018 post; "IAM-V" is the IAM Vulnerable path name; pathfinding.cloud IDs follow the `<service>-NNN` pattern (we cite `iam-001` because we verified it; look up the others on the site at test time rather than trusting a static list).

| # | Path | Required permissions | Family | Sources | Test |
|---|---|---|---|---|---|
| 1 | New policy version | `iam:CreatePolicyVersion` | Policy | Rhino 1, IAM-V `IAM-CreateNewPolicyVersion`, pathfinding `iam-001` | [2](#gt-aws-privesc-2-policy-manipulation-permissions) |
| 2 | Roll back default version | `iam:SetDefaultPolicyVersion` | Policy | Rhino 2, IAM-V | 2 |
| 3 | Inline policy on user | `iam:PutUserPolicy` | Policy | Rhino 10, IAM-V | 2 |
| 4 | Inline policy on group | `iam:PutGroupPolicy` | Policy | Rhino 11, IAM-V | 2 |
| 5 | Inline policy on role | `iam:PutRolePolicy` (+ `sts:AssumeRole`) | Policy | Rhino 12, IAM-V | 2 |
| 6 | Attach managed policy to user | `iam:AttachUserPolicy` | Policy | Rhino 7, IAM-V | 2 |
| 7 | Attach managed policy to group | `iam:AttachGroupPolicy` | Policy | Rhino 8, IAM-V | 2 |
| 8 | Attach managed policy to role | `iam:AttachRolePolicy` (+ `sts:AssumeRole`) | Policy | Rhino 9, IAM-V | 2 |
| 9 | Join a privileged group | `iam:AddUserToGroup` | Policy | Rhino 13, IAM-V | 2 |
| 10 | Access key for another user | `iam:CreateAccessKey` (+ `iam:DeleteAccessKey`) | Credentials | Rhino 4, IAM-V | [3](#gt-aws-privesc-3-credential-creation-on-other-users) |
| 11 | Console password for a user without one | `iam:CreateLoginProfile` | Credentials | Rhino 5, IAM-V | 3 |
| 12 | Reset a user's console password | `iam:UpdateLoginProfile` | Credentials | Rhino 6, IAM-V | 3 |
| 13 | Rewrite a role's trust policy | `iam:UpdateAssumeRolePolicy` + `sts:AssumeRole` | Trust | Rhino 14, IAM-V | [4](#gt-aws-privesc-4-trust-policy-manipulation-and-over-trusting-roles) |
| 14 | Assume an over-trusting role | `sts:AssumeRole` on a role trusting the account | Trust | IAM-V `STS-AssumeRole` | 4 |
| 15 | EC2 with an existing instance profile | `iam:PassRole` + `ec2:RunInstances` | PassRole | Rhino 3, IAM-V | [6](#gt-aws-privesc-6-passrole-with-new-compute-ec2-lambda-ecs-codebuild) |
| 16 | Lambda, then invoke | `iam:PassRole` + `lambda:CreateFunction` + `lambda:InvokeFunction` | PassRole | Rhino 15, IAM-V | 6 |
| 17 | Lambda, then event trigger | `iam:PassRole` + `lambda:CreateFunction` + `lambda:CreateEventSourceMapping` | PassRole | Rhino 16, IAM-V | 6 |
| 18 | Lambda, cross-account invoke | `iam:PassRole` + `lambda:CreateFunction` + `lambda:AddPermission` | PassRole | Pacu | 6 |
| 19 | ECS task with a passed task role | `iam:PassRole` + `ecs:RegisterTaskDefinition` + `ecs:RunTask`/`StartTask`/`CreateService` | PassRole | pathfinding.cloud, HackTricks, Prowler | 6 |
| 20 | CodeBuild project | `iam:PassRole` + `codebuild:CreateProject` + `codebuild:StartBuild` | PassRole | IAM-V `CodeBuild-CreateProjectPassRole` | 6 |
| 21 | CloudFormation stack | `iam:PassRole` + `cloudformation:CreateStack` | PassRole | Rhino 20, IAM-V | [7](#gt-aws-privesc-7-passrole-with-orchestration-and-data-services) |
| 22 | Glue dev endpoint | `iam:PassRole` + `glue:CreateDevEndpoint` | PassRole | Rhino 18, IAM-V | 7 |
| 23 | Glue job | `iam:PassRole` + `glue:CreateJob` + `glue:StartJobRun` or `glue:CreateTrigger` | PassRole | pathfinding.cloud, CloudGoat `glue_privesc`, Prowler | 7 |
| 24 | SageMaker notebook | `iam:PassRole` + `sagemaker:CreateNotebookInstance` + `sagemaker:CreatePresignedNotebookInstanceUrl` | PassRole | Rhino Part 2, IAM-V | 7 |
| 25 | SageMaker training or processing job | `iam:PassRole` + `sagemaker:CreateTrainingJob` or `sagemaker:CreateProcessingJob` | PassRole | IAM-V | 7 |
| 26 | Data Pipeline | `iam:PassRole` + `datapipeline:CreatePipeline` + `datapipeline:PutPipelineDefinition` | PassRole | Rhino 21, IAM-V | 7 |
| 27 | Update Lambda code | `lambda:UpdateFunctionCode` | Existing | Rhino 17, IAM-V | [8](#gt-aws-privesc-8-modifying-existing-compute-that-runs-as-a-stronger-role) |
| 28 | Lambda layer or configuration | `lambda:UpdateFunctionConfiguration` | Existing | Rhino Part 2 | 8 |
| 29 | EC2 user data on a stopped instance | `ec2:ModifyInstanceAttribute` + `ec2:StopInstances` + `ec2:StartInstances` | Existing | HackTricks, Prowler | 8 |
| 30 | Launch template version | `ec2:CreateLaunchTemplateVersion` + `ec2:ModifyLaunchTemplate` | Existing | HackTricks, Prowler | 8 |
| 31 | Swap an instance profile | `ec2:AssociateIamInstanceProfile` or `ec2:ReplaceIamInstanceProfileAssociation` + `iam:PassRole` | Existing | HackTricks | 8 |
| 32 | Update a stack with a service role | `cloudformation:UpdateStack` (or change sets) | Existing | IAM-V `CloudFormation-UpdateStack` | 8 |
| 33 | CodeBuild buildspec override | `codebuild:StartBuild` (or `codebuild:UpdateProject`) | Existing | Prowler, HackTricks | 8 |
| 34 | Update a Glue dev endpoint or job | `glue:UpdateDevEndpoint`; `glue:UpdateJob` + `glue:StartJobRun` | Existing | Rhino 19, IAM-V | 8 |
| 35 | Presigned URL to an existing notebook | `sagemaker:CreatePresignedNotebookInstanceUrl` | Existing | Rhino Part 2, IAM-V | 8 |
| 36 | SSM Run Command | `ssm:SendCommand` | Existing | IAM-V `SSM-SendCommand` | [9](#gt-aws-privesc-9-command-execution-on-running-compute) |
| 37 | SSM Session Manager | `ssm:StartSession` | Existing | IAM-V `SSM-StartSession` | 9 |
| 38 | EC2 Instance Connect | `ec2-instance-connect:SendSSHPublicKey` (+ network reach) | Existing | IAM-V `EC2InstanceConnect-SendSSHPublicKey` | 9 |
| 39 | ECS Exec into a running task | `ecs:ExecuteCommand` | Existing | Prowler, HackTricks | 9 |
| 40 | Create an unbounded principal | `iam:CreateRole`/`iam:CreateUser` without a boundary condition, + policy write | Boundary gap | AWS boundary docs | [10](#gt-aws-privesc-10-permission-boundary-and-delegated-administration-gaps) |
| 41 | Remove or weaken a boundary | `iam:Delete*PermissionsBoundary`, `iam:Put*PermissionsBoundary`, version changes to the boundary policy | Boundary gap | AWS boundary docs | 10 |
| 42 | Lever actions outside SCP coverage | Any of the above in an account or principal that SCPs do not cover | SCP gap | AWS Organizations docs | [11](#gt-aws-privesc-11-organisation-guardrails-against-escalation) |

## Testing

Every test here assumes an **authorised** engagement against the client's own AWS accounts, with written scope, and respects the [AWS penetration testing policy](https://aws.amazon.com/security/penetration-testing/). Finding a path is a read-only exercise: you read policies, build the graph and confirm with the IAM policy simulator. Exploiting a path changes IAM state in a production account, so the "benign proof" steps below are **lab or explicitly approved only**, use a test principal the client created for you, and are reverted immediately. All command output shown is **illustrative**; we ran nothing against a real account for this note.

### Before you start

**Credentials.** Ask for a role with the AWS managed `SecurityAudit` and `ViewOnlyAccess` policies. Those cover `iam:GetAccountAuthorizationDetails` and the `List*`/`Get*` calls in each service. Check that the role can also call `iam:SimulatePrincipalPolicy`, `iam:GetContextKeysForPrincipalPolicy` and `access-analyzer:CheckAccessNotGranted`; if your read-only role lacks them, ask for a small extra policy rather than a broader managed one. For organisation-level tests ([GT-AWS-PRIVESC-11](#gt-aws-privesc-11-organisation-guardrails-against-escalation)) you need read access to AWS Organizations from the management account or a delegated administrator.

```bash
export AWS_PROFILE=gt-audit
aws sts get-caller-identity
mkdir -p evidence && cd evidence

# One snapshot of every user, group, role and policy (all versions), paginated by the CLI
aws iam get-account-authorization-details --output json > auth.json
jq '{users: (.UserDetailList|length), groups: (.GroupDetailList|length),
     roles: (.RoleDetailList|length), policies: (.Policies|length)}' auth.json
```

**Region loop.** IAM is global, but the compute in the "existing compute" family is regional. Use one loop and reuse it:

```bash
REGIONS=$(aws ec2 describe-regions --query 'Regions[].RegionName' --output text)
for r in $REGIONS; do
  aws lambda list-functions --region "$r" \
    --query 'Functions[].[FunctionName,Role]' --output text | sed "s/^/$r\t/"
done > lambda-roles.tsv
```

**Tools.**

| Tool | Use here | Notes |
|---|---|---|
| [PMapper](https://github.com/nccgroup/PMapper) (NCC Group) | Graph of principals and escalation edges; `query`, `argquery`, `preset privesc` | Builds the graph from read-only calls. Its edge set predates many newer services; pathfinding.cloud records which paths it misses. |
| [Pacu](https://github.com/RhinoSecurityLabs/pacu) (Rhino) | `iam__enum_permissions` then `iam__privesc_scan --scan-only` | Without `--scan-only`, `iam__privesc_scan` **attempts the escalation**. Never run it without the flag outside a lab. |
| [cloudsplaining](https://github.com/salesforce/cloudsplaining) (Salesforce) | Policy-centric report: privilege escalation, resource exposure, credentials exposure, data exfiltration, infrastructure modification | Works offline on `auth.json`. Flags actions without resource constraints. |
| [Prowler](https://github.com/prowler-cloud/prowler) | `iam_policy_allows_privilege_escalation`, `iam_inline_policy_allows_privilege_escalation` and related checks | Its privesc library is policy-centric and, per its own source comments, does not evaluate resource constraints or conditions: expect false positives. |
| [CloudFox](https://github.com/BishopFox/cloudfox) (Bishop Fox) | `role-trusts`, `permissions`, `workloads`, `lambda`, `iam-simulator`, `pmapper` | `workloads` lists compute and its roles and flags admin roles; with PMapper data it marks privesc paths. |
| AWS CLI | `iam simulate-principal-policy`, `accessanalyzer check-access-not-granted` | The authoritative check for "is this action allowed for this principal on this resource". |

**The simulator, in one paragraph.** `aws iam simulate-principal-policy` evaluates the principal's identity policies, its permissions boundary and the SCPs that apply to its account (including their conditions), against the actions in `--action-names` and the ARNs in `--resource-arns`. It does not fetch resource-based policies (you can pass one with `--resource-policy`, and that is not supported for roles), and the IAM documentation notes that results can differ from the live environment. At the time of writing the CLI documents that it returns **one result per action**, with the aggregate decision at the top and per-resource decisions under `ResourceSpecificResults`; older scripts that read `EvalResourceName` from the top-level result will mislead you. Supply condition keys the policies use (find them with `aws iam get-context-keys-for-principal-policy`) through `--context-entries`, or a conditional allow shows up as `implicitDeny` with the key listed in `MissingContextValues`.

### Practising in deliberately vulnerable labs

Learn the exploitation side in a sandbox account, never in a client account. All three projects below deploy intentionally vulnerable IAM into **your own** dedicated AWS account; set a budget alarm and tear them down afterwards.

| Lab | Relevant scenarios | Deploy |
|---|---|---|
| [CloudGoat](https://github.com/RhinoSecurityLabs/cloudgoat) (Rhino) | `iam_privesc_by_rollback` (policy versions), `iam_privesc_by_attachment` (instance profile), `iam_privesc_by_key_rotation` (access keys), `lambda_privesc` (PassRole + Lambda), `vulnerable_lambda`, `glue_privesc`, `iam_enum_basics` | `cloudgoat create iam_privesc_by_rollback`, `cloudgoat destroy all` |
| [IAM Vulnerable](https://github.com/BishopFox/iam-vulnerable) (Bishop Fox) | 31 paths, one principal per path (`privesc1` to `privesc21`, `privesc-ssm-command`, `privesc-codeBuildProject` and so on) | `terraform init && terraform apply`; the EC2, Lambda, Glue, SageMaker and CloudFormation modules cost money and are disabled by default |
| [Pathfinding Labs](https://securitylabs.datadoghq.com/articles/introducing-pathfinding-labs/) (Datadog) | More than 100 Terraform labs (self-escalation, one-hop, multi-hop, cross-account) mapped to pathfinding.cloud IDs | `plabs` CLI |

A useful exercise is to deploy IAM Vulnerable and run every tool in this section against it before an engagement: you learn which paths each tool reports, which it misses, and what the false positives look like. Bishop Fox published exactly that comparison ([Assessing the AWS assessment tools](https://bishopfox.com/blog/assessing-the-aws-assessment-tools)).

### GT-AWS-PRIVESC-1: Map escalation paths account-wide

*Guler Tech methodology.*

#### What it checks

Which principals in the account can reach administrator (or another named high-value role) through one or more escalation edges, regardless of what their own policies look like. This is the test that produces the finding list; tests 2 to 10 confirm and explain individual paths.

#### Prerequisites

Read-only audit role; `auth.json` from [Before you start](#before-you-start); PMapper, Pacu, cloudsplaining and Prowler installed in a virtual environment.

#### Steps

1. Build the PMapper graph and ask for every principal that can escalate. `-s` (`--skip-admin`) hides principals that are already admins, which keeps the output readable:

```bash
pmapper --profile gt-audit graph create
pmapper --profile gt-audit query -s 'preset privesc *'
pmapper --profile gt-audit argquery -s --preset privesc --principal '*'   # same, flag form
# Who can perform a specific lever, on a specific resource
pmapper --profile gt-audit query 'who can do iam:PassRole with arn:aws:iam::111122223333:role/platform-admin'
pmapper --profile gt-audit argquery -s --action 'iam:CreateAccessKey' --resource 'arn:aws:iam::111122223333:user/*'
```

2. Run Pacu's enumeration and scanner **in scan-only mode**. `iam__enum_permissions --all-users --all-roles` stores each principal's confirmed policy set, and the scanner can then run offline on those files:

```text
Pacu (engagement:gt-audit) > import_keys gt-audit
Pacu (engagement:gt-audit) > run iam__enum_permissions --all-users --all-roles
Pacu (engagement:gt-audit) > run iam__privesc_scan --scan-only
Pacu (engagement:gt-audit) > run iam__privesc_scan --method-list
```

3. Run cloudsplaining offline against the snapshot and open the HTML report's Privilege Escalation tab:

```bash
cloudsplaining create-exclusions-file          # edit to exclude known break-glass roles, if agreed
cloudsplaining scan --input-file auth.json --exclusions-file exclusions.yml --output ./cloudsplaining/
```

4. Run the Prowler IAM checks that concern escalation:

```bash
prowler aws --profile gt-audit --checks \
  iam_policy_allows_privilege_escalation iam_inline_policy_allows_privilege_escalation \
  iam_customer_attached_policy_no_administrative_privileges iam_inline_policy_no_administrative_privileges \
  iam_no_custom_policy_permissive_role_assumption
```

5. List compute that runs as admin or near-admin roles, because those are the targets of the existing-compute family:

```bash
cloudfox aws --profile gt-audit workloads
cloudfox aws --profile gt-audit role-trusts
```

6. Merge the results into one table: starting principal, path (pathfinding.cloud ID where one exists), target, tool(s) that reported it. Confirm each candidate with the per-family tests below before you report it.

#### Observation

Illustrative PMapper output:

```text
role/ci-deployer can escalate privileges by accessing the administrative principal role/platform-admin:
   role/ci-deployer can create an EC2 instance and use an existing instance profile to access role/platform-admin
user/helpdesk-1 can escalate privileges by accessing the administrative principal user/ops-admin:
   user/helpdesk-1 can create access keys to authenticate as user/ops-admin
```

#### Evaluation

- **Fail:** any non-administrative principal has a confirmed path (simulator `allowed` on every action in the combination, on the specific resources) to an administrative principal or to a role that the client classifies as high value. Rate per [Rating findings](#rating-findings).
- **Pass:** no confirmed paths, or only paths from principals the client designates as administrators or break-glass.
- **Common false positives:** paths that every tool reports from `"Resource": "*"` while a resource constraint or condition actually blocks them (Prowler and cloudsplaining are policy-centric); paths blocked by an SCP or boundary that the tool did not evaluate; Pacu methods that need a DynamoDB table or Glue endpoint that does not exist. **Common false negatives:** newer services that no open-source tool models (Datadog found 27 of 65 paths undetected by any tool they evaluated), and edges through existing compute that need resource inventory, not just policies.

#### Automated coverage

Prowler: `iam_policy_allows_privilege_escalation`, `iam_inline_policy_allows_privilege_escalation`, `iam_customer_attached_policy_no_administrative_privileges`, `iam_inline_policy_no_administrative_privileges`, `iam_no_custom_policy_permissive_role_assumption`. Security Hub CSPM: `IAM.1` (customer managed policies with `"*"` on `"*"`), `IAM.21` (customer managed policies with service-wide wildcards). Neither Security Hub control models escalation paths; they catch only the crudest policies.

#### Detection

The enumeration itself is read-only, but heavy `List*`/`Get*` IAM activity from one principal can raise GuardDuty `Discovery:IAMUser/AnomalousBehavior`. Tell the client's SOC the source IP and role before you start.

### GT-AWS-PRIVESC-2: Policy manipulation permissions

*Guler Tech methodology.*

#### What it checks

Whether any non-admin principal can change a policy that applies to itself (or to a role it can assume), through `iam:CreatePolicyVersion`, `iam:SetDefaultPolicyVersion`, `iam:Put{User,Group,Role}Policy`, `iam:Attach{User,Group,Role}Policy` or `iam:AddUserToGroup`.

#### Prerequisites

`auth.json`; the candidate list from GT-AWS-PRIVESC-1.

#### Steps

1. List every allow statement in a default policy version or inline policy that grants one of the lever actions, directly or through a wildcard. The jq below covers managed policies; repeat with `.UserDetailList[].UserPolicyList[]`, `.GroupDetailList[].GroupPolicyList[]` and `.RoleDetailList[].RolePolicyList[]` (field `PolicyDocument`) for inline policies:

```bash
jq -r '
  def arr: if type=="array" then . else [.] end;
  .Policies[] as $p
  | $p.PolicyVersionList[] | select(.IsDefaultVersion)
  | .Document.Statement | arr | .[] | select(.Effect=="Allow")
  | (.Action // empty | arr | .[]) as $a
  | select($a | test("^(\\*|iam:\\*|iam:(Create|Set|Put|Attach|Add)\\*|iam:CreatePolicyVersion|iam:SetDefaultPolicyVersion|iam:Put(User|Group|Role)Policy|iam:Attach(User|Group|Role)Policy|iam:AddUserToGroup)$"; "i"))
  | [$p.PolicyName, $a, (.Resource|tostring), ((.Condition // {})|tostring)] | @tsv' auth.json | sort -u
```

Statements that use `NotAction` need a manual read: `"NotAction": "iam:*"` is safe here, `"NotAction": ["iam:DeleteUser"]` grants every lever.

2. For each principal that holds such a statement, find the policies, groups and roles it could modify **that affect itself**. Then confirm with the simulator on those exact resources:

```bash
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::111122223333:user/dev-alice \
  --action-names iam:CreatePolicyVersion iam:SetDefaultPolicyVersion iam:PutUserPolicy \
                 iam:AttachUserPolicy iam:AddUserToGroup \
  --resource-arns arn:aws:iam::111122223333:policy/dev-common \
                  arn:aws:iam::111122223333:user/dev-alice \
                  arn:aws:iam::111122223333:group/platform-admins \
  --query 'EvaluationResults[].{action:EvalActionName,decision:EvalDecision,perResource:ResourceSpecificResults[].[EvalResourceName,EvalResourceDecision]}'
```

3. For `iam:SetDefaultPolicyVersion`, read every non-default version of the policies the principal can touch; an old version with broader access is the target:

```bash
aws iam list-policy-versions --policy-arn arn:aws:iam::111122223333:policy/dev-common
aws iam get-policy-version --policy-arn arn:aws:iam::111122223333:policy/dev-common --version-id v1
```

4. **Benign proof (lab or explicitly approved only).** Prove the write without granting anything: create a *non-default* version (leave out `--set-as-default`) that is identical to the current one, then delete it. For inline policies, put a policy that only denies a non-existent bucket, then delete it.

```bash
# lab only
aws iam create-policy-version --policy-arn arn:aws:iam::111122223333:policy/dev-common --policy-document file://current-version.json
# lab only
aws iam put-user-policy --user-name gt-test-user --policy-name gt-marker --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"s3:GetObject","Resource":"arn:aws:s3:::gt-marker-does-not-exist/*"}]}'
```

#### Observation

A principal with `iam:CreatePolicyVersion` on `arn:aws:iam::111122223333:policy/*` and the `dev-common` policy attached to itself: simulator returns `allowed` for that policy ARN. Or `iam:AttachUserPolicy` on `"*"` with no condition on `iam:PolicyARN`.

#### Evaluation

- **Fail:** the simulator returns `allowed` for any lever action on a resource that affects the caller (its own user, a group it belongs to, a managed policy attached to it, a role it is or can assume), or `iam:AddUserToGroup` into a group with stronger policies; or a non-default version of a policy the principal can set as default is broader than the current one.
- **Pass:** lever actions are absent, denied, scoped to resources that do not affect the caller, or conditioned (for example `iam:PolicyARN` limited to a set of approved, low-privilege policies, together with a permissions boundary requirement).
- Fix: [Least privilege for IAM write actions](#least-privilege-for-iam-write-actions); delete stale policy versions.

#### Automated coverage

Prowler `iam_policy_allows_privilege_escalation` and `iam_inline_policy_allows_privilege_escalation` (combinations `CreatePolicyVersion`, `SetDefaultPolicyVersion`, `iam:Put*Policy`, `iam:Attach*Policy`, `iam:AddUserToGroup`); PMapper; Pacu methods `CreateNewPolicyVersion`, `SetExistingDefaultPolicyVersion`, `PutUserPolicy`, `PutGroupPolicy`, `PutRolePolicy`, `AttachUserPolicy`, `AttachGroupPolicy`, `AttachRolePolicy`, `AddUserToGroup`; Security Hub CSPM `IAM.1`, `IAM.2` (policies attached directly to users) and `IAM.21`.

#### Detection

CloudTrail (`eventSource` `iam.amazonaws.com`): `CreatePolicyVersion` (watch `requestParameters.setAsDefault`), `SetDefaultPolicyVersion`, `PutUserPolicy`, `PutGroupPolicy`, `PutRolePolicy`, `AttachUserPolicy`, `AttachGroupPolicy`, `AttachRolePolicy`, `AddUserToGroup`. Alert with high priority when `requestParameters.policyArn` is `arn:aws:iam::aws:policy/AdministratorAccess` or the policy document contains `"Action": "*"`. GuardDuty `PrivilegeEscalation:IAMUser/AnomalousBehavior` (Medium; the documented example APIs include `AddUserToGroup` and `PutUserPolicy`) fires only when GuardDuty's model considers the call anomalous for that identity, so it is a backstop, not the control.

### GT-AWS-PRIVESC-3: Credential creation on other users

*Guler Tech methodology.*

#### What it checks

Whether a principal can create access keys, create a console password, or reset a console password for an IAM user other than itself, in particular for administrative users.

#### Prerequisites

`auth.json`; the IAM credential report for context (`aws iam generate-credential-report` then `aws iam get-credential-report`).

#### Steps

1. Find statements granting `iam:CreateAccessKey`, `iam:CreateLoginProfile`, `iam:UpdateLoginProfile` (or `iam:*AccessKey*`, `iam:*LoginProfile`) with a `Resource` broader than `arn:aws:iam::*:user/${aws:username}`. Adapt the jq from GT-AWS-PRIVESC-2 with the pattern `iam:(\\*|Create\\*|CreateAccessKey|\\*AccessKey\\*|CreateLoginProfile|UpdateLoginProfile|\\*LoginProfile)`.
2. List the high-value users (admin policies, admin group membership) and check which ones have no console password (`CreateLoginProfile` target), a password but no MFA (`UpdateLoginProfile` target), or fewer than two keys (`CreateAccessKey` target):

```bash
aws iam get-credential-report --query Content --output text | base64 -d \
  | cut -d, -f1,4,8,9,14 > cred-report.csv   # user, password_enabled, mfa_active, key1_active, key2_active
```

Identify the high-value users from their policies and groups in `auth.json`, not from their names.

3. Simulate against each high-value user:

```bash
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::111122223333:role/helpdesk \
  --action-names iam:CreateAccessKey iam:CreateLoginProfile iam:UpdateLoginProfile iam:DeleteAccessKey \
  --resource-arns arn:aws:iam::111122223333:user/ops-admin arn:aws:iam::111122223333:user/AdminJoe \
  --query 'EvaluationResults[].{action:EvalActionName,decision:EvalDecision}'
```

4. **Benign proof (lab or explicitly approved only):** on a client-created test user that holds a harmless policy, create a key and delete it in the same minute. Never create keys or reset passwords for real users; it is persistence for an attacker and an outage for the user.

```bash
aws iam create-access-key --user-name gt-test-user   # lab only; then delete-access-key immediately
```

#### Observation

`allowed` for `iam:CreateAccessKey` on `user/*`, often with a `NotResource` exclusion for one admin user (other admins, or the same admin with different capitalisation, are not excluded).

#### Evaluation

- **Fail:** `allowed` on any user with more privilege than the caller. Rate Critical when the target is an administrator and the caller is broadly reachable.
- **Pass:** credential actions limited to `${aws:username}` (self-service), or to a path such as `user/service/*` whose members hold only low privilege, with a boundary requirement on those users.
- Fix: [Least privilege for IAM write actions](#least-privilege-for-iam-write-actions); move humans to IAM Identity Center so there are no admin IAM users to target.

#### Automated coverage

Prowler `iam_policy_allows_privilege_escalation` (`iam:CreateAccessKey`, `iam:CreateLoginProfile`, `iam:UpdateLoginProfile`, `CreateAccessKey+DeleteAccessKey`); PMapper; Pacu `CreateAccessKey`, `CreateLoginProfile`, `UpdateLoginProfile`. Security Hub CSPM has no control for this path; `IAM.5` and `IAM.19` (MFA for users) reduce the console variant only.

#### Detection

CloudTrail `CreateAccessKey`, `CreateLoginProfile`, `UpdateLoginProfile`, `DeleteAccessKey` where `requestParameters.userName` differs from the caller's user name; then `ConsoleLogin` or first API use from the new key. GuardDuty `Persistence:IAMUser/AnomalousBehavior` lists `CreateAccessKey` among its example APIs.

### GT-AWS-PRIVESC-4: Trust policy manipulation and over-trusting roles

*Guler Tech methodology.*

#### What it checks

Whether a principal can rewrite a more privileged role's trust policy (`iam:UpdateAssumeRolePolicy`), and whether privileged roles trust the whole account so that any principal with a broad `sts:AssumeRole` grant can assume them.

#### Prerequisites

`auth.json`.

#### Steps

1. List roles whose trust policy allows the account root or a wildcard, together with the permissions they carry:

```bash
jq -r '.RoleDetailList[]
  | . as $r
  | $r.AssumeRolePolicyDocument.Statement[]
  | select(.Effect=="Allow")
  | (.Principal | if type=="object" then (.AWS // empty) else . end
     | if type=="array" then .[] else . end) as $p
  | select($p=="*" or ($p|test(":root$")))
  | [$r.RoleName, $p, ((.Condition // {})|tostring),
     ([$r.AttachedManagedPolicies[].PolicyName]|join(","))] | @tsv' auth.json
```

2. Find principals with `sts:AssumeRole` on `"*"` (or on `role/*`) and those with `iam:UpdateAssumeRolePolicy` on anything:

```bash
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::111122223333:role/developer \
  --action-names sts:AssumeRole iam:UpdateAssumeRolePolicy \
  --resource-arns arn:aws:iam::111122223333:role/platform-admin \
  --query 'EvaluationResults[].{action:EvalActionName,decision:EvalDecision}'
```

3. Cross-check with `cloudfox aws --profile gt-audit role-trusts` and PMapper (`query 'who can do sts:AssumeRole with arn:aws:iam::111122223333:role/platform-admin'`). Remember the simulator does not read the role's trust policy; combine both halves yourself.
4. **Benign proof (lab or explicitly approved only):** on a lab role, add your test principal to the trust policy, assume it, call `sts get-caller-identity`, and restore the original document from your saved copy.

```bash
aws sts assume-role --role-arn arn:aws:iam::111122223333:role/gt-lab-target --role-session-name gt-proof   # lab only
```

#### Observation

`platform-admin` trusts `arn:aws:iam::111122223333:root` with no condition, and the `developer` role allows `sts:AssumeRole` on `"*"`: every developer is an administrator.

#### Evaluation

- **Fail:** a non-admin principal can update the trust policy of a more privileged role; or a privileged role trusts the account root (or `"*"`) and any non-admin principal holds `sts:AssumeRole` on it.
- **Pass:** privileged roles trust specific principal ARNs (or Identity Center permission set roles) and, where they trust the account, require a condition such as `aws:PrincipalArn` matching an admin path or `aws:MultiFactorAuthPresent`; `iam:UpdateAssumeRolePolicy` is held only by administrators.
- Fix: [Least privilege for IAM write actions](#least-privilege-for-iam-write-actions); cross-account and federation hardening is in [STS, cross-account trust and federation](/cloud/aws-sts-cross-account-trust-federation/).

#### Automated coverage

Prowler `iam_no_custom_policy_permissive_role_assumption`, `iam_policy_allows_privilege_escalation` (`iam:UpdateAssumeRolePolicy` and the `AssumeRole+...` combinations), `iam_role_cross_service_confused_deputy_prevention` (service trusts); Pacu `UpdateRolePolicyToAssumeIt`; PMapper; CloudFox `role-trusts`. IAM Access Analyzer external access findings cover trust to principals outside the account or organisation, not this in-account case.

#### Detection

CloudTrail `UpdateAssumeRolePolicy` (alert on any change to a role tagged or named as privileged), followed by `AssumeRole` (`eventSource` `sts.amazonaws.com`) from a new principal for that role.

### GT-AWS-PRIVESC-5: PassRole scope and conditions

*Guler Tech methodology.*

#### What it checks

Which principals may pass which roles, to which services. This is the prerequisite half of every PassRole path in tests 6 and 7, and it is worth reporting on its own when the scope is wide, because it turns any future compute permission into an escalation.

#### Prerequisites

`auth.json`.

#### Steps

1. List every allow statement that grants `iam:PassRole` (directly, as `iam:Pass*`, `iam:*` or `*`), with its resource and conditions. Use the jq from GT-AWS-PRIVESC-2 with the pattern `^(\\*|iam:\\*|iam:Pass\\*|iam:PassRole)$` on managed and inline policies.
2. Classify each grant: `Resource` is `"*"` or `role/*` (wide); has `iam:PassedToService` (service-limited); has `iam:AssociatedResourceArn` (resource-limited, supported by some services only).
3. List the roles that each service can actually use. A role can only be used by a service its trust policy allows, and EC2 additionally needs an instance profile:

```bash
# role -> trusted service principal(s)
jq -r '.RoleDetailList[] | . as $r | .AssumeRolePolicyDocument.Statement[]
  | select(.Effect=="Allow")
  | (.Principal.Service? // empty | if type=="array" then .[] else . end) as $s
  | [$r.RoleName, $s] | @tsv' auth.json | sort > role-services.tsv

# roles that are in an instance profile
jq -r '.RoleDetailList[] | select((.InstanceProfileList|length) > 0)
  | [.RoleName, (.InstanceProfileList[].InstanceProfileName)] | @tsv' auth.json
```

4. Intersect: for each principal with wide PassRole, the dangerous roles are those that (a) are more privileged than the principal and (b) trust a service where the principal can create or modify compute (tests 6 to 8). Confirm the PassRole half with the simulator, passing the service the condition expects:

```bash
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::111122223333:role/ci-deployer \
  --action-names iam:PassRole \
  --resource-arns arn:aws:iam::111122223333:role/platform-admin \
  --context-entries "ContextKeyName=iam:PassedToService,ContextKeyValues=lambda.amazonaws.com,ContextKeyType=string" \
  --query 'EvaluationResults[].{decision:EvalDecision,missing:MissingContextValues}'
```

Repeat with `ec2.amazonaws.com`, `ecs-tasks.amazonaws.com`, `codebuild.amazonaws.com`, `cloudformation.amazonaws.com`, `glue.amazonaws.com` and `sagemaker.amazonaws.com` as needed.

5. Check custom policies before deployment with IAM Access Analyzer's custom policy check, which is also how you recommend the client gates new policies (see [Preventive checks in the pipeline](#preventive-checks-in-the-pipeline)):

```bash
aws accessanalyzer check-access-not-granted --policy-type IDENTITY_POLICY \
  --policy-document file://ci-deployer-policy.json \
  --access '[{"actions":["iam:PassRole"],"resources":["arn:aws:iam::111122223333:role/platform-admin"]}]'
```

#### Observation

`ci-deployer` allows `iam:PassRole` on `"*"` with no condition; `platform-admin` (AdministratorAccess) trusts `lambda.amazonaws.com` and `ec2.amazonaws.com`, and has an instance profile.

#### Evaluation

- **Fail (High when combined with test 6 to 8 findings):** a non-admin principal can pass a role more privileged than itself to a service where it can run code.
- **Fail (Medium, latent):** `iam:PassRole` on `"*"` or `role/*` without `iam:PassedToService`, even where no compute permission exists today.
- **Pass:** PassRole is scoped to named roles or a dedicated path (`role/app/lambda/*`) whose members are no more privileged than intended, with `iam:PassedToService`.
- Fix: [Scoping PassRole](#scoping-passrole).

#### Automated coverage

Prowler `iam_policy_allows_privilege_escalation` (every `PassRole+...` combination); cloudsplaining (privilege escalation and "infrastructure modification" findings, which list unconstrained `iam:PassRole`); PMapper edges for PassRole. Security Hub CSPM has no PassRole control.

#### Detection

None for PassRole itself (no CloudTrail event). Detect the consuming calls in tests 6 and 7, and alert when the role ARN in their `requestParameters` is a privileged role.

### GT-AWS-PRIVESC-6: PassRole with new compute (EC2, Lambda, ECS, CodeBuild)

*Guler Tech methodology.*

#### What it checks

Whether a principal that can pass a privileged role (test 5) can also create compute that runs as it: EC2 instances, Lambda functions (invoked, triggered by an event source, or opened to another account), ECS tasks, or CodeBuild projects.

#### Prerequisites

Test 5 results; the list of privileged roles that trust each service.

#### Steps

1. Simulate the compute half of each combination. Use real target ARNs where the policy is resource-scoped; for `ec2:RunInstances`, which authorises several resource types at once, a `"*"` simulation is a reasonable first pass, followed by a read of the policy for instance, subnet or tag conditions:

```bash
P=arn:aws:iam::111122223333:role/ci-deployer
aws iam simulate-principal-policy --policy-source-arn "$P" \
  --action-names ec2:RunInstances ec2:RequestSpotInstances \
                 lambda:CreateFunction lambda:InvokeFunction lambda:CreateEventSourceMapping lambda:AddPermission \
                 ecs:RegisterTaskDefinition ecs:RunTask ecs:StartTask ecs:CreateService \
                 codebuild:CreateProject codebuild:StartBuild codebuild:StartBuildBatch \
  --query 'EvaluationResults[].[EvalActionName,EvalDecision]' --output table
```

2. Combine with test 5. A path exists when every action in one row of the [PassRole table](#passrole-to-a-service-that-runs-code) is `allowed` **and** a privileged role trusts that service. For ECS also check that a cluster exists that the principal can run tasks in (`aws ecs list-clusters`) and that the target role trusts `ecs-tasks.amazonaws.com`.
3. Where the client wants evidence beyond the simulator, EC2's `--dry-run` checks the EC2 permissions without launching anything (`DryRunOperation` means allowed). It is not documented whether the dry run also evaluates `iam:PassRole` on the instance profile, so keep the simulator for that half.

```bash
aws ec2 run-instances --dry-run --image-id ami-EXAMPLE --instance-type t3.micro \
  --iam-instance-profile Name=platform-admin-profile        # lab or explicitly approved only
```

4. **Benign proof (lab or explicitly approved only).** The proof is "code ran as the role and said who it is", nothing more. For Lambda, a three-line handler, then invoke and delete:

```python
# index.py, lab only: returns the identity of the execution role
import boto3
def handler(event, context):
    return boto3.client("sts").get_caller_identity()["Arn"]
```

```bash
aws lambda create-function --function-name gt-proof --runtime python3.12 --handler index.handler \
  --role arn:aws:iam::111122223333:role/gt-lab-target --zip-file fileb://index.zip   # lab only
```

For EC2, user data that runs `aws sts get-caller-identity` (cloud-init output typically appears in `aws ec2 get-console-output`); for CodeBuild, a buildspec whose only command is `aws sts get-caller-identity` (visible in the build log). Delete what you created and record the resource IDs in your evidence.

#### Observation

`ci-deployer`: `iam:PassRole` allowed on `platform-admin` for `lambda.amazonaws.com`; `lambda:CreateFunction` and `lambda:InvokeFunction` allowed on `function:*`. The lab proof returns `arn:aws:sts::111122223333:assumed-role/gt-lab-target/gt-proof`.

#### Evaluation

- **Fail:** all actions of a combination are allowed and a more privileged role is passable to, and trusted by, that service.
- **Pass:** any half is missing: no passable privileged role for the service, or no create/invoke permission, or an SCP denies the combination for non-admin principals.
- Remember the variants: no `lambda:InvokeFunction` does not close the Lambda path if `lambda:CreateEventSourceMapping` (with an existing stream or queue) or `lambda:AddPermission` is allowed.
- Fix: [Scoping PassRole](#scoping-passrole); compute-specific hardening is in [EC2](/cloud/aws-ec2-imds-ebs-ssm-security/), [Lambda](/cloud/aws-lambda-serverless-security/) and [containers](/cloud/aws-containers-ecs-eks-ecr-security/).

#### Automated coverage

Prowler combinations `PassRole+EC2`, `PassRole+EC2SpotInstances`, `PassRole+CreateLambda+Invoke`, `PassRole+CreateLambda+ExistingDynamo`, `PassRole+CreateLambda+NewDynamo`, `PassRole+CreateLambda+AddPermission`, `PassRole+ECS+RegisterTaskDef+RunTask` (and `StartTask`, `CreateService`), `PassRole+CodeBuildCreateProject+StartBuild`; Pacu `CreateEC2WithExistingIP`, `PassExistingRoleToNewLambdaThenInvoke`, `PassExistingRoleToNewLambdaThenTriggerWithExistingDynamo`, `PassExistingRoleToNewLambdaThenTriggerWithNewDynamo`, `PassExistingRoleToNewLambdaThenInvokeCrossAccount`; PMapper for EC2 and Lambda.

#### Detection

CloudTrail `RunInstances` and `RequestSpotInstances` (`requestParameters.iamInstanceProfile`), `CreateFunction20150331` (`requestParameters.role`), `CreateEventSourceMapping20150331`, `AddPermission20150331v2`, `RegisterTaskDefinition` (`taskRoleArn`), `RunTask`/`StartTask`/`CreateService` (including `overrides.taskRoleArn`), `CreateProject` and `StartBuild` (`serviceRole`). Lambda `Invoke` is a data event and is logged only if you enable Lambda data events. GuardDuty `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS` and `.InsideAWS` (EC2) and `UnauthorizedAccess:IAMUser/ResourceCredentialExfiltration.OutsideAWS` and `.InsideAWS` (Lambda and ECS) fire when the role's credentials are later used from elsewhere.

### GT-AWS-PRIVESC-7: PassRole with orchestration and data services

*Guler Tech methodology.*

#### What it checks

The same pattern as test 6 for services that run templates, jobs or notebooks as a role: CloudFormation stacks (and StackSets and change sets), Glue dev endpoints and jobs, SageMaker notebooks, training and processing jobs, and, where still in use, Data Pipeline.

#### Prerequisites

Test 5 results. Confirm which of these services the account actually uses (`aws cloudformation list-stacks`, `aws glue get-jobs`, `aws sagemaker list-notebook-instances`, `aws datapipeline list-pipelines`) in each region.

#### Steps

1. Simulate the service half:

```bash
aws iam simulate-principal-policy --policy-source-arn "$P" \
  --action-names cloudformation:CreateStack cloudformation:CreateStackSet \
                 cloudformation:CreateChangeSet cloudformation:ExecuteChangeSet \
                 glue:CreateDevEndpoint glue:GetDevEndpoint glue:CreateJob glue:StartJobRun glue:CreateTrigger \
                 sagemaker:CreateNotebookInstance sagemaker:CreatePresignedNotebookInstanceUrl \
                 sagemaker:CreateTrainingJob sagemaker:CreateProcessingJob \
                 datapipeline:CreatePipeline datapipeline:PutPipelineDefinition datapipeline:ActivatePipeline \
  --query 'EvaluationResults[].[EvalActionName,EvalDecision]' --output table
```

2. Intersect with roles that trust `cloudformation.amazonaws.com`, `glue.amazonaws.com`, `sagemaker.amazonaws.com` or `datapipeline.amazonaws.com` and are passable by the principal. CloudFormation deserves extra attention: a stack role usually has IAM write permissions so that templates can create roles, so a passable CloudFormation role is often an admin role in all but name.
3. **Benign proof (lab or explicitly approved only).** For CloudFormation, a template that creates one marker resource the starting principal could not create itself, then delete the stack:

```yaml
# gt-proof.yaml, lab only
AWSTemplateFormatVersion: "2010-09-09"
Resources:
  Marker:
    Type: AWS::SSM::Parameter
    Properties:
      Name: /gt-pentest/marker
      Type: String
      Value: created-by-stack-role
```

```bash
aws cloudformation create-stack --stack-name gt-proof --template-body file://gt-proof.yaml \
  --role-arn arn:aws:iam::111122223333:role/gt-lab-cfn-role   # lab only; delete-stack afterwards
```

For Glue, a job script that prints `get_caller_identity()` to its log. SageMaker notebooks cost money and take minutes to start; simulator evidence is normally enough.

#### Observation

`data-eng` users: `iam:PassRole` on `role/*`; `glue:CreateJob` and `glue:StartJobRun` allowed; the account's `GlueAdminRole` trusts `glue.amazonaws.com` and has `AdministratorAccess`.

#### Evaluation

- **Fail:** as for test 6. Rate CloudFormation and Glue paths at least as high as the role they reach.
- **Pass:** no passable privileged role for these services, or the service permissions are absent.
- Status checks: Data Pipeline is closed to new customers and CodeStar project creation ended on 31 July 2024, so report those paths only where the service is still active in the account. Glue dev endpoints are legacy (Glue 0.9 and 1.0 only, console removed in 2023, API still documented); check that `CreateDevEndpoint` is still accepted before you rely on it.
- Fix: [Scoping PassRole](#scoping-passrole); for CloudFormation, give stack roles permission boundaries and restrict who can pass them (see [CI/CD and IaC security](/cloud/aws-cicd-iac-security/)).

#### Automated coverage

Prowler `PassRole+CloudFormationCreateStack`, `PassRole+CloudFormationCreateStackSet`, `CloudFormationChangeSet`, `PassRole+GlueCreateDevEndpoint`, `PassRole+GlueCreateJob+StartJobRun`, `PassRole+GlueCreateJob+CreateTrigger`, `PassRole+SageMakerCreateNotebookInstance`, `PassRole+SageMakerCreateTrainingJob`, `PassRole+SageMakerCreateProcessingJob`, `PassRole+DataPipeline`; Pacu `PassExistingRoleToNewCloudFormation`, `PassExistingRoleToNewGlueDevEndpoint`, `PassExistingRoleToNewDataPipeline`.

#### Detection

CloudTrail `CreateStack`, `CreateStackSet`, `CreateChangeSet`, `ExecuteChangeSet` (`requestParameters.roleARN`); `CreateDevEndpoint`, `CreateJob`, `StartJobRun`, `CreateTrigger` (`role`); `CreateNotebookInstance`, `CreatePresignedNotebookInstanceUrl`, `CreateTrainingJob`, `CreateProcessingJob` (`roleArn`); `CreatePipeline`, `PutPipelineDefinition`, `ActivatePipeline`. A CloudFormation stack that creates IAM resources leaves its own `CreateRole`, `AttachRolePolicy` or `CreateUser` events with `invokedBy` `cloudformation.amazonaws.com`.

### GT-AWS-PRIVESC-8: Modifying existing compute that runs as a stronger role

*Guler Tech methodology.*

#### What it checks

Whether a principal can change code or configuration of compute that already runs as a more privileged role: Lambda code, layers and configuration, EC2 user data and launch templates, instance profile associations, CloudFormation stacks with service roles, CodeBuild projects, Glue endpoints and jobs, and SageMaker notebooks. No PassRole is needed for most of these, which is why policy-only tools miss them.

#### Prerequisites

The workload inventory from GT-AWS-PRIVESC-1 (CloudFox `workloads`), plus per-service role inventories:

```bash
for r in $REGIONS; do
  aws ec2 describe-instances --region "$r" \
    --query 'Reservations[].Instances[].[InstanceId,IamInstanceProfile.Arn,State.Name]' --output text
  aws cloudformation describe-stacks --region "$r" --query 'Stacks[?RoleARN].[StackName,RoleARN]' --output text
  aws codebuild list-projects --region "$r" --output text
  aws glue get-jobs --region "$r" --query 'Jobs[].[Name,Role]' --output text
  aws sagemaker list-notebook-instances --region "$r" --query 'NotebookInstances[].NotebookInstanceName' --output text
done
```

`lambda-roles.tsv` from [Before you start](#before-you-start) covers Lambda.

#### Steps

1. Rank the workloads by role privilege (admin, IAM write, data access to crown jewels).
2. For each high-value workload, simulate the modifying actions on its ARN:

```bash
aws iam simulate-principal-policy --policy-source-arn arn:aws:iam::111122223333:role/developer \
  --action-names lambda:UpdateFunctionCode lambda:UpdateFunctionConfiguration lambda:InvokeFunction \
  --resource-arns arn:aws:lambda:eu-west-2:111122223333:function:ec2-bootstrap \
  --query 'EvaluationResults[].{action:EvalActionName,decision:EvalDecision}'

aws iam simulate-principal-policy --policy-source-arn arn:aws:iam::111122223333:role/developer \
  --action-names ec2:ModifyInstanceAttribute ec2:StopInstances ec2:StartInstances \
                 ec2:CreateLaunchTemplateVersion ec2:ModifyLaunchTemplate \
                 ec2:AssociateIamInstanceProfile ec2:ReplaceIamInstanceProfileAssociation \
  --resource-arns arn:aws:ec2:eu-west-2:111122223333:instance/i-0123456789abcdef0 \
  --query 'EvaluationResults[].{action:EvalActionName,decision:EvalDecision}'
```

Do the same for `cloudformation:UpdateStack` (stack ARN), `codebuild:StartBuild` and `codebuild:UpdateProject` (project ARN), `glue:UpdateDevEndpoint`, `glue:UpdateJob` and `glue:StartJobRun`, and `sagemaker:CreatePresignedNotebookInstanceUrl` (notebook ARN).

3. Check the mitigating controls on the target: Lambda code signing with an `Enforce` policy blocks unsigned `UpdateFunctionCode` packages; a CodeBuild project whose source is a protected repository still accepts a buildspec override at `StartBuild` unless the policy denies it; an EC2 instance whose user data is not re-run on start does not run new user data (cloud-init runs scripts once per instance by default, unless configured otherwise).
4. **Benign proof (explicitly approved only).** Lambda's `UpdateFunctionCode` accepts a dry run that validates parameters and permissions without changing the code. EC2's `ModifyInstanceAttribute` also supports `--dry-run`. These are the only proofs we run outside a lab for this family:

```bash
aws lambda update-function-code --function-name ec2-bootstrap --zip-file fileb://index.zip --dry-run
aws ec2 modify-instance-attribute --instance-id i-0123456789abcdef0 --attribute userData --value EXAMPLE --dry-run
```

#### Observation

`developer` can `lambda:UpdateFunctionCode` on `function:*`; `ec2-bootstrap` runs as a role with `iam:*`. The dry run returns success, not `AccessDeniedException`.

#### Evaluation

- **Fail:** a principal can modify code or configuration of a workload whose role is more privileged than the principal, with a way to make it run (invoke permission, a schedule or event that fires anyway, or an instance restart it can trigger).
- **Pass:** modifying actions are scoped to workloads whose roles are no more privileged than the caller (by name prefix, path or tag condition on the workload, where the service supports it), or the workload is protected by code signing or an SCP.
- Fix: [Protecting compute that runs as a privileged role](#protecting-compute-that-runs-as-a-privileged-role).

#### Automated coverage

Prowler `lambda:UpdateFunctionCode`, `lambda:UpdateFunctionConfiguration`, `UpdateFunctionCode+InvokeFunction`, `EC2ModifyInstanceAttribute`, `EC2ModifyLaunchTemplate`, `CloudFormationUpdateStack`, `CodeBuildStartBuild`, `GlueUpdateDevEndpoint`, `PassRole+GlueUpdateJob+StartJobRun`, `SageMakerCreatePresignedNotebookInstanceUrl`, `SageMakerNotebookLifecycleConfig`, `AppRunnerUpdateService`; Pacu `EditExistingLambdaFunctionWithRole`, `UpdateExistingGlueDevEndpoint`; CloudFox `workloads` and `lambda` for the target list. Because these combinations are policy-only in Prowler, every hit needs the target inventory to be meaningful.

#### Detection

CloudTrail `UpdateFunctionCode20150331v2`, `UpdateFunctionConfiguration20150331v2` (the `Environment` and `ZipFile` parameters are omitted from the logs), `PublishLayerVersion20181031`; `ModifyInstanceAttribute` (`userData`), `StopInstances` and `StartInstances` in quick succession on the same instance, `CreateLaunchTemplateVersion`, `ModifyLaunchTemplate`, `AssociateIamInstanceProfile`, `ReplaceIamInstanceProfileAssociation`; `UpdateStack`, `ExecuteChangeSet`; `StartBuild` with `buildspecOverride`, `UpdateProject`; `UpdateDevEndpoint`, `UpdateJob`; `CreatePresignedNotebookInstanceUrl`. GuardDuty `Persistence:IAMUser/AnomalousBehavior` lists `ModifyInstanceAttribute` among its examples, and `PrivilegeEscalation:IAMUser/AnomalousBehavior` lists `AssociateIamInstanceProfile`.

### GT-AWS-PRIVESC-9: Command execution on running compute

*Guler Tech methodology.*

#### What it checks

Whether a principal can run commands on, or open a shell into, compute that has a stronger role: SSM Run Command (`ssm:SendCommand`), Session Manager (`ssm:StartSession`), EC2 Instance Connect (`ec2-instance-connect:SendSSHPublicKey`, plus network reach to port 22), and ECS Exec (`ecs:ExecuteCommand`). From a shell, the instance or task credentials are one local HTTP request away, so the principal effectively holds the workload's role.

#### Prerequisites

The EC2 and ECS inventory from test 8, and the SSM-managed instance list:

```bash
for r in $REGIONS; do
  aws ssm describe-instance-information --region "$r" \
    --query 'InstanceInformationList[].[InstanceId,PlatformName,PingStatus]' --output text
done
```

#### Steps

1. Simulate on the highest-value instances and the SSM documents that matter. `ssm:SendCommand` authorises both the instance and the document, so include both ARNs; `ssm:StartSession` authorises the instance and the session document:

```bash
aws iam simulate-principal-policy --policy-source-arn arn:aws:iam::111122223333:role/support \
  --action-names ssm:SendCommand ssm:StartSession ec2-instance-connect:SendSSHPublicKey \
  --resource-arns arn:aws:ec2:eu-west-2:111122223333:instance/i-0123456789abcdef0 \
                  arn:aws:ssm:eu-west-2::document/AWS-RunShellScript \
  --query 'EvaluationResults[].{action:EvalActionName,perResource:ResourceSpecificResults[].[EvalResourceName,EvalResourceDecision]}'
```

2. Read the policy for tag conditions (`ssm:resourceTag/...` or `aws:ResourceTag/...` on the instance). A policy that limits sessions to `Environment=dev` instances is only as good as the principal's inability to tag a production instance `Environment=dev` (`ec2:CreateTags`).
3. For ECS, list tasks with ECS Exec enabled (`aws ecs describe-tasks ... --query 'tasks[].[taskArn,enableExecuteCommand]'`) and simulate `ecs:ExecuteCommand` on their cluster and task ARNs.
4. **Benign proof (lab or explicitly approved only):** run `aws sts get-caller-identity` through Run Command on a lab instance and read the output; for Session Manager, open a session and run the same command. Do not read the credentials themselves.

```bash
aws ssm send-command --instance-ids i-0123456789abcdef0 --document-name AWS-RunShellScript \
  --parameters 'commands=["aws sts get-caller-identity"]'   # lab only
```

#### Observation

`support` may `ssm:StartSession` on `instance/*` with `AWS-StartInteractiveCommand` allowed; the `bastion-ops` instance profile holds `AdministratorAccess`.

#### Evaluation

- **Fail:** a principal can execute commands on an instance or task whose role is more privileged than the principal.
- **Pass:** command execution is limited to instances whose roles are no stronger than the operator's, by ARN or by tags the operator cannot change; and powerful roles are not attached to interactive hosts.
- Fix: [Protecting compute that runs as a privileged role](#protecting-compute-that-runs-as-a-privileged-role); SSM details are in [EC2, IMDS, EBS and SSM](/cloud/aws-ec2-imds-ebs-ssm-security/).

#### Automated coverage

Prowler `SSMSendCommand`, `SSMStartSession`, `EC2InstanceConnect+SendSSHPublicKey`, `ECS+ExecuteCommand`; IAM Vulnerable paths `privesc-ssm-command`, `privesc-ssm-session`, `privesc-instanceConnect` for practice.

#### Detection

CloudTrail `SendCommand` and `StartSession` (`eventSource` `ssm.amazonaws.com`), `SendSSHPublicKey` (`ec2-instance-connect.amazonaws.com`), `ExecuteCommand` (`ecs.amazonaws.com`). Session Manager session logging to S3 or CloudWatch Logs records what was typed. GuardDuty `InitialAccess:IAMUser/AnomalousBehavior` lists `StartSession` among its example APIs, and MITRE ATT&CK tracks this behaviour as [T1651 Cloud Administration Command](https://attack.mitre.org/techniques/T1651/).

### GT-AWS-PRIVESC-10: Permission boundary and delegated administration gaps

*Guler Tech methodology.*

#### What it checks

Where the client uses permissions boundaries to delegate IAM administration (developers who may create roles for their own workloads, a helpdesk that manages users), whether the boundary actually holds: new principals must carry it, nobody can remove or edit it, and bounded principals cannot reach unbounded roles through PassRole.

#### Prerequisites

`auth.json`; the client's description of the intended delegation model.

#### Steps

1. List bounded principals and the boundary policies in use:

```bash
jq -r '(.UserDetailList[], .RoleDetailList[])
  | select(.PermissionsBoundary)
  | [(.UserName // .RoleName), .PermissionsBoundary.PermissionsBoundaryArn] | @tsv' auth.json
```

2. For every principal that can create users or roles, check that creation **requires** the boundary. Simulate without the context key (a pass returns `implicitDeny`), then with it (expect `allowed`):

```bash
P=arn:aws:iam::111122223333:role/dev-iam-delegate
aws iam simulate-principal-policy --policy-source-arn "$P" \
  --action-names iam:CreateRole iam:CreateUser iam:PutRolePermissionsBoundary iam:PutUserPermissionsBoundary \
  --query 'EvaluationResults[].[EvalActionName,EvalDecision]' --output table

aws iam simulate-principal-policy --policy-source-arn "$P" \
  --action-names iam:CreateRole iam:AttachRolePolicy iam:PutRolePolicy \
  --context-entries "ContextKeyName=iam:PermissionsBoundary,ContextKeyValues=arn:aws:iam::111122223333:policy/DevBoundary,ContextKeyType=string" \
  --query 'EvaluationResults[].[EvalActionName,EvalDecision]' --output table
```

3. Check that the boundary cannot be removed or edited:

```bash
aws iam simulate-principal-policy --policy-source-arn "$P" \
  --action-names iam:DeleteRolePermissionsBoundary iam:DeleteUserPermissionsBoundary \
                 iam:CreatePolicyVersion iam:SetDefaultPolicyVersion iam:DeletePolicyVersion iam:DeletePolicy \
  --resource-arns arn:aws:iam::111122223333:policy/DevBoundary arn:aws:iam::111122223333:role/dev-app-role \
  --query 'EvaluationResults[].{action:EvalActionName,perResource:ResourceSpecificResults[].[EvalResourceName,EvalResourceDecision]}'
```

4. Check that bounded principals cannot pass unbounded roles (test 5 for each bounded principal, restricted to roles without a `PermissionsBoundary`).
5. Read the boundary policy itself: does it allow IAM write, PassRole on `*`, or the credential actions from test 3 on other users? A boundary copied from AWS's delegation example still lets the delegate create keys and reset passwords for every user except the one named admin.

#### Observation

`dev-iam-delegate` can `iam:CreateRole` with or without a boundary (`allowed` in both simulations), and `iam:DeleteRolePermissionsBoundary` is `allowed` on `role/*`.

#### Evaluation

- **Fail:** creation without the boundary is allowed; the boundary can be removed, replaced or edited by the delegate; or a bounded principal can pass an unbounded, more privileged role.
- **Pass:** all creation and policy-write actions carry a `StringEquals` condition on `iam:PermissionsBoundary`; explicit denies cover boundary removal and edits to the boundary policies; PassRole for delegates is limited to roles in a path that itself requires the boundary.
- Fix: [Permission boundaries that hold](#permission-boundaries-that-hold).

#### Automated coverage

No Prowler or Security Hub CSPM check models boundary completeness. PMapper accounts for boundaries in its edges; the simulator evaluates them (`PermissionsBoundaryDecisionDetail`).

#### Detection

CloudTrail `DeleteUserPermissionsBoundary`, `DeleteRolePermissionsBoundary`, `PutUserPermissionsBoundary`, `PutRolePermissionsBoundary`, and `CreateRole`/`CreateUser` whose `requestParameters` lack `permissionsBoundary`; any `CreatePolicyVersion` or `SetDefaultPolicyVersion` on a boundary policy ARN.

### GT-AWS-PRIVESC-11: Organisation guardrails against escalation

*Guler Tech methodology.*

#### What it checks

Whether SCPs (and, for trust policies, RCPs) deny the lever actions to everyone except named administrative roles, across all member accounts, and whether the management account, which SCPs cannot restrict, is kept free of workloads and broad human access.

#### Prerequisites

Read access to AWS Organizations from the management account or a delegated administrator. Organisation design is covered in depth in [Organizations and multi-account security](/cloud/aws-organizations-multi-account-security/).

#### Steps

1. List SCPs and RCPs and where they are attached:

```bash
aws organizations list-policies --filter SERVICE_CONTROL_POLICY --query 'Policies[].[Id,Name]' --output text
aws organizations list-policies --filter RESOURCE_CONTROL_POLICY --query 'Policies[].[Id,Name]' --output text
aws organizations describe-policy --policy-id p-examplepolicyid --query 'Policy.Content' --output text | jq .
aws organizations list-targets-for-policy --policy-id p-examplepolicyid
```

2. Look for deny statements that cover the lever actions from tests 2 to 4 and 10 (policy writes, credential creation, trust updates, boundary removal), with an exception keyed on `aws:PrincipalArn` for the platform's admin and pipeline roles. Check that the exception patterns cannot be satisfied by a role the attacker creates (`arn:aws:iam::*:role/*admin*` is satisfiable by anyone with `iam:CreateRole`).
3. In a member account, confirm the effect with the simulator, which evaluates SCPs: `OrganizationsDecisionDetail.AllowedByOrganizations` is `false` for a denied action.

```bash
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::444455556666:role/developer \
  --action-names iam:CreatePolicyVersion iam:AttachRolePolicy iam:CreateAccessKey iam:UpdateAssumeRolePolicy \
  --query 'EvaluationResults[].[EvalActionName,EvalDecision,OrganizationsDecisionDetail.AllowedByOrganizations]' --output table
```

4. In the management account, list IAM users, roles other than AWS-created ones, and any workloads (Lambda, EC2, CodeBuild). Each is outside SCP coverage.
5. If role trust policies are a concern (test 4), check for an RCP that limits `sts:AssumeRole` to principals in the organisation (`aws:PrincipalOrgID`), with the exceptions AWS services need.

#### Observation

The only SCP is `FullAWSAccess` plus a region deny; IAM write is unrestricted in every member account. The management account hosts a CodeBuild project with an admin role.

#### Evaluation

- **Fail:** no SCP denies the high-risk lever actions to non-admin principals, or exceptions are satisfiable by attacker-created principals; workloads or broad human access in the management account.
- **Pass:** a tested SCP baseline denies policy writes, credential creation, trust updates and boundary removal except for named platform roles; the management account has no workloads.
- SCPs are a backstop. They do not replace scoping the identity policies, because they cannot express "only on resources that are not more privileged than you".
- Fix: [SCP and RCP guardrails](#scp-and-rcp-guardrails).

#### Automated coverage

None of the Security Hub CSPM or Prowler checks evaluates SCP content for escalation coverage (Prowler's `organizations_scp_check_deny_regions` checks region restrictions only). Review by hand.

#### Detection

CloudTrail in the management account: `CreatePolicy`, `UpdatePolicy`, `AttachPolicy`, `DetachPolicy`, `DeletePolicy` (`eventSource` `organizations.amazonaws.com`), and `RegisterDelegatedAdministrator`.

### GT-AWS-PRIVESC-12: Detection coverage for escalation activity

*Guler Tech methodology.*

#### What it checks

Whether the client would notice an escalation in progress: CloudTrail captures the relevant management events in every region and account, GuardDuty is on, and specific rules alert on the lever actions rather than relying on anomaly detection alone. This test checks that alerts exist and work; it never tests ways to avoid them.

#### Prerequisites

Read access to CloudTrail, EventBridge, CloudWatch and GuardDuty configuration. Logging in depth is in [CloudTrail logging](/cloud/aws-cloudtrail-logging/), alerting in [CloudWatch and EventBridge monitoring](/cloud/aws-cloudwatch-eventbridge-monitoring/), and GuardDuty in [detection and posture services](/cloud/aws-detection-posture-services/).

#### Steps

1. Confirm an organisation or multi-region trail with management events (read and write):

```bash
aws cloudtrail describe-trails --query 'trailList[].[Name,IsMultiRegionTrail,IsOrganizationTrail,HomeRegion]' --output table
aws cloudtrail get-event-selectors --trail-name org-trail
```

2. Confirm GuardDuty is enabled in every region in use (`aws guardduty list-detectors --region "$r"` in the region loop) and that findings reach someone.
3. List the rules that alert on IAM changes. IAM is a global service and its CloudTrail events are delivered to EventBridge in US East (N. Virginia), so rules for IAM events belong in `us-east-1`; check the current docs for your partition:

```bash
aws events list-rules --region us-east-1 --query 'Rules[].[Name,EventPattern]' --output text
aws logs describe-metric-filters --query 'metricFilters[].[filterName,filterPattern]' --output text
```

4. Compare what exists with the event table below. Where an approved lab proof was run (tests 2 to 9), confirm that the client's alert fired for it, with the time to alert.

| Family | CloudTrail `eventName` values to alert on |
|---|---|
| Policy manipulation | `CreatePolicyVersion`, `SetDefaultPolicyVersion`, `PutUserPolicy`, `PutGroupPolicy`, `PutRolePolicy`, `AttachUserPolicy`, `AttachGroupPolicy`, `AttachRolePolicy`, `AddUserToGroup` |
| Credential creation | `CreateAccessKey`, `CreateLoginProfile`, `UpdateLoginProfile` (where `userName` is not the caller) |
| Trust manipulation | `UpdateAssumeRolePolicy`; then `AssumeRole` by a new principal |
| PassRole + new compute | `RunInstances`, `RequestSpotInstances`, `CreateFunction20150331`, `CreateEventSourceMapping20150331`, `AddPermission20150331v2`, `RegisterTaskDefinition`, `RunTask`, `StartTask`, `CreateService`, `CreateProject`, `StartBuild`, `CreateStack`, `CreateStackSet`, `CreateChangeSet`, `CreateDevEndpoint`, `CreateJob`, `StartJobRun`, `CreateNotebookInstance`, `CreateTrainingJob`, `CreateProcessingJob`, `CreatePipeline`, `PutPipelineDefinition` (high priority when the passed role is privileged) |
| Existing compute | `UpdateFunctionCode20150331v2`, `UpdateFunctionConfiguration20150331v2`, `ModifyInstanceAttribute`, `CreateLaunchTemplateVersion`, `ModifyLaunchTemplate`, `AssociateIamInstanceProfile`, `ReplaceIamInstanceProfileAssociation`, `UpdateStack`, `ExecuteChangeSet`, `UpdateProject`, `UpdateDevEndpoint`, `UpdateJob`, `CreatePresignedNotebookInstanceUrl` |
| Command execution | `SendCommand`, `StartSession`, `SendSSHPublicKey`, `ExecuteCommand` |
| Boundary and guardrails | `DeleteUserPermissionsBoundary`, `DeleteRolePermissionsBoundary`, `PutUserPermissionsBoundary`, `PutRolePermissionsBoundary`, Organizations `UpdatePolicy`, `DetachPolicy`, `DeletePolicy` |

GuardDuty findings that relate to escalation, from the [IAM finding types](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html) page: `PrivilegeEscalation:IAMUser/AnomalousBehavior` (Medium; anomalous calls that change IAM policies, roles and users, with `AssociateIamInstanceProfile`, `AddUserToGroup` and `PutUserPolicy` as documented examples), `Persistence:IAMUser/AnomalousBehavior` (`CreateAccessKey`, `ModifyInstanceAttribute`), `InitialAccess:IAMUser/AnomalousBehavior` (`StartSession`), `Discovery:IAMUser/AnomalousBehavior` (enumeration), and the credential exfiltration findings for EC2, Lambda and ECS credentials used outside their resource. The anomaly findings depend on a learned baseline for each identity, so a CI role that changes IAM every day may never produce one. Treat them as a second layer behind explicit rules.

#### Observation

A multi-region organisation trail exists and GuardDuty is on, but there is no rule for IAM policy changes and no rule in `us-east-1` at all.

#### Evaluation

- **Fail (Medium):** no explicit alerting on policy manipulation, credential creation or trust changes; reliance on GuardDuty anomaly findings alone.
- **Fail (High):** CloudTrail does not capture management events in all regions and accounts, or the management account is not covered.
- **Pass:** explicit, tested alerts for the families above, routed to a monitored queue, with exceptions for the pipeline roles that make these changes legitimately.

#### Automated coverage

Security Hub CSPM `CloudTrail.1` (multi-Region trail with read and write management events), `CloudWatch.4` (metric filter and alarm for IAM policy changes), `GuardDuty.1` (GuardDuty enabled). Prowler `cloudtrail_multi_region_enabled`, `cloudwatch_log_metric_filter_policy_changes`, `guardduty_is_enabled`.

#### Detection

This test is about detection. Changes to the detection itself (`StopLogging`, `DeleteTrail`, `UpdateTrail`, `PutEventSelectors`, `DeleteDetector`, `DeleteRule`, `DisableRule`) should alert too; verify that SCPs prevent them and that alerts exist, as described in [CloudTrail logging](/cloud/aws-cloudtrail-logging/).

## Hardening

### Least privilege for IAM write actions

- Reserve IAM write actions for a small set of platform roles and the deployment pipeline. Developers get IAM read and, at most, delegated creation inside a boundary ([below](#permission-boundaries-that-hold)).
- Never grant `iam:*`, `iam:Put*`, `iam:Attach*`, `iam:Create*` or `iam:Update*` on `"*"`. When a team needs to attach policies, condition on `iam:PolicyARN`:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AttachOnlyApprovedPoliciesToAppRoles",
      "Effect": "Allow",
      "Action": ["iam:AttachRolePolicy", "iam:DetachRolePolicy"],
      "Resource": "arn:aws:iam::111122223333:role/app/*",
      "Condition": {
        "ArnEquals": {
          "iam:PolicyARN": [
            "arn:aws:iam::111122223333:policy/app/app-read-config",
            "arn:aws:iam::111122223333:policy/app/app-write-queue"
          ]
        },
        "StringEquals": {
          "iam:PermissionsBoundary": "arn:aws:iam::111122223333:policy/AppBoundary"
        }
      }
    }
  ]
}
```

- Keep credential management self-service only: `iam:CreateAccessKey`, `iam:UpdateAccessKey`, `iam:DeleteAccessKey` and `iam:ChangePassword` on `arn:aws:iam::*:user/${aws:username}`. Better, remove IAM users for humans entirely and use IAM Identity Center, so there are no admin users to target.
- Delete non-default policy versions you no longer need (`aws iam delete-policy-version`), so `SetDefaultPolicyVersion` has nothing to roll back to.
- Privileged roles trust specific principal ARNs, not the account root; if they must trust the account, add `aws:PrincipalArn` conditions and require MFA for human use.

### Scoping PassRole

Scope by role ARN and service, never by tag:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "PassOnlyAppLambdaRolesToLambda",
      "Effect": "Allow",
      "Action": "iam:PassRole",
      "Resource": "arn:aws:iam::111122223333:role/app/lambda/*",
      "Condition": {
        "StringEquals": { "iam:PassedToService": "lambda.amazonaws.com" }
      }
    }
  ]
}
```

Put workload roles under paths (`/app/lambda/`, `/app/ecs/`) that only the platform pipeline can create roles in, so the wildcard in `Resource` cannot be satisfied by a privileged role. In Terraform:

```hcl
data "aws_iam_policy_document" "pass_app_lambda_roles" {
  statement {
    sid       = "PassOnlyAppLambdaRolesToLambda"
    actions   = ["iam:PassRole"]
    resources = ["arn:aws:iam::111122223333:role/app/lambda/*"]
    condition {
      test     = "StringEquals"
      variable = "iam:PassedToService"
      values   = ["lambda.amazonaws.com"]
    }
  }
}
```

Avoid AWS managed "full access" policies for services in developer roles; several include `iam:PassRole` on broad resources. Read the current version of each managed policy you attach (`aws iam get-policy-version`) rather than trusting its name.

### Protecting compute that runs as a privileged role

- Do not give workloads more than they need. A bootstrap function that creates IAM users should run in a separate account or be replaced by the pipeline.
- Separate who may change a privileged workload from who may use it: `lambda:UpdateFunctionCode`, `lambda:UpdateFunctionConfiguration`, `cloudformation:UpdateStack`, `codebuild:StartBuild` (because of buildspec overrides), `codebuild:UpdateProject`, `glue:UpdateJob` and `ssm:SendCommand`/`ssm:StartSession` on privileged targets belong to the pipeline and to named operators.
- Enable [Lambda code signing](https://docs.aws.amazon.com/lambda/latest/dg/configuration-codesigning.html) with an `Enforce` policy for privileged functions so unsigned code cannot be deployed.
- Restrict Session Manager and Run Command by instance ARN or by tags that operators cannot change; deny `ec2:CreateTags` and `ec2:DeleteTags` on the controlling tag key for those operators.
- Keep privileged roles off interactive hosts (bastions, build agents, notebooks).

### Permission boundaries that hold

The pattern from AWS's delegation example, with the gaps closed:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "CreateAndManageOnlyWithBoundary",
      "Effect": "Allow",
      "Action": [
        "iam:CreateRole", "iam:PutRolePolicy", "iam:AttachRolePolicy",
        "iam:DeleteRolePolicy", "iam:DetachRolePolicy", "iam:PutRolePermissionsBoundary"
      ],
      "Resource": "arn:aws:iam::111122223333:role/app/*",
      "Condition": {
        "StringEquals": { "iam:PermissionsBoundary": "arn:aws:iam::111122223333:policy/AppBoundary" }
      }
    },
    {
      "Sid": "PassOnlyBoundedAppRoles",
      "Effect": "Allow",
      "Action": "iam:PassRole",
      "Resource": "arn:aws:iam::111122223333:role/app/*"
    },
    {
      "Sid": "NoBoundaryRemoval",
      "Effect": "Deny",
      "Action": ["iam:DeleteRolePermissionsBoundary", "iam:DeleteUserPermissionsBoundary"],
      "Resource": "*"
    },
    {
      "Sid": "NoBoundaryPolicyEdits",
      "Effect": "Deny",
      "Action": ["iam:CreatePolicyVersion", "iam:DeletePolicy", "iam:DeletePolicyVersion", "iam:SetDefaultPolicyVersion"],
      "Resource": [
        "arn:aws:iam::111122223333:policy/AppBoundary",
        "arn:aws:iam::111122223333:policy/DelegateBoundary"
      ]
    }
  ]
}
```

Attach `DelegateBoundary` as the boundary of the delegate itself, so it cannot grant itself anything outside the model. Make `AppBoundary` deny IAM write, PassRole outside `role/app/*`, and credential actions on other users. Then test it with [GT-AWS-PRIVESC-10](#gt-aws-privesc-10-permission-boundary-and-delegated-administration-gaps).

### SCP and RCP guardrails

An SCP baseline for member accounts that denies the escalation levers to everyone except the platform's roles. Exceptions use `aws:PrincipalArn` with exact ARNs or a path that only the platform can create roles in:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyIamEscalationLeversExceptPlatform",
      "Effect": "Deny",
      "Action": [
        "iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion",
        "iam:PutUserPolicy", "iam:PutGroupPolicy", "iam:PutRolePolicy",
        "iam:AttachUserPolicy", "iam:AttachGroupPolicy", "iam:AttachRolePolicy",
        "iam:AddUserToGroup", "iam:CreateAccessKey", "iam:CreateLoginProfile", "iam:UpdateLoginProfile",
        "iam:UpdateAssumeRolePolicy",
        "iam:DeleteUserPermissionsBoundary", "iam:DeleteRolePermissionsBoundary"
      ],
      "Resource": "*",
      "Condition": {
        "ArnNotLike": {
          "aws:PrincipalArn": [
            "arn:aws:iam::*:role/platform/iam-pipeline",
            "arn:aws:iam::*:role/aws-reserved/sso.amazonaws.com/*AWSReservedSSO_PlatformAdmin_*"
          ]
        }
      }
    }
  ]
}
```

Test any SCP in a non-production OU first: it applies to every principal in the account, including roles that legitimate tooling uses. Denying `iam:CreateAccessKey` also stops IAM users rotating their own keys, which is one more reason to move humans to IAM Identity Center before you apply it. Where developers need delegated role creation, replace the blanket deny for `PutRolePolicy` and `AttachRolePolicy` with a deny that applies when `iam:PermissionsBoundary` is not your boundary policy. Keep the management account free of workloads, because SCPs do not apply there. For trust policies, an RCP on `sts:AssumeRole` that requires `aws:PrincipalOrgID` (with exceptions for AWS service principals) stops a rewritten trust policy from admitting an outside account; RCP design is in [Organizations and multi-account security](/cloud/aws-organizations-multi-account-security/).

### Preventive checks in the pipeline

- Run IAM Access Analyzer custom policy checks on every IAM change in CI: `check-access-not-granted` with the lever actions (up to 100 actions per check) and privileged role ARNs, and `check-no-new-access` against an approved reference policy.
- Run cloudsplaining's `scan-policy-file` on new policies and fail the build on privilege escalation findings.
- Use IAM Access Analyzer unused access findings to remove permissions nobody uses, which removes levers nobody would miss.
- Re-run GT-AWS-PRIVESC-1 after significant IAM changes and compare graphs.

## Real-world cases

- **SCARLETEEL 2.0 (Sysdig, July 2023).** Sysdig describes a policy that blocked access key creation only for users whose names contained lowercase "admin"; one admin user was named with a capital "A", so the attacker created access keys for it and took over the account. It is the credential-creation family plus a name-based exclusion that failed. [Sysdig: SCARLETEEL 2.0](https://sysdig.com/blog/scarleteel-2-0/).
- **Lambda code injection to admin in minutes (Sysdig, February 2026).** Credentials from a public S3 bucket belonged to a user with Lambda update permissions. The actor used `UpdateFunctionCode` on an existing function whose execution role was administrative, raised its timeout with `UpdateFunctionConfiguration`, had the injected code create access keys for an admin user, then created a new admin user. The existing-compute family followed by credential creation. [Sysdig: AI-assisted cloud intrusion achieves admin access in 8 minutes](https://www.sysdig.com/blog/ai-assisted-cloud-intrusion-achieves-admin-access-in-8-minutes).
- **CodeStar `CreateProjectFromTemplate` (Rhino Security Labs).** An undocumented API that let a user with only that permission have the CodeStar service role create a project and attach new permissions to the caller; AWS later restricted the role with a permissions boundary. A reminder that service roles acting on your behalf are part of the graph. [Rhino: Escalating AWS IAM privileges with an undocumented CodeStar API](https://rhinosecuritylabs.com/aws/escalating-aws-iam-privileges-undocumented-codestar-api/).
- **Over-scoped AWS managed policy (Cymulate, July 2025).** Version 1 of `AmazonGuardDutyFullAccess` granted `organizations:RegisterDelegatedAdministrator` on all resources, so a management-account principal holding it could register a member account as delegated administrator for other services. AWS released `AmazonGuardDutyFullAccess_v2`, which limits delegation to GuardDuty, and existing attachments must be moved to it by hand. [Cymulate: Exploring delegated admin risks in AWS Organizations](https://cymulate.com/blog/aws-delegated-admin-org-takeover/).

More incidents are collected in [AWS security incidents and write-ups](/cloud/aws-security-incidents-and-writeups/).

## Rating findings

| Finding | Typical severity | Reasoning |
|---|---|---|
| Non-admin principal can reach administrator in one step (policy manipulation, credential creation on an admin, trust rewrite, PassRole of an admin role to compute it can create) | High; Critical when the starting principal is broadly reachable (all developers, a CI role triggered by pull requests, an internet-facing workload's role, or credentials exposed elsewhere) | Account takeover from a foothold the client considers low risk; blast radius is the account, and the organisation if the account holds organisation-level trust |
| Escalation through existing compute (`UpdateFunctionCode`, `StartBuild` override, `SendCommand`) to an admin role | High; Critical on the same reachability conditions | Same outcome; often unnoticed by policy-only reviews and by GuardDuty baselines, because the actions look like normal developer activity |
| Escalation to a non-admin but more privileged role (data access, another team's workloads) | Medium to High, by the data or systems reached | Lateral movement rather than takeover; rate by what the target role can read or change |
| Multi-hop path requiring several principals or conditions | One level below the equivalent one-hop path, unless each hop is trivially available | Preconditions raise effort, but tooling finds and chains these automatically |
| Wide `iam:PassRole` (`"*"`) with no exploitable service today | Medium | Latent: the next compute permission granted to that principal becomes an escalation |
| Boundary gaps (creation without boundary, removable boundary, editable boundary policy) where delegation is in use | High when a path results; Medium when latent | The control the client relies on does not hold |
| No SCP guardrail on lever actions, with no path found | Low to Medium | Defence in depth missing; rises to Medium in large or multi-team organisations |
| Workloads or broad access in the management account | High | Outside SCP and RCP coverage; compromise there is organisation-wide |
| No alerting on IAM policy, credential and trust changes | Medium; High if it covers the management account or CloudTrail itself | An escalation would go unnoticed until its impact |
| Wildcard service actions in customer managed policies (`IAM.21`) without a demonstrated path | Low | Hygiene; report with the policy names so they can be tightened |

When you report a path, give the chain (start, each hop with its permission and resource, target), the pathfinding.cloud ID where one exists, the simulator evidence, and whether a lab proof was run and reverted.

## Mapping

"Security Hub CSPM" is the name AWS gave the original Security Hub product in 2025, when it launched the new unified Security Hub; the control IDs did not change (check the current docs if the naming has moved again). CIS references are taken from the Security Hub CSPM control pages; versions are stated per reference. ATT&CK IDs are Enterprise techniques for IaaS.

| Test | Security Hub CSPM | CIS AWS Foundations | MITRE ATT&CK |
|---|---|---|---|
| GT-AWS-PRIVESC-1 | IAM.1, IAM.21 | v1.2.0 1.22, v1.4.0 1.16 (IAM.1) | T1078.004, T1098.003 |
| GT-AWS-PRIVESC-2 | IAM.1, IAM.2, IAM.21 | v1.4.0 1.16 (IAM.1); v5.0.0 1.14, v3.0.0 1.15 (IAM.2) | T1098.003 |
| GT-AWS-PRIVESC-3 | none direct (IAM.5, IAM.19 reduce console variant) | v5.0.0 1.9 (IAM.5) | T1098.001 |
| GT-AWS-PRIVESC-4 | none | none | T1098.003, T1078.004 |
| GT-AWS-PRIVESC-5 | none | none | T1548.005 |
| GT-AWS-PRIVESC-6 | none | none | T1548.005, T1648 |
| GT-AWS-PRIVESC-7 | none | none | T1548.005, T1648 |
| GT-AWS-PRIVESC-8 | none | none | T1648, T1548.005 |
| GT-AWS-PRIVESC-9 | none | none | T1651 |
| GT-AWS-PRIVESC-10 | none | none | T1098.003 |
| GT-AWS-PRIVESC-11 | none | none | T1098.003 (prevention of) |
| GT-AWS-PRIVESC-12 | CloudTrail.1, CloudWatch.4, GuardDuty.1 | v5.0.0 3.1, v1.4.0 3.1 (CloudTrail.1); v1.4.0 4.4 (CloudWatch.4) | detection for all of the above |

ATT&CK names: [T1078.004](https://attack.mitre.org/techniques/T1078/004/) Valid Accounts: Cloud Accounts; [T1098.001](https://attack.mitre.org/techniques/T1098/001/) Account Manipulation: Additional Cloud Credentials; [T1098.003](https://attack.mitre.org/techniques/T1098/003/) Account Manipulation: Additional Cloud Roles (its description cites `CreatePolicyVersion` and `AttachUserPolicy`); [T1548.005](https://attack.mitre.org/techniques/T1548/005/) Abuse Elevation Control Mechanism: Temporary Elevated Cloud Access (cites `PassRole`); [T1648](https://attack.mitre.org/techniques/T1648/) Serverless Execution; [T1651](https://attack.mitre.org/techniques/T1651/) Cloud Administration Command.

## References

**AWS documentation**

- [Grant a user permissions to pass a role to an AWS service](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_passrole.html) (PassRole, no CloudTrail event, do not use tags to control PassRole)
- [IAM and AWS STS condition context keys](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_iam-condition-keys.html) (`iam:PassedToService`, `iam:AssociatedResourceArn`, `iam:PolicyARN`, `iam:PermissionsBoundary`)
- [Permissions boundaries for IAM entities](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_boundaries.html)
- [AWS CLI: `iam simulate-principal-policy`](https://docs.aws.amazon.com/cli/latest/reference/iam/simulate-principal-policy.html)
- [AWS CLI: `accessanalyzer check-access-not-granted`](https://docs.aws.amazon.com/cli/latest/reference/accessanalyzer/check-access-not-granted.html)
- [Service control policies](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_scps.html) and [resource control policies](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_rcps.html)
- [GuardDuty IAM finding types](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html)
- [Logging Lambda API calls with CloudTrail](https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html) (versioned event names)
- [Lambda `UpdateFunctionCode` API](https://docs.aws.amazon.com/lambda/latest/api/API_UpdateFunctionCode.html) (`DryRun`)
- [Security Hub CSPM controls for IAM](https://docs.aws.amazon.com/securityhub/latest/userguide/iam-controls.html), [CloudTrail](https://docs.aws.amazon.com/securityhub/latest/userguide/cloudtrail-controls.html), [CloudWatch](https://docs.aws.amazon.com/securityhub/latest/userguide/cloudwatch-controls.html), [GuardDuty](https://docs.aws.amazon.com/securityhub/latest/userguide/guardduty-controls.html)
- [AWS Glue development endpoints](https://docs.aws.amazon.com/glue/latest/dg/dev-endpoints.html) and [AWS Data Pipeline developer guide](https://docs.aws.amazon.com/datapipeline/latest/DeveloperGuide/what-is-datapipeline.html) (service status notices)
- AWS Security Blog: [How to use trust policies with IAM roles](https://aws.amazon.com/blogs/security/how-to-use-trust-policies-with-iam-roles/)
- [AWS penetration testing policy](https://aws.amazon.com/security/penetration-testing/)

**Research and path catalogues**

- Spencer Gietzen, Rhino Security Labs: [AWS privilege escalation: methods and mitigation](https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/), [Part 2](https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation-part-2/), [Undocumented CodeStar API](https://rhinosecuritylabs.com/aws/escalating-aws-iam-privileges-undocumented-codestar-api/)
- Seth Art, Bishop Fox: [IAM Vulnerable](https://github.com/BishopFox/iam-vulnerable), [An AWS IAM privilege escalation playground](https://bishopfox.com/blog/aws-iam-privilege-escalation-playground), [Assessing the AWS assessment tools](https://bishopfox.com/blog/assessing-the-aws-assessment-tools)
- Seth Art, Datadog Security Labs: [pathfinding.cloud](https://pathfinding.cloud/) ([GitHub](https://github.com/DataDog/pathfinding.cloud)), [Introducing pathfinding.cloud](https://securitylabs.datadoghq.com/articles/introducing-pathfinding.cloud/), [Introducing Pathfinding Labs](https://securitylabs.datadoghq.com/articles/introducing-pathfinding-labs/)
- [HackTricks Cloud: AWS privilege escalation](https://cloud.hacktricks.wiki/en/pentesting-cloud/aws-security/aws-privilege-escalation/index.html)
- MITRE ATT&CK: [T1098.003](https://attack.mitre.org/techniques/T1098/003/), [T1548.005](https://attack.mitre.org/techniques/T1548/005/), [T1648](https://attack.mitre.org/techniques/T1648/), [T1651](https://attack.mitre.org/techniques/T1651/)

**Tools and labs**

- [PMapper](https://github.com/nccgroup/PMapper) and its [query reference](https://github.com/nccgroup/PMapper/wiki/Query-Reference)
- [Pacu](https://github.com/RhinoSecurityLabs/pacu) (`iam__enum_permissions`, `iam__privesc_scan`)
- [cloudsplaining](https://github.com/salesforce/cloudsplaining)
- [Prowler](https://github.com/prowler-cloud/prowler) (`prowler/providers/aws/services/iam/`)
- [CloudFox](https://github.com/BishopFox/cloudfox)
- [CloudGoat](https://github.com/RhinoSecurityLabs/cloudgoat)
