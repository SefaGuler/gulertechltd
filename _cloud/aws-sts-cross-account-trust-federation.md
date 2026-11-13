---
title: "AWS STS, Cross-Account Trust and Federation"
date: 2026-11-12 18:03:00 +0000
subcategory: aws
summary: "Testing who can assume your AWS roles: open trust policies, ExternalId, service principals, GitHub OIDC, IRSA, SAML, session tags and revocation."
refs: [IAM.28, "CIS AWS v5.0.0 1.19", "CIS AWS v3.0.0 1.20", T1199, T1078.004, T1548.005, T1484.002, T1606.002, T1550.001, T1528, T1087.004]
tags: [aws, sts, iam, federation, oidc, cross-account]
---

This note is part of our [AWS Security Testing Guide](/cloud/aws-security-testing-guide/) and covers the question every AWS environment has to answer correctly: *who, outside this role, can become this role?* Roles are the main identity in a modern AWS estate. People reach them through IAM Identity Center or SAML, pipelines through OIDC, workloads through service principals, partners and SaaS vendors through cross-account trust. Each path is a trust policy, and a trust policy is a resource policy whose resource is "the permissions of this role". When it is too broad, the result is not a data leak but an identity takeover: an attacker gets a working session with whatever the role can do. Below are the mechanics of AWS STS, role trust, sessions and federation, the mistakes we find most (open principals, missing `sts:ExternalId`, unscoped service principals, GitHub Actions trust without a pinned subject, IRSA trust without a service account, unconstrained session tags), eleven tests, the policies and guardrails that fix them, and how to rate the findings. Policy evaluation in general, and the credential types STS issues, are in [AWS IAM fundamentals and policy evaluation](/cloud/aws-iam-fundamentals-policy-evaluation/).

## Contents

- [How it works](#how-it-works)
- [What goes wrong](#what-goes-wrong)
- [Testing](#testing)
  - [Before you start](#before-you-start)
  - [GT-AWS-STS-1: Inventory of role trust relationships](#gt-aws-sts-1-inventory-of-role-trust-relationships)
  - [GT-AWS-STS-2: Wildcard and whole-account principals](#gt-aws-sts-2-wildcard-and-whole-account-principals)
  - [GT-AWS-STS-3: Third-party roles and sts:ExternalId](#gt-aws-sts-3-third-party-roles-and-stsexternalid)
  - [GT-AWS-STS-4: Service principal trust and confused deputy](#gt-aws-sts-4-service-principal-trust-and-confused-deputy)
  - [GT-AWS-STS-5: GitHub Actions OIDC trust](#gt-aws-sts-5-github-actions-oidc-trust)
  - [GT-AWS-STS-6: EKS IRSA, Cognito and other OIDC trust](#gt-aws-sts-6-eks-irsa-cognito-and-other-oidc-trust)
  - [GT-AWS-STS-7: SAML federation](#gt-aws-sts-7-saml-federation)
  - [GT-AWS-STS-8: Session duration, chaining, session tags and source identity](#gt-aws-sts-8-session-duration-chaining-session-tags-and-source-identity)
  - [GT-AWS-STS-9: IAM Identity Center, federated user and session token use](#gt-aws-sts-9-iam-identity-center-federated-user-and-session-token-use)
  - [GT-AWS-STS-10: Organisation-wide trust graph and external access findings](#gt-aws-sts-10-organisation-wide-trust-graph-and-external-access-findings)
  - [GT-AWS-STS-11: Session revocation readiness](#gt-aws-sts-11-session-revocation-readiness)
- [Hardening](#hardening)
- [Real-world cases](#real-world-cases)
- [Rating findings](#rating-findings)
- [Mapping](#mapping)
- [References](#references)

## How it works

### Two halves of a role assumption

Assuming a role takes two permissions, and which one matters depends on where the caller lives.

1. **The trust policy** on the role (a resource-based policy, attached as `AssumeRolePolicyDocument`) must allow the caller to perform `sts:AssumeRole`, `sts:AssumeRoleWithSAML` or `sts:AssumeRoleWithWebIdentity`, plus `sts:TagSession` if session tags are passed and `sts:SetSourceIdentity` if a source identity is set.
2. **The caller's own identity policy** must allow `sts:AssumeRole` on the role ARN, for callers that are AWS principals. Federated callers (SAML, OIDC) have no AWS identity yet, so the trust policy is the only gate.

Cross-account, both halves must allow the request; the trusting account (the role's) controls the first, the trusted account (the caller's) controls the second, and SCPs in the caller's organisation and RCPs in the role's organisation apply on top. That split is the core of most trust findings: **when a trust policy names an account, the trusting account hands the decision about *who* may assume the role to the other account's administrators.**

### Principal forms in a trust policy

| Principal | Example | Who can actually assume the role |
|---|---|---|
| Account | `{"AWS": "arn:aws:iam::444455556666:root"}` or `{"AWS": "444455556666"}` | Any principal in 444455556666 whose identity policy allows `sts:AssumeRole` on the role. The `:root` suffix does **not** mean the root user only. |
| Specific role or user | `{"AWS": "arn:aws:iam::444455556666:role/ci-runner"}` | That principal only. IAM stores the principal's unique ID; if the principal is deleted and recreated, the trust breaks and the policy shows an ID beginning with AROA (role) or AIDA (user) instead of an ARN. |
| Everyone | `"*"` or `{"AWS": "*"}` | Any AWS principal in any account, unless a condition narrows it. |
| Service | `{"Service": "lambda.amazonaws.com"}` | The service, acting for whoever configured it. `"Service": "*"` is not allowed. |
| Federated OIDC | `{"Federated": "arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com"}` | Anyone holding a token from that issuer that satisfies the conditions. For shared issuers such as GitHub, that is every customer of the issuer. |
| Federated SAML | `{"Federated": "arn:aws:iam::111122223333:saml-provider/CorpIdP"}` | Anyone the IdP issues a signed assertion for, naming this role. |

A trust policy cannot use a partial wildcard in a principal ARN (`arn:aws:iam::444455556666:role/ci-*` is rejected); to match by pattern you use `"AWS": "*"` with an `aws:PrincipalArn` condition. That pattern is legitimate, and it is also the source of most `"*"` findings, because the condition is the only thing standing between the role and the internet.

### Trust conditions that matter

| Key | Use | Typical mistake |
|---|---|---|
| `sts:ExternalId` | Third-party (SaaS) roles: the vendor passes the tenant-specific value it generated for you | Missing; value chosen by the customer (guessable, reused) rather than generated by the vendor |
| `aws:PrincipalOrgID`, `aws:PrincipalOrgPaths` | Allow any principal in your organisation (or OU path) | Used with `ForAllValues`/`ForAnyValue` (it is single-valued); omitted on `"*"` trusts |
| `aws:PrincipalArn` | Pattern-match caller ARNs with `ArnLike` | `StringLike` used on an ARN key; patterns broad enough to match roles anyone can create |
| `aws:SourceArn`, `aws:SourceAccount`, `aws:SourceOrgID`, `aws:SourceOrgPaths` | Bind a service principal to the resource, account or organisation it acts for | Missing, which leaves a cross-service confused deputy |
| `<issuer>:aud`, `<issuer>:sub` and other claim keys | OIDC: bind the token to your app and to a specific workload | `sub` missing or wildcarded; mutable name-based claims |
| `SAML:aud` (also written `saml:aud`) | SAML: assertion must target the AWS sign-in endpoint | Missing; regional endpoint mismatch |
| `aws:MultiFactorAuthPresent` | Require MFA for human `AssumeRole` | `Bool` rather than `BoolIfExists` in a Deny (see the IAM note) |
| `sts:RoleSessionName`, `sts:SourceIdentity` | Make sessions attributable to a person | Optional, so not enforced; any value accepted |

### Sessions

`AssumeRole` returns temporary credentials (access key ID beginning with ASIA, secret, session token) valid from 15 minutes up to the role's **maximum session duration**, which an administrator sets between 1 and 12 hours (default 1 hour). Three session features change what a session can do:

- **Session policies** (passed with `--policy` or `--policy-arns`) narrow the session; they never widen it.
- **Session tags** (`--tags`) become `aws:PrincipalTag/<key>` values for the session. New session tags override earlier session tags with the same key, and AWS's own role-chaining example shows an inherited session tag overriding a role tag of the same key, so do not rely on a role tag to pin a value the caller can also pass. If tag-based access control (ABAC) trusts principal tags, whoever can choose the session tags can choose their access. Passing tags needs `sts:TagSession` in the trust policy; `aws:RequestTag/<key>`, `aws:TagKeys` and `sts:TransitiveTagKeys` constrain which tags and values a caller may pass. Transitive tags persist through role chaining. Limits: 50 tags, single-valued.
- **Source identity** (`--source-identity`) is a caller-supplied string that persists across role chaining and cannot be changed during the session; it appears in CloudTrail and as `aws:SourceIdentity`. It needs `sts:SetSourceIdentity` in the trust policy. It is an attribution control only if the trust policy constrains the value.

**Role chaining** (using a role session to assume another role) is limited to 1 hour regardless of each role's maximum, and a `DurationSeconds` above 3600 fails. Switching role in the console from a role session (for example after signing in through Identity Center or SAML) is chaining too.

### Federation paths

| Path | API | Trust principal | What binds the caller |
|---|---|---|---|
| **SAML 2.0** (corporate IdP, legacy direct federation) | `AssumeRoleWithSAML` | `Federated: saml-provider/<name>` | The IdP's signature (from the metadata uploaded to IAM), the `https://aws.amazon.com/SAML/Attributes/Role` attribute listing role and provider ARN pairs, `SAML:aud`. Assertions may be encrypted (`AssertionEncryptionMode` `Required` or `Allowed`). |
| **OIDC** (GitHub Actions, GitLab, Terraform Cloud, EKS IRSA, Google, custom issuers) | `AssumeRoleWithWebIdentity` | `Federated: oidc-provider/<issuer>` (or `accounts.google.com`, `cognito-identity.amazonaws.com`) | The token signature (JWKS from the issuer), and the trust conditions on claims (`aud`, `sub`, provider-specific keys). AWS validates the JWKS endpoint against its trusted root CA library and falls back to configured thumbprints only when needed. |
| **IAM Identity Center** | Identity Center sign-in, then role sessions | Roles `AWSReservedSSO_*` with an Identity Center SAML provider | Permission set assignments; session duration set on the permission set (1 to 12 hours). |
| **Cognito identity pools** | `GetCredentialsForIdentity` (internally web identity) | `Federated: cognito-identity.amazonaws.com` | `cognito-identity.amazonaws.com:aud` (the pool ID) and `amr` (`authenticated` or `unauthenticated`). See the [Cognito note](/cloud/aws-cognito-security/). |
| **Custom broker** | `GetFederationToken` | None (called by an IAM user) | The IAM user's permissions intersected with the session policy; up to 36 hours; produces `arn:aws:sts::<account>:federated-user/<name>`. |

**Shared OIDC issuers** deserve their own sentence. GitHub's `https://token.actions.githubusercontent.com` issues tokens for every repository on github.com. A role that trusts that issuer without pinning the subject trusts every GitHub user on the planet. AWS now enforces *identity-provider controls* for a list of shared issuers (GitHub Actions, GitLab.com, Terraform Cloud, Buildkite, Codefresh, Scalr, Pulumi, Vercel, Cognito and others): creating or updating a trust policy that does not evaluate the required claim (`token.actions.githubusercontent.com:sub` or `:job_workflow_ref` for GitHub) fails with `MalformedPolicyDocument`, and IAM also rejects a GitHub `sub` that is solely a wildcard. **Existing trust policies are not re-evaluated**, so roles created before the control are the ones to test (Datadog reported AWS blocking new vulnerable GitHub roles from June 2025).

GitHub has also started issuing **immutable subject claims**: per GitHub's documentation, repositories created after 15 July 2026 (and repositories that opt in) get a default `sub` of the form `repo:OWNER@OWNER-ID/REPO@REPO-ID:ref:refs/heads/BRANCH`, while older repositories keep `repo:OWNER/REPO:...` for now. AWS exposes `token.actions.githubusercontent.com:repository_id`, `:repository_owner_id`, `:actor_id` and `:enterprise_id` as condition keys and recommends immutable identifiers over names, because a deleted or renamed organisation name can be registered by someone else.

### Service principals and the confused deputy

A role that trusts `{"Service": "events.amazonaws.com"}` can be assumed by EventBridge **on behalf of any customer** who names that role ARN in their own rule, if the service does not otherwise check. AWS's answer is that service principals carry the context of who they act for in `aws:SourceArn`, `aws:SourceAccount`, `aws:SourceOrgID` and `aws:SourceOrgPaths`, and that you should test those keys wherever a service principal is trusted. Many services also check that the caller who configured them could pass the role (`iam:PassRole`), which is the main reason the confused deputy is usually theoretical for roles; it is far more practical for resource policies (S3, SNS, SQS, KMS) that trust a service principal. Resource control policies can enforce the source condition centrally for supported services.

### Revocation

A session cannot be cancelled. What you can do is deny it: AWS evaluates permissions on every request, so a `Deny` that matches the session stops it. The IAM console's **Revoke active sessions** button attaches an inline policy named `AWSRevokeOlderSessions` to the role, denying `*` when `aws:TokenIssueTime` is earlier than the revocation time (plus roughly 30 seconds for propagation). Points that matter in an incident:

- It needs `iam:PutRolePolicy` on the role. It does not work for service-linked roles, and roles created from Identity Center permission sets are revoked from Identity Center instead.
- A resource policy that grants access directly to the session ARN is not stopped by a deny on the role's identity policy; you must add a deny on the resource too.
- `aws:TokenIssueTime` is absent on long-term credentials, so the same policy on an IAM user stops sessions minted from that user's keys (`GetSessionToken`, `GetFederationToken`) without affecting the keys themselves. Deleting a leaked key does not end sessions already minted from it.
- Sessions created by the root user with `GetSessionToken` or `GetFederationToken` cannot be restricted at all.

### What CloudTrail sees

STS calls are logged in the account where the STS operation is performed and, for cross-account `AssumeRole`, in the calling account too (the two events share a `sharedEventID`). `AssumeRoleWithSAML` and `AssumeRoleWithWebIdentity` are logged even though they are unauthenticated calls, with the IdP information in the event. Two blind spots: **denied cross-account role assumptions are not logged in the target account**, and denied `AssumeRoot` privileged sessions are not either. So if someone outside the organisation is trying role names against your accounts, your trail will not show it; RCPs and correct trust policies are the control, not detection.

## What goes wrong

**`"Principal": {"AWS": "*"}` with no effective condition.** Usually left over from testing, from "temporarily" sharing with a partner, or from a pattern-match intent where the condition was dropped or uses the wrong operator. Why it matters: any AWS account in the world can obtain a session.

**Trusting an entire external account.** `arn:aws:iam::<partner>:root` delegates the decision to the partner's administrators; a single over-privileged or compromised principal in their account can assume your role. Why it matters: your security now equals theirs, and you cannot see their IAM.

**SaaS roles without `sts:ExternalId`.** The vendor's account is trusted, and any of the vendor's other customers can ask the vendor to use your role ARN. Why it matters: cross-tenant access through a trusted third party (the confused deputy), invisible to you because the calls come from the vendor's legitimate account.

**Service principals without source conditions.** Trust or resource policies for `events`, `sns`, `s3`, `cloudtrail`, `config`, `lambda` and similar, with no `aws:SourceArn` or `aws:SourceAccount`. Why it matters: another customer's resource in the same service may be able to act with your role or on your resource, depending on the service's own checks.

**GitHub (and other CI) OIDC trust without a pinned subject.** Missing `sub`, `repo:org/*` where `org` has hundreds of repositories, `repo:org/repo:*` allowing every branch and pull request, `StringLike` patterns such as `repo:org/app*` that also match `repo:org/app-fork-test`, environment-scoped subjects without environment protection rules, name-based subjects for organisations that have been renamed. Why it matters: anyone who can run a workflow in a matching repository, branch or environment gets the deployment role, which is usually close to admin.

**IRSA trust without a service account.** EKS IRSA roles that check only `aud`, or that use `system:serviceaccount:*:*`. Why it matters: every pod in the cluster that can get a projected token, including compromised or multi-tenant workloads, can assume the role. Depth is in the [containers note](/cloud/aws-containers-ecs-eks-ecr-security/).

**Unconstrained session tags and source identity.** Trust policies that allow `sts:TagSession` or `sts:SetSourceIdentity` with no conditions, combined with ABAC policies keyed on `aws:PrincipalTag`. Why it matters: the caller chooses the attribute that decides their access.

**Long sessions on powerful roles.** 12-hour maximum session duration on administrative roles, Identity Center admin permission sets with 12-hour sessions. Why it matters: a stolen session stays useful for most of a day; revocation becomes the only control.

**SAML trust that is broader than the IdP mapping.** Roles that trust the SAML provider with no `SAML:aud`, IdP group mappings that grant admin roles to large groups, stale signing certificates and multiple providers nobody owns. Why it matters: the IdP becomes the authorisation system, and a compromised IdP signing key (Golden SAML) mints sessions for every role that trusts it.

**No revocation path.** Nobody with `iam:PutRolePolicy` on call, no runbook for revoking sessions, no deny for `GetFederationToken`. Why it matters: a contained incident becomes a 12- or 36-hour one.

## Testing

*All tests assume an authorised engagement against the client's own AWS accounts, with written scope, and respect for AWS's [penetration testing policy](https://aws.amazon.com/security/penetration-testing/). Commands are read-only unless marked otherwise. Outputs shown are illustrative; we ran nothing against a real account to produce them.*

### Before you start

**Permissions.** `SecurityAudit` and `ViewOnlyAccess` in each account; read access to IAM Access Analyzer findings; `organizations:ListAccounts` (from the management account or a delegated administrator) so you can tell organisation accounts from external ones; read access to CloudTrail (event history or the organisation trail in Athena or CloudTrail Lake).

**Benign proofs.** A trust weakness is usually proven from the policy text alone. When the client wants a live proof, it is **lab or explicitly approved only**, limited to roles named in scope, and consists of exactly two calls: assume the role from an approved principal, then call `sts get-caller-identity` with the session. Use a session name that identifies the test, keep the duration at the minimum, and record the request ID:

```bash
# lab or explicitly approved only: role named in the written scope
aws sts assume-role \
  --role-arn arn:aws:iam::111122223333:role/partner-readonly \
  --role-session-name gt-pentest-STS2-proof \
  --duration-seconds 900 \
  --query 'Credentials.[AccessKeyId,SecretAccessKey,SessionToken]' --output text \
| { read -r AK SK ST; AWS_ACCESS_KEY_ID=$AK AWS_SECRET_ACCESS_KEY=$SK AWS_SESSION_TOKEN=$ST \
    aws sts get-caller-identity; }
```

Never use the session for anything else, never assume roles in accounts you do not have written permission for (including a vendor's or a partner's), and never test whether roles exist in third-party accounts.

**One snapshot per account.**

```bash
aws iam get-account-authorization-details --filter Role --output json > gaad-roles-111122223333.json
aws organizations list-accounts --query 'Accounts[].Id' --output text | tr '\t' '\n' > org-accounts.txt
aws organizations describe-organization --query 'Organization.Id' --output text
```

**Tools.** [CloudFox](https://github.com/BishopFox/cloudfox) (`role-trusts`, `principals`, `outbound-assumed-roles`, `cape`), [PMapper](https://github.com/nccgroup/PMapper) (`graph create`, `orgs create`, `query`), [Prowler](https://github.com/prowler-cloud/prowler), IAM Access Analyzer, Pacu's `organizations__enum` and `iam__enum_users_roles_policies_groups` for enumeration. The [fwd:cloudsec known AWS accounts list](https://github.com/fwdcloudsec/known_aws_accounts) helps you put names to vendor account IDs. Practice environments: [CloudGoat](https://github.com/RhinoSecurityLabs/cloudgoat) and [flaws2.cloud](http://flaws2.cloud/).

### GT-AWS-STS-1: Inventory of role trust relationships

*Guler Tech methodology.*

#### What it checks

Every role's trust policy in every in-scope account, classified by who it trusts: same account, other accounts in the organisation, external accounts, everyone, services, OIDC issuers, SAML providers. The other tests work from this inventory.

#### Prerequisites

The GAAD role snapshot and the organisation account list from [Before you start](#before-you-start).

#### Steps

```python
# trust_inventory.py  -- run with: python3 -I trust_inventory.py gaad-roles-111122223333.json org-accounts.txt
import json, re, sys
gaad = json.load(open(sys.argv[1]))
org = set(open(sys.argv[2]).read().split())
def as_list(x):
    return x if isinstance(x, list) else [x]
for role in gaad["RoleDetailList"]:
    if role["Path"].startswith("/aws-service-role/"):
        continue
    own = role["Arn"].split(":")[4]
    for st in as_list(role["AssumeRolePolicyDocument"]["Statement"]):
        if st.get("Effect") != "Allow":
            continue
        p = st.get("Principal", {})
        p = {"AWS": p} if p == "*" else p
        cond = json.dumps(st.get("Condition", {}), separators=(",", ":"))
        for kind, vals in p.items():
            for v in as_list(vals):
                if kind == "AWS":
                    acct = "*" if v == "*" else (re.search(r"\d{12}", v) or [None])[0]
                    cls = ("EVERYONE" if acct == "*" else "SAME" if acct == own
                           else "ORG" if acct in org else "EXTERNAL" if acct else "UNIQUE-ID")
                else:
                    cls = kind.upper()
                print("\t".join([role["RoleName"], cls, v, ",".join(as_list(st["Action"])), cond]))
```

Cross-check with CloudFox, which also flags common risky patterns:

```bash
cloudfox aws --profile client-audit role-trusts
cloudfox aws --profile client-audit outbound-assumed-roles   # roles this account's principals assumed elsewhere
```

#### Observation

Illustrative:

```text
OrganizationAccountAccessRole  ORG        arn:aws:iam::123456789012:root              sts:AssumeRole  {}
partner-readonly               EXTERNAL   arn:aws:iam::444455556666:root              sts:AssumeRole  {}
vendor-cspm                    EXTERNAL   arn:aws:iam::444455556666:root              sts:AssumeRole  {"StringEquals":{"sts:ExternalId":"..."} }
gh-deploy                      FEDERATED  arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com  sts:AssumeRoleWithWebIdentity  {"StringEquals":{"token.actions.githubusercontent.com:aud":"sts.amazonaws.com"} }
debug-role                     EVERYONE   *                                           sts:AssumeRole  {}
old-ci                         UNIQUE-ID  AROAEXAMPLEEXAMPLEEXA                       sts:AssumeRole  {}
```

#### Evaluation

The inventory is the deliverable; findings come from the tests below. Two entries are findings on their own: `UNIQUE-ID` principals (a deleted user or role: the trust is dead, but the role is orphaned and someone may "fix" it by trusting the whole account), and any `EXTERNAL` account the client cannot name.

#### Automated coverage

Prowler `iam_role_cross_account_readonlyaccess_policy`, `iam_no_custom_policy_permissive_role_assumption`; IAM Access Analyzer external access findings for `AWS::IAM::Role` (test 10).

#### Detection

`UpdateAssumeRolePolicy` and `CreateRole` events, especially where the new document adds an external account, `"*"` or a federated principal (ATT&CK T1484.002, trust modification).

### GT-AWS-STS-2: Wildcard and whole-account principals

*Guler Tech methodology.*

#### What it checks

Trust policies with `"*"` principals, and trust policies that delegate to an entire account, and whether their conditions actually confine them.

#### Prerequisites

Inventory from test 1.

#### Steps

Read every `EVERYONE` and `EXTERNAL`/`ORG` account-level entry. For `"*"`, the conditions must restrict the caller to known principals; check the operator and the key:

```bash
jq -r '.RoleDetailList[] | .RoleName as $r
  | .AssumeRolePolicyDocument.Statement | (if type=="array" then .[] else . end)
  | select(.Effect=="Allow")
  | select((.Principal=="*") or (.Principal.AWS? | (if type=="array" then . else [.] end) | any(. == "*")))
  | [$r, ((.Condition // {})|tostring)] | @tsv' gaad-roles-111122223333.json
```

Acceptable shapes look like this; anything weaker is a finding:

```json
{
  "Effect": "Allow",
  "Principal": {"AWS": "*"},
  "Action": "sts:AssumeRole",
  "Condition": {
    "StringEquals": {
      "aws:PrincipalOrgID": "o-exampleorgid"
    },
    "ArnLike": {
      "aws:PrincipalArn": "arn:aws:iam::*:role/platform/ci-*"
    }
  }
}
```

For account-level trusts in the organisation, ask which principals in the trusted account can assume the role, and check with the simulator from the trusted side:

```bash
aws iam simulate-principal-policy --profile trusted-account-audit \
  --policy-source-arn arn:aws:iam::123456789012:role/developer \
  --action-names sts:AssumeRole \
  --resource-arns arn:aws:iam::111122223333:role/OrganizationAccountAccessRole \
  --query 'EvaluationResults[].EvalDecision' --output text
```

PMapper answers the same question across the organisation once graphs exist for each account (test 10).

#### Observation

`debug-role` trusts `*` with no condition. `partner-readonly` trusts account 444455556666 with no condition and has `ReadOnlyAccess` attached, which includes reading S3 objects, DynamoDB items and Lambda code across the account.

#### Evaluation

- **Fail (Critical):** `"*"` with no condition, or with a condition that does not bind the caller to the organisation or named principals (`aws:SourceIp` alone, `aws:UserAgent`, `ForAnyValue:StringEquals` on `aws:PrincipalOrgID`, `StringLike` on an ARN key with an over-broad pattern), on a role with meaningful permissions. Anyone with an AWS account can take it.
- **Fail (High):** an external account trusted at account level with no `sts:ExternalId` and no `aws:PrincipalArn` restriction, where the role reads sensitive data or writes anything.
- **Fail (Medium):** organisation accounts trusted at account level for privileged roles (`OrganizationAccountAccessRole` is the classic) where many principals in the trusted account can assume it.
- **Pass:** named principal ARNs, or `"*"` constrained with `aws:PrincipalOrgID` plus `aws:PrincipalArn`.
- **Proof:** policy text is enough. If the client asks for a live proof of a `"*"` trust, it must come from an AWS account the client owns and has put in scope (never a personal account), using the benign two-call proof.

#### Automated coverage

IAM Access Analyzer external access (role findings); Security Hub CSPM `IAM.28` checks only that the analyzer exists. Prowler `iam_role_cross_account_readonlyaccess_policy`. Access Analyzer policy validation (`validate-policy` with `AWS::IAM::AssumeRolePolicyDocument`) for operator mistakes.

#### Detection

`AssumeRole` events in the role's account where `userIdentity.accountId` is not in the organisation; GuardDuty `Discovery:IAMUser/AnomalousBehavior` and `CredentialAccess:IAMUser/AnomalousBehavior` for the session's follow-on activity. Remember failed cross-account attempts are not logged in the target account.

### GT-AWS-STS-3: Third-party roles and sts:ExternalId

*Guler Tech methodology.*

#### What it checks

Roles created for SaaS vendors and managed service providers (CSPM, cost management, backup, monitoring, MSP operations): that each requires an `sts:ExternalId` generated by the vendor, unique to the client, and that the permissions match the vendor's stated need.

#### Prerequisites

Inventory from test 1; the client's list of vendors with AWS access; the vendor documentation for each integration.

#### Steps

```bash
jq -r '.RoleDetailList[] | .RoleName as $r
  | .AssumeRolePolicyDocument.Statement | (if type=="array" then .[] else . end)
  | select(.Effect=="Allow" and (.Principal.AWS? != null))
  | [$r, (.Principal.AWS|tostring), (.Condition["StringEquals"]["sts:ExternalId"] // "NO-EXTERNAL-ID"|tostring)] | @tsv' \
  gaad-roles-111122223333.json | grep -v -f org-accounts.txt
```

For every external role, record:

- the vendor (match the account ID against the client's list and the fwd:cloudsec known accounts list);
- whether `sts:ExternalId` is present and looks vendor-generated (a long random string or UUID), rather than the client's name, account ID or a short number;
- the permissions attached (`aws iam list-attached-role-policies`, `list-role-policies`) compared with the vendor's documented minimum;
- `RoleLastUsed` (an unused vendor role from a cancelled contract is its own finding).

The ExternalId is not a secret (anyone who can read the role can see it); its protection comes from the vendor setting it per tenant and never letting a customer choose it. Whether a vendor implements that correctly is the vendor's test, not yours; do not attempt to onboard a second tenant at the vendor against the client's role.

#### Observation

Illustrative:

```text
vendor-cspm      arn:aws:iam::444455556666:root   7f3c9a1e-EXAMPLE-uuid
vendor-backup    arn:aws:iam::444455556666:root   NO-EXTERNAL-ID
msp-ops          arn:aws:iam::444455556666:root   acme-corp
```

#### Evaluation

- **Fail (High):** a vendor or MSP role with no `sts:ExternalId` where the vendor serves other customers. Raise to Critical if the role has write or administrative permissions.
- **Fail (Medium):** an ExternalId that is predictable (company name, account ID) and was evidently chosen by the client, or a vendor role with permissions far beyond the vendor's documented need (for example `AdministratorAccess` for a cost tool).
- **Fail (Low to Medium):** vendor roles unused for 90 days or more, or for vendors no longer under contract.
- **Pass:** vendor-generated, unique ExternalId; least-privilege permissions; documented owner and review date.

#### Automated coverage

None directly in Security Hub CSPM. IAM Access Analyzer reports the external trust (test 10) without judging the ExternalId. Prowler's cross-account checks partly cover it.

#### Detection

`AssumeRole` events for vendor roles carry `requestParameters.externalId`; alert on vendor role use from unexpected source IPs or at unexpected times, and on `UpdateAssumeRolePolicy` for vendor roles. GuardDuty anomaly findings on the vendor session.

### GT-AWS-STS-4: Service principal trust and confused deputy

*Guler Tech methodology.*

#### What it checks

Roles that trust AWS service principals, and whether the trust binds the service to the client's own resources or account with `aws:SourceArn`, `aws:SourceAccount` or the organisation equivalents. Resource policies that trust service principals are covered in the service notes ([S3](/cloud/aws-s3-security/), [API Gateway, SNS and SQS](/cloud/aws-api-gateway-sns-sqs-security/), [KMS](/cloud/aws-secrets-manager-parameter-store-kms/)).

#### Prerequisites

Inventory from test 1.

#### Steps

```bash
jq -r '.RoleDetailList[] | select(.Path | startswith("/aws-service-role/") | not) | .RoleName as $r
  | .AssumeRolePolicyDocument.Statement | (if type=="array" then .[] else . end)
  | select(.Effect=="Allow" and (.Principal.Service? != null))
  | [$r, (.Principal.Service|tostring),
     ((.Condition // {}) | tostring | test("aws:Source(Arn|Account|OrgID|OrgPaths)") | if . then "bound" else "UNBOUND" end)] | @tsv' \
  gaad-roles-111122223333.json | sort -k3
```

Prioritise unbound trusts for services where another customer could name the role in their own configuration and the service does not require the caller to hold `iam:PassRole` on it. Check the service's documentation for its confused deputy guidance; many service documentation pages state which source keys they populate. Compute services (`ec2`, `lambda`, `ecs-tasks`) protected by `iam:PassRole` are low risk; cross-account-capable integrations deserve the closest look.

#### Observation

```text
lambda-exec-orders      ["lambda.amazonaws.com"]            UNBOUND
events-invoke-sfn       ["events.amazonaws.com"]            UNBOUND
config-recorder         ["config.amazonaws.com"]            bound
```

#### Evaluation

- **Fail (Medium):** service principal trust without source conditions for services that support them and are not gated by `iam:PassRole` in the configuring account. Severity rises with the role's permissions, and when the client cannot show the service performs its own check.
- **Low or Info:** compute execution roles (`lambda`, `ec2`, `ecs-tasks`) without source conditions; record it as hardening.
- **Pass:** `aws:SourceAccount` (or `aws:SourceArn` with `ArnLike`/`ArnEquals`) on every service trust that supports it, or an RCP enforcing `aws:SourceOrgID` for service principals.

#### Automated coverage

Prowler `iam_role_cross_service_confused_deputy_prevention`, `iam_role_service_trust_restricts_source_to_account`. Access Analyzer policy validation security warning `RESTRICT_ACCESS_TO_SERVICE_PRINCIPAL` (for resource policies).

#### Detection

`AssumeRole` events where `userIdentity.type` is `AWSService` and the follow-on activity touches resources outside the expected set; `UpdateAssumeRolePolicy` removing source conditions.

### GT-AWS-STS-5: GitHub Actions OIDC trust

*Guler Tech methodology.*

#### What it checks

Every role that trusts `token.actions.githubusercontent.com`: that the audience is pinned, that the subject (or an equivalent claim) is pinned to the client's organisation, repository and branch or protected environment, that the match cannot be widened by `StringLike` patterns, and that identifiers are stable. CI pipeline security in general is in the [CI/CD and IaC note](/cloud/aws-cicd-iac-security/).

#### Prerequisites

Inventory from test 1; the client's GitHub organisation name and IDs; read access to the repositories' workflow files and environment settings (or a client contact who has it).

#### Steps

List GitHub-trusting roles and their conditions:

```bash
aws iam list-open-id-connect-providers --query 'OpenIDConnectProviderList[].Arn' --output text

jq -r '.RoleDetailList[] | .RoleName as $r
  | .AssumeRolePolicyDocument.Statement | (if type=="array" then .[] else . end)
  | select(.Principal.Federated? // "" | tostring | test("token.actions.githubusercontent.com"))
  | [$r, ((.Condition // {}) | tostring)] | @tsv' gaad-roles-111122223333.json
```

Run Access Analyzer validation on each trust policy (see the [IAM note](/cloud/aws-iam-fundamentals-policy-evaluation/), test 9); `MISSING_GITHUB_REPO_CONDITION_KEY` and the general warning `Specific github repo and branch recommended` are the relevant results.

Then read each condition against this checklist:

| Check | Bad | Good |
|---|---|---|
| `aud` present | missing, or `ForAnyValue:StringLike` on `aud` | `StringEquals` `"token.actions.githubusercontent.com:aud": "sts.amazonaws.com"` |
| Subject pinned | `sub` missing; `repo:*`; `repo:*/*`; `repo:client-org/*` for a role that deploys production | `repo:client-org/app:ref:refs/heads/main` or `repo:client-org/app:environment:production` |
| Operator | `StringLike` with a trailing `*` on the repository name (`repo:client-org/app*`) | `StringEquals`, or `StringLike` only on the part after the repository name |
| Pull requests | subject allows `:pull_request` or `ref:refs/heads/*` on a deploy role | deploy roles bound to the default branch or a protected environment; separate read-only role for `plan` |
| Environment | `environment:production` with no required reviewers or deployment branch rules in GitHub | environment protection rules that restrict which branches may deploy |
| Stable identity | name-based only, for an organisation that was renamed, or a repository that was transferred | `repository_owner_id` and `repository_id` claims, or the immutable `sub` format |
| Duplicate keys | two `StringEquals` blocks or duplicate keys in Terraform `jsonencode`, where the second silently overwrites the first | one condition block per operator, reviewed in the deployed JSON, not the source |

Read the workflows that use each role: which events trigger them (`push`, `pull_request`, `pull_request_target`, `workflow_dispatch`), which have `permissions: id-token: write`, and whether a `pull_request_target` workflow checks out and runs pull request code. A `pull_request_target` job runs in the context of the base branch, so its token can carry the base branch's subject; treat a "pwn request" in such a workflow as able to assume any role bound to that branch, and confirm the exact subject GitHub issues for the client's configuration.

Optional live proof, **lab or explicitly approved only**, from a client-owned repository named in scope, using a minimal workflow (no `${...}` expressions needed):

```yaml
name: gt-oidc-proof
on: workflow_dispatch
permissions:
  id-token: write
  contents: read
jobs:
  proof:
    runs-on: ubuntu-latest
    steps:
      - uses: aws-actions/configure-aws-credentials@v4  # pin to a commit SHA in real use
        with:
          role-to-assume: arn:aws:iam::111122223333:role/gh-deploy
          role-session-name: gt-pentest-sts5-proof
          aws-region: eu-west-2
      - run: aws sts get-caller-identity
```

Do not attempt to assume a client role from a repository outside the client's organisation, even your own, unless the client has explicitly approved that exact test in writing; the policy text proves a missing or wildcard `sub` on its own.

#### Observation

Illustrative trust conditions and verdicts:

```text
gh-deploy       {"StringEquals":{"token.actions.githubusercontent.com:aud":"sts.amazonaws.com"} }                                   -> no sub: any GitHub repo
gh-terraform    {"StringLike":{"token.actions.githubusercontent.com:sub":"repo:client-org/*"},"StringEquals":{"...:aud":"sts.amazonaws.com"} }  -> any repo in org, any branch, PRs
gh-app-prod     {"StringEquals":{"...:aud":"sts.amazonaws.com","...:sub":"repo:client-org/app:environment:production"} }       -> good if env protected
```

#### Evaluation

- **Fail (Critical):** no `sub` (or equivalent claim) condition, or a subject that matches any organisation (`repo:*`, `repo:*/*`, a pattern on the organisation name). Any GitHub user can obtain the role's credentials from a workflow in their own repository. Existing roles created before AWS's identity-provider controls are the likely place to find this.
- **Fail (High):** subject pinned to the organisation but not the repository (`repo:client-org/*`) on a role with write or deploy permissions, where many people can create repositories or push branches; subject allowing any branch or pull request on a production deploy role; `pull_request_target` workflows that run untrusted code with `id-token: write`.
- **Fail (Medium):** environment-bound subjects without environment protection rules; name-based conditions for an organisation or repository that has been renamed or transferred, or whose old name is unclaimed; missing `aud`.
- **Pass:** `aud` pinned, `sub` pinned to repository plus branch or protected environment (or immutable IDs), one role per purpose, least privilege.

#### Automated coverage

IAM itself now blocks creating or updating GitHub trust without a qualifying `sub` (or `job_workflow_ref`); existing roles are not re-checked. Access Analyzer validation (`MISSING_GITHUB_REPO_CONDITION_KEY`, `MISSING_CONDITION_KEY_FOR_OIDC_PRINCIPAL`). No Security Hub CSPM control at the time of writing.

#### Detection

`AssumeRoleWithWebIdentity` events for GitHub-trusting roles record the identity provider and the token's subject in `userIdentity` (confirm the exact field on a sample event in the client's trail before building the alert); alert when the subject is outside `repo:client-org/...` (or the client's owner ID). Also alert on `CreateOpenIDConnectProvider`, `UpdateOpenIDConnectProviderThumbprint`, `AddClientIDToOpenIDConnectProvider` and on `UpdateAssumeRolePolicy` for these roles. GuardDuty `UnauthorizedAccess:IAMUser/ResourceCredentialExfiltration.OutsideAWS` does not apply here (GitHub-hosted runners are outside AWS by design), which is why subject-based alerting matters.

### GT-AWS-STS-6: EKS IRSA, Cognito and other OIDC trust

*Guler Tech methodology.*

#### What it checks

Every other OIDC trust: EKS IAM Roles for Service Accounts (IRSA), Cognito identity pool roles, other CI issuers (GitLab, Terraform Cloud, Buildkite), and custom issuers. The common rule: the trust must check the audience and pin the subject or tenant claim. EKS specifics (Pod Identity, access entries) are in the [containers note](/cloud/aws-containers-ecs-eks-ecr-security/); Cognito specifics in the [Cognito note](/cloud/aws-cognito-security/).

#### Prerequisites

Inventory from test 1; cluster list per Region (`aws eks list-clusters`).

#### Steps

Map OIDC providers to clusters and list trusts per provider:

```bash
for r in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text); do
  for c in $(aws eks list-clusters --region "$r" --query 'clusters[]' --output text); do
    printf '%s\t%s\t%s\n' "$r" "$c" \
      "$(aws eks describe-cluster --region "$r" --name "$c" --query 'cluster.identity.oidc.issuer' --output text)"
  done
done

jq -r '.RoleDetailList[] | .RoleName as $r
  | .AssumeRolePolicyDocument.Statement | (if type=="array" then .[] else . end)
  | select(.Action | tostring | test("AssumeRoleWithWebIdentity"))
  | [$r, (.Principal.Federated|tostring), ((.Condition // {})|tostring)] | @tsv' gaad-roles-111122223333.json
```

A correct IRSA trust pins both claims:

```json
{
  "Effect": "Allow",
  "Principal": {
    "Federated": "arn:aws:iam::111122223333:oidc-provider/oidc.eks.eu-west-2.amazonaws.com/id/EXAMPLED539D4633E53DE1B71EXAMPLE"
  },
  "Action": "sts:AssumeRoleWithWebIdentity",
  "Condition": {
    "StringEquals": {
      "oidc.eks.eu-west-2.amazonaws.com/id/EXAMPLED539D4633E53DE1B71EXAMPLE:aud": "sts.amazonaws.com",
      "oidc.eks.eu-west-2.amazonaws.com/id/EXAMPLED539D4633E53DE1B71EXAMPLE:sub": "system:serviceaccount:payments:payments-api"
    }
  }
}
```

For Cognito identity pool roles, the trust must pin `cognito-identity.amazonaws.com:aud` to the pool ID and `amr` to `authenticated` or `unauthenticated` as intended; check what the unauthenticated role can do. For GitLab, Terraform Cloud and other shared issuers, check the required claim from AWS's identity-provider controls table (`gitlab.com:sub`, `app.terraform.io:sub` and so on) is pinned to the client's project or workspace. Also note OIDC providers in IAM that no role trusts (stale) and providers for clusters that no longer exist.

#### Observation

```text
eks-s3-reader   oidc.eks.eu-west-2.amazonaws.com/id/EXAMPLE...   {"StringEquals":{"...:aud":"sts.amazonaws.com"} }                 -> any SA in cluster
eks-dns         oidc.eks.eu-west-2.amazonaws.com/id/EXAMPLE...   {"StringLike":{"...:sub":"system:serviceaccount:*:external-dns"} } -> any namespace
```

#### Evaluation

- **Fail (High):** IRSA trust without `sub`, or with `system:serviceaccount:*:*`, on a role with sensitive permissions; any pod in the cluster can assume it. Raise to Critical for multi-tenant clusters or clusters running internet-facing workloads.
- **Fail (Medium):** namespace wildcards (`system:serviceaccount:*:name`) where tenants control namespaces; missing `aud`.
- **Fail (High to Critical):** shared CI issuers (GitLab.com, Terraform Cloud and others) without the tenant claim pinned; same reasoning as GitHub in test 5.
- **Fail (per Cognito note):** unauthenticated identity pool roles with more than the app's public needs.
- **Pass:** `aud` and `sub` pinned with `StringEquals`; one role per service account.

#### Automated coverage

Access Analyzer validation (`MISSING_CONDITION_KEY_FOR_OIDC_PRINCIPAL`). IAM identity-provider controls for shared issuers (new or updated trusts only). kube-bench and Prowler's EKS checks for cluster-side settings. No Security Hub CSPM control for trust conditions.

#### Detection

`AssumeRoleWithWebIdentity` events per role, with the subject in `userIdentity`; alert on unexpected subjects. GuardDuty EKS protection and runtime findings for the pod side, and `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS` / `ResourceCredentialExfiltration.OutsideAWS` when credentials are used from outside AWS.

### GT-AWS-STS-7: SAML federation

*Guler Tech methodology.*

#### What it checks

IAM SAML providers and the roles that trust them: audience conditions, which roles each provider can reach, IdP signing certificates, encryption, and whether direct SAML federation is still needed alongside Identity Center.

#### Prerequisites

`iam:ListSAMLProviders`, `iam:GetSAMLProvider`; inventory from test 1; the client's IdP group-to-role mapping (from the IdP administrator).

#### Steps

```bash
aws iam list-saml-providers --query 'SAMLProviderList[].[Arn,CreateDate]' --output text

for p in $(aws iam list-saml-providers --query 'SAMLProviderList[].Arn' --output text); do
  echo "== $p"
  aws iam get-saml-provider --saml-provider-arn "$p" \
    --query '[AssertionEncryptionMode, CreateDate]' --output text
  aws iam get-saml-provider --saml-provider-arn "$p" --query SAMLMetadataDocument --output text \
    | grep -o '<ds:X509Certificate>[^<]*' | head -1 | sed 's/<ds:X509Certificate>//' \
    | base64 --decode 2>/dev/null | openssl x509 -inform DER -noout -subject -enddate
done

jq -r '.RoleDetailList[] | .RoleName as $r
  | .AssumeRolePolicyDocument.Statement | (if type=="array" then .[] else . end)
  | select(.Principal.Federated? // "" | tostring | test("saml-provider"))
  | [$r, (.Principal.Federated|tostring), ((.Condition // {})|tostring)] | @tsv' gaad-roles-111122223333.json
```

Identity Center's own provider appears as `AWSSSO_..._DO_NOT_DELETE` and trusts only the `AWSReservedSSO_*` roles; that is expected. Focus on other providers.

#### Observation

Illustrative:

```text
arn:aws:iam::111122223333:saml-provider/LegacyADFS   Allowed   2019-03-11
subject=CN=ADFS Signing - adfs.example.com   notAfter=Jan  4 12:00:00 2025 GMT
LegacyAdmin   arn:aws:iam::111122223333:saml-provider/LegacyADFS   {}
```

#### Evaluation

- **Fail (Medium):** roles trusting a SAML provider with no `SAML:aud` condition; a legacy provider kept alongside Identity Center with admin roles still trusting it; signing certificates long expired (indicating an unmanaged, possibly orphaned IdP integration).
- **Fail (High):** the IdP mapping grants administrative roles to broad groups, or the provider belongs to an IdP the client no longer controls. Rate by what the reachable roles can do; a compromised IdP signing key mints sessions for every role that trusts the provider (Golden SAML, ATT&CK T1606.002).
- **Observation:** `AssertionEncryptionMode` `Allowed` rather than `Required`; encryption protects assertions in the browser and in transit through the client but does not change who can assume what.
- **Pass:** one managed provider (or Identity Center only), `SAML:aud` on every trust, documented group mapping, certificate rotation owned.

#### Automated coverage

Prowler `iam_check_saml_providers_sts` (inventory). No Security Hub CSPM control.

#### Detection

`AssumeRoleWithSAML` events (with the provider and subject in the event), `CreateSAMLProvider`, `UpdateSAMLProvider`, `DeleteSAMLProvider` (ATT&CK T1484.002 when an attacker adds their own IdP). GuardDuty anomaly findings for the resulting sessions.

### GT-AWS-STS-8: Session duration, chaining, session tags and source identity

*Guler Tech methodology.*

#### What it checks

How long sessions on powerful roles last, whether session tags can be chosen by the caller where ABAC depends on them, and whether source identity and session names are required where attribution matters.

#### Prerequisites

Inventory from test 1; the GAAD snapshot including permissions policies (for ABAC conditions).

#### Steps

Maximum session durations (from GAAD, or `get-role`):

```bash
aws iam list-roles --query 'Roles[?MaxSessionDuration > `3600`].[RoleName,MaxSessionDuration]' --output text | sort -k2 -n
```

Trusts allowing `sts:TagSession` or `sts:SetSourceIdentity`, and whether they constrain the values:

```bash
jq -r '.RoleDetailList[] | .RoleName as $r
  | .AssumeRolePolicyDocument.Statement | (if type=="array" then .[] else . end)
  | select(.Effect=="Allow" and (.Action | tostring | test("TagSession|SetSourceIdentity")))
  | [$r, (.Action|tostring),
     ((.Condition // {}) | tostring | test("aws:RequestTag|aws:TagKeys|sts:TransitiveTagKeys|sts:SourceIdentity") | if . then "constrained" else "UNCONSTRAINED" end)] | @tsv' \
  gaad-roles-111122223333.json
```

Permissions that depend on principal tags (ABAC):

```bash
jq -r '.. | objects | select(has("Condition")) | .Condition | tostring | select(test("aws:PrincipalTag/"))' \
  gaad-roles-111122223333.json | grep -o 'aws:PrincipalTag/[A-Za-z0-9_.:/=+@-]*' | sort | uniq -c
```

If a role's trust lets a caller pass any value for a tag key that permissions policies use in `aws:PrincipalTag/<key>`, simulate the effect (no assumption needed):

```bash
aws iam simulate-custom-policy --policy-input-list file://abac-policy.json \
  --action-names secretsmanager:GetSecretValue \
  --resource-arns arn:aws:secretsmanager:eu-west-2:111122223333:secret:finance/db-EXAMPLE \
  --context-entries "ContextKeyName=aws:PrincipalTag/team,ContextKeyValues=finance,ContextKeyType=string" \
                    "ContextKeyName=aws:ResourceTag/team,ContextKeyValues=finance,ContextKeyType=string" \
  --query 'EvaluationResults[].EvalDecision' --output text
```

Role chaining paths (role A can assume role B) appear in PMapper's graph and CloudFox output; a 12-hour maximum on role B does not survive chaining, which matters when the client relies on long sessions for a chained path.

#### Observation

`data-analyst` trusts the SSO roles with `sts:AssumeRole` and an unconstrained `sts:TagSession`; S3 and Secrets Manager policies in the account grant access where `aws:PrincipalTag/team` equals `aws:ResourceTag/team`. Any caller who can assume `data-analyst` can pass `team=finance`.

#### Evaluation

- **Fail (High):** unconstrained `sts:TagSession` on a role whose permissions are tag-based (ABAC); the caller selects their own access. Critical if it crosses a sensitive data boundary (finance, customer data, production).
- **Fail (Medium):** 12-hour maximum session duration on administrative or production-write roles without a business reason; unconstrained `sts:SetSourceIdentity` where the client relies on source identity for attribution or access control.
- **Low or Info:** no source identity or session name requirements on shared human roles (attribution gap).
- **Pass:** tag keys and values constrained with `aws:RequestTag`, `aws:TagKeys` and `sts:TransitiveTagKeys`, or tags only from the IdP; short sessions on privileged roles; source identity required and constrained where used.

#### Automated coverage

None in Security Hub CSPM. Access Analyzer validation catches some set-operator misuse on `aws:TagKeys`.

#### Detection

`AssumeRole`, `AssumeRoleWithSAML` and `AssumeRoleWithWebIdentity` events show `principalTags`, `transitiveTagKeys` and `sourceIdentity` in `requestParameters`; alert on tag values outside the IdP's expected set, and on `UpdateRole` changing `MaxSessionDuration`.

### GT-AWS-STS-9: IAM Identity Center, federated user and session token use

*Guler Tech methodology.*

#### What it checks

The human access layer: Identity Center permission sets (session duration, who gets admin, inline policies in permission sets), and the use of `GetFederationToken` and `GetSessionToken`, which produce sessions that a role-level revocation does not touch.

#### Prerequisites

Read access to IAM Identity Center in the management account or its delegated administrator (`sso:List*`, `sso:Describe*`, `identitystore:List*`); CloudTrail history.

#### Steps

```bash
INSTANCE=$(aws sso-admin list-instances --query 'Instances[0].InstanceArn' --output text)
for ps in $(aws sso-admin list-permission-sets --instance-arn "$INSTANCE" --query 'PermissionSets[]' --output text); do
  aws sso-admin describe-permission-set --instance-arn "$INSTANCE" --permission-set-arn "$ps" \
    --query 'PermissionSet.[Name,SessionDuration]' --output text
  aws sso-admin list-managed-policies-in-permission-set --instance-arn "$INSTANCE" --permission-set-arn "$ps" \
    --query 'AttachedManagedPolicies[].Name' --output text
done
```

Then, for administrative permission sets, list the accounts and principals assigned (`list-accounts-for-provisioned-permission-set`, `list-account-assignments`) and compare with the client's expectation.

Use of the STS federated user and session token APIs over the last 90 days (per Region; or query the organisation trail):

```bash
for e in GetFederationToken GetSessionToken; do
  aws cloudtrail lookup-events --lookup-attributes AttributeKey=EventName,AttributeValue=$e \
    --max-results 50 --output json \
  | jq -r '.Events[].CloudTrailEvent | fromjson
           | [.eventTime, .eventName, .userIdentity.arn, (.requestParameters.durationSeconds // "default"), .sourceIPAddress] | @tsv'
done
```

#### Observation

Illustrative: an `AdministratorAccess` permission set with `PT12H` assigned to 40 users in every account; `GetFederationToken` called weekly by a legacy reporting user with `durationSeconds` 129600.

#### Evaluation

- **Fail (Medium to High):** administrative permission sets assigned broadly or to all accounts including the management account, with maximum session length; legacy `GetFederationToken` brokers running on IAM users with broad permissions (36-hour sessions that outlive key rotation and role revocation).
- **Fail (High):** `GetSessionToken` or `GetFederationToken` called by the root user (those sessions cannot be restricted).
- **Pass:** least-privilege permission sets, admin assignments limited and short, no STS federated users (or an SCP denying `sts:GetFederationToken` where unused).

#### Automated coverage

None in Security Hub CSPM. Prowler `iam_user_with_temporary_credentials` is related (long-lived key use).

#### Detection

`GetFederationToken` (rare in modern estates; any use deserves review), `GetSessionToken` by root, Identity Center `CreateAccountAssignment` and `AttachManagedPolicyToPermissionSet` / `PutInlinePolicyToPermissionSet` events (ATT&CK T1098.003). GuardDuty `Persistence:IAMUser/AnomalousBehavior` for unusual credential creation.

### GT-AWS-STS-10: Organisation-wide trust graph and external access findings

*Guler Tech methodology.*

#### What it checks

Trust as a graph across all accounts: which principals can reach which roles in other accounts, directly or by chaining, and which roles are reachable from outside the organisation. This is where single-account findings turn into "a developer in the sandbox account can reach production admin in three hops".

#### Prerequisites

Audit access in every in-scope account; Access Analyzer external access analyzers (ideally organisation-level, in each Region you use) or permission to read them.

#### Steps

IAM Access Analyzer external access findings for roles:

```bash
ARN=$(aws accessanalyzer list-analyzers --type ORGANIZATION --query 'analyzers[0].arn' --output text)
aws accessanalyzer list-findings-v2 --analyzer-arn "$ARN" \
  --filter '{"resourceType": {"eq": ["AWS::IAM::Role"]}, "status": {"eq": ["ACTIVE"]} }' \
  --query 'findings[].[resource,findingType]' --output text
aws accessanalyzer get-finding-v2 --analyzer-arn "$ARN" --id <finding-id>
```

Each finding names the external principal and the conditions under which access is granted. An organisation analyzer treats every account in the organisation as trusted, so it shows only trust leaving the organisation; account-level analyzers also show trust between your own accounts.

Graph across accounts with PMapper (one graph per account profile, then the organisation layer):

```bash
for p in audit-prod audit-dev audit-shared; do pmapper --profile "$p" graph create; done
pmapper --profile audit-mgmt orgs create
pmapper --account 111122223333 query 'who can do sts:AssumeRole with arn:aws:iam::111122223333:role/prod-admin'
cloudfox aws --profile audit-prod cape     # cross-account paths from PMapper data
```

Check the PMapper wiki for the current `orgs` sub-commands. With CloudTrail, `cloudfox aws outbound-assumed-roles` shows which roles outside the account its principals have actually assumed, which is the quickest way to find undocumented partner access and shadow cross-account automation.

#### Observation

Illustrative: Access Analyzer shows `partner-readonly` trusted by 444455556666 and `debug-role` trusted by `*`; PMapper shows `sandbox/developer` can assume `shared-services/deployer`, which can assume `prod/OrganizationAccountAccessRole`.

#### Evaluation

- **Fail:** any active external access finding on a role that the client cannot justify (rate per test 2 or 3); any path from a low-trust account (sandbox, dev, CI, a vendor) to administrative roles in production or the management account (High to Critical, per the [Organizations note](/cloud/aws-organizations-multi-account-security/)).
- **Fail (Medium):** no external access analyzer in one or more Regions in use (Security Hub `IAM.28`).
- **Pass:** every external finding archived with a documented reason, and no chaining path from low-trust to high-trust accounts.

#### Automated coverage

Security Hub CSPM `IAM.28` (external access analyzer enabled; CIS v3.0.0 1.20, v5.0.0 1.19). Prowler `accessanalyzer_enabled`, `accessanalyzer_enabled_without_findings`, `organizations_account_part_of_organizations`.

#### Detection

Cross-account `AssumeRole` events correlated by `sharedEventID` between the calling and target accounts; EventBridge rules on Access Analyzer findings (new external access); GuardDuty `AttackSequence:IAM/CompromisedCredentials` for multi-stage activity by one compromised identity.

### GT-AWS-STS-11: Session revocation readiness

*Guler Tech methodology.*

#### What it checks

Whether the client can stop a stolen session quickly: who holds the permission, whether there is a runbook, whether past revocations happened, and whether the runbook covers the cases a role-level revoke misses.

#### Prerequisites

GAAD snapshot; an interview with the incident response owner. A live revocation is **lab or explicitly approved only**: it denies every current session of the role, including legitimate ones.

#### Steps

Existing revocations (evidence of past incidents or exercises):

```bash
jq -r '.RoleDetailList[] | select(any(.RolePolicyList[]?; .PolicyName == "AWSRevokeOlderSessions"))
       | [.RoleName, ([.RolePolicyList[] | select(.PolicyName=="AWSRevokeOlderSessions") | .PolicyDocument | tostring] | first)] | @tsv' \
  gaad-roles-111122223333.json
```

Who can revoke: simulate `iam:PutRolePolicy` for the incident response role against a sample of critical roles, and check that an SCP does not deny it to responders in member accounts. Then walk through the runbook against this checklist: role sessions (inline `AWSRevokeOlderSessions` or the console button); resource policies that grant to session ARNs directly (add an explicit deny on the resource); IAM user sessions from `GetSessionToken` and `GetFederationToken` (deny with `aws:TokenIssueTime` on the user, then disable the key); Identity Center sessions (revoke in Identity Center); EC2, ECS and Lambda credentials (they refresh automatically, so contain the workload first); root-derived sessions (no restriction possible; prevention only).

In a lab, the revocation itself looks like this:

```bash
# lab or explicitly approved only: denies every existing session of the role
NOW=$(date -u +%Y-%m-%dT%H:%M:%SZ)
cat > revoke.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "DateLessThan": {
          "aws:TokenIssueTime": "$NOW"
        }
      }
    }
  ]
}
EOF
aws iam put-role-policy --role-name lab-target --policy-name AWSRevokeOlderSessions --policy-document file://revoke.json
```

#### Observation

A typical gap: the runbook says "delete the access key", which leaves any `GetSessionToken` session minted with it valid for up to 36 hours; or responders lack `iam:PutRolePolicy` in member accounts because an SCP protects IAM.

#### Evaluation

- **Fail (Medium):** no documented revocation procedure for role sessions and IAM user sessions; responders without the permission to revoke in member accounts; runbooks that stop at deleting keys.
- **Pass:** tested runbook covering the cases above, an exercise in the last year, and responders able to revoke everywhere.

#### Automated coverage

None. This is a process control supported by the IAM features above.

#### Detection

`PutRolePolicy` with `policyName` `AWSRevokeOlderSessions` (expected during incidents, otherwise review); `DeleteRolePolicy` removing it (an attacker undoing containment).

## Hardening

**Name principals; avoid `"*"`.** Trust specific role ARNs. When you need pattern matching, combine `"*"` with both organisation and ARN conditions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "OrgCiRunnersOnly",
      "Effect": "Allow",
      "Principal": {"AWS": "*"},
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": {
          "aws:PrincipalOrgID": "o-exampleorgid"
        },
        "ArnLike": {
          "aws:PrincipalArn": "arn:aws:iam::*:role/platform/ci-runner"
        }
      }
    }
  ]
}
```

**Third parties: vendor-generated ExternalId, named vendor principal where the vendor supports it, and least privilege.**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::444455556666:role/VendorScanner"},
      "Action": "sts:AssumeRole",
      "Condition": {
        "StringEquals": {
          "sts:ExternalId": "<vendor-generated-unique-id>"
        }
      }
    }
  ]
}
```

**Service principals: bind the source.**

```json
{
  "Effect": "Allow",
  "Principal": {"Service": "events.amazonaws.com"},
  "Action": "sts:AssumeRole",
  "Condition": {
    "StringEquals": {
      "aws:SourceAccount": "111122223333"
    },
    "ArnLike": {
      "aws:SourceArn": "arn:aws:events:eu-west-2:111122223333:rule/orders-*"
    }
  }
}
```

**GitHub Actions: pin audience, repository, and branch or protected environment; prefer immutable IDs.**

```hcl
data "aws_iam_policy_document" "gh_deploy_trust" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = ["arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:client-org/app:environment:production"]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:repository_owner_id"
      values   = ["123456"]
    }
  }
}
```

Using `aws_iam_policy_document` avoids the duplicate-key trap of hand-written JSON in `jsonencode`. Separate roles for `plan` (read-only, any branch) and `apply` (write, protected environment only). In GitHub, add required reviewers and deployment branch rules to the environment.

**IRSA: pin `aud` and `sub` per service account**, one role per service account; consider EKS Pod Identity for new workloads (see the [containers note](/cloud/aws-containers-ecs-eks-ecr-security/)).

**Constrain session tags and require source identity where attribution matters.** Allow `sts:TagSession` only with `aws:RequestTag` values and `aws:TagKeys` lists you expect, or let only the IdP assert tags. Require `sts:SourceIdentity` set to the user's name for shared administrative roles.

**Short sessions for power.** 1 hour for administrative roles and admin permission sets unless there is a reason; long sessions only for read-only roles.

**Organisation guardrails.** An RCP that keeps STS role assumption inside the organisation (with listed exceptions for vendors), and enforces confused deputy protection for service principals, based on AWS's data perimeter examples:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "EnforceOrgIdentitiesForAssumeRole",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "sts:AssumeRole",
      "Resource": "*",
      "Condition": {
        "StringNotEqualsIfExists": {
          "aws:PrincipalOrgID": "o-exampleorgid",
          "aws:PrincipalAccount": ["444455556666"]
        },
        "BoolIfExists": {
          "aws:PrincipalIsAWSService": "false"
        }
      }
    },
    {
      "Sid": "EnforceConfusedDeputyProtectionForSts",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "sts:*",
      "Resource": "*",
      "Condition": {
        "StringNotEqualsIfExists": {
          "aws:SourceOrgID": "o-exampleorgid"
        },
        "Null": {
          "aws:SourceAccount": "false"
        },
        "Bool": {
          "aws:PrincipalIsAWSService": "true"
        }
      }
    }
  ]
}
```

Test RCPs on a single account first; they apply to every principal, including vendors and AWS services acting for you, and they do not apply to the management account. An SCP denying `sts:GetFederationToken` (where unused) and `iam:CreateSAMLProvider`, `iam:CreateOpenIDConnectProvider`, `iam:UpdateAssumeRolePolicy` outside the platform role closes the most common persistence routes through trust.

**Continuous checks.** Organisation-level Access Analyzer external access analyzers in every Region in use (`IAM.28`); `validate-policy` with `AWS::IAM::AssumeRolePolicyDocument` and `check-no-public-access` in CI for every trust policy change; EventBridge alerts on `UpdateAssumeRolePolicy`, `CreateOpenIDConnectProvider` and `CreateSAMLProvider`.

## Real-world cases

- **GitHub-to-AWS keyless authentication flaws (Datadog Security Labs, July 2023, updated 2025).** Datadog collected over 500 role ARNs from public code and found GitHub-trusting roles with no `sub` condition, assumable from any GitHub repository, including one in a UK government account with push access to source repositories; they also described a Terraform duplicate-key bug that silently dropped the subject check. Datadog reports that AWS blocked creation of new vulnerable trust policies from June 2025, while existing roles stay exposed until fixed: [Exploring GitHub-to-AWS keyless authentication flaws](https://securitylabs.datadoghq.com/articles/exploring-github-to-aws-keyless-authentication-flaws/).
- **Third-party AssumeRole and ExternalId (Praetorian, 2020).** Praetorian tested 90 vendors that access customer accounts through cross-account roles and found many did not implement ExternalId correctly (generated by the customer, not validated on the back end), making cross-tenant access through the vendor possible: [AWS IAM Assume Role vulnerabilities found in many top vendors](https://www.praetorian.com/blog/aws-iam-assume-role-vulnerabilities/).
- **"Sleeper squats" and GitHub's immutable subject claims (BoostSecurity, 2026).** While GitHub was rolling out immutable `sub` claims, the first delimiter choice allowed an attacker to pre-register an organisation name matching a victim's future subject string; GitHub changed the delimiter to `@` before default rollout. The lesson for trust policies is to copy subject prefixes exactly and prefer immutable ID claims: [Sleeper Squats](https://labs.boostsecurity.io/articles/sleeper-squats-github-oidc-immutable-subject-claim), and GitHub's [changelog](https://github.blog/changelog/2026-04-23-immutable-subject-claims-for-github-actions-oidc-tokens/).
- **AWS guidance on exposed keys.** AWS's own [what to do if you inadvertently expose an access key](https://aws.amazon.com/blogs/security/what-to-do-if-you-inadvertently-expose-an-aws-access-key/) explains why deleting a key is not enough when temporary credentials were minted from it, and how to deny them with `aws:TokenIssueTime`.

For more public incidents across the series, see [AWS security incidents and write-ups](/cloud/aws-security-incidents-and-writeups/).

## Rating findings

| Finding | Typical severity | Reasoning |
|---|---|---|
| Trust policy `"*"` with no effective condition on a role with meaningful permissions | Critical | Unauthenticated-equivalent: any AWS account holder obtains a session. Blast radius is the role's permissions; admin roles mean account takeover. |
| GitHub (or other shared-issuer) OIDC trust without `sub`, or with an organisation wildcard | Critical | Any user of the shared issuer can mint a token from their own repository; deployment roles are typically near-admin. |
| Subject pinned to organisation only, or any branch or pull request, on a deploy role | High | Any insider or compromised contributor (or a malicious pull request in a `pull_request_target` workflow) gets deploy rights; no review gate. |
| External account trusted at account level without ExternalId or principal restriction | High | Security depends on another organisation's IAM; a single compromised principal there reaches you. Critical for write or admin roles. |
| SaaS role without ExternalId (vendor serves other tenants) | High | Confused deputy: another tenant can direct the vendor at your role; activity looks like legitimate vendor access. |
| IRSA trust without `sub` (or `*:*`) | High | Any pod in the cluster becomes the role; Critical in multi-tenant or internet-facing clusters. |
| Unconstrained `sts:TagSession` with ABAC permissions | High | Caller chooses their own authorisation attributes; privilege escalation across data boundaries. |
| Low-trust account can chain to admin in production or management account | High to Critical | Organisation-level privilege escalation; rate on the starting point's exposure. |
| Service principal trust without source conditions (non-PassRole-gated service) | Medium | Cross-service confused deputy possible; depends on the service's own checks and the role's permissions. |
| SAML trust without `SAML:aud`, orphaned or legacy providers with admin roles | Medium (High for admin reach) | Weakens the binding between IdP and AWS; orphaned IdPs are unmonitored paths to admin. |
| 12-hour sessions on admin roles; broad admin permission sets | Medium | Extends the value of a stolen session; increases reliance on revocation. |
| No external access analyzer; no revocation runbook | Medium | Loss of visibility and of the ability to contain; raises the impact of every other finding. |
| Name-based GitHub conditions for a renamed organisation; missing `aud` | Medium | Exploitable only if the old name is claimable or tokens with other audiences exist; still a real path. |

## Mapping

| Test | Security Hub CSPM | CIS AWS Foundations (version/rec.) | MITRE ATT&CK |
|---|---|---|---|
| GT-AWS-STS-1 | IAM.28 | v5.0.0 1.19; v3.0.0 1.20 | T1087.004, T1069.003 |
| GT-AWS-STS-2 | IAM.28 | v5.0.0 1.19 | T1078.004, T1548.005 |
| GT-AWS-STS-3 | none | none | T1199, T1078.004 |
| GT-AWS-STS-4 | none | none | T1548.005 |
| GT-AWS-STS-5 | none | none | T1550.001, T1528, T1078.004 |
| GT-AWS-STS-6 | none | none | T1550.001, T1078.004 |
| GT-AWS-STS-7 | none | none | T1606.002, T1484.002 |
| GT-AWS-STS-8 | none | none | T1548.005 |
| GT-AWS-STS-9 | none | none | T1078.004, T1098.003 |
| GT-AWS-STS-10 | IAM.28 | v5.0.0 1.19; v3.0.0 1.20 | T1199, T1548.005, T1087.004 |
| GT-AWS-STS-11 | none | none | T1078.004 |

Security Hub CSPM (the name AWS gave the original Security Hub in 2025, when the new unified Security Hub launched) has no control that inspects trust policy conditions; `IAM.28` only checks that an external access analyzer exists. Most coverage for this area comes from IAM Access Analyzer, Access Analyzer policy validation, Prowler and manual review.

## References

- AWS: [IAM roles: terms and concepts (role chaining, trust policy)](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_terms-and-concepts.html), [Principal element](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_principal.html), [Cross-account policy evaluation](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic-cross-account.html)
- AWS: [The confused deputy problem](https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html), [Access to AWS accounts owned by third parties (external ID)](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_common-scenarios_third-party.html)
- AWS: [Compare AWS STS credentials](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_sts-comparison.html), [Request temporary security credentials](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_request.html), [Pass session tags](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_session-tags.html), [Source identity](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_control-access_monitor.html)
- AWS: [Create a role for OIDC federation (GitHub section)](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-idp_oidc.html), [Identity-provider controls for shared OIDC providers](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_oidc_secure-by-default.html), [Create an OIDC identity provider](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_oidc.html), [IAM and STS condition keys (OIDC and GitHub claims)](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_iam-condition-keys.html)
- AWS: [SAML 2.0 federation](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_saml.html), [Create a role for SAML 2.0 federation](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-idp_saml.html)
- AWS: [Revoke IAM role temporary security credentials](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_revoke-sessions.html), [Disable permissions for temporary credentials](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_temp_control-access_disable-perms.html), [What to do if you inadvertently expose an AWS access key](https://aws.amazon.com/blogs/security/what-to-do-if-you-inadvertently-expose-an-aws-access-key/)
- AWS: [Logging IAM and AWS STS calls with CloudTrail](https://docs.aws.amazon.com/IAM/latest/UserGuide/cloudtrail-integration.html), [IAM Access Analyzer findings](https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-findings.html), [Policy check reference](https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-reference-policy-checks.html)
- AWS: [EKS IAM roles for service accounts](https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html), [Assign IAM roles to Kubernetes service accounts](https://docs.aws.amazon.com/eks/latest/userguide/associate-service-account-role.html)
- AWS: [IAM Identity Center user access](https://docs.aws.amazon.com/singlesignon/latest/userguide/useraccess.html), [Referencing permission sets](https://docs.aws.amazon.com/singlesignon/latest/userguide/referencingpermissionsets.html)
- AWS Organizations: [RCPs](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_rcps.html), [Data perimeter policy examples](https://github.com/aws-samples/data-perimeter-policy-examples)
- AWS: [Security Hub CSPM IAM controls](https://docs.aws.amazon.com/securityhub/latest/userguide/iam-controls.html), [GuardDuty IAM finding types](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html), [Penetration testing policy](https://aws.amazon.com/security/penetration-testing/)
- GitHub: [OpenID Connect reference](https://docs.github.com/en/actions/reference/security/oidc), [Configuring OIDC in AWS](https://docs.github.com/en/actions/how-tos/secure-your-work/security-harden-deployments/oidc-in-aws)
- Tools: [CloudFox](https://github.com/BishopFox/cloudfox), [PMapper](https://github.com/nccgroup/PMapper), [Prowler](https://github.com/prowler-cloud/prowler), [Pacu](https://github.com/RhinoSecurityLabs/pacu), [fwd:cloudsec known AWS accounts](https://github.com/fwdcloudsec/known_aws_accounts)
- Labs: [CloudGoat](https://github.com/RhinoSecurityLabs/cloudgoat), [flaws2.cloud](http://flaws2.cloud/)
- MITRE ATT&CK: [T1199](https://attack.mitre.org/techniques/T1199/), [T1078.004](https://attack.mitre.org/techniques/T1078/004/), [T1548.005](https://attack.mitre.org/techniques/T1548/005/), [T1484.002](https://attack.mitre.org/techniques/T1484/002/), [T1606.002](https://attack.mitre.org/techniques/T1606/002/), [T1550.001](https://attack.mitre.org/techniques/T1550/001/), [T1528](https://attack.mitre.org/techniques/T1528/), [T1087.004](https://attack.mitre.org/techniques/T1087/004/)
- Research: [Datadog Security Labs, GitHub-to-AWS keyless authentication flaws](https://securitylabs.datadoghq.com/articles/exploring-github-to-aws-keyless-authentication-flaws/), [Praetorian, AssumeRole vulnerabilities in vendors](https://www.praetorian.com/blog/aws-iam-assume-role-vulnerabilities/), [BoostSecurity, Sleeper Squats](https://labs.boostsecurity.io/articles/sleeper-squats-github-oidc-immutable-subject-claim)
