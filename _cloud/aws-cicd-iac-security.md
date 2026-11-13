---
title: "AWS CI/CD and Infrastructure-as-Code Security"
date: 2026-11-12 18:17:00 +0000
subcategory: aws
summary: "Testing the pipelines that deploy AWS: OIDC trust, CI role privilege, CodeBuild webhooks, CloudFormation and CDK roles, Terraform state and IaC scanning."
refs: [CodeBuild.1, CodeBuild.2, CodeBuild.4, CloudFormation.3, CloudFormation.4, IAM.1, IAM.3, IAM.22, S3.1, S3.8, S3.14, "CIS AWS v1.4.0 1.16", "CIS AWS v3.0.0 1.14", T1677, T1195.002, T1195.001, T1199, T1078.004, T1552.001, T1528]
tags: [aws, cicd, codebuild, cloudformation, terraform, oidc]
---

This note is part of our [AWS security testing guide](/cloud/aws-security-testing-guide/) and covers the systems that build and deploy AWS infrastructure: GitHub Actions and GitLab CI federated into AWS, AWS CodeBuild, CodePipeline and CodeArtifact, CloudFormation and StackSets, Terraform and the AWS CDK. The reason it gets its own note is simple. In most organisations the deployment role is the most privileged non-human identity in every account, often `AdministratorAccess`, and the question "who can make that role do something?" has answers far outside IAM: anyone who can push a branch, open a pull request that triggers a build, edit a buildspec, publish a package the build pulls, write to the artefact bucket, or read the Terraform state file. A pipeline review is therefore an IAM review in which the principals are Git events. Below are the trust and privilege models, what goes wrong, eleven tests, the policies and IaC that fix them, and how to rate what you find.

## Contents

- [How it works](#how-it-works)
  - [The pipeline is an identity](#the-pipeline-is-an-identity)
  - [OIDC federation from GitHub Actions and GitLab](#oidc-federation-from-github-actions-and-gitlab)
  - [Long-lived keys in CI](#long-lived-keys-in-ci)
  - [AWS CodeBuild](#aws-codebuild)
  - [CodePipeline and CodeArtifact](#codepipeline-and-codeartifact)
  - [CloudFormation and StackSets](#cloudformation-and-stacksets)
  - [Terraform state and backends](#terraform-state-and-backends)
  - [AWS CDK bootstrap](#aws-cdk-bootstrap)
  - [IaC scanning, policy as code and drift](#iac-scanning-policy-as-code-and-drift)
- [What goes wrong](#what-goes-wrong)
- [Testing](#testing)
  - [Before you start](#before-you-start)
  - [GT-AWS-CICD-1: OIDC providers and role trust policies](#gt-aws-cicd-1-oidc-providers-and-role-trust-policies)
  - [GT-AWS-CICD-2: CI/CD role privilege and blast radius](#gt-aws-cicd-2-cicd-role-privilege-and-blast-radius)
  - [GT-AWS-CICD-3: Long-lived AWS keys used by CI](#gt-aws-cicd-3-long-lived-aws-keys-used-by-ci)
  - [GT-AWS-CICD-4: CodeBuild project review](#gt-aws-cicd-4-codebuild-project-review)
  - [GT-AWS-CICD-5: CodeBuild webhooks and untrusted pull request builds](#gt-aws-cicd-5-codebuild-webhooks-and-untrusted-pull-request-builds)
  - [GT-AWS-CICD-6: CodePipeline artefact stores and CodeArtifact origins](#gt-aws-cicd-6-codepipeline-artefact-stores-and-codeartifact-origins)
  - [GT-AWS-CICD-7: CloudFormation service roles, stack policies and StackSets](#gt-aws-cicd-7-cloudformation-service-roles-stack-policies-and-stacksets)
  - [GT-AWS-CICD-8: Terraform state bucket review](#gt-aws-cicd-8-terraform-state-bucket-review)
  - [GT-AWS-CICD-9: CDK bootstrap review](#gt-aws-cicd-9-cdk-bootstrap-review)
  - [GT-AWS-CICD-10: IaC and workflow scan of the client repository](#gt-aws-cicd-10-iac-and-workflow-scan-of-the-client-repository)
  - [GT-AWS-CICD-11: Drift detection](#gt-aws-cicd-11-drift-detection)
- [Hardening](#hardening)
- [Real-world cases](#real-world-cases)
- [Rating findings](#rating-findings)
- [Mapping](#mapping)
- [References](#references)

## How it works

### The pipeline is an identity

Every pipeline ends in an AWS principal: a role assumed through OIDC, an IAM user's access key stored in the CI system, a CodeBuild service role, a CodePipeline role, a CloudFormation service role, a CDK bootstrap role, a StackSet execution role. Three questions decide the risk:

1. **What can that principal do?** Deploying arbitrary infrastructure needs, in practice, the ability to create IAM roles and pass them to services, which is administrator-equivalent whatever the policy is called. See [IAM privilege escalation](/cloud/aws-iam-privilege-escalation/).
2. **Who can make the pipeline run code of their choosing as that principal?** Not only people with AWS access: anyone who can push to a branch the trust policy accepts, open a pull request that triggers a privileged build, change the build definition in the repository, poison a dependency or artefact the build consumes, or modify the template the deploy role applies. ATT&CK calls the code-injection half of this **Poisoned Pipeline Execution** (T1677).
3. **Where do the pipeline's secrets and outputs end up?** Build logs, artefact buckets, Terraform state, CloudFormation outputs, package registries.

### OIDC federation from GitHub Actions and GitLab

The recommended way for an external CI system to reach AWS is web identity federation: the CI platform issues a short-lived signed JWT for each job, the job calls `sts:AssumeRoleWithWebIdentity`, and the role's **trust policy** decides which tokens are accepted. No AWS secret is stored in the CI system. Depth on STS and federation is in the [STS and cross-account trust note](/cloud/aws-sts-cross-account-trust-federation/); this section covers what matters for CI.

**The provider.** An IAM OIDC identity provider for `token.actions.githubusercontent.com` (GitHub) or `gitlab.com` (GitLab SaaS) exists once per account. The provider only says "tokens signed by this issuer are valid". It does not restrict *which* repository's tokens are accepted. For providers whose TLS certificates chain to a trusted root CA, which includes GitHub and GitLab.com, AWS no longer relies on the thumbprint configured on the provider, so thumbprint values are not where the security lives.

**The claims that matter.** GitHub's token carries `aud` (default `sts.amazonaws.com` with the official action) and `sub`, plus claims such as `repository`, `repository_id`, `repository_owner_id`, `ref`, `environment`, `job_workflow_ref`, `actor`. The default `sub` formats are:

| Workflow context | Default `sub` |
|---|---|
| Job using an environment | `repo:ORG/REPO:environment:ENV` |
| Push to a branch or tag (no environment) | `repo:ORG/REPO:ref:refs/heads/BRANCH` or `...:ref:refs/tags/TAG` |
| `pull_request` event | `repo:ORG/REPO:pull_request` |

IAM supports conditions on `aud` and `sub`, and for GitHub also on `token.actions.githubusercontent.com:repository_id`, `repository_owner_id`, `job_workflow_ref`, `environment`, `ref`, `actor`, `workflow` and others. For GitLab SaaS, `gitlab.com:sub` has the form `project_path:GROUP/PROJECT:ref_type:branch:ref:main`, and IAM also supports `gitlab.com:project_id`, `namespace_id`, `ref_protected`, `pipeline_source` and more (for GitLab SaaS only, not self-managed instances).

**The failure that matters.** These issuers are *shared*: every GitHub repository in the world gets tokens from the same issuer. A trust policy that checks `aud` but not `sub` accepts a token from **any repository on GitHub**, so anyone can assume the role from their own repository. Datadog Security Labs found this at scale in 2023 (see [Real-world cases](#real-world-cases)). AWS responded with **identity-provider controls**: since around June 2025, IAM rejects creating or updating a role trust policy for GitHub's provider unless it evaluates `sub` (or `job_workflow_ref`) with a value that is not just a wildcard, and similar rules apply to GitLab SaaS, HCP Terraform, Buildkite and other shared issuers. **Existing roles are not re-evaluated** until someone edits their trust policy, so roles created before the change can still be open. That makes this test still worth running in 2026.

Weaker but still common shapes:

- `StringLike` on `repo:ORG/*`: any repository in the organisation, including throwaway repositories any member can create.
- `repo:ORG/REPO:*`: any branch, tag, environment or pull request workflow in that repository, so anyone who can push a branch, or get a workflow to run on a pull request in the base repository's context, gets the deploy role.
- Duplicate `StringEquals` keys produced by templating (Terraform maps, JSON merges), where the second silently overwrites the first and the `sub` check disappears.

**GitHub's subject format change.** For repositories created after **15 July 2026**, or that opt in, GitHub now puts immutable numeric IDs into `sub`, for example `repo:example-org@1234567/payments-infra@7654321:environment:production`, so that a deleted and re-registered organisation or repository name cannot mint matching tokens. Trust policies written for the old format do not match new repositories (deploys fail closed), and policies written only with names remain exposed to name reuse for older repositories. Check GitHub's current OIDC reference for the format your client's repositories use; conditions on `repository_id` and `repository_owner_id` give the same protection explicitly.

### Long-lived keys in CI

The alternative to OIDC is an IAM user whose access key sits in the CI system's secret store (GitHub Actions secrets, GitLab CI/CD variables, Jenkins credentials, a `.env` in the runner image). Those keys do not expire, they are readable by anyone who can change a workflow that runs with secrets (and printed by any step that echoes the environment), they are copied into runner caches and logs, and they leak in supply-chain incidents like the 2025 `tj-actions/changed-files` compromise. Every one is also an IAM user that Security Hub IAM.3 and IAM.22 expect to be rotated or removed. OIDC is available for GitHub, GitLab, Bitbucket Pipelines, CircleCI, Buildkite, HCP Terraform and others; long-lived keys in CI are a finding unless the platform genuinely cannot federate.

### AWS CodeBuild

A CodeBuild **project** defines a source (CodeCommit, GitHub, GitLab, Bitbucket, S3, or none), a build environment (image, compute, optional VPC), a **service role** the build runs as, environment variables, the buildspec (from the repository, inline, or an S3 object), logs, artefacts and optional **webhook** triggers.

Security-relevant properties:

- **Service role.** Every command in the buildspec runs with this role's credentials, available from the container's credentials endpoint. Anyone who can change what the build runs (the buildspec in the repository, the project's inline buildspec, `StartBuild` overrides) acts as the role. `codebuild:StartBuild` accepts `buildspecOverride`, `environmentVariablesOverride`, `sourceVersion` and more, so **`StartBuild` on a project is code execution as its service role**, and `CreateProject` plus `iam:PassRole` is a classic escalation path that PMapper models.
- **Environment variables** have a type: `PLAINTEXT` (stored and returned in clear by `BatchGetProjects`), `PARAMETER_STORE` or `SECRETS_MANAGER` (stored as a reference, resolved at build time). Values from any type end up in the build's environment and in logs if a command prints them.
- **Privileged mode** lets the build run a Docker daemon (needed for `docker build`). Each build runs in its own isolated environment, and Security Hub CSPM retired its privileged-mode control (CodeBuild.5) in April 2024 on the basis that it adds no risk to the customer's environment. Treat it as relevant only together with other weaknesses (untrusted code reaching a privileged build that also has a powerful role).
- **Source credentials.** CodeBuild stores a GitHub, GitHub Enterprise, GitLab or Bitbucket token, OAuth connection or CodeConnections connection per account and Region (`ImportSourceCredentials`, `ListSourceCredentials`) or per project. The token's scope is whatever the person who created it had: often a personal access token with `repo` and `admin:repo_hook`, readable by builds.
- **Public builds.** `projectVisibility: PUBLIC_READ` makes build logs and artefacts readable by anyone on the internet through a public URL. Useful for open-source projects; dangerous when builds print environment or secrets.
- **Webhooks and filter groups.** A webhook triggers builds on repository events. Filter groups combine an `EVENT` (`PUSH`, `PULL_REQUEST_CREATED`, `PULL_REQUEST_UPDATED`, `PULL_REQUEST_REOPENED`, `PULL_REQUEST_MERGED`, `PULL_REQUEST_CLOSED`, `RELEASED`, `PRERELEASED`, `WORKFLOW_JOB_QUEUED`) with regular-expression filters: `ACTOR_ACCOUNT_ID` (shown as `ACTOR_ID` in the console), `HEAD_REF`, `BASE_REF`, `FILE_PATH`, `COMMIT_MESSAGE`, `TAG_NAME`, `RELEASE_NAME`, `REPOSITORY_NAME`, `ORGANIZATION_NAME`, `WORKFLOW_NAME`. Patterns use RE2 and **match anywhere in the string unless anchored**.
- **Pull request comment approval** (`pullRequestBuildPolicy`). `requiresCommentApproval` is `ALL_PULL_REQUESTS` (the default for new projects), `FORK_PULL_REQUESTS` or `DISABLED`; `approverRoles` lists repository roles (default for GitHub: admin, maintain, write) whose pull requests build automatically and who can approve others with a `/codebuild_run(<commit SHA>)` comment. Projects created before this feature, or with it set to `DISABLED`, build whatever pull request matches the filters.
- **CodeBuild-hosted GitHub Actions runners** (`WORKFLOW_JOB_QUEUED`): GitHub workflow jobs run on CodeBuild with the project's service role, so the GitHub workflow's trigger rules (including `pull_request_target`) decide who runs code as that role.

The **CodeBreach** research by Wiz (disclosed January 2026) showed how this goes wrong on AWS's own repositories: `ACTOR_ACCOUNT_ID` allow-lists of maintainer user IDs written as unanchored `|`-separated patterns matched any new GitHub account whose numeric ID *contained* a maintainer's ID, a pull request from such an account ran in the privileged build, and the build's GitHub token gave admin over the repository. Details in [Real-world cases](#real-world-cases).

### CodePipeline and CodeArtifact

**CodePipeline** orchestrates stages (source, build, test, deploy). It has a **pipeline role** and optional per-action roles (often in other accounts for cross-account deploys), and an **artefact store** per Region: an S3 bucket (with an optional customer managed key) through which every stage passes its output to the next. Whoever can write to that bucket between stages can substitute the artefact the deploy stage applies, and whoever can read it gets source code, built packages and rendered templates. Cross-account pipelines need a customer managed key whose policy lets the target account's roles decrypt artefacts; the AWS managed `aws/s3` key cannot be shared. Source actions use CodeConnections (formerly CodeStar Connections) to GitHub or GitLab; the connection is an account-level resource that any pipeline in the account with permission to `codeconnections:UseConnection` (historically `codestar-connections:UseConnection`) can use.

**CodeArtifact** hosts npm, PyPI, Maven, NuGet and other repositories in a **domain**. A repository can have **upstream** repositories and one **external connection** to a public registry (`public:npmjs`, `public:pypi`, ...). That is the shape of a **dependency confusion** (AWS says "dependency substitution") attack: if an internal package name is also published publicly with a higher version, a client resolving through the repository may receive the public one. CodeArtifact's **package origin controls** (enforced since July 2022) set, per package, whether versions may be **published** directly and whether they may come from **upstream** (including the external connection). A package whose first version was published directly defaults to `publish=ALLOW, upstream=BLOCK`; one first ingested from a public source defaults to `publish=BLOCK, upstream=ALLOW`. Packages that existed before about May 2022 default to `ALLOW`/`ALLOW` and need fixing by hand, and internal names that have *never* been published to the repository (a new internal library, a typo, a scoped name used only in one service) have no protection until their first version arrives. **Package groups** apply origin controls to name patterns, which is how you protect a whole internal namespace in advance.

### CloudFormation and StackSets

**Service roles.** A stack can carry a service role (`RoleARN`) that CloudFormation uses for every create, update and delete. Setting it requires `iam:PassRole` once. After that, **any principal allowed to update the stack uses that role, whether or not it has `iam:PassRole`**, which AWS states in the documentation of Security Hub CloudFormation.4. A stack whose role is administrator is therefore an administrator credential for everyone with `cloudformation:UpdateStack`, `CreateChangeSet` plus `ExecuteChangeSet`, or `cloudformation:*` on it. Stacks without a service role run with the caller's own permissions, which is safer for that reason and less safe in that the caller then needs broad permissions.

**Stack policies** (`SetStackPolicy`) protect named resources from replacement or deletion during updates; they are not an access control (anyone who can update the stack can usually change the stack policy) but they do stop accidents. **Termination protection** (CloudFormation.3) stops `DeleteStack`.

**Secrets in templates.** Parameters without `NoEcho: true` appear in plaintext in `DescribeStacks`; `NoEcho` masks them there but not if the template copies the value into `Outputs` or `Metadata`. The right pattern is a **dynamic reference** to Secrets Manager or an SSM `SecureString`, resolved at deploy time and never stored in the stack. Detailed checks are in [the secrets note](/cloud/aws-secrets-manager-parameter-store-kms/) (GT-AWS-SEC-10).

**StackSets** deploy one template to many accounts and Regions.

- *Self-managed permissions*: an administration role in the admin account (by convention `AWSCloudFormationStackSetAdministrationRole`) assumes an **execution role** in each target account (by convention `AWSCloudFormationStackSetExecutionRole`) that trusts the admin account. AWS's sample execution role template grants `AdministratorAccess`. Anyone who can create or update StackSets in the admin account is therefore administrator in every target account.
- *Service-managed permissions*: AWS Organizations trusted access; the management account or a **delegated administrator** deploys to OUs through service-linked roles. Here the control point is who can act as StackSets administrator in those accounts (see the [Organizations note](/cloud/aws-organizations-multi-account-security/)).

**Drift.** `DetectStackDrift` compares live resources with the template and reports `MODIFIED`, `DELETED` or `IN_SYNC` per resource (for supported resource types and properties). Drift is often harmless console fixes; it is also how out-of-band changes, including an attacker's, show up.

### Terraform state and backends

Terraform's **state file** records every managed resource's attributes as returned by the provider, in JSON, and that includes secrets: generated database passwords, `random_password` results, `tls_private_key` private keys, IAM access key secrets (`aws_iam_access_key`), anything passed through a resource argument. Marking a variable or output `sensitive = true` **only hides it from CLI output; the value is still written to state and plan files**. Since Terraform 1.10, **ephemeral** variables, outputs and resources keep values out of state and plan entirely, and since 1.11 **write-only arguments** (provider arguments typically ending in `_wo`) let you pass such values to resources without persisting them. Adoption depends on provider support; most existing configurations still persist secrets.

So **read access to state is credential access**, and **write access to state is a deployment control**: tampering with state can make the next `apply` destroy, recreate or "import" resources in ways a reviewer of the plan may miss. The `terraform_remote_state` data source and the `-backend-config` files used in CI give the same read access.

For the S3 backend:

- **Locking.** Terraform 1.10 introduced S3-native locking (`use_lockfile = true`, a `.tflock` object next to the state), generally available in 1.11; DynamoDB-based locking (`dynamodb_table`) is deprecated and will be removed in a future version. Locking needs `s3:GetObject`, `s3:PutObject` and `s3:DeleteObject` on the lock object.
- **Hardening.** A dedicated bucket (or account) with Block Public Access, versioning (for recovery from corrupted or malicious state), SSE-KMS with a customer managed key whose policy limits decrypt to the CI role and a break-glass role, a bucket policy denying non-TLS access and limiting access to those same roles, access logging or S3 data events, and Object Lock only if the client's recovery process accounts for it.
- **Who reads it.** Developers who run `terraform plan` locally often have read access to production state "for convenience". That is read access to every secret in it.

HCP Terraform and Terraform Enterprise store state in the platform; access is controlled by workspace permissions, and the AWS-side risk becomes the platform's OIDC trust (`app.terraform.io:sub`, which AWS also enforces for new roles).

### AWS CDK bootstrap

`cdk bootstrap` deploys a CloudFormation stack (`CDKToolkit`) per account and Region containing, by default:

| Resource | Default name | Notes |
|---|---|---|
| Staging bucket | `cdk-hnb659fds-assets-ACCOUNT-REGION` | Holds templates and file assets |
| ECR repository | `cdk-hnb659fds-container-assets-ACCOUNT-REGION` | Container assets |
| Deploy role | `cdk-hnb659fds-deploy-role-ACCOUNT-REGION` | Assumed by the CDK CLI; can pass the execution role, so effectively administrator |
| CloudFormation execution role | `cdk-hnb659fds-cfn-exec-role-ACCOUNT-REGION` | `AdministratorAccess` unless `--cloudformation-execution-policies` says otherwise |
| File and image publishing roles | `cdk-hnb659fds-file-publishing-role-...`, `...-image-publishing-role-...` | Write to the bucket and repository |
| Lookup role | `cdk-hnb659fds-lookup-role-...` | Read-only lookups during synthesis |
| SSM parameter | `/cdk-bootstrap/hnb659fds/version` | Bootstrap template version |

`hnb659fds` is the default **qualifier**, identical in every account that does not change it. The roles trust the account itself plus any accounts given with `--trust` (deploy, publishing) and `--trust-for-lookup`. The AWS documentation itself notes that the deploy role "is effectively an administrator".

Because the bucket name is predictable from the account ID and Region, Aqua Security showed in October 2024 that if a client deletes the staging bucket, an attacker can create a bucket with the same name in their own account; the still-existing publishing role then uploads the victim's templates to the attacker's bucket, where they can be modified before the deploy role and administrator execution role apply them. The fix (CDK v2.149.0, **bootstrap template version 21**) added a condition so the file publishing role only writes to buckets in the same account; it applies only after re-bootstrapping. The general problem of predictable bucket names is covered in the [S3 note](/cloud/aws-s3-security/) (bucket squatting).

### IaC scanning, policy as code and drift

Static analysis of templates and plans catches most of the misconfiguration classes in this series before they reach an account:

| Tool | Scans | Notes |
|---|---|---|
| [Checkov](https://github.com/bridgecrewio/checkov) | Terraform (HCL and plan JSON), CloudFormation, CDK output, Kubernetes, Dockerfiles, GitHub Actions and GitLab CI | Large built-in rule set, custom policies in YAML or Python |
| [Trivy](https://github.com/aquasecurity/trivy) (`trivy config`) | Terraform, CloudFormation, Kubernetes, Dockerfiles | tfsec's checks now live in Trivy; tfsec itself is in maintenance |
| [cfn-nag](https://github.com/stelligent/cfn_nag) | CloudFormation | Focus on IAM wildcards, security groups, encryption |
| [KICS](https://github.com/Checkmarx/kics) | Terraform, CloudFormation, CDK output, Ansible, Kubernetes, and more | Rego-based queries |
| [CloudFormation Guard](https://github.com/aws-cloudformation/cloudformation-guard) | CloudFormation, any JSON/YAML (including Terraform plan JSON) | AWS's policy-as-code DSL; also usable as CloudFormation Hooks |
| [Conftest](https://www.conftest.dev/) / [OPA](https://www.openpolicyagent.org/docs/latest/) | Any structured file, typically Terraform plan JSON | Write your own Rego rules |
| [zizmor](https://github.com/zizmorcore/zizmor), [actionlint](https://github.com/rhysd/actionlint) | GitHub Actions workflows | Template injection, dangerous triggers, excessive permissions, unpinned actions |

Scanners find **configuration** problems in **what is in the repository**. They do not see the trust between the CI platform and AWS, what the deploy role can do, who can read state, or what was changed by hand after deployment. That is why this note's tests are mostly against the account, with the scan as one test among them.

## What goes wrong

**OIDC role trusts too much.** No `sub` check (any GitHub repository), an organisation wildcard, or a repository wildcard that includes pull request and feature-branch workflows. Why it matters: the deploy role, often administrator, is available to people with no AWS access at all.

**Deploy role is administrator and shared by every workflow.** One role for plan and apply, for every repository, for every environment. Why it matters: a compromise of the least protected workflow (a test job, a pull request build) yields production administrator.

**Long-lived IAM user keys in CI secrets.** Why it matters: they leak through logs, compromised actions and runner images, they do not expire, and they usually belong to a user with the same administrator policy.

**CodeBuild builds untrusted code with a privileged role.** Pull request builds from forks or outside contributors with comment approval disabled, unanchored actor filters, or a buildspec taken from the pull request itself. Why it matters: anyone on the internet can run code as the service role and read the source credential.

**CodeBuild plaintext secrets, public builds, broad source tokens.** `PLAINTEXT` variables holding tokens, `PUBLIC_READ` projects whose logs print environment, personal access tokens with admin scopes.

**`StartBuild`, `UpdateProject`, `UpdateStack` given to developers.** Each is code execution as a more privileged role (the build's service role, the stack's service role). Often granted as "developer convenience".

**Artefact store and package registry writable by the wrong principals.** Substituting an artefact between build and deploy, or publishing an internal package name to a repository with an external connection.

**StackSet execution roles with `AdministratorAccess` and broad administrators.** One compromised admin-account principal reaches every account.

**Terraform state readable by developers, or in a weak bucket.** Every secret Terraform ever generated, plus the full resource inventory, plus the ability to influence the next apply if writable.

**CDK bootstrap left at defaults.** Administrator execution role, default qualifier, old bootstrap version, broad `--trust`, staging bucket deleted.

**No IaC scanning and no drift detection.** Problems ship, and hand-made changes (including persistence) go unnoticed.

## Testing

Every test assumes an **authorised engagement** against the client's own AWS accounts and repositories, with written scope that names the CI platforms and repositories in scope, and respects the [AWS penetration testing policy](https://aws.amazon.com/security/penetration-testing/) and the CI platform's own terms. Tests are read-only unless marked **lab or explicitly approved only**. In particular, do **not** open pull requests, push branches, trigger builds or assume CI roles against a client's real repositories to "prove" a trust weakness; prove it by policy evaluation, offline reproduction (for example, testing a filter regex locally) or a lab copy, and, where the client explicitly approves a live proof, use a dedicated test repository and finish with `aws sts get-caller-identity` only. Outputs shown are **illustrative**, not from a real account.

### Before you start

**Permissions.** `SecurityAudit` plus `ViewOnlyAccess` cover the IAM, CodeBuild (`BatchGetProjects`, `ListSourceCredentials`), CodePipeline (`GetPipeline`), CodeArtifact (`Describe*`, `List*`, `GetRepositoryPermissionsPolicy`), CloudFormation (`DescribeStacks`, `GetStackPolicy`, `DescribeStackSet`) and S3 configuration reads used here. Note that `BatchGetProjects` returns `PLAINTEXT` variable values and `DescribeStacks` returns non-`NoEcho` parameters; the client should know the audit role sees them. For the repository side, ask for read access to the infrastructure repositories and CI configuration (workflow files, `.gitlab-ci.yml`, buildspecs, Terraform and CDK code), and for an organisation owner to export CI secret *names* (never values).

**Region loop.**

```bash
export AWS_PROFILE=client-audit
ACCT=$(aws sts get-caller-identity --query Account --output text)
REGIONS=$(aws ec2 describe-regions --query 'Regions[].RegionName' --output text)
for r in $REGIONS; do
  printf '%s codebuild=%s pipelines=%s stacks=%s\n' "$r" \
    "$(aws codebuild list-projects --region "$r" --query 'length(projects)')" \
    "$(aws codepipeline list-pipelines --region "$r" --query 'length(pipelines)')" \
    "$(aws cloudformation list-stacks --region "$r" --query 'length(StackSummaries[?StackStatus!=`DELETE_COMPLETE`])')"
done
```

**Tools.** Prowler (`prowler aws --services codebuild codeartifact codepipeline cloudformation iam`), PMapper (`pmapper graph create`, which includes CodeBuild and CloudFormation escalation edges), CloudFox (`role-trusts`, `codebuild`, `cloudformation`, `permissions`), the IaC scanners above, gitleaks or trufflehog for repository history, and the GitHub CLI (`gh`) for workflow and settings review where you have read access. For practice, [CI/CD Goat](https://github.com/cider-security-research/cicd-goat) and CloudGoat cover poisoned-pipeline scenarios in a lab.

### GT-AWS-CICD-1: OIDC providers and role trust policies

*Guler Tech methodology.*

#### What it checks

Every OIDC identity provider in the account and every role that trusts it: whether the trust policy restricts `aud` and `sub` (or equivalent claims) to the intended repositories, branches or environments, and whether the restriction survives name reuse.

#### Prerequisites

`iam:ListOpenIDConnectProviders`, `iam:GetOpenIDConnectProvider`, `iam:GetAccountAuthorizationDetails`.

#### Steps

1. List providers and their audiences:

   ```bash
   for p in $(aws iam list-open-id-connect-providers --query 'OpenIDConnectProviderList[].Arn' --output text); do
     aws iam get-open-id-connect-provider --open-id-connect-provider-arn "$p" \
       --query '[Url,ClientIDList]' --output json | jq -c --arg p "$p" '{p:$p, url:.[0], aud:.[1]}'
   done
   ```

2. Every role that trusts a web identity provider, with its conditions:

   ```bash
   aws iam get-account-authorization-details --filter Role --output json > roles.json
   jq -r '.RoleDetailList[] | .RoleName as $r | .CreateDate as $d
     | .AssumeRolePolicyDocument.Statement[]
     | select(.Action|tostring|test("AssumeRoleWithWebIdentity"))
     | [$r, $d, (.Principal.Federated|tostring), (.Condition|tostring)] | @tsv' roles.json > oidc-roles.tsv
   ```

3. Classify each role (a short script beats eyeballing):

   ```bash
   jq -r '.RoleDetailList[] | .RoleName as $r
     | .AssumeRolePolicyDocument.Statement[]
     | select(.Principal.Federated? // "" | tostring | test("token.actions.githubusercontent.com|gitlab.com"))
     | (.Condition // {}) as $c
     | ([$c[]? | to_entries[] | select(.key|test(":sub$|:job_workflow_ref$|:repository_id$|:project_id$")) | .value]
        | flatten) as $subs
     | [ $r,
         (if ($subs|length)==0 then "NO-SUB"
          elif ($subs|map(test("^repo:[^/]+/\\*$|^repo:\\*|^\\*$|^project_path:[^/]+/\\*"))|any) then "ORG-OR-ANY-WILDCARD"
          elif ($subs|map(test(":\\*$"))|any) then "REPO-WILDCARD"
          else "SCOPED" end),
         ($subs|join(",")) ] | @tsv' roles.json
   ```

4. Check for issues the classifier misses: `aud` absent or not `sts.amazonaws.com` (or the GitLab audience the client configured); `ForAnyValue:StringLike` on `sub` (any one value matching is enough); a `StringLike` with `?` wildcards; trust in the old and new GitHub `sub` formats at once; conditions on `actor` or `workflow` alone (names, not security boundaries); statements that also trust an AWS principal broadly. Read the raw JSON of every non-`SCOPED` role.

5. For each role, record its **creation date** and the date of its last trust policy update (CloudTrail `UpdateAssumeRolePolicy` if retained). Roles last changed before AWS's June 2025 identity-provider controls may never have been validated.

6. Map the accepted `sub` values back to repository settings (with client read access): is the branch protected, does the environment require reviewers and restrict deployment branches, can pull requests from forks run workflows that request `id-token: write`? Use `gh api repos/ORG/REPO/environments` and `gh api repos/ORG/REPO/branches/main/protection`.

7. **Lab or explicitly approved only.** To demonstrate a `NO-SUB` or `ORG-OR-ANY-WILDCARD` trust live, use a repository the client owns and has designated for testing (never your own organisation against a client role unless the client has explicitly approved that exact proof), run a workflow that assumes the role and executes only `aws sts get-caller-identity`, and stop.

#### Observation

```text
gha-deploy-prod       NO-SUB                 -
gha-terraform-plan    ORG-OR-ANY-WILDCARD    repo:example-org/*
gha-app-deploy        REPO-WILDCARD          repo:example-org/payments-api:*
gitlab-infra          SCOPED                 project_path:example-group/infra:ref_type:branch:ref:main
```

#### Evaluation

**Fail (Critical)** if any role trusting a shared issuer has no `sub` (or `job_workflow_ref`) restriction: any repository on the platform can assume it. **Fail (High)** for organisation-wide wildcards on roles with write or administrative permissions, and for repository-wide wildcards (`:*`) on production deploy roles, because any branch or pull request workflow qualifies. **Fail (Medium)** where trust is scoped to a branch or environment but that branch is unprotected or the environment has no required reviewers, so anyone with write access to the repository can deploy. **Pass** if each role trusts a specific repository and a protected environment or branch (`repo:ORG/REPO:environment:production`), checks `aud`, and, ideally, pins `repository_id` and `repository_owner_id` (or `gitlab.com:project_id`) against name reuse.

#### Automated coverage

No Security Hub CSPM control and no dedicated Prowler check at the time of writing; AWS's identity-provider controls prevent new misconfigurations but do not flag old ones. CloudFox `role-trusts` lists web identity trusts. Checkov and other IaC scanners have rules for GitHub OIDC trust in Terraform; run them in GT-AWS-CICD-10.

#### Detection

CloudTrail `AssumeRoleWithWebIdentity` (eventSource `sts.amazonaws.com`): the event identifies the identity provider and the token's subject in `userIdentity` and `requestParameters`; check a sample event in the client's trail and build an alert for subjects outside an allow-list of repositories. Also alert on `CreateOpenIDConnectProvider`, `UpdateOpenIDConnectProviderThumbprint`, `AddClientIDToOpenIDConnectProvider` and `UpdateAssumeRolePolicy` for CI roles (ATT&CK T1199, T1078.004).

### GT-AWS-CICD-2: CI/CD role privilege and blast radius

*Guler Tech methodology.*

#### What it checks

What each CI/CD principal can do: administrator policies, `iam:PassRole` on `*`, IAM write, the ability to change its own trust or permissions, cross-account reach, and whether plan and apply, or environments, share a role.

#### Prerequisites

`roles.json` (full `get-account-authorization-details`, not only roles), PMapper graph, the list of CI principals from GT-AWS-CICD-1, CodeBuild service roles (GT-AWS-CICD-4), CodePipeline roles (GT-AWS-CICD-6), CloudFormation and StackSet roles (GT-AWS-CICD-7) and CDK roles (GT-AWS-CICD-9).

#### Steps

1. Build the list of CI/CD principals and their attached policies:

   ```bash
   aws iam get-account-authorization-details --output json > gaad.json
   jq -r '.RoleDetailList[]
     | select(.RoleName|test("deploy|ci|cd|pipeline|build|github|gitlab|terraform|cdk-|StackSet|jenkins|atlantis"; "i"))
     | [.RoleName, ([.AttachedManagedPolicies[].PolicyName]|join(",")),
        ([.RolePolicyList[]?.PolicyName]|join(",")), (.PermissionsBoundary.PermissionsBoundaryArn // "-")] | @tsv' gaad.json
   ```

2. Ask PMapper which of them are administrators or can become one:

   ```bash
   pmapper --profile client-audit graph create
   pmapper --profile client-audit query 'preset privesc *' | grep -iE 'deploy|ci|pipeline|build|github|gitlab|terraform|cdk'
   pmapper --profile client-audit query 'who can do iam:PassRole with *'
   ```

3. For each role, test the specific risky actions:

   ```bash
   aws iam simulate-principal-policy --policy-source-arn arn:aws:iam::111122223333:role/gha-deploy-prod \
     --action-names iam:CreateRole iam:AttachRolePolicy iam:PutRolePolicy iam:UpdateAssumeRolePolicy \
       iam:PassRole iam:CreateAccessKey organizations:LeaveOrganization cloudtrail:StopLogging \
     --query 'EvaluationResults[].[EvalActionName,EvalDecision]' --output text
   ```

4. Cross-account: list roles in other accounts that trust this account's CI roles (from the target accounts' `get-account-authorization-details`, or CloudFox `role-trusts` in each), and whether a non-production pipeline can reach production.

5. Separation: does the plan job (which runs on every pull request) use the same role as apply? Does every repository share one role? Are environments separated by account?

#### Observation

```text
gha-deploy-prod     AdministratorAccess          -         -
gha-terraform-plan  ReadOnlyAccess               -         -
codebuild-app-role  -                            inline:all  -      (iam:PassRole on *, lambda:*, s3:*)
```

#### Evaluation

**Fail (High)** if a role reachable by untrusted or broadly available triggers (pull request workflows, any branch, any repository in the organisation) has administrator or administrator-equivalent permissions (`iam:*`, `iam:PassRole` on `*` with a compute service, `iam:PutRolePolicy` on itself). **Fail (Medium)** if production deploy roles are administrator without a permissions boundary or SCP limiting the obvious abuses (disabling logging, leaving the organisation, creating IAM users and keys), or if one role serves plan and apply or several environments. **Pass** if apply roles are scoped by environment (ideally separate accounts), plan roles are read-only and denied `kms:Decrypt` and secret reads where possible, and administrator-level deploy roles are fenced by a permissions boundary and SCPs and reachable only from protected branches or environments.

#### Automated coverage

Security Hub CSPM IAM.1 (no full `*:*` policies; CIS v1.2.0 1.22, v1.4.0 1.16). Prowler `iam_role_administratoraccess_policy`, `iam_policy_allows_privilege_escalation`, `iam_inline_policy_allows_privilege_escalation`. cloudsplaining for privilege escalation and resource exposure categories.

#### Detection

Activity from CI roles outside their normal pattern: IAM write calls (`CreateUser`, `CreateAccessKey`, `AttachRolePolicy`, `UpdateAssumeRolePolicy`) from deploy roles outside pipeline runs, source IPs or user agents that are not the CI platform's, calls from CI roles in unusual Regions. GuardDuty IAM anomaly findings and Extended Threat Detection attack sequences cover parts of this; see the [detection services note](/cloud/aws-detection-posture-services/).

### GT-AWS-CICD-3: Long-lived AWS keys used by CI

*Guler Tech methodology.*

#### What it checks

IAM users with access keys used by CI/CD systems, their age, last use and privileges, and evidence of AWS keys stored in repositories or CI configuration.

#### Prerequisites

`iam:GenerateCredentialReport`, `iam:GetCredentialReport`, `iam:ListAccessKeys`, `iam:GetAccessKeyLastUsed`; read access to infrastructure repositories; an export of CI secret names from the client.

#### Steps

1. Users with active keys and how they are used:

   ```bash
   aws iam generate-credential-report >/dev/null; sleep 5
   aws iam get-credential-report --query Content --output text | base64 -d > cred.csv
   awk -F, 'NR==1 || $9=="true" || $14=="true" {print $1","$4","$9","$10","$11","$12","$13","$14","$15","$16}' cred.csv | column -s, -t
   for u in $(awk -F, 'NR>1 && ($9=="true"||$14=="true"){print $1}' cred.csv); do
     for k in $(aws iam list-access-keys --user-name "$u" --query 'AccessKeyMetadata[?Status==`Active`].AccessKeyId' --output text); do
       aws iam get-access-key-last-used --access-key-id "$k" \
         --query '[UserName,AccessKeyLastUsed.LastUsedDate,AccessKeyLastUsed.ServiceName,AccessKeyLastUsed.Region]' --output text
     done
   done
   ```

   Users with no console password, an old key, and last use by `cloudformation`, `s3`, `ecr`, `lambda` or `sts` from a CI platform's address ranges are usually CI users.

2. With the client, map CI secret names to IAM users: `gh secret list --org ORG` and `gh secret list --repo ORG/REPO` list names only; GitLab exposes variable keys to maintainers in project and group settings. Names such as `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_KEY_PROD` indicate long-lived keys.

3. Scan repository history for committed keys (the client's own repositories, with approval):

   ```bash
   gitleaks git --report-path gitleaks-infra.json ./infra-repo
   trufflehog git file://./infra-repo --no-verification --json > trufflehog-infra.json
   ```

   Do not verify found keys against AWS unless the client approves; if they do, use `aws sts get-caller-identity` only, then report and have the client rotate. Keys belonging to anyone other than the client are out of scope: stop and report.

4. For each CI user, list its policies (GT-AWS-CICD-2 logic) and whether the platform it serves supports OIDC.

#### Observation

```text
svc-github-deploy  2022-03-01  true  2022-03-01  2026-11-12  eu-west-2  cloudformation   (AdministratorAccess)
svc-jenkins        2019-07-15  true  2019-07-15  2026-11-11  eu-west-2  s3
```

#### Evaluation

**Fail (High)** for administrator-equivalent IAM user keys used by a CI platform that supports OIDC; **Critical** if the key is found in repository history or logs. **Fail (Medium)** for scoped CI keys older than the client's rotation standard. **Pass** if CI uses federation, and any remaining keys (for platforms without OIDC) are scoped, rotated automatically and restricted by `aws:SourceIp` or `aws:SourceVpc` conditions where the platform allows.

#### Automated coverage

Security Hub CSPM IAM.3 (keys rotated every 90 days; CIS v1.2.0 1.4, v1.4.0 1.14, v3.0.0 1.14, v5.0.0 1.13), IAM.22 (credentials unused for 45 days; CIS v1.4.0 1.12, v3.0.0 1.12, v5.0.0 1.11), IAM.8 (CIS v1.2.0 1.3). Prowler `iam_rotate_access_key_90_days`, `iam_user_accesskey_unused`, `iam_user_no_setup_initial_access_key`. GitHub secret scanning and push protection on the client's repositories.

#### Detection

Use of a CI user's key from addresses outside the CI platform, `CreateAccessKey` on CI users, and GuardDuty findings for credential use from unusual infrastructure. AWS also detects AWS keys published in public GitHub repositories and quarantines them by attaching the `AWSCompromisedKeyQuarantine` family of managed policies; check for those attachments as evidence of past leaks.

### GT-AWS-CICD-4: CodeBuild project review

*Guler Tech methodology.*

#### What it checks

For every CodeBuild project: service role privilege, environment variable types, privileged mode, buildspec source, project visibility, source credentials, logging and VPC placement, and who can start or change the project.

#### Prerequisites

`codebuild:ListProjects`, `codebuild:BatchGetProjects`, `codebuild:ListSourceCredentials`; IAM read.

#### Steps

1. Project summary per Region:

   ```bash
   for r in $REGIONS; do
     p=$(aws codebuild list-projects --region "$r" --query 'projects[]' --output text); [ -z "$p" ] && continue
     aws codebuild batch-get-projects --region "$r" --names $p --output json | jq -r --arg r "$r" '.projects[] | [
       $r, .name, .serviceRole,
       (.environment.privilegedMode // false),
       ([.environment.environmentVariables[]? | select(.type=="PLAINTEXT") | .name] | join(",")),
       (.source.type), (.source.location // "-"),
       (if (.source.buildspec // "") == "" then "repo:buildspec.yml"
        elif (.source.buildspec|test("^version:")) then "inline" else .source.buildspec end),
       (.projectVisibility // "PRIVATE"),
       (.logsConfig.cloudWatchLogs.status // "-"), (.vpcConfig.vpcId // "no-vpc"),
       (if .webhook then "webhook" else "-" end) ] | @tsv'
   done > codebuild.tsv
   ```

2. Source credentials (account-level tokens and connections):

   ```bash
   for r in $REGIONS; do
     aws codebuild list-source-credentials --region "$r" \
       --query 'sourceCredentialsInfos[].[serverType,authType,resource || `-`]' --output text | sed "s/^/$r\t/"
   done
   ```

   For `PERSONAL_ACCESS_TOKEN` or `BASIC_AUTH`, ask the client which account issued it and with which scopes. A classic GitHub token with `repo` and `admin:repo_hook` gives builds (and anyone who controls a build) write and webhook administration over every repository that account can reach.

3. Who can run code as each service role: principals with `codebuild:StartBuild`, `codebuild:StartBuildBatch`, `codebuild:UpdateProject` or `codebuild:CreateProject` plus `iam:PassRole` on the role:

   ```bash
   pmapper --profile client-audit query 'who can do codebuild:StartBuild with arn:aws:codebuild:eu-west-2:111122223333:project/infra-deploy'
   ```

   `StartBuild` accepts `--buildspec-override` and `--environment-variables-override`, so this is code execution as the service role.

4. Public projects: for `PUBLIC_READ`, check what the logs contain (with approval, read one recent public log as an anonymous user via the public build URL shown in the console) and whether `resourceAccessRole` exposes artefacts.

5. Service role privilege (GT-AWS-CICD-2 logic) for every role in column 3.

#### Observation

```text
eu-west-2  infra-deploy  arn:aws:iam::111122223333:role/codebuild-infra  true   NPM_TOKEN,SLACK_WEBHOOK  GITHUB  https://github.com/example-org/infra  repo:buildspec.yml  PRIVATE      ENABLED  no-vpc  webhook
eu-west-2  oss-sdk-ci    arn:aws:iam::111122223333:role/codebuild-oss    true   -                        GITHUB  https://github.com/example-org/sdk    repo:buildspec.yml  PUBLIC_READ  ENABLED  no-vpc  webhook
```

#### Evaluation

**Fail** for `PLAINTEXT` variables holding secrets (Critical if they are AWS keys, which Security Hub CodeBuild.2 reports). **Fail** for credentials embedded in source URLs (CodeBuild.1). **Fail** if a public project's logs or artefacts expose secrets or internal details, or a public project's service role has more than it needs. **Fail** if principals other than the pipeline and build administrators can `StartBuild` or `UpdateProject` on projects whose service role is more privileged than they are. **Fail** if account-level source credentials are personal tokens with broad scopes. Privileged mode on its own is **not** a finding; record it, and raise it only together with untrusted triggers (GT-AWS-CICD-5). **Pass** if each project has a scoped service role, secrets come from Secrets Manager or Parameter Store references, source access uses a CodeConnections connection or a fine-grained token for a dedicated machine account, logs are on, and only the pipeline can start or change privileged projects.

#### Automated coverage

Security Hub CSPM CodeBuild.1 (Bitbucket source URLs without credentials), CodeBuild.2 (no clear-text AWS credentials in variables), CodeBuild.3 (S3 logs encrypted), CodeBuild.4 (logging configured), CodeBuild.7 (report group exports encrypted). Prowler `codebuild_project_no_secrets_in_variables`, `codebuild_project_source_repo_url_no_sensitive_credentials`, `codebuild_project_not_publicly_accessible`, `codebuild_project_logging_enabled`, `codebuild_project_s3_logs_encrypted`, `codebuild_project_user_controlled_buildspec`, `codebuild_project_older_90_days`. PMapper models CodeBuild escalation edges. CloudFox `codebuild`.

#### Detection

CloudTrail `UpdateProject`, `CreateProject`, `StartBuild` / `StartBuildBatch` with `buildspecOverride` or `environmentVariablesOverride` in `requestParameters`, `UpdateProjectVisibility`, `ImportSourceCredentials`, `DeleteSourceCredentials`, `BatchGetProjects` by unusual principals (reading plaintext variables). In build logs, unexpected outbound network calls or credential endpoint access patterns.

### GT-AWS-CICD-5: CodeBuild webhooks and untrusted pull request builds

*Guler Tech methodology.*

#### What it checks

Whether a project can be triggered by people outside the trusted team: pull request events from forks or arbitrary accounts, unanchored or weak filter patterns, comment approval disabled, and the combination of an untrusted trigger with a privileged role or source credential.

#### Prerequisites

`BatchGetProjects` output; knowledge of whether each source repository is public; read access to the repository's settings if possible.

#### Steps

1. Dump webhook configuration:

   ```bash
   aws codebuild batch-get-projects --names $(aws codebuild list-projects --query 'projects[]' --output text) \
     --query 'projects[?webhook].{n:name,src:source.location,fg:webhook.filterGroups,prp:webhook.pullRequestBuildPolicy,bt:webhook.buildType}' \
     --output json > webhooks.json
   jq -c '.[] | {n, src, prp, events: [.fg[]?[]? | select(.type=="EVENT") | .pattern],
                 actor: [.fg[]?[]? | select(.type=="ACTOR_ACCOUNT_ID") | .pattern],
                 head: [.fg[]?[]? | select(.type=="HEAD_REF") | .pattern],
                 base: [.fg[]?[]? | select(.type=="BASE_REF") | .pattern]}' webhooks.json
   ```

2. For each project that builds on `PULL_REQUEST_CREATED`, `PULL_REQUEST_UPDATED` or `PULL_REQUEST_REOPENED`:
   - Is the repository public, or can outside collaborators open pull requests?
   - `pullRequestBuildPolicy.requiresCommentApproval`: `DISABLED` or absent means pull requests build without approval; `FORK_PULL_REQUESTS` still builds non-fork pull requests from anyone with push rights; check `approverRoles` does not include `GITHUB_READ` or `GITHUB_TRIAGE` (or the GitLab and Bitbucket equivalents).
   - Is every `ACTOR_ACCOUNT_ID`, `HEAD_REF` and `BASE_REF` pattern anchored with `^...$`, with alternations grouped, for example `^(123456|234567)$`?
   - `FILE_PATH` and `COMMIT_MESSAGE` filters are attacker-controlled content and never a security boundary.
   - Where is the buildspec taken from? If from the repository, the pull request supplies it.

3. Demonstrate an unanchored pattern offline (no interaction with the client's repository). RE2 and Python agree for these simple patterns:

   ```bash
   python3 - <<'EOF'
   import re
   pattern = "123456|234567"          # as configured, unanchored
   for candidate in ["123456", "91234567", "2345678", "777777"]:
       print(candidate, bool(re.search(pattern, candidate)))
   anchored = "^(123456|234567)$"
   print("anchored:", [c for c in ["123456", "91234567"] if re.search(anchored, c)])
   EOF
   ```

   ```text
   123456 True
   91234567 True
   2345678 True
   777777 False
   anchored: ['123456']
   ```

   GitHub user and app IDs are sequential, so IDs that contain a trusted shorter ID as a substring are created regularly; Wiz's CodeBreach write-up describes how an attacker can time account creation to obtain one.

4. Combine with GT-AWS-CICD-4: what would an untrusted build get? The service role's permissions, the source credential (readable from the build environment), plaintext variables, and any VPC network reach.

5. **Lab or explicitly approved only.** A live proof uses a dedicated test repository and project configured like the client's, or, with explicit approval, a pull request to a designated test repository whose buildspec runs only `aws sts get-caller-identity`. Never attempt to read the source credential from a client build.

#### Observation

```json
{"n":"oss-sdk-ci","src":"https://github.com/example-org/sdk","prp":null,"events":["PULL_REQUEST_CREATED, PULL_REQUEST_UPDATED"],"actor":["123456|234567|345678"],"head":[],"base":["refs/heads/main"]}
```

#### Evaluation

**Fail (Critical)** if a public repository's pull requests (from forks or any account) trigger builds without comment approval, through missing or bypassable (unanchored) actor filters, on a project whose service role or source credential gives write access to code, artefacts or AWS resources. **Fail (High)** for the same with a low-privilege role but a source token with write or admin scope. **Fail (Medium)** for unanchored patterns where the repository is private (exploitation needs a collaborator account). **Pass** if pull request builds require comment approval from maintainers, filters are anchored, untrusted builds run in a separate project with no secrets and a minimal role, and privileged builds trigger only on pushes to protected branches.

#### Automated coverage

Prowler `codebuild_project_webhook_filters_use_anchored_patterns`, `codebuild_project_uses_allowed_github_organizations`, `codebuild_project_user_controlled_buildspec`. No Security Hub CSPM control at the time of writing.

#### Detection

CloudTrail `UpdateWebhook` and `CreateWebhook` (changes to filters or `pullRequestBuildPolicy`), builds whose `initiator` is a webhook from an unexpected actor (CodeBuild records the source version and initiator per build: `aws codebuild batch-get-builds --ids ...`), and builds that fail with "Pull request approval required" (attempts by untrusted contributors).

### GT-AWS-CICD-6: CodePipeline artefact stores and CodeArtifact origins

*Guler Tech methodology.*

#### What it checks

Who can read and write each pipeline's artefact bucket and key, which roles each stage uses, and whether CodeArtifact repositories with public upstreams protect internal package names.

#### Prerequisites

`codepipeline:ListPipelines`, `codepipeline:GetPipeline`, S3 bucket policy and KMS key policy reads, `codeartifact:List*`, `codeartifact:Describe*`, `codeartifact:GetRepositoryPermissionsPolicy`, `codeartifact:GetDomainPermissionsPolicy`.

#### Steps

1. Pipelines, roles and artefact stores:

   ```bash
   for p in $(aws codepipeline list-pipelines --query 'pipelines[].name' --output text); do
     aws codepipeline get-pipeline --name "$p" --output json | jq -c '{
       name: .pipeline.name, type: .pipeline.pipelineType, role: .pipeline.roleArn,
       store: (.pipeline.artifactStore // .pipeline.artifactStores),
       actionRoles: [.pipeline.stages[].actions[] | select(.roleArn) | {a: .name, r: .roleArn}],
       sources: [.pipeline.stages[0].actions[] | {p: .actionTypeId.provider, c: .configuration}] }'
   done
   ```

2. For each artefact bucket: bucket policy, Block Public Access, and **who can `s3:PutObject`** besides the pipeline role and build roles (simulate developer and CI roles). For each artefact key: whether it is `aws/s3` (no second gate, no cross-account) or a customer managed key, and its policy (as in [the KMS note](/cloud/aws-secrets-manager-parameter-store-kms/)).

3. CodeArtifact repositories and their upstreams:

   ```bash
   aws codeartifact list-repositories --query 'repositories[].[domainName,name]' --output text |
   while read -r d r; do
     aws codeartifact describe-repository --domain "$d" --repository "$r" \
       --query 'repository.[name,upstreams[].repositoryName,externalConnections[].externalConnectionName]' --output json | jq -c .
   done
   ```

4. For repositories that have, or are upstream-chained to, an external connection: list internal packages and their origin controls. Internal packages should be `publish=ALLOW, upstream=BLOCK`:

   ```bash
   aws codeartifact list-packages --domain example-domain --repository internal-npm --format npm \
     --query 'packages[].[namespace || `-`,package,originConfiguration.restrictions.publish,originConfiguration.restrictions.upstream]' \
     --output text | awk '$3=="ALLOW" && $4=="ALLOW"'
   aws codeartifact list-package-groups --domain example-domain --query 'packageGroups[].[pattern,originConfiguration.restrictions]' --output json
   ```

   Ask the client for their list of internal package names and scopes (from manifests) and check that each is either present with `upstream=BLOCK` or covered by a package group that blocks upstream for the internal scope. Names that appear in manifests but not in the repository are unprotected.

5. Repository and domain policies: who can `codeartifact:PublishPackageVersion` and `PutPackageOriginConfiguration`.

#### Observation

```text
@example/auth-client   ALLOW  ALLOW     (created 2021; pre-origin-controls default)
internal-utils (pypi)  missing from repository; referenced in requirements.txt; no package group
```

#### Evaluation

**Fail (High)** if roles outside the pipeline can write artefacts that a later stage deploys, or if internal package names can be resolved from a public upstream (`ALLOW`/`ALLOW`, or absent with no blocking package group) in a repository used by builds with deploy privileges. **Fail (Medium)** for artefact buckets readable by broad roles (source and secrets exposure) or using `aws/s3` where cross-account separation is intended. **Pass** if artefact stores are writable only by pipeline and build roles, encrypted with a scoped customer managed key, and internal namespaces are protected by package groups with upstream blocked.

#### Automated coverage

Prowler `codeartifact_packages_external_public_publishing_disabled`, `codepipeline_project_repo_private`, plus the S3 checks on the artefact bucket. Security Hub CSPM S3 controls apply to the artefact bucket (S3.1, S3.5, S3.8).

#### Detection

S3 data events for `PutObject` on artefact buckets by principals other than the pipeline and build roles (requires data event logging; Security Hub S3.22 checks object-level write logging). CodeArtifact `PublishPackageVersion`, `PutPackageOriginConfiguration`, `UpdatePackageGroupOriginConfiguration`, `AssociateExternalConnection`. CodePipeline `UpdatePipeline`, `CreatePipeline`, and `PutActionRevision` / manual approvals by unusual principals.

### GT-AWS-CICD-7: CloudFormation service roles, stack policies and StackSets

*Guler Tech methodology.*

#### What it checks

Which stacks use a service role, how privileged it is, who can update those stacks (and so act as the role), stack policies and termination protection on critical stacks, and the trust and privilege of StackSet administration and execution roles.

#### Prerequisites

`cloudformation:DescribeStacks`, `GetStackPolicy`, `ListStackSets`, `DescribeStackSet`; IAM read in the admin and target accounts.

#### Steps

1. Stacks with service roles and protections:

   ```bash
   for r in $REGIONS; do
     aws cloudformation describe-stacks --region "$r" --output json | jq -r --arg r "$r" '.Stacks[] |
       [$r, .StackName, (.RoleARN // "caller-permissions"), (.EnableTerminationProtection // false),
        ([.Parameters[]? | select(.ParameterValue != "****" and (.ParameterKey|test("pass|secret|token|key";"i"))) | .ParameterKey] | join(","))] | @tsv'
   done > stacks.tsv
   ```

   The last column lists parameters with secret-like names that are *not* masked (no `NoEcho`).

2. For each distinct `RoleARN`, check its permissions (GT-AWS-CICD-2). Then find who can act as it, because AWS does not require `iam:PassRole` for later updates:

   ```bash
   aws iam simulate-principal-policy --policy-source-arn arn:aws:iam::111122223333:role/developer \
     --action-names cloudformation:UpdateStack cloudformation:CreateChangeSet cloudformation:ExecuteChangeSet \
     --resource-arns 'arn:aws:cloudformation:eu-west-2:111122223333:stack/network-core/*' \
     --query 'EvaluationResults[].[EvalActionName,EvalDecision]' --output text
   ```

3. Stack policies on critical stacks (network, IAM, data stores):

   ```bash
   aws cloudformation get-stack-policy --stack-name network-core --query StackPolicyBody --output text
   ```

4. StackSets (in the admin account or delegated administrator):

   ```bash
   aws cloudformation list-stack-sets --status ACTIVE --query 'Summaries[].[StackSetName,PermissionModel]' --output text
   aws cloudformation describe-stack-set --stack-set-name baseline \
     --query 'StackSet.[PermissionModel,AdministrationRoleARN,ExecutionRoleName,AutoDeployment]'
   aws cloudformation list-stack-sets --call-as DELEGATED_ADMIN --status ACTIVE 2>/dev/null
   ```

   For self-managed StackSets, in a sample of target accounts read the execution role's trust policy and attached policies:

   ```bash
   aws iam get-role --role-name AWSCloudFormationStackSetExecutionRole --query 'Role.AssumeRolePolicyDocument'
   aws iam list-attached-role-policies --role-name AWSCloudFormationStackSetExecutionRole
   ```

   Then list who in the admin account can `CreateStackSet`, `UpdateStackSet`, `CreateStackInstances` and pass the administration role.

5. Secrets in templates and outputs: covered by GT-AWS-SEC-10 in [the secrets note](/cloud/aws-secrets-manager-parameter-store-kms/); cross-reference its results here.

#### Observation

```text
eu-west-2  network-core   arn:aws:iam::111122223333:role/cfn-admin   false  -
eu-west-2  shop-db        caller-permissions                        false  DBPassword
StackSet baseline  SELF_MANAGED  arn:aws:iam::111122223333:role/AWSCloudFormationStackSetAdministrationRole  AWSCloudFormationStackSetExecutionRole
  target 444455556666: execution role trusts arn:aws:iam::111122223333:root, AdministratorAccess
```

#### Evaluation

**Fail (High)** if principals that are not administrators can update stacks whose service role is administrator-equivalent (a privilege escalation path, PMapper's CloudFormation edges show it). **Fail (High)** if a self-managed StackSet execution role with `AdministratorAccess` trusts the admin account's `:root` and the admin account has more StackSet administrators than the organisation's administrators (or trusts the whole account rather than the administration role). **Fail (Medium)** for critical stacks without termination protection or stack policies, and for unmasked secret parameters (rate as GT-AWS-SEC-10). **Pass** if service roles are scoped per stack purpose, stack update rights match role privilege, critical stacks are protected, and StackSet execution roles trust only the administration role ARN (with `aws:PrincipalArn` or a specific principal) and carry only the permissions the StackSets need.

#### Automated coverage

Security Hub CSPM CloudFormation.3 (termination protection), CloudFormation.4 (service roles associated; note it also fails for service-managed StackSet instances by design). Prowler `cloudformation_stacks_termination_protection_enabled`, `cloudformation_stack_outputs_find_secrets`. PMapper `cloudformation_edges`. Pacu `cfn__resource_injection` demonstrates template injection in a lab; do not run it against a client.

#### Detection

`UpdateStack`, `CreateChangeSet`, `ExecuteChangeSet` and `DeleteStack` by principals that are not the pipeline; `SetStackPolicy`, `UpdateTerminationProtection`; `CreateStackSet`, `UpdateStackSet`, `CreateStackInstances` from unexpected principals; `AssumeRole` of StackSet execution roles outside StackSet operations.

### GT-AWS-CICD-8: Terraform state bucket review

*Guler Tech methodology.*

#### What it checks

Where Terraform state lives, who can read and write it, how the bucket and key are protected, and how locking is done.

#### Prerequisites

Read access to infrastructure repositories (backend configuration); S3 configuration reads; IAM read; KMS key policy reads.

#### Steps

1. Find state locations from code and from the account:

   ```bash
   grep -RInE 'backend +"s3"' -A12 --include='*.tf' ./infra-repo | grep -E 'bucket|key|region|kms_key_id|use_lockfile|dynamodb_table|encrypt|role_arn'
   aws s3api list-buckets --query 'Buckets[?contains(Name, `tfstate`) || contains(Name, `terraform`) || contains(Name, `state`)].Name' --output text
   ```

2. Bucket configuration:

   ```bash
   B=example-org-tfstate-prod
   aws s3api get-public-access-block --bucket "$B"
   aws s3api get-bucket-policy --bucket "$B" --query Policy --output text | jq .
   aws s3api get-bucket-versioning --bucket "$B"
   aws s3api get-bucket-encryption --bucket "$B"
   aws s3api get-bucket-ownership-controls --bucket "$B"
   aws s3api get-bucket-logging --bucket "$B"
   aws s3api get-object-lock-configuration --bucket "$B" 2>/dev/null
   ```

3. Object metadata only (approved read-only listing): state keys, their sizes and encryption. Do not download state unless the client explicitly approves it:

   ```bash
   aws s3api list-objects-v2 --bucket "$B" --query 'Contents[].[Key,Size,LastModified]' --output text | head -50
   aws s3api head-object --bucket "$B" --key env/prod/terraform.tfstate --query '[ServerSideEncryption,SSEKMSKeyId]'
   ```

4. Who can read and write state: simulate developer, CI plan, CI apply and support roles for `s3:GetObject`, `s3:PutObject` on the state key and `kms:Decrypt` on the bucket's key; include roles in other accounts allowed by the bucket policy.

   ```bash
   aws iam simulate-principal-policy --policy-source-arn arn:aws:iam::111122223333:role/developer \
     --action-names s3:GetObject s3:PutObject \
     --resource-arns "arn:aws:s3:::$B/env/prod/terraform.tfstate" \
     --resource-policy "$(aws s3api get-bucket-policy --bucket "$B" --query Policy --output text)" \
     --query 'EvaluationResults[].[EvalActionName,EvalDecision]' --output text
   ```

5. Locking: `use_lockfile = true` (S3 native) or a DynamoDB table; for DynamoDB, who can write the table (deleting a lock during an apply corrupts state).

6. **Explicitly approved only:** if the client wants evidence of what the state exposes, they download it themselves (or approve you doing so into the engagement's encrypted store) and you scan it offline without printing values:

   ```bash
   jq -r '[paths(scalars) as $p | {path: ($p|map(tostring)|join(".")), v: getpath($p)}
           | select(.path|test("password|secret|private_key|token|access_key";"i")) | .path] | .[]' terraform.tfstate | sort -u
   ```

   Report attribute paths, not values.

#### Observation

```text
bucket example-org-tfstate-prod: BPA all true; versioning Enabled; SSE-S3 (AES256); no bucket policy; logging disabled
developer: s3:GetObject allowed (via PowerUserAccess), s3:PutObject allowed
state contains: resources.aws_db_instance.main.instances.0.attributes.password, resources.aws_iam_access_key.ci.instances.0.attributes.secret
```

#### Evaluation

**Fail (High)** if principals beyond the CI apply role and a break-glass role can read production state that contains secrets (credential access), or can write it (deployment tampering). **Critical** if the state bucket is public or readable from outside the organisation. **Fail (Medium)** for state buckets without versioning (no recovery), with SSE-S3 only where the client needs a second gate, or without access logging or data events. **Pass** if state lives in a dedicated, locked-down bucket (ideally a separate account), encrypted with a customer managed key whose policy limits decryption to the apply role and break-glass, versioned, logged, with a TLS-only policy, and secrets are kept out of state where possible (ephemeral values, write-only arguments, or generating secrets in Secrets Manager rather than Terraform).

#### Automated coverage

Security Hub CSPM S3.1 and S3.8 (Block Public Access; CIS v1.4.0 2.1.5, v3.0.0 2.1.4 for S3.1, v5.0.0 2.1.4 for both), S3.5 (TLS; CIS v1.4.0 2.1.2, v3.0.0 2.1.1, v5.0.0 2.1.1), S3.14 (versioning), S3.9 (server access logging), S3.17 (SSE-KMS), S3.23 (object-level read events logged). Prowler S3 checks (`s3_bucket_public_access`, `s3_bucket_object_versioning`, `s3_bucket_kms_encryption`, `s3_bucket_secure_transport_policy`, `s3_bucket_server_access_logging_enabled`). Depth on bucket review is in the [S3 note](/cloud/aws-s3-security/).

#### Detection

S3 data events `GetObject` and `PutObject` on `*.tfstate` keys by principals other than CI (ATT&CK T1530, T1552.001), `DeleteObject` on `.tflock` objects, `PutBucketPolicy` and `DeleteBucketEncryption` on the state bucket, `Decrypt` on the state key by unexpected principals.

### GT-AWS-CICD-9: CDK bootstrap review

*Guler Tech methodology.*

#### What it checks

The bootstrap version, qualifier, trusted accounts, execution policies and staging bucket ownership in every bootstrapped account and Region.

#### Prerequisites

`cloudformation:DescribeStacks`, `ssm:GetParameter` on the bootstrap version parameter (non-secret), IAM and S3 reads.

#### Steps

1. Find bootstrap stacks and their parameters:

   ```bash
   for r in $REGIONS; do
     aws cloudformation describe-stacks --region "$r" --stack-name CDKToolkit --output json 2>/dev/null | jq -r --arg r "$r" '
       .Stacks[0] | [$r,
         (.Outputs[]? | select(.OutputKey=="BootstrapVersion") | .OutputValue),
         (.Parameters[]? | select(.ParameterKey=="Qualifier") | .ParameterValue),
         (.Parameters[]? | select(.ParameterKey=="TrustedAccounts") | .ParameterValue),
         (.Parameters[]? | select(.ParameterKey=="TrustedAccountsForLookup") | .ParameterValue),
         (.Parameters[]? | select(.ParameterKey=="CloudFormationExecutionPolicies") | .ParameterValue),
         (.EnableTerminationProtection // false)] | @tsv'
   done
   ```

   Custom bootstraps may use another stack name (`--toolkit-stack-name`); search for stacks whose template includes `CdkBootstrapVersion` if `CDKToolkit` is absent.

2. Confirm the staging bucket exists and belongs to the account (a missing bucket with surviving roles is the Aqua scenario):

   ```bash
   Q=hnb659fds   # or the client's qualifier
   aws s3api head-bucket --bucket "cdk-$Q-assets-$ACCT-eu-west-2" --expected-bucket-owner "$ACCT" \
     && echo "owned by $ACCT" || echo "MISSING OR NOT OWNED"
   ```

3. Bootstrap roles: trust and permissions.

   ```bash
   for role in deploy-role file-publishing-role image-publishing-role lookup-role cfn-exec-role; do
     n="cdk-$Q-$role-$ACCT-eu-west-2"
     echo "== $n"
     aws iam get-role --role-name "$n" --query 'Role.AssumeRolePolicyDocument.Statement[].Principal' --output json
     aws iam list-attached-role-policies --role-name "$n" --query 'AttachedPolicies[].PolicyName' --output text
   done
   aws iam get-role-policy --role-name "cdk-$Q-file-publishing-role-$ACCT-eu-west-2" \
     --policy-name "$(aws iam list-role-policies --role-name "cdk-$Q-file-publishing-role-$ACCT-eu-west-2" --query 'PolicyNames[0]' --output text)" \
     --query 'PolicyDocument' | jq '.Statement[] | {a: .Action, c: .Condition}'
   ```

   On bootstrap version 21 and later the file publishing role's S3 statements carry a condition limiting them to buckets in the account.

4. Who can assume the deploy role (any principal in each trusted account whose IAM allows `sts:AssumeRole` on it), and which accounts are in `TrustedAccounts`. A CI account trusted by every production account is the real administrator of all of them.

#### Observation

```text
eu-west-2  19  hnb659fds  111122223333,444455556666  -  arn:aws:iam::aws:policy/AdministratorAccess  false
cdk-hnb659fds-assets-123456789012-eu-west-2: MISSING OR NOT OWNED
```

#### Evaluation

**Fail (Critical)** if the staging bucket is missing while bootstrap roles remain on a template older than version 21 (the deployment path can be redirected to an attacker's bucket). **Fail (High)** for bootstrap versions below 21 in active accounts, and for `TrustedAccounts` that include accounts outside the client's control or broadly accessible CI accounts. **Fail (Medium)** for the default `AdministratorAccess` execution policy where a scoped policy or permissions boundary is feasible, and for no termination protection on the bootstrap stack. **Pass** if bootstrap is current, uses a custom qualifier (or at least a current template), execution policies are scoped or bounded, trust is limited to the pipeline account, and the bootstrap stack is termination-protected.

#### Automated coverage

Prowler `cloudformation_stack_cdktoolkit_bootstrap_version` (default minimum 21). Security Hub CSPM CloudFormation.3 for termination protection on the bootstrap stack. Prowler `s3_bucket_shadow_resource_vulnerability` looks for predictable service bucket names (Glue, SageMaker and similar) owned by another account; check whether your Prowler version includes the CDK naming pattern, and run step 2 regardless.

#### Detection

`AssumeRole` on `cdk-*-deploy-role-*` and `cdk-*-cfn-exec-role-*` from principals or accounts outside the pipeline; `DeleteBucket` on the staging bucket; `UpdateStack` on `CDKToolkit`; `PutObject` from the file publishing role to buckets in other accounts (visible in the caller's CloudTrail as S3 data events if enabled).

### GT-AWS-CICD-10: IaC and workflow scan of the client repository

*Guler Tech methodology.*

#### What it checks

The client's infrastructure code and CI configuration, statically: misconfigurations before deployment, dangerous CI workflow patterns, secrets in code, and whether policy-as-code gates exist and block merges.

#### Prerequisites

Read access to the repositories; scanners installed locally (scan on your machine, not in the client's CI, unless agreed).

#### Steps

1. Infrastructure code:

   ```bash
   checkov -d ./infra-repo --compact --quiet -o cli -o sarif --output-file-path ./out
   trivy config --severity HIGH,CRITICAL ./infra-repo
   cfn_nag_scan --input-path ./infra-repo/cloudformation
   docker run --rm -v "$PWD/infra-repo":/src checkmarx/kics:latest scan -p /src -o /src/kics-out
   ```

   For CDK, scan the synthesised templates: `npx cdk synth --quiet && checkov -d cdk.out --framework cloudformation`. For Terraform with modules and variables, scan the plan as well as the code, because many problems only exist after variables are applied: `terraform plan -out tf.plan && terraform show -json tf.plan > tf.json && checkov -f tf.json --framework terraform_plan` (the client runs the plan; it needs state access).

2. CI workflows:

   ```bash
   zizmor ./app-repo/.github/workflows
   actionlint ./app-repo/.github/workflows/*.yml
   grep -RnE 'pull_request_target|workflow_run|id-token: *write|aws-access-key-id|AWS_SECRET_ACCESS_KEY' ./app-repo/.github/workflows
   ```

   Look for `pull_request_target` or `workflow_run` workflows that check out the pull request's code and run it with secrets or `id-token: write`, untrusted input (issue titles, branch names, pull request bodies) expanded directly into `run:` scripts, actions pinned to tags rather than commit SHAs, and jobs that request `id-token: write` without needing it. Workflow-level attacks ("pwn requests", expression injection) are a topic of their own, with public write-ups collected in our [bug bounty reading list](/bug-bounty-writeups/); here the point is whether those jobs can reach AWS roles.

3. Secrets in code and history: gitleaks and trufflehog as in GT-AWS-CICD-3, plus `checkov --framework secrets`.

4. Policy-as-code gates: is any of this enforced in CI before merge (required status checks), and are exceptions (`#checkov:skip`, `#tfsec:ignore`, `trivy:ignore`, `cfn_nag` `rules_to_suppress`) reviewed? Count suppressions:

   ```bash
   grep -RnoE 'checkov:skip=[A-Z0-9_]+|tfsec:ignore:[a-z0-9-]+|trivy:ignore:[A-Z0-9-]+|rules_to_suppress' ./infra-repo | sort | uniq -c | sort -rn | head
   ```

5. Triage: map scanner findings to the tests in this series (public buckets, wildcard IAM, OIDC trust, CodeBuild variables, `NoEcho`, missing `BlockPublicPolicy`, unrotated keys) and confirm in the account before reporting.

#### Observation

```text
checkov: <rule-id> IAM role trust for GitHub OIDC without sub restriction   FAILED  modules/ci/oidc.tf:12
trivy:   <rule-id> (HIGH) IAM policy document uses wildcarded action 'iam:*'  modules/ci/deploy.tf:40
zizmor: dangerous-triggers  .github/workflows/preview.yml  pull_request_target with checkout of PR head
suppressions: 37 x checkov:skip=CKV_AWS_18 (S3 access logging)
```

Scanner rule IDs change between versions; quote the IDs your run produced, not the ones above.

#### Evaluation

**Fail** per confirmed misconfiguration, rated by the corresponding account-side finding. **Fail (High)** for workflows that run untrusted code with `id-token: write` or AWS secrets available. **Fail (Medium)** if no IaC scanning gate exists for infrastructure repositories, or suppressions are unreviewed and cover security-relevant rules. **Pass** if scans run on every pull request as required checks, findings above an agreed severity block merge, suppressions carry a justification and owner, and workflows follow least privilege.

#### Automated coverage

This test *is* the automated coverage for code. Security Hub CSPM and Prowler see only deployed resources.

#### Detection

Not applicable in AWS. In the source platform: audit logs for changes to branch protection, required checks and workflow files; GitHub's and GitLab's own audit streams.

### GT-AWS-CICD-11: Drift detection

*Guler Tech methodology.*

#### What it checks

Whether deployed resources match their IaC definitions, whether drift is detected routinely, and whether drift on security-relevant resources (IAM, security groups, bucket policies, KMS policies, trails) is investigated.

#### Prerequisites

`cloudformation:DetectStackDrift`, `DescribeStackDriftDetectionStatus`, `DescribeStackResourceDrifts` (detection starts an analysis but changes no resources; confirm the client is comfortable with that); for Terraform, the client runs a refresh-only plan.

#### Steps

1. CloudFormation drift on critical stacks:

   ```bash
   id=$(aws cloudformation detect-stack-drift --stack-name network-core --query StackDriftDetectionId --output text)
   sleep 20
   aws cloudformation describe-stack-drift-detection-status --stack-drift-detection-id "$id" \
     --query '[StackDriftStatus,DriftedStackResourceCount]'
   aws cloudformation describe-stack-resource-drifts --stack-name network-core \
     --stack-resource-drift-status-filters MODIFIED DELETED \
     --query 'StackResourceDrifts[].[LogicalResourceId,ResourceType,StackResourceDriftStatus]' --output text
   ```

2. Terraform (client-run): `terraform plan -refresh-only -detailed-exitcode` per workspace; exit code 2 means drift. Ask for the resource list, not the full plan output (which can contain secrets).

3. Resources outside IaC entirely: compare IAM roles, users, policies and security groups in the account with those in state or templates. Unmanaged IAM principals created recently are worth a question; persistence often looks like "a role somebody made by hand".

   ```bash
   aws iam list-roles --query 'Roles[?CreateDate>=`2026-08-01`].[RoleName,CreateDate]' --output text
   ```

4. Is drift detection scheduled (AWS Config's `cloudformation-stack-drift-detection-check` rule, a scheduled pipeline job running `plan -refresh-only`), and who receives the result?

#### Observation

```text
network-core  DRIFTED  2
SgWebIngress  AWS::EC2::SecurityGroup  MODIFIED
FlowLogsRole  AWS::IAM::Role           MODIFIED
```

#### Evaluation

**Fail (Medium)** if security-relevant resources have drifted without a recorded change, or no drift detection runs at all on production. **Fail (High)** if drift includes IAM trust or permission changes, logging changes or new principals that nobody can explain; stop, treat it as a potential incident and hand it to the client's incident process before continuing. **Pass** if drift detection runs on a schedule, alerts reach owners, and drifted resources are reconciled.

#### Automated coverage

AWS Config managed rule `cloudformation-stack-drift-detection-check`. No Security Hub CSPM control. Prowler does not check drift.

#### Detection

Drift is itself a detection signal. Pair it with CloudTrail: changes to IaC-managed resources by principals other than the pipeline roles (`PutRolePolicy`, `AuthorizeSecurityGroupIngress`, `PutBucketPolicy` by humans) are the events that create drift.

## Hardening

**OIDC trust for GitHub Actions.** One role per repository and environment, trusting a protected environment, pinned to immutable IDs:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "GitHubDeployProd",
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::111122223333:oidc-provider/token.actions.githubusercontent.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
          "token.actions.githubusercontent.com:sub": "repo:example-org/payments-infra:environment:production",
          "token.actions.githubusercontent.com:repository_id": "7654321",
          "token.actions.githubusercontent.com:repository_owner_id": "1234567"
        }
      }
    }
  ]
}
```

For repositories using GitHub's immutable subject format, the `sub` becomes `repo:example-org@1234567/payments-infra@7654321:environment:production`; check which format the repository emits before switching. Protect the `production` environment with required reviewers and restrict it to the default branch. Give the plan job a separate read-only role that trusts `repo:example-org/payments-infra:pull_request` and nothing else.

The workflow side: request the token only in the job that needs it, pin actions to commit SHAs, and use the environment. GitHub expressions use double braces, so the block is wrapped for the site generator:

{% raw %}
```yaml
name: deploy
on:
  push:
    branches: [main]
permissions:
  contents: read
jobs:
  deploy:
    runs-on: ubuntu-latest
    environment: production
    permissions:
      contents: read
      id-token: write
    steps:
      - uses: actions/checkout@<FULL_COMMIT_SHA>
      - uses: aws-actions/configure-aws-credentials@<FULL_COMMIT_SHA>
        with:
          role-to-assume: arn:aws:iam::111122223333:role/gha-payments-infra-prod
          role-session-name: gha-${{ github.run_id }}
          aws-region: eu-west-2
      - run: aws sts get-caller-identity
```
{% endraw %}

**OIDC trust for GitLab SaaS.**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": { "Federated": "arn:aws:iam::111122223333:oidc-provider/gitlab.com" },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "gitlab.com:aud": "https://gitlab.com",
          "gitlab.com:sub": "project_path:example-group/infra:ref_type:branch:ref:main",
          "gitlab.com:project_id": "67890",
          "gitlab.com:ref_protected": "true"
        }
      }
    }
  ]
}
```

Use whatever `aud` the job requests in `id_tokens` and the provider lists; it must match exactly.

**Terraform for the role, avoiding duplicate keys.** Build conditions with `aws_iam_policy_document`, which merges values per test and variable instead of silently overwriting a map key:

```hcl
data "aws_iam_policy_document" "gha_trust" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]
    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github.arn]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:example-org/payments-infra:environment:production"]
    }
  }
}

resource "aws_iam_role" "gha_prod" {
  name                 = "gha-payments-infra-prod"
  assume_role_policy   = data.aws_iam_policy_document.gha_trust.json
  permissions_boundary = aws_iam_policy.deploy_boundary.arn
}
```

**Fence administrator-level deploy roles.** A permissions boundary or SCP denying the actions a deploy pipeline never needs:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DeployRoleNeverDoes",
      "Effect": "Deny",
      "Action": [
        "iam:CreateUser", "iam:CreateAccessKey", "iam:CreateLoginProfile",
        "iam:UpdateAssumeRolePolicy", "iam:DeleteRolePermissionsBoundary",
        "cloudtrail:StopLogging", "cloudtrail:DeleteTrail", "cloudtrail:PutEventSelectors",
        "guardduty:DeleteDetector", "organizations:LeaveOrganization",
        "kms:ScheduleKeyDeletion"
      ],
      "Resource": "*"
    }
  ]
}
```

Add `iam:PassRole` restrictions (`iam:PassedToService` and role path) so the deploy role can only pass roles under a workload path.

**CodeBuild.** Comment approval for all pull requests, anchored filters, secrets by reference, no pull request builds on privileged projects:

```yaml
InfraBuild:
  Type: AWS::CodeBuild::Project
  Properties:
    Name: infra-deploy
    ServiceRole: !GetAtt InfraBuildRole.Arn
    Source:
      Type: GITHUB
      Location: https://github.com/example-org/infra.git
      BuildSpec: buildspec/deploy.yml
    Environment:
      Type: LINUX_CONTAINER
      ComputeType: BUILD_GENERAL1_SMALL
      Image: aws/codebuild/standard:7.0
      EnvironmentVariables:
        - Name: NPM_TOKEN
          Type: SECRETS_MANAGER
          Value: ci/npm-token
    LogsConfig:
      CloudWatchLogs:
        Status: ENABLED
    Triggers:
      Webhook: true
      FilterGroups:
        - - Type: EVENT
            Pattern: PUSH
          - Type: HEAD_REF
            Pattern: ^refs/heads/main$
      PullRequestBuildPolicy:
        RequiresCommentApproval: ALL_PULL_REQUESTS
        ApproverRoles:
          - GITHUB_ADMIN
          - GITHUB_MAINTAIN
```

If actor filters are needed, anchor and group them: `^(123456|234567)$`. Use a CodeConnections connection or a fine-grained token for a dedicated machine account with access to only the repositories the project builds. SCP guardrails can enforce some of this with CodeBuild condition keys (for example `codebuild:projectVisibility` and `codebuild:source.buildspec` on `CreateProject` / `UpdateProject`); test them in a lab, since they apply to API parameters, not to existing projects.

**CloudFormation.** Scope service roles per stack purpose; restrict `UpdateStack` / `ExecuteChangeSet` on stacks with powerful roles to the pipeline; enable termination protection and stack policies on network, IAM and data stacks; use dynamic references for secrets. For self-managed StackSets, make the execution role trust only the administration role:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": { "AWS": "arn:aws:iam::111122223333:role/AWSCloudFormationStackSetAdministrationRole" },
      "Action": "sts:AssumeRole"
    }
  ]
}
```

**Terraform state.** A dedicated bucket, ideally in a separate account, with a policy that denies everyone except the apply role and break-glass:

```hcl
terraform {
  backend "s3" {
    bucket       = "example-org-tfstate-prod"
    key          = "payments/terraform.tfstate"
    region       = "eu-west-2"
    encrypt      = true
    kms_key_id   = "arn:aws:kms:eu-west-2:111122223333:key/EXAMPLE-KEY-ID"
    use_lockfile = true
  }
}
```

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyNonTLS",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": ["arn:aws:s3:::example-org-tfstate-prod", "arn:aws:s3:::example-org-tfstate-prod/*"],
      "Condition": { "Bool": { "aws:SecureTransport": "false" } }
    },
    {
      "Sid": "OnlyApplyAndBreakGlass",
      "Effect": "Deny",
      "Principal": "*",
      "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject"],
      "Resource": "arn:aws:s3:::example-org-tfstate-prod/*",
      "Condition": {
        "ArnNotLike": {
          "aws:PrincipalArn": [
            "arn:aws:iam::111122223333:role/gha-payments-infra-prod",
            "arn:aws:iam::111122223333:role/tfstate-break-glass"
          ]
        }
      }
    }
  ]
}
```

Enable versioning, Block Public Access, access logging or data events, and keep secrets out of state where providers allow: ephemeral variables (Terraform 1.10+), write-only arguments (1.11+), or let services generate and hold secrets (`manage_master_user_password` for RDS) instead of Terraform.

**CDK.** Upgrade the CDK CLI and re-bootstrap every environment to the current template (version 21 or later), use a custom qualifier, scope the execution role with `--cloudformation-execution-policies` or a permissions boundary (`--custom-permissions-boundary`), limit `--trust` to the pipeline account, enable `--termination-protection`, and never delete the staging bucket while the roles exist.

**CodeArtifact.** Create package groups for internal scopes with upstream blocked:

```bash
aws codeartifact create-package-group --domain example-domain --package-group '/npm/example/*'
aws codeartifact update-package-group-origin-configuration --domain example-domain \
  --package-group '/npm/example/*' --restrictions PUBLISH=ALLOW,EXTERNAL_UPSTREAM=BLOCK,INTERNAL_UPSTREAM=ALLOW
```

The per-package equivalent is `put-package-origin-configuration --restrictions publish=ALLOW,upstream=BLOCK`.

**Policy as code.** Make the checks in this note merge-blocking. A Conftest rule over a Terraform plan that rejects GitHub OIDC trust without a `sub` condition:

```text
# policy/oidc.rego
package main

import rego.v1

deny contains msg if {
  rc := input.resource_changes[_]
  rc.type == "aws_iam_role"
  doc := json.unmarshal(rc.change.after.assume_role_policy)
  st := doc.Statement[_]
  contains(sprintf("%v", [st.Principal.Federated]), "token.actions.githubusercontent.com")
  not has_sub(st)
  msg := sprintf("%s trusts GitHub OIDC without a sub condition", [rc.address])
}

has_sub(st) if {
  some op, k
  st.Condition[op][k]
  endswith(k, ":sub")
}
```

```bash
terraform show -json tf.plan > tf.json
conftest test tf.json --policy policy/
```

A CloudFormation Guard rule for CodeBuild webhooks:

```text
let codebuild_projects = Resources.*[ Type == 'AWS::CodeBuild::Project' ]

rule codebuild_pr_builds_need_approval when %codebuild_projects !empty {
  %codebuild_projects.Properties.Triggers.PullRequestBuildPolicy.RequiresCommentApproval != 'DISABLED'
  <<Pull request builds must require comment approval>>
}
```

**Drift.** Schedule CloudFormation drift detection (Config rule) and `terraform plan -refresh-only` for production, and alert on IAM, network and logging drift.

## Real-world cases

- **CodeBreach (Wiz Research, disclosed January 2026).** Four AWS-owned GitHub repositories built pull requests in CodeBuild with `ACTOR_ACCOUNT_ID` allow-lists written as unanchored regular expressions. The researchers obtained a GitHub account whose numeric ID contained a maintainer's ID, opened a pull request to `aws/aws-sdk-js-v3`, and recovered the build's GitHub token, which had admin rights over the repository. AWS anchored the filters within about 48 hours of the August 2025 report, revoked the token, added protection against reading project credentials from non-privileged builds, and recommends pull request comment approval. [Wiz: CodeBreach](https://www.wiz.io/blog/wiz-research-codebreach-vulnerability-aws-codebuild).
- **CDK staging bucket takeover (Aqua Security, October 2024).** Predictable bootstrap bucket names allowed an attacker to claim a deleted staging bucket and have the victim's deployments upload templates to it, leading to an administrator role in the victim account. Fixed in CDK v2.149.0 (bootstrap version 21) for re-bootstrapped environments. [Aqua: AWS CDK risk, exploiting a missing S3 bucket allowed account takeover](https://www.aquasec.com/blog/aws-cdk-risk-exploiting-a-missing-s3-bucket-allowed-account-takeover/).
- **GitHub-to-AWS OIDC roles without `sub` (Datadog Security Labs, 2023, updated 2025).** Research that found roles assumable from any GitHub repository in the wild, including a UK government role where a duplicated `StringEquals` key in Terraform dropped the subject check. AWS later blocked creating such trust policies. [Datadog: No keys attached, exploring GitHub-to-AWS keyless authentication flaws](https://securitylabs.datadoghq.com/articles/exploring-github-to-aws-keyless-authentication-flaws/).
- **SCARLETEEL (Sysdig, 2023).** Terraform state files in S3 provided credentials that the actor used to move into further AWS accounts. [Sysdig: SCARLETEEL](https://sysdig.com/blog/cloud-breach-terraform-data-theft/).
- **tj-actions/changed-files (March 2025, CVE-2025-30066).** A compromised, widely used GitHub Action printed CI secrets into workflow logs, exposing long-lived cloud keys stored as repository secrets in public repositories. [GitHub advisory GHSA-mrrh-fwg8-r2c3](https://github.com/advisories/GHSA-mrrh-fwg8-r2c3), [Wiz analysis](https://www.wiz.io/blog/github-action-tj-actions-changed-files-supply-chain-attack-cve-2025-30066).

More in [AWS security incidents and writeups](/cloud/aws-security-incidents-and-writeups/).

## Rating findings

| Finding | Typical severity | Reasoning |
|---|---|---|
| OIDC role trusting GitHub/GitLab with no `sub` restriction, with write/admin permissions | Critical | Unauthenticated internet path: anyone with a free account on the platform assumes the role |
| Public repository pull requests build without approval (or with unanchored filters) on a privileged CodeBuild project | Critical | Internet-reachable code execution as the service role; source token often gives repository admin |
| CDK staging bucket missing with pre-v21 bootstrap roles | Critical | Attacker-controlled template applied by an administrator execution role |
| Terraform state or artefact bucket public or readable from outside the organisation | Critical | Credential and source disclosure without authentication |
| Organisation-wide or repository-wide OIDC wildcards on production deploy roles | High | Any organisation member or any branch/pull request workflow deploys to production |
| Administrator IAM user keys in CI secrets | High (Critical if leaked) | Non-expiring admin credential in a system with many readers and frequent supply-chain incidents |
| Developers can `StartBuild`/`UpdateProject`/`UpdateStack` against more privileged roles | High | Privilege escalation inside the account via the pipeline's identity |
| Terraform state readable or writable by broad internal roles | High | Read is credential access to every generated secret; write influences deployments |
| Self-managed StackSet execution role with `AdministratorAccess` trusting a broadly administered account | High | One account's administrators become administrators of every target account |
| Internal package names resolvable from public upstreams | High–Medium | Dependency confusion reaches build environments with deploy credentials; Medium when builds are unprivileged |
| Plaintext secrets in CodeBuild variables or public build logs | Medium–Critical | Rate by credential; AWS keys readable by many are Critical |
| Deploy role administrator without boundary/SCP, but reachable only from protected environments | Medium | Large blast radius, controlled entry |
| No IaC scanning gate, unreviewed suppressions | Medium | Missing preventive control, no demonstrated exposure on its own |
| No drift detection | Medium (High if unexplained IAM drift found) | Out-of-band changes and persistence go unnoticed |
| CDK bootstrap below current version but bucket present | Medium | Known-fixed weakness latent until the bucket is deleted |
| Privileged mode enabled on its own | Info | AWS considers it no additional risk; relevant only combined with untrusted triggers |
| Termination protection missing on non-critical stacks | Low | Availability hygiene |

## Mapping

| Test | Security Hub CSPM | CIS AWS Foundations | ATT&CK |
|---|---|---|---|
| GT-AWS-CICD-1 | (none) | — | T1199, T1078.004 |
| GT-AWS-CICD-2 | IAM.1 | IAM.1: v1.2.0 1.22; v1.4.0 1.16 | T1078.004, T1098.003 |
| GT-AWS-CICD-3 | IAM.3, IAM.8, IAM.22 | IAM.3: v1.2.0 1.4; v1.4.0 1.14; v3.0.0 1.14; v5.0.0 1.13. IAM.22: v1.4.0 1.12; v3.0.0 1.12; v5.0.0 1.11 | T1552.001, T1078.004 |
| GT-AWS-CICD-4 | CodeBuild.1, CodeBuild.2, CodeBuild.3, CodeBuild.4, CodeBuild.7 | — | T1677, T1552.001, T1528 |
| GT-AWS-CICD-5 | (none) | — | T1677, T1195.002, T1528 |
| GT-AWS-CICD-6 | S3.1, S3.5, S3.8 (artefact bucket) | S3.5: v1.4.0 2.1.2; v3.0.0 2.1.1; v5.0.0 2.1.1 | T1195.001, T1195.002, T1530 |
| GT-AWS-CICD-7 | CloudFormation.3, CloudFormation.4 | — | T1098.003, T1078.004 |
| GT-AWS-CICD-8 | S3.1, S3.5, S3.8, S3.9, S3.14, S3.17, S3.23 | S3.1: v1.4.0 2.1.5; v3.0.0 2.1.4; v5.0.0 2.1.4 | T1530, T1552.001 |
| GT-AWS-CICD-9 | CloudFormation.3 | — | T1195.002, T1098.003 |
| GT-AWS-CICD-10 | (code, not resources) | — | T1677, T1552.001 |
| GT-AWS-CICD-11 | (none) | — | T1098.003 |

## References

- AWS IAM: [Create a role for OIDC federation, GitHub section](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_create_for-idp_oidc.html), [Identity-provider controls for shared OIDC providers](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_oidc_secure-by-default.html), [Available keys for OIDC federation](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_iam-condition-keys.html)
- GitHub: [Configuring OIDC in AWS](https://docs.github.com/en/actions/how-tos/secure-your-work/security-harden-deployments/oidc-in-aws), [OIDC token claims reference](https://docs.github.com/en/actions/reference/security/oidc), [Changelog: immutable subject claims (April 2026)](https://github.blog/changelog/2026-04-23-immutable-subject-claims-for-github-actions-oidc-tokens)
- GitLab: [Configure OIDC in AWS](https://docs.gitlab.com/ci/cloud_services/aws/)
- AWS CodeBuild: [GitHub webhook events and filters](https://docs.aws.amazon.com/codebuild/latest/userguide/github-webhook.html), [Pull request comment approval](https://docs.aws.amazon.com/codebuild/latest/userguide/pull-request-build-policy.html), [Public builds](https://docs.aws.amazon.com/codebuild/latest/userguide/public-builds.html), [CodeBuild-hosted GitHub Actions runners](https://docs.aws.amazon.com/codebuild/latest/userguide/action-runner.html)
- AWS CodePipeline: [Artefact encryption](https://docs.aws.amazon.com/codepipeline/latest/userguide/S3-artifact-encryption.html). AWS CodeArtifact: [Package origin controls](https://docs.aws.amazon.com/codeartifact/latest/ug/package-origin-controls.html), [Dependency substitution attacks](https://docs.aws.amazon.com/codeartifact/latest/ug/dependency-substitution-attacks.html)
- AWS CloudFormation: [Service role](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-iam-servicerole.html), [Stack policies](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/protect-stack-resources.html), [Dynamic references](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/dynamic-references.html), [Drift detection](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-cfn-stack-drift.html), [StackSets self-managed permissions](https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/stacksets-prereqs-self-managed.html)
- AWS CDK: [Bootstrapping your environment, including template version history](https://docs.aws.amazon.com/cdk/v2/guide/bootstrapping-env.html)
- Terraform: [S3 backend](https://developer.hashicorp.com/terraform/language/backend/s3), [Managing sensitive data, ephemeral values and write-only arguments](https://developer.hashicorp.com/terraform/language/manage-sensitive-data)
- Security Hub CSPM control references: [CodeBuild](https://docs.aws.amazon.com/securityhub/latest/userguide/codebuild-controls.html), [CloudFormation](https://docs.aws.amazon.com/securityhub/latest/userguide/cloudformation-controls.html), [IAM](https://docs.aws.amazon.com/securityhub/latest/userguide/iam-controls.html), [S3](https://docs.aws.amazon.com/securityhub/latest/userguide/s3-controls.html), [Change log (retired controls, including CodeBuild.5)](https://docs.aws.amazon.com/securityhub/latest/userguide/controls-change-log.html), [CIS AWS Foundations Benchmark](https://docs.aws.amazon.com/securityhub/latest/userguide/cis-aws-foundations-benchmark.html). Security Hub CSPM is the original Security Hub, renamed in 2025 when the new Security Hub launched; control IDs are unchanged.
- MITRE ATT&CK: [T1677 Poisoned Pipeline Execution](https://attack.mitre.org/techniques/T1677/), [T1195.002 Compromise Software Supply Chain](https://attack.mitre.org/techniques/T1195/002/), [T1195.001 Compromise Software Dependencies and Development Tools](https://attack.mitre.org/techniques/T1195/001/), [T1199 Trusted Relationship](https://attack.mitre.org/techniques/T1199/), [T1078.004 Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/), [T1552.001 Credentials In Files](https://attack.mitre.org/techniques/T1552/001/), [T1528 Steal Application Access Token](https://attack.mitre.org/techniques/T1528/), [T1530 Data from Cloud Storage](https://attack.mitre.org/techniques/T1530/), [T1098.003 Additional Cloud Roles](https://attack.mitre.org/techniques/T1098/003/)
- Tools: [Checkov](https://github.com/bridgecrewio/checkov), [Trivy](https://github.com/aquasecurity/trivy), [tfsec](https://github.com/aquasecurity/tfsec), [cfn-nag](https://github.com/stelligent/cfn_nag), [KICS](https://github.com/Checkmarx/kics), [CloudFormation Guard](https://github.com/aws-cloudformation/cloudformation-guard), [Conftest](https://github.com/open-policy-agent/conftest), [zizmor](https://github.com/zizmorcore/zizmor), [actionlint](https://github.com/rhysd/actionlint), [Prowler](https://github.com/prowler-cloud/prowler), [PMapper](https://github.com/nccgroup/PMapper), [CloudFox](https://github.com/BishopFox/cloudfox), [Pacu](https://github.com/RhinoSecurityLabs/pacu), [gitleaks](https://github.com/gitleaks/gitleaks), [trufflehog](https://github.com/trufflesecurity/trufflehog)
- Labs: [CI/CD Goat](https://github.com/cider-security-research/cicd-goat), [CloudGoat](https://github.com/RhinoSecurityLabs/cloudgoat), [IAM Vulnerable](https://github.com/BishopFox/iam-vulnerable)
- Related notes: [STS, cross-account trust and federation](/cloud/aws-sts-cross-account-trust-federation/), [IAM privilege escalation](/cloud/aws-iam-privilege-escalation/), [S3 (including bucket squatting)](/cloud/aws-s3-security/), [Secrets Manager, Parameter Store and KMS](/cloud/aws-secrets-manager-parameter-store-kms/), [Organizations](/cloud/aws-organizations-multi-account-security/), [CloudTrail](/cloud/aws-cloudtrail-logging/), [detection services](/cloud/aws-detection-posture-services/)
