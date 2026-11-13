---
title: "AWS Container Security: ECS, EKS and ECR"
date: 2026-11-12 18:09:00 +0000
subcategory: aws
summary: "Testing ECR, ECS and EKS: registry exposure, secrets in images, task and pod credentials, metadata reachability, cluster access and rating findings."
refs: [ECR.1, ECR.2, ECR.3, ECR.5, ECS.2, ECS.3, ECS.4, ECS.5, ECS.8, ECS.9, ECS.17, ECS.20, EKS.1, EKS.2, EKS.8, EKS.9, EC2.8, EC2.170, "CIS AWS v5.0.0 5.7", T1525, T1552.001, T1552.005, T1609, T1610, T1611, T1613, T1098.006, T1078.004, T1528]
tags: [aws, containers, ecr, ecs, eks, kubernetes]
---

This note is part of our [AWS security testing guide](/cloud/aws-security-testing-guide/) and covers the three AWS container services as one attack surface: **Amazon ECR** (where images live), **Amazon ECS** (AWS's own orchestrator, on EC2 or Fargate) and **Amazon EKS** (managed Kubernetes). They belong together because the interesting bugs sit at the joins. An image pushed by anyone who can reach a repository runs with a production task role. A secret that is "in Secrets Manager" is injected as an environment variable and also lives on in a task definition revision from 2021. A pod with an SSRF reaches the node's instance metadata and leaves with the node role. An IAM principal with two EKS permissions makes itself cluster admin without touching Kubernetes. We focus on those AWS integration points (identities, credential delivery, registry policies, endpoint exposure, logging) and keep generic Kubernetes hardening proportionate: kube-bench, RBAC and Pod Security Standards get a test, not a treatise. Below: how each service's security model works, what goes wrong, twelve tests with commands, hardening snippets, real cases, and how to rate what you find.

## Contents

- [How it works](#how-it-works)
  - [Amazon ECR](#amazon-ecr)
  - [Amazon ECS](#amazon-ecs)
  - [Amazon EKS](#amazon-eks)
- [What goes wrong](#what-goes-wrong)
- [Testing](#testing)
  - [Before you start](#before-you-start)
  - [GT-AWS-CNT-1: ECR repository and registry policies](#gt-aws-cnt-1-ecr-repository-and-registry-policies)
  - [GT-AWS-CNT-2: ECR scanning, tag immutability, lifecycle and pull-through cache](#gt-aws-cnt-2-ecr-scanning-tag-immutability-lifecycle-and-pull-through-cache)
  - [GT-AWS-CNT-3: Secrets baked into image layers](#gt-aws-cnt-3-secrets-baked-into-image-layers)
  - [GT-AWS-CNT-4: ECS secrets in task definitions](#gt-aws-cnt-4-ecs-secrets-in-task-definitions)
  - [GT-AWS-CNT-5: ECS task role and task execution role](#gt-aws-cnt-5-ecs-task-role-and-task-execution-role)
  - [GT-AWS-CNT-6: ECS container and network hardening](#gt-aws-cnt-6-ecs-container-and-network-hardening)
  - [GT-AWS-CNT-7: ECS Exec permissions and logging](#gt-aws-cnt-7-ecs-exec-permissions-and-logging)
  - [GT-AWS-CNT-8: EKS endpoint exposure, control-plane logging and encryption](#gt-aws-cnt-8-eks-endpoint-exposure-control-plane-logging-and-encryption)
  - [GT-AWS-CNT-9: EKS authentication with access entries and aws-auth](#gt-aws-cnt-9-eks-authentication-with-access-entries-and-aws-auth)
  - [GT-AWS-CNT-10: IRSA trust policies and Pod Identity associations](#gt-aws-cnt-10-irsa-trust-policies-and-pod-identity-associations)
  - [GT-AWS-CNT-11: Workload access to IMDS and credential endpoints](#gt-aws-cnt-11-workload-access-to-imds-and-credential-endpoints)
  - [GT-AWS-CNT-12: In-cluster posture with kube-bench, RBAC, PSS and GuardDuty](#gt-aws-cnt-12-in-cluster-posture-with-kube-bench-rbac-pss-and-guardduty)
- [Hardening](#hardening)
- [Real-world cases](#real-world-cases)
- [Rating findings](#rating-findings)
- [Mapping](#mapping)
- [References](#references)

## How it works

### Amazon ECR

**Private registries and repositories.** Every account has one private registry per Region (`111122223333.dkr.ecr.eu-west-2.amazonaws.com`) holding repositories. Access is IAM: a principal needs `ecr:GetAuthorizationToken` (account-level, issues a 12-hour Docker login token) plus repository actions such as `ecr:BatchGetImage` and `ecr:GetDownloadUrlForLayer` to pull, or `ecr:InitiateLayerUpload`, `ecr:UploadLayerPart`, `ecr:CompleteLayerUpload` and `ecr:PutImage` to push. Those actions can be granted by identity policies in the same account or by a **repository policy** (a resource policy on the repository), which is how cross-account access works. There is also a **registry policy** (`PutRegistryPolicy`) that governs registry-level operations such as replication and pull-through cache.

The important property: the Docker login token is not tied to a registry. A principal in *any* account can call `GetAuthorizationToken` in its own account and use the token against your registry; your repository policy then decides. So a repository policy with `"Principal": "*"` does not mean "anonymous HTTP", it means "any AWS principal in any account", which is a very low bar. Genuinely anonymous pulls are what **ECR Public** (`public.ecr.aws`, API prefix `ecr-public`, managed from `us-east-1`) is for. Private and public are separate services with separate policies, and both are in scope.

**Encryption.** Image layers are stored in S3 that ECR manages. By default ECR uses SSE-S3 (AES-256); you can choose KMS (`aws/ecr` AWS managed key or a customer managed key) at creation only. The encryption setting of an existing repository cannot be changed.

**Scanning.** Two modes, configured at registry level (`PutRegistryScanningConfiguration`) with repository filters:

- **Basic scanning**: OS package CVEs, on push or manual. The current docs describe it as AWS-native technology (it previously used the open-source Clair project). Results come from `DescribeImageScanFindings`.
- **Enhanced scanning**: Amazon Inspector scans OS *and* language packages, on push and **continuously** as new CVEs appear, and emits EventBridge events. Results live in Inspector.

Neither mode looks for secrets in layers; that is your job (GT-AWS-CNT-3).

**Tags, lifecycle, cache.** Tags are mutable by default; `IMMUTABLE` (and the newer `IMMUTABLE_WITH_EXCLUSION` / `MUTABLE_WITH_EXCLUSION` variants with wildcard filters) make `PutImage` fail with `ImageTagAlreadyExistsException` for an existing tag. Lifecycle policies expire old images. **Pull-through cache** rules map a prefix in your registry to an upstream registry (ECR Public, the Kubernetes registry, Quay, Docker Hub, GitHub, GitLab, Azure CR, Chainguard, another ECR); the first pull of `111122223333.dkr.ecr.<region>.amazonaws.com/<prefix>/<image>` creates a repository and caches the upstream image, refreshing at most every 24 hours. Upstream credentials sit in a Secrets Manager secret whose name must start with `ecr-pullthroughcache/`. Repositories created this way get default settings (mutable tags, AES256, no policy, no lifecycle) unless a **repository creation template** matches the prefix.

### Amazon ECS

**Two roles per task, and they are different things.**

| Role | Used by | Typical permissions | Exposed to the container? |
|---|---|---|---|
| **Task execution role** (`executionRoleArn`) | The ECS/Fargate agent, before and around your container | Pull from ECR, write to CloudWatch Logs, fetch `secrets` from Secrets Manager / SSM, pull private registry credentials | No |
| **Task role** (`taskRoleArn`) | Your application code | Whatever the app calls: S3, DynamoDB, SQS... plus `ssmmessages:*` if ECS Exec is enabled | **Yes**, via the credential endpoint |

The task role is delivered through the **container credential provider**: when a task has a task role, ECS sets `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` in its containers, the SDK appends it to `http://169.254.170.2` and gets temporary credentials. The relative URI contains a per-task identifier that is not practical to guess, so a blind SSRF to `169.254.170.2` alone does not return credentials; an SSRF *plus* any way to read the environment (`/proc/self/environ`, a debug endpoint, an error page, a log line) does. The same link-local address serves the **task metadata endpoint**: v4 at the per-container URI in `ECS_CONTAINER_METADATA_URI_V4`, and the older v2 at the fixed path `http://169.254.170.2/v2/metadata` for Fargate and `awsvpc` tasks. Metadata (cluster, task ARN, image, VPC, subnet, IPs) contains no credentials, which makes `v2/metadata` an ideal benign SSRF proof.

The trust policy of a task role trusts `ecs-tasks.amazonaws.com`. AWS recommends `aws:SourceAccount` and `aws:SourceArn` (`arn:aws:ecs:<region>:<account>:*`; cluster-specific `SourceArn` is not supported) against confused-deputy use.

**Secrets.** Container definitions have `environment` (plain name/value, stored verbatim in the task definition and readable by anyone with `ecs:DescribeTaskDefinition`), `environmentFiles` (S3 objects), and `secrets` (name plus `valueFrom` pointing at a Secrets Manager secret or SSM parameter ARN, fetched by the *execution role* at start). `secrets` keeps the value out of the task definition, but it still arrives as an environment variable inside the container, so anything that can read the process environment reads it. Private registry credentials use `repositoryCredentials.credentialsParameter`.

**Launch types and isolation.** On **Fargate**, each task runs in its own isolation boundary (own kernel, ENI), there is no EC2 instance profile to steal, privileged containers are not supported and `awsvpc` networking is mandatory. On **EC2** (and ECS Managed Instances and ECS Anywhere), AWS states plainly that there is no task isolation: containers can potentially reach other tasks' credentials, the **container instance role** (`ecsInstanceRole`) through the EC2 IMDS, and co-located data. AWS provides `ECS_AWSVPC_BLOCK_IMDS=true` (agent config, for `awsvpc` tasks) and an `iptables` `DOCKER-USER` rule (for `bridge` tasks) to cut containers off from IMDS; `host` network mode shares the instance's network identity. The IMDS side (IMDSv2, hop limit) is covered in the [EC2 note](/cloud/aws-ec2-imds-ebs-ssm-security/).

**Network.** With `awsvpc`, every task gets its own ENI and security groups (`networkConfiguration.awsvpcConfiguration.securityGroups`) and optionally a public IP (`assignPublicIp`). Security group and load balancer review is in the [VPC and edge note](/cloud/aws-vpc-edge-dns-security/).

**ECS Exec.** `aws ecs execute-command` opens an SSM Session Manager channel into a running container. It requires `enableExecuteCommand: true` on the task or service (it cannot be switched on for running tasks), `ssmmessages:*` on the task role, and `ecs:ExecuteCommand` for the caller. Commands run as **root** inside the container regardless of the container `user`, and the agent needs a writable root filesystem. Who ran it is in CloudTrail (`ExecuteCommand`); what was typed is only logged if the cluster's `executeCommandConfiguration` sends session logs to CloudWatch Logs or S3 *and* the image contains `script` and `cat`.

### Amazon EKS

**Control plane endpoint.** New clusters get a **public** API server endpoint by default, with `publicAccessCidrs` of `0.0.0.0/0`. You can restrict CIDRs, enable the private endpoint (nodes then talk to the API server inside the VPC, controlled by the cluster security group) and disable public access. Even a private-only endpoint's DNS name resolves publicly to private IPs.

**Authentication: IAM to Kubernetes.** Callers present a pre-signed STS `GetCallerIdentity` token; the AWS IAM Authenticator on the control plane maps the IAM principal to a Kubernetes identity. The mapping comes from one or both of:

- the **`aws-auth` ConfigMap** in `kube-system` (`mapRoles`, `mapUsers`), the original and now deprecated method, edited with `kubectl`; and
- **access entries** (Cluster Access Management API, `eks:CreateAccessEntry`), managed through the EKS API, with permissions from AWS **access policies** (`AmazonEKSClusterAdminPolicy`, `AmazonEKSAdminPolicy`, `AmazonEKSEditPolicy`, `AmazonEKSViewPolicy`, `AmazonEKSAdminViewPolicy`, `AmazonEKSSecretReaderPolicy` and others) scoped to the cluster or to namespaces, and/or Kubernetes group names bound by your own RBAC.

The cluster's `authenticationMode` is `CONFIG_MAP`, `API_AND_CONFIG_MAP` or `API`. Per the API reference, clusters created through the EKS API, SDKs or CloudFormation default to `CONFIG_MAP`; the console defaults to `API_AND_CONFIG_MAP`. Moving towards `API` is one-way: once access entries are enabled they cannot be disabled, and `CONFIG_MAP` cannot be enabled later if it was off at creation.

Two consequences matter for testing. First, **the cluster creator**: `bootstrapClusterCreatorAdminPermissions` defaults to `true`, which under access entries creates a visible cluster-admin entry for whoever created the cluster (often a CI role), and under `CONFIG_MAP`-only clusters gives that principal invisible `system:masters` rights that appear nowhere in `aws-auth`. Second, **access entries move cluster admin into IAM**: anyone with `eks:CreateAccessEntry` and `eks:AssociateAccessPolicy` on a cluster can grant themselves `AmazonEKSClusterAdminPolicy`, without any Kubernetes RBAC. A `STANDARD` access entry may also name a principal in another account.

**Workload identity: three ways a pod gets AWS credentials.**

| Mechanism | How | Trust | Where the credential appears |
|---|---|---|---|
| **Node IAM role** via IMDS | Any pod that can reach `169.254.169.254` | Implicit: everything on the node | IMDS response |
| **IRSA** (IAM roles for service accounts) | Projected SA token (`AWS_WEB_IDENTITY_TOKEN_FILE`, `/var/run/secrets/eks.amazonaws.com/serviceaccount/token`) exchanged with `sts:AssumeRoleWithWebIdentity` | Role trusts the cluster's IAM OIDC provider; conditions on `<issuer>:sub` (`system:serviceaccount:<ns>:<sa>`) and `<issuer>:aud` (`sts.amazonaws.com`) | STS response in the pod |
| **EKS Pod Identity** | Pod Identity Agent on each node at `169.254.170.23` calls `eks-auth:AssumeRoleForPodIdentity`; pod presents a token from `AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE` to `AWS_CONTAINER_CREDENTIALS_FULL_URI` | Role trusts `pods.eks.amazonaws.com` (`sts:AssumeRole`, `sts:TagSession`); the binding is the **association** in the EKS API, not the trust policy | Agent response in the pod |

With IRSA the trust policy *is* the access control, so a missing or wildcard `sub` lets every service account in the cluster assume the role. With Pod Identity the trust policy is generic by design and control moves to who can call `eks:CreatePodIdentityAssociation` (plus `iam:PassRole` on the role); session tags (`eks-cluster-arn`, `eks-cluster-name`, `kubernetes-namespace`, `kubernetes-service-account`, `kubernetes-pod-name`, `kubernetes-pod-uid`) let you pin the trust policy with `aws:RequestTag/...` conditions. Neither removes the node role: AWS's own best-practice guide warns that pods "can still inherit the rights of the instance profile assigned to the worker node" unless you block IMDS (IMDSv2 required plus hop limit 1, or iptables/network policy). Hop limit 1 does not help pods on `hostNetwork`, nor an instance that still allows IMDSv1.

**Secrets encryption.** For clusters on Kubernetes 1.28 and later, EKS envelope-encrypts **all** Kubernetes API data in etcd by default with KMS v2 and an AWS-owned key; you can bring a customer managed key (`associate-encryption-config`), which is then the KEK for everything. Disabling or deleting that CMK degrades the cluster, and a deleted key or revoked grant is unrecoverable. Security Hub CSPM gave notice in June 2026 that it would retire **EKS.3** (secrets encryption) after 10 August 2026 for exactly this reason.

**Logging.** Control-plane log types are `api`, `audit`, `authenticator`, `controllerManager` and `scheduler`, all off by default, delivered to CloudWatch Logs (`/aws/eks/<cluster>/cluster`). `audit` is who-did-what in Kubernetes; `authenticator` maps IAM principals to Kubernetes usernames, which is how you tie a `kubectl exec` back to an IAM session. GuardDuty **EKS Protection** analyses audit logs independently (you do not need to enable them for GuardDuty), and **Runtime Monitoring** adds an agent (EKS add-on, ECS Fargate sidecar, EC2 agent) for process-level detections.

**Add-ons** (`vpc-cni`, `coredns`, `kube-proxy`, `aws-ebs-csi-driver`, `eks-pod-identity-agent`, GuardDuty agent...) run with identities of their own. The VPC CNI uses the node role by default, which is why many node roles carry `AmazonEKS_CNI_Policy` (EC2 network-interface write permissions) that every pod reaching IMDS then inherits.

## What goes wrong

**Repository policy with `"Principal": "*"`.** Usually written to "let our other accounts pull". Any AWS account on the internet can then pull every image (source code, embedded config, secrets) and, if push actions are included, *replace* images that production pulls by tag. That is a supply-chain compromise of every workload using the repository, reached from a free-tier account.

**Internal images in ECR Public, or a public repository created by mistake.** ECR Public is world-readable by design. Teams publish "base images" that contain internal certificates, `.npmrc` tokens or build scripts.

**Secrets in layers.** `COPY . .` with a `.env` file, `ARG`/`ENV` with a token, `RUN echo $KEY > ~/.aws/credentials && ... && rm` in a separate layer: deleting a file in a later layer does not remove it from the earlier one, and `ENV`/`ARG` values are recorded in the image config and history. Anyone who can pull can read them, including every principal that can pull for legitimate reasons.

**Plaintext secrets in `environment`.** The task definition stores them verbatim, every revision keeps them (deregistered revisions are still describable), and `ecs:DescribeTaskDefinition` is in almost every read-only policy. Security Hub's ECS.8 only looks for three variable *names* (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `ECS_ENGINE_AUTH_DATA`), so `DB_PASSWORD` passes.

**Over-privileged task roles, or one role for both jobs.** The execution role legitimately needs `secretsmanager:GetSecretValue` on the task's secrets; when the same role is also the task role, the application (and any SSRF or RCE in it) can read every secret the role can. Task roles with `s3:*` on `*` or `AdministratorAccess` turn any app bug into account compromise. Combined with `iam:PassRole` and `ecs:RegisterTaskDefinition`/`ecs:RunTask` for a lower-privileged user, a powerful task role is also a privilege-escalation path ([privesc note](/cloud/aws-iam-privilege-escalation/)).

**Metadata and credential endpoints reachable from the application.** SSRF in a container on EC2 reaches the instance role through IMDS; on ECS, SSRF plus an environment leak yields the task role from `169.254.170.2`; on EKS, any pod (or SSRF in any pod) reaching IMDS gets the node role, which can also impersonate the node towards the Kubernetes API.

**Privileged and host-sharing containers on EC2.** `privileged: true`, `pidMode: host`, `networkMode: host`, extra capabilities or sensitive host mounts make container escape to the instance (and from there to every co-located task and the instance role) a short step.

**ECS Exec as an unlogged backdoor.** `ecs:ExecuteCommand` granted on `*` to developer roles, enabled on production services, with `logging: NONE` or images without `script`, gives a root shell in production with only a CloudTrail record that it happened.

**Public EKS endpoint open to the world.** Authentication still applies, but the API server is exposed to leaked kubeconfigs and SA tokens used from anywhere, to anonymous-access misconfigurations (`system:anonymous` or `system:unauthenticated` bound to anything beyond discovery), and to pre-auth API server bugs.

**Cluster admin that nobody can see or that too many can grant.** Wildcard SSO roles mapped to `system:masters` in `aws-auth`, the original creator's invisible admin rights, cross-account access entries, and IAM policies granting `eks:*` (which includes `CreateAccessEntry` and `AssociateAccessPolicy`) to people who were meant to have read-only Kubernetes access.

**IRSA trust without `sub`, or with `StringLike` and `*`.** Every service account in the cluster, including ones an attacker can create in their own namespace, can assume the role.

**No control-plane audit logging and no GuardDuty EKS coverage.** You cannot reconstruct who exec'd into what, and nothing alerts on an anonymous `ClusterRoleBinding`.

**Unscanned, mutable images.** Without scanning nobody knows about the critical CVE in the base image; with mutable tags, `:latest` or `:prod` can be silently replaced and old images never expire.

## Testing

All tests assume an **authorised engagement** against the client's own accounts and clusters, with written scope and AWS's [penetration testing policy](https://aws.amazon.com/security/penetration-testing/) respected. Default to read-only calls; anything that creates pods, Jobs, tasks or images is marked **lab or explicitly approved only**. The command outputs below are **illustrative**, not from a real environment.

### Before you start

**Credentials.** An AWS role with `SecurityAudit` plus `ViewOnlyAccess` covers the ECR, ECS and EKS describe/list calls, IAM role and policy reads, and Inspector/GuardDuty reads. Image pulls need `ecr:GetAuthorizationToken`, `ecr:BatchGetImage` and `ecr:GetDownloadUrlForLayer` (the AWS managed `AmazonEC2ContainerRegistryReadOnly` policy); agree that separately, because pulling copies client code and data to your machine. For in-cluster tests, ask for a dedicated access entry with `AmazonEKSAdminViewPolicy` (cluster scope) for review, and a separate, time-boxed entry for anything that creates resources.

```bash
export AWS_PROFILE=client-audit
aws sts get-caller-identity

# Regions in use (enabled regions only)
REGIONS=$(aws ec2 describe-regions --query 'Regions[].RegionName' --output text)

# Inventory: repositories, ECS clusters, EKS clusters per region
for r in $REGIONS; do
  repos=$(aws ecr describe-repositories --region "$r" --query 'length(repositories)' --output text 2>/dev/null)
  ecs=$(aws ecs list-clusters --region "$r" --query 'length(clusterArns)' --output text 2>/dev/null)
  eks=$(aws eks list-clusters --region "$r" --query 'length(clusters)' --output text 2>/dev/null)
  echo -e "$r\tECR:$repos\tECS:$ecs\tEKS:$eks"
done

# ECR Public is managed from us-east-1
aws ecr-public describe-repositories --region us-east-1 --query 'repositories[].repositoryUri'

# kubeconfig for an in-scope cluster (uses your current AWS identity)
aws eks update-kubeconfig --name prod-eks --region eu-west-2 --alias prod-eks-audit
kubectl auth whoami
```

**Naming.** "Security Hub CSPM" below is the original AWS Security Hub posture product (controls such as `ECR.1`, `EKS.8`), which AWS renamed in 2025 when it launched the new unified Security Hub. Control IDs are unchanged.

**Tools.** [Prowler](https://github.com/prowler-cloud/prowler) (`prowler aws --services ecr ecs eks`), ScoutSuite, [CloudFox](https://github.com/BishopFox/cloudfox) (`ecr`, `ecs-tasks`, `eks`, `env-vars`, `role-trusts`, `workloads`), Pacu enumeration modules `ecr__enum`, `ecs__enum`, `ecs__enum_task_def` and `eks__enum`, PMapper for role escalation graphs, Datadog's [MKAT](https://github.com/datadog/managed-kubernetes-auditing-toolkit) (`mkat eks find-role-relationships`, `mkat eks find-secrets`), [kube-bench](https://github.com/aquasecurity/kube-bench), `docker`, [dive](https://github.com/wagoodman/dive), [trufflehog](https://github.com/trufflesecurity/trufflehog) and `jq`. Practise the attack paths in [CloudGoat](https://github.com/RhinoSecurityLabs/cloudgoat) or a throwaway cluster before using them on a client.

### GT-AWS-CNT-1: ECR repository and registry policies

*Guler Tech methodology.*

#### What it checks

Whether any private repository policy, the registry policy, or an ECR Public repository grants pull or push to principals outside the intended accounts, especially `"Principal": "*"` or `"AWS": "*"` without an organisation condition.

#### Prerequisites

`ecr:DescribeRepositories`, `ecr:GetRepositoryPolicy`, `ecr:GetRegistryPolicy`, `ecr-public:DescribeRepositories`, `ecr-public:GetRepositoryPolicy` (all in `SecurityAudit`).

#### Steps

1. Dump every repository policy and flag wildcard or foreign principals:

   ```bash
   ORG_ACCOUNTS="111122223333 444455556666"   # accounts the client says should have access
   for r in $REGIONS; do
     for repo in $(aws ecr describe-repositories --region "$r" --query 'repositories[].repositoryName' --output text); do
       pol=$(aws ecr get-repository-policy --region "$r" --repository-name "$repo" \
             --query policyText --output text 2>/dev/null) || continue
       echo "$pol" | jq -c --arg repo "$r/$repo" '.Statement[] | select(.Effect=="Allow") |
         {repo:$repo, sid:.Sid, principal:.Principal, actions:.Action, cond:.Condition}'
     done
   done > ecr-policies.jsonl

   # Wildcard principals
   jq -c 'select((.principal=="*") or (.principal.AWS=="*") or ((.principal.AWS|type)=="array" and (.principal.AWS|index("*"))))' ecr-policies.jsonl
   ```

2. For each hit, classify the actions: **pull** (`BatchGetImage`, `GetDownloadUrlForLayer`, `BatchCheckLayerAvailability`, `DescribeImages`, `ListImages`) versus **push/admin** (`PutImage`, `InitiateLayerUpload`, `UploadLayerPart`, `CompleteLayerUpload`, `BatchDeleteImage`, `SetRepositoryPolicy`, `ecr:*`). Check whether a `Condition` on `aws:PrincipalOrgID`, `aws:PrincipalAccount` or `aws:SourceAccount` narrows the wildcard.
3. List explicit account principals and compare with the client's account inventory; any account not owned by the client needs an owner and a reason.
4. Read the registry policy and replication configuration (cross-account replication sends every image elsewhere):

   ```bash
   aws ecr get-registry-policy --region eu-west-2 --query policyText --output text | jq .
   aws ecr describe-registry --region eu-west-2 --query 'replicationConfiguration'
   ```

5. Review ECR Public: list repositories and their catalogue data, then pull the latest tag of each (it is public, so no extra approval is needed for the pull itself) and feed it to GT-AWS-CNT-3. Ask the owner whether each repository is meant to be public.

   ```bash
   aws ecr-public describe-repositories --region us-east-1 \
     --query 'repositories[].{name:repositoryName,uri:repositoryUri,created:createdAt}' --output table
   ```

6. **Lab or explicitly approved only:** to prove cross-account pull for a wildcard policy, use a separate AWS account the client controls (or Guler Tech's test account, if the client agrees in writing) and pull one agreed, non-sensitive image. Do not push.

#### Observation

```json
{"repo":"eu-west-2/payments-api","sid":"AllowOtherAccounts","principal":{"AWS":"*"},"actions":["ecr:BatchGetImage","ecr:GetDownloadUrlForLayer","ecr:PutImage","ecr:InitiateLayerUpload","ecr:UploadLayerPart","ecr:CompleteLayerUpload"],"cond":null}
```

#### Evaluation

**Fail** if any Allow statement grants ECR actions to `*` without a condition that limits it to the client's organisation or named accounts; push actions under such a statement are the worst case. **Fail** if an ECR Public repository contains images the owner considers internal. **Fail (lower)** for explicit foreign accounts with no owner. **Pass** if all principals are named client accounts, roles or AWS service principals with `aws:SourceArn`/`aws:SourceAccount`, or wildcards are fenced by `aws:PrincipalOrgID`. False positive to rule out: a `Deny` statement with `"Principal": "*"` (that is a guardrail, not exposure).

#### Automated coverage

No Security Hub CSPM control covers ECR repository policies at the time of writing. Prowler: `ecr_repositories_not_publicly_accessible`. IAM Access Analyzer external access analysers report ECR repositories shared outside the zone of trust.

#### Detection

CloudTrail `SetRepositoryPolicy`, `DeleteRepositoryPolicy`, `PutRegistryPolicy`, `PutReplicationConfiguration`, `ecr-public:CreateRepository`, `ecr-public:SetRepositoryPolicy`; `PutImage` from an unexpected account or principal. Alert on any `SetRepositoryPolicy` whose `requestParameters.policyText` contains `"*"`.

### GT-AWS-CNT-2: ECR scanning, tag immutability, lifecycle and pull-through cache

*Guler Tech methodology.*

#### What it checks

Registry hygiene that decides whether a vulnerable or swapped image would be noticed: scanning mode and coverage, open critical findings on images actually deployed, tag mutability, lifecycle policies, KMS encryption where the client requires it, and pull-through cache rules plus creation templates.

#### Prerequisites

`SecurityAudit`; `inspector2:ListFindings` (in `SecurityAudit` at the time of writing; otherwise `AmazonInspector2ReadOnlyAccess`).

#### Steps

1. Registry-level scanning configuration and repository settings:

   ```bash
   aws ecr get-registry-scanning-configuration --region eu-west-2
   aws ecr describe-repositories --region eu-west-2 --query 'repositories[].{name:repositoryName,tags:imageTagMutability,scanOnPush:imageScanningConfiguration.scanOnPush,enc:encryptionConfiguration.encryptionType}' --output table
   ```

   `scanType: ENHANCED` with rules whose `scanFrequency` is `CONTINUOUS_SCAN` and a `*` filter is the strong configuration. `BASIC` with `SCAN_ON_PUSH` scans each image once. A repository-level `scanOnPush: false` under basic scanning, or a filter that does not match a repository, means no scanning.

2. Open critical and high findings for deployed images (cross-reference the image URIs and digests from GT-AWS-CNT-4 and `kubectl get pods -A -o json`):

   ```bash
   aws inspector2 list-findings --region eu-west-2 \
     --filter-criteria '{"resourceType":[{"comparison":"EQUALS","value":"AWS_ECR_CONTAINER_IMAGE"}],"severity":[{"comparison":"EQUALS","value":"CRITICAL"}],"findingStatus":[{"comparison":"EQUALS","value":"ACTIVE"}]}' \
     --query 'findings[].{title:title,repo:resources[0].details.awsEcrContainerImage.repositoryName,tags:resources[0].details.awsEcrContainerImage.imageTags,fix:fixAvailable}' --output table

   # Basic scanning results
   aws ecr describe-image-scan-findings --region eu-west-2 --repository-name payments-api --image-id imageTag=prod \
     --query 'imageScanFindings.findingSeverityCounts'
   ```

3. Lifecycle policies:

   ```bash
   for repo in $(aws ecr describe-repositories --region eu-west-2 --query 'repositories[].repositoryName' --output text); do
     aws ecr get-lifecycle-policy --region eu-west-2 --repository-name "$repo" >/dev/null 2>&1 \
       || echo "no lifecycle policy: $repo"
   done
   ```

4. Pull-through cache and creation templates:

   ```bash
   aws ecr describe-pull-through-cache-rules --region eu-west-2 \
     --query 'pullThroughCacheRules[].{prefix:ecrRepositoryPrefix,upstream:upstreamRegistryUrl,secret:credentialArn}'
   aws ecr describe-repository-creation-templates --region eu-west-2
   ```

   Ask: which upstreams are allowed, who can trigger a first pull (identity policies granting `ecr:CreateRepository` and `ecr:BatchImportUpstreamImage` on the cache prefix), and whether a creation template gives cached repositories scanning, a lifecycle and a restrictive policy. A Docker Hub rule with a broad prefix lets anyone with pull rights materialise arbitrary public images inside the "trusted" private registry.

#### Observation

```text
scanType: BASIC   rules: [{scanFrequency: SCAN_ON_PUSH, repositoryFilters: [{filter: "prod-*", filterType: WILDCARD}]}]
payments-api        MUTABLE   scanOnPush=False   AES256
dockerhub/library/* cached via pull-through, no creation template (MUTABLE, no lifecycle, no scanning filter match)
```

#### Evaluation

**Fail** if deployed images have no scanning coverage, if critical findings with a fix available have been open beyond the client's SLA on images running in production, or if production repositories use mutable tags *and* deployments reference tags rather than digests. **Fail (low)** for missing lifecycle policies and pull-through cache rules without a creation template. KMS CMK encryption (ECR.5) is a requirement only where the client's policy demands it; SSE-S3 alone is not a vulnerability. **Pass** when scanning is enhanced and continuous for all repositories, production tags are immutable or deployments pin digests, and lifecycle policies exist.

#### Automated coverage

Security Hub CSPM **ECR.1** (scanning configured), **ECR.2** (tag immutability), **ECR.3** (lifecycle policy), **ECR.5** (CMK encryption). Prowler: `ecr_registry_enhanced_scanning_enabled`, `ecr_registry_scan_images_on_push_enabled`, `ecr_repositories_scan_images_on_push_enabled`, `ecr_repositories_scan_vulnerabilities_in_latest_image`, `ecr_repositories_tag_immutability`, `ecr_repositories_lifecycle_policy_enabled`.

#### Detection

CloudTrail `PutRegistryScanningConfiguration`, `PutImageScanningConfiguration`, `PutImageTagMutability`, `DeleteLifecyclePolicy`, `CreatePullThroughCacheRule`, `PutImage` overwriting an existing production tag. Inspector findings to EventBridge for new critical CVEs on deployed images.

### GT-AWS-CNT-3: Secrets baked into image layers

*Guler Tech methodology.*

#### What it checks

Whether images in ECR (and ECR Public) contain credentials in any layer, in `ENV`/`ARG` values, or in the build history, and therefore leak them to everyone with pull access.

#### Prerequisites

Approved pull access (see [Before you start](#before-you-start)), an isolated analysis host with enough disk, `docker`, `dive`, `trufflehog`. Handle pulled images as client data and delete them at the end.

#### Steps

1. Pick images: the tags actually deployed (from task definitions and pod specs), the latest tag of each repository, and every ECR Public image.
2. Log in and pull by digest:

   ```bash
   aws ecr get-login-password --region eu-west-2 | \
     docker login --username AWS --password-stdin 111122223333.dkr.ecr.eu-west-2.amazonaws.com
   IMG=111122223333.dkr.ecr.eu-west-2.amazonaws.com/payments-api@sha256:<digest>
   docker pull "$IMG"
   ```

3. Read the image config and history; `ENV` and build `ARG`s used in `RUN` lines appear here in clear text:

   ```bash
   docker image inspect "$IMG" | jq '.[0].Config.Env'
   docker history --no-trunc "$IMG" | grep -niE 'secret|token|passw|key|arg |env |aws_|\.npmrc|\.env'
   ```

4. Scan every layer, including files deleted in later layers:

   ```bash
   trufflehog docker --image "$IMG" --only-verified=false --json > th-payments-api.json
   jq -r '.DetectorName + "\t" + (.SourceMetadata.Data.Docker.layer // "") + "\t" + (.SourceMetadata.Data.Docker.file // "")' th-payments-api.json | sort -u
   ```

5. Use `dive "$IMG"` to inspect suspicious layers interactively (files added then removed show as wasted space in an earlier layer). Look specifically for `.env`, `.npmrc`, `.pypirc`, `.git/`, `~/.aws/credentials`, `id_rsa`, `*.pem`, `settings.xml`, Terraform state and `kubeconfig`.
6. For each candidate, stop at identification. Report detector, layer digest, file path and the build step; do not print or use the value. If a key looks like an AWS key, the client decides whether you may run `sts get-caller-identity` with it; otherwise they rotate.

#### Observation

```text
AWS          sha256:3f1c...e9   app/.env
PrivateKey   sha256:9a07...41   root/.ssh/id_rsa   (deleted in sha256:b2d4...07)
ENV          NPM_TOKEN=<redacted, 36 chars>
```

#### Evaluation

**Fail** if any layer, config `Env` or history entry contains a live or plausibly live credential, private key or token, regardless of whether a later layer deletes it. Severity scales with who can pull (GT-AWS-CNT-1) and what the secret unlocks. **Pass** if no secrets are found in the sampled images and the client's build uses BuildKit secret mounts (`RUN --mount=type=secret`) or multi-stage builds that copy only artefacts. False positives: test fixtures, public CA bundles, example keys in vendored libraries; verify before reporting.

#### Automated coverage

None in Security Hub CSPM. Prowler `ecr_repository_image_no_secrets` analyses the latest image per repository (config, history and layer contents). Inspector does not scan for secrets.

#### Detection

ECR pulls by unexpected principals (CloudTrail `BatchGetImage`, `GetDownloadUrlForLayer` from unfamiliar accounts or IPs). Use of the leaked credential shows up wherever it is valid: CloudTrail for AWS keys, the third party's audit log for others.

### GT-AWS-CNT-4: ECS secrets in task definitions

*Guler Tech methodology.*

#### What it checks

Whether credentials sit in plain `environment` variables of task definitions (current and old revisions), and whether `secrets`/`valueFrom` is used correctly instead.

#### Prerequisites

`ecs:ListTaskDefinitionFamilies`, `ecs:ListTaskDefinitions`, `ecs:DescribeTaskDefinition`.

#### Steps

1. Scan the latest revision of each active family, printing variable names and value lengths, never values:

   ```bash
   for r in $REGIONS; do
     for fam in $(aws ecs list-task-definition-families --region "$r" --status ACTIVE --query 'families[]' --output text); do
       aws ecs describe-task-definition --region "$r" --task-definition "$fam" --query 'taskDefinition' --output json |
       jq -r --arg r "$r" '. as $td | .containerDefinitions[] | .name as $c |
         (.environment // [])[] |
         select(.name | test("pass|secret|token|key|cred|auth|dsn|conn|private"; "i")) |
         "\($r)\t\($td.family):\($td.revision)\t\($c)\t\(.name)\tlen=\(.value|length)"'
     done
   done
   ```

2. Repeat with `--status INACTIVE` families and older revisions (`aws ecs list-task-definitions --family-prefix <fam> --status INACTIVE`); deregistered revisions remain describable, so a rotated-in-theory secret may still be readable.
3. Look for secret-shaped *values* under innocent names (high-entropy strings, `postgres://user:pass@`, `-----BEGIN`) by piping values through trufflehog locally:

   ```bash
   aws ecs describe-task-definition --task-definition payments-api --query 'taskDefinition.containerDefinitions[].environment' \
     --output json > td-env.json
   trufflehog filesystem td-env.json --json | jq -r '.DetectorName'
   ```

4. Review `secrets` entries: each `valueFrom` should be a Secrets Manager or SSM SecureString ARN, and the execution role should be scoped to exactly those ARNs (GT-AWS-CNT-5). Note `environmentFiles` (S3 objects): who can read that bucket?
5. Check where else the value lives: IaC (Terraform state, CloudFormation templates and parameters), CI variables and CloudTrail `RegisterTaskDefinition` request parameters. CloudFox `env-vars` collects ECS, Lambda and App Runner variables in one pass.

#### Observation

```text
eu-west-2   payments-api:42   app   DB_PASSWORD        len=24
eu-west-2   payments-api:42   app   STRIPE_SECRET_KEY  len=107
eu-west-2   reporting:7       app   AWS_ACCESS_KEY_ID  len=20
```

#### Evaluation

**Fail** if any active or still-describable revision holds a credential in `environment`. Explain the readership: every principal with `ecs:DescribeTaskDefinition`, which includes broad read-only roles. **Pass** if sensitive values come only through `secrets` with `valueFrom`. Note for the report that `secrets` still lands in the container's environment at runtime; it fixes the storage problem, not exposure to code running inside the container.

#### Automated coverage

Security Hub CSPM **ECS.8** (only the variable names `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `ECS_ENGINE_AUTH_DATA`; it misses most real secrets). Prowler `ecs_task_definitions_no_environment_secrets` (pattern-based on values).

#### Detection

CloudTrail `DescribeTaskDefinition` and `ListTaskDefinitions` in bulk from an unusual principal (enumeration); `RegisterTaskDefinition` changes. Then use of the exposed secret in the target system.

### GT-AWS-CNT-5: ECS task role and task execution role

*Guler Tech methodology.*

#### What it checks

Least privilege and separation of the task role and execution role, their trust policies, and who can pass them to new tasks.

#### Prerequisites

`SecurityAudit`; PMapper or CloudFox `workloads` for escalation analysis.

#### Steps

1. Map task definitions to roles:

   ```bash
   for fam in $(aws ecs list-task-definition-families --status ACTIVE --query 'families[]' --output text); do
     aws ecs describe-task-definition --task-definition "$fam" \
       --query 'taskDefinition.{family:family,rev:revision,task:taskRoleArn,exec:executionRoleArn,compat:requiresCompatibilities}' --output json
   done | jq -s -c '.[]'
   ```

2. Flag task definitions where `taskRoleArn == executionRoleArn`, where the task role is missing on EC2 launch type (the app then falls back to the instance role), and roles with AWS managed admin-like policies:

   ```bash
   aws iam list-attached-role-policies --role-name payments-task-role
   aws iam list-role-policies --role-name payments-task-role
   aws iam simulate-principal-policy --policy-source-arn arn:aws:iam::111122223333:role/payments-task-role \
     --action-names s3:GetObject secretsmanager:GetSecretValue iam:PassRole kms:Decrypt \
     --resource-arns '*' --query 'EvaluationResults[].{a:EvalActionName,d:EvalDecision}' --output table
   ```

3. Check the execution role's secret access is scoped to the task's `valueFrom` ARNs, not `secretsmanager:GetSecretValue` on `*`.
4. Trust policies: task roles should trust only `ecs-tasks.amazonaws.com`, ideally with `aws:SourceAccount` and `aws:SourceArn`. CloudFox `role-trusts` lists them quickly.
5. Who can pass these roles: find principals with `iam:PassRole` on the task role plus `ecs:RegisterTaskDefinition` and `ecs:RunTask`/`ecs:UpdateService`. That combination lets them run arbitrary code with the role's permissions; see the [privilege escalation note](/cloud/aws-iam-privilege-escalation/) for the analysis method.

#### Observation

```text
payments-api:42  task=role/ecsTaskExecutionRole  exec=role/ecsTaskExecutionRole
ecsTaskExecutionRole: AmazonECSTaskExecutionRolePolicy + inline "secrets" -> secretsmanager:GetSecretValue on *
simulate: secretsmanager:GetSecretValue allowed on *
```

#### Evaluation

**Fail** if the task role equals the execution role, if a task role or execution role has wildcard access to secrets, KMS decrypt or data stores beyond the workload's needs, or if a lower-privileged principal can pass a more privileged task role into a new task. **Pass** if each service has its own task role scoped to its resources, the execution role reads only its own secrets, and `iam:PassRole` is limited to deployment roles with `iam:PassedToService` set to `ecs-tasks.amazonaws.com`.

#### Automated coverage

None specific in Security Hub CSPM (IAM.1-style controls catch only full admin). Prowler IAM checks on attached policies; CloudFox `workloads` flags admin workload roles.

#### Detection

CloudTrail `RegisterTaskDefinition` with a new `taskRoleArn`, `RunTask` by unusual principals, and task-role credentials used from outside AWS: GuardDuty `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS` and `.InsideAWS` cover credentials obtained from the ECS credential endpoint as well as IMDS. CloudTrail events from task credentials carry the task ARN in the session context.

### GT-AWS-CNT-6: ECS container and network hardening

*Guler Tech methodology.*

#### What it checks

Container-level settings that decide whether app compromise becomes host compromise (EC2 launch type) and whether tasks are reachable from where they should not be.

#### Prerequisites

`SecurityAudit`.

#### Steps

1. Extract the risky fields from every active task definition:

   ```bash
   for fam in $(aws ecs list-task-definition-families --status ACTIVE --query 'families[]' --output text); do
     aws ecs describe-task-definition --task-definition "$fam" --query 'taskDefinition' --output json |
     jq -c '{family, revision, networkMode, pidMode, ipcMode, compat: .requiresCompatibilities,
       containers: [.containerDefinitions[] | {name, privileged, user, readonlyRootFilesystem,
         caps: .linuxParameters.capabilities.add, devices: .linuxParameters.devices,
         mounts: [.mountPoints[]?.sourceVolume], log: .logConfiguration.logDriver}],
       hostVolumes: [.volumes[]? | select(.host.sourcePath) | .host.sourcePath]}'
   done
   ```

2. Flag: `privileged: true`; `pidMode: "host"`; `networkMode: "host"`; added capabilities such as `SYS_ADMIN`, `NET_ADMIN`, `SYS_PTRACE`; host volumes like `/`, `/var/run/docker.sock`, `/proc`, `/etc`; `user` missing, `root` or `0`; `readonlyRootFilesystem` not `true`; no `logConfiguration`.
3. Services and launch type: which services run on EC2 and which on Fargate, platform versions, public IPs and security groups:

   ```bash
   CL=prod-cluster
   for s in $(aws ecs list-services --cluster $CL --query 'serviceArns[]' --output text); do
     aws ecs describe-services --cluster $CL --services "$s" --output json --query 'services[0].{svc:serviceName,lt:launchType,
       cp:capacityProviderStrategy[0].capacityProvider,pv:platformVersion,pubip:networkConfiguration.awsvpcConfiguration.assignPublicIp,
       sgs:networkConfiguration.awsvpcConfiguration.securityGroups,exec:enableExecuteCommand}'
   done
   ```

4. For each task security group, check ingress for `0.0.0.0/0` on application ports that should only accept the load balancer's security group (review method in the [VPC and edge note](/cloud/aws-vpc-edge-dns-security/)).
5. On EC2 launch type, check the container instances: IMDS settings of the Auto Scaling launch template (`aws ec2 describe-launch-template-versions ... --query '...MetadataOptions'`) and, if you have approved host access, the agent config `/etc/ecs/ecs.config` for `ECS_AWSVPC_BLOCK_IMDS=true` and the `DOCKER-USER` rule for bridge mode.

#### Observation

```json
{"family":"log-shipper","revision":9,"networkMode":"host","pidMode":"host","compat":["EC2"],"containers":[{"name":"agent","privileged":true,"user":null,"readonlyRootFilesystem":null,"caps":null,"devices":null,"mounts":["docker-sock","rootfs"],"log":"awslogs"}],"hostVolumes":["/var/run/docker.sock","/"]}
```

#### Evaluation

**Fail (high)** for privileged containers, host PID, `docker.sock` or `/` host mounts on EC2 launch type unless the workload is a documented node agent and the cluster hosts nothing more sensitive than that agent; each is a direct route to the instance and every co-located task. **Fail (medium)** for `host` network mode and `assignPublicIp: ENABLED` on services that sit behind a load balancer. **Fail (low)** for root user, writable root filesystem, missing log configuration. **Pass** for Fargate or EC2 tasks with non-root users, read-only root filesystems (except where ECS Exec is required; see GT-AWS-CNT-7), no extra capabilities, `awsvpc` with least-privilege security groups.

#### Automated coverage

Security Hub CSPM **ECS.2** (services auto-assign public IP), **ECS.3** (host PID namespace), **ECS.4** (privileged), **ECS.5** (read-only root filesystem), **ECS.9** (logging configuration), **ECS.10** (latest Fargate platform version), **ECS.16** (task sets public IP), **ECS.17** (host network mode), **ECS.20** (non-root Linux user). ECS.1 was retired in 2026. Prowler: `ecs_task_definitions_no_privileged_containers`, `ecs_task_definitions_host_namespace_not_shared`, `ecs_task_definitions_host_networking_mode_users`, `ecs_task_definitions_containers_readonly_access`, `ecs_task_definitions_logging_enabled`, `ecs_service_no_assign_public_ip`, `ecs_task_set_no_assign_public_ip`, `ecs_service_fargate_latest_platform_version`.

#### Detection

GuardDuty Runtime Monitoring (EC2 and ECS Fargate): `PrivilegeEscalation:Runtime/ContainerMountsHostDirectory`, `PrivilegeEscalation:Runtime/DockerSocketAccessed`, `PrivilegeEscalation:Runtime/RuncContainerEscape`, `PrivilegeEscalation:Runtime/CGroupsReleaseAgentModified`, `Execution:Runtime/NewBinaryExecuted`, `Execution:Runtime/ReverseShell`. CloudTrail `RegisterTaskDefinition` introducing `privileged` or host mounts.

### GT-AWS-CNT-7: ECS Exec permissions and logging

*Guler Tech methodology.*

#### What it checks

Who can open a root shell in running containers with ECS Exec, on which services it is enabled, and whether sessions are recorded.

#### Prerequisites

`SecurityAudit`; `iam:SimulatePrincipalPolicy`.

#### Steps

1. Which services and tasks have `enableExecuteCommand: true` (step 3 of GT-AWS-CNT-6 prints it) and whether they are production.
2. Cluster logging configuration:

   ```bash
   aws ecs describe-clusters --clusters prod-cluster --include CONFIGURATIONS \
     --query 'clusters[].{name:clusterName,exec:configuration.executeCommandConfiguration}'
   ```

   `logging: NONE` means no session logs. `DEFAULT` sends logs to the task's `awslogs` driver and saves nothing if there is none. `OVERRIDE` sends them to the named CloudWatch Logs group and/or S3 bucket; check those exist, are encrypted, have retention, and that the images contain `script` and `cat` (without them, command logs are not uploaded).
3. Who holds `ecs:ExecuteCommand`: search identity policies (Steampipe, cloudsplaining or a CloudFox/PMapper export) for `ecs:ExecuteCommand` and `ecs:*`, then simulate for typical developer and CI roles against a production task ARN:

   ```bash
   aws iam simulate-principal-policy \
     --policy-source-arn arn:aws:iam::111122223333:role/developer \
     --action-names ecs:ExecuteCommand \
     --resource-arns arn:aws:ecs:eu-west-2:111122223333:task/prod-cluster/0123456789abcdef0123456789abcdef \
     --query 'EvaluationResults[].EvalDecision'
   ```

4. Check that direct `ssm:StartSession` on ECS task targets is denied; AWS notes that sessions started outside `execute-command` are not logged by ECS Exec's configuration.
5. **Lab or explicitly approved only:** run one `execute-command` with `id` against an agreed non-production task to confirm the logging path end to end, then find your session in CloudTrail and in the log destination.

#### Observation

```text
prod-cluster  executeCommandConfiguration: {logging: NONE}
services with enableExecuteCommand=true: payments-api, admin-portal
role/developer -> ecs:ExecuteCommand on prod task: allowed (policy "DevOpsPower", Action ecs:*)
```

#### Evaluation

**Fail** if ECS Exec is enabled on production services and either broad human roles can call `ecs:ExecuteCommand` on production tasks without conditions (`ecs:cluster`, `ecs:container-name`, resource tags), or sessions are not logged. **Pass** if Exec is disabled in production, or enabled only for a break-glass role, scoped by condition keys, with `OVERRIDE` logging to an encrypted, retained destination and alerting on use.

#### Automated coverage

No Security Hub CSPM control for ECS Exec. Review manually; Prowler's ECS checks do not cover it at the time of writing.

#### Detection

CloudTrail `ExecuteCommand` (caller, cluster, task, container), `UpdateService`/`RunTask` with `enableExecuteCommand: true`, `UpdateCluster` changing `executeCommandConfiguration`, and SSM `StartSession` targeting `ecs:` resources. GuardDuty Runtime findings during the session window (for example `Execution:Runtime/SuspiciousCommand`).

### GT-AWS-CNT-8: EKS endpoint exposure, control-plane logging and encryption

*Guler Tech methodology.*

#### What it checks

The cluster settings visible through `eks describe-cluster`: public and private endpoint access and `publicAccessCidrs`, enabled control-plane log types, envelope encryption key, Kubernetes version and authentication mode.

#### Prerequisites

`eks:ListClusters`, `eks:DescribeCluster`.

#### Steps

1. Summarise every cluster:

   ```bash
   for r in $REGIONS; do
     for c in $(aws eks list-clusters --region "$r" --query 'clusters[]' --output text); do
       aws eks describe-cluster --region "$r" --name "$c" --query 'cluster.{name:name,version:version,
         public:resourcesVpcConfig.endpointPublicAccess,private:resourcesVpcConfig.endpointPrivateAccess,
         cidrs:resourcesVpcConfig.publicAccessCidrs,logs:logging.clusterLogging[?enabled].types[],
         kms:encryptionConfig[0].provider.keyArn,auth:accessConfig.authenticationMode,
         oidc:identity.oidc.issuer}' --output json
     done
   done
   ```

2. Endpoint: `public: true` with `0.0.0.0/0` is the default and the finding. With public access on, confirm the API rejects anonymous requests beyond discovery (read-only, against the client's own endpoint):

   ```bash
   EP=$(aws eks describe-cluster --name prod-eks --query 'cluster.endpoint' --output text)
   curl -sk -o /dev/null -w '%{http_code}\n' "$EP/version"                      # often 200: public discovery
   curl -sk -o /dev/null -w '%{http_code}\n' "$EP/api/v1/namespaces"            # expect 401 or 403
   curl -sk -o /dev/null -w '%{http_code}\n' "$EP/apis/rbac.authorization.k8s.io/v1/clusterrolebindings"
   ```

   A `200` on the last two means anonymous access is bound to more than discovery: stop and report immediately.
3. Logging: `audit` and `authenticator` are the minimum for investigations; check the log group `/aws/eks/<cluster>/cluster` retention and KMS encryption.
4. Encryption: for Kubernetes 1.28+, all API data is envelope-encrypted by default with an AWS-owned key. `kms` set means a CMK; then review the key policy (who can `DisableKey`/`ScheduleKeyDeletion`, see the [KMS note](/cloud/aws-secrets-manager-parameter-store-kms/)). Older versions without an `encryptionConfig` have only disk-level encryption of etcd.
5. Version and node groups: `EKS.2`/`EKS.9` parameters move each time a version leaves standard support (1.34 at the time of writing); `aws eks list-nodegroups` and `describe-nodegroup --query 'nodegroup.{v:version,ami:releaseVersion,lt:launchTemplate}'`.

#### Observation

```json
{"name":"prod-eks","version":"1.33","public":true,"private":false,"cidrs":["0.0.0.0/0"],"logs":["api"],"kms":null,"auth":"CONFIG_MAP","oidc":"https://oidc.eks.eu-west-2.amazonaws.com/id/EXAMPLED539D4633E53DE1B71EXAMPLE"}
```

#### Evaluation

**Fail** if the public endpoint allows `0.0.0.0/0` (Medium on its own; Critical if anonymous requests reach anything beyond discovery), if `audit` logging is off, or if the cluster runs a version outside standard support. **Fail (low)** if `authenticator` logging is off, or a CMK is required by client policy and absent. **Pass** with private endpoint on and public access off (or restricted to named egress CIDRs), `audit` and `authenticator` logging on with retention, and a supported version. An AWS-owned key on 1.28+ is acceptable unless the client's standard requires a CMK.

#### Automated coverage

Security Hub CSPM **EKS.1** (public endpoint), **EKS.2** (cluster version), **EKS.8** (audit logging), **EKS.9** (node group version); EKS.3 (secrets encryption) was scheduled for retirement after 10 August 2026. Prowler: `eks_cluster_not_publicly_accessible`, `eks_cluster_private_nodes_enabled`, `eks_control_plane_logging_all_types_enabled`, `eks_cluster_kms_cmk_encryption_in_secrets_enabled`, `eks_cluster_uses_a_supported_version`. kube-bench `eks-1.8.0` 2.1.1 (audit logs), 5.3.1 (CMK), 5.4.1 to 5.4.3 (endpoint and private nodes).

#### Detection

CloudTrail `UpdateClusterConfig` (endpoint access and logging changes), `AssociateEncryptionConfig`, `CreateCluster`; KMS `DisableKey`/`ScheduleKeyDeletion` on the cluster CMK. GuardDuty EKS Protection: `Discovery:Kubernetes/SuccessfulAnonymousAccess`, `Policy:Kubernetes/AnonymousAccessGranted`, `CredentialAccess:Kubernetes/MaliciousIPCaller`, `Discovery:Kubernetes/TorIPCaller`. Verifying that logging cannot be turned off quietly belongs with the [CloudTrail note](/cloud/aws-cloudtrail-logging/).

### GT-AWS-CNT-9: EKS authentication with access entries and aws-auth

*Guler Tech methodology.*

#### What it checks

Every path from an IAM principal to Kubernetes permissions: the authentication mode, access entries and their policies and scopes, the `aws-auth` ConfigMap, the cluster creator's rights, and which IAM principals can grant themselves access through the EKS API.

#### Prerequisites

`eks:ListAccessEntries`, `eks:DescribeAccessEntry`, `eks:ListAssociatedAccessPolicies` (in `SecurityAudit` at the time of writing; otherwise request them), Kubernetes read access to `kube-system` ConfigMaps and RBAC objects.

#### Steps

1. Access entries and associated policies:

   ```bash
   C=prod-eks
   aws eks describe-cluster --name $C --query 'cluster.accessConfig'
   for p in $(aws eks list-access-entries --cluster-name $C --query 'accessEntries[]' --output text); do
     aws eks describe-access-entry --cluster-name $C --principal-arn "$p" \
       --query 'accessEntry.{p:principalArn,type:type,user:username,groups:kubernetesGroups}' --output json
     aws eks list-associated-access-policies --cluster-name $C --principal-arn "$p" \
       --query 'associatedAccessPolicies[].{policy:policyArn,scope:accessScope}' --output json
   done
   ```

   Flag: `AmazonEKSClusterAdminPolicy` at cluster scope beyond one break-glass role; `kubernetesGroups` containing `system:masters`; entries for IAM *users*; principals in accounts the client does not own; entries for deleted roles (harmless now, dangerous if someone recreates the name, so remove them); the creator entry (often a CI role) left in place.
2. The `aws-auth` ConfigMap (if `authenticationMode` is not `API`):

   ```bash
   kubectl -n kube-system get configmap aws-auth -o json | jq -r '.data.mapRoles, .data.mapUsers, .data.mapAccounts'
   ```

   Flag `system:masters` mappings, broad SSO permission-set roles (`AWSReservedSSO_*`) mapped to admin groups, `mapAccounts` (maps every principal of an account), and node roles reused for anything else. Then find who can edit it: RBAC subjects with `update`/`patch` on ConfigMaps in `kube-system` effectively control cluster admin.
3. Cluster creator: for `CONFIG_MAP` clusters, find the creating principal from CloudTrail `CreateCluster` (if within retention) or the IaC; that principal has `system:masters` invisibly. For newer modes, check whether the creator access entry was removed after bootstrap.
4. IAM-side escalation: who can call `eks:CreateAccessEntry`, `eks:AssociateAccessPolicy`, `eks:UpdateAccessEntry` or `eks:UpdateClusterConfig` on production clusters?

   ```bash
   aws iam simulate-principal-policy --policy-source-arn arn:aws:iam::111122223333:role/platform-readonly \
     --action-names eks:CreateAccessEntry eks:AssociateAccessPolicy eks:UpdateAccessEntry \
     --resource-arns arn:aws:eks:eu-west-2:111122223333:cluster/prod-eks \
     --query 'EvaluationResults[].{a:EvalActionName,d:EvalDecision}' --output table
   ```

   Also check SCPs for a guardrail on these actions ([organisations note](/cloud/aws-organizations-multi-account-security/)).
5. In-cluster RBAC tie-in: list `ClusterRoleBindings` to `cluster-admin` and any binding to `system:anonymous`, `system:unauthenticated` or `system:authenticated`:

   ```bash
   kubectl get clusterrolebindings -o json | jq -r '.items[] | select(.roleRef.name=="cluster-admin" or
     ([.subjects[]?.name] | any(. == "system:anonymous" or . == "system:unauthenticated" or . == "system:authenticated")))
     | .metadata.name + " -> " + ([.subjects[]? | .kind + ":" + .name] | join(", "))'
   ```

#### Observation

```text
auth: CONFIG_MAP, bootstrapClusterCreatorAdminPermissions: true
mapRoles: rolearn arn:aws:iam::111122223333:role/AWSReservedSSO_Developers_EXAMPLE  groups [system:masters]
access policy check: role/platform-readonly -> eks:CreateAccessEntry allowed, eks:AssociateAccessPolicy allowed (policy "EKSFullAccess": eks:*)
clusterrolebinding legacy-dashboard -> ServiceAccount:kubernetes-dashboard (cluster-admin)
```

#### Evaluation

**Fail** if cluster-admin (via `system:masters` or `AmazonEKSClusterAdminPolicy` at cluster scope) is held by broad human groups, IAM users, or foreign accounts; if non-admin IAM principals can create access entries or associate access policies; if any binding grants more than discovery to unauthenticated or all authenticated users. **Fail (medium)** for `CONFIG_MAP`-only clusters with an unknown creator principal. **Pass** for `API` mode, a single break-glass admin entry, team access through namespace-scoped policies or RBAC groups, creator admin removed, and EKS access-management actions limited to a platform role and guarded by SCP.

#### Automated coverage

No Security Hub CSPM control evaluates access entries or `aws-auth`. kube-bench `eks-1.8.0` 4.1.1 (cluster-admin use), 4.1.7 (Cluster Access Manager API), 4.1.8 (bind, impersonate, escalate). MKAT and CloudFox `eks` help enumerate.

#### Detection

CloudTrail `CreateAccessEntry`, `AssociateAccessPolicy`, `UpdateAccessEntry`, `DeleteAccessEntry`, `UpdateClusterConfig` (authentication mode). Kubernetes audit log: `update`/`patch` on `configmaps/aws-auth`, `create` of `clusterrolebindings`. GuardDuty: `PrivilegeEscalation:Kubernetes/AnomalousBehavior.RoleBindingCreated`, `Policy:Kubernetes/AdminAccessToDefaultServiceAccount`, `Policy:Kubernetes/AnonymousAccessGranted`. ATT&CK T1098.006 (Additional Container Cluster Roles).

### GT-AWS-CNT-10: IRSA trust policies and Pod Identity associations

*Guler Tech methodology.*

#### What it checks

Whether each IAM role usable by pods can be assumed only by the intended service account in the intended namespace and cluster, and what those roles grant.

#### Prerequisites

`SecurityAudit`, `eks:ListPodIdentityAssociations`, `eks:DescribePodIdentityAssociation`, Kubernetes read of ServiceAccounts.

#### Steps

1. IRSA: find roles trusting each cluster's OIDC issuer and print their conditions:

   ```bash
   ISSUER=$(aws eks describe-cluster --name prod-eks --query 'cluster.identity.oidc.issuer' --output text | sed 's|^https://||')
   for role in $(aws iam list-roles --query "Roles[?contains(to_string(AssumeRolePolicyDocument), '$ISSUER')].RoleName" --output text); do
     aws iam get-role --role-name "$role" --query 'Role.AssumeRolePolicyDocument' --output json |
     jq -c --arg role "$role" '.Statement[] | select([.Action] | flatten | index("sts:AssumeRoleWithWebIdentity")) |
       {role: $role, ops: (.Condition // {} | keys),
        sub: [.Condition // {} | .[] | to_entries[] | select(.key | endswith(":sub")) | .value],
        aud: [.Condition // {} | .[] | to_entries[] | select(.key | endswith(":aud")) | .value]}'
   done
   ```

   Flag: no `:sub` key at all (any service account in the cluster); `StringLike` with `system:serviceaccount:*` or `system:serviceaccount:<ns>:*` where the namespace is shared or tenants can create service accounts; `sub` naming a namespace or service account that does not exist (anyone who can create it gets the role). A missing `:aud` is lower risk because STS also validates the audience against the OIDC provider's client ID list, but keep it in the trust policy.
2. Also search for trust policies naming OIDC providers of **other** clusters or other accounts, and old clusters' providers that still exist (`aws iam list-open-id-connect-providers`).
3. Pod Identity: list associations and review each role's trust and permissions:

   ```bash
   aws eks list-pod-identity-associations --cluster-name prod-eks \
     --query 'associations[].{ns:namespace,sa:serviceAccount,id:associationId}' --output table
   aws eks describe-pod-identity-association --cluster-name prod-eks --association-id a-abcdefghijklmnop1 \
     --query 'association.{role:roleArn,target:targetRoleArn,tags:disableSessionTags}'
   ```

   The default trust (`pods.eks.amazonaws.com`, no conditions) lets any cluster in the account use the role once someone creates an association. Check whether trust policies pin `aws:RequestTag/eks-cluster-arn`, `kubernetes-namespace` and `kubernetes-service-account`, and who holds `eks:CreatePodIdentityAssociation` plus `iam:PassRole` for those roles.
4. Rate the blast radius by what each role can do (`simulate-principal-policy`, PMapper). Operator roles (External Secrets, Crossplane, cluster-autoscaler, load balancer controller, Karpenter) are the usual high-value targets.
5. Cross-check with `mkat eks find-role-relationships`, which maps service accounts to assumable roles for both mechanisms.
6. **Lab or explicitly approved only:** to prove a wildcard IRSA trust, create a service account in an approved test namespace, run a pod using it, call `aws sts get-caller-identity` from the pod and record the assumed-role ARN. Delete both afterwards.

#### Observation

```json
{"role":"external-secrets-irsa","ops":["StringLike"],"sub":["system:serviceaccount:*:*"],"aud":["sts.amazonaws.com"]}
{"role":"s3-reader-irsa","ops":["StringEquals"],"sub":[],"aud":["sts.amazonaws.com"]}
```

#### Evaluation

**Fail** if any IRSA role lacks a `sub` condition or uses a wildcard that admits service accounts outside the intended workload, or if Pod Identity roles with sensitive permissions are associable by principals beyond the platform team. Severity follows the role's permissions. **Pass** when every IRSA trust uses `StringEquals` on both `sub` (exact namespace and service account) and `aud`, Pod Identity trusts are pinned with session-tag conditions or association rights are tightly controlled, and each application has its own role.

#### Automated coverage

None in Security Hub CSPM. Prowler's IAM trust checks catch some cross-account issues but not IRSA `sub` scoping. kube-bench `eks-1.8.0` 5.2.1 (dedicated EKS service accounts).

#### Detection

CloudTrail `AssumeRoleWithWebIdentity` (the `subjectFromWebIdentityToken` field shows the service account), `AssumeRoleForPodIdentity`, `CreatePodIdentityAssociation`, `UpdatePodIdentityAssociation`, `UpdateAssumeRolePolicy`. Kubernetes audit: `create` of `serviceaccounts` and `serviceaccounts/token`.

### GT-AWS-CNT-11: Workload access to IMDS and credential endpoints

*Guler Tech methodology.*

#### What it checks

Whether code running in a container (or an SSRF in it) can reach the EC2 instance metadata service and obtain the node or container-instance role, and whether ECS credential and metadata endpoints are reachable from application-controlled requests.

#### Prerequisites

Static part: `SecurityAudit`. Dynamic part: **lab or explicitly approved only**, with a named test namespace or task, a pinned test image, and agreement that the proof stops at the role *name*.

#### Steps

1. Static: IMDS settings of nodes and container instances.

   ```bash
   aws ec2 describe-instances --filters Name=tag:eks:cluster-name,Values=prod-eks \
     --query 'Reservations[].Instances[].{id:InstanceId,tokens:MetadataOptions.HttpTokens,hop:MetadataOptions.HttpPutResponseHopLimit,ep:MetadataOptions.HttpEndpoint}' --output table
   aws ec2 describe-launch-template-versions --launch-template-id lt-0abcd1234example --versions '$Latest' \
     --query 'LaunchTemplateVersions[].LaunchTemplateData.MetadataOptions'
   ```

   For EKS pods, `HttpTokens=required` and `HttpPutResponseHopLimit=1` block IMDSv2 from pod network namespaces; a hop limit of 2 (common in eksctl and older templates) or `optional` tokens do not. Pods with `hostNetwork: true` bypass the hop limit; list them with `kubectl get pods -A -o json | jq -r '.items[] | select(.spec.hostNetwork==true) | .metadata.namespace + "/" + .metadata.name'`. For ECS on EC2, check `ECS_AWSVPC_BLOCK_IMDS` and the bridge-mode `iptables` rule (GT-AWS-CNT-6).
2. Static: Kubernetes NetworkPolicies or security-group-for-pods rules that deny egress to `169.254.169.254/32` (`kubectl get networkpolicy -A -o yaml | grep -n 169.254.169.254`), and whether the VPC CNI's network policy enforcement is on.
3. **Lab or explicitly approved only (EKS):** a throwaway pod in the agreed namespace, on a normal node, without `hostNetwork`:

   ```bash
   kubectl -n gt-test run imds-check --rm -i --restart=Never --image=<approved-curl-image@sha256:digest> -- sh -c '
     TOKEN=$(curl -s -m 3 -X PUT http://169.254.169.254/latest/api/token -H "X-aws-ec2-metadata-token-ttl-seconds: 60");
     echo "IMDSv2 token length: ${#TOKEN}";
     curl -s -m 3 -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/; echo;
     curl -s -m 3 -o /dev/null -w "IMDSv1 status: %{http_code}\n" http://169.254.169.254/latest/meta-data/'
   ```

   The `security-credentials/` listing returns only the **role name**; do not request `security-credentials/<role>`. MKAT's `mkat eks test-imds-access` automates a similar test but retrieves credentials, so use it only where the client accepts that.
4. **Lab or explicitly approved only (ECS):** via ECS Exec into an agreed test task (or the app's own SSRF, if that is in scope), request `http://169.254.170.2/v2/metadata` (task metadata, no credentials) and the IMDS role listing as above. On Fargate, IMDS should not answer.
5. **SSRF in the application** (in-scope web test): the benign proofs are `http://169.254.170.2/v2/metadata` (ECS awsvpc/Fargate), `http://169.254.169.254/latest/meta-data/iam/security-credentials/` (EC2 or EKS node with IMDSv1), and a check whether the SSRF can set headers or use `PUT` (needed for IMDSv2). Then check whether the app also leaks its environment (error pages, debug endpoints, `file://` support): `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`, `AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE`, `AWS_WEB_IDENTITY_TOKEN_FILE` turn the SSRF into task-role or pod-role credentials. Report the chain; do not fetch the credentials.

#### Observation

```text
i-0abc...  tokens=optional  hop=2  ep=enabled
IMDSv2 token length: 56
eks-prod-nodegroup-NodeInstanceRole-EXAMPLE
IMDSv1 status: 200
```

#### Evaluation

**Fail** if a non-`hostNetwork` pod, an ECS container on EC2, or an application SSRF can list the node or container-instance role through IMDS (v1 or v2). The node role is never "just the node": it pulls every image, often modifies network interfaces (`AmazonEKS_CNI_Policy`), and lets its holder act as the node in the cluster. **Fail** if an SSRF plus environment disclosure reaches task-role or pod-role credentials. **Pass** if IMDS times out or refuses from workload network namespaces, IMDSv1 is disabled, `hostNetwork` pods are limited to system DaemonSets, ECS IMDS blocking is configured on EC2 container instances, or the workloads run on Fargate.

#### Automated coverage

Security Hub CSPM **EC2.8** (instances require IMDSv2; CIS AWS Foundations v5.0.0 5.7, v3.0.0 5.6) and **EC2.170** (launch templates require IMDSv2). Neither checks the hop limit. Prowler EC2 IMDS checks; Datadog's Cloud Security Atlas entry "EKS cluster allows pods to steal worker nodes' AWS credentials" describes the condition.

#### Detection

GuardDuty `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS` and `.InsideAWS` (instance or task credentials used elsewhere), `UnauthorizedAccess:Runtime/MetadataDNSRebind` (Runtime Monitoring). CloudTrail calls by the node role that nodes never make (`s3:ListBuckets`, `iam:*`, `sts:GetCallerIdentity` from a pod IP outside normal patterns). VPC Flow Logs cannot see IMDS traffic.

### GT-AWS-CNT-12: In-cluster posture with kube-bench, RBAC, PSS and GuardDuty

*Guler Tech methodology.*

#### What it checks

A proportionate in-cluster baseline: CIS Amazon EKS Benchmark items via kube-bench, high-risk RBAC, Pod Security Standards enforcement, Kubernetes Secrets usage, add-on identities and versions, and whether GuardDuty EKS Protection and Runtime Monitoring cover the cluster.

#### Prerequisites

Read access (`AmazonEKSAdminViewPolicy`); for kube-bench, approval to run a Job (it creates a pod with `hostPID` and read-only host mounts on one node).

#### Steps

1. **Explicitly approved only:** run kube-bench with the EKS benchmark as a Job (based on `job-eks.yaml` in the repository; push the image to the client's ECR rather than pulling from Docker Hub if egress is restricted):

   ```bash
   kubectl -n gt-test apply -f job-eks.yaml        # set --benchmark to the newest eks-* config, eks-1.8.0 at the time of writing
   kubectl -n gt-test wait --for=condition=complete job/kube-bench --timeout=180s
   kubectl -n gt-test logs job/kube-bench > kube-bench-prod-eks.txt
   kubectl -n gt-test delete job kube-bench
   grep -E '^\[(FAIL|WARN)\]' kube-bench-prod-eks.txt
   ```

   Many EKS items in sections 4 and 5 are `Manual`; tests GT-AWS-CNT-8 to 11 cover the AWS-side ones properly.
2. RBAC: who can read Secrets, create pods, exec, impersonate, bind or escalate? `kubectl auth can-i --list --as=system:serviceaccount:<ns>:<sa>` for workload service accounts, and the bindings query in GT-AWS-CNT-9. Remember that `AmazonEKSEditPolicy` and `AmazonEKSAdminPolicy` include Secrets read and `pods/exec`, so they are not security boundaries from cluster admin-equivalent workloads in the same namespace.
3. Pod Security Standards: namespaces without an `enforce` label, and privileged workloads that exist anyway:

   ```bash
   kubectl get ns -o json | jq -r '.items[] | .metadata.name + "\t" + (.metadata.labels["pod-security.kubernetes.io/enforce"] // "none")'
   kubectl get pods -A -o json | jq -r '.items[] | select([.spec.containers[].securityContext.privileged] | any) |
     .metadata.namespace + "/" + .metadata.name'
   ```

   Also look for `hostPath` volumes, `hostPID`, `hostNetwork` outside `kube-system`, and `automountServiceAccountToken` left on for workloads that never call the API.
4. Secrets: `mkat eks find-secrets` (AWS keys in ConfigMaps, Secrets and pod specs); environment variables populated from Secrets versus mounted files (kube-bench 4.4.1).
5. Add-ons: versions and identities.

   ```bash
   for a in $(aws eks list-addons --cluster-name prod-eks --query 'addons[]' --output text); do
     aws eks describe-addon --cluster-name prod-eks --addon-name "$a" \
       --query 'addon.{name:addonName,ver:addonVersion,irsa:serviceAccountRoleArn,podid:podIdentityAssociations}' --output json
   done
   ```

   `vpc-cni` without its own IRSA or Pod Identity role means the CNI permissions sit on the node role (and with GT-AWS-CNT-11, on every pod).
6. GuardDuty coverage:

   ```bash
   DET=$(aws guardduty list-detectors --query 'DetectorIds[0]' --output text)
   aws guardduty get-detector --detector-id "$DET" --query 'Features[].{name:Name,status:Status,extra:AdditionalConfiguration}'
   ```

   Look for `EKS_AUDIT_LOGS` and `RUNTIME_MONITORING` enabled, with agent management for EKS (and for ECS Fargate and EC2 if those run containers). Organisation-wide configuration is covered in the [detection services note](/cloud/aws-detection-posture-services/).

#### Observation

```text
[FAIL] 4.1.1 Ensure that the cluster-admin role is only used where required (Automated)
[FAIL] 4.2.1 Minimize the admission of privileged containers (Automated)
default     none
payments    none
monitoring/node-exporter-x7k2p  privileged
vpc-cni  v1.18.x  irsa=null  podid=null
EKS_AUDIT_LOGS ENABLED, RUNTIME_MONITORING DISABLED
```

#### Evaluation

**Fail** per kube-bench item with a demonstrated consequence (rate by the consequence, not the item count); **fail** if application namespaces have no PSS enforcement and privileged or host-namespace pods exist outside system components; **fail** if GuardDuty EKS Protection is off for production clusters. **Fail (low)** for outdated add-ons and CNI permissions on the node role without IMDS exposure. **Pass** with `restricted` or `baseline` enforcement on application namespaces, no unexpected privileged workloads, Secrets mounted as files or sourced from Secrets Manager, and GuardDuty audit-log and runtime coverage.

#### Automated coverage

kube-bench (CIS Amazon EKS Benchmark, `eks-1.8.0` config: 4.1.x RBAC, 4.2.x Pod Security, 4.3.x CNI and network policies, 4.4.x secrets). Prowler `eks_cluster_network_policy_enabled`, `eks_cluster_vpc_cni_network_policy_enforced`. No Security Hub CSPM control checks in-cluster posture; GuardDuty findings flow into Security Hub.

#### Detection

GuardDuty EKS Protection: `Execution:Kubernetes/ExecInKubeSystemPod`, `Execution:Kubernetes/AnomalousBehavior.ExecInPod`, `PrivilegeEscalation:Kubernetes/AnomalousBehavior.WorkloadDeployed!PrivilegedContainer`, `Persistence:Kubernetes/AnomalousBehavior.WorkloadDeployed!ContainerWithSensitiveMount`, `CredentialAccess:Kubernetes/AnomalousBehavior.SecretsAccessed`, `Discovery:Kubernetes/AnomalousBehavior.PermissionChecked`, `Policy:Kubernetes/ExposedDashboard`. Runtime Monitoring findings as in GT-AWS-CNT-6. GuardDuty disablement (`DeleteDetector`, `UpdateDetector` turning features off) should be blocked by SCP and alerted.

## Hardening

**ECR: repository policy limited to the organisation.** Grant pull to the organisation, never to a bare wildcard; push only from the CI role:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "OrgPull",
      "Effect": "Allow",
      "Principal": "*",
      "Action": ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer", "ecr:BatchCheckLayerAvailability"],
      "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-exampleorgid"} }
    },
    {
      "Sid": "CiPush",
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::111122223333:role/ci-image-publisher"},
      "Action": ["ecr:PutImage", "ecr:InitiateLayerUpload", "ecr:UploadLayerPart", "ecr:CompleteLayerUpload", "ecr:BatchCheckLayerAvailability"]
    }
  ]
}
```

**ECR: data-perimeter RCP.** ECR and ECR Public support resource control policies, so a single RCP stops any repository in member accounts from being readable or writable outside the organisation, whatever its own policy says (test on one OU first; AWS service principals are exempted by the second condition):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "EcrOrgOnly",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "ecr:*",
      "Resource": "*",
      "Condition": {
        "StringNotEqualsIfExists": {"aws:PrincipalOrgID": "o-exampleorgid"},
        "BoolIfExists": {"aws:PrincipalIsAWSService": "false"}
      }
    }
  ]
}
```

**ECR: registry and repository defaults in Terraform.**

```hcl
resource "aws_ecr_registry_scanning_configuration" "this" {
  scan_type = "ENHANCED"
  rule {
    scan_frequency = "CONTINUOUS_SCAN"
    repository_filter {
      filter      = "*"
      filter_type = "WILDCARD"
    }
  }
}

resource "aws_ecr_repository" "payments_api" {
  name                 = "payments-api"
  image_tag_mutability = "IMMUTABLE"
  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = aws_kms_key.ecr.arn
  }
}

resource "aws_ecr_lifecycle_policy" "payments_api" {
  repository = aws_ecr_repository.payments_api.name
  policy = jsonencode({
    rules = [{
      rulePriority = 1
      description  = "Expire untagged images after 14 days"
      selection    = { tagStatus = "untagged", countType = "sinceImagePushed", countUnit = "days", countNumber = 14 }
      action       = { type = "expire" }
    }]
  })
}
```

Add a repository creation template for every pull-through cache prefix so cached repositories inherit scanning, lifecycle and a restrictive policy. Build images with BuildKit secret mounts and multi-stage builds, and run a secret scanner (trufflehog, gitleaks) on the built image in CI before push ([CI/CD note](/cloud/aws-cicd-iac-security/)). Deploy by digest.

**ECS: task definition baseline (CloudFormation).**

```yaml
TaskDefinition:
  Type: AWS::ECS::TaskDefinition
  Properties:
    Family: payments-api
    RequiresCompatibilities: [FARGATE]
    NetworkMode: awsvpc
    Cpu: "512"
    Memory: "1024"
    ExecutionRoleArn: !GetAtt PaymentsExecutionRole.Arn
    TaskRoleArn: !GetAtt PaymentsTaskRole.Arn
    ContainerDefinitions:
      - Name: app
        Image: 111122223333.dkr.ecr.eu-west-2.amazonaws.com/payments-api@sha256:<digest>
        User: "10001"
        ReadonlyRootFilesystem: true
        Privileged: false
        LinuxParameters:
          Capabilities:
            Drop: [ALL]
        Secrets:
          - Name: DB_PASSWORD
            ValueFrom: !Ref PaymentsDbSecret
        LogConfiguration:
          LogDriver: awslogs
          Options:
            awslogs-group: /ecs/payments-api
            awslogs-region: eu-west-2
            awslogs-stream-prefix: app
```

Give the execution role `secretsmanager:GetSecretValue` on that secret ARN only, and the task role only what the app calls. Task role trust:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Service": "ecs-tasks.amazonaws.com"},
    "Action": "sts:AssumeRole",
    "Condition": {
      "ArnLike": {"aws:SourceArn": "arn:aws:ecs:eu-west-2:111122223333:*"},
      "StringEquals": {"aws:SourceAccount": "111122223333"}
    }
  }]
}
```

On EC2 launch type: `ECS_AWSVPC_BLOCK_IMDS=true` in `/etc/ecs/ecs.config`, the `DOCKER-USER` drop rule for bridge mode, IMDSv2 required in the launch template, and the container instance role limited to `AmazonEC2ContainerServiceforEC2Role`. Prefer Fargate where isolation between tasks matters.

**ECS Exec guardrails.** Deny launching tasks with Exec in production and restrict who may exec (SCP or permission boundary):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "NoExecEnabledTasksInProd",
      "Effect": "Deny",
      "Action": ["ecs:RunTask", "ecs:StartTask", "ecs:CreateService", "ecs:UpdateService"],
      "Resource": "*",
      "Condition": {"StringEquals": {"ecs:enable-execute-command": "true", "aws:ResourceTag/environment": "prod"} }
    },
    {
      "Sid": "ExecOnlyBreakGlass",
      "Effect": "Deny",
      "Action": "ecs:ExecuteCommand",
      "Resource": "*",
      "Condition": {"ArnNotLike": {"aws:PrincipalArn": "arn:aws:iam::*:role/break-glass-ecs"} }
    }
  ]
}
```

Where Exec stays, set the cluster's `executeCommandConfiguration` to `OVERRIDE` with an encrypted log group and bucket, keep `script` in images, and deny `ssm:StartSession` on `arn:aws:ecs:*:*:task/*`.

**EKS cluster settings (Terraform).**

```hcl
resource "aws_eks_cluster" "prod" {
  name     = "prod-eks"
  role_arn = aws_iam_role.cluster.arn
  version  = "1.34"

  vpc_config {
    subnet_ids              = var.private_subnet_ids
    endpoint_private_access = true
    endpoint_public_access  = false
  }

  access_config {
    authentication_mode                         = "API"
    bootstrap_cluster_creator_admin_permissions = false
  }

  enabled_cluster_log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]

  encryption_config {
    provider { key_arn = aws_kms_key.eks.arn }
    resources = ["secrets"]
  }
}

resource "aws_eks_access_entry" "breakglass" {
  cluster_name  = aws_eks_cluster.prod.name
  principal_arn = "arn:aws:iam::111122223333:role/eks-break-glass"
}

resource "aws_eks_access_policy_association" "breakglass" {
  cluster_name  = aws_eks_cluster.prod.name
  principal_arn = aws_eks_access_entry.breakglass.principal_arn
  policy_arn    = "arn:aws:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"
  access_scope { type = "cluster" }
}

resource "aws_launch_template" "nodes" {
  name_prefix = "prod-eks-nodes-"
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }
}
```

If public access must stay on, set `public_access_cidrs` to the client's egress ranges and turn on the private endpoint so node traffic stays in the VPC. Set `bootstrap_cluster_creator_admin_permissions = false` only if another admin entry is created in the same apply, or you lock yourself out.

**SCP: keep EKS access management with the platform team.**

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "EksAccessMgmtPlatformOnly",
    "Effect": "Deny",
    "Action": [
      "eks:CreateAccessEntry", "eks:UpdateAccessEntry", "eks:AssociateAccessPolicy",
      "eks:CreatePodIdentityAssociation", "eks:UpdatePodIdentityAssociation", "eks:UpdateClusterConfig"
    ],
    "Resource": "*",
    "Condition": {"ArnNotLike": {"aws:PrincipalArn": ["arn:aws:iam::*:role/eks-platform-admin", "arn:aws:iam::*:role/ci-eks-deployer"]} }
  }]
}
```

**IRSA and Pod Identity trust.** IRSA: `StringEquals` on `<issuer>:sub` with the exact `system:serviceaccount:<namespace>:<name>` and on `<issuer>:aud` with `sts.amazonaws.com` (the AWS-documented pattern shown in GT-AWS-CNT-10). Pod Identity: pin the generic trust with session tags:

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Service": "pods.eks.amazonaws.com"},
    "Action": ["sts:AssumeRole", "sts:TagSession"],
    "Condition": {
      "StringEquals": {
        "aws:RequestTag/eks-cluster-arn": "arn:aws:eks:eu-west-2:111122223333:cluster/prod-eks",
        "aws:RequestTag/kubernetes-namespace": "payments",
        "aws:RequestTag/kubernetes-service-account": "payments-api"
      }
    }
  }]
}
```

Give `vpc-cni` its own IRSA or Pod Identity role and remove `AmazonEKS_CNI_Policy` from the node role where your node bootstrap allows it.

**In-cluster baseline.** Label application namespaces `pod-security.kubernetes.io/enforce: restricted` (or `baseline` where `restricted` breaks a workload, with an exception list), turn on VPC CNI network policy enforcement and add a default-deny egress policy that excludes `169.254.169.254/32`, set `automountServiceAccountToken: false` on service accounts that never call the API, and remove `cluster-admin` bindings to workload service accounts.

**Config and detection.** AWS Config rules `ecr-private-image-scanning-enabled`, `ecr-private-tag-immutability-enabled`, `ecs-containers-nonprivileged`, `ecs-no-environment-secrets`, `eks-endpoint-no-public-access`, `eks-cluster-log-enabled` (these back the Security Hub controls above). Enable GuardDuty EKS Protection and Runtime Monitoring organisation-wide, send Inspector critical findings for deployed images to the owning team, and alert on the CloudTrail events listed under each test.

## Real-world cases

- **SCARLETEEL (Sysdig, February 2023).** Attackers compromised a public-facing service in a self-managed Kubernetes cluster on AWS, read the worker's IAM role credentials from IMDSv1, used them to enumerate the account, and moved on to credentials in Lambda environment variables and Terraform state in S3, stealing proprietary data. It is GT-AWS-CNT-11 and GT-AWS-CNT-4 in one chain. [Sysdig write-up](https://sysdig.com/blog/cloud-breach-terraform-data-theft/).
- **ECR Public Gallery flaw (Lightspin, December 2022).** Researcher Gafnit Amiga found undocumented internal ECR Public API actions that let any AWS account delete or overwrite images, layers and tags in other accounts' public repositories, including widely used images. AWS fixed it within a day and found no misuse beyond the researcher's own accounts. It shows why consumers should pin digests and verify signatures rather than trust a tag. [The Hacker News coverage](https://thehackernews.com/2022/12/serious-attacks-could-have-been-staged.html).
- **Attacking and securing cloud identities in EKS (Datadog Security Labs, 2023, updated 2024).** Christophe Tafani-Dereeper documents SSRF from a pod to node credentials via IMDS, using node credentials to impersonate pods, IRSA token theft through file read, and the invisible cluster-creator admin under `aws-auth`. [Article](https://securitylabs.datadoghq.com/articles/amazon-eks-attacking-securing-cloud-identities/); the tooling is [MKAT](https://github.com/datadog/managed-kubernetes-auditing-toolkit).
- **New attack vectors in EKS (Wiz, February 2024).** Analysis of access entries and Pod Identity: `CreateAccessEntry` plus `AssociateAccessPolicy` as an IAM-to-cluster-admin path, `AmazonEKSEditPolicy` not being a security boundary, and a `hostNetwork` pod intercepting other pods' Pod Identity credentials on the same node. [Wiz research](https://www.wiz.io/blog/new-attack-vectors-emerge-via-recent-eks-access-entries-and-pod-identity-features).

More incidents and write-ups across the series are collected in [AWS security incidents and write-ups](/cloud/aws-security-incidents-and-writeups/).

## Rating findings

| Finding | Typical severity | Reasoning |
|---|---|---|
| ECR repository policy allows push to `*` (no org condition) | Critical | Any AWS account can replace images that production pulls by tag: code execution in your workloads with their task and pod roles, from an unauthenticated-equivalent position. |
| ECR repository policy allows pull to `*`, or internal images in ECR Public | High (Medium if images hold nothing sensitive) | Source, configuration and any baked secrets are readable by anyone with an AWS account. Rate up if GT-AWS-CNT-3 finds secrets. |
| Live credentials in image layers | High; Critical if the image is pullable outside the organisation and the secret grants production admin | Everyone with pull rights holds the secret, deletions in later layers do not help, and rotation is often forgotten because "it is in a private registry". |
| No scanning on deployed images, or critical CVEs with fixes open past SLA | Medium | No direct path by itself; raises likelihood of exploitation of public-facing containers. High if a known-exploited CVE is in an internet-facing service. |
| Mutable tags, no lifecycle, pull-through cache without template | Low | Hygiene; matters when combined with weak push controls. |
| Plaintext secrets in ECS `environment` | Medium; High for production database or payment credentials | Readable by every principal with `DescribeTaskDefinition` (common in read-only roles), persisted in all revisions and often in IaC state. |
| Task role equals execution role, or wildcard secret or data access on task roles | Medium to High | Any app bug (SSRF with env leak, RCE, dependency compromise) inherits every secret and dataset the role reaches. High when demonstrated with GT-AWS-CNT-11. |
| Low-privileged principal can pass a powerful task role into a new task | High to Critical | Classic escalation (`iam:PassRole` + `RegisterTaskDefinition` + `RunTask`); Critical if the role is admin-equivalent. |
| Privileged, host-PID or `docker.sock` containers on EC2 launch type | High | Container compromise becomes instance compromise: instance role, every co-located task's credentials and data. |
| Root user, writable root filesystem, no logging configuration | Low | Defence in depth; eases exploitation and hinders investigation without creating a path. |
| ECS Exec enabled in production, broad `ExecuteCommand`, no session logging | Medium (High if any developer role can exec into payment or identity services) | Root shell in production for a wide group, with only a CloudTrail record that a session happened. |
| EKS public endpoint open to `0.0.0.0/0` | Medium | Authentication still applies; exposure magnifies leaked kubeconfigs and tokens and pre-auth bugs. Critical if anonymous requests reach more than discovery. |
| Control-plane `audit` logging off, or GuardDuty EKS Protection off in production | Medium | Missing detection and forensics; no path on its own. |
| Cluster admin held by broad SSO groups, IAM users or foreign accounts, or invisible creator admin | High | Large or unaccountable population with full cluster control, hence all pod identities and Secrets. |
| Non-admin IAM principals can create access entries or associate access policies | High | Direct IAM-to-cluster-admin escalation that bypasses Kubernetes RBAC entirely. |
| IRSA role trust without `sub` or with wildcard | High (Medium if the role is low privilege) | Any pod, including one an attacker or tenant can create, assumes the role. |
| Pods or app SSRF can reach node IMDS and list the node role | High | Node role credentials: image pulls, network-interface changes, node impersonation in the cluster; frequently the first step in public cluster compromises. |
| SSRF plus environment disclosure reaches ECS task or EKS pod credentials | High to Critical | Unauthenticated internet to AWS credentials; severity follows the role. |
| No Pod Security enforcement with privileged pods present outside system namespaces | Medium | Lowers the bar from pod compromise to node compromise. |
| CMK not used for EKS envelope encryption (1.28+) | Info or Low | Data is already envelope-encrypted with an AWS-owned key; only a finding where policy requires customer-controlled keys. |

## Mapping

| Test | Security Hub CSPM | CIS (version) | MITRE ATT&CK |
|---|---|---|---|
| GT-AWS-CNT-1 | None (Access Analyzer covers sharing) | Not covered by CIS AWS Foundations; CIS EKS (kube-bench `eks-1.8.0`) 5.1.2 | T1525, T1078.004 |
| GT-AWS-CNT-2 | ECR.1, ECR.2, ECR.3, ECR.5 | CIS EKS 5.1.1, 5.1.4 | T1525, T1204.003 |
| GT-AWS-CNT-3 | None | None | T1552.001 |
| GT-AWS-CNT-4 | ECS.8 | None | T1552 |
| GT-AWS-CNT-5 | None | None | T1078.004 |
| GT-AWS-CNT-6 | ECS.2, ECS.3, ECS.4, ECS.5, ECS.9, ECS.10, ECS.16, ECS.17, ECS.20 | None | T1611, T1610 |
| GT-AWS-CNT-7 | None | None | T1609 |
| GT-AWS-CNT-8 | EKS.1, EKS.2, EKS.8, EKS.9 (EKS.3 retired) | CIS EKS 2.1.1, 5.3.1, 5.4.1, 5.4.2, 5.4.3 | T1133, T1685.002 (formerly T1562.008) |
| GT-AWS-CNT-9 | None | CIS EKS 4.1.1, 4.1.7, 4.1.8 | T1098.006, T1078.004 |
| GT-AWS-CNT-10 | None | CIS EKS 5.2.1 | T1528, T1550.001, T1078.004 |
| GT-AWS-CNT-11 | EC2.8, EC2.170 | CIS AWS Foundations v5.0.0 5.7, v3.0.0 5.6 (EC2.8) | T1552.005 |
| GT-AWS-CNT-12 | None (GuardDuty findings flow in) | CIS EKS 4.1.x, 4.2.x, 4.3.x, 4.4.1 | T1613, T1610, T1609 |

CIS EKS item numbers are as implemented in kube-bench's `eks-1.8.0` configuration; check them against your licensed copy of the CIS Amazon EKS Benchmark before quoting them in a report.

## References

- AWS Security Hub CSPM controls: [Amazon ECR](https://docs.aws.amazon.com/securityhub/latest/userguide/ecr-controls.html), [Amazon ECS](https://docs.aws.amazon.com/securityhub/latest/userguide/ecs-controls.html), [Amazon EKS](https://docs.aws.amazon.com/securityhub/latest/userguide/eks-controls.html), [Amazon EC2](https://docs.aws.amazon.com/securityhub/latest/userguide/ec2-controls.html), [controls change log](https://docs.aws.amazon.com/securityhub/latest/userguide/controls-change-log.html), [CIS AWS Foundations Benchmark in Security Hub CSPM](https://docs.aws.amazon.com/securityhub/latest/userguide/cis-aws-foundations-benchmark.html)
- Amazon ECR: [private repository policies](https://docs.aws.amazon.com/AmazonECR/latest/userguide/repository-policies.html), [repository policy examples](https://docs.aws.amazon.com/AmazonECR/latest/userguide/repository-policy-examples.html), [image scanning](https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-scanning.html), [tag mutability](https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-tag-mutability.html), [lifecycle policies](https://docs.aws.amazon.com/AmazonECR/latest/userguide/LifecyclePolicies.html), [pull through cache](https://docs.aws.amazon.com/AmazonECR/latest/userguide/pull-through-cache.html), [ECR Public repositories](https://docs.aws.amazon.com/AmazonECR/latest/public/public-repositories.html)
- Amazon ECS: [task IAM role](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-iam-roles.html), [task execution IAM role](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_execution_IAM_role.html), [passing sensitive data](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/specifying-sensitive-data.html), [task metadata endpoint v4](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-metadata-endpoint-v4.html), [task metadata endpoint v2](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-metadata-endpoint-v2.html), [ECS Exec](https://docs.aws.amazon.com/AmazonECS/latest/developerguide/ecs-exec.html)
- AWS SDKs: [container credential provider](https://docs.aws.amazon.com/sdkref/latest/guide/feature-container-credentials.html)
- Amazon EKS: [cluster API server endpoint](https://docs.aws.amazon.com/eks/latest/userguide/cluster-endpoint.html), [grant IAM principals access](https://docs.aws.amazon.com/eks/latest/userguide/grant-k8s-access.html), [access entries](https://docs.aws.amazon.com/eks/latest/userguide/access-entries.html), [creating access entries](https://docs.aws.amazon.com/eks/latest/userguide/creating-access-entries.html), [access policy permissions](https://docs.aws.amazon.com/eks/latest/userguide/access-policy-permissions.html), [CreateAccessConfigRequest](https://docs.aws.amazon.com/eks/latest/APIReference/API_CreateAccessConfigRequest.html), [IRSA](https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html), [assigning IRSA roles](https://docs.aws.amazon.com/eks/latest/userguide/associate-service-account-role.html), [Pod Identity](https://docs.aws.amazon.com/eks/latest/userguide/pod-identities.html), [how Pod Identity works](https://docs.aws.amazon.com/eks/latest/userguide/pod-id-how-it-works.html), [Pod Identity trust policy](https://docs.aws.amazon.com/eks/latest/userguide/pod-id-role.html), [Pod Identity session tags](https://docs.aws.amazon.com/eks/latest/userguide/pod-id-abac.html), [default envelope encryption](https://docs.aws.amazon.com/eks/latest/userguide/envelope-encryption.html), [control plane logs](https://docs.aws.amazon.com/eks/latest/userguide/control-plane-logs.html), [add-ons](https://docs.aws.amazon.com/eks/latest/userguide/eks-add-ons.html), [EKS best practices: identity and access management](https://docs.aws.amazon.com/eks/latest/best-practices/identity-and-access-management.html)
- Amazon GuardDuty: [EKS Protection](https://docs.aws.amazon.com/guardduty/latest/ug/kubernetes-protection.html), [EKS Protection finding types](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty-finding-types-eks-audit-logs.html), [Runtime Monitoring](https://docs.aws.amazon.com/guardduty/latest/ug/runtime-monitoring.html), [Runtime Monitoring finding types](https://docs.aws.amazon.com/guardduty/latest/ug/findings-runtime-monitoring.html)
- AWS Organizations: [resource control policies](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_rcps.html)
- Kubernetes: [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- MITRE ATT&CK: [Containers matrix](https://attack.mitre.org/matrices/enterprise/containers/), [T1552.005 Cloud Instance Metadata API](https://attack.mitre.org/techniques/T1552/005/), [T1098.006 Additional Container Cluster Roles](https://attack.mitre.org/techniques/T1098/006/)
- Tools: [Prowler](https://github.com/prowler-cloud/prowler), [kube-bench](https://github.com/aquasecurity/kube-bench), [MKAT](https://github.com/datadog/managed-kubernetes-auditing-toolkit), [CloudFox](https://github.com/BishopFox/cloudfox), [Pacu](https://github.com/RhinoSecurityLabs/pacu), [trufflehog](https://github.com/trufflesecurity/trufflehog), [dive](https://github.com/wagoodman/dive), [CloudGoat](https://github.com/RhinoSecurityLabs/cloudgoat)
- Research: [Sysdig, SCARLETEEL](https://sysdig.com/blog/cloud-breach-terraform-data-theft/), [Datadog Security Labs, attacking and securing cloud identities in EKS](https://securitylabs.datadoghq.com/articles/amazon-eks-attacking-securing-cloud-identities/), [Datadog Security Labs, EKS Pod Identity deep dive](https://securitylabs.datadoghq.com/articles/eks-pod-identity-deep-dive/), [Datadog Cloud Security Atlas, EKS pods can steal node credentials](https://securitylabs.datadoghq.com/cloud-security-atlas/vulnerabilities/eks-pods-can-steal-host-credentials/), [Wiz, new attack vectors in EKS](https://www.wiz.io/blog/new-attack-vectors-emerge-via-recent-eks-access-entries-and-pod-identity-features)
- Related notes in this series: [EC2, IMDS, EBS and SSM](/cloud/aws-ec2-imds-ebs-ssm-security/), [IAM privilege escalation](/cloud/aws-iam-privilege-escalation/), [Secrets Manager, Parameter Store and KMS](/cloud/aws-secrets-manager-parameter-store-kms/), [VPC, edge and DNS](/cloud/aws-vpc-edge-dns-security/), [CI/CD and IaC](/cloud/aws-cicd-iac-security/), [detection and posture services](/cloud/aws-detection-posture-services/), [CloudTrail](/cloud/aws-cloudtrail-logging/)
