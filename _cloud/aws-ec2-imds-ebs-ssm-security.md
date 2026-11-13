---
title: "Amazon EC2 Security: IMDS, EBS, AMIs and Systems Manager"
date: 2026-11-12 18:05:00 +0000
subcategory: aws
summary: "Testing EC2 the way attackers use it: IMDS credential theft, user data secrets, public snapshots and AMIs, and Systems Manager as a remote shell."
refs: [EC2.8, EC2.170, EC2.7, EC2.3, EC2.1, EC2.182, EC2.9, EC2.25, EC2.53, EC2.54, SSM.1, SSM.4, SSM.6, SSM.7, "CIS AWS v3.0.0 5.6", "CIS AWS v5.0.0 5.7", "CIS AWS v3.0.0 2.2.1", "CIS AWS v5.0.0 5.1.1", T1552.005, T1078.004, T1552.001, T1537, T1578.001, T1525, T1651, T1021.007, T1021.008, T1098.004]
tags: [aws, ec2, imds, ebs, systems-manager, ssrf]
---

This note is part of our [AWS security testing guide](/cloud/aws-security-testing-guide/) and covers the compute layer most AWS estates still run on: EC2 instances, the instance metadata service (IMDS) that hands them credentials, the EBS volumes, snapshots and AMIs that hold their disks, and AWS Systems Manager (SSM), which turns every managed instance into something an API caller can run commands on. These are the places where a web bug becomes a cloud breach. A server-side request forgery on an instance with IMDSv1 and a broad role is an account compromise; a public snapshot is a copy of a server's disk, `/etc/shadow` and deployment keys included; an `ssm:SendCommand` permission is root on every managed instance it covers. The checks below are mostly read-only and fast. The care goes into knowing what each setting really prevents (IMDSv2 stops most SSRF, not code execution), which defaults changed and when, and how to tell a hygiene gap from a path to the crown jewels.

## Contents

- [How it works](#how-it-works)
  - [Instance profiles and how credentials reach the instance](#instance-profiles-and-how-credentials-reach-the-instance)
  - [IMDSv1 and IMDSv2](#imdsv1-and-imdsv2)
  - [Account-level IMDS defaults, enforcement and policy keys](#account-level-imds-defaults-enforcement-and-policy-keys)
  - [User data and launch templates](#user-data-and-launch-templates)
  - [EBS encryption, snapshots and AMIs](#ebs-encryption-snapshots-and-amis)
  - [Getting a shell: key pairs, Instance Connect, serial console and Session Manager](#getting-a-shell-key-pairs-instance-connect-serial-console-and-session-manager)
  - [Systems Manager as a control plane](#systems-manager-as-a-control-plane)
  - [Nitro Enclaves](#nitro-enclaves)
- [What goes wrong](#what-goes-wrong)
- [Testing](#testing)
  - [Before you start](#before-you-start)
  - [GT-AWS-EC2-1: IMDS configuration sweep across Regions](#gt-aws-ec2-1-imds-configuration-sweep-across-regions)
  - [GT-AWS-EC2-2: Instances with admin-level instance profiles](#gt-aws-ec2-2-instances-with-admin-level-instance-profiles)
  - [GT-AWS-EC2-3: Secrets in user data and launch templates](#gt-aws-ec2-3-secrets-in-user-data-and-launch-templates)
  - [GT-AWS-EC2-4: Public and externally shared EBS snapshots](#gt-aws-ec2-4-public-and-externally-shared-ebs-snapshots)
  - [GT-AWS-EC2-5: Public and shared AMIs, and AMI provenance](#gt-aws-ec2-5-public-and-shared-amis-and-ami-provenance)
  - [GT-AWS-EC2-6: EBS encryption by default and unencrypted volumes](#gt-aws-ec2-6-ebs-encryption-by-default-and-unencrypted-volumes)
  - [GT-AWS-EC2-7: Systems Manager coverage, session logging and shared documents](#gt-aws-ec2-7-systems-manager-coverage-session-logging-and-shared-documents)
  - [GT-AWS-EC2-8: Who can run commands on instances](#gt-aws-ec2-8-who-can-run-commands-on-instances)
  - [GT-AWS-EC2-9: Instance exposure, key pairs and remote access settings](#gt-aws-ec2-9-instance-exposure-key-pairs-and-remote-access-settings)
  - [GT-AWS-EC2-10: SSRF reachability of IMDS from an in-scope application](#gt-aws-ec2-10-ssrf-reachability-of-imds-from-an-in-scope-application)
- [Hardening](#hardening)
- [Real-world cases](#real-world-cases)
- [Rating findings](#rating-findings)
- [Mapping](#mapping)
- [References](#references)

## How it works

### Instance profiles and how credentials reach the instance

An EC2 instance gets AWS permissions through an **instance profile**, a container that holds exactly one IAM role. When you attach the profile, EC2 assumes the role on the instance's behalf and publishes short-lived credentials (access key ID, secret, session token) in the instance metadata service at:

```text
http://169.254.169.254/latest/meta-data/iam/security-credentials/<role-name>
```

The SDKs and the CLI find them there automatically through the default credential chain, and EC2 rotates them before they expire. Three things about this mechanism matter for testing:

- **Anything that can make an HTTP request from the instance can get the credentials.** The IMDS is a link-local HTTP endpoint (`169.254.169.254`, and `[fd00:ec2::254]` on Nitro instances when the IPv6 endpoint is enabled). There is no OS-level authentication: any process, any container that can reach the address, and any server-side request forgery in an application running on the box.
- **The credentials work from anywhere.** They are ordinary STS session credentials. The role session name is the instance ID, so in CloudTrail the caller appears as `arn:aws:sts::111122223333:assumed-role/<role>/i-0123456789abcdef0`. Nothing stops them being used from an attacker's laptop unless you add conditions (see [Hardening](#hardening)) or detect it (GuardDuty, below).
- **Attaching a role is a privileged act.** Launching an instance with a profile, or swapping one onto a running instance (`ec2:AssociateIamInstanceProfile`, `ec2:ReplaceIamInstanceProfileAssociation`), requires `iam:PassRole` on the role. "Who can pass which role to EC2" is a classic escalation path covered in the [privilege escalation note](/cloud/aws-iam-privilege-escalation/).

Separately, every instance also has an **instance identity role** whose credentials appear under `/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance`. AWS features such as EC2 Instance Connect and Systems Manager's default host management use it to identify the instance. It is not your application role, but do not ignore it when you inventory what the IMDS exposes.

### IMDSv1 and IMDSv2

**IMDSv1** is a plain request/response service: `GET /latest/meta-data/...` returns the value. Any request that reaches the address is answered. That is why a server-side request forgery that only lets an attacker choose a URL is enough to steal role credentials.

**IMDSv2** (November 2019) makes every interaction session-oriented:

1. The client sends `PUT /latest/api/token` with the header `X-aws-ec2-metadata-token-ttl-seconds` (up to 21600 seconds, six hours) and gets a token back.
2. Every subsequent `GET` must carry `X-aws-ec2-metadata-token: <token>`.

```bash
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

The design defeats the common SSRF and proxy cases in three ways, as AWS described when it launched the feature:

- **A `PUT` with a custom header is required.** Most SSRF primitives (an image fetcher, a webhook URL, a PDF renderer, an XXE) can only issue `GET` requests with headers the attacker does not control.
- **Token requests carrying `X-Forwarded-For` are refused.** Open reverse proxies and misconfigured WAFs normally add that header, so they cannot be used as relays.
- **The token response has an IP TTL (hop limit) of 1 by default.** If the instance is misconfigured as a router, NAT or VPN, the response dies before it leaves the host. The token is also bound to the instance it was issued on.

What IMDSv2 does **not** do: it does not protect against an attacker who already has code execution on the instance, or against a "full" SSRF where the attacker controls the method and headers (some HTTP client libraries exposed through an API, or a request-smuggling primitive). It also does nothing about **user data**, which is served from the same service. Treat IMDSv2 as removing the cheapest path, not as making instance credentials safe.

The **hop limit** (`HttpPutResponseHopLimit`) needs a sentence of its own. With a limit of 1, a container on a bridged Docker network cannot get a token, because the extra network hop exhausts the TTL. AWS therefore recommends 2 for hosts that run containers, and the account-level IMDSv2 default sets 2. On container hosts this is a trade-off: a hop limit of 2 lets every container reach the node's role. On EKS and ECS, give workloads their own credentials (EKS Pod Identity or IRSA, ECS task roles) and block pod access to the node's IMDS; see the [containers note](/cloud/aws-containers-ecs-eks-ecr-security/).

### Account-level IMDS defaults, enforcement and policy keys

The instance's metadata options are decided at launch from several layers, and the history matters when you explain a finding:

| Layer | Setting | Notes |
|---|---|---|
| Launch parameters / launch template | `MetadataOptions.HttpTokens`, `HttpPutResponseHopLimit`, `HttpEndpoint`, `InstanceMetadataTags` | Explicit values win over everything below. |
| AMI | `ImdsSupport: v2.0` | Instances launched from the AMI get `HttpTokens=required` and a hop limit of 2. Cannot be undone on that AMI. Current Amazon Linux 2023 AMIs ship with it; check others. |
| Account default (per Region) | `aws ec2 modify-instance-metadata-defaults --http-tokens required` | Applies to *new* launches only; existing instances are untouched. Available since 2024. |
| Account enforcement (per Region) | `--http-tokens-enforced enabled` | Newer: launches that would end up with IMDSv1 enabled fail, and IMDSv1 cannot be re-enabled on existing instances that have it off. Check the current docs for availability. |
| Declarative policy (Organizations) | `ec2_attributes.instance_metadata_defaults` | Sets the account defaults across accounts and Regions; `get-instance-metadata-defaults` then shows `"ManagedBy": "declarative-policy"` and local changes are blocked. |

IAM gives you three condition keys to enforce the same thing at the API layer, usable in SCPs:

- `ec2:MetadataHttpTokens` on `ec2:RunInstances`: deny unless `required`.
- `ec2:Attribute/HttpTokens` on `ec2:ModifyInstanceMetadataOptions`: deny turning IMDSv1 back on.
- `ec2:MetadataHttpPutResponseHopLimit` (numeric) and `ec2:MetadataHttpEndpoint`.

And one key that works on the **use** of the credentials rather than the launch: `ec2:RoleDelivery`. It is present on requests signed with EC2 role credentials and carries the IMDS version that delivered them (`1.0` or `2.0`). A deny on `NumericLessThan ec2:RoleDelivery 2.0` makes credentials fetched through IMDSv1 useless even on instances that still allow IMDSv1. That is the fastest way to remove the SSRF-to-credentials path in a large estate while application teams migrate.

Before anyone enforces IMDSv2, they need to know who still calls IMDSv1. Every instance publishes two CloudWatch metrics in `AWS/EC2`: `MetadataNoToken` (IMDSv1 calls answered) and `MetadataNoTokenRejected` (IMDSv1 calls refused after you required IMDSv2). AWS also publishes an open-source IMDS Packet Analyzer that names the process making the calls.

### User data and launch templates

**User data** is the script or cloud-init document passed at launch. It is stored as an instance attribute, served to the instance through the IMDS at `/latest/user-data`, and readable through the API by anyone with `ec2:DescribeInstanceAttribute`. It is base64-encoded, limited to 16 KB, frequently gzip-compressed by tooling, and is not included in an AMI created from the instance. It is not a secret store, yet it is where bootstrap scripts put database passwords, registration tokens, private keys and, still, long-lived access keys.

**Launch templates** (and the legacy Auto Scaling launch configurations) carry the same user data plus the metadata options, network interfaces and instance profile for every instance an Auto Scaling group will ever create. A template with `HttpTokens=optional` or a secret in its user data reproduces the problem every time the group scales. Readable with `ec2:DescribeLaunchTemplateVersions`, which read-only policies grant widely.

### EBS encryption, snapshots and AMIs

**EBS encryption by default** is a per-Region account setting (`aws ec2 get-ebs-encryption-by-default`). When on, every new volume and snapshot copy is encrypted with the default KMS key for EBS: the AWS managed key `aws/ebs` unless you set a customer managed key. It does not encrypt existing volumes. The choice of key has security consequences beyond "encrypted or not":

- A snapshot encrypted with the **AWS managed key** cannot be shared with another account at all.
- A snapshot encrypted with a **customer managed key** can be shared, but the recipient also needs `kms:Decrypt`/`CreateGrant` on that key through its key policy. The key policy, not the snapshot permission, is the real control.
- **Encrypted snapshots cannot be made public.** Public exposure is only possible for unencrypted snapshots.

**Snapshot sharing** is controlled by the `createVolumePermission` attribute: a list of account IDs, or the group `all` (public). A public snapshot is a full block-level copy of the disk that anyone can turn into a volume and mount, including deleted files still present in unallocated blocks. **Block public access for EBS snapshots** (per Region, since late 2023) has two modes: `block-all-sharing` (existing public snapshots stop being public) and `block-new-sharing`. It does not stop private sharing with specific accounts, and it does not cover AMIs.

**AMIs** have their own `launchPermission` attribute (account IDs, organisation or OU ARNs, or public). Sharing an EBS-backed AMI also lets the recipient create volumes from its snapshots, so a public AMI is a public disk even when snapshot BPA is on. **Block public access for AMIs** is enabled by default for new accounts and for existing accounts that had no public AMIs (AWS's cut-off date is 15 July 2023); accounts that had public AMIs have it off until someone turns it on.

On the consuming side, AMI selection is a supply-chain question. Code that looks up "the newest image named `ubuntu-*`" without an owner filter can pick up an attacker's public AMI (Datadog's "whoAMI" research, below). **Allowed AMIs** (December 2024) is an account-level allow list of image providers, with an audit mode, also settable by declarative policy.

### Getting a shell: key pairs, Instance Connect, serial console and Session Manager

There are four ways in, and each has a different trust model:

| Method | Authorisation | Network path | Audit trail |
|---|---|---|---|
| **SSH/RDP with an EC2 key pair** | Possession of the private key (and, for Windows, the decrypted Administrator password via `ec2:GetPasswordData`) | Inbound 22/3389 from wherever the security group allows | Only OS logs; nothing in CloudTrail for the login itself |
| **EC2 Instance Connect** | IAM: `ec2-instance-connect:SendSSHPublicKey` (condition `ec2:osuser`) pushes a key valid for 60 seconds | Still SSH to the instance, or through an **EC2 Instance Connect Endpoint** (`ec2-instance-connect:OpenTunnel`, conditions `remotePort`, `privateIpAddress`, `maxTunnelDuration`) | `SendSSHPublicKey` / `OpenTunnel` in CloudTrail |
| **EC2 serial console** | Account-level switch (`get-serial-console-access-status`, off by default) plus `ec2-instance-connect:SendSerialConsoleSSHPublicKey`; a password-based OS user for Linux | Out of band; security groups and NACLs do not apply | `SendSerialConsoleSSHPublicKey` in CloudTrail |
| **Systems Manager Session Manager** | IAM: `ssm:StartSession` on the instance and the session document | Outbound HTTPS from the SSM Agent; no inbound ports | `StartSession` in CloudTrail; session content in S3/CloudWatch Logs if configured |

Key pairs are the weakest: a private key outlives the person who had it, is copied into CI systems and laptops, and cannot be tied to an IAM identity. Session Manager is the strongest default, because access is an IAM decision, there is no inbound port, and the session content can be logged. It is also the most powerful lateral-movement tool in the account, which is the next section.

### Systems Manager as a control plane

An instance becomes a **managed node** when the SSM Agent runs on it and its instance role (or the account's Default Host Management Configuration) allows it to register. From then on, AWS API calls translate directly into commands executed as `root` / `SYSTEM`:

- `ssm:SendCommand` with `AWS-RunShellScript` or `AWS-RunPowerShellScript` runs arbitrary commands on any targeted instance, by ID or by tag.
- `ssm:StartSession` opens an interactive shell; `AWS-StartPortForwardingSession` and `AWS-StartPortForwardingSessionToRemoteHost` tunnel to the instance or *through it* to anything it can reach.
- `ssm:CreateAssociation` (State Manager) runs a document on a schedule; Automation runbooks run with their own assume role.

So `ssm:SendCommand` on `*` is equivalent to code execution on every managed instance, and therefore to every instance role's permissions. That is why we treat it as a privilege escalation and lateral movement primitive (MITRE [T1651 Cloud Administration Command](https://attack.mitre.org/techniques/T1651/)); see the [privilege escalation note](/cloud/aws-iam-privilege-escalation/) for the permission combinations.

Two more SSM features carry their own risks. **SSM documents** you own can be shared with specific accounts or publicly (`ModifyDocumentPermission` with `all`), and an account-level **block public sharing** setting (`/ssm/documents/console/public-sharing-permission`) prevents new public shares. **Parameter Store** holds configuration and `SecureString` secrets that instance roles often read with broad `ssm:GetParameter*` permissions; that is covered in the [secrets note](/cloud/aws-secrets-manager-parameter-store-kms/).

**Session logging** is configured through the account's Session Manager preferences, stored as a document named `SSM-SessionManagerRunShell` in each Region, with inputs `s3BucketName`, `s3EncryptionEnabled`, `cloudWatchLogGroupName`, `cloudWatchEncryptionEnabled`, `cloudWatchStreamingEnabled`, `kmsKeyId` (encrypts session data in transit between client and node), `runAsEnabled`, `idleSessionTimeout` and `maxSessionDuration`. Two limitations: sessions that use **port forwarding or SSH over Session Manager are not logged** (the SSM channel only carries an encrypted tunnel), and logging is per Region.

### Nitro Enclaves

A Nitro Enclave is an isolated VM carved out of an instance's CPU and memory, with no network, no persistent storage and no interactive access, even for root on the parent. It talks to the parent only over a vsock. Its main security property is **attestation**: KMS key policies can require that only an enclave with a specific image hash can decrypt, using condition keys such as `kms:RecipientAttestation:ImageSha384` and `kms:RecipientAttestation:PCR0`…`PCR8`. When a client says "the keys are in an enclave", check the key policy for those conditions; without them, the parent instance's role can decrypt directly and the enclave adds nothing. Debug-mode enclaves produce all-zero PCRs and should never satisfy a production key policy.

## What goes wrong

**IMDSv1 still enabled.** Instances launched before the account default was set, from old AMIs, by old launch templates or by Auto Scaling groups pinned to `$Latest` of a template nobody updated. With an SSRF in any application on the instance, the role credentials are one `GET` away. This is the Capital One path.

**Broad instance roles.** `AdministratorAccess`, `PowerUserAccess`, `s3:*` on `*`, or `iam:PassRole` plus `ec2:RunInstances` on a web-facing instance. The role's permissions are what any code on the instance, or any SSRF, can exercise. A web server rarely needs more than a few named resources.

**Credentials usable from anywhere.** No `ec2:RoleDelivery`, `aws:Ec2InstanceSourceVpc` or network conditions, and no GuardDuty, so a stolen instance credential works from the internet for hours without anyone noticing.

**Secrets in user data and launch templates.** Database passwords, API tokens, Git deploy keys and IAM access keys in bootstrap scripts. They are readable by anyone with read-only EC2 permissions, by every process on the instance, and through any SSRF (user data is served by the IMDS and is not credential-gated beyond the IMDSv2 token).

**Public or externally shared snapshots and AMIs.** Snapshots made public "to copy to another account", AMIs published for a partner and never withdrawn, sharing with personal or ex-vendor accounts. The disk contains whatever the server had: keys, `.env` files, database files, shell history.

**Unencrypted EBS, or encryption with the wrong key.** Default encryption off in some Regions, so new volumes are created unencrypted; or everything encrypted with `aws/ebs`, which is fine for confidentiality at rest but means the snapshot sharing control is all-or-nothing and there is no key policy to scope who can decrypt.

**Untrusted AMIs.** Instances launched from community AMIs selected by name without an owner filter, or from marketplace images nobody reviewed.

**Unmanaged and unlogged access.** Long-lived SSH key pairs and `0.0.0.0/0` on port 22 instead of Session Manager; Session Manager enabled without logging, or logging to a bucket the session users can delete from; SSM documents shared publicly or containing credentials.

**Over-broad command execution rights.** `ssm:SendCommand`, `ssm:StartSession` or `ec2-instance-connect:SendSSHPublicKey` on `*` for developer roles, so any developer (or anyone who phishes one) has a root shell on production instances and their roles. Serial console enabled account-wide with broad `SendSerialConsoleSSHPublicKey`.

**Enclave theatre.** Nitro Enclaves deployed, but KMS key policies that do not check attestation, so the parent can decrypt.

## Testing

Every test below assumes an **authorised** engagement against the client's own AWS accounts, with written scope, and respects AWS's [penetration testing policy](https://aws.amazon.com/security/penetration-testing/). The default is read-only. Commands that change state are marked **lab or explicitly approved only**. Outputs shown are **illustrative**, not from a real account.

### Before you start

**Credentials.** A role with the AWS managed `SecurityAudit` policy plus `ViewOnlyAccess` covers almost everything here. At the time of writing `SecurityAudit` grants `ec2:Describe*` (which includes `DescribeInstanceAttribute` for user data and `DescribeLaunchTemplateVersions`), `ssm:Describe*`, `ssm:ListDocuments` and `ssm:GetServiceSetting`, but **not** `ssm:GetDocument`, which you need to read Session Manager preferences and document content; ask for it as a small inline addition. Some organisations also strip user data access from auditor roles, so check with `simulate-principal-policy` before you start rather than concluding "no user data" from an `AccessDenied`. You do **not** need `ssm:SendCommand`, `ssm:StartSession` or any Instance Connect permission for these tests.

```bash
export AWS_PROFILE=client-audit
aws sts get-caller-identity
aws iam simulate-principal-policy \
  --policy-source-arn "$(aws sts get-caller-identity --query Arn --output text | sed 's#:sts:#:iam:#;s#assumed-role/\([^/]*\)/.*#role/\1#')" \
  --action-names ec2:DescribeInstanceAttribute ec2:DescribeLaunchTemplateVersions ssm:GetDocument ssm:DescribeDocumentPermission \
  --query 'EvaluationResults[].[EvalActionName,EvalDecision]' --output table
```

**Region loop.** EC2, EBS and SSM settings are per Region. Use the Regions enabled in the account, and keep the loop in a function you can reuse:

```bash
REGIONS=$(aws ec2 describe-regions --query 'Regions[].RegionName' --output text)
each_region() { for r in $REGIONS; do "$@" --region "$r" 2>/dev/null | sed "s/^/$r\t/"; done; }
```

**Tools.**

- [Prowler](https://github.com/prowler-cloud/prowler): `prowler aws --services ec2 ssm` runs every EC2/SSM check named below.
- [ScoutSuite](https://github.com/nccgroup/ScoutSuite) for a browsable report; [Steampipe](https://hub.steampipe.io/plugins/turbot/aws) when you want SQL across Regions (`aws_ec2_instance`, `aws_ebs_snapshot`, `aws_ssm_managed_instance`).
- [CloudFox](https://github.com/BishopFox/cloudfox): `cloudfox aws instances` (instances, public IPs, roles), `cloudfox aws env-vars`, `cloudfox aws permissions`.
- [Pacu](https://github.com/RhinoSecurityLabs/pacu) enumeration modules: `ec2__enum`, `ec2__download_userdata`, `ebs__enum_volumes_snapshots`.
- [PMapper](https://github.com/nccgroup/PMapper) for "who can reach this role / who can run commands" questions.
- [trufflehog](https://github.com/trufflesecurity/trufflehog) or [gitleaks](https://github.com/gitleaks/gitleaks) for secret scanning the user data you collect.

**Practice.** [CloudGoat](https://github.com/RhinoSecurityLabs/cloudgoat) scenarios such as `ec2_ssrf` and `cloud_breach_s3` reproduce the SSRF-to-IMDS path; [flaws.cloud](http://flaws.cloud/) level 4 (public snapshot) and level 5 (metadata through a proxy) and [flaws2.cloud](http://flaws2.cloud/) teach the same lessons in a browser.

### GT-AWS-EC2-1: IMDS configuration sweep across Regions

*Guler Tech methodology.*

#### What it checks

Whether every running instance, every launch template version in use and every account-level default requires IMDSv2, whether the hop limit is justified, and whether IMDSv1 is still being used (so you can tell the client what will break when they fix it).

#### Prerequisites

Read-only EC2 and CloudWatch permissions in every enabled Region; for organisation-level checks, read access to AWS Organizations from the management or delegated administrator account.

#### Steps

1. **Account defaults and enforcement per Region:**

   ```bash
   each_region aws ec2 get-instance-metadata-defaults \
     --query 'AccountLevel.[HttpTokens,HttpTokensEnforced,HttpPutResponseHopLimit,HttpEndpoint]' --output text
   each_region aws ec2 get-instance-metadata-defaults --query 'ManagedBy' --output text
   ```

2. **Every instance's live metadata options:**

   ```bash
   each_region aws ec2 describe-instances \
     --filters Name=instance-state-name,Values=running,stopped \
     --query 'Reservations[].Instances[].[InstanceId,State.Name,MetadataOptions.HttpTokens,MetadataOptions.HttpEndpoint,MetadataOptions.HttpPutResponseHopLimit,MetadataOptions.HttpProtocolIpv6,IamInstanceProfile.Arn]' \
     --output text | sort
   ```

   Stopped instances matter: they come back with the same settings.
3. **Launch templates** (the version Auto Scaling actually uses, and `$Latest`):

   ```bash
   for r in $REGIONS; do
     for lt in $(aws ec2 describe-launch-templates --region "$r" --query 'LaunchTemplates[].LaunchTemplateId' --output text); do
       aws ec2 describe-launch-template-versions --region "$r" --launch-template-id "$lt" \
         --versions '$Default' '$Latest' \
         --query 'LaunchTemplateVersions[].[LaunchTemplateName,VersionNumber,LaunchTemplateData.MetadataOptions.HttpTokens]' \
         --output text | sed "s/^/$r\t/"
     done
   done
   aws autoscaling describe-auto-scaling-groups --query 'AutoScalingGroups[].[AutoScalingGroupName,LaunchTemplate.Version,LaunchConfigurationName]' --output text
   ```

   A template version with no `MetadataOptions` prints `None`: the instance then inherits the AMI or account default, so evaluate it against step 1 and step 4. Auto Scaling groups still on launch configurations cannot be governed by the `RunInstances` IMDS policies and should be migrated.
4. **Your own AMIs:** `each_region aws ec2 describe-images --owners self --query 'Images[].[ImageId,Name,ImdsSupport]' --output text`.
5. **Who still uses IMDSv1** (per instance, last 14 days):

   ```bash
   aws cloudwatch get-metric-statistics --namespace AWS/EC2 --metric-name MetadataNoToken \
     --dimensions Name=InstanceId,Value=i-0123456789abcdef0 \
     --start-time "$(date -u -d '-14 days' +%FT%TZ)" --end-time "$(date -u +%FT%TZ)" \
     --period 86400 --statistics Sum --query 'Datapoints[].Sum'
   ```

6. **Organisation guardrails:** look for an SCP that conditions `ec2:RunInstances` on `ec2:MetadataHttpTokens` and a declarative policy for instance metadata:

   ```bash
   aws organizations list-policies --filter SERVICE_CONTROL_POLICY --query 'Policies[].[Id,Name]' --output text
   aws organizations describe-effective-policy --policy-type DECLARATIVE_POLICY_EC2 --target-id 111122223333
   ```

#### Observation

Illustrative output for a partly migrated account:

```text
eu-west-2   required   None       2   None
eu-west-2   account
us-east-1   None       None       None None
eu-west-2   i-0123456789abcdef0  running  optional  enabled  1  disabled  arn:aws:iam::111122223333:instance-profile/web-app
eu-west-2   i-0fedcba9876543210  running  required  enabled  2  disabled  arn:aws:iam::111122223333:instance-profile/ecs-node
eu-west-2   web-asg-lt   7   None
```

`i-0123456789abcdef0` still allows IMDSv1, and `us-east-1` has no account default at all.

#### Evaluation

- **Fail** if any running or stopped instance has `HttpTokens=optional` with `HttpEndpoint=enabled`. Severity depends on GT-AWS-EC2-2 (what the role can do) and on whether the instance runs anything that processes untrusted input (see [Rating findings](#rating-findings)).
- **Fail** if a launch template version used by an Auto Scaling group, or an AMI used for new launches, yields `optional`.
- **Fail (lower severity)** if an enabled Region has no account default of `required`, even with no instances today: the next launch there will allow IMDSv1.
- **Note** a hop limit above 1 on hosts that do not run containers, and any hop limit above 2; ask why. On container hosts, a hop limit of 2 is expected but means containers can reach the node role, which you then cover in the [containers note](/cloud/aws-containers-ecs-eks-ecr-security/).
- **Pass** when every Region has `HttpTokens=required` (ideally enforced or managed by a declarative policy), every instance and template is `required`, and `MetadataNoToken` is zero.
- A disabled endpoint (`HttpEndpoint=disabled`) passes but check that the instance still works as intended; user data and SSH keys from metadata are unavailable.

#### Automated coverage

Security Hub CSPM: **EC2.8** (instances use IMDSv2; CIS v3.0.0 5.6, v5.0.0 5.7), **EC2.170** (launch templates use IMDSv2). Prowler: `ec2_instance_imdsv2_enabled`, `ec2_instance_account_imdsv2_enabled`, `ec2_launch_template_imdsv2_required`. AWS Config: `ec2-imdsv2-check`, `ec2-launch-template-imdsv2-check`.

#### Detection

Changes: `ModifyInstanceMetadataOptions` (look at `requestParameters.httpTokens` = `optional`), `ModifyInstanceMetadataDefaults`, `CreateLaunchTemplateVersion`, `ModifyImageAttribute` with `imdsSupport`. Abuse: there is no CloudTrail event for an IMDS read; you see the stolen credentials being *used*. GuardDuty raises `UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration.OutsideAWS` (credentials used from outside AWS) and `.InsideAWS` (used from another AWS account), and `UnauthorizedAccess:EC2/MetadataDNSRebind` for DNS-rebinding attempts at the IMDS. ATT&CK [T1552.005](https://attack.mitre.org/techniques/T1552/005/).

### GT-AWS-EC2-2: Instances with admin-level instance profiles

*Guler Tech methodology.*

#### What it checks

The blast radius of a stolen instance credential: which instances carry roles with administrative or escalation-capable permissions, and which of those are reachable from the internet or run untrusted workloads.

#### Prerequisites

Read access to EC2 and IAM (`iam:GetInstanceProfile`, `iam:ListAttachedRolePolicies`, `iam:GetRolePolicy`, `iam:SimulatePrincipalPolicy`). PMapper and cloudsplaining are optional.

#### Steps

1. **Map instances to roles:**

   ```bash
   each_region aws ec2 describe-iam-instance-profile-associations \
     --query 'IamInstanceProfileAssociations[?State==`associated`].[InstanceId,IamInstanceProfile.Arn]' --output text
   aws iam get-instance-profile --instance-profile-name web-app --query 'InstanceProfile.Roles[].RoleName' --output text
   ```

2. **Read the role's policies:**

   ```bash
   ROLE=web-app-role
   aws iam list-attached-role-policies --role-name "$ROLE" --query 'AttachedPolicies[].PolicyArn' --output text
   for p in $(aws iam list-role-policies --role-name "$ROLE" --query 'PolicyNames[]' --output text); do
     aws iam get-role-policy --role-name "$ROLE" --policy-name "$p" --query 'PolicyDocument'
   done
   ```

3. **Ask the questions that matter with the simulator** (resource `*` is a coarse first pass; refine with real ARNs):

   ```bash
   aws iam simulate-principal-policy \
     --policy-source-arn arn:aws:iam::111122223333:role/web-app-role \
     --action-names iam:CreateAccessKey iam:AttachRolePolicy iam:PassRole ec2:RunInstances \
                    sts:AssumeRole ssm:SendCommand s3:GetObject secretsmanager:GetSecretValue kms:Decrypt \
     --query 'EvaluationResults[].[EvalActionName,EvalDecision]' --output table
   ```

4. **Graph it.** `pmapper --profile client-audit graph create`, then `pmapper --profile client-audit query -s 'preset privesc *'` lists principals, including instance roles, that can escalate to admin. Cloudsplaining (`cloudsplaining download` then `cloudsplaining scan`) flags privilege escalation, data exfiltration and resource exposure actions per role.
5. **Add exposure.** For each high-privilege instance, note whether it has a public IP (`PublicIpAddress`), sits behind an internet-facing load balancer (see the [network note](/cloud/aws-vpc-edge-dns-security/)), allows IMDSv1 (GT-AWS-EC2-1), or runs CI jobs, containers or other tenants' code.

#### Observation

A table per instance: role, effective dangerous actions, exposure, IMDS version. Illustrative:

```text
i-0123456789abcdef0  web-app-role   AdministratorAccess (attached)  public IP 203.0.113.10  IMDSv1 allowed
i-0fedcba9876543210  ci-runner-role iam:PassRole on *, ec2:RunInstances  private, runs PR builds  IMDSv2
```

#### Evaluation

- **Fail (Critical)**: an internet-facing instance with an administrative or escalation-capable role and IMDSv1 enabled. One SSRF away from account takeover.
- **Fail (High)**: the same role on an internet-facing or untrusted-workload instance with IMDSv2 (an RCE or full SSRF still yields admin), or any instance role that can escalate to admin (`iam:PassRole` + `ec2:RunInstances`, `iam:Attach*Policy`, `iam:CreateAccessKey`, `ssm:SendCommand` on `*`).
- **Fail (Medium)**: broad data access (`s3:*` on `*`, `secretsmanager:GetSecretValue` on `*`) on internal instances.
- **Pass**: roles scoped to named resources, no IAM write, no `PassRole`, and network or source conditions on use.

Common false positive: roles with `AmazonSSMManagedInstanceCore` attached look broad in naive scans (`ssm:*Message*`, `ec2messages:*`), but those actions only let the agent talk to SSM. They are not an escalation.

#### Automated coverage

Prowler: `ec2_instance_profile_attached`, `ec2_instance_internet_facing_with_instance_profile`, `iam_role_administratoraccess_policy`, `iam_policy_allows_privilege_escalation`. No single Security Hub CSPM control expresses "instance role too broad"; IAM controls such as IAM.1 cover full-admin customer policies.

#### Detection

`AssociateIamInstanceProfile`, `ReplaceIamInstanceProfileAssociation` and `RunInstances` with an `iamInstanceProfile` (who attached which role); GuardDuty `PrivilegeEscalation:IAMUser/AnomalousBehavior` (lists `AssociateIamInstanceProfile` among its APIs) and the `InstanceCredentialExfiltration` findings. In CloudTrail, alert on calls by `assumed-role/<instance role>/i-*` principals to IAM write APIs. ATT&CK [T1078.004](https://attack.mitre.org/techniques/T1078/004/).

### GT-AWS-EC2-3: Secrets in user data and launch templates

*Guler Tech methodology.*

#### What it checks

Credentials and other secrets embedded in instance user data, launch template versions and Auto Scaling launch configurations.

#### Prerequisites

`ec2:DescribeInstanceAttribute`, `ec2:DescribeLaunchTemplateVersions`, `autoscaling:DescribeLaunchConfigurations`. A local working directory you will delete at the end of the engagement; treat the collected data as client secrets.

#### Steps

1. **Collect instance user data** (decoded and, where needed, decompressed):

   ```bash
   mkdir -p ud && for r in $REGIONS; do
     for i in $(aws ec2 describe-instances --region "$r" --query 'Reservations[].Instances[].InstanceId' --output text); do
       aws ec2 describe-instance-attribute --region "$r" --instance-id "$i" --attribute userData \
         --query 'UserData.Value' --output text | grep -v '^None$' | base64 -d > "ud/$r-$i.bin" 2>/dev/null
       file "ud/$r-$i.bin" | grep -q gzip && gunzip -c "ud/$r-$i.bin" > "ud/$r-$i.txt" || mv "ud/$r-$i.bin" "ud/$r-$i.txt"
     done
   done
   find ud -size 0 -delete
   ```

   Pacu's `ec2__download_userdata` module does the same for instances and launch templates.
2. **Collect launch template and launch configuration user data:**

   ```bash
   aws ec2 describe-launch-template-versions --launch-template-id lt-0123456789abcdef0 --versions '$Latest' \
     --query 'LaunchTemplateVersions[].LaunchTemplateData.UserData' --output text | base64 -d > ud/lt-0123456789abcdef0.txt
   aws autoscaling describe-launch-configurations --query 'LaunchConfigurations[].[LaunchConfigurationName,UserData]' --output text
   ```

   Check old template versions too: secrets removed in version 9 are still in version 3, and every version stays readable.
3. **Scan:**

   ```bash
   trufflehog filesystem ud/ --no-update
   gitleaks dir ud/ --no-banner     # gitleaks v8.19+; older releases: gitleaks detect --no-git --source ud/
   grep -nEi '(password|passwd|secret|token|api[_-]?key|BEGIN [A-Z ]*PRIVATE KEY|aws_secret_access_key|AKIA|ASIA)' ud/*
   ```

4. **Read what the scanners do not understand.** Bootstrap scripts often pass secrets as arguments (`--token ...`, `mysql -p...`), write them into files (`cat > /etc/app.env <<EOF`), or pull them from somewhere (a bucket URL, an SSM parameter name). The last is good practice; note it as a pass.
5. **Leaked key handling.** If you find an AWS access key, stop at identification: record where it is, and only run `aws sts get-caller-identity` with it if the client approved that in writing. Report immediately so it can be rotated. Do not use it for anything else.

#### Observation

Illustrative, redacted:

```text
ud/eu-west-2-i-0123456789abcdef0.txt:14: export DB_PASSWORD='EXAMPLE-not-a-real-password'
ud/eu-west-2-i-0123456789abcdef0.txt:15: git clone https://deploy:<REDACTED>@git.example.com/app.git
```

#### Evaluation

- **Fail** if user data or any launch template version contains a usable credential: password, token, private key, cloud access key. Rate by what the credential opens, and remember that anyone with read-only EC2 access, every process on the instance and any SSRF that reaches the IMDS can read it.
- **Pass** if user data only references secrets by name and retrieves them at boot from Secrets Manager or Parameter Store using the instance role.
- False positives: example placeholders, public keys, hashes used for integrity checks, and agent registration values that are designed to be non-secret (check the vendor's documentation before reporting).

#### Automated coverage

Prowler: `ec2_instance_secrets_user_data`, `ec2_launch_template_no_secrets` (both use detect-secrets, so they miss custom formats). No Security Hub CSPM control at the time of writing.

#### Detection

`DescribeInstanceAttribute` with `requestParameters.attribute` = `userData` from unusual principals, in bulk; `DescribeLaunchTemplateVersions` sweeps; `ModifyInstanceAttribute` with `userData` (changing user data on a stopped instance is a code-execution primitive when the instance next starts with a "run every boot" configuration). ATT&CK [T1552.001](https://attack.mitre.org/techniques/T1552/001/) and [T1552.005](https://attack.mitre.org/techniques/T1552/005/).

### GT-AWS-EC2-4: Public and externally shared EBS snapshots

*Guler Tech methodology.*

#### What it checks

Snapshots that are public or shared with accounts outside the client's organisation, and whether block public access for snapshots is on.

#### Prerequisites

`ec2:DescribeSnapshots`, `ec2:DescribeSnapshotAttribute`, `ec2:GetSnapshotBlockPublicAccessState`; `organizations:ListAccounts` to tell internal from external account IDs.

#### Steps

1. **Block public access state per Region:**

   ```bash
   each_region aws ec2 get-snapshot-block-public-access-state --query 'State' --output text
   ```

2. **Public snapshots you own:**

   ```bash
   each_region aws ec2 describe-snapshots --owner-ids self --restorable-by-user-ids all \
     --query 'Snapshots[].[SnapshotId,VolumeId,Encrypted,StartTime,Description]' --output text
   ```

3. **Every share, public or private:**

   ```bash
   for r in $REGIONS; do
     for s in $(aws ec2 describe-snapshots --region "$r" --owner-ids self --query 'Snapshots[].SnapshotId' --output text); do
       aws ec2 describe-snapshot-attribute --region "$r" --snapshot-id "$s" --attribute createVolumePermission \
         --query 'CreateVolumePermissions[].[Group,UserId]' --output text | sed "s/^/$r\t$s\t/"
     done
   done
   aws organizations list-accounts --query 'Accounts[].Id' --output text   # from the management account
   ```

   For large estates, Pacu's `ebs__enum_volumes_snapshots` or a Steampipe query on `aws_ebs_snapshot` (column `create_volume_permissions`) is faster.
4. **For each external share,** record the recipient account, ask the client who it is, and check the snapshot's KMS key policy: for an encrypted snapshot, the recipient needs key access too, so the key policy tells you whether the share is actually usable.
5. **Do not mount** a client snapshot in your own account to "prove" exposure. The attribute is the evidence. If the client wants a demonstration of contents, do it in their account, in an isolated test VPC, with approval.

#### Observation

```text
eu-west-2   block-new-sharing
us-east-1   unblocked
us-east-1   snap-0123456789abcdef0  vol-0123456789abcdef0  False  2022-03-01T10:12:00Z  web01 pre-migration
us-east-1   snap-0123456789abcdef0  all
eu-west-2   snap-0aaaabbbbccccdddd0  None  444455556666
```

#### Evaluation

- **Fail (Critical by default)** for any public snapshot: anyone can create a volume from it. Downgrade only if the client demonstrates the content is genuinely non-sensitive (a deliberately published dataset).
- **Fail** for a share to an account outside the organisation that the client cannot identify and justify. Severity follows the data on the disk and whether the recipient can actually decrypt.
- **Fail (lower)** if snapshot BPA is `unblocked` in any enabled Region. `block-all-sharing` is the target; `block-new-sharing` is acceptable while known public shares are being retired.
- **Pass**: no public snapshots, every external share documented, BPA `block-all-sharing` in all Regions (ideally through a declarative policy).

#### Automated coverage

Security Hub CSPM: **EC2.1** (snapshots not publicly restorable), **EC2.182** (block public access enabled for EBS snapshots). Prowler: `ec2_ebs_public_snapshot`, `ec2_ebs_snapshot_account_block_public_access`, `ec2_ebs_snapshots_encrypted`. AWS Config: `ebs-snapshot-public-restorable-check`, `ebs-snapshot-block-public-access`.

#### Detection

`ModifySnapshotAttribute` with `createVolumePermission` add of group `all` or an unknown account ID; `DisableSnapshotBlockPublicAccess`; bursts of `CreateSnapshot`/`CopySnapshot` followed by sharing (GuardDuty `Exfiltration:IAMUser/AnomalousBehavior` names `CreateSnapshot` among its APIs). ATT&CK [T1537 Transfer Data to Cloud Account](https://attack.mitre.org/techniques/T1537/) and [T1578.001 Create Snapshot](https://attack.mitre.org/techniques/T1578/001/).

### GT-AWS-EC2-5: Public and shared AMIs, and AMI provenance

*Guler Tech methodology.*

#### What it checks

Two directions: AMIs the client publishes (public or shared outside the organisation, and the AMI block public access setting), and AMIs the client consumes (who owns the images running in the account, and whether IaC selects them safely).

#### Prerequisites

`ec2:DescribeImages`, `ec2:DescribeImageAttribute`, `ec2:GetImageBlockPublicAccessState`, `ec2:GetAllowedImagesSettings`; read access to the client's IaC repositories if in scope.

#### Steps

1. **Publishing side:**

   ```bash
   each_region aws ec2 get-image-block-public-access-state --query 'ImageBlockPublicAccessState' --output text
   each_region aws ec2 describe-images --owners self --filters Name=is-public,Values=true \
     --query 'Images[].[ImageId,Name,CreationDate]' --output text
   aws ec2 describe-image-attribute --image-id ami-0abcdef1234567890 --attribute launchPermission \
     --query 'LaunchPermissions[]'
   ```

   Launch permissions may name account IDs, `OrganizationArn` or `OrganizationalUnitArn`; only external account IDs and `Group: all` need follow-up.
2. **Consuming side: who owns what you run:**

   ```bash
   for r in $REGIONS; do
     ids=$(aws ec2 describe-instances --region "$r" --query 'Reservations[].Instances[].ImageId' --output text | tr '\t' '\n' | sort -u)
     [ -n "$ids" ] && aws ec2 describe-images --region "$r" --image-ids $ids \
       --query 'Images[].[ImageId,OwnerId,ImageOwnerAlias,Public,Name]' --output text | sed "s/^/$r\t/"
   done
   each_region aws ec2 get-allowed-images-settings
   ```

   Flag owners that are not the client's accounts, not `amazon`, and not a reviewed Marketplace vendor. Images that have been deregistered return nothing; record them as "unknown provenance". Datadog's [whoAMI-scanner](https://github.com/DataDog/whoAMI-scanner) automates this.
3. **IaC review** (if in scope): search for AMI lookups without an owner filter, the whoAMI pattern:

   ```bash
   grep -rnE 'data "aws_ami"' --include='*.tf' . -A12 | grep -vE 'owners|^--$' | head
   grep -rnE 'describe-images|DescribeImages|describe_images' . | grep -vE 'owners|Owners|owner-id|owner-alias'
   ```

#### Observation

```text
eu-west-2   unblocked
eu-west-2   ami-0abcdef1234567890  partner-appliance-2021  2021-06-14T09:00:00.000Z
eu-west-2   ami-0123456789abcdef0  210987654321  None  True  ubuntu-jammy-22.04-amd64-server-custom
```

#### Evaluation

- **Fail** for any AMI public without a documented publishing purpose; rate as for a public snapshot (the AMI's snapshots are mountable). Check AMIs that are intentionally public for secrets anyway.
- **Fail (lower)** if AMI BPA is `unblocked` in an enabled Region.
- **Fail** for running instances from public AMIs owned by unknown accounts (supply-chain risk) and for IaC that selects AMIs by name without `owners`. A Low/Medium hygiene finding unless you can show the lookup is reachable by an attacker-published image.
- **Pass**: no public AMIs, BPA `block-new-sharing`, Allowed AMIs enabled (or in audit mode with no violations), owner filters everywhere.

#### Automated coverage

Prowler: `ec2_ami_public`, `ec2_ami_account_block_public_access`, `ec2_instance_with_outdated_ami`. No Security Hub CSPM control for public AMIs at the time of writing; check the current control list.

#### Detection

`ModifyImageAttribute` (launchPermission add `all` or external account), `DisableImageBlockPublicAccess`, `DisableAllowedImagesSettings`, `RegisterImage`/`CopyImage` by unusual principals; in the whoAMI pattern, a `DescribeImages` without owner parameters followed by `RunInstances` from the same principal. ATT&CK [T1537](https://attack.mitre.org/techniques/T1537/) (exfiltration by sharing) and [T1525 Implant Internal Image](https://attack.mitre.org/techniques/T1525/) (for the consuming side).

### GT-AWS-EC2-6: EBS encryption by default and unencrypted volumes

*Guler Tech methodology.*

#### What it checks

Whether EBS encryption by default is on in every enabled Region, which key it uses, and which existing volumes and snapshots are unencrypted.

#### Prerequisites

`ec2:GetEbsEncryptionByDefault`, `ec2:GetEbsDefaultKmsKeyId`, `ec2:DescribeVolumes`, `ec2:DescribeSnapshots`, `kms:DescribeKey`, `kms:GetKeyPolicy`.

#### Steps

```bash
each_region aws ec2 get-ebs-encryption-by-default --query 'EbsEncryptionByDefault' --output text
each_region aws ec2 get-ebs-default-kms-key-id --query 'KmsKeyId' --output text
each_region aws ec2 describe-volumes --filters Name=encrypted,Values=false \
  --query 'Volumes[].[VolumeId,State,Size,Attachments[0].InstanceId]' --output text
each_region aws ec2 describe-snapshots --owner-ids self --query 'Snapshots[?Encrypted==`false`].[SnapshotId,VolumeId,StartTime]' --output text
```

For a customer managed default key, read its key policy (`aws kms get-key-policy --key-id <id> --policy-name default`) and note who can use it and whether any external account is granted.

#### Observation

```text
eu-west-2   True
eu-west-2   alias/aws/ebs
us-east-1   False
us-east-1   vol-0123456789abcdef0  in-use  100  i-0123456789abcdef0
```

#### Evaluation

- **Fail (Medium)** if any enabled Region has default encryption off. It is a preventive control, and the gap is real wherever the client launches instances.
- **Fail (Low–Medium)** per unencrypted volume or snapshot, higher if it holds regulated data. On its own this is a defence-in-depth and compliance finding: EBS data at rest is not readable by other tenants. It matters most in combination with sharing (unencrypted is the only kind that can be made public) and with insider and snapshot-copy threats.
- **Note**: `aws/ebs` as the default key is acceptable for confidentiality but gives no key policy to scope decryption; recommend a customer managed key where cross-account backup or least-privilege decryption is required.
- **Pass**: default encryption on everywhere, no unencrypted volumes or snapshots, launch templates that set `Encrypted=true` explicitly (EC2.181 does not credit account defaults).

#### Automated coverage

Security Hub CSPM: **EC2.7** (EBS default encryption; CIS v3.0.0 2.2.1, v5.0.0 5.1.1), **EC2.3** (attached volumes encrypted), **EC2.181** (launch templates encrypt EBS). Prowler: `ec2_ebs_default_encryption`, `ec2_ebs_volume_encryption`, `ec2_ebs_snapshots_encrypted`.

#### Detection

`DisableEbsEncryptionByDefault`, `ModifyEbsDefaultKmsKeyId`, `ResetEbsDefaultKmsKeyId`; KMS `ScheduleKeyDeletion` or `DisableKey` on the default EBS key (a ransomware pattern). ATT&CK [T1578.001](https://attack.mitre.org/techniques/T1578/001/) for the snapshot-copy route around encryption controls.

### GT-AWS-EC2-7: Systems Manager coverage, session logging and shared documents

*Guler Tech methodology.*

#### What it checks

Which instances are managed by Systems Manager, whether Session Manager sessions are logged to a protected, encrypted destination, whether SSM documents are shared publicly or contain secrets, and whether public sharing is blocked.

#### Prerequisites

`ssm:DescribeInstanceInformation`, `ssm:GetDocument`, `ssm:ListDocuments`, `ssm:DescribeDocumentPermission`, `ssm:GetServiceSetting`, `ssm:DescribeSessions`, `logs:DescribeLogGroups`, `s3:GetBucketPolicy` on the logging bucket.

#### Steps

1. **Coverage:** compare EC2 instances with SSM managed nodes.

   ```bash
   aws ec2 describe-instances --filters Name=instance-state-name,Values=running \
     --query 'Reservations[].Instances[].InstanceId' --output text | tr '\t' '\n' | sort > ec2.txt
   aws ssm describe-instance-information \
     --query 'InstanceInformationList[].[InstanceId,PingStatus,AgentVersion,IsLatestVersion,PlatformName]' --output text | sort > ssm.txt
   comm -23 ec2.txt <(cut -f1 ssm.txt)     # running instances not managed by SSM
   ```

2. **Session Manager preferences** in each Region:

   ```bash
   aws ssm get-document --name SSM-SessionManagerRunShell --query 'Content' --output text | jq '.inputs'
   ```

   An `InvalidDocument` error means preferences were never saved in that Region: no logging.
3. **Check the destination.** For CloudWatch Logs: `aws logs describe-log-groups --log-group-name-prefix <name> --query 'logGroups[].[logGroupName,kmsKeyId,retentionInDays]'`. For S3: the bucket policy, encryption and whether session users (or the instance role that writes the logs) can delete or overwrite objects. The instance role must be able to write; it should not be able to read or delete.
4. **Recent session use:** `aws ssm describe-sessions --state History --query 'Sessions[].[SessionId,Target,Owner,StartDate,DocumentName]' --output text`. Sessions with `DocumentName` of a port-forwarding document were not content-logged.
5. **Documents:**

   ```bash
   aws ssm get-service-setting --setting-id /ssm/documents/console/public-sharing-permission \
     --query 'ServiceSetting.SettingValue' --output text        # "Disable" means public sharing is blocked
   for d in $(aws ssm list-documents --filters Key=Owner,Values=Self --query 'DocumentIdentifiers[].Name' --output text); do
     echo "== $d"; aws ssm describe-document-permission --name "$d" --permission-type Share --query 'AccountIds'
     aws ssm get-document --name "$d" --query 'Content' --output text > "doc-$d.txt"
   done
   trufflehog filesystem doc-*.txt --no-update
   ```

   `AccountIds` containing `all` is a public document. Documents shared through AWS RAM are not shown by `describe-document-permission`; check `aws ram list-resources --resource-owner SELF --resource-type ssm:Document`.
6. **Automation logging** (SSM.6): `aws ssm get-service-setting --setting-id /ssm/automation/customer-script-log-destination`.

#### Observation

```json
{
  "s3BucketName": "",
  "s3EncryptionEnabled": true,
  "cloudWatchLogGroupName": "",
  "cloudWatchEncryptionEnabled": true,
  "kmsKeyId": "",
  "runAsEnabled": false,
  "idleSessionTimeout": "20"
}
```

Encryption flags are `true`, but there is no destination, so nothing is logged.

#### Evaluation

- **Fail (Medium)** if Session Manager is used (step 4 shows sessions) but no S3 bucket or log group is configured, or the destination is unencrypted or deletable by session users. Raise to High where SSM is the only administrative access path to production.
- **Note** that `kmsKeyId` empty means session data is protected only by TLS; set a key where policy requires it.
- **Fail (High–Critical)** for a publicly shared document; severity depends on content (credentials, internal hostnames, scripts that reveal architecture). **Fail (Medium)** if block public sharing is off in an enabled Region.
- **Fail (Low–Medium)** for running instances outside SSM: no central patching or inventory, and usually SSH key access instead. Some exclusions are legitimate (appliances, Elastic Disaster Recovery replication servers, which AWS deliberately leaves without the agent).
- **Pass**: all intended instances managed, logging to an encrypted, write-only destination with retention, no public documents, public sharing blocked in all Regions, `runAsEnabled` with a non-root default user on Linux.

#### Automated coverage

Security Hub CSPM: **SSM.1** (instances managed by SSM), **SSM.4** (documents not public), **SSM.7** (block public sharing enabled), **SSM.6** (Automation CloudWatch logging), **SSM.2/SSM.3** (patch and association compliance), **EC2.57** (interface endpoint for Systems Manager). Prowler: `ec2_instance_managed_by_ssm`, `ssm_documents_set_as_public`, `ssm_document_secrets`, `ssm_managed_compliant_patching`. Session logging itself has no dedicated control at the time of writing; that is why it is a manual check.

#### Detection

`UpdateDocument` on `SSM-SessionManagerRunShell` (someone changing logging), `UpdateServiceSetting` on the public-sharing setting, `ModifyDocumentPermission` with `all`, and on the log destination `DeleteLogGroup`, `PutRetentionPolicy`, `DeleteBucketPolicy`/`PutBucketPolicy`. The [CloudTrail](/cloud/aws-cloudtrail-logging/) and [CloudWatch](/cloud/aws-cloudwatch-eventbridge-monitoring/) notes cover alerting on these.

### GT-AWS-EC2-8: Who can run commands on instances

*Guler Tech methodology.*

#### What it checks

Which principals can execute code or open shells on instances through AWS APIs (Run Command, Session Manager, State Manager, Instance Connect, the serial console, or by changing user data), on which instances, and whether that crosses a privilege boundary. This is the lateral movement and escalation surface of EC2.

#### Prerequisites

IAM read access, `iam:SimulatePrincipalPolicy`; optionally PMapper and CloudFox. No execution rights are needed for the assessment.

#### Steps

1. **List the actions that equal code execution:**

   | Action | Effect |
   |---|---|
   | `ssm:SendCommand` | Run a document (e.g. `AWS-RunShellScript`) as root/SYSTEM |
   | `ssm:StartSession`, `ssm:ResumeSession` | Interactive shell or port forwarding |
   | `ssm:CreateAssociation`, `ssm:UpdateAssociation` | Scheduled document execution |
   | `ssm:StartAutomationExecution` (+ `iam:PassRole`) | Runbook under an automation role |
   | `ec2-instance-connect:SendSSHPublicKey` | 60-second SSH key for an OS user (needs network path) |
   | `ec2-instance-connect:OpenTunnel` | Tunnel through an Instance Connect Endpoint |
   | `ec2-instance-connect:SendSerialConsoleSSHPublicKey` | Serial console (if enabled for the account) |
   | `ec2:ModifyInstanceAttribute` (+ `StopInstances`/`StartInstances`) | Replace user data, run it at next boot |

2. **Simulate for every human and workload role** (loop over `aws iam list-roles` and `list-users`, excluding service-linked roles):

   ```bash
   for arn in $(aws iam list-roles --query 'Roles[?!starts_with(Path,`/aws-service-role/`)].Arn' --output text); do
     aws iam simulate-principal-policy --policy-source-arn "$arn" \
       --action-names ssm:SendCommand ssm:StartSession ec2-instance-connect:SendSSHPublicKey \
                      ec2-instance-connect:SendSerialConsoleSSHPublicKey ec2:ModifyInstanceAttribute \
       --resource-arns 'arn:aws:ec2:eu-west-2:111122223333:instance/*' \
       --query 'EvaluationResults[?EvalDecision==`allowed`].EvalActionName' --output text | sed "s#^#$arn\t#"
   done
   ```

   `simulate-principal-policy` does not evaluate SCPs or resource tags unless you supply context; treat the output as candidate paths and confirm by reading the policy (tag conditions such as `ssm:resourceTag/Environment`, document restrictions, `ssm:SessionDocumentAccessCheck`).
3. **Map who gains what.** For each principal that can run commands on instance X, compare its own permissions with X's instance role (GT-AWS-EC2-2). If X's role is stronger, that is privilege escalation; if X sits in a more trusted network segment, it is lateral movement. PMapper models some of these edges; CloudFox's `permissions` and `iam-simulator` commands help at scale.
4. **Account switches:** `aws ec2 get-serial-console-access-status` per Region, and `aws ec2 describe-instance-connect-endpoints` (which subnets and security groups the endpoints reach).
5. **Benign proof (lab or explicitly approved only).** On a test instance the client nominates, with their written approval:

   ```bash
   aws ssm send-command --instance-ids i-0123456789abcdef0 --document-name AWS-RunShellScript \
     --parameters 'commands=["id","hostname"]' --comment "Guler Tech approved test"
   ```

   Never fetch the instance role's credentials as part of the proof; `id` and the hostname are enough.

#### Observation

```text
arn:aws:iam::111122223333:role/developer   ssm:SendCommand  ssm:StartSession
arn:aws:iam::111122223333:role/support     ec2-instance-connect:SendSerialConsoleSSHPublicKey
eu-west-2   SerialConsoleAccessEnabled: true
```

and `developer` has no IAM write, while production instances run `AdministratorAccess`-equivalent roles.

#### Evaluation

- **Fail (High–Critical)** when a principal can run commands on an instance whose role is more privileged than the principal (escalation), especially with `Resource: *` and no tag conditions. Critical when the path reaches administrator.
- **Fail (Medium–High)** when developers or support roles have unscoped shell access to production, even without role escalation: it is direct access to production data and secrets on disk.
- **Fail (Medium)** for serial console enabled account-wide without a documented break-glass process, or `SendSerialConsoleSSHPublicKey` granted broadly.
- **Pass**: execution rights scoped by tag or instance ARN to a small set of operator roles, restricted to approved documents, instance roles no stronger than the operators who can reach them, serial console off except in break-glass.

#### Automated coverage

None of the CSPM standards express this; it needs IAM graph analysis (PMapper, Cloudsplaining's privilege escalation output, Prowler `iam_policy_allows_privilege_escalation` for some combinations). See the [privilege escalation note](/cloud/aws-iam-privilege-escalation/).

#### Detection

`SendCommand` (with `requestParameters.documentName` and targets), `StartSession`, `ResumeSession`, `CreateAssociation`, `StartAutomationExecution`, `SendSSHPublicKey`, `OpenTunnel`, `SendSerialConsoleSSHPublicKey`, `EnableSerialConsoleAccess`, `ModifyInstanceAttribute` with `userData`. GuardDuty `InitialAccess:IAMUser/AnomalousBehavior` cites `StartSession` among its APIs. ATT&CK [T1651](https://attack.mitre.org/techniques/T1651/), [T1021.007 Cloud Services](https://attack.mitre.org/techniques/T1021/007/), [T1021.008 Direct Cloud VM Connections](https://attack.mitre.org/techniques/T1021/008/), [T1098.004 SSH Authorized Keys](https://attack.mitre.org/techniques/T1098/004/).

### GT-AWS-EC2-9: Instance exposure, key pairs and remote access settings

*Guler Tech methodology.*

#### What it checks

The instance-level view of network exposure (public IPs and the security groups on them), the key pairs that still grant SSH or RDP, and launch templates that hand out public IPs. The full security group, NACL and load balancer review is in the [network note](/cloud/aws-vpc-edge-dns-security/); here you join it to the instance and role data from GT-AWS-EC2-1 and 2.

#### Prerequisites

Read-only EC2.

#### Steps

1. **Public instances with their security groups, key pair and role:**

   ```bash
   each_region aws ec2 describe-instances --filters Name=instance-state-name,Values=running \
     --query 'Reservations[].Instances[?PublicIpAddress!=`null`].[InstanceId,PublicIpAddress,KeyName,join(`,`,SecurityGroups[].GroupId),IamInstanceProfile.Arn]' \
     --output text
   ```

2. **Admin ports open to the world** on those groups:

   ```bash
   aws ec2 describe-security-group-rules --filters Name=group-id,Values=sg-0123456789abcdef0 \
     --query 'SecurityGroupRules[?IsEgress==`false` && (CidrIpv4==`0.0.0.0/0` || CidrIpv6==`::/0`)].[GroupId,IpProtocol,FromPort,ToPort]' --output text
   ```

   `IpProtocol` of `-1` means all ports.
3. **Key pairs:** `each_region aws ec2 describe-key-pairs --query 'KeyPairs[].[KeyName,KeyType,CreateTime]' --output text`. Cross-reference with `KeyName` on instances: which keys are in use, which instances are also SSM-managed (and so do not need a key), and who holds each private key (ask; AWS does not know).
4. **Launch templates that assign public IPs:** `LaunchTemplateData.NetworkInterfaces[].AssociatePublicIpAddress` in `describe-launch-template-versions`.
5. **Windows:** principals with `ec2:GetPasswordData` and access to the key pair can decrypt the initial Administrator password; include them in GT-AWS-EC2-8.

#### Observation

```text
eu-west-2   i-0123456789abcdef0  203.0.113.10  legacy-ops-2019  sg-0123456789abcdef0  arn:aws:iam::111122223333:instance-profile/web-app
sg-0123456789abcdef0  tcp  22  22
```

#### Evaluation

- **Fail (High)** for SSH/RDP open to `0.0.0.0/0` or `::/0` on a production instance; raise to Critical with a weak or shared key, a known-vulnerable service, or an administrative role. **Medium** on isolated non-production instances.
- **Fail (Low–Medium)** for key pairs in use on instances that are SSM-managed (an unnecessary second door), and for keys whose holder nobody can name.
- **Fail (Low)** for launch templates and subnets that auto-assign public IPs where the workload does not need them.
- **Pass**: no admin ports from the internet, access through Session Manager or an Instance Connect Endpoint, no key pairs on new instances.

#### Automated coverage

Security Hub CSPM: **EC2.53** and **EC2.54** (0.0.0.0/0 and ::/0 to ports 22/3389; CIS v3.0.0 5.2/5.3, v5.0.0 5.3/5.4), **EC2.9** (no public IPv4), **EC2.25** (launch templates without public IPs). Prowler: `ec2_instance_public_ip`, `ec2_instance_port_ssh_exposed_to_internet`, `ec2_instance_port_rdp_exposed_to_internet`, `ec2_securitygroup_from_launch_wizard`, `ec2_launch_template_no_public_ip`.

#### Detection

`AuthorizeSecurityGroupIngress` with `0.0.0.0/0`, `ImportKeyPair`/`CreateKeyPair`, `GetPasswordData`; GuardDuty `UnauthorizedAccess:EC2/SSHBruteForce`, `UnauthorizedAccess:EC2/RDPBruteForce`, `Recon:EC2/PortProbeUnprotectedPort`. ATT&CK [T1133 External Remote Services](https://attack.mitre.org/techniques/T1133/), [T1021.004](https://attack.mitre.org/techniques/T1021/004/).

### GT-AWS-EC2-10: SSRF reachability of IMDS from an in-scope application

*Guler Tech methodology.*

#### What it checks

Whether a server-side request feature in an application hosted on EC2 can reach the instance metadata service, and whether IMDSv2 actually blocks it in practice. This is the one test in this note that touches a running application, so it needs explicit approval and the application in scope.

#### Prerequisites

**Explicitly approved only**: written approval naming the application and the instance(s), a test account in the application, and agreement on what you may request. Our default agreement is: non-sensitive paths only (`/latest/meta-data/instance-id`, `/latest/meta-data/ami-id`), never `/iam/security-credentials/<role>` and never `/latest/user-data`.

#### Steps

1. **Find the server-side request features**: URL previews, webhooks, image or PDF fetchers, import-from-URL, XML parsers, OAuth/OpenID discovery URLs, integrations. The [bug bounty reading list](/bug-bounty-writeups/) has many real examples.
2. **Confirm the instance's IMDS settings first** (GT-AWS-EC2-1), so you know what to expect.
3. **Probe with a benign path** through the feature: `http://169.254.169.254/latest/meta-data/instance-id`. If the application returns an instance ID matching the target, IMDSv1 is reachable through the SSRF. Stop there; that is the finding.
4. **If you get no data,** check whether it is IMDSv2 doing its job (a `401` relayed back, or an empty body) or the application blocking the address. Then, still with benign paths, test the address variants an attacker would try: `http://[fd00:ec2::254]/latest/meta-data/instance-id` (only if the IPv6 endpoint is enabled), decimal and hex forms of the IPv4 address, a redirect from an approved external host you control, and DNS names resolving to `169.254.169.254`. GuardDuty detects DNS rebinding against the IMDS, so agree timing with the client's SOC.
5. **Assess whether the primitive is "full" SSRF**: can you choose the method (`PUT`) and add arbitrary headers? If yes, IMDSv2 will not save the instance, and the finding is about the application and the role, not the IMDS setting.

#### Observation

The request you sent, the application's response containing (or not) the instance ID, the instance's `HttpTokens` value, and whether method and headers are controllable.

#### Evaluation

- **Fail (Critical)** if the SSRF returns IMDS data with IMDSv1 enabled and the instance has a role: credential theft is a matter of changing the path. Do not escalate further to prove it.
- **Fail (High)** if the SSRF can reach the IMDS but IMDSv2 blocks it, because the SSRF itself remains (internal services, other cloud endpoints) and a method/header-controllable variant would succeed. Rate the SSRF as an application finding.
- **Pass** if the application refuses link-local and internal destinations and IMDSv2 is required.

#### Automated coverage

None: application testing. Configuration tests GT-AWS-EC2-1 and 2 tell you how bad a positive result is.

#### Detection

The IMDS read itself is invisible to CloudTrail. Look for WAF or application logs containing `169.254.169.254` (the AWS WAF core rule set, `AWSManagedRulesCommonRuleSet`, includes `EC2MetaDataSSRF_BODY`, `_COOKIE`, `_URIPATH` and `_QUERYARGUMENTS` rules that match metadata addresses in requests), GuardDuty `UnauthorizedAccess:EC2/MetadataDNSRebind`, and, if credentials are taken, `InstanceCredentialExfiltration.OutsideAWS`/`.InsideAWS`. ATT&CK [T1190](https://attack.mitre.org/techniques/T1190/) leading to [T1552.005](https://attack.mitre.org/techniques/T1552/005/).

## Hardening

**Require IMDSv2 in every Region, and lock it.** Set the account default and enforcement per Region, or, for an organisation, a declarative policy, which also stops account administrators changing it:

```json
{
  "ec2_attributes": {
    "instance_metadata_defaults": {
      "http_tokens": { "@@assign": "required" },
      "http_put_response_hop_limit": { "@@assign": "2" },
      "http_endpoint": { "@@assign": "enabled" },
      "http_tokens_enforced": { "@@assign": "enabled" }
    },
    "snapshot_block_public_access": { "state": { "@@assign": "block_all_sharing" } },
    "image_block_public_access": { "state": { "@@assign": "block_new_sharing" } },
    "serial_console_access": { "status": { "@@assign": "disabled" } }
  }
}
```

Use a hop limit of 1 where no containers run. Roll out `http_tokens_enforced` only after `MetadataNoToken` is zero; enforcement makes non-compliant launches fail.

**Back it with an SCP** that denies IMDSv1 launches, denies turning IMDSv1 back on, and makes IMDSv1-delivered credentials useless:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "RequireImdsV2",
      "Effect": "Deny",
      "Action": "ec2:RunInstances",
      "Resource": "arn:aws:ec2:*:*:instance/*",
      "Condition": { "StringNotEquals": { "ec2:MetadataHttpTokens": "required" } }
    },
    {
      "Sid": "DenyImdsV1Reenable",
      "Effect": "Deny",
      "Action": "ec2:ModifyInstanceMetadataOptions",
      "Resource": "arn:aws:ec2:*:*:instance/*",
      "Condition": {
        "StringNotEquals": { "ec2:Attribute/HttpTokens": "required" },
        "Null": { "ec2:Attribute/HttpTokens": "false" }
      }
    },
    {
      "Sid": "DenyImdsV1Credentials",
      "Effect": "Deny",
      "Action": "*",
      "Resource": "*",
      "Condition": { "NumericLessThan": { "ec2:RoleDelivery": "2.0" } }
    },
    {
      "Sid": "ProtectEc2AccountGuardrails",
      "Effect": "Deny",
      "Action": [
        "ec2:ModifyInstanceMetadataDefaults",
        "ec2:DisableEbsEncryptionByDefault",
        "ec2:DisableSnapshotBlockPublicAccess",
        "ec2:DisableImageBlockPublicAccess",
        "ec2:EnableSerialConsoleAccess",
        "ssm:UpdateServiceSetting"
      ],
      "Resource": "*",
      "Condition": {
        "ArnNotLike": { "aws:PrincipalArn": "arn:aws:iam::*:role/platform-guardrail-admin" }
      }
    }
  ]
}
```

Auto Scaling groups must use launch templates with a pinned version for the `RunInstances` condition to be evaluated; AWS documents `autoscaling:LaunchConfigurationName` (null) and `autoscaling:LaunchTemplateVersionSpecified` conditions to enforce that.

**Bind instance credentials to where they were issued.** `aws:Ec2InstanceSourceVpc` and `aws:Ec2InstanceSourcePrivateIPv4` describe where the credentials were delivered; compare them with `aws:SourceVpc` and `aws:VpcSourceIp`. The catch is that `aws:SourceVpc` is only present when the request goes through a **VPC endpoint**, so this works for workloads whose AWS API traffic all goes through interface or gateway endpoints:

```json
{
  "Sid": "InstanceCredsOnlyFromTheirVpc",
  "Effect": "Deny",
  "Action": "*",
  "Resource": "*",
  "Condition": {
    "StringNotEquals": { "aws:SourceVpc": "${aws:Ec2InstanceSourceVpc}" },
    "Null": { "ec2:SourceInstanceARN": "false" },
    "BoolIfExists": { "aws:ViaAWSService": "false" }
  }
}
```

Roll it out per workload, after confirming endpoint coverage; for everything else, rely on GuardDuty's exfiltration findings and alert on them.

**Least-privilege instance roles.** One role per workload, scoped to named resources, no IAM write, no `iam:PassRole` unless the workload genuinely launches resources (then with `iam:PassedToService` and a specific role ARN). Use IAM Access Analyzer's unused access findings to cut roles down.

**No secrets in user data.** Fetch at boot from Secrets Manager or Parameter Store with the instance role. Clean old launch template versions (`delete-launch-template-versions`) after rotating anything they contained.

**Encrypt and block sharing.** EBS default encryption with a customer managed key in every Region; snapshot BPA `block-all-sharing`; AMI BPA on; Allowed AMIs in audit mode, then enabled. In Terraform (per Region, with a provider alias per Region):

```hcl
resource "aws_ebs_encryption_by_default" "this" {
  enabled = true
}

resource "aws_ebs_default_kms_key" "this" {
  key_arn = aws_kms_key.ebs.arn
}

resource "aws_ebs_snapshot_block_public_access" "this" {
  state = "block-all-sharing"
}

resource "aws_ec2_image_block_public_access" "this" {
  state = "block-new-sharing"
}

resource "aws_ec2_instance_metadata_defaults" "this" {
  http_tokens                 = "required"
  http_put_response_hop_limit = 1
}

resource "aws_ec2_serial_console_access" "this" {
  enabled = false
}

resource "aws_ssm_service_setting" "block_public_documents" {
  setting_id    = "/ssm/documents/console/public-sharing-permission"
  setting_value = "Disable"
}

resource "aws_launch_template" "web" {
  name_prefix   = "web-"
  image_id      = data.aws_ami.al2023.id
  instance_type = "t3.small"

  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      encrypted = true
    }
  }
}

data "aws_ami" "al2023" {
  most_recent = true
  owners      = ["amazon"]
  filter {
    name   = "name"
    values = ["al2023-ami-2023.*-x86_64"]
  }
}
```

The `owners` argument in the AMI data source is the whoAMI fix; alternatively resolve AMIs through the public SSM parameters AWS publishes for its images.

**Replace SSH with Session Manager, and log it.** Save Session Manager preferences in every Region with an S3 bucket and/or CloudWatch log group, both encrypted with KMS, a `kmsKeyId` for session encryption, `runAsEnabled` with a non-root default user, and idle/maximum session timeouts. Make the log destination write-only for instance roles. Remove key pairs from new launches, close 22/3389, and use an Instance Connect Endpoint where SSH is genuinely required. Scope `ssm:StartSession` and `ssm:SendCommand` by tag:

```json
{
  "Sid": "SessionsOnlyToOwnTeamInstances",
  "Effect": "Allow",
  "Action": ["ssm:StartSession", "ssm:SendCommand"],
  "Resource": "arn:aws:ec2:*:111122223333:instance/*",
  "Condition": {
    "StringEquals": { "ssm:resourceTag/Team": "${aws:PrincipalTag/Team}" }
  }
}
```

Pair it with a statement allowing only approved documents (`arn:aws:ssm:*:*:document/AWS-StartSSHSession` is *not* one of them if you want session content logged) and set `ssm:SessionDocumentAccessCheck` to `true` where principals pass a document name.

**Turn on detection.** GuardDuty in every Region and account (the exfiltration findings are in the foundational tier), with EventBridge rules routing `InstanceCredentialExfiltration` findings to on-call; CloudTrail alerts on the API names listed in each test. AWS Config rules from the tests (`ec2-imdsv2-check`, `ec2-launch-template-imdsv2-check`, `ec2-ebs-encryption-by-default`, `ebs-snapshot-public-restorable-check`, `ec2-instance-managed-by-systems-manager`, `ssm-document-not-public`) give continuous coverage between assessments. See the [detection services note](/cloud/aws-detection-posture-services/).

## Real-world cases

- **Capital One (2019).** A misconfigured web application firewall running on EC2 was used as an SSRF relay to the instance metadata service; the role credentials it returned had permission to list and read S3 buckets, and, according to public reporting, data on more than 100 million people was taken. IMDSv2 was announced a few months later with exactly this pattern in mind. Krebs on Security's [What We Can Learn from the Capital One Hack](https://krebsonsecurity.com/2019/08/what-we-can-learn-from-the-capital-one-hack/) is a good public summary; AWS's [IMDSv2 launch post](https://aws.amazon.com/blogs/security/defense-in-depth-open-firewalls-reverse-proxies-ssrf-vulnerabilities-ec2-instance-metadata-service/) explains the countermeasures.
- **SSRF campaign against EC2 metadata (March 2025).** F5 Labs observed a campaign probing websites hosted on EC2 for SSRF parameters (`url`, `dest`, `target`, `redirect`...) pointing at `/latest/meta-data/iam/security-credentials/` and `/latest/user-data`, i.e. still looking for IMDSv1 in 2025. [Campaign Targets Amazon EC2 Instance Metadata via SSRF](https://www.f5.com/labs/articles/campaign-targets-amazon-ec2-instance-metadata-via-ssrf).
- **Public EBS snapshots (DEF CON 27, 2019).** Bishop Fox's Ben Morris showed that public snapshots across Regions contained SSH private keys, TLS keys, source code, API keys and thousands of `/etc/shadow` files, and released Dufflebag to search them. [Dufflebag: Uncovering Secrets in Exposed EBS Volumes](https://bishopfox.com/blog/dufflebag-uncovering-exposed-ebs).
- **whoAMI (February 2025).** Datadog Security Labs showed that code selecting the newest AMI by name without an owner filter would launch an attacker-published public AMI, estimated that about 1% of organisations using AWS were exposed, found the pattern in non-production AWS internal systems, and prompted Allowed AMIs adoption and a Terraform provider warning. [whoAMI: A cloud image name confusion attack](https://securitylabs.datadoghq.com/articles/whoami-a-cloud-image-name-confusion-attack/).

More incidents across services are collected in our [AWS incidents and write-ups](/cloud/aws-security-incidents-and-writeups/) note.

## Rating findings

| Finding | Typical severity | Reasoning |
|---|---|---|
| Confirmed SSRF to IMDSv1 on an instance with a role | Critical | Unauthenticated internet attacker obtains the role's credentials; blast radius is whatever the role can do. |
| Internet-facing instance with admin-capable role and IMDSv1 enabled (no SSRF proven) | High | One common bug class away from account takeover; the preconditions are realistic and exploitation is fast and hard to see. |
| Public EBS snapshot or public AMI (unintended) | Critical | Anyone on the internet can mount the disk; contents nearly always include credentials. Downgrade only with evidence the content is non-sensitive. |
| Principal can run commands on instances whose role is stronger (`ssm:SendCommand` / `StartSession` / user-data change) | High–Critical | Privilege escalation from an authenticated low-privilege principal; Critical when it reaches administrator. |
| Credential in user data or launch template | High (Critical for admin cloud keys) | Readable by any principal with read-only EC2 access, any process on the instance and any SSRF reaching the IMDS. |
| Snapshot or AMI shared with an unknown external account | High | Data in another party's control; severity follows data sensitivity and whether the KMS key is also shared. |
| Admin port open to 0.0.0.0/0 or ::/0 on production | High | Direct internet attack surface on the most targeted services; Medium on isolated non-production. |
| IMDSv1 enabled on internal instances with narrow roles | Medium | Needs an SSRF on that instance and yields limited access, but is the cheapest credential theft path. |
| Account default not IMDSv2 / snapshot or AMI BPA off / serial console on account-wide | Medium (Low if Region unused) | Preventive guardrail missing; no exploit on its own but the next mistake goes unchecked. |
| Session Manager in use without logging, or logs deletable by session users | Medium (High where SSM is the only admin path) | Loss of accountability for root-level actions; covers up the escalation paths above. |
| SSM document public, or block public sharing off | High if content sensitive, otherwise Medium/Low | Public documents expose scripts and sometimes credentials; the setting is a guardrail. |
| EBS default encryption off / unencrypted volumes | Medium / Low–Medium | Compliance and defence in depth; matters most combined with sharing. |
| Instances not managed by SSM, stale key pairs, launch templates assigning public IPs | Low | Hygiene with no demonstrated path; increases attack surface and slows response. |
| Nitro Enclave keys without attestation conditions | Medium | The claimed isolation does not exist; the parent instance can decrypt. |

## Mapping

| Test | Security Hub CSPM | CIS AWS Foundations | MITRE ATT&CK |
|---|---|---|---|
| GT-AWS-EC2-1 | EC2.8, EC2.170 | v3.0.0 5.6; v5.0.0 5.7 (EC2.8) | T1552.005 |
| GT-AWS-EC2-2 | (none specific; IAM.1 for full-admin policies) | — | T1078.004, T1552.005 |
| GT-AWS-EC2-3 | — | — | T1552.001, T1552.005 |
| GT-AWS-EC2-4 | EC2.1, EC2.182 | — | T1537, T1578.001, T1530 |
| GT-AWS-EC2-5 | — | — | T1537, T1525 |
| GT-AWS-EC2-6 | EC2.7, EC2.3, EC2.181 | v3.0.0 2.2.1; v5.0.0 5.1.1 (EC2.7) | T1578.001 |
| GT-AWS-EC2-7 | SSM.1, SSM.4, SSM.6, SSM.7, EC2.57 | — | T1651 |
| GT-AWS-EC2-8 | — | — | T1651, T1021.007, T1021.008, T1098.004 |
| GT-AWS-EC2-9 | EC2.53, EC2.54, EC2.9, EC2.25 | v3.0.0 5.2, 5.3; v5.0.0 5.3, 5.4 (EC2.53/54) | T1133, T1021.004 |
| GT-AWS-EC2-10 | — | — | T1190, T1552.005 |

CIS numbers are taken from the Security Hub CSPM control pages' "related requirements" at the time of writing. AWS renamed the original Security Hub product to **AWS Security Hub CSPM** in 2025 when it launched the new unified Security Hub; the control IDs did not change.

## References

- AWS: [Use the Instance Metadata Service to access instance metadata](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html), [Configure instance metadata options for new instances](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configuring-IMDS-new-instances.html), [Transition to IMDSv2](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-metadata-transition-to-version-2.html), [Example policies: work with instance metadata](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ExamplePolicies_EC2.html)
- AWS: [IAM roles for Amazon EC2](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/iam-roles-for-amazon-ec2.html), [Global condition context keys (`aws:Ec2InstanceSourceVpc`, `aws:SourceVpc`)](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html)
- AWS: [EBS encryption by default](https://docs.aws.amazon.com/ebs/latest/userguide/encryption-by-default.html), [Block public access for EBS snapshots](https://docs.aws.amazon.com/ebs/latest/userguide/block-public-access-snapshots.html), [Share a snapshot](https://docs.aws.amazon.com/ebs/latest/userguide/ebs-modifying-snapshot-permissions.html), [Block public access for AMIs](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/block-public-access-to-amis.html), [Sharing AMIs](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/sharingamis-intro.html), [Allowed AMIs](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-allowed-amis.html)
- AWS: [EC2 Instance Connect permissions](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-connect-configure-IAM-role.html), [EC2 Instance Connect Endpoint](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/connect-using-eice.html), [Configure access to the EC2 Serial Console](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/configure-access-to-serial-console.html)
- AWS: [Session Manager](https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager.html), [Session logging](https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-logging.html), [Session Manager preferences (CLI)](https://docs.aws.amazon.com/systems-manager/latest/userguide/getting-started-create-preferences-cli.html), [Sharing SSM documents and block public sharing](https://docs.aws.amazon.com/systems-manager/latest/userguide/documents-ssm-sharing.html)
- AWS: [Nitro Enclaves and AWS KMS](https://docs.aws.amazon.com/enclaves/latest/user/kms.html), [Declarative policies: EC2 syntax](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_declarative_syntax.html)
- AWS: [GuardDuty IAM finding types](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html), [GuardDuty EC2 finding types](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-ec2.html)
- AWS: [Security Hub CSPM controls for EC2](https://docs.aws.amazon.com/securityhub/latest/userguide/ec2-controls.html), [for Systems Manager](https://docs.aws.amazon.com/securityhub/latest/userguide/ssm-controls.html), [CIS AWS Foundations Benchmark in Security Hub CSPM](https://docs.aws.amazon.com/securityhub/latest/userguide/cis-aws-foundations-benchmark.html)
- AWS: [Penetration testing policy](https://aws.amazon.com/security/penetration-testing/)
- Tools: [Prowler](https://github.com/prowler-cloud/prowler), [ScoutSuite](https://github.com/nccgroup/ScoutSuite), [CloudFox](https://github.com/BishopFox/cloudfox), [Pacu](https://github.com/RhinoSecurityLabs/pacu), [PMapper](https://github.com/nccgroup/PMapper), [Steampipe AWS plugin](https://hub.steampipe.io/plugins/turbot/aws), [trufflehog](https://github.com/trufflesecurity/trufflehog), [gitleaks](https://github.com/gitleaks/gitleaks), [whoAMI-scanner](https://github.com/DataDog/whoAMI-scanner), [Dufflebag](https://github.com/BishopFox/dufflebag)
- Labs: [CloudGoat](https://github.com/RhinoSecurityLabs/cloudgoat), [flaws.cloud](http://flaws.cloud/), [flaws2.cloud](http://flaws2.cloud/), [IAM Vulnerable](https://github.com/BishopFox/iam-vulnerable)
- MITRE ATT&CK: [T1552.005](https://attack.mitre.org/techniques/T1552/005/), [T1078.004](https://attack.mitre.org/techniques/T1078/004/), [T1537](https://attack.mitre.org/techniques/T1537/), [T1578.001](https://attack.mitre.org/techniques/T1578/001/), [T1525](https://attack.mitre.org/techniques/T1525/), [T1651](https://attack.mitre.org/techniques/T1651/), [T1021.007](https://attack.mitre.org/techniques/T1021/007/), [T1021.008](https://attack.mitre.org/techniques/T1021/008/), [T1098.004](https://attack.mitre.org/techniques/T1098/004/)
- Related notes: [IAM fundamentals](/cloud/aws-iam-fundamentals-policy-evaluation/), [privilege escalation](/cloud/aws-iam-privilege-escalation/), [network, edge and DNS](/cloud/aws-vpc-edge-dns-security/), [containers](/cloud/aws-containers-ecs-eks-ecr-security/), [secrets and KMS](/cloud/aws-secrets-manager-parameter-store-kms/), [detection services](/cloud/aws-detection-posture-services/), [Organizations guardrails](/cloud/aws-organizations-multi-account-security/)
