---
title: "AWS Security Testing Guide"
date: 2026-11-12 18:30:00 +0000
subcategory: aws
summary: "Hub for our AWS series: rules of engagement, audit access, a phased method, 19 notes with 203 tests, tooling, severity and framework mapping."
refs: [AWS Security Hub CSPM, CIS AWS Foundations v5.0.0, MITRE ATT&CK IaaS]
tags: [aws, cloud, methodology, configuration-review, assumed-breach]
---

This is the hub of our AWS security series. The series is written for people who test AWS accounts for a living: configuration reviews, assumed-breach assessments and the cloud half of a wider pentest. It is equally useful to the cloud and DevOps teams who want to run the same checks themselves before someone else does. There are 19 notes. Eighteen cover one area each and follow the same shape: how the service's security model works, what goes wrong, numbered tests with commands (203 in total, `GT-AWS-<AREA>-n`), hardening with policy and IaC snippets, public real-world cases, a rating table and a mapping to AWS Security Hub CSPM, the CIS AWS Foundations Benchmark and MITRE ATT&CK. The nineteenth is a reading list of public AWS incidents and research. This page explains how the pieces fit together and how we run an assessment end to end.

## Contents

- [Rules of engagement](#rules-of-engagement)
- [Access for the assessment](#access-for-the-assessment)
- [Methodology](#methodology)
- [Series map](#series-map)
- [Where to start: twenty high-value checks](#where-to-start-twenty-high-value-checks)
- [Tooling](#tooling)
- [Rating findings](#rating-findings)
- [Framework mapping](#framework-mapping)
- [Practice labs](#practice-labs)
- [References](#references)

## Rules of engagement

Everything in this series assumes an **authorised** engagement against accounts the client owns, with a written scope that names the account IDs, Regions and any production restrictions. Three rules come from AWS itself, and they are worth reading in full on the [AWS penetration testing policy](https://aws.amazon.com/security/penetration-testing/) page before every engagement because it changes:

- **What you may test without asking AWS.** The policy lists "permitted services" (at the time of writing EC2, RDS, Aurora, CloudFront, API Gateway, AppSync, Lambda, Lightsail, Elastic Beanstalk, ECS, Fargate, OpenSearch, FSx, Transit Gateway, Global Accelerator and a few more). Testing *your client's configuration* through read-only API calls is a different thing from attacking the service, but anything that sends attack traffic at a resource should target a permitted service.
- **What is prohibited outright.** DNS zone walking, hijacking or pharming via Route 53; DoS, DDoS and simulated versions of them outside AWS's separate DDoS-simulation policy; port, protocol and request flooding; **S3 bucket takeover** and **subdomain takeover**. That last pair matters for this series: when you find a dangling bucket or CNAME you report it, and the client re-creates the resource in their own account as the fix. You never claim it yourself, even with the client's blessing.
- **You test the customer, not AWS.** If you find a flaw in an AWS service itself, stop and report it to AWS Security. Covert red-team exercises and hosting command and control need AWS's Simulated Events approval.

On top of AWS's rules, the series follows ours: read-only by default; anything that changes state is marked **lab or explicitly approved only** and uses a benign proof (`sts get-caller-identity` after assuming a role, a marker object in an approved bucket); no reading of secret values, log contents or customer data unless the client has agreed to it in writing; and no techniques for evading CloudTrail, GuardDuty or CloudWatch. The logging notes ask the opposite question: is tampering blocked and does somebody get paged?

If you find a credential during the test (in code, user data, logs, an image layer), stop at identification. `aws sts get-access-key-info` tells you which account the key belongs to without touching that account; anything more, including `get-caller-identity` with the key, needs written approval. Then the client rotates it.

## Access for the assessment

Ask for a role, not a user. The cleanest set-up is an IAM Identity Center permission set, or a cross-account role in each in-scope account that trusts a tester account, with:

| Need | Typical grant | Notes |
|---|---|---|
| Configuration review | AWS managed `SecurityAudit` + `ViewOnlyAccess` | Covers most `List*`/`Describe*`/`Get*Policy` calls. It deliberately does **not** read secret values, S3 objects or CloudWatch Logs content. |
| Effective-permission checks | `iam:SimulatePrincipalPolicy`, `iam:SimulateCustomPolicy` | Not always in `SecurityAudit`; ask for it explicitly. Needed by the privilege-escalation and STS notes. |
| Organisation view | Read-only role in the management account or the delegated admin for Organizations | `organizations:List*`/`Describe*` for SCPs, RCPs and the account tree. |
| Log content and secret scans | Separate, time-boxed grant (e.g. `logs:StartQuery` on named log groups) | Only with written approval; results redacted. See the [CloudWatch note](/cloud/aws-cloudwatch-eventbridge-monitoring/). |
| Assumed-breach paths | A low-privileged role the client chooses as the "foothold" | State-changing proofs only where approved, in agreed accounts. |

Use short sessions with MFA, keep the tester's actions identifiable (a dedicated role name and a source identity or session name that says who you are), and give the client your egress IPs so their SOC can tell your activity apart. Do **not** ask them to add your IPs to GuardDuty trusted lists or suppression rules; you want to know what their detection sees.

A Region loop you will use in nearly every note:

```bash
for r in $(aws ec2 describe-regions --all-regions \
            --query 'Regions[?OptInStatus!=`not-opted-in`].RegionName' --output text); do
  echo "== $r"
  aws ec2 describe-instances --region "$r" --query 'length(Reservations[].Instances[])'
done
```

## Methodology

We run AWS assessments in eight phases. They overlap in practice, but the order matters: the inventory and identity work in phases 1–4 tells you where the service reviews should go deep.

| Phase | Goal | Notes to use |
|---|---|---|
| 1. Scope and inventory | Confirm account IDs, Regions in use, organisation layout, which accounts hold production data | [Organizations](/cloud/aws-organizations-multi-account-security/), [IAM fundamentals](/cloud/aws-iam-fundamentals-policy-evaluation/) |
| 2. Outside-in view | What an anonymous attacker sees: hostnames, buckets, public snapshots, leaked keys, dangling DNS | [Unauthenticated recon](/cloud/aws-unauthenticated-recon/), [Cognito](/cloud/aws-cognito-security/) |
| 3. Automated baseline | Prowler / ScoutSuite run plus the client's own Security Hub CSPM results, triaged rather than pasted | [Detection and posture services](/cloud/aws-detection-posture-services/) |
| 4. Identity review | Root hygiene, MFA, keys, over-broad policies, trust relationships, escalation graph | [IAM fundamentals](/cloud/aws-iam-fundamentals-policy-evaluation/), [Privilege escalation](/cloud/aws-iam-privilege-escalation/), [STS and trust](/cloud/aws-sts-cross-account-trust-federation/) |
| 5. Service reviews | Go deep where the data and the internet exposure are | Data: [S3](/cloud/aws-s3-security/), [data stores](/cloud/aws-rds-dynamodb-data-stores-security/), [secrets and KMS](/cloud/aws-secrets-manager-parameter-store-kms/). Compute: [EC2](/cloud/aws-ec2-imds-ebs-ssm-security/), [Lambda](/cloud/aws-lambda-serverless-security/), [containers](/cloud/aws-containers-ecs-eks-ecr-security/). Edge: [network, edge and DNS](/cloud/aws-vpc-edge-dns-security/), [API Gateway, SNS, SQS](/cloud/aws-api-gateway-sns-sqs-security/) |
| 6. Assumed-breach paths | From the agreed foothold, which paths lead to admin, data or other accounts, proven benignly where approved | [Privilege escalation](/cloud/aws-iam-privilege-escalation/), [STS](/cloud/aws-sts-cross-account-trust-federation/), [CI/CD and IaC](/cloud/aws-cicd-iac-security/) |
| 7. Logging and detection | Is everything recorded, protected from tampering, and does an alert reach a human? | [CloudTrail](/cloud/aws-cloudtrail-logging/), [CloudWatch and EventBridge](/cloud/aws-cloudwatch-eventbridge-monitoring/), [Detection and posture services](/cloud/aws-detection-posture-services/) |
| 8. Reporting | Findings with evidence, attack paths drawn end to end, fixes as policy/IaC | Rating table below; each note's "Rating findings" section |

Two habits make the difference between a scanner report and an assessment. First, **chain findings**: an IMDSv1 instance is Medium on its own and Critical when its role can pass an admin role to Lambda. Draw the path. Second, **check the controls that would have caught you**: for every path, note whether CloudTrail recorded it, whether GuardDuty raised anything and whether that finding reached a person.

## Series map

| Area | Note | Tests | What it covers |
|---|---|---|---|
| Outside-in | [AWS Unauthenticated Reconnaissance and Exposure Discovery](/cloud/aws-unauthenticated-recon/) | 10 | AWS fingerprints in DNS/HTTP/TLS, account IDs, client bucket names, public snapshots/AMIs/SSM documents, leaked keys, dangling DNS |
| Identity | [AWS IAM Fundamentals and Policy Evaluation](/cloud/aws-iam-fundamentals-policy-evaluation/) | 11 | Principals, credentials, the full evaluation logic, root, MFA, keys, over-broad statements, `iam:PassRole` |
| Identity | [AWS IAM Privilege Escalation Paths](/cloud/aws-iam-privilege-escalation/) | 12 | The published escalation families (42 paths), finding who holds them, benign lab proofs, fixes, detection |
| Identity | [AWS STS, Cross-Account Trust and Federation](/cloud/aws-sts-cross-account-trust-federation/) | 11 | Trust policies, ExternalId, confused deputy, GitHub OIDC, IRSA, SAML, session tags, revocation |
| Identity | [Amazon Cognito Security](/cloud/aws-cognito-security/) | 12 | Self-sign-up, writable attributes, account takeover, token validation, guest credentials, role mapping |
| Data | [Amazon S3 Security](/cloud/aws-s3-security/) | 12 | Block Public Access, ACLs, policies, SSE-C abuse, squatted and dangling buckets, logging |
| Data | [AWS Data Stores: RDS, Aurora, DynamoDB and Snapshots](/cloud/aws-rds-dynamodb-data-stores-security/) | 12 | Exposure, shared snapshots, auth and TLS, IAM paths to data; ElastiCache, OpenSearch, Redshift |
| Data | [AWS Secrets Manager, Parameter Store and KMS](/cloud/aws-secrets-manager-parameter-store-kms/) | 10 | Who can read secrets and keys, key policies, grants, rotation, destructive key actions |
| Compute | [Amazon EC2 Security: IMDS, EBS, AMIs and Systems Manager](/cloud/aws-ec2-imds-ebs-ssm-security/) | 10 | IMDSv1/v2, instance roles, user data, snapshots and AMIs, SSM as a remote shell |
| Compute | [AWS Lambda and Serverless Security](/cloud/aws-lambda-serverless-security/) | 12 | Resource policies, function URLs, env-var secrets, code and layers, event injection, runtimes |
| Compute | [AWS Container Security: ECS, EKS and ECR](/cloud/aws-containers-ecs-eks-ecr-security/) | 12 | Registry exposure, secrets in images, task and pod credentials, EKS access, IRSA and Pod Identity |
| Network and edge | [AWS Network, Edge and DNS Security](/cloud/aws-vpc-edge-dns-security/) | 12 | Security groups, endpoints and policies, load balancers, CloudFront, WAF, Route 53, flow logs |
| Integration | [Amazon API Gateway, SNS and SQS Security](/cloud/aws-api-gateway-sns-sqs-security/) | 12 | Authorisers and their caching, private APIs, default endpoints, topic, queue and event-bus policies |
| Logging | [AWS CloudTrail: Audit Logging Done Right](/cloud/aws-cloudtrail-logging/) | 11 | Organisation trails, data and network events, validation, bucket and KMS hardening, tamper alerts, Athena |
| Monitoring | [Amazon CloudWatch and EventBridge](/cloud/aws-cloudwatch-eventbridge-monitoring/) | 12 | CIS metric filters and alarms, EventBridge rules, Logs Insights; secrets in logs, log sharing, public dashboards |
| Detection | [AWS Detection and Posture Services](/cloud/aws-detection-posture-services/) | 11 | GuardDuty, Security Hub CSPM, Config, Inspector, Macie, Detective, Access Analyzer, flow and DNS logs |
| Governance | [AWS Organizations and Multi-Account Security](/cloud/aws-organizations-multi-account-security/) | 10 | Management account, SCPs, RCPs, declarative policies, delegated admins, root access, Identity Center |
| Delivery | [AWS CI/CD and Infrastructure-as-Code Security](/cloud/aws-cicd-iac-security/) | 11 | OIDC trust, CI role privilege, CodeBuild webhooks, CloudFormation and CDK roles, Terraform state |
| Reading list | [AWS Security Incidents and Research Writeups](/cloud/aws-security-incidents-and-writeups/) | — | Thirty public breaches and research disclosures, each with its lesson and the note that tests for it |

The test IDs are stable: `GT-AWS-S3-6` will always mean the same check, so you can cite them in reports and track them between engagements.

## Where to start: twenty high-value checks

If you have a day rather than two weeks, these checks find most of the serious issues we see. Each links to the note with the full test.

1. **Root user**: no access keys, MFA on, centralised root access where Organizations is used. [IAM fundamentals](/cloud/aws-iam-fundamentals-policy-evaluation/)
2. **Long-lived access keys** older than 90 days or unused, especially on CI users. [IAM fundamentals](/cloud/aws-iam-fundamentals-policy-evaluation/)
3. **Escalation graph**: which non-admin principals can reach admin (PMapper, `simulate-principal-policy`). [Privilege escalation](/cloud/aws-iam-privilege-escalation/)
4. **Trust policies** with `"AWS": "*"`, a whole foreign account, or third-party roles without `sts:ExternalId`. [STS](/cloud/aws-sts-cross-account-trust-federation/)
5. **GitHub Actions OIDC roles** without a tight `token.actions.githubusercontent.com:sub` condition. [CI/CD](/cloud/aws-cicd-iac-security/)
6. **Public S3**: account-level Block Public Access off, policies or ACLs granting `*`, website buckets. [S3](/cloud/aws-s3-security/)
7. **Public or cross-account snapshots and AMIs** (EBS, RDS, Redshift). [EC2](/cloud/aws-ec2-imds-ebs-ssm-security/), [data stores](/cloud/aws-rds-dynamodb-data-stores-security/)
8. **IMDSv1 still allowed** on instances whose role matters. [EC2](/cloud/aws-ec2-imds-ebs-ssm-security/)
9. **Secrets outside the vault**: user data, Lambda environment variables, ECS task definitions, CloudFormation parameters, log groups. [Secrets and KMS](/cloud/aws-secrets-manager-parameter-store-kms/)
10. **Security groups** open to `0.0.0.0/0` or `::/0` on SSH, RDP and database ports. [Network](/cloud/aws-vpc-edge-dns-security/)
11. **Dangling DNS** in the client's hosted zones. [Network](/cloud/aws-vpc-edge-dns-security/)
12. **Lambda function URLs** with `AuthType NONE` and functions with public resource policies. [Lambda](/cloud/aws-lambda-serverless-security/)
13. **API Gateway** routes with no authorisation and authoriser caching keyed on the wrong identity source. [API Gateway](/cloud/aws-api-gateway-sns-sqs-security/)
14. **Cognito identity pools** with guest access, and what the unauthenticated role can do. [Cognito](/cloud/aws-cognito-security/)
15. **EKS** public endpoints, `aws-auth`/access-entry admin sprawl, pods that can reach the node role. [Containers](/cloud/aws-containers-ecs-eks-ecr-security/)
16. **KMS key policies** with `*` principals or broad cross-account grants; keys pending deletion. [Secrets and KMS](/cloud/aws-secrets-manager-parameter-store-kms/)
17. **CloudTrail**: one organisation trail, all Regions, validation on, bucket in a log-archive account, `StopLogging`/`DeleteTrail` denied by SCP and alerted. [CloudTrail](/cloud/aws-cloudtrail-logging/)
18. **Alert routing**: GuardDuty and Security Hub findings reach a human through EventBridge and a confirmed SNS subscription. [CloudWatch and EventBridge](/cloud/aws-cloudwatch-eventbridge-monitoring/)
19. **GuardDuty coverage**: every account and Region, protection plans on, no over-broad suppression rules. [Detection services](/cloud/aws-detection-posture-services/)
20. **Management account**: no workloads, few humans, and a tight trust on `OrganizationAccountAccessRole`. [Organizations](/cloud/aws-organizations-multi-account-security/)

## Tooling

All of these run read-only with the audit role above, except where a note says otherwise.

| Tool | What we use it for | Main notes |
|---|---|---|
| [AWS CLI v2](https://docs.aws.amazon.com/cli/latest/userguide/) + `jq` | Every check in the series; examples use real commands and `--query` | All |
| [Prowler](https://github.com/prowler-cloud/prowler) | Broad baseline; each note lists the relevant check names | All |
| [ScoutSuite](https://github.com/nccgroup/ScoutSuite) | Second baseline and an offline HTML report for the evidence pack | All |
| [CloudFox](https://github.com/BishopFox/cloudfox) | Attack-surface views: role trusts, secrets locations, endpoints, environment variables | Recon, STS, compute notes |
| [PMapper](https://github.com/nccgroup/PMapper) | IAM graph and escalation queries | Privilege escalation, STS |
| [Pacu](https://github.com/RhinoSecurityLabs/pacu) | Enumeration modules and `iam__privesc_scan --scan-only`; offensive modules lab only | Privilege escalation, Cognito |
| [cloudsplaining](https://github.com/salesforce/cloudsplaining) | Policy risk report (privilege escalation, data exfiltration, resource exposure) | IAM fundamentals, privilege escalation |
| IAM Access Analyzer | External, internal and unused access findings; policy validation | IAM, S3, STS, detection |
| [trufflehog](https://github.com/trufflesecurity/trufflehog) / [gitleaks](https://github.com/gitleaks/gitleaks) | Secrets in code, images and exports, run without key verification unless approved | Recon, containers, CI/CD |
| [kube-bench](https://github.com/aquasecurity/kube-bench), `kubectl` | EKS node and cluster checks | Containers |
| [Checkov](https://github.com/bridgecrewio/checkov), [Trivy](https://github.com/aquasecurity/trivy), [KICS](https://github.com/Checkmarx/kics), cfn-nag | IaC scanning of the client's repositories | CI/CD |
| [Stratus Red Team](https://github.com/DataDog/stratus-red-team) | Detection validation in a lab or approved sandbox account only | Detection, CloudTrail, CloudWatch |

Treat scanner output as leads, not findings. Every note explains the common false positives for its area (a "public" bucket that serves a public website by design, a wildcard principal constrained by `aws:PrincipalOrgID`, a role that looks admin but is fenced by a permission boundary and an SCP).

## Rating findings

The series uses one rating model so that findings from different notes sit in the same report without arguing with each other. Rate by what an attacker gains (data read or write, code execution, account or organisation takeover), the precondition (anonymous internet, any authenticated principal, a specific role, an insider), the blast radius (one resource, one account, the organisation) and whether the activity would be detected.

| Typical finding | Severity | Why |
|---|---|---|
| Anonymous read of sensitive data (public bucket, snapshot, unauthenticated API) or anonymous path to admin | Critical | No precondition, direct data or control impact |
| Low-privileged role can escalate to account admin | High–Critical | Every compromised workload or user becomes a full compromise; Critical when the foothold is internet-facing |
| Cross-account trust open to any account, or OIDC trust open to any repository | Critical | Anyone on the internet who can mint a token or holds an AWS account walks in |
| Secret in user data, environment variables or logs readable by broad roles | High | Turns read-only access into credentials; severity follows what the secret unlocks |
| IMDSv1 on an instance with a powerful role and an SSRF-prone application | High | One web bug away from credential theft; Medium without a meaningful role |
| CloudTrail missing, not organisation-wide, or tamperable without an alert | Medium–High | High when it covers the management or log-archive account; you cannot investigate what you did not record |
| Findings that never reach a human (no routing, unconfirmed SNS) | Medium | Detection exists on paper only |
| Hygiene gaps without a demonstrated path (old keys unused, missing tags, default encryption choices) | Low–Info | Fix, but do not let them crowd the report |

Each note refines this for its own finding types. When findings chain, rate the chain and reference the parts.

## Framework mapping

Every test carries three kinds of reference, and each note ends with a mapping table.

- **AWS Security Hub CSPM controls** (for example `S3.1`, `IAM.6`, `CloudTrail.2`). AWS renamed the original Security Hub product to *Security Hub CSPM* in 2025 when it launched a new, unified Security Hub; the control IDs did not change. Where no control exists for a test (trust-policy conditions, KMS grants, webhook filters and many more), the mapping says "none". That gap is the point of a manual review.
- **CIS AWS Foundations Benchmark**, cited with the version (mostly v5.0.0 and v3.0.0, with v1.4.0 where Security Hub still evaluates older monitoring controls). CIS covers identity, storage, logging, monitoring and networking basics; it says nothing about most services in this series.
- **MITRE ATT&CK** Enterprise techniques for the IaaS platform. ATT&CK v20 (2026) re-numbered the defence-impairment area: what used to be T1562.008 *Disable or Modify Cloud Logs* is now [T1685.002](https://attack.mitre.org/techniques/T1685/002/), and cloud firewall changes moved from T1562.007 to [T1686.001](https://attack.mitre.org/techniques/T1686/001/). The notes use the new IDs and mention the old ones.

Prowler check names are listed under "Automated coverage" in each test, taken from the Prowler repository at the time of writing.

## Practice labs

Practise anything state-changing in an account you own, never on a client's.

- [flaws.cloud](http://flaws.cloud/) and [flaws2.cloud](http://flaws2.cloud/): Scott Piper's classic walk-throughs of S3, snapshot, IMDS and logging mistakes (flaws2 has an attacker and a defender path).
- [CloudGoat](https://github.com/RhinoSecurityLabs/cloudgoat): Rhino Security Labs' scenarios for privilege escalation, Lambda, ECS, Cognito and more, deployed into your own account.
- [IAM Vulnerable](https://github.com/BishopFox/iam-vulnerable): Bishop Fox's Terraform for 31 IAM escalation paths, ideal for testing PMapper, Pacu and your own queries.
- [Stratus Red Team](https://github.com/DataDog/stratus-red-team): runs single ATT&CK techniques against a sandbox account so you can check that CloudTrail, GuardDuty and your alert routing actually fire.

Related on this site: the [Cognito note](/cloud/aws-cognito-security/) and the mobile note on [secrets hardcoded in app packages](/mobile/maswe-0004-sensitive-data-hardcoded-app-package/) meet in the middle, because mobile apps are where identity pool IDs and stray AWS keys most often turn up. Public mobile writeups are collected on the [Bug Bounty Writeups](/bug-bounty-writeups/) page.

## References

- AWS: [Penetration testing policy](https://aws.amazon.com/security/penetration-testing/)
- AWS: [Shared responsibility model](https://aws.amazon.com/compliance/shared-responsibility-model/)
- AWS: [Security Hub CSPM controls reference](https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-controls-reference.html)
- AWS: [CIS AWS Foundations Benchmark in Security Hub CSPM](https://docs.aws.amazon.com/securityhub/latest/userguide/cis-aws-foundations-benchmark.html)
- AWS: [Security Reference Architecture](https://docs.aws.amazon.com/prescriptive-guidance/latest/security-reference-architecture/welcome.html)
- AWS: [Well-Architected Framework, Security Pillar](https://docs.aws.amazon.com/wellarchitected/latest/security-pillar/welcome.html)
- AWS: [AWS managed policy `SecurityAudit`](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/SecurityAudit.html)
- CIS: [CIS Amazon Web Services Benchmarks](https://www.cisecurity.org/benchmark/amazon_web_services)
- MITRE: [ATT&CK IaaS matrix](https://attack.mitre.org/matrices/enterprise/cloud/iaas/)
- [Hacking the Cloud](https://hackingthe.cloud/) (community knowledge base on cloud attack techniques)
