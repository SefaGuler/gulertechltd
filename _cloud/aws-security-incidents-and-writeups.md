---
title: "AWS Security Incidents and Research Writeups"
date: 2026-11-12 18:18:00 +0000
subcategory: aws
summary: "Thirty public AWS breaches, incident reports and research disclosures, grouped by theme, each with its lesson and the note that tests for it."
refs: [EC2.8, T1078.004, T1552.001, T1552.005, T1530, T1496, T1486, T1195]
tags: [aws, incidents, writeups, research]
---

This is the reading list for our [AWS security testing guide](/cloud/aws-security-testing-guide/). It collects 30 public, free-to-read write-ups of things that went wrong in real AWS environments: breaches that reached court or regulators, incident-response reports from threat-research teams, and coordinated disclosures of flaws in AWS services themselves. Every entry is grouped by theme and ends with the one lesson we think you should take from it, plus a link to the note in this series where you test for that weakness. Use it to explain to a client why a finding matters ("this exact misconfiguration is how X lost Y"), to choose what to prioritise in a time-boxed review, or simply to read what attackers actually do with a stolen access key. If you are after mobile rather than cloud cases, see our [mobile bug bounty writeups](/bug-bounty-writeups/).

How the list was built:

- **Public and free.** Every link goes to the original author, regulator or court record, or, where the primary source is not freely readable, to a well-sourced analysis. No paywalls.
- **Links checked.** Every link was opened and checked against its summary on 2026-11-13. Vendor blogs move; if one breaks, search for the title.
- **Our words.** The summaries and lessons are ours. Read the original before you quote a figure from it in a report.
- **Type.** *Incident* means real attacker activity against a real organisation. *Research* means work by researchers on their own or AWS-owned resources, usually disclosed to AWS first. *Bug bounty* is kept for findings reported through a bounty programme; none of the entries below is a pure bounty report, because most AWS service flaws are disclosed directly to AWS rather than through a bounty platform.
- **"Year"** is the year of the incident or of public disclosure, whichever the source leads with.

Most of the AWS-side flaws below were fixed within days. The customer-side lessons were not: the same misconfigurations (long-lived keys in code, IMDSv1, public-write buckets, trust policies with no conditions) keep appearing in new reports years later, which is why they keep appearing in our tests.

## Contents

- [IAM and credentials](#iam-and-credentials)
  - [Uber (2014 and 2016): an AWS key in a code repository](#uber-2014-and-2016-an-aws-key-in-a-code-repository)
  - [Code Spaces (2014): console takeover deletes the company](#code-spaces-2014-console-takeover-deletes-the-company)
  - [Rhino Security Labs: AWS IAM privilege escalation methods](#rhino-security-labs-aws-iam-privilege-escalation-methods)
  - [Unit 42: EleKtra-Leak, keys exposed on GitHub used within minutes](#unit-42-elektra-leak-keys-exposed-on-github-used-within-minutes)
  - [Sysdig: LLMjacking, stolen credentials used against Amazon Bedrock](#sysdig-llmjacking-stolen-credentials-used-against-amazon-bedrock)
  - [Sysdig: EMERALDWHALE, credentials harvested from exposed Git configs](#sysdig-emeraldwhale-credentials-harvested-from-exposed-git-configs)
- [S3 and data exposure](#s3-and-data-exposure)
  - [Twilio (2020): a publicly writable bucket served a tampered SDK](#twilio-2020-a-publicly-writable-bucket-served-a-tampered-sdk)
  - [Unit 42: extortion using leaked .env files](#unit-42-extortion-using-leaked-env-files)
  - [Halcyon: Codefinger ransomware using S3 SSE-C](#halcyon-codefinger-ransomware-using-s3-sse-c)
  - [watchTowr: 8 million requests to abandoned S3 buckets](#watchtowr-8-million-requests-to-abandoned-s3-buckets)
- [Compute, IMDS and SSRF](#compute-imds-and-ssrf)
  - [Capital One (2019): SSRF to instance credentials to S3](#capital-one-2019-ssrf-to-instance-credentials-to-s3)
  - [F5 Labs: a campaign targeting EC2 instance metadata via SSRF](#f5-labs-a-campaign-targeting-ec2-instance-metadata-via-ssrf)
  - [Wiz: hunting rare IMDS access uncovers a pandoc zero-day](#wiz-hunting-rare-imds-access-uncovers-a-pandoc-zero-day)
  - [Appsecco: SSRF via HTML injection in a PDF generator on EC2](#appsecco-ssrf-via-html-injection-in-a-pdf-generator-on-ec2)
  - [Datadog Security Labs: whoAMI, an AMI name confusion attack](#datadog-security-labs-whoami-an-ami-name-confusion-attack)
- [Serverless and containers](#serverless-and-containers)
  - [Sysdig: SCARLETEEL, from a Kubernetes pod to Terraform state](#sysdig-scarleteel-from-a-kubernetes-pod-to-terraform-state)
  - [Sweet Security: ECScape, cross-task credential theft on ECS on EC2](#sweet-security-ecscape-cross-task-credential-theft-on-ecs-on-ec2)
  - [Datadog Security Labs: Amazon ECS is the new EC2 for crypto mining](#datadog-security-labs-amazon-ecs-is-the-new-ec2-for-crypto-mining)
  - [Datadog Security Labs: the attacker doth persist too much](#datadog-security-labs-the-attacker-doth-persist-too-much)
- [Cross-tenant and AWS service vulnerabilities](#cross-tenant-and-aws-service-vulnerabilities)
  - [Datadog Security Labs: a cross-tenant confused deputy in AWS AppSync](#datadog-security-labs-a-cross-tenant-confused-deputy-in-aws-appsync)
  - [Datadog Security Labs: Amplify-created IAM roles open to takeover](#datadog-security-labs-amplify-created-iam-roles-open-to-takeover)
  - [Orca Security: BreakingFormation, XXE in AWS CloudFormation](#orca-security-breakingformation-xxe-in-aws-cloudformation)
  - [Orca Security: Superglue, cross-tenant access in AWS Glue](#orca-security-superglue-cross-tenant-access-in-aws-glue)
  - [Aqua Security: Bucket Monopoly, shadow resources in AWS services](#aqua-security-bucket-monopoly-shadow-resources-in-aws-services)
- [CI/CD and supply chain](#cicd-and-supply-chain)
  - [Datadog Security Labs: GitHub-to-AWS keyless authentication flaws](#datadog-security-labs-github-to-aws-keyless-authentication-flaws)
  - [Wiz: CodeBreach, hijacking AWS GitHub repositories via CodeBuild](#wiz-codebreach-hijacking-aws-github-repositories-via-codebuild)
  - [Aqua Security: AWS CDK bootstrap bucket takeover](#aqua-security-aws-cdk-bootstrap-bucket-takeover)
- [Logging and detection lessons](#logging-and-detection-lessons)
  - [Permiso: GUI-vil, a cloud actor that prefers point-and-click](#permiso-gui-vil-a-cloud-actor-that-prefers-point-and-click)
  - [Invictus IR: the curious case of DangerDev](#invictus-ir-the-curious-case-of-dangerdev)
  - [Datadog Security Labs: following attackers' (Cloud)trail in AWS](#datadog-security-labs-following-attackers-cloudtrail-in-aws)
- [Keep learning](#keep-learning)

## IAM and credentials {#iam-and-credentials}

Leaked long-term access keys remain the most common way into an AWS account in public incident reports. The entries here show how keys leak, how fast they are used, and what an over-privileged key turns into.

### [Uber (2014 and 2016): an AWS key in a code repository](https://www.ftc.gov/news-events/news/press-releases/2018/04/uber-agrees-expanded-settlement-ftc-related-privacy-security-claims) {#uber-2014-and-2016-an-aws-key-in-a-code-repository}

**Source:** US Federal Trade Commission · **Year:** 2016 (FTC action 2018) · **Type:** incident

The FTC's revised complaint says that in late 2016 intruders used an access key an Uber engineer had posted to a code-sharing site to download unencrypted files from Uber's cloud storage, covering tens of millions of riders and drivers, including 600,000 US driver's licence numbers. It was, in the FTC's words, "strikingly similar" to a 2014 breach that was already under investigation. Uber paid the intruders $100,000 through its bug bounty programme and did not disclose the breach until November 2017, which is why the settlement was reopened and widened.

**Lesson:** A long-term IAM user key with broad S3 access is a breach waiting for a leak, so you treat every long-lived key in a code repository as a finding and push workloads and people towards roles and short-lived credentials.

**Related note:** [IAM fundamentals and policy evaluation](/cloud/aws-iam-fundamentals-policy-evaluation/)

### [Code Spaces (2014): console takeover deletes the company](https://www.csoonline.com/article/2365062/code-spaces-forced-to-close-its-doors-after-security-incident.html) {#code-spaces-2014-console-takeover-deletes-the-company}

**Source:** CSO Online · **Year:** 2014 · **Type:** incident

Code Spaces, a hosted Git and Subversion provider running on EC2, was hit by a DDoS and an extortion demand. The attacker had access to its AWS control panel and had created extra logins; when the company tried to regain control, the attacker deleted EBS snapshots, S3 buckets, AMIs and instances, including the backups. The company announced it could not continue trading. How the attacker first got console access was never made public.

**Lesson:** Backups that live in the same account, under the same administrators, are not backups against an account compromise, so you check for a separate, locked-down backup or log-archive account and for MFA on every human with console access.

**Related note:** [Organisations and multi-account security](/cloud/aws-organizations-multi-account-security/)

### [Rhino Security Labs: AWS IAM privilege escalation methods](https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/) {#rhino-security-labs-aws-iam-privilege-escalation-methods}

**Source:** Rhino Security Labs (Spencer Gietzen) · **Year:** 2018 · **Type:** research

The post that put AWS privilege escalation on most testers' checklists. It catalogues 21 ways a principal with a narrow-looking set of IAM permissions can grant itself more, such as creating a new default version of a policy it is attached to, creating access keys for another user, attaching policies, joining a group, or passing a privileged role to a service (Lambda, EC2, CloudFormation and others) it can then control. Each method lists the permissions involved and how to mitigate it, and Rhino released a scanner for them alongside the post (it also maintains the Pacu framework).

**Lesson:** Permissions are dangerous in combination, not one at a time, so you evaluate what each principal can *become* (PMapper, `simulate-principal-policy`, policy review) rather than reading its policies line by line.

**Related note:** [IAM privilege escalation](/cloud/aws-iam-privilege-escalation/)

### [Unit 42: EleKtra-Leak, keys exposed on GitHub used within minutes](https://unit42.paloaltonetworks.com/malicious-operations-of-exposed-iam-keys-cryptojacking/) {#unit-42-elektra-leak-keys-exposed-on-github-used-within-minutes}

**Source:** Palo Alto Networks Unit 42 · **Year:** 2023 · **Type:** research

Unit 42 deliberately leaked AWS keys in public GitHub repositories and watched. An actor they track as EleKtra-Leak found and started using a key within about four minutes, launching large EC2 instances across regions to mine Monero. AWS had already attached its `AWSCompromisedKeyQuarantine` policy after GitHub secret scanning flagged the key; the researchers removed it on purpose to see the full attack. They estimate the campaign has run since at least 2020.

**Lesson:** The time between a key reaching a public repository and its first malicious use is measured in minutes, so detection after the fact is not enough; prevent long-lived keys from existing, scan your own repositories in CI, and never remove AWS's quarantine policy without rotating the key.

**Related note:** [Unauthenticated reconnaissance](/cloud/aws-unauthenticated-recon/)

### [Sysdig: LLMjacking, stolen credentials used against Amazon Bedrock](https://sysdig.com/blog/llmjacking-stolen-cloud-credentials-used-in-new-ai-attack/) {#sysdig-llmjacking-stolen-credentials-used-against-amazon-bedrock}

**Source:** Sysdig Threat Research Team · **Year:** 2024 · **Type:** incident

Attackers exploited a vulnerable Laravel application (CVE-2021-3129), stole the cloud credentials on the host, and used them to test and resell access to hosted large language models, including Amazon Bedrock. They probed Bedrock with deliberately invalid requests to learn whether the models were enabled without generating real usage, and checked whether model invocation logging was turned on. Sysdig estimated a worst-case bill of more than $46,000 a day for the victim.

**Lesson:** A credential with AI-service permissions is now worth stealing for its own sake, so you scope Bedrock (and other expensive services) to the principals that need it and turn on model invocation logging, because prompts and responses are not in CloudTrail.

**Related note:** [CloudWatch and EventBridge monitoring](/cloud/aws-cloudwatch-eventbridge-monitoring/)

### [Sysdig: EMERALDWHALE, credentials harvested from exposed Git configs](https://sysdig.com/blog/emeraldwhale/) {#sysdig-emeraldwhale-credentials-harvested-from-exposed-git-configs}

**Source:** Sysdig Threat Research Team · **Year:** 2024 · **Type:** incident

An operation scanned the internet for web servers exposing `/.git/config`, used the repository URLs and tokens inside to clone private repositories, and searched them for further secrets. Sysdig found more than 15,000 stolen cloud and service credentials in a public S3 bucket belonging to the attackers, which AWS took down. The tooling checked found AWS keys with the CLI, including whether they could create administrator users or send email through SES.

**Lesson:** Secrets leak from places nobody thinks of as "storage" (deployed `.git` directories, build artefacts, config files), so you look for them in the deployed application as well as in the repository, and move them into a secrets store.

**Related note:** [Secrets Manager, Parameter Store and KMS](/cloud/aws-secrets-manager-parameter-store-kms/)

## S3 and data exposure {#s3-and-data-exposure}

S3 incidents are rarely about the service being broken. They are about who can write to a bucket, who can still claim a bucket name, and what an attacker can do with read and write permissions they should not have.

### [Twilio (2020): a publicly writable bucket served a tampered SDK](https://www.twilio.com/en-us/blog/incident-report-taskrouter-js-sdk-july-2020) {#twilio-2020-a-publicly-writable-bucket-served-a-tampered-sdk}

**Source:** Twilio incident report · **Year:** 2020 · **Type:** incident

The path in S3 that hosted Twilio's TaskRouter JavaScript SDK was not public when it was created in 2015, but a change made a few months later while troubleshooting a build system made it publicly writable, and nobody reversed it. In July 2020 an opportunistic actor replaced the SDK file with a copy that loaded malvertising code into users' browsers; it was live for about nine hours before Twilio replaced it. Twilio's audit found other buckets with improper write settings and committed to serving content only through its CDN, monitoring policy changes and publishing integrity checks.

**Lesson:** Public *write* is worse than public read because it turns your bucket into someone else's distribution channel, so you test bucket policies and ACLs for anonymous and cross-account write, not just read, and treat temporary policy changes as changes that need an owner and an expiry.

**Related note:** [S3 security](/cloud/aws-s3-security/)

### [Unit 42: extortion using leaked .env files](https://unit42.paloaltonetworks.com/large-scale-cloud-extortion-operation/) {#unit-42-extortion-using-leaked-env-files}

**Source:** Palo Alto Networks Unit 42 · **Year:** 2024 · **Type:** incident

Attackers scanned around 110,000 domains for exposed `.env` files and harvested tens of thousands of secrets, including AWS access keys. With one key that could create roles and attach policies, they created an administrator role, deployed a scanning Lambda function to every enabled region, then listed, copied and deleted the victims' S3 objects and left ransom notes in the emptied buckets. The data was exfiltrated and deleted, not encrypted.

**Lesson:** `iam:CreateRole` plus `iam:AttachRolePolicy` on a leaked key is a full account compromise, and unused regions are where attackers hide, so you restrict IAM write permissions tightly and deny unused regions with an SCP.

**Related note:** [Organisations and multi-account security](/cloud/aws-organizations-multi-account-security/)

### [Halcyon: Codefinger ransomware using S3 SSE-C](https://www.halcyon.ai/blog/abusing-aws-native-services-ransomware-encrypting-s3-buckets-with-sse-c) {#halcyon-codefinger-ransomware-using-s3-sse-c}

**Source:** Halcyon RISE Team · **Year:** 2025 · **Type:** incident

An actor Halcyon calls Codefinger used compromised AWS keys with S3 read and write permissions to re-encrypt victims' objects using server-side encryption with customer-provided keys (SSE-C), where the attacker supplies a key that AWS never stores. They then set lifecycle rules to delete the objects within seven days and left a ransom note. Because only the attacker holds the key, AWS cannot help recover the data.

**Lesson:** Native features can be the ransomware, so you check which principals can write objects and change lifecycle configuration, block SSE-C where your workloads do not use it, and make sure versioning and backups are outside the reach of the same keys.

**Related note:** [S3 security](/cloud/aws-s3-security/)

### [watchTowr: 8 million requests to abandoned S3 buckets](https://labs.watchtowr.com/8-million-requests-later-we-made-the-solarwinds-supply-chain-attack-look-amateur/) {#watchtowr-8-million-requests-to-abandoned-s3-buckets}

**Source:** watchTowr Labs · **Year:** 2025 · **Type:** research

watchTowr re-registered about 150 S3 buckets that software vendors, open-source projects and governments had deleted but were still referenced by installers, update mechanisms, CloudFormation templates, VM images and web pages. Over two months the buckets received more than 8 million requests, including from government, military and large corporate networks, asking for files that an attacker could have replaced with malicious ones. AWS agreed to sinkhole the buckets.

**Lesson:** Deleting a bucket does not delete the references to it, and S3 names are global, so you inventory every bucket name your code, templates and DNS refer to and keep (or sinkhole) names you have published rather than releasing them.

**Related note:** [S3 security](/cloud/aws-s3-security/)

## Compute, IMDS and SSRF {#compute-imds-and-ssrf}

The instance metadata service hands an EC2 instance's role credentials to anything on the instance that asks. With IMDSv1, "anything" includes a server-side request forgery bug in the application.

### [Capital One (2019): SSRF to instance credentials to S3](https://krebsonsecurity.com/2019/08/what-we-can-learn-from-the-capital-one-hack/) {#capital-one-2019-ssrf-to-instance-credentials-to-s3}

**Source:** KrebsOnSecurity; conviction: [US Attorney's Office, Western District of Washington](https://www.justice.gov/usao-wdwa/pr/former-seattle-tech-worker-convicted-wire-fraud-and-computer-intrusions) · **Year:** 2019 (conviction 2022) · **Type:** incident

The defining AWS breach. As Krebs explains it, a misconfigured ModSecurity web application firewall could be made to relay requests, which let the attacker reach the instance metadata service and obtain the temporary credentials of the role attached to the server. That role could list and read S3 buckets holding customer data. The Department of Justice says the attacker built a tool to scan for misconfigured AWS accounts, took data from more than 30 organisations, affected more than 100 million Capital One customers and also used compromised accounts to mine cryptocurrency.

**Lesson:** An SSRF on an EC2 workload is as serious as the instance role is broad, so you require IMDSv2 (Security Hub `EC2.8`) and scope instance roles to the specific buckets and actions the application uses.

**Related note:** [EC2, IMDS, EBS and SSM security](/cloud/aws-ec2-imds-ebs-ssm-security/)

### [F5 Labs: a campaign targeting EC2 instance metadata via SSRF](https://www.f5.com/labs/articles/threat-intelligence/campaign-targets-amazon-ec2-instance-metadata-via-ssrf) {#f5-labs-a-campaign-targeting-ec2-instance-metadata-via-ssrf}

**Source:** F5 Labs · **Year:** 2025 · **Type:** incident

In March 2025 F5 Labs observed a single actor spraying websites hosted on EC2 with requests that passed the metadata address in common URL parameters (such as `url` and `dest`), hoping one would be fetched server-side and return instance or IAM role data. The campaign was not tied to any particular CVE: it simply looked for any SSRF on any EC2-hosted site. F5's main recommendation is to move from IMDSv1 to IMDSv2, which this kind of request cannot satisfy.

**Lesson:** SSRF-to-IMDS is scanned for opportunistically at internet scale, so IMDSv1 on an internet-facing instance is a finding even when you have not found the SSRF yet.

**Related note:** [EC2, IMDS, EBS and SSM security](/cloud/aws-ec2-imds-ebs-ssm-security/)

### [Wiz: hunting rare IMDS access uncovers a pandoc zero-day](https://www.wiz.io/blog/imds-anomaly-hunting-zero-day) {#wiz-hunting-rare-imds-access-uncovers-a-pandoc-zero-day}

**Source:** Wiz Research · **Year:** 2025 · **Type:** research

Wiz baselined which processes normally talk to the metadata service (SDKs, cloud agents) and hunted for ones that rarely do. That surfaced `pandoc` querying IAM credential paths, which led to an SSRF in its HTML conversion (CVE-2025-51591) being exploited in the wild: attacker-supplied HTML made the converter fetch metadata URLs. The attempts failed because the victim enforced IMDSv2. Wiz notes that on IMDSv1 they would likely have exposed credentials.

**Lesson:** IMDSv2 turns many SSRF bugs from credential theft into a non-event, and "which process touched IMDS" is a useful detection, so you check both enforcement and whether runtime telemetry would catch an unusual metadata client.

**Related note:** [EC2, IMDS, EBS and SSM security](/cloud/aws-ec2-imds-ebs-ssm-security/)

### [Appsecco: SSRF via HTML injection in a PDF generator on EC2](https://appsecco.com/blog/finding-ssrf-via-html-injection-inside-a-pdf-file-on-aws-ec2) {#appsecco-ssrf-via-html-injection-in-a-pdf-generator-on-ec2}

**Source:** Appsecco · **Year:** 2020 · **Type:** research (authorised assessment write-up)

During an authorised application test, Appsecco found that an address field was not encoded in an HTML report preview that the server converted to PDF. Injected HTML made the converter fetch the metadata service, and the instance role's temporary credentials came back printed in the PDF. The testers confirmed the identity and mapped its permissions, then stopped and reported.

**Lesson:** Server-side renderers (HTML to PDF, image fetchers, webhook senders) are where SSRF hides in otherwise ordinary applications, and the write-up is a model for stopping at a benign proof once you hold credentials.

**Related note:** [EC2, IMDS, EBS and SSM security](/cloud/aws-ec2-imds-ebs-ssm-security/)

### [Datadog Security Labs: whoAMI, an AMI name confusion attack](https://securitylabs.datadoghq.com/articles/whoami-a-cloud-image-name-confusion-attack/) {#datadog-security-labs-whoami-an-ami-name-confusion-attack}

**Source:** Datadog Security Labs (Seth Art) · **Year:** 2025 · **Type:** research

Code and Terraform that look up "the most recent AMI whose name matches X" without restricting the owner will happily pick a public community AMI that anyone can publish with a matching name. Datadog estimated about 1% of the organisations it monitors had the vulnerable pattern somewhere, and found it in AWS's own non-production systems too (fixed in 2024). AWS responded with Allowed AMIs, an account-level allow list of trusted image providers.

**Lesson:** Every AMI lookup must pin the owner, and Allowed AMIs gives you an account-wide backstop, so you grep IaC for owner-less image lookups and check whether the control is enabled.

**Related note:** [EC2, IMDS, EBS and SSM security](/cloud/aws-ec2-imds-ebs-ssm-security/)

## Serverless and containers {#serverless-and-containers}

Containers and functions inherit credentials from their host or their execution role. These reports show how those credentials get stolen and how attackers use serverless and container services themselves as infrastructure.

### [Sysdig: SCARLETEEL, from a Kubernetes pod to Terraform state](https://sysdig.com/blog/cloud-breach-terraform-data-theft/) {#sysdig-scarleteel-from-a-kubernetes-pod-to-terraform-state}

**Source:** Sysdig Threat Research Team · **Year:** 2023 · **Type:** incident

The attacker exploited an internet-facing service in a self-managed Kubernetes cluster on AWS, deployed a cryptominer, and pulled the worker node's role credentials from IMDSv1. The node role could read far more than it needed: the attacker downloaded Lambda code and environment variables containing IAM user keys, read over 1 TB from S3, disabled some CloudTrail logging, and found a plaintext access key for a second account in a Terraform state file. The cryptomining may have been cover for stealing proprietary software.

**Lesson:** A pod compromise becomes an account compromise through the node role, so you check IMDS hop limits and IMDSv2 on nodes, use per-pod identities (IRSA or EKS Pod Identity), keep secrets out of Lambda environment variables and Terraform state, and verify that logging changes are blocked and alerted.

**Related note:** [Containers: ECS, EKS and ECR security](/cloud/aws-containers-ecs-eks-ecr-security/)

### [Sweet Security: ECScape, cross-task credential theft on ECS on EC2](https://www.sweet.security/blog/ecscape-understanding-iam-privilege-boundaries-in-amazon-ecs) {#sweet-security-ecscape-cross-task-credential-theft-on-ecs-on-ec2}

**Source:** Sweet Security (Naor Haziz) · **Year:** 2025 · **Type:** research

Haziz showed that a low-privileged container on an ECS container instance can use the instance role credentials from IMDS to impersonate the ECS agent and have the control plane deliver the IAM credentials of every other task on the same host. The stolen credentials show up in CloudTrail as the victim task's role. AWS treated it as a design consideration rather than a vulnerability and updated its documentation to say tasks on the same EC2 instance are not isolated from each other's credentials.

**Lesson:** On ECS with the EC2 launch type the host, not the task, is the security boundary, so you check that containers cannot reach IMDS, that high- and low-privilege tasks do not share instances, and consider Fargate where isolation matters.

**Related note:** [Containers: ECS, EKS and ECR security](/cloud/aws-containers-ecs-eks-ecr-security/)

### [Datadog Security Labs: Amazon ECS is the new EC2 for crypto mining](https://securitylabs.datadoghq.com/articles/tales-from-the-cloud-trenches-ecs-crypto-mining/) {#datadog-security-labs-amazon-ecs-is-the-new-ec2-for-crypto-mining}

**Source:** Datadog Security Labs · **Year:** 2024 · **Type:** incident

With leaked IAM user keys, an attacker skipped reconnaissance and immediately created Fargate clusters and task definitions running a public image that mined Monero, scaled to 25 tasks each in at least 17 regions. Datadog notes that ECS cannot enforce image signing or a repository allow list on task definitions, so the `image` field in `RegisterTaskDefinition` events is worth watching. The same actor infrastructure was linked to S3 data theft and admin user creation elsewhere.

**Lesson:** Attackers use whichever compute service is least watched, so your cost and creation alerts must cover ECS, Lambda and every region, not just EC2 in your home region.

**Related note:** [CloudWatch and EventBridge monitoring](/cloud/aws-cloudwatch-eventbridge-monitoring/)

### [Datadog Security Labs: the attacker doth persist too much](https://securitylabs.datadoghq.com/articles/tales-from-the-cloud-trenches-the-attacker-doth-persist-too-much/) {#datadog-security-labs-the-attacker-doth-persist-too-much}

**Source:** Datadog Security Labs (Martin McCloskey) · **Year:** 2025 · **Type:** incident

A leaked long-term key for an IAM user in an organisation's management account was used from several IP addresses within hours. Besides creating admin IAM users and enumerating SES, the attacker deployed a Lambda function behind an API Gateway endpoint that could create IAM users on demand, so access survived revocation of the original key. They also created users and a permission set in IAM Identity Center and weakened its MFA settings.

**Lesson:** Lambda functions and Identity Center configuration are persistence locations, so after any key compromise you review functions, API Gateway routes and Identity Center changes as well as IAM users, and you alert on IAM users created from a Lambda execution environment.

**Related note:** [Lambda and serverless security](/cloud/aws-lambda-serverless-security/)

## Cross-tenant and AWS service vulnerabilities {#cross-tenant-and-aws-service-vulnerabilities}

These are flaws in AWS services, found by researchers and fixed by AWS. You cannot test for most of them in a client account, but they explain why trust policies and resource ownership checks matter and why "AWS will handle it" is not a control.

### [Datadog Security Labs: a cross-tenant confused deputy in AWS AppSync](https://securitylabs.datadoghq.com/articles/appsync-vulnerability-disclosure/) {#datadog-security-labs-a-cross-tenant-confused-deputy-in-aws-appsync}

**Source:** Datadog Security Labs (Nick Frichette) · **Year:** 2022 · **Type:** research

AppSync blocked attempts to configure a data source with a role from another account, but the check could be bypassed by changing the letter case of the parameter name. An attacker could then make AppSync assume a role in a victim account that trusted `appsync.amazonaws.com` and read whatever that role could reach. CloudTrail showed AppSync, not the attacker, as the caller. AWS fixed it within days of the report in September 2022.

**Lesson:** A role that trusts an AWS service principal with no `aws:SourceAccount` or `aws:SourceArn` condition relies entirely on that service never being confused, so you flag service trust policies without those conditions.

**Related note:** [STS, cross-account trust and federation](/cloud/aws-sts-cross-account-trust-federation/)

### [Datadog Security Labs: Amplify-created IAM roles open to takeover](https://securitylabs.datadoghq.com/articles/amplified-exposure-how-aws-flaws-made-amplify-iam-roles-vulnerable-to-takeover/) {#datadog-security-labs-amplify-created-iam-roles-open-to-takeover}

**Source:** Datadog Security Labs (Nick Frichette) · **Year:** 2024 · **Type:** research

Amplify created roles for Cognito identity pools whose trust policies, in some cases, had no condition restricting which identity pool could assume them, so an identity pool in the attacker's own account could obtain credentials for the victim's role without authenticating. A second variant affected roles created from 2018 to 2019. AWS fixed the Amplify CLI and Studio, then changed STS to block cross-account assumption of affected roles, and published bulletin AWS-2024-003.

**Lesson:** Any role trusting `cognito-identity.amazonaws.com` must pin `cognito-identity.amazonaws.com:aud` to your own identity pool, so you check every such trust policy, including old roles created by tooling.

**Related note:** [Cognito security](/cloud/aws-cognito-security/)

### [Orca Security: BreakingFormation, XXE in AWS CloudFormation](https://orca.security/resources/blog/aws-cloudformation-vulnerability/) {#orca-security-breakingformation-xxe-in-aws-cloudformation}

**Source:** Orca Security (Tzah Pahima) · **Year:** 2022 · **Type:** research

An XML external entity flaw in how CloudFormation processed templates let researchers read files on the service's servers and make requests from them. They recovered configuration and credentials for internal AWS infrastructure and believed the access could have crossed tenant boundaries. AWS deployed a fix to all regions within six days of the September 2021 report.

**Lesson:** Managed services run code on your behalf with real privileges, so the roles you hand to CloudFormation and other deployment services should be no broader than the stacks need, which limits what a service-side flaw or a stolen template can do.

**Related note:** [CI/CD and IaC security](/cloud/aws-cicd-iac-security/)

### [Orca Security: Superglue, cross-tenant access in AWS Glue](https://orca.security/resources/blog/aws-glue-vulnerability/) {#orca-security-superglue-cross-tenant-access-in-aws-glue}

**Source:** Orca Security (Yanir Tsarimi) · **Year:** 2022 · **Type:** research

A Glue feature let researchers obtain credentials for a role inside the Glue service's own AWS account, and an internal misconfiguration then gave them administrative access to Glue's internal API for the region. From there they could have assumed roles that customers had set up to trust Glue and read or change other customers' Glue jobs, crawlers and workflows. AWS reproduced the issue within hours and deployed a full fix within days; Orca tested only against its own accounts.

**Lesson:** Roles that trust a service principal are reachable by the service's own infrastructure, so the same `aws:SourceAccount` / `aws:SourceArn` discipline and least-privilege service roles limit the damage when a service is compromised.

**Related note:** [STS, cross-account trust and federation](/cloud/aws-sts-cross-account-trust-federation/)

### [Aqua Security: Bucket Monopoly, shadow resources in AWS services](https://www.aquasec.com/blog/bucket-monopoly-breaching-aws-accounts-through-shadow-resources/) {#aqua-security-bucket-monopoly-shadow-resources-in-aws-services}

**Source:** Aqua Security (Team Nautilus) · **Year:** 2024 · **Type:** research

Several AWS services (CloudFormation, Glue, EMR, SageMaker, CodeStar, Service Catalog) created S3 buckets with predictable names built from the account ID or an account hash plus the region. An attacker who knew those values could create the bucket first in a region the victim had not used yet; when the victim later used the service there, it wrote templates, scripts or data into the attacker's bucket. Depending on the service this led to code execution, data exposure or, for CloudFormation, account takeover. AWS changed the affected services.

**Lesson:** "Bucket owned by me" is an assumption you should enforce, so you look for `aws:ResourceAccount` conditions on service roles and `--expected-bucket-owner` in scripts, and treat predictable bucket names as a design weakness.

**Related note:** [S3 security](/cloud/aws-s3-security/)

## CI/CD and supply chain {#cicd-and-supply-chain}

Pipelines hold the most powerful credentials in most AWS estates. These cases show trust policies and build triggers that let outsiders borrow them.

### [Datadog Security Labs: GitHub-to-AWS keyless authentication flaws](https://securitylabs.datadoghq.com/articles/exploring-github-to-aws-keyless-authentication-flaws/) {#datadog-security-labs-github-to-aws-keyless-authentication-flaws}

**Source:** Datadog Security Labs (Christophe Tafani-Dereeper) · **Year:** 2023 · **Type:** research

Roles that trust GitHub's OIDC provider but do not restrict the token's `sub` claim can be assumed by a GitHub Actions workflow in *any* repository. Datadog collected more than 500 role ARNs from public workflow files and found vulnerable ones, including a UK government role with push access to CodeCommit repositories, caused by a duplicated `StringEquals` key in Terraform that silently dropped the subject check. AWS now blocks creating new roles with this kind of trust policy, but existing ones stay exposed until fixed.

**Lesson:** Keyless federation is only as strong as its trust conditions, so you check every OIDC-trusting role for a `sub` condition pinned to your organisation, repository and ideally branch or environment.

**Related note:** [CI/CD and IaC security](/cloud/aws-cicd-iac-security/)

### [Wiz: CodeBreach, hijacking AWS GitHub repositories via CodeBuild](https://www.wiz.io/blog/wiz-research-codebreach-vulnerability-aws-codebuild) {#wiz-codebreach-hijacking-aws-github-repositories-via-codebuild}

**Source:** Wiz Research · **Year:** 2026 · **Type:** research

Several AWS open-source repositories, including the JavaScript SDK used by the AWS Console, ran CodeBuild on pull requests and used an `ACTOR_ID` webhook filter to allow only trusted maintainers. The filter regexes were not anchored, so any GitHub user ID *containing* a maintainer's ID passed. Wiz registered such an account, triggered a build from a pull request, and recovered a token with admin rights on the SDK repositories. AWS anchored the filters within 48 hours of the August 2025 report and added protections; Wiz stresses it was a pipeline configuration issue, not a CodeBuild service bug.

**Lesson:** Untrusted contributions must never trigger privileged builds, so you review CodeBuild webhook filters for unanchored patterns, use approval gates for external pull requests, and give each build the narrowest token possible.

**Related note:** [CI/CD and IaC security](/cloud/aws-cicd-iac-security/)

### [Aqua Security: AWS CDK bootstrap bucket takeover](https://www.aquasec.com/blog/aws-cdk-risk-exploiting-a-missing-s3-bucket-allowed-account-takeover/) {#aqua-security-aws-cdk-bootstrap-bucket-takeover}

**Source:** Aqua Security · **Year:** 2024 · **Type:** research

CDK's bootstrap creates a staging bucket named from a default qualifier, the account ID and the region. If a user later deleted that bucket, an attacker could create one with the same name; the victim's next deployment would upload CloudFormation templates into it, where the attacker could add an admin role before CloudFormation's highly privileged execution role deployed them. AWS added a condition in CDK v2.149.0 so the publishing role only trusts buckets in the user's own account, but only for environments bootstrapped again with that version or later.

**Lesson:** Fixes in tooling do not reach existing environments by themselves, so you check the CDK bootstrap version in each account and environment and confirm the staging bucket exists and belongs to the account.

**Related note:** [CI/CD and IaC security](/cloud/aws-cicd-iac-security/)

## Logging and detection lessons {#logging-and-detection-lessons}

These incident reports are most useful for what they say about evidence: which CloudTrail events revealed the attacker, what was missing, and what defenders wish they had alerted on.

### [Permiso: GUI-vil, a cloud actor that prefers point-and-click](https://permiso.io/blog/s/unmasking-guivil-new-cloud-threat-actor/) {#permiso-gui-vil-a-cloud-actor-that-prefers-point-and-click}

**Source:** Permiso p0 Labs · **Year:** 2023 · **Type:** incident

Permiso tracked a financially motivated actor for 18 months that found AWS keys on GitHub, Pastebin and vulnerable GitLab servers, then worked through the S3 Browser desktop tool and the console rather than the CLI. It created IAM users named to blend in with the victim's conventions, gave existing users console passwords, and launched large EC2 instances for mining. Permiso's detection advice centres on CloudTrail: unusual user agents, `CreateLoginProfile` on users that had none, inline policies with tool-default placeholder text, and EC2 creation across many regions.

**Lesson:** Login-profile creation and new IAM users with lookalike names are high-signal, low-volume events, so you check that they are alerted on, not just logged.

**Related note:** [CloudTrail logging](/cloud/aws-cloudtrail-logging/)

### [Invictus IR: the curious case of DangerDev](https://www.invictus-ir.com/news/the-curious-case-of-dangerdev-protonmail-me) {#invictus-ir-the-curious-case-of-dangerdev}

**Source:** Invictus Incident Response · **Year:** 2024 · **Type:** incident

An accidentally exposed key for an administrator IAM user gave an attacker a month in the account. They enumerated SES, created an admin user and lookalike users and roles trusting external accounts, launched GPU instances, sent phishing through SES and registered lookalike domains in Route 53. The first sign was an AWS support case about an SES quota increase the client had never requested, and VPC flow logs were not available to the responders.

**Lesson:** If AWS Support notices before you do, your detection has a gap, so you check that GuardDuty is on in every region, that flow logs exist for investigation, and that new roles trusting external accounts raise an alert.

**Related note:** [Detection and posture services](/cloud/aws-detection-posture-services/)

### [Datadog Security Labs: following attackers' (Cloud)trail in AWS](https://securitylabs.datadoghq.com/articles/following-attackers-trail-in-aws-methodology-findings-in-the-wild/) {#datadog-security-labs-following-attackers-cloudtrail-in-aws}

**Source:** Datadog Security Labs · **Year:** 2023 · **Type:** research

A hypothesis-driven threat-hunting write-up across real CloudTrail data. Datadog describes how attackers with stolen keys typically start (`GetCallerIdentity`, `GetSendQuota`, `ListUsers`, `DescribeInstances`, `ListBuckets` in quick succession), create IAM users with names meant to look legitimate, and prepare EC2 access with new security groups and key pairs. It includes hunting queries and distinguishes brittle indicators (specific names) from behavioural ones (IAM users created by EC2 instance roles, bursts of `AccessDenied` across services).

**Lesson:** Behaviour-based detections outlast indicator lists, so when you review a client's monitoring, ask whether it would catch a burst of discovery calls from a long-term key, not whether it knows last year's malicious user names.

**Related note:** [CloudTrail logging](/cloud/aws-cloudtrail-logging/)

## Keep learning {#keep-learning}

Two free resources sit naturally alongside this list:

- **[flaws.cloud](http://flaws.cloud/) and [flaws2.cloud](http://flaws2.cloud/)** by Scott Piper are deliberately vulnerable AWS challenges. The first walks you level by level through AWS-specific mistakes (bucket permissions, leaked keys, snapshots, metadata); the second adds attacker and defender paths through Lambda and ECS Fargate. Each level explains how to avoid the mistake you just exploited, which makes them good onboarding for new cloud testers before they touch a client account.
- **[AWS security bulletins](https://aws.amazon.com/security/security-bulletins/)** are where AWS publishes issues in its services, SDKs and tools, including several of the disclosures above. Check them when a client's tooling (CDK, SDKs, agents, CLIs) is in scope, because a fix in a newer version often needs action from the customer to take effect.
