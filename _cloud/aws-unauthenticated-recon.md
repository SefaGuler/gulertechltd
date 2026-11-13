---
title: "AWS Unauthenticated Reconnaissance and Exposure Discovery"
date: 2026-11-12 18:00:00 +0000
subcategory: aws
summary: "What an outsider learns about a client's AWS estate without credentials: hostnames, account IDs, buckets, public snapshots, leaked keys and dangling DNS."
refs: [S3.1, S3.2, S3.3, S3.8, EC2.1, EC2.182, RDS.1, SSM.4, SSM.7, Lambda.1, CloudFront.12, Cognito.2, CIS AWS 5.0.0 2.1.4, T1590.002, T1593.003, T1594, T1596, T1595.003, T1580, T1530, T1552.001, T1078.004, T1584.001]
tags: [aws, recon, s3, secrets, subdomain-takeover, osint]
---

This note is part of our [AWS security testing guide](/cloud/aws-security-testing-guide/) and covers the outside-in phase of an AWS assessment: what someone with no credentials for the client's accounts can learn about them and reach. That means recognising AWS-hosted assets from DNS, HTTP and TLS, working out which AWS account owns them, checking the client's own bucket names, finding snapshots, images, documents, layers and container images the client has shared with the whole world, finding access keys that leaked through code, CI, mobile apps and JavaScript, spotting Cognito identifiers in front-ends, and finding DNS records that still point at AWS resources the client deleted. None of it needs an exploit. Every item is either a configuration the client chose (often by accident) or information AWS itself treats as public, and the skill is in collecting it methodically, proving ownership before you touch anything, and rating it by what it actually leads to. This is also the phase where a tester can most easily stray onto someone else's assets, so the scoping rules below matter more here than anywhere else in the series.

## Contents

- [Scope and ethics for this phase](#scope-and-ethics-for-this-phase)
- [How it works](#how-it-works)
- [What goes wrong](#what-goes-wrong)
- [Testing](#testing)
  - [Before you start](#before-you-start)
  - [GT-AWS-RECON-1: Fingerprint AWS-hosted assets from DNS, HTTP and TLS](#gt-aws-recon-1-fingerprint-aws-hosted-assets-from-dns-http-and-tls)
  - [GT-AWS-RECON-2: Establish the owning account IDs](#gt-aws-recon-2-establish-the-owning-account-ids)
  - [GT-AWS-RECON-3: Client-owned S3 bucket names, existence and anonymous access](#gt-aws-recon-3-client-owned-s3-bucket-names-existence-and-anonymous-access)
  - [GT-AWS-RECON-4: Public EBS snapshots, AMIs and RDS snapshots](#gt-aws-recon-4-public-ebs-snapshots-amis-and-rds-snapshots)
  - [GT-AWS-RECON-5: Public SSM documents](#gt-aws-recon-5-public-ssm-documents)
  - [GT-AWS-RECON-6: Public Lambda layers, ECR repositories and ECR Public images](#gt-aws-recon-6-public-lambda-layers-ecr-repositories-and-ecr-public-images)
  - [GT-AWS-RECON-7: Access keys leaked in code, CI, mobile apps and JavaScript](#gt-aws-recon-7-access-keys-leaked-in-code-ci-mobile-apps-and-javascript)
  - [GT-AWS-RECON-8: Cognito and Amplify identifiers in front-ends](#gt-aws-recon-8-cognito-and-amplify-identifiers-in-front-ends)
  - [GT-AWS-RECON-9: Dangling DNS pointing at deleted AWS resources](#gt-aws-recon-9-dangling-dns-pointing-at-deleted-aws-resources)
  - [GT-AWS-RECON-10: Directly reachable origins and default endpoints](#gt-aws-recon-10-directly-reachable-origins-and-default-endpoints)
- [Hardening](#hardening)
- [Real-world cases](#real-world-cases)
- [Rating findings](#rating-findings)
- [Mapping](#mapping)
- [References](#references)

## Scope and ethics for this phase

Every test in this note assumes an authorised engagement with written scope against the client's own AWS accounts and domains, and that you respect the [AWS penetration testing policy](https://aws.amazon.com/security/penetration-testing/). Outside-in recon adds three rules of its own:

- **Only client-owned names and identifiers.** You work from a list the client gives you or confirms: domains, subdomains, account IDs, bucket naming conventions, GitHub organisations, app store listings. You do not run internet-wide sweeps for "any bucket containing the client's name", you do not brute-force bucket names from generic wordlists, and you do not enumerate other organisations' public snapshots, documents or keys. Wordlist generation is fine only when every candidate comes from the client's own naming patterns and the client has agreed to it.
- **Prove ownership before you look inside.** A bucket called `examplecorp-backups` may belong to someone else entirely. Before you list or download anything, confirm ownership with the client (or from the inside view, if you also have read-only credentials). If a resource exists and you cannot confirm the client owns it, record the name, stop, and ask.
- **Credentials you find are not yours to use.** If you find an access key, you identify which account it belongs to without using it (`sts get-access-key-info`, below), report it, and have it rotated. You call `sts get-caller-identity` with it only if the client explicitly approves that, and you never enumerate or act with it beyond that.

Commands that change state (creating a bucket to prove a takeover, writing an object) are marked **lab or explicitly approved only**. Command output shown in this note is **illustrative**; we ran nothing against real accounts while writing it.

## How it works

There is no single "unauthenticated surface" in AWS. There are several mechanisms, each with its own rules, that put information or access in front of people who have no credentials for your account. Knowing which mechanism you are looking at tells you what to check and how to fix it.

### Global namespaces

Some AWS names are global across all customers, which means anyone can test whether a name exists and, once you release it, anyone can claim it:

| Namespace | Example hostname | Claimable after deletion? |
|---|---|---|
| S3 general purpose bucket names (global namespace) | `examplecorp-assets.s3.eu-west-2.amazonaws.com` | Yes, by any account, unless AWS has sinkholed it |
| S3 static website endpoints | `examplecorp-www.s3-website.eu-west-2.amazonaws.com` (format varies by Region) | Yes, the bucket name is the claim |
| Elastic Beanstalk environment CNAME prefixes | `examplecorp-prod.eu-west-2.elasticbeanstalk.com` | Yes, once the environment is terminated |
| Cognito user pool domain prefixes | `examplecorp.auth.eu-west-2.amazoncognito.com` | Prefix is unique per Region |
| CloudFront distribution hostnames | `d111111abcdef8.cloudfront.net` | No, AWS assigns the hostname |
| API Gateway, Lambda function URL, ELB hostnames | `a1b2c3d4e5.execute-api.eu-west-2.amazonaws.com`, `<url-id>.lambda-url.eu-west-2.on.aws`, `my-alb-123456789.eu-west-2.elb.amazonaws.com` | No, these contain AWS-generated IDs |

Two recent changes shift this picture. In 2024, after Aqua Security's "Bucket Monopoly" research, AWS changed several services that used to create S3 buckets with guessable names. And in March 2026 AWS introduced **account regional namespaces** for general purpose buckets: names that end in a suffix containing the account ID and Region (for example `amzn-s3-demo-bucket-111122223333-us-west-2-an`), which only that account can create, even after deletion. Existing buckets stay in the global namespace, and organisations can enforce the new namespace with the `s3:x-amz-bucket-namespace` condition key. At the time of writing this is opt-in, so most estates you test will still be almost entirely in the global namespace.

### Resource sharing that can be set to "everyone"

Several resource types have a share setting where one of the options is the whole of AWS (or the whole internet):

- **EBS snapshots** (`createVolumePermission` with group `all`) and **AMIs** (`launchPermission` with group `all`). Anyone with any AWS account can copy a public snapshot or launch a public AMI and read every byte of the disk.
- **RDS and Aurora snapshots** (`restore` attribute set to `all`). Any AWS account can restore an unencrypted public snapshot into its own database.
- **SSM documents** (shared with `all`). Anyone can read the document content, including any script, hostname or secret written into it.
- **Lambda layers** (a layer version policy with `"Principal": "*"`). Anyone who knows the ARN can download the layer's code.
- **ECR private repositories** (a repository policy allowing `*`), and **ECR Public** repositories, which are public by design.
- **S3 buckets and objects** (bucket policy with `"Principal": "*"`, or an ACL granting `AllUsers` or `AuthenticatedUsers`). `AuthenticatedUsers` means *any AWS account*, not "my users", and that misunderstanding is still common in older buckets.

AWS has added account-level guardrails for most of these over time: **S3 Block Public Access** (on by default, together with ACLs disabled, for new buckets since April 2023), **block public access for AMIs** (enabled by default for new accounts and for existing accounts that had no public AMIs on or after 15 July 2023), **block public access for EBS snapshots** (a Regional setting, *not* on by default, with "block all sharing" and "block new sharing" modes), and **block public sharing for SSM documents** (a Regional service setting). These guardrails are Regional, mostly don't retroactively un-share what is already public (the exceptions are S3 Block Public Access and the snapshot "block all sharing" mode), and are frequently missing in older accounts. Organisations can now set the AMI and snapshot settings centrally with declarative policies; see the [Organizations note](/cloud/aws-organizations-multi-account-security/).

### Identifiers and credentials

- **Account IDs** are 12-digit numbers that appear in ARNs, in public resource metadata, in error messages and in front-end configuration. AWS's own documentation states that account IDs "are not considered secret, sensitive, or confidential information", although they "should be used and shared carefully". Knowing the account ID does not grant access; it lets an attacker look up everything the account has made public (public snapshots and AMIs are queryable by owner ID), craft targeted phishing, and test cross-account trust policies that forgot `sts:ExternalId`. Treat account ID disclosure as an enabler, not a finding on its own.
- **Access key IDs** encode their type in the prefix: keys that start with `AKIA` are long-term keys for an IAM user or the root user, and keys that start with `ASIA` are temporary STS credentials. The STS API `GetAccessKeyInfo` returns the account ID for any access key ID, without needing the secret and without touching the key owner's account (it is logged in the *caller's* CloudTrail only). The account ID is also recoverable offline by decoding the key ID, as Aidan Steele and Tal Be'ery showed.
- **Front-end configuration** for Cognito and Amplify contains a user pool ID, an app client ID and often an identity pool ID. These are meant to be public. What matters is what an unauthenticated caller can do with them, which is the subject of the [Cognito note](/cloud/aws-cognito-security/).

### HTTP, DNS and TLS fingerprints

AWS services leave consistent marks: hostnames under `amazonaws.com`, `cloudfront.net`, `elasticbeanstalk.com`, `on.aws`, `amazoncognito.com`, `amplifyapp.com` and `awsapprunner.com`; response headers such as `Server: AmazonS3`, `x-amz-request-id`, `x-amz-id-2`, `x-amz-bucket-region`, `x-amz-cf-id`, `x-amz-cf-pop`, `Via: ... (CloudFront)`, `x-amzn-requestid`, `x-amz-apigw-id` and `x-amzn-errortype`; load balancer cookies such as `AWSALB` and `AWSALBCORS`; ALB-generated error pages with `Server: awselb/2.0`; and TLS certificates issued by Amazon's ACM intermediates. AWS publishes its IP ranges per service and Region at `https://ip-ranges.amazonaws.com/ip-ranges.json`, so you can map an IP address to "CloudFront", "EC2 eu-west-2" and so on.

A useful S3 detail: a `HEAD` request to any bucket name returns an `x-amz-bucket-region` header even when the response is `403 Forbidden` and the request is anonymous, so the response code tells you whether the bucket exists (`404` with `NoSuchBucket` when it does not) and the header tells you where.

## What goes wrong

**Sensitive data in a public or "any AWS account" bucket.** The classic. The bucket policy has `"Principal": "*"` without a restricting condition, an object ACL grants `AllUsers` read, or an old ACL grants `AuthenticatedUsers`. It matters because the attacker needs nothing but the name, and bucket names leak through HTML, JavaScript, mobile apps, CloudFormation templates and error messages. Depth on S3 policies, ACLs and Block Public Access is in the [S3 note](/cloud/aws-s3-security/).

**Public disk images and database snapshots.** A snapshot shared "temporarily" with `all` to move data between accounts, an AMI made public by a build pipeline, an RDS snapshot shared publicly instead of with one account. A disk image is everything: application code, configuration files, SSH host keys, `.bash_history`, cached credentials, database files. A public, unencrypted snapshot of a production volume is usually the worst single finding in this note.

**Public SSM documents with embedded secrets.** Runbooks and command documents often carry passwords, tokens, internal hostnames and bootstrap scripts. A document shared with `all` is readable by anyone who knows or finds it.

**Public layers and container images with embedded secrets.** Lambda layers and container images bundle dependencies, configuration and occasionally `.env` files. A public ECR Public image built from the wrong directory ships the developer's credentials.

**Access keys in code and apps.** IAM user keys committed to Git (and still in history after the "fix"), printed in CI logs, baked into mobile apps or bundled into single-page application JavaScript. Long-term `AKIA` keys are the dangerous ones because they work until someone rotates them. Mobile apps are a recurring source: see [hardcoded data in the app package](/mobile/maswe-0004-sensitive-data-hardcoded-app-package/).

**Guest access through Cognito identity pools.** The front-end exposes an identity pool ID, the pool allows unauthenticated identities, and the unauthenticated role can read S3, query DynamoDB or invoke Lambda functions far beyond what the app needs. This turns a public configuration value into AWS credentials for anyone on the internet. Covered in depth in the [Cognito note](/cloud/aws-cognito-security/).

**Dangling DNS.** A CNAME still points at an S3 website endpoint, an Elastic Beanstalk environment or another claimable AWS name that the client deleted. Whoever re-creates the name serves content under the client's domain: phishing, cookie theft for the parent domain, OAuth redirect abuse, and in some cases a valid certificate issued for the subdomain. CloudFront itself is much harder to take over today (see below), and Route 53 delegation and Elastic IP issues are covered in the [VPC, edge and DNS note](/cloud/aws-vpc-edge-dns-security/).

**Abandoned but still-referenced buckets.** A bucket that software, scripts, documentation or infrastructure templates still download from is deleted. Anyone who re-registers the name serves those downloads. watchTowr's 2025 research showed the scale of this: about 150 re-registered abandoned buckets received over 8 million requests in two months, including for executables, virtual machine images and CloudFormation templates.

**Origins reachable around the edge.** The public hostname goes through CloudFront and a WAF, but the API Gateway default endpoint, the ALB hostname or the Lambda function URL is reachable directly, so WAF rules, geo-restrictions and header-based origin checks are bypassed. Depth in the [API Gateway note](/cloud/aws-api-gateway-sns-sqs-security/) and the [Lambda note](/cloud/aws-lambda-serverless-security/).

**Information disclosure that helps the next step.** Account IDs, Regions, internal hostnames, role names in error messages and front-end configuration. Individually Low or Informational; they matter because they feed cross-account trust testing (see [STS and cross-account trust](/cloud/aws-sts-cross-account-trust-federation/)) and targeted phishing.

## Testing

### Before you start

**Inputs from the client.** Agree a written list of in-scope domains, account IDs (all of them, including the management account and any "sandbox" accounts), known bucket naming conventions, GitHub/GitLab organisations, mobile app identifiers and container registry aliases. Ask explicitly whether you may run `sts get-caller-identity` with any key you find (the default answer should be no).

**Two vantage points.** Most tests here have an *outside view* (what an attacker sees) and an *inside view* (the ground truth from read-only credentials in the client's accounts). Do both when you can: the outside view proves exposure, the inside view finds what you could not guess and confirms ownership.

- Outside view: a dedicated testing AWS account owned by your company (never a personal account and never the client's), used only for calls that need *some* AWS credentials, such as listing public snapshots by owner or making signed S3 requests that simulate "any AWS customer". Name the profile clearly, for example `gt-external`.
- Inside view: a role in each client account with `SecurityAudit` and `ViewOnlyAccess` (or a custom read-only policy), for example profile `client-audit`.

**Tools.** AWS CLI v2, `jq`, `dig`, `curl`, `openssl`, a subdomain enumeration tool you already trust (passive sources and certificate transparency only, against the client's domains), [trufflehog](https://github.com/trufflesecurity/trufflehog), [gitleaks](https://github.com/gitleaks/gitleaks), jadx or apktool for Android apps, [Prowler](https://github.com/prowler-cloud/prowler) for the inside view, and optionally [Pacu](https://github.com/RhinoSecurityLabs/pacu) (only the modules named below, only against the client's account IDs). For practice, [flaws.cloud](http://flaws.cloud/) and [flaws2.cloud](http://flaws2.cloud/) cover most of this note.

**Region loop.** Public sharing settings are Regional, so every inside-view and outside-view check loops over enabled Regions:

```bash
# Enabled Regions for the account behind the current profile
REGIONS=$(aws ec2 describe-regions --query 'Regions[].RegionName' --output text)
for r in $REGIONS; do
  echo "== $r"
  # check goes here, with --region "$r"
done
```

For outside-view loops, run `describe-regions` with your own testing profile; opt-in Regions the client uses but you have not enabled will not be queryable from your account, so check the client's enabled Regions from the inside view and enable the same ones in your testing account if needed.

### GT-AWS-RECON-1: Fingerprint AWS-hosted assets from DNS, HTTP and TLS

*Guler Tech methodology.*

#### What it checks

Which of the client's in-scope hostnames run on AWS, on which service and in which Region, so that the rest of the tests target the right things. This is mapping, not a finding by itself.

#### Prerequisites

The client's in-scope domain list. Passive subdomain sources and certificate transparency for those domains only.

#### Steps

Resolve each in-scope hostname and record the CNAME chain:

```bash
while read -r h; do
  printf '%s\t' "$h"
  dig +short CNAME "$h" | tr '\n' ' '
  dig +short A "$h" | tr '\n' ' '
  echo
done < inscope-hosts.txt | tee dns-map.tsv
```

Classify by CNAME target (illustrative patterns):

```bash
grep -E 's3[.-]|s3-website' dns-map.tsv          # S3 REST or website endpoints
grep -E 'cloudfront\.net' dns-map.tsv           # CloudFront
grep -E 'elb\.amazonaws\.com' dns-map.tsv       # ALB / NLB / CLB
grep -E 'execute-api\.' dns-map.tsv             # API Gateway default endpoints
grep -E 'elasticbeanstalk\.com' dns-map.tsv     # Elastic Beanstalk
grep -E 'lambda-url\..*\.on\.aws' dns-map.tsv   # Lambda function URLs
grep -E 'amazoncognito\.com' dns-map.tsv        # Cognito managed login domains
grep -E 'amplifyapp\.com|awsapprunner\.com' dns-map.tsv
```

For A records with no AWS CNAME, map the IP to an AWS service and Region with the published ranges:

```bash
curl -s https://ip-ranges.amazonaws.com/ip-ranges.json -o ip-ranges.json
python3 - "$IP" <<'EOF'
import ipaddress, json, sys
ip = ipaddress.ip_address(sys.argv[1])
for p in json.load(open("ip-ranges.json"))["prefixes"]:
    if ip in ipaddress.ip_network(p["ip_prefix"]):
        print(p["ip_prefix"], p["service"], p["region"])
EOF
```

Fetch headers once per host, without following redirects, and record the AWS markers:

```bash
curl -sk -o /dev/null -D - "https://$h/" | \
  grep -iE '^(server|via|x-amz-|x-amzn-|x-cache|set-cookie: awsalb)'
```

Read the certificate issuer and the SAN list (SANs often reveal more in-scope names):

```bash
echo | openssl s_client -connect "$h:443" -servername "$h" 2>/dev/null | \
  openssl x509 -noout -issuer -ext subjectAltName
```

Finally, harvest AWS references from the sites' own content: HTML, JavaScript bundles and `robots.txt` often reference bucket names, API Gateway IDs, Cognito IDs and Regions:

```bash
grep -rhoE '[a-z0-9.-]+\.s3[.-][a-z0-9.-]*amazonaws\.com|[a-z0-9]{10}\.execute-api\.[a-z0-9-]+\.amazonaws\.com|[a-z]{2}-[a-z]+-[0-9]_[A-Za-z0-9]{9}' ./site-mirror | sort -u
```

#### Observation

An inventory table: hostname, AWS service, Region, how you identified it (CNAME, header, IP range, certificate), and any bucket names, API IDs or Cognito IDs referenced in content.

```text
www.example.com      CloudFront      global     CNAME d111111abcdef8.cloudfront.net; x-amz-cf-pop
assets.example.com   S3 (website)    eu-west-2  CNAME examplecorp-assets.s3-website.eu-west-2.amazonaws.com
api.example.com      API Gateway     eu-west-2  x-amz-apigw-id; JS references a1b2c3d4e5.execute-api...
old.example.com      Beanstalk       eu-west-1  CNAME examplecorp-old.eu-west-1.elasticbeanstalk.com (NXDOMAIN)
```

#### Evaluation

No pass or fail. Flag for follow-up: every S3 name (RECON-3), every CNAME to a name that no longer resolves or returns a provider error (RECON-9), every default endpoint that bypasses CloudFront (RECON-10), and every Cognito ID (RECON-8). Confirm with the client that each AWS-hosted name belongs to them; a CNAME to a third party's CloudFront distribution is a third-party asset.

#### Automated coverage

None in Security Hub CSPM or Prowler; this is outside-in work. Passive DNS and certificate transparency tools do the collection.

#### Detection

Largely undetectable by the client: DNS lookups, certificate transparency queries and single page fetches look like normal traffic. CloudFront and ALB access logs record the requests if enabled.

### GT-AWS-RECON-2: Establish the owning account IDs

*Guler Tech methodology.*

#### What it checks

Which AWS account owns each asset you found, so that you can query what that account shares publicly, decide whether a found key belongs to the client, and spot assets in accounts the client did not list (shadow accounts, agency accounts, acquisitions).

#### Prerequisites

The client's declared account IDs. Your testing profile for the `get-access-key-info` call.

#### Steps

**Ask first.** The simplest and most reliable technique is the client's own list from AWS Organizations (`aws organizations list-accounts` from the management account, inside view). Everything below is for confirming that list from the outside and catching what is missing from it.

**From public metadata.** Account IDs appear in many outside-visible places: ARNs in JavaScript and mobile app configuration, SNS topic and SQS queue ARNs in error responses, `OwnerId` on public AMIs and snapshots you already found, and S3 access point hostnames (`<name>-<account-id>.s3-accesspoint.<region>.amazonaws.com`).

**From an access key ID you were given or found.** `GetAccessKeyInfo` takes only the key ID, needs no secret, does not use the key, and is logged only in your own account:

```bash
aws sts get-access-key-info --access-key-id <ACCESS_KEY_ID> --profile gt-external
```

```json
{
    "Account": "111122223333"
}
```

The call does not tell you whether the key is active, which principal it belongs to, or what it can do. That is deliberate and is exactly where you stop (see RECON-7).

**From an S3 bucket name (research context only).** Public research has shown that the owning account of an S3 bucket can be derived from outside. In 2021 Ben Bridts (Cloudar) showed that an IAM policy in the tester's own account using the `s3:ResourceAccount` condition key with wildcards (`1*`, `11*`, ...) acts as an oracle against a *publicly readable* bucket, recovering the account ID digit by digit; the [s3-account-search](https://github.com/WeAreCloudar/s3-account-search) tool automates it. In 2024 Sam Cox (Tracebit) extended the idea to *any* bucket by moving the wildcard into a VPC endpoint policy and observing which requests reached CloudTrail; AWS then changed VPC endpoint policy evaluation in July 2024 to reject wildcards in several positions, which Tracebit reports blocks that technique and obvious variants. Whether the original IAM-policy variant still works against public buckets at the time you read this is something to verify in a lab, not assume. In a client engagement you rarely need either: if the bucket is in scope, the client tells you which account owns it. Mention the research in the report when the client's threat model includes "attacker learns our account IDs", and do not run it against buckets you have not confirmed are the client's.

#### Observation

A mapping of asset to account ID, with the source of each mapping, and a list of account IDs observed that are not in the client's declared list.

#### Evaluation

- **Pass:** every observed account ID is a declared, governed account in the client's organisation.
- **Fail (Informational to Medium):** assets live in accounts the client did not know about, or in accounts outside their organisation (a contractor's account serving the client's domain). The severity comes from the governance gap, not from the ID itself: an unknown account is an account without the client's guardrails, logging and patching.
- An account ID being discoverable is **not** a finding on its own, given AWS's position that IDs are not secret. Note it as context where it enabled another finding.

#### Automated coverage

None. Inside view: `aws organizations list-accounts`.

#### Detection

`GetAccessKeyInfo` appears only in the caller's CloudTrail, so the client cannot see it. Outside-in metadata collection is invisible to the client.

### GT-AWS-RECON-3: Client-owned S3 bucket names, existence and anonymous access

*Guler Tech methodology.*

#### What it checks

Whether bucket names referenced by or derived from the client's assets exist, who owns them, and whether they allow anonymous or any-AWS-account listing, reading or writing. Depth on bucket policy and ACL analysis is in the [S3 note](/cloud/aws-s3-security/); this test is the outside-in proof.

#### Prerequisites

Bucket names from RECON-1, from the client, or generated from the client's naming conventions with their agreement (for example `examplecorp-{prod,staging,dev}-{assets,logs,backups}`). Never generic wordlists.

#### Steps

**Existence and Region**, anonymously, one name at a time:

```bash
check_bucket() {
  code=$(curl -s -o /dev/null -w '%{http_code}' -I "https://$1.s3.amazonaws.com/")
  region=$(curl -s -I "https://$1.s3.amazonaws.com/" | awk -F': ' 'tolower($1)=="x-amz-bucket-region"{print $2}' | tr -d '\r')
  printf '%s\t%s\t%s\n' "$1" "$code" "${region:--}"
}
while read -r b; do check_bucket "$b"; sleep 1; done < client-bucket-candidates.txt
```

`404` means no such bucket (record it: a referenced but missing bucket is a RECON-9 candidate). `403` means it exists and you may not list it anonymously. `200` means anonymous listing is allowed. `301` means it exists in another Region; use the Region from the header.

**Confirm ownership before going further.** From the inside view, the bucket must appear in `aws s3api list-buckets` for one of the client's accounts. If you only have the outside view, get written confirmation from the client.

**Anonymous access**, for confirmed client buckets:

```bash
aws s3 ls "s3://examplecorp-assets/" --no-sign-request --region eu-west-2
aws s3api get-bucket-acl --bucket examplecorp-assets --no-sign-request
aws s3api get-bucket-policy --bucket examplecorp-assets --no-sign-request
aws s3api get-object --bucket examplecorp-assets --key index.html /dev/null --no-sign-request
```

**Any-AWS-account access.** Repeat the same commands signed with your own testing account. A difference between unsigned (denied) and signed (allowed) results means the bucket trusts `AuthenticatedUsers` or a `"Principal": {"AWS": "*"}` statement without an account or organisation condition:

```bash
aws s3 ls "s3://examplecorp-assets/" --profile gt-external --region eu-west-2
```

**Write access, lab or explicitly approved only.** Prove public write with a harmless marker object whose name and content the client has agreed, then confirm deletion with them:

```bash
echo "Guler Tech authorised test $(date -u +%FT%TZ)" > gt-marker.txt
aws s3 cp gt-marker.txt "s3://examplecorp-assets/gt-marker-DO-NOT-USE.txt" --no-sign-request
```

**Inside view** (ground truth):

```bash
aws s3control get-public-access-block --account-id 111122223333
for b in $(aws s3api list-buckets --query 'Buckets[].Name' --output text); do
  printf '%s\t' "$b"
  aws s3api get-bucket-policy-status --bucket "$b" --query 'PolicyStatus.IsPublic' --output text 2>/dev/null || echo "no-policy"
done
```

#### Observation

Non-compliant (illustrative):

```text
$ aws s3 ls s3://examplecorp-backups/ --no-sign-request
                           PRE db/
2026-10-30 02:00:11  734003200 prod-db-2026-10-30.sql.gz
```

Compliant:

```text
An error occurred (AccessDenied) when calling the ListObjectsV2 operation: Access Denied
```

#### Evaluation

- **Fail:** any confirmed client bucket allows anonymous or any-AWS-account `ListBucket`, `GetObject` on non-public data, or any write.
- **Pass:** all access is denied unless the bucket is an intentional public website or asset bucket, contains only intended public content, and does not allow listing or writing.
- **Common false positives:** intentional static website buckets (check the content, not just the setting); buckets fronted by CloudFront with origin access control where the bucket itself correctly denies you; `403` on a bucket the client does not own.

#### Automated coverage

Security Hub CSPM: `S3.1` (account-level Block Public Access), `S3.2` (public read), `S3.3` (public write), `S3.8` (bucket-level Block Public Access), `S3.19` (access points). Prowler: `s3_account_level_public_access_blocks`, `s3_bucket_level_public_access_block`, `s3_bucket_public_access`, `s3_bucket_public_list_acl`, `s3_bucket_public_write_acl`, `s3_bucket_policy_public_write_access`, `s3_bucket_acl_prohibited`. CIS AWS Foundations Benchmark v5.0.0 2.1.4 (and v3.0.0 2.1.4) maps to `S3.1` and `S3.8`.

#### Detection

Anonymous reads appear only in S3 server access logs or CloudTrail S3 data events (`ListObjects`, `GetObject`, `PutObject` with an anonymous principal), and data events are off by default. GuardDuty S3 Protection raises `Policy:S3/BucketAnonymousAccessGranted`, `Policy:S3/BucketPublicAccessGranted` and `Policy:S3/BucketBlockPublicAccessDisabled` when the configuration changes, and `Discovery:S3/AnomalousBehavior` or `Exfiltration:S3/AnomalousBehavior` for unusual access patterns when S3 data events are analysed.

### GT-AWS-RECON-4: Public EBS snapshots, AMIs and RDS snapshots

*Guler Tech methodology.*

#### What it checks

Whether any of the client's accounts shares EBS snapshots, AMIs or RDS/Aurora snapshots with everyone, and whether the account-level block-public-access guardrails are on. Cross-account (non-public) sharing, AMI provenance and snapshot encryption are covered in the [EC2 note](/cloud/aws-ec2-imds-ebs-ssm-security/) and the [data stores note](/cloud/aws-rds-dynamodb-data-stores-security/).

#### Prerequisites

The client's account IDs. Your testing profile (outside view) and/or `client-audit` (inside view).

#### Steps

**Outside view, EBS snapshots.** Any AWS account can list snapshots that a given owner has made publicly restorable. The owner filter keeps you to the client's accounts:

```bash
for r in $REGIONS; do
  aws ec2 describe-snapshots --region "$r" --profile gt-external \
    --owner-ids 111122223333 --restorable-by-user-ids all \
    --query 'Snapshots[].[SnapshotId,VolumeSize,Encrypted,StartTime,Description]' --output text
done
```

**Outside view, AMIs.** Owner-filtered, public only:

```bash
for r in $REGIONS; do
  aws ec2 describe-images --region "$r" --profile gt-external \
    --owners 111122223333 --filters Name=is-public,Values=true \
    --query 'Images[].[ImageId,Name,CreationDate,Description]' --output text
done
```

Pacu's `ebs__enum_snapshots_unauth` module does the snapshot query across Regions; give it only the client's account IDs.

**Inside view, guardrails and RDS:**

```bash
for r in $REGIONS; do
  echo "== $r"
  aws ec2 get-snapshot-block-public-access-state --region "$r" --query State --output text
  aws ec2 get-image-block-public-access-state --region "$r" --query ImageBlockPublicAccessState --output text
  # RDS: manual snapshots whose restore attribute includes "all"
  for s in $(aws rds describe-db-snapshots --region "$r" --snapshot-type manual \
               --query 'DBSnapshots[].DBSnapshotIdentifier' --output text); do
    aws rds describe-db-snapshot-attributes --region "$r" --db-snapshot-identifier "$s" \
      --query "DBSnapshotAttributesResult.DBSnapshotAttributes[?AttributeName=='restore'].AttributeValues[]" \
      --output text | grep -qw all && echo "PUBLIC RDS snapshot: $s"
  done
  for s in $(aws rds describe-db-cluster-snapshots --region "$r" --snapshot-type manual \
               --query 'DBClusterSnapshots[].DBClusterSnapshotIdentifier' --output text); do
    aws rds describe-db-cluster-snapshot-attributes --region "$r" --db-cluster-snapshot-identifier "$s" \
      --query "DBClusterSnapshotAttributesResult.DBClusterSnapshotAttributes[?AttributeName=='restore'].AttributeValues[]" \
      --output text | grep -qw all && echo "PUBLIC Aurora snapshot: $s"
  done
done
```

Do **not** copy, restore or mount a public snapshot to "prove" impact unless the client explicitly approves it and you do it in an isolated account they nominate. The metadata (owner, size, description, encryption flag, creation date) plus the public flag is sufficient evidence. AWS does not let you share encrypted EBS or RDS snapshots publicly, so anything you find here is unencrypted by definition; record the `Encrypted` flag anyway, because it confirms the point in the report.

#### Observation

Non-compliant (illustrative):

```text
eu-west-2  snap-0123456789abcdef0  100  False  2025-03-14T09:12:40Z  prod-db01 data volume before migration
eu-west-2  block-public-access state: unblocked
```

#### Evaluation

- **Fail (Critical when the content is production data, High otherwise):** any public EBS snapshot, public AMI not intended for distribution, or public RDS/Aurora snapshot in a client account.
- **Fail (Medium):** snapshot or AMI block public access is not enabled in a Region the client uses, with no public resources today. The guardrail is what stops the next mistake.
- **Pass:** no public snapshots or AMIs; snapshot block public access set to `block-all-sharing` and AMI block public access `block-new-sharing` (the only AMI mode) in every enabled Region.
- **False positives:** AMIs the client publishes on purpose (Marketplace or community images). Check that those images were built from a clean pipeline with no credentials baked in.

#### Automated coverage

Security Hub CSPM: `EC2.1` (EBS snapshots should not be publicly restorable), `EC2.182` (block public access for EBS snapshots), `RDS.1` (RDS snapshots should be private). At the time of writing we found no Security Hub CSPM control for AMI block public access. Prowler: `ec2_ebs_public_snapshot`, `ec2_ebs_snapshot_account_block_public_access`, `ec2_ami_public`, `ec2_ami_account_block_public_access`, `rds_snapshots_public_access`.

#### Detection

CloudTrail management events `ModifySnapshotAttribute`, `ModifyImageAttribute`, `ModifyDBSnapshotAttribute`, `ModifyDBClusterSnapshotAttribute` (look for `all` in the request parameters), and `DisableSnapshotBlockPublicAccess` / `DisableImageBlockPublicAccess`. The copy or restore by an outsider happens in *their* account and is not visible to the client, which is why the share event is the one to alert on. GuardDuty's `Exfiltration:IAMUser/AnomalousBehavior` covers unusual snapshot and restore activity by the client's own principals.

### GT-AWS-RECON-5: Public SSM documents

*Guler Tech methodology.*

#### What it checks

Whether any client SSM document is shared publicly, whether its content leaks secrets or internal detail, and whether block public sharing is on.

#### Prerequisites

Inside view preferred. Outside view needs your testing profile.

#### Steps

Inside view:

```bash
for r in $REGIONS; do
  echo "== $r"
  aws ssm get-service-setting --region "$r" \
    --setting-id /ssm/documents/console/public-sharing-permission \
    --query 'ServiceSetting.SettingValue' --output text
  for d in $(aws ssm list-documents --region "$r" --filters Key=Owner,Values=Self \
               --query 'DocumentIdentifiers[].Name' --output text); do
    aws ssm describe-document-permission --region "$r" --name "$d" --permission-type Share \
      --query 'AccountIds' --output text | grep -qw all && echo "PUBLIC: $d"
  done
done
```

A setting value of `Disable` means public sharing is blocked; `Enable` means it is allowed.

Outside view: list public documents in a Region and keep only the client's account IDs. This returns metadata for every publicly shared document in the Region, which you filter locally; do not read the content of documents owned by anyone else:

```bash
aws ssm list-documents --region eu-west-2 --profile gt-external \
  --filters Key=Owner,Values=Public \
  --query "DocumentIdentifiers[?Owner=='111122223333'].[Name,DocumentType,DocumentVersion]" --output text
```

Read the content of a public client document and scan it:

```bash
aws ssm get-document --region eu-west-2 --profile gt-external \
  --name arn:aws:ssm:eu-west-2:111122223333:document/ExampleBootstrap \
  --query Content --output text > ExampleBootstrap.json
trufflehog filesystem ExampleBootstrap.json --no-verification
```

#### Observation

The list of public documents per Region, their content summary, and any secrets found.

#### Evaluation

- **Fail (High to Critical):** a public document contains credentials, tokens or connection strings that work.
- **Fail (Medium):** a public document exposes internal hostnames, IP plans, account IDs or operational detail without being meant for publication; or block public sharing is off in a Region in use.
- **Pass:** no client document is public (or only deliberately published ones without sensitive content), and the setting is `Disable` in every enabled Region.

#### Automated coverage

Security Hub CSPM: `SSM.4` (SSM documents should not be public), `SSM.7` (block public sharing setting enabled). Prowler: `ssm_documents_set_as_public`, `ssm_document_secrets`.

#### Detection

CloudTrail `ModifyDocumentPermission` with `all` in `accountIdsToAdd`, and `UpdateServiceSetting` on the public-sharing setting.

### GT-AWS-RECON-6: Public Lambda layers, ECR repositories and ECR Public images

*Guler Tech methodology.*

#### What it checks

Whether the client publishes code artefacts (Lambda layers, container images) to everyone, and whether those artefacts contain secrets or internal configuration.

#### Prerequisites

Inside view for discovery. Outside view to prove the access and to pull public images.

#### Steps

Lambda layers, inside view. A public layer version has a policy statement with `"Principal": "*"`:

```bash
for r in $REGIONS; do
  for l in $(aws lambda list-layers --region "$r" --query 'Layers[].LayerName' --output text); do
    for v in $(aws lambda list-layer-versions --region "$r" --layer-name "$l" \
                 --query 'LayerVersions[].Version' --output text); do
      aws lambda get-layer-version-policy --region "$r" --layer-name "$l" --version-number "$v" \
        --query Policy --output text 2>/dev/null | jq -c '.Statement[] | select(.Principal=="*")' \
        | grep -q . && echo "PUBLIC layer: $r $l:$v"
    done
  done
done
```

Prove from outside that the layer is downloadable (the response includes a pre-signed `Content.Location` URL):

```bash
aws lambda get-layer-version-by-arn --region eu-west-2 --profile gt-external \
  --arn arn:aws:lambda:eu-west-2:111122223333:layer:example-shared-libs:7 \
  --query 'Content.Location' --output text
```

Download and scan only client layers:

```bash
curl -s -o layer.zip "$LOCATION" && mkdir layer && unzip -q layer.zip -d layer
trufflehog filesystem layer --no-verification
gitleaks dir layer
```

ECR private repositories with public policies, inside view:

```bash
for r in $REGIONS; do
  for repo in $(aws ecr describe-repositories --region "$r" --query 'repositories[].repositoryName' --output text); do
    aws ecr get-repository-policy --region "$r" --repository-name "$repo" --query policyText --output text 2>/dev/null \
      | jq -c '.Statement[] | select(.Principal=="*" or .Principal.AWS=="*")' | grep -q . \
      && echo "PUBLIC ECR policy: $r $repo"
  done
done
```

ECR Public, inside view (the ECR Public API lives in `us-east-1`):

```bash
aws ecr-public describe-repositories --region us-east-1 --query 'repositories[].repositoryUri' --output text
```

Pull and scan the client's public images (outside view needs no credentials):

```bash
trufflehog docker --image public.ecr.aws/<client-alias>/<repo>:latest --no-verification
docker pull public.ecr.aws/<client-alias>/<repo>:latest
docker history --no-trunc public.ecr.aws/<client-alias>/<repo>:latest | grep -iE 'secret|token|password|aws_'
```

#### Observation

The list of public layers, repositories and images, with secrets or sensitive files found in each.

#### Evaluation

- **Fail (Critical):** a public artefact contains working AWS keys or other production credentials.
- **Fail (High):** a private ECR repository allows `*` to pull without an organisation condition, or a public artefact contains internal configuration, proprietary code the client did not intend to publish, or credentials for non-production systems.
- **Pass:** public artefacts are deliberate, built from clean pipelines, and contain nothing sensitive; private repositories restrict principals with `aws:PrincipalOrgID` or explicit account IDs.

#### Automated coverage

Security Hub CSPM: `Lambda.1` covers function policies, not layers; at the time of writing we found no Security Hub CSPM control for public layer or ECR repository policies. Prowler: `ecr_repositories_not_publicly_accessible`, `ecr_repository_image_no_secrets`, `awslambda_layer_no_secrets_in_content`, `awslambda_function_using_cross_account_layers`, `awslambda_function_not_publicly_accessible`.

#### Detection

CloudTrail `AddLayerVersionPermission` (look for `principal` `*`), `SetRepositoryPolicy` in ECR, and ECR Public `CreateRepository` / `PutImage`. Downloads of a public layer by outsiders are not visible to the client.

### GT-AWS-RECON-7: Access keys leaked in code, CI, mobile apps and JavaScript

*Guler Tech methodology.*

#### What it checks

Whether AWS credentials belonging to the client are exposed in places an outsider can read: public or leaked repositories, CI logs and artefacts, mobile app packages, web JavaScript bundles, container images and the public artefacts from RECON-4 to RECON-6.

#### Prerequisites

The client's repositories (public ones, and private ones they give you access to), their app store listings, their web front-ends. Written agreement on what you may do with a key you find (default: identify and report only).

#### Steps

**Repositories.** Scan full history, not just the default branch. Turn verification off: trufflehog's verification step calls AWS with the key, which is using the credential.

```bash
trufflehog github --org=<client-org> --no-verification --json > th-org.json
trufflehog git file://./client-repo --no-verification --json > th-repo.json
gitleaks git ./client-repo --report-path gitleaks-repo.json
```

**CI logs and artefacts.** Download logs and artefacts the client exposes (public GitHub Actions runs, public build badges linking to logs) and scan them as files:

```bash
trufflehog filesystem ./ci-logs --no-verification
```

**Mobile apps.** Decompile and scan. The [hardcoded data in the app package note](/mobile/maswe-0004-sensitive-data-hardcoded-app-package/) covers acquisition and decompilation; for AWS specifically look for key pairs, Cognito pool IDs, `amplifyconfiguration.json` or `amplify_outputs.json`, `awsconfiguration.json`, and S3 bucket names:

```bash
jadx -d app-src app.apk
gitleaks dir app-src --report-path gitleaks-app.json
grep -rEo '(AKIA|ASIA)[0-9A-Z]{16}' app-src | sort -u
```

**JavaScript bundles.** Mirror the client's SPA bundles and source maps and scan them:

```bash
gitleaks dir ./site-mirror --report-path gitleaks-web.json
grep -rEo '(AKIA|ASIA)[0-9A-Z]{16}' ./site-mirror | sort -u
```

**Triage a candidate key without using it.** Identify the owning account with `GetAccessKeyInfo` (RECON-2). If the account is not the client's, stop and report it to the client as "a key belonging to a third party found in your asset"; do not contact or test the third party. If it is the client's:

```bash
aws sts get-access-key-info --access-key-id <ACCESS_KEY_ID> --profile gt-external
# Only if the client has explicitly approved it in writing:
AWS_ACCESS_KEY_ID=<ACCESS_KEY_ID> AWS_SECRET_ACCESS_KEY=<SECRET> \
  aws sts get-caller-identity
```

Then report immediately (do not wait for the final report), have the client deactivate and rotate the key, and ask them to review CloudTrail for its use. From the inside view, in the owning account, the client can find the user, its status and its last use without using the key:

```bash
aws iam get-access-key-last-used --access-key-id <ACCESS_KEY_ID>
for u in $(aws iam list-users --query 'Users[].UserName' --output text); do
  aws iam list-access-keys --user-name "$u" \
    --query "AccessKeyMetadata[?AccessKeyId=='<ACCESS_KEY_ID>'].[UserName,Status,CreateDate]" --output text
done
```

`get-access-key-last-used` returns the user name, the last service and Region the key was used with and when; CloudTrail lookups on `userIdentity.accessKeyId` give the full history.

#### Observation

Each candidate: where found (file, commit, app version, URL), key ID (truncated in the report), owning account, whether the key is still active (from the client's inside view), and the principal and its permissions.

#### Evaluation

- **Fail (Critical):** an active long-term key for a client principal is publicly exposed. Severity rises further with the principal's permissions, but even a "read-only" key is usually Critical because read access in AWS includes secrets, data and the map for the next step.
- **Fail (High):** an exposed key that is now inactive but was exposed while active (the client must investigate use in that window), or an active key found in a private location many people can read.
- **Fail (Medium):** temporary `ASIA` credentials in logs (short-lived but often still valid for hours), or keys for non-production accounts.
- **Pass:** no client credentials found; the client uses roles and short-lived credentials (OIDC federation for CI, Cognito or a backend for apps) so that there is nothing long-lived to leak.

#### Automated coverage

Security Hub CSPM and Prowler can't see code outside AWS, but they flag the conditions that make leaks dangerous: Prowler `iam_rotate_access_key_90_days`, `iam_user_two_active_access_key`, `iam_no_root_access_key`, `awslambda_function_no_secrets_in_variables`, `ec2_instance_secrets_user_data`. GitHub secret scanning (with push protection) catches AWS key pairs at commit time.

#### Detection

AWS scans public GitHub and other sources for exposed keys. When it finds one it typically opens a support case, sends an AWS Health notification and attaches the `AWSCompromisedKeyQuarantineV3` managed policy to the IAM user, which denies a set of high-risk actions; CloudTrail shows the `AttachUserPolicy` event. GuardDuty raises `CredentialAccess:IAMUser/CompromisedCredentials` when Amazon threat intelligence identifies a key as compromised and it is then used, plus `UnauthorizedAccess:IAMUser/MaliciousIPCaller`, `Recon:IAMUser/MaliciousIPCaller`, the `PenTest:IAMUser/*` findings and the `*/AnomalousBehavior` family for unusual use. The client should alert on the quarantine policy attachment as a high-priority event.

### GT-AWS-RECON-8: Cognito and Amplify identifiers in front-ends

*Guler Tech methodology.*

#### What it checks

Which Cognito user pools, app clients and identity pools the client's front-ends expose, and whether the identity pools hand out AWS credentials to unauthenticated callers. The full Cognito methodology is in the [Cognito note](/cloud/aws-cognito-security/); this test finds the entry points and runs the one benign proof that belongs in recon.

#### Prerequisites

Mirrored web bundles and decompiled apps from RECON-1 and RECON-7.

#### Steps

Extract identifiers. User pool IDs look like `<region>_<9 characters>`, identity pool IDs like `<region>:<uuid>`:

```bash
grep -rhoE '[a-z]{2}-[a-z]+-[0-9]_[A-Za-z0-9]{9}' ./site-mirror app-src | sort -u          # user pool IDs
grep -rhoE '[a-z]{2}-[a-z]+-[0-9]:[0-9a-f-]{36}' ./site-mirror app-src | sort -u           # identity pool IDs
grep -rhoE '"(aws_user_pools_web_client_id|userPoolClientId|user_pool_client_id)"[^,]*' ./site-mirror app-src | sort -u
```

Check whether an identity pool gives guest credentials. This is a single benign proof: obtain an identity ID and credentials, and confirm whose they are.

```bash
IDP=eu-west-2:00000000-1111-2222-3333-444444444444
ID=$(aws cognito-identity get-id --identity-pool-id "$IDP" --region eu-west-2 \
       --no-sign-request --query IdentityId --output text)
aws cognito-identity get-credentials-for-identity --identity-id "$ID" --region eu-west-2 \
  --no-sign-request --query 'Credentials.[AccessKeyId]' --output text
# Export the three returned values, then:
aws sts get-caller-identity
```

```json
{
    "UserId": "AROAEXAMPLEROLEID:CognitoIdentityCredentials",
    "Account": "111122223333",
    "Arn": "arn:aws:sts::111122223333:assumed-role/Cognito_ExampleUnauth_Role/CognitoIdentityCredentials"
}
```

Stop there in the recon phase. Working out what that role can do is done from the inside view by policy review, as described in the [Cognito note](/cloud/aws-cognito-security/).

#### Observation

The identifiers per front-end, and for each identity pool: guest access allowed (credentials returned) or not (`NotAuthorizedException` stating unauthenticated access is not supported).

#### Evaluation

- Exposure of pool and client IDs is **not** a finding; they are designed to be public.
- **Fail (rating depends on the role):** guest credentials are issued and the unauthenticated role has permissions beyond what the anonymous part of the app needs. Rate it in the Cognito note's terms: Critical when it reads or writes sensitive data, Low when the role is genuinely scoped to, for example, writing analytics events.
- Record which user pools allow self-sign-up (tested in the Cognito note), because a self-signed-up user turns an "authenticated role" into an effectively public one.

#### Automated coverage

Security Hub CSPM `Cognito.2` (identity pools should not allow unauthenticated identities). Prowler `cognito_identity_pool_guest_access_disabled`.

#### Detection

`GetId` and `GetCredentialsForIdentity` are CloudTrail **data events** for Cognito identity pools, not logged by default; the client needs a data event selector for `AWS::Cognito::IdentityPool` to see them. The resulting `AssumeRoleWithWebIdentity` by the Cognito service, and every API call made with the guest credentials, appear as normal management or data events under the unauthenticated role.

### GT-AWS-RECON-9: Dangling DNS pointing at deleted AWS resources

*Guler Tech methodology.*

#### What it checks

Whether any in-scope DNS record points at an AWS name that no longer exists and that someone else could claim. This test covers detection from the outside; the full treatment of Route 53, delegation and Elastic IP reuse is in the [VPC, edge and DNS note](/cloud/aws-vpc-edge-dns-security/).

#### Prerequisites

The DNS map from RECON-1.

#### Steps

**S3 website and REST CNAMEs.** For a CNAME to an S3 endpoint, the bucket name is the hostname (for website hosting) or the first label of the target. Check it:

```bash
curl -s "http://assets.example.com/" | grep -oE '<Code>NoSuchBucket</Code>|<BucketName>[^<]+</BucketName>'
```

A `NoSuchBucket` error naming the bucket means anyone can create that bucket in that Region and serve content on the client's hostname.

**Elastic Beanstalk CNAMEs.** A CNAME to `<prefix>.<region>.elasticbeanstalk.com` that returns NXDOMAIN is a candidate. Confirm whether the prefix is available (a read-only API call that creates nothing):

```bash
aws elasticbeanstalk check-dns-availability --cname-prefix examplecorp-old \
  --region eu-west-1 --profile gt-external
```

```json
{
    "Available": true,
    "FullyQualifiedCNAME": "examplecorp-old.eu-west-1.elasticbeanstalk.com"
}
```

**CloudFront CNAMEs.** A CNAME to a `cloudfront.net` hostname that returns CloudFront's "The request could not be satisfied" 403 for your hostname means no distribution currently claims that alternate domain name. Today this is rarely exploitable: CloudFront requires a trusted certificate covering the alternate domain name before it lets anyone add it, so an attacker would also need a valid certificate for the client's hostname. Record it as a dangling record to clean up (Low), and raise it only if you can show the certificate requirement is satisfiable (for example, the attacker can already obtain certificates for that name through another dangling record).

**Abandoned buckets still referenced.** Collect bucket names referenced by the client's software, documentation, install scripts, CloudFormation templates and package manifests (from RECON-1 and RECON-7) and run the RECON-3 existence check. A referenced name that returns `404` is a supply-chain risk even with no DNS record pointing at it.

**Do not take the resource over to prove it.** AWS's [penetration testing policy](https://aws.amazon.com/security/penetration-testing/) lists "S3 bucket takeover" and "Subdomain Takeover" as prohibited activities, so claiming the dangling name in a tester's account is off the table even when the client agrees. The `NoSuchBucket` response or `Available: true` result is sufficient evidence. If the client wants a demonstration, they re-create the resource in **their own** account, which is also the fix, and you confirm the hostname now serves their content.

#### Observation

Hostname, record, target, evidence of non-existence, and whether the name is claimable.

#### Evaluation

- **Fail (High):** a claimable dangling record on a hostname that shares cookies with authenticated applications, is an OAuth or SAML redirect target, is on an email or CSP allow-list, or serves scripts or downloads to other systems. Critical when it is a script or binary source loaded by production systems.
- **Fail (Medium):** a claimable dangling record on an isolated marketing hostname.
- **Fail (Low):** a dangling record that is not currently claimable (CloudFront with no certificate path, AWS-generated IDs).
- **Pass:** every AWS-pointing record resolves to a live resource the client owns.

#### Automated coverage

Security Hub CSPM `CloudFront.12` (distributions should not point to non-existent S3 origins) catches the reverse case inside the account. Prowler: `cloudfront_distributions_s3_origin_non_existent_bucket`, `route53_dangling_ip_subdomain_takeover`.

#### Detection

The takeover itself happens in the attacker's account. The client can detect the precondition by inventory: alert on `DeleteBucket`, `TerminateEnvironment` (Elastic Beanstalk) and `DeleteDistribution` events and reconcile them against DNS records. Route 53 changes appear as `ChangeResourceRecordSets`.

### GT-AWS-RECON-10: Directly reachable origins and default endpoints

*Guler Tech methodology.*

#### What it checks

Whether the protections on the public hostname (CloudFront, WAF, geo-restriction, authentication at the edge) can be bypassed by calling the origin directly: an API Gateway default `execute-api` endpoint, an ALB hostname, a Lambda function URL, an S3 bucket behind CloudFront, or an EC2 public IP.

#### Prerequisites

Origin identifiers from RECON-1 (JavaScript, headers, DNS history, the client's IaC).

#### Steps

Compare the protected and direct paths with the same benign request:

```bash
curl -s -o /dev/null -w '%{http_code}\n' "https://api.example.com/v1/health"
curl -s -o /dev/null -w '%{http_code}\n' "https://a1b2c3d4e5.execute-api.eu-west-2.amazonaws.com/prod/v1/health"
curl -s -o /dev/null -w '%{http_code}\n' "https://my-alb-123456789.eu-west-2.elb.amazonaws.com/v1/health"
curl -s -o /dev/null -w '%{http_code}\n' "https://<url-id>.lambda-url.eu-west-2.on.aws/v1/health"
```

Then check whether a request the edge would block (a WAF rule the client tells you about, a geo-blocked path) is accepted directly. Inside view, confirm the intended controls: `aws apigateway get-rest-apis` (`disableExecuteApiEndpoint`), the ALB security group (should allow only the CloudFront managed prefix list), `aws lambda get-function-url-config` (`AuthType`), and the S3 bucket policy (should allow only the distribution via origin access control).

#### Observation

Status codes and responses for each path, and the configuration that explains them.

#### Evaluation

- **Fail (Medium to High):** the origin is reachable directly and skips a security control the client relies on (WAF, authentication at the edge, geo-restriction). High when the skipped control is the only authentication.
- **Pass:** the default endpoint is disabled or locked to CloudFront (resource policy, origin access control, prefix-list security group, secret header verified at the origin), or there is nothing at the edge that the origin depends on.

#### Automated coverage

Security Hub CSPM: `CloudFront.13` (origin access control for S3 origins), `CloudFront.16` (origin access control for Lambda function URL origins), `Lambda.1`. Prowler: `awslambda_function_url_public`, `cloudfront_distributions_s3_origin_access_control`.

#### Detection

Direct calls show up in API Gateway access logs, ALB access logs and Lambda logs with source IPs that are not CloudFront's. A useful detection is "requests to the origin from outside the CloudFront prefix list".

## Hardening

**Turn on every account-level public-access guardrail, in every Region, centrally.** Use an SCP so that member accounts cannot turn them off, and declarative policies for EC2 settings where available (see the [Organizations note](/cloud/aws-organizations-multi-account-security/)).

```bash
aws s3control put-public-access-block --account-id 111122223333 \
  --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
for r in $REGIONS; do
  aws ec2 enable-snapshot-block-public-access --state block-all-sharing --region "$r"
  aws ec2 enable-image-block-public-access --image-block-public-access-state block-new-sharing --region "$r"
  aws ssm update-service-setting --setting-id /ssm/documents/console/public-sharing-permission \
    --setting-value Disable --region "$r"
done
```

An SCP that stops principals undoing those guardrails or making individual resources public (attach to all OUs except a break-glass OU, and test in a sandbox first):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyDisablingPublicAccessGuardrails",
      "Effect": "Deny",
      "Action": [
        "s3:PutAccountPublicAccessBlock",
        "ec2:DisableSnapshotBlockPublicAccess",
        "ec2:DisableImageBlockPublicAccess"
      ],
      "Resource": "*"
    },
    {
      "Sid": "DenyPublicSsmDocumentSetting",
      "Effect": "Deny",
      "Action": "ssm:UpdateServiceSetting",
      "Resource": "arn:aws:ssm:*:*:servicesetting/ssm/documents/console/public-sharing-permission"
    },
    {
      "Sid": "DenyPublicFunctionPolicies",
      "Effect": "Deny",
      "Action": "lambda:AddPermission",
      "Resource": "*",
      "Condition": { "StringEquals": { "lambda:Principal": "*" } }
    },
    {
      "Sid": "OnlyPublishingRoleSharesLayers",
      "Effect": "Deny",
      "Action": "lambda:AddLayerVersionPermission",
      "Resource": "*",
      "Condition": {
        "ArnNotLike": { "aws:PrincipalArn": "arn:aws:iam::*:role/layer-publisher" }
      }
    }
  ]
}
```

At the time of writing the [Lambda service authorization reference](https://docs.aws.amazon.com/service-authorization/latest/reference/list_awslambda.html) lists `lambda:Principal` for `AddPermission` but no condition key for `AddLayerVersionPermission`, which is why layer sharing is restricted by caller rather than by principal; recheck before deploying. Denying `s3:PutAccountPublicAccessBlock` also blocks *setting* it, so apply the guardrail before attaching the SCP, and exempt the role that manages it.

**Resource control policies (RCPs) for the data perimeter.** RCPs (November 2024) apply to resources in member accounts regardless of what the resource policy says, so they can stop "anyone outside our organisation" access to S3 even if a bucket policy is wrong:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "EnforceOrgIdentities",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": "*",
      "Condition": {
        "StringNotEqualsIfExists": { "aws:PrincipalOrgID": "o-exampleorgid" },
        "BoolIfExists": { "aws:PrincipalIsAWSService": "false" }
      }
    }
  ]
}
```

This sample denies anonymous access too, which breaks intentionally public buckets; exclude those by ARN, and read the AWS data perimeter guidance before deploying.

**Use the account regional namespace for new buckets.** It removes squatting and re-registration risk for new names. Enforce it for new bucket creation with an SCP on `s3:CreateBucket` using the `s3:x-amz-bucket-namespace` condition key (check the S3 documentation for the exact value to match).

**Never delete a bucket that anything still references.** Before deleting, search code, documentation, DNS and templates for the name. If in doubt, keep the empty bucket with a deny-all policy; a bucket you still own cannot be claimed.

**Remove DNS before resources, and inventory both.** Delete DNS records first, then the resource. Run a scheduled job that resolves every AWS-pointing record and alerts on `NoSuchBucket`, NXDOMAIN Beanstalk targets and unclaimed CloudFront hostnames.

**No long-lived keys where an alternative exists.** CI uses OIDC federation to IAM roles (see the [CI/CD note](/cloud/aws-cicd-iac-security/)), apps use Cognito or a backend, humans use IAM Identity Center. Turn on GitHub secret scanning and push protection, and run gitleaks or trufflehog in pre-commit and CI.

**Lock origins to the edge.** Disable the API Gateway default endpoint when a custom domain is used (`disableExecuteApiEndpoint`), restrict ALB security groups to the CloudFront managed prefix list, use origin access control for S3 and Lambda function URL origins.

Terraform for the main account-level settings:

```hcl
resource "aws_s3_account_public_access_block" "this" {
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_ebs_snapshot_block_public_access" "this" {
  state = "block-all-sharing"
}

resource "aws_ec2_image_block_public_access" "this" {
  state = "block-new-sharing"
}

resource "aws_ssm_service_setting" "block_public_docs" {
  setting_id    = "/ssm/documents/console/public-sharing-permission"
  setting_value = "Disable"
}
```

The EC2 and SSM resources are Regional; instantiate them per Region (provider aliases or a module per Region).

**AWS Config rules** to keep it that way: `s3-account-level-public-access-blocks-periodic`, `s3-bucket-level-public-access-prohibited`, `ebs-snapshot-public-restorable-check`, `rds-snapshots-public-prohibited`, `ssm-document-not-public`, `lambda-function-public-access-prohibited`, `cloudfront-s3-origin-non-existent-bucket`.

## Real-world cases

- **Abandoned S3 buckets as a supply chain (watchTowr, 2025).** watchTowr re-registered about 150 abandoned buckets that governments, large companies and software projects had once used, and logged over 8 million requests in two months for executables, VM images, JavaScript and CloudFormation templates. AWS sinkholed the buckets afterwards. The lesson for testers is the "referenced but missing bucket" check in RECON-9. [8 Million Requests Later, We Made The SolarWinds Supply Chain Attack Look Amateur](https://labs.watchtowr.com/8-million-requests-later-we-made-the-solarwinds-supply-chain-attack-look-amateur/).
- **Bucket Monopoly and shadow resources (Aqua Security, 2024).** Several AWS services created S3 buckets with predictable names (for example `cf-templates-<hash>-<region>` for CloudFormation), so an attacker who learnt the hash could pre-create the bucket in an unused Region and have the victim's service read templates from it, in some cases leading to account takeover. AWS fixed the affected services between March and June 2024. [Bucket Monopoly: Breaching AWS Accounts Through Shadow Resources](https://www.aquasec.com/blog/bucket-monopoly-breaching-aws-accounts-through-shadow-resources/).
- **Hardcoded AWS credentials in 1,859 mobile apps (Symantec, 2022).** Most were iOS apps; Symantec reported that 77% of them contained valid AWS access tokens and many shared the same keys through a common SDK. [Mobile supply chain: AWS credentials in apps](https://www.security.com/threat-intelligence/mobile-supply-chain-aws), with a summary in [The Hacker News](https://thehackernews.com/2022/09/over-1800-android-and-ios-apps-found.html).
- **Account ID from an S3 bucket (Cloudar 2021, Tracebit 2024).** Public research showing that a bucket's owning account can be derived from outside, and AWS's July 2024 change to VPC endpoint policy evaluation in response. [Finding the Account ID of any public S3 bucket](https://cloudar.be/awsblog/finding-the-account-id-of-any-public-s3-bucket/), [How to find the AWS Account ID of any S3 Bucket](https://tracebit.com/blog/how-to-find-the-aws-account-id-of-any-s3-bucket).

More incidents are collected in our [AWS incidents and writeups](/cloud/aws-security-incidents-and-writeups/) page and the [bug bounty reading list](/bug-bounty-writeups/).

## Rating findings

| Finding | Typical severity | Reasoning |
|---|---|---|
| Active client access key publicly exposed | Critical | Unauthenticated internet attacker gets an AWS principal; even read-only access exposes data, secrets and the map for escalation. Account-wide blast radius |
| Public EBS/RDS snapshot or AMI containing production data | Critical | Full copy of a disk or database to any AWS account, invisible to the client after the copy |
| Public bucket exposing sensitive data, or publicly writable bucket serving content | Critical | No preconditions beyond the name; write access enables content injection into whatever reads the bucket |
| Claimable dangling record on an authenticated, cookie-sharing or redirect-target hostname | High | Session theft, OAuth code theft and phishing under the client's domain; Critical if production systems load scripts or binaries from it |
| Referenced but deleted bucket still requested by software or templates | High to Critical | Supply chain: whoever claims the name serves code or templates to the client's systems or customers |
| Public SSM document, layer or image with working credentials | Critical | Same as an exposed key |
| Public SSM document, layer or image without secrets but with internal detail | Medium | Information that shortens the attacker's path; no direct access |
| Guest credentials from an identity pool with over-broad role | Low to Critical | Rated on what the role can do; see the [Cognito note](/cloud/aws-cognito-security/) |
| Origin reachable around CloudFront/WAF | Medium to High | High when the skipped edge control is the only authentication |
| Public-access guardrail off (S3 account BPA, snapshot or AMI BPA, SSM block) with nothing public today | Medium | Missing preventive control; one mistake away from exposure |
| Assets in accounts the client did not declare | Medium | Governance gap: unknown accounts lack the client's guardrails and logging |
| Dangling record that is not currently claimable | Low | Hygiene; becomes exploitable if conditions change |
| Account ID, Region or pool IDs discoverable | Informational | AWS treats these as non-secret; note only where they enabled another finding |

## Mapping

| Test | Security Hub CSPM | CIS AWS Foundations | MITRE ATT&CK |
|---|---|---|---|
| GT-AWS-RECON-1 | None | None | T1590.002, T1596, T1594 |
| GT-AWS-RECON-2 | None | None | T1596, T1594 |
| GT-AWS-RECON-3 | S3.1, S3.2, S3.3, S3.8, S3.19 | v5.0.0 2.1.4, v3.0.0 2.1.4 | T1595.003, T1619, T1530 |
| GT-AWS-RECON-4 | EC2.1, EC2.182, RDS.1 | None | T1580, T1530 |
| GT-AWS-RECON-5 | SSM.4, SSM.7 | None | T1580, T1552.001 |
| GT-AWS-RECON-6 | Lambda.1 (functions only) | None | T1580, T1552.001 |
| GT-AWS-RECON-7 | None (indirect: IAM key hygiene) | None | T1593.003, T1552.001, T1078.004 |
| GT-AWS-RECON-8 | Cognito.2 | None | T1594, T1078.004 |
| GT-AWS-RECON-9 | CloudFront.12 | None | T1584.001 |
| GT-AWS-RECON-10 | CloudFront.13, CloudFront.16, Lambda.1 | None | T1594 |

## References

- AWS: [Penetration testing policy](https://aws.amazon.com/security/penetration-testing/)
- AWS: [View AWS account identifiers](https://docs.aws.amazon.com/accounts/latest/reference/manage-acct-identifiers.html)
- AWS: [STS GetAccessKeyInfo (CLI)](https://docs.aws.amazon.com/cli/latest/reference/sts/get-access-key-info.html)
- AWS: [AWS IP address ranges](https://docs.aws.amazon.com/vpc/latest/userguide/aws-ip-ranges.html)
- AWS: [S3 HeadBucket](https://docs.aws.amazon.com/AmazonS3/latest/API/API_HeadBucket.html)
- AWS: [Namespaces for general purpose buckets](https://docs.aws.amazon.com/AmazonS3/latest/userguide/gpbucketnamespaces.html) and the [March 2026 announcement](https://aws.amazon.com/about-aws/whats-new/2026/03/amazon-s3-account-regional-namespaces)
- AWS: [Block public access for AMIs](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/block-public-access-to-amis.html)
- AWS: [Block public access for Amazon EBS snapshots](https://docs.aws.amazon.com/ebs/latest/userguide/block-public-access-snapshots.html)
- AWS: [Sharing SSM documents and blocking public sharing](https://docs.aws.amazon.com/systems-manager/latest/userguide/documents-ssm-sharing.html)
- AWS: [CloudFront alternate domain name requirements](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/CNAMEs.html)
- AWS: [Amazon Cognito logging in CloudTrail](https://docs.aws.amazon.com/cognito/latest/developerguide/logging-using-cloudtrail.html)
- AWS: [GuardDuty IAM finding types](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html), [S3 finding types](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-s3.html)
- AWS: Security Hub CSPM controls for [S3](https://docs.aws.amazon.com/securityhub/latest/userguide/s3-controls.html), [EC2](https://docs.aws.amazon.com/securityhub/latest/userguide/ec2-controls.html), [RDS](https://docs.aws.amazon.com/securityhub/latest/userguide/rds-controls.html), [SSM](https://docs.aws.amazon.com/securityhub/latest/userguide/ssm-controls.html), [Lambda](https://docs.aws.amazon.com/securityhub/latest/userguide/lambda-controls.html), [CloudFront](https://docs.aws.amazon.com/securityhub/latest/userguide/cloudfront-controls.html), [Cognito](https://docs.aws.amazon.com/securityhub/latest/userguide/cognito-controls.html)
- AWS managed policy: [AWSCompromisedKeyQuarantineV3](https://docs.aws.amazon.com/aws-managed-policy/latest/reference/AWSCompromisedKeyQuarantineV3.html)
- Tools: [Prowler](https://github.com/prowler-cloud/prowler), [trufflehog](https://github.com/trufflesecurity/trufflehog), [gitleaks](https://github.com/gitleaks/gitleaks), [Pacu](https://github.com/RhinoSecurityLabs/pacu), [s3-account-search](https://github.com/WeAreCloudar/s3-account-search), [can-i-take-over-xyz](https://github.com/EdOverflow/can-i-take-over-xyz)
- Research: [Hacking The Cloud: account ID from an S3 bucket](https://hackingthe.cloud/aws/enumeration/account_id_from_s3_bucket/), [Hacking The Cloud: account ID from access keys](https://hackingthe.cloud/aws/enumeration/get-account-id-from-keys/), [Tracebit: discovering the organisation ID of any AWS account](https://tracebit.com/blog/no-wildcard-how-i-discovered-the-organization-id-of-any-aws-account)
- Labs: [flaws.cloud](http://flaws.cloud/), [flaws2.cloud](http://flaws2.cloud/), [CloudGoat](https://github.com/RhinoSecurityLabs/cloudgoat)
- MITRE ATT&CK: [T1590.002](https://attack.mitre.org/techniques/T1590/002/), [T1593.003](https://attack.mitre.org/techniques/T1593/003/), [T1594](https://attack.mitre.org/techniques/T1594/), [T1595.003](https://attack.mitre.org/techniques/T1595/003/), [T1596](https://attack.mitre.org/techniques/T1596/), [T1580](https://attack.mitre.org/techniques/T1580/), [T1619](https://attack.mitre.org/techniques/T1619/), [T1530](https://attack.mitre.org/techniques/T1530/), [T1552.001](https://attack.mitre.org/techniques/T1552/001/), [T1078.004](https://attack.mitre.org/techniques/T1078/004/), [T1584.001](https://attack.mitre.org/techniques/T1584/001/)
