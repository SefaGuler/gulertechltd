---
title: "Amazon S3 Security"
date: 2026-11-12 18:04:00 +0000
subcategory: aws
summary: "Testing S3 as attackers use it: public access, ACLs, policies, SSE-C ransom, squatted and dangling buckets, logging gaps, plus fixes and ratings."
refs: [S3.1, S3.2, S3.3, S3.5, S3.6, S3.8, S3.9, S3.12, S3.14, S3.15, S3.17, S3.19, S3.20, S3.22, S3.23, S3.24, CIS AWS 3.0.0 2.1.1, CIS AWS 3.0.0 2.1.2, CIS AWS 3.0.0 2.1.4, CIS AWS 3.0.0 3.8, CIS AWS 3.0.0 3.9, T1530, T1619, T1537, T1485, T1486, T1565.001, T1195.002, T1583.006]
tags: [aws, s3, storage, data-exposure, encryption, supply-chain]
---

This note is part of our [AWS security testing guide](/cloud/aws-security-testing-guide/) and covers Amazon S3: how access to a bucket is actually decided, the defaults AWS changed between 2023 and 2026, and the misconfigurations we still find in reviews. Public buckets get the headlines, but they are now the minority of S3 findings. The ones that matter in 2026 are quieter: a bucket policy that trusts "any principal in any account with this one condition", a CI role that can overwrite the JavaScript your CloudFront distribution serves, an SSE-C-capable bucket in an account whose keys leaked, a CDK staging bucket name that an outsider can register first, and a DNS record or app config that still points at a bucket someone deleted. Below is the security model, what goes wrong and why, twelve tests with the commands and pass/fail criteria, the hardening that closes each gap, and how we rate the findings.

## Contents

- [How it works](#how-it-works)
- [What goes wrong](#what-goes-wrong)
- [Testing](#testing)
  - [Before you start](#before-you-start)
  - [GT-AWS-S3-1: Account and organisation Block Public Access](#gt-aws-s3-1-account-and-organisation-block-public-access)
  - [GT-AWS-S3-2: Bucket inventory, bucket-level Block Public Access and policy status](#gt-aws-s3-2-bucket-inventory-bucket-level-block-public-access-and-policy-status)
  - [GT-AWS-S3-3: ACLs, Object Ownership and legacy group grants](#gt-aws-s3-3-acls-object-ownership-and-legacy-group-grants)
  - [GT-AWS-S3-4: Bucket policy review and external access findings](#gt-aws-s3-4-bucket-policy-review-and-external-access-findings)
  - [GT-AWS-S3-5: Access points, Multi-Region Access Points and directory buckets](#gt-aws-s3-5-access-points-multi-region-access-points-and-directory-buckets)
  - [GT-AWS-S3-6: Anonymous and any-account access to client buckets](#gt-aws-s3-6-anonymous-and-any-account-access-to-client-buckets)
  - [GT-AWS-S3-7: Encryption configuration and SSE-C exposure](#gt-aws-s3-7-encryption-configuration-and-sse-c-exposure)
  - [GT-AWS-S3-8: Versioning, MFA delete, Object Lock and replication](#gt-aws-s3-8-versioning-mfa-delete-object-lock-and-replication)
  - [GT-AWS-S3-9: Server access logging and CloudTrail data events](#gt-aws-s3-9-server-access-logging-and-cloudtrail-data-events)
  - [GT-AWS-S3-10: Presigned URLs, upload flows and CORS](#gt-aws-s3-10-presigned-urls-upload-flows-and-cors)
  - [GT-AWS-S3-11: Predictable bucket names and shadow resources](#gt-aws-s3-11-predictable-bucket-names-and-shadow-resources)
  - [GT-AWS-S3-12: Dangling bucket references and writable served content](#gt-aws-s3-12-dangling-bucket-references-and-writable-served-content)
- [Hardening](#hardening)
- [Real-world cases](#real-world-cases)
- [Rating findings](#rating-findings)
- [Mapping](#mapping)
- [References](#references)

## How it works

### Buckets, objects and the request path

S3 stores objects in buckets. A **general purpose bucket** lives in one Region but, by default, its name sits in a **global namespace** shared by every AWS account in the partition: once you hold `example-assets`, nobody else can create it, and once you delete it, anybody can. Since March 2026 you can instead create buckets in your **account regional namespace**, with names that end in `-<account-id>-<region>-an`; only your account can ever create a bucket with that suffix. Existing buckets cannot be moved into it. S3 also has **directory buckets** (S3 Express One Zone, zonal namespace), **table buckets** and **vector buckets**; this note focuses on general purpose buckets and covers directory buckets briefly.

Every request is authorised by S3 against several policy types at once. In order of how often they decide a review finding:

| Control | Attached to | What it can do |
|---|---|---|
| **Identity-based policy** | IAM user or role | Grant same-account access. Cross-account access needs this *and* a resource-side grant. |
| **Bucket policy** | Bucket (max 20 KB) | Grant or deny any principal, including `"*"` (everyone) and other accounts, with conditions. |
| **Access point policy** | Access point | Same grammar, scoped to the access point; the bucket must delegate to access points. |
| **ACLs** | Bucket and each object | Legacy grants to accounts and to two predefined groups (below). Disabled on new buckets since April 2023. |
| **Block Public Access (BPA)** | Organisation, account, bucket, access point | Overrides anything above that would make data public. |
| **SCPs and RCPs** | AWS Organizations | SCPs cap what your principals can do; RCPs cap what anyone can do to your resources. |
| **VPC endpoint policy** | Gateway or interface endpoint | Caps what flows through that endpoint. |
| **KMS key policy** | KMS key | For SSE-KMS objects, the reader also needs `kms:Decrypt` on the key. |

Within an account, an explicit `Deny` anywhere wins, then an `Allow` in either the identity policy or the bucket policy is enough. Across accounts, both sides must allow. The full evaluation logic, including session policies and permissions boundaries, is in our [IAM fundamentals note](/cloud/aws-iam-fundamentals-policy-evaluation/).

### Who counts as "public"

Two ACL grantees and one policy pattern make data public:

- `http://acs.amazonaws.com/groups/global/AllUsers`: everyone on the internet, signed or not.
- `http://acs.amazonaws.com/groups/global/AuthenticatedUsers`: **any principal in any AWS account** that signs the request. The console once labelled this "Any Authenticated AWS User", and many teams read it as "users in our account". It never meant that. Anyone can create a free AWS account in a minute, so this grant is as public as `AllUsers` in practice, and S3 Block Public Access treats it that way.
- A bucket or access point policy statement with `"Principal": "*"` (or `{"AWS": "*"}`) whose conditions do not pin the caller to fixed, non-public values. S3 and IAM Access Analyzer treat conditions on keys such as `aws:SourceVpc`, `aws:SourceVpce`, `aws:PrincipalAccount`, `aws:PrincipalOrgID`, `aws:SourceArn` with fixed values, or `aws:SourceIp` with specific CIDRs, as making a statement non-public; wildcards and policy variables in those values do not.

### Block Public Access

BPA is four switches, each evaluated at the organisation, account, bucket and access point level, with the most restrictive combination winning:

| Setting | Effect |
|---|---|
| `BlockPublicAcls` | Rejects `PUT` requests that would add a public ACL (bucket or object). |
| `IgnorePublicAcls` | Makes S3 ignore public ACLs that already exist. |
| `BlockPublicPolicy` | Rejects bucket and access point policies that grant public access. |
| `RestrictPublicBuckets` | For buckets that still have a public policy, limits access to AWS service principals and authorised users in the bucket owner's account. |

The history matters when you read an older estate:

- **April 2023:** S3 enabled all four BPA settings and set Object Ownership to *bucket owner enforced* (ACLs disabled) on every **new** bucket. Buckets created before that keep whatever they had.
- **Account-level BPA** is a separate setting. It is not inherited from bucket defaults; you set it per account (and per account in every organisation member).
- **November 2025:** AWS Organizations gained an **Amazon S3 policy** type that enforces BPA at organisation, OU or account level. When it is in force, member accounts cannot change their account-level BPA settings. Before this, the usual pattern was account BPA plus an SCP denying `s3:PutAccountPublicAccessBlock`.
- **Access points and Multi-Region Access Points** get their BPA settings at creation, all on by default, and they cannot be changed afterwards.
- **Directory buckets** have BPA permanently on and ACLs permanently disabled.

### ACLs and Object Ownership

Object Ownership has three settings. **Bucket owner enforced** (default for new buckets) disables ACLs: the bucket owner owns every object, ACLs are ignored for access decisions, and `PUT` requests carrying any ACL other than `bucket-owner-full-control` fail with `AccessControlListNotSupported`. **Bucket owner preferred** and **Object writer** keep ACLs live. The second one is the dangerous legacy: an object uploaded by another account is owned by that account, and the bucket owner may not even be able to read it or change its ACL. If you switch an existing bucket back from *enforced* to an ACL-enabled setting, the old ACLs come back into force; disabling ACLs is reversible and does not delete them.

### Access points, Multi-Region Access Points, Object Lambda and directory buckets

- **Access points** are named network endpoints for a bucket, each with its own policy, BPA settings and a **network origin** of `Internet` or `VPC`. A bucket policy can delegate authorisation to access points owned by the same account using `s3:DataAccessPointAccount`, which is convenient and also means that whoever can create access points can, in effect, write new access policy for the bucket.
- **Multi-Region Access Points (MRAP)** give one global endpoint over buckets in several Regions. Their control-plane API is served from `us-west-2`. Their BPA settings are fixed at creation (Security Hub CSPM `S3.24` checks them).
- **S3 Object Lambda** access points run a Lambda function on `GET`. AWS closed Object Lambda to new customers on 7 November 2025; existing users can keep it. When you find one, review the function's role and code as part of the data path, because it sees every object it transforms.
- **Directory buckets** (S3 Express One Zone) authorise object-level calls through `CreateSession`, which returns bucket-scoped credentials valid for five minutes; the IAM action is `s3express:CreateSession`, and bucket policies (not ACLs) control access. The review questions are which principals can create sessions, and whether `s3express:SessionMode` limits them to `ReadOnly`.

### Presigned URLs and CORS

A **presigned URL** is a request already signed with someone's credentials, so it is a bearer token: whoever holds it can perform that one operation on that one key until it expires. With Signature Version 4 the maximum lifetime is **seven days**, and only when it is signed with long-term IAM user keys. A URL signed with temporary credentials (a role session, an EC2 instance profile, an ECS task role) dies when those credentials expire, whatever expiry was requested; instance profile credentials last about six hours. A URL also stops working if the signing credentials are deleted or deactivated. Bucket policies can limit presigned use with `s3:signatureAge`, `s3:authType` (`REST-QUERY-STRING` for presigned URLs) and network conditions.

**CORS** on a bucket does not grant access to anything. It tells browsers whether a script on another origin may read S3's response. A `"*"` CORS rule on a private bucket leaks nothing by itself; it becomes relevant when the bucket serves authenticated content to browsers (presigned URLs embedded in pages) or when you are assessing what a cross-origin script could do with a URL it already has.

### Encryption

- **SSE-S3** has been applied to every new object since **5 January 2023**; "is default encryption on?" is no longer a meaningful finding.
- **SSE-KMS** encrypts each object under a KMS key, so reading needs both S3 and KMS permissions and each access is visible in CloudTrail as a KMS call. **S3 Bucket Keys** cut KMS traffic by deriving a bucket-level key; the encryption context becomes the bucket ARN instead of the object ARN, so per-object KMS events disappear and key policy conditions written against object ARNs stop matching. **DSSE-KMS** adds a second layer for compliance regimes that need it.
- **SSE-C** lets the caller supply the AES-256 key with every request. AWS stores only a salted HMAC of the key, so **without the key the object cannot be read by anyone, including AWS**. This is the feature that the *Codefinger* campaign abused in January 2025 (see [Real-world cases](#real-world-cases)): with stolen keys that had `s3:GetObject` and `s3:PutObject`, the attacker rewrote objects in place under an SSE-C key only they held, then set lifecycle rules to delete them. AWS responded with a Security Blog post on blocking SSE-C through bucket policies or RCPs using the `s3:x-amz-server-side-encryption-customer-algorithm` condition key, automatic mitigations on its side, and finally a default change: since **April 2026**, SSE-C is disabled on all new general purpose buckets and on existing buckets in accounts that held no SSE-C objects. The setting is `BlockedEncryptionTypes` in the bucket's default encryption configuration, managed with `PutBucketEncryption`. Accounts that already had SSE-C data kept SSE-C enabled on their existing buckets, so you still need to check.

The same ransom idea works with SSE-KMS if the writer may name **any** KMS key: an attacker rewrites objects under a key in their own account and later disables it. Restrict `s3:x-amz-server-side-encryption-aws-kms-key-id` to your keys.

### Protecting against deletion and overwrite

- **Versioning** keeps every version; a `DELETE` adds a delete marker. Anyone with `s3:DeleteObjectVersion` or `s3:PutLifecycleConfiguration` can still remove versions, so versioning alone is not ransomware protection.
- **MFA delete** requires the root user's MFA to permanently delete versions or change versioning state. Only the root user can enable it, through the API or CLI, and it cannot be combined with lifecycle rules. It is rare in practice and that is usually acceptable.
- **Object Lock** stores versions write-once-read-many. *Governance* mode can be bypassed by principals with `s3:BypassGovernanceRetention`; *compliance* mode cannot be shortened or removed by anyone, including the root user, until retention ends. Object Lock can be enabled on existing buckets; it requires versioning.
- **Replication** (same-Region or cross-Region) copies new objects to another bucket, possibly in another account. It is a resilience control when the destination is yours and locked down, and an exfiltration channel when an attacker adds a replication rule pointing at their account (`PutBucketReplication`).

### Logging

Two independent sources record S3 activity:

- **CloudTrail management events** (bucket-level API calls such as `PutBucketPolicy`) are recorded by default.
- **CloudTrail data events** (`GetObject`, `PutObject`, `CopyObject`, `DeleteObject` and friends) are **not recorded unless you configure them**, and they are billed. Without them, there is no record of what was read or overwritten. CloudTrail does log authorisation failures (`AccessDenied`) and requests by anonymous users, but not requests that fail authentication.
- **Server access logs** are best-effort, delivered within a few hours, to a bucket or (newer) to CloudWatch Logs. They include authentication failures and lifecycle actions that CloudTrail does not.

Logging design, retention and tamper protection are covered in the [CloudTrail note](/cloud/aws-cloudtrail-logging/); this note checks that S3 itself is covered.

### Sensitive data discovery

**Amazon Macie** inventories buckets (public access, encryption, sharing) and samples objects for sensitive data such as credentials and personal data. **IAM Access Analyzer** (surfaced in the S3 console as *IAM Access Analyzer for S3*) reports buckets shared outside the zone of trust you define (account or organisation). Both are detection services; configuring them is covered in the [detection and posture note](/cloud/aws-detection-posture-services/). In a review you use their output as evidence and as a cross-check on your own policy reading.

### Static website hosting and S3 as an origin

**Static website hosting** serves a bucket at `http://<bucket>.s3-website-<region>.amazonaws.com` (or `s3-website.<region>`, depending on the Region). The website endpoint is HTTP only and serves only publicly readable content, so it needs BPA relaxed and a public read policy. The modern pattern is a private bucket behind **CloudFront with Origin Access Control (OAC)**, where the bucket policy allows `cloudfront.amazonaws.com` only with `aws:SourceArn` set to the distribution ARN. Either way, whoever can write to the bucket controls what your users' browsers execute.

## What goes wrong

**Public read through policy or ACL.** A bucket policy with `"Principal": "*"` on `s3:GetObject` for `bucket/*`, or an old `AllUsers` or `AuthenticatedUsers` ACL on a pre-2023 bucket, with BPA off at both account and bucket level. Why it matters: it is unauthenticated data access, routinely found by automated scanners, and anything inside (backups, exports, logs with tokens, `.env` files) becomes the next step.

**Public write or public ACL write.** `s3:PutObject`, `s3:PutObjectAcl` or `s3:PutBucketAcl` granted to everyone or to any authenticated AWS user. Why it matters: content tampering (malware served from your domain), cost abuse, and with ACL-write an attacker grants themselves `FULL_CONTROL`.

**Any-account access hidden behind a weak condition.** `"Principal": "*"` with a condition that only looks restrictive: `aws:SourceIp` with a broad range, `StringLike` on `aws:PrincipalArn` with `*`, `aws:Referer` (a header the caller controls), or `aws:userid` patterns. Why it matters: it is cross-account access that BPA may not classify as public and that a quick review misses.

**Over-broad cross-account trust.** A policy that grants an entire partner account (`arn:aws:iam::444455556666:root`) `s3:*`, or grants write actions such as `s3:PutBucketPolicy` and `s3:PutObjectAcl` across accounts (Security Hub CSPM `S3.6`). Why it matters: the partner's weakest principal becomes your attacker, and write-side actions let them widen access further.

**Writable buckets behind trusted delivery.** CI roles, developer roles or third-party integrations that can `PutObject` to a bucket that CloudFront, a website endpoint, a mobile app or an update mechanism serves. Why it matters: it converts an AWS credential leak into stored XSS or a software supply-chain compromise for every user.

**SSE-C (and foreign KMS keys) still allowed.** Buckets with SSE-C unblocked in accounts that had SSE-C data before April 2026, and writers allowed to name arbitrary KMS keys. Why it matters: one leaked key with `GetObject` and `PutObject` is enough for an in-place, unrecoverable encryption attack.

**No recovery path.** No versioning, or versioning without Object Lock where the same principals that write can also delete versions and set lifecycle rules. Why it matters: ransom and destruction become permanent.

**Blind spots in logging.** No CloudTrail data events on sensitive buckets, no server access logs, and logs written to a bucket the workload role can modify. Why it matters: you cannot answer "what was taken" after an incident, which turns a contained event into a notifiable breach.

**Presigned URLs as long-lived credentials.** Seven-day URLs signed with IAM user keys, URLs generated for any key a user supplies (a path-controlled IDOR), upload URLs that let the client choose the key or content type, and URLs that end up in logs, analytics or referrers. Why it matters: a URL is a bearer token; whoever sees it gets the object.

**Predictable names and shadow resources.** Infrastructure that creates or uses a bucket whose name an outsider can predict (account ID plus Region), such as CDK bootstrap staging buckets or the AWS-service defaults that Aqua's *Bucket Monopoly* research abused. Why it matters: if the attacker registers the name first, your tools upload templates or code into the attacker's bucket and read them back.

**Dangling references.** DNS records, CloudFront origins, application configuration, mobile apps, installers or documentation that point at a bucket that no longer exists. Why it matters: anyone can recreate the name and serve content to everything that still trusts it; watchTowr's 2025 research recorded more than eight million requests to 150 such buckets in two months.

## Testing

All tests assume an **authorised** engagement against the client's own AWS accounts, with written scope, within the [AWS penetration testing policy](https://aws.amazon.com/security/penetration-testing/). They are read-only unless marked otherwise. Command outputs below are **illustrative**, not captured from a real environment.

### Before you start

**Credentials.** A role in each in-scope account with the AWS managed policies `SecurityAudit` and `ViewOnlyAccess`. `SecurityAudit` covers `s3:GetBucket*`, `s3:GetAccountPublicAccessBlock`, `s3:ListAllMyBuckets` and the `s3control` list and get calls; it does **not** allow `s3:GetObject`, which is what you want for a configuration review. Ask for `access-analyzer:List*`, `macie2:Describe*`/`List*`/`Get*` and `cloudtrail:GetEventSelectors` too if they are not already covered in the client's version of those policies.

**A second, unrelated AWS account** that you own (not the client's and not a colleague's personal one), with no permissions in the client's accounts. You use it in GT-AWS-S3-6 to prove "any authenticated AWS user" exposure. Get the client's written agreement to use it against their named buckets.

**Profiles and Regions.**

```bash
export AWS_PROFILE=client-audit
aws sts get-caller-identity --query '[Account,Arn]' --output text
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
REGIONS=$(aws ec2 describe-regions --query 'Regions[].RegionName' --output text)
mkdir -p s3-review && cd s3-review
```

**Bucket inventory with Regions.** `ListBuckets` is global; ask each bucket for its Region (an empty or `null` `LocationConstraint` means `us-east-1`):

```bash
aws s3api list-buckets --query 'Buckets[].Name' --output text | tr '\t' '\n' > buckets.txt
while read -r b; do
  r=$(aws s3api get-bucket-location --bucket "$b" --query LocationConstraint --output text 2>/dev/null)
  [ "$r" = "None" ] || [ -z "$r" ] && r=us-east-1
  echo "$b $r"
done < buckets.txt > bucket-regions.txt
wc -l bucket-regions.txt
```

**Tools.** AWS CLI v2 and `jq`; [Prowler](https://github.com/prowler-cloud/prowler) (`prowler aws --service s3`); [ScoutSuite](https://github.com/nccgroup/ScoutSuite); [CloudFox](https://github.com/BishopFox/cloudfox) (`cloudfox aws buckets`, `cloudfox aws resource-trusts`); [PMapper](https://github.com/nccgroup/PMapper) for "who can write to this bucket"; [Pacu](https://github.com/RhinoSecurityLabs/pacu) (`s3__download_bucket` only on lab or explicitly approved targets). For hands-on practice, [flaws.cloud](http://flaws.cloud/) and [CloudGoat](https://github.com/RhinoSecurityLabs/cloudgoat) both include S3 scenarios.

### GT-AWS-S3-1: Account and organisation Block Public Access

*Guler Tech methodology.*

#### What it checks

Whether all four BPA settings are on for every in-scope account, whether an organisation-level S3 policy or an SCP stops member accounts from turning them off, and which accounts are intentional exceptions.

#### Prerequisites

`s3:GetAccountPublicAccessBlock` in each account; read access to AWS Organizations policies from the management account or a delegated administrator for the organisation part.

#### Steps

1. Account level, per account:

   ```bash
   aws s3control get-public-access-block --account-id "$ACCOUNT_ID"
   ```

2. Organisation level, from the management or delegated administrator account. List the S3 policies and SCPs attached to the root, OUs and accounts, and read them:

   ```bash
   aws organizations list-policies --filter SERVICE_CONTROL_POLICY \
     --query 'Policies[].[Id,Name]' --output text
   aws organizations describe-policy --policy-id p-examplescp1 \
     --query Policy.Content --output text | jq .
   ```

   For the Amazon S3 policy type, list policies of that type in the Organizations console (or with the filter value that `aws organizations list-policies help` shows in your CLI version) and record where each one is attached.

3. Search SCPs for a guard on BPA changes:

   ```bash
   aws organizations describe-policy --policy-id p-examplescp1 --query Policy.Content --output text \
     | jq '.Statement[] | select(.Effect=="Deny") | select((.Action|tostring)|test("PutAccountPublicAccessBlock|PutBucketPublicAccessBlock"))'
   ```

#### Observation

Illustrative non-compliant result:

```text
An error occurred (NoSuchPublicAccessBlockConfiguration) when calling the GetPublicAccessBlock operation:
The public access block configuration was not found
```

Illustrative compliant result:

```json
{
  "PublicAccessBlockConfiguration": {
    "BlockPublicAcls": true,
    "IgnorePublicAcls": true,
    "BlockPublicPolicy": true,
    "RestrictPublicBuckets": true
  }
}
```

#### Evaluation

**Pass:** all four settings `true` in every account, enforced by an organisation S3 policy or an SCP, with documented exceptions only for accounts whose job is public content (and even there, prefer CloudFront with OAC, which works with BPA on). **Fail:** any setting missing or `false` in an account that holds non-public data, or no guard against an account administrator turning BPA off. A failed account-level check is not by itself a public bucket; it removes the safety net, and GT-AWS-S3-2 decides whether anything fell through.

#### Automated coverage

Security Hub CSPM `S3.1` (CIS AWS Foundations Benchmark v3.0.0 2.1.4, v1.4.0 2.1.5). Prowler `s3_account_level_public_access_blocks`.

#### Detection

CloudTrail `PutAccountPublicAccessBlock` and `DeleteAccountPublicAccessBlock` (event source `s3.amazonaws.com`). GuardDuty `Policy:S3/AccountBlockPublicAccessDisabled`.

### GT-AWS-S3-2: Bucket inventory, bucket-level Block Public Access and policy status

*Guler Tech methodology.*

#### What it checks

For every bucket: its bucket-level BPA settings, whether S3 itself evaluates its policy as public, whether static website hosting is on, and what Macie already knows about it.

#### Prerequisites

The inventory from [Before you start](#before-you-start); `s3:GetBucketPublicAccessBlock`, `s3:GetBucketPolicyStatus`, `s3:GetBucketWebsite`; optionally `macie2:DescribeBuckets`.

#### Steps

1. Loop over the buckets (use each bucket's Region to avoid redirects):

   ```bash
   while read -r b r; do
     bpa=$(aws s3api get-public-access-block --bucket "$b" --region "$r" \
             --query 'PublicAccessBlockConfiguration' --output json 2>&1 | tr -d '\n ')
     pub=$(aws s3api get-bucket-policy-status --bucket "$b" --region "$r" \
             --query 'PolicyStatus.IsPublic' --output text 2>&1 | tail -1)
     web=$(aws s3api get-bucket-website --bucket "$b" --region "$r" >/dev/null 2>&1 && echo website || echo -)
     echo -e "$b\t$r\t$pub\t$web\t$bpa"
   done < bucket-regions.txt | tee bucket-bpa.tsv
   ```

2. Pull Macie's view if it is enabled (per Region):

   ```bash
   aws macie2 describe-buckets --region eu-west-2 \
     --query 'buckets[].{b:bucketName,public:publicAccess.effectivePermission,shared:sharedAccess,enc:serverSideEncryption.type}' \
     --output table
   ```

3. Run Prowler's S3 checks as a cross-check:

   ```bash
   prowler aws --service s3 --output-formats csv json-ocsf -F s3-prowler
   ```

#### Observation

Illustrative extract:

```text
example-public-docs     eu-west-2  True   website  {"BlockPublicAcls":false,"IgnorePublicAcls":false,"BlockPublicPolicy":false,"RestrictPublicBuckets":false}
example-app-uploads     eu-west-2  False  -        {"BlockPublicAcls":true,...}
example-legacy-exports  us-east-1  An error occurred (NoSuchBucketPolicy) ...  -  An error occurred (NoSuchPublicAccessBlockConfiguration) ...
```

#### Evaluation

**Pass:** BPA on at bucket level (or account level, which covers it) and `IsPublic` false, for every bucket not documented as public. **Fail:** `IsPublic` true on a bucket with non-public content, or a bucket with no BPA configuration in an account without account-level BPA; the latter is *exposure potential* until GT-AWS-S3-3 and GT-AWS-S3-4 show an actual grant. `NoSuchBucketPolicy` is normal. For each intentionally public bucket, sample the object listing (with the client) to confirm that only public content is there; public buckets accumulate private files over time.

False positives: `IsPublic` reflects the bucket policy only, not ACLs and not access points; a bucket can be public through an ACL with `IsPublic` false. Website hosting on with BPA on simply serves `403`s.

#### Automated coverage

Security Hub CSPM `S3.8` (CIS v3.0.0 2.1.4), `S3.2` (public read), `S3.3` (public write). Prowler `s3_bucket_level_public_access_block`, `s3_bucket_public_access`, `s3_bucket_policy_public_write_access`.

#### Detection

CloudTrail `PutBucketPublicAccessBlock`, `DeleteBucketPublicAccessBlock`, `PutBucketPolicy`, `PutBucketWebsite`. GuardDuty `Policy:S3/BucketBlockPublicAccessDisabled`, `Policy:S3/BucketAnonymousAccessGranted`, `Policy:S3/BucketPublicAccessGranted`.

### GT-AWS-S3-3: ACLs, Object Ownership and legacy group grants

*Guler Tech methodology.*

#### What it checks

Which buckets still have ACLs enabled, whether any bucket or sampled object ACL grants `AllUsers`, `AuthenticatedUsers` or another account, and whether objects owned by other accounts exist.

#### Prerequisites

`s3:GetBucketOwnershipControls`, `s3:GetBucketAcl`; `s3:GetObjectAcl` and `s3:ListBucket` for object sampling (agree the sample with the client).

#### Steps

1. Object Ownership per bucket:

   ```bash
   while read -r b r; do
     o=$(aws s3api get-bucket-ownership-controls --bucket "$b" --region "$r" \
           --query 'OwnershipControls.Rules[0].ObjectOwnership' --output text 2>&1 | tail -1)
     echo -e "$b\t$o"
   done < bucket-regions.txt | tee ownership.tsv
   grep -v BucketOwnerEnforced ownership.tsv
   ```

   An error such as `OwnershipControlsNotFoundError` means no setting is stored, which behaves as *Object writer*.

2. Bucket ACL grants for every bucket that is not `BucketOwnerEnforced`:

   ```bash
   aws s3api get-bucket-acl --bucket example-legacy-exports \
     | jq '.Grants[] | {who: (.Grantee.URI // .Grantee.ID // .Grantee.EmailAddress), perm: .Permission}'
   ```

3. Sample object ACLs and owners, including the oldest objects:

   ```bash
   aws s3api list-objects-v2 --bucket example-legacy-exports --fetch-owner --max-items 200 \
     --query 'Contents[].[Key,Owner.ID]' --output text | sort -k2 | uniq -c -f1 | head
   aws s3api get-object-acl --bucket example-legacy-exports --key reports/2019/summary.csv \
     | jq '.Grants[] | select(.Grantee.URI != null)'
   ```

#### Observation

Illustrative non-compliant grant:

```json
{ "who": "http://acs.amazonaws.com/groups/global/AuthenticatedUsers", "perm": "READ" }
```

#### Evaluation

**Pass:** `BucketOwnerEnforced` on every bucket, or ACLs enabled only where a documented requirement exists (for example, legacy log delivery for some services) with no group grants. **Fail:** any `AllUsers` or `AuthenticatedUsers` grant on a bucket or object, which is public access unless `IgnorePublicAcls` is on at bucket or account level; `READ` on a bucket means object **listing**, `READ` on an object means download, `WRITE` on a bucket means upload and overwrite, `READ_ACP`/`WRITE_ACP` mean read and change the ACL. Objects whose owner ID is not the bucket owner's canonical ID are a finding on their own: the client may not control access to them. Grants to other canonical IDs are cross-account access; map each to an account and check it is expected.

#### Automated coverage

Security Hub CSPM `S3.12`. Prowler `s3_bucket_acl_prohibited`, `s3_bucket_public_list_acl`, `s3_bucket_public_write_acl`.

#### Detection

CloudTrail `PutBucketAcl`, `PutBucketOwnershipControls`, `DeleteBucketOwnershipControls`; `PutObjectAcl` (data event). GuardDuty `Impact:S3/AnomalousBehavior.Permission`.

### GT-AWS-S3-4: Bucket policy review and external access findings

*Guler Tech methodology.*

#### What it checks

Every bucket policy statement that grants access outside the account: wildcard principals, whole-account trusts, write and permission-management actions granted cross-account, weak conditions, and whether a TLS-only deny is present. It also checks that the client's IAM Access Analyzer agrees with your reading.

#### Prerequisites

`s3:GetBucketPolicy`; `access-analyzer:ListAnalyzers` and `access-analyzer:ListFindingsV2`. A list of the client's own and partner account IDs and organisation ID, so you can classify principals.

#### Steps

1. Pull all policies:

   ```bash
   mkdir -p policies
   while read -r b r; do
     aws s3api get-bucket-policy --bucket "$b" --region "$r" --query Policy --output text \
       > "policies/$b.json" 2>/dev/null || rm -f "policies/$b.json"
   done < bucket-regions.txt
   ls policies | wc -l
   ```

2. Flag wildcard principals, external accounts and missing TLS denies:

   ```bash
   for f in policies/*.json; do
     jq -r --arg me "$ACCOUNT_ID" --arg f "$f" '
       .Statement[] | select(.Effect=="Allow") |
       (.Principal | if type=="string" then [.] else ([.AWS] | flatten) end) as $p |
       select(($p|index("*")) or ($p|map(select(test($me)|not))|length>0)) |
       "\($f)\t\(.Sid // "-")\t\($p|join(","))\t\(.Action|tostring)\t\(.Condition // {}|tostring)"' "$f"
   done | tee external-grants.tsv

   for f in policies/*.json; do
     jq -e '.Statement[] | select(.Effect=="Deny" and .Condition.Bool["aws:SecureTransport"]=="false")' "$f" \
       >/dev/null || echo "no TLS deny: $f"
   done
   ```

3. Read every line of `external-grants.tsv` by hand. For each statement, answer: which principals (everyone, any account, a named account, a service principal), which actions (read, list, write, delete, `PutBucketPolicy`, `PutObjectAcl`, `PutBucketAcl`, `PutEncryptionConfiguration`), and whether the conditions actually narrow the caller. Service principals such as `cloudfront.amazonaws.com` or `logging.s3.amazonaws.com` must be constrained with `aws:SourceArn` or `aws:SourceAccount`; without that, another customer's resource of the same service can use the grant (the confused deputy problem, see the [cross-account trust note](/cloud/aws-sts-cross-account-trust-federation/)).
4. Compare with Access Analyzer:

   ```bash
   ANALYZER=$(aws accessanalyzer list-analyzers --type ORGANIZATION --query 'analyzers[0].arn' --output text)
   aws accessanalyzer list-findings-v2 --analyzer-arn "$ANALYZER" \
     --filter '{"resourceType":{"eq":["AWS::S3::Bucket"]},"status":{"eq":["ACTIVE"]} }' \
     --query 'findings[].[id,resource,findingType]' --output text
   aws accessanalyzer get-finding-v2 --analyzer-arn "$ANALYZER" --id <finding-id> \
     --query 'findingDetails[].externalAccessDetails'
   ```

   If no analyzer exists, record that as a detection gap (link to the [detection note](/cloud/aws-detection-posture-services/)) and validate individual policies with `aws accessanalyzer validate-policy --policy-type RESOURCE_POLICY --validate-policy-resource-type AWS::S3::Bucket --policy-document file://policies/<bucket>.json`.

#### Observation

An illustrative statement that looks restricted but is not:

```json
{
  "Sid": "PartnerRead",
  "Effect": "Allow",
  "Principal": "*",
  "Action": ["s3:GetObject", "s3:ListBucket"],
  "Resource": ["arn:aws:s3:::example-exports", "arn:aws:s3:::example-exports/*"],
  "Condition": { "StringLike": { "aws:PrincipalArn": "arn:aws:iam::*:role/partner-sync" } }
}
```

Any AWS account can create a role called `partner-sync`. The intended condition was `aws:PrincipalAccount` equal to the partner's account ID.

#### Evaluation

**Pass:** no `Allow` to `"*"` without conditions on fixed principal, organisation or network values; cross-account grants name specific roles in known accounts and give only the actions the partner needs; no cross-account `PutBucketPolicy`, `DeleteBucketPolicy`, `PutBucketAcl`, `PutObjectAcl` or `PutEncryptionConfiguration`; a `Deny` on `aws:SecureTransport` = `false` for `s3:*`; every service principal grant constrained by source. **Fail:** any of those missing. Rate by what the external party gains (read, write, permission change) and how hard it is to become that party (anyone vs a named partner account). A missing TLS deny alone is Low: modern SDKs use HTTPS, and the realistic risk is a misconfigured client sending data over HTTP, not an attacker forcing it.

#### Automated coverage

Security Hub CSPM `S3.5` (CIS v3.0.0 2.1.1, v1.4.0 2.1.2), `S3.6`, `S3.2`, `S3.3`. Prowler `s3_bucket_secure_transport_policy`, `s3_bucket_cross_account_access`, `s3_bucket_policy_public_write_access`. CloudFox `cloudfox aws resource-trusts`.

#### Detection

CloudTrail `PutBucketPolicy`, `DeleteBucketPolicy`. Access Analyzer new external access findings to EventBridge. GuardDuty `Policy:S3/BucketAnonymousAccessGranted`, `Policy:S3/BucketPublicAccessGranted`, `Impact:S3/AnomalousBehavior.Permission`.

### GT-AWS-S3-5: Access points, Multi-Region Access Points and directory buckets

*Guler Tech methodology.*

#### What it checks

That access points, MRAPs, any remaining Object Lambda access points and directory buckets do not open a path that the bucket review missed.

#### Prerequisites

`s3:ListAccessPoints`, `s3:GetAccessPoint`, `s3:GetAccessPointPolicy`, `s3:GetAccessPointPolicyStatus`, `s3:ListMultiRegionAccessPoints`, `s3:ListAllMyDirectoryBuckets`, `s3express:GetBucketPolicy`.

#### Steps

1. Access points per Region:

   ```bash
   for r in $REGIONS; do
     aws s3control list-access-points --account-id "$ACCOUNT_ID" --region "$r" \
       --query 'AccessPointList[].[Name,Bucket,NetworkOrigin]' --output text 2>/dev/null | sed "s/^/$r\t/"
   done | tee access-points.tsv
   ```

2. For each, BPA and policy status:

   ```bash
   aws s3control get-access-point --account-id "$ACCOUNT_ID" --name example-ap --region eu-west-2 \
     --query '{origin:NetworkOrigin,vpc:VpcConfiguration.VpcId,bpa:PublicAccessBlockConfiguration}'
   aws s3control get-access-point-policy-status --account-id "$ACCOUNT_ID" --name example-ap --region eu-west-2
   aws s3control get-access-point-policy --account-id "$ACCOUNT_ID" --name example-ap --region eu-west-2 \
     --query Policy --output text | jq .
   ```

3. Find bucket policies that delegate to access points (anyone who can create an access point in that account can then write access policy for the bucket):

   ```bash
   grep -l 's3:DataAccessPointAccount\|s3:DataAccessPointArn' policies/*.json
   ```

4. MRAPs (control plane in `us-west-2`) and Object Lambda access points:

   ```bash
   aws s3control list-multi-region-access-points --account-id "$ACCOUNT_ID" --region us-west-2 \
     --query 'AccessPoints[].{name:Name,bpa:PublicAccessBlock,regions:Regions[].Bucket}'
   aws s3control list-access-points-for-object-lambda --account-id "$ACCOUNT_ID" --region eu-west-2
   ```

5. Directory buckets and their policies:

   ```bash
   aws s3api list-directory-buckets --region eu-west-2 --query 'Buckets[].Name' --output text
   aws s3api get-bucket-policy --bucket example-fast--euw2-az1--x-s3 --region eu-west-2 \
     --query Policy --output text | jq .
   ```

#### Observation

Record each access point's network origin, BPA, policy status and who can use it; for Object Lambda, the function ARN and its execution role; for directory buckets, the principals allowed `s3express:CreateSession` and any `s3express:SessionMode` condition.

#### Evaluation

**Pass:** every access point and MRAP has BPA on (S3 does not allow changing it later, so a non-compliant one must be replaced); `Internet`-origin access points exist only where justified; access point policies follow the same rules as GT-AWS-S3-4; delegation to access points is used only in accounts where `s3:CreateAccessPoint` is tightly held. **Fail:** an access point with BPA off and a public or any-account policy, a delegation pattern combined with broad `s3:CreateAccessPoint`, an Object Lambda function role with more access than the transformation needs, or a directory bucket policy granting `s3express:CreateSession` to `"*"` or to broad roles in `ReadWrite` mode.

#### Automated coverage

Security Hub CSPM `S3.19`, `S3.24`. Prowler `s3_access_point_public_access_block`, `s3_multi_region_access_point_public_access_block`.

#### Detection

CloudTrail `CreateAccessPoint`, `PutAccessPointPolicy`, `DeleteAccessPoint`, `CreateMultiRegionAccessPoint`, `PutMultiRegionAccessPointPolicy`; for directory buckets, `PutBucketPolicy` (management) and `CreateSession` (data event).

### GT-AWS-S3-6: Anonymous and any-account access to client buckets

*Guler Tech methodology.*

#### What it checks

What the policies and ACLs from the earlier tests actually allow, proved from outside: unsigned requests, and signed requests from an unrelated AWS account. This is the evidence that turns "policy looks public" into a finding.

#### Prerequisites

Written scope listing the **client-owned** buckets to test (include names discovered in their apps and DNS during [unauthenticated recon](/cloud/aws-unauthenticated-recon/), but only after the client confirms they own them). Your separate test account from [Before you start](#before-you-start). No bulk downloads: list, fetch one agreed object, stop.

#### Steps

1. Unsigned listing, ACL read and object read:

   ```bash
   B=example-public-docs
   aws s3 ls "s3://$B/" --no-sign-request | head -20
   aws s3api get-bucket-acl --bucket "$B" --no-sign-request
   aws s3api get-bucket-policy --bucket "$B" --no-sign-request
   aws s3 cp "s3://$B/agreed/sample.pdf" ./evidence/ --no-sign-request
   curl -s -o /dev/null -w '%{http_code}\n' "https://$B.s3.amazonaws.com/"
   ```

2. Any-authenticated-account access, from your unrelated account:

   ```bash
   aws sts get-caller-identity --profile gt-external
   aws s3 ls "s3://$B/" --profile gt-external | head -20
   ```

3. **Write test, lab or explicitly approved only.** Upload a harmless, clearly named marker to an approved bucket, record it, and delete it with the client (or leave it for them to delete):

   ```bash
   echo "Guler Tech authorised test $(date -u +%FT%TZ)" > gt-marker.txt
   aws s3 cp gt-marker.txt "s3://$B/gt-pentest-marker.txt" --no-sign-request
   ```

   Never overwrite an existing key, never upload executable content, and never test write on a bucket that serves production content without a change window.

#### Observation

`AccessDenied` on each call is the compliant result. Listing output, a downloaded object, or a successful marker upload is the evidence. Note which identity succeeded: unsigned (`AllUsers`/`"*"`), only the external account (`AuthenticatedUsers` or `"*"` with an `aws:` condition any account satisfies), or neither.

#### Evaluation

**Fail** (and usually High or Critical, see [Rating findings](#rating-findings)) when an unsigned or external-account request can list, read non-public objects, write, or read or change the ACL or policy. A public read of a bucket that is meant to be public, containing only public content, is not a finding; record it as accepted. Read access to `GetBucketPolicy` or `GetBucketAcl` anonymously is a minor disclosure but tells an attacker exactly what else to try.

#### Automated coverage

None directly; Security Hub CSPM and Prowler evaluate configuration, not behaviour. This test confirms their `S3.2`/`S3.3` and `s3_bucket_public_access` results.

#### Detection

CloudTrail data events record anonymous requests to the bucket owner's trail (when data events are on); server access logs record them too. GuardDuty `Discovery:S3/AnomalousBehavior`, `Exfiltration:S3/AnomalousBehavior` and the `MaliciousIPCaller`/`TorIPCaller` families apply to authenticated callers. Your test will appear in these logs; tell the client's SOC in advance if detection is not in scope.

### GT-AWS-S3-7: Encryption configuration and SSE-C exposure

*Guler Tech methodology.*

#### What it checks

The default encryption type and key per bucket, whether S3 Bucket Keys are on, whether SSE-C is blocked, whether writers can choose arbitrary KMS keys, and whether the KMS key policy is tighter or looser than the bucket policy.

#### Prerequisites

`s3:GetEncryptionConfiguration`, `kms:GetKeyPolicy`, `kms:DescribeKey`; S3 Inventory reports if the client has them (to find existing SSE-C objects).

#### Steps

1. Default encryption per bucket:

   ```bash
   while read -r b r; do
     aws s3api get-bucket-encryption --bucket "$b" --region "$r" \
       --query 'ServerSideEncryptionConfiguration.Rules[0]' --output json 2>&1 \
       | jq -c --arg b "$b" '{bucket:$b, alg:.ApplyServerSideEncryptionByDefault.SSEAlgorithm,
            key:.ApplyServerSideEncryptionByDefault.KMSMasterKeyID, bucketKey:.BucketKeyEnabled,
            blocked:.BlockedEncryptionTypes.EncryptionType}' 2>/dev/null
   done < bucket-regions.txt | tee encryption.jsonl
   jq -r 'select((.blocked // []) | index("SSE-C") | not) | .bucket' encryption.jsonl
   ```

2. Policy-level SSE-C and KMS key controls:

   ```bash
   grep -l 'x-amz-server-side-encryption-customer-algorithm' policies/*.json
   grep -l 'x-amz-server-side-encryption-aws-kms-key-id' policies/*.json
   ```

3. For SSE-KMS buckets, read the key policy and compare principals with the bucket policy:

   ```bash
   aws kms get-key-policy --key-id arn:aws:kms:eu-west-2:111122223333:key/EXAMPLE-KEY-ID \
     --policy-name default --query Policy --output text | jq '.Statement[] | {Sid,Principal,Action,Condition}'
   ```

4. If S3 Inventory is configured, count objects by encryption status (Athena over the inventory, or the CSV): look for `SSE-C` and `NOT-SSE`.

#### Observation

Illustrative extract:

```text
{"bucket":"example-app-uploads","alg":"aws:kms","key":"arn:aws:kms:eu-west-2:111122223333:key/EXAMPLE","bucketKey":true,"blocked":["SSE-C"]}
{"bucket":"example-legacy-exports","alg":"AES256","key":null,"bucketKey":false,"blocked":null}
```

#### Evaluation

**Pass:** SSE-C blocked (by `BlockedEncryptionTypes`, or by a bucket policy or RCP deny on the SSE-C header) on every bucket that does not need it; buckets holding sensitive or regulated data on SSE-KMS with a customer managed key whose policy limits `kms:Decrypt` to the principals that should read; writers restricted to approved KMS keys. **Fail:** SSE-C allowed on buckets in an account with any history of leaked keys or broad `PutObject` grants (Medium, High when combined with no versioning or Object Lock); KMS key policy granting `kms:Decrypt` to the whole account or to `"*"` with weak conditions, which makes the key no barrier at all. SSE-S3 on non-sensitive buckets is not a finding: `S3.17` is a policy choice, and we rate it Info unless the client's own standard requires KMS.

#### Automated coverage

Security Hub CSPM `S3.17`. Prowler `s3_bucket_default_encryption`, `s3_bucket_kms_encryption`. No mainstream check flags SSE-C being unblocked at the time of writing; use step 1.

#### Detection

CloudTrail data events: `PutObject`/`CopyObject` with `requestParameters.x-amz-server-side-encryption-customer-algorithm` present (the field AWS recommends baselining). Management: `PutBucketEncryption`, `DeleteBucketEncryption`, `PutBucketLifecycle`. KMS: `Decrypt` and `GenerateDataKey` volume anomalies. GuardDuty S3 Protection with Extended Threat Detection, plus `Impact:S3/AnomalousBehavior.Write` and `Impact:S3/AnomalousBehavior.Delete`.

### GT-AWS-S3-8: Versioning, MFA delete, Object Lock and replication

*Guler Tech methodology.*

#### What it checks

Whether the client can recover from overwrite and deletion of important data, whether the principals that write can also destroy history, and where replication sends copies.

#### Prerequisites

`s3:GetBucketVersioning`, `s3:GetBucketObjectLockConfiguration`, `s3:GetLifecycleConfiguration`, `s3:GetReplicationConfiguration`; a list from the client of which buckets hold data they cannot recreate.

#### Steps

1. Versioning, MFA delete and Object Lock:

   ```bash
   while read -r b r; do
     v=$(aws s3api get-bucket-versioning --bucket "$b" --region "$r" --output json)
     l=$(aws s3api get-object-lock-configuration --bucket "$b" --region "$r" \
           --query 'ObjectLockConfiguration.Rule.DefaultRetention' --output json 2>/dev/null || echo null)
     echo -e "$b\t$(echo "$v" | jq -r '.Status // "Never"')\t$(echo "$v" | jq -r '.MFADelete // "-"')\t$l"
   done < bucket-regions.txt | tee versioning.tsv
   ```

2. Lifecycle rules that expire noncurrent versions quickly (they shorten your recovery window and are what the Codefinger operators used to delete data):

   ```bash
   aws s3api get-bucket-lifecycle-configuration --bucket example-app-uploads \
     | jq '.Rules[] | {ID, Status, exp: .Expiration, ncExp: .NoncurrentVersionExpiration}'
   ```

3. Replication destinations:

   ```bash
   aws s3api get-bucket-replication --bucket example-app-uploads \
     | jq '.ReplicationConfiguration | {Role, dest: [.Rules[].Destination | {Bucket, Account}]}'
   ```

4. Who can destroy history: query PMapper or simulate the write roles for `s3:DeleteObjectVersion`, `s3:PutLifecycleConfiguration`, `s3:PutBucketVersioning`, `s3:BypassGovernanceRetention`:

   ```bash
   aws iam simulate-principal-policy \
     --policy-source-arn arn:aws:iam::111122223333:role/app-writer \
     --action-names s3:PutObject s3:DeleteObjectVersion s3:PutLifecycleConfiguration s3:PutBucketVersioning s3:BypassGovernanceRetention \
     --resource-arns 'arn:aws:s3:::example-app-uploads' 'arn:aws:s3:::example-app-uploads/*' \
     --query 'EvaluationResults[].[EvalActionName,EvalDecision]' --output table
   ```

#### Observation

Per bucket: versioning state, MFA delete, Object Lock mode and period, noncurrent expiration days, replication destination accounts, and which roles can both write and destroy versions.

#### Evaluation

**Pass:** for critical buckets, versioning enabled and either Object Lock (compliance mode for backups and logs) or a separation where the workload's writer cannot delete versions, change lifecycle or suspend versioning; replication only to accounts the client owns, ideally a separate backup account with its own lock. **Fail:** critical data with versioning `Never` or `Suspended`; writers holding delete-version and lifecycle permissions on the same bucket; replication to an account outside the organisation that the client cannot explain (treat as a potential incident and escalate). Missing MFA delete is Low on its own; AWS's `S3.20` passes buckets with lifecycle rules, and Object Lock is the stronger control.

#### Automated coverage

Security Hub CSPM `S3.14`, `S3.15`, `S3.20` (CIS v3.0.0 2.1.2), `S3.7`, `S3.10`, `S3.13`. Prowler `s3_bucket_object_versioning`, `s3_bucket_object_lock`, `s3_bucket_no_mfa_delete`, `s3_bucket_cross_region_replication`, `s3_bucket_lifecycle_enabled`.

#### Detection

CloudTrail `PutBucketVersioning`, `PutBucketLifecycle`, `DeleteBucketLifecycle`, `PutBucketReplication`, `PutObjectLockConfiguration`; data events `DeleteObject`, `DeleteObjects`, `PutObjectRetention`. GuardDuty `Impact:S3/AnomalousBehavior.Delete`.

### GT-AWS-S3-9: Server access logging and CloudTrail data events

*Guler Tech methodology.*

#### What it checks

Whether object-level reads and writes on sensitive buckets are recorded, where the records go, and whether the workload could tamper with them.

#### Prerequisites

`s3:GetBucketLogging`, `cloudtrail:DescribeTrails`, `cloudtrail:GetEventSelectors`, `cloudtrail:ListEventDataStores` (if CloudTrail Lake is used).

#### Steps

1. Server access logging per bucket:

   ```bash
   while read -r b r; do
     t=$(aws s3api get-bucket-logging --bucket "$b" --region "$r" \
           --query 'LoggingEnabled.TargetBucket' --output text)
     echo -e "$b\t$t"
   done < bucket-regions.txt | tee access-logging.tsv
   ```

2. CloudTrail data event selectors for S3 objects:

   ```bash
   for t in $(aws cloudtrail describe-trails --query 'trailList[].TrailARN' --output text); do
     echo "== $t"
     aws cloudtrail get-event-selectors --trail-name "$t" \
       | jq '[.EventSelectors[]?.DataResources[]?, .AdvancedEventSelectors[]?] '
   done
   ```

   Look for `AWS::S3::Object` (and `AWS::S3Express::Object` for directory buckets) with `readOnly` absent or covering both reads and writes, and note whether the selector covers all buckets or a prefix list.

3. Check that the log destination bucket is not writable or deletable by the workload roles (reuse step 4 of GT-AWS-S3-8 against the log bucket).

#### Observation

Illustrative non-compliant result: trail with management events only, no `DataResources`, and `access-logging.tsv` showing `None` for the bucket holding customer exports.

#### Evaluation

**Pass:** a multi-Region trail (or organisation trail) records S3 data events at least for buckets holding sensitive data, both read and write, delivered to a log archive account; server access logs on for buckets where anonymous or failed-authentication traffic matters (public buckets, website origins). **Fail:** no record of object reads for sensitive buckets (Medium; High if the bucket is internet-exposed or holds regulated data, because a breach could not be scoped). Prefix-limited selectors are acceptable when they cover the sensitive prefixes.

#### Automated coverage

Security Hub CSPM `S3.9`, `S3.22` (CIS v3.0.0 3.8), `S3.23` (CIS v3.0.0 3.9). Prowler `s3_bucket_server_access_logging_enabled`; CloudTrail checks for S3 data events are in the CloudTrail service group (see the [CloudTrail note](/cloud/aws-cloudtrail-logging/)).

#### Detection

CloudTrail `PutBucketLogging`, `PutEventSelectors`, `StopLogging`, `DeleteTrail`. GuardDuty `Stealth:S3/ServerAccessLoggingDisabled`. Verify that tampering with trails is prevented by SCP and alerted; that design is covered in the CloudTrail note.

### GT-AWS-S3-10: Presigned URLs, upload flows and CORS

*Guler Tech methodology.*

#### What it checks

How the application issues presigned URLs (whose credentials, what lifetime, for which keys), whether upload flows let the client choose keys or content, whether the bucket policy limits presigned use, and what the CORS configuration allows.

#### Prerequisites

Access to the application (test accounts at two privilege levels), its source or infrastructure code if available, and `s3:GetBucketCors`. Application-level testing is in scope only where the engagement includes the web or mobile app.

#### Steps

1. Capture presigned URLs the app hands out and decode them: `X-Amz-Credential` shows the access key ID prefix type (long-term user key vs temporary session, which also carries `X-Amz-Security-Token`), `X-Amz-Expires` the requested lifetime, `X-Amz-SignedHeaders` what is bound into the signature.
2. Test the issuer, not S3: change the key or path parameter the app uses to build the URL (another user's file ID, `../`, a prefix wildcard) and see whether the app signs it. That is an IDOR in the application, with S3 as the storage.
3. For uploads, check whether the client controls the key, `Content-Type` and `Content-Disposition`. Uploading `text/html` or SVG to a bucket served from a first-party domain is stored XSS.
4. Review the bucket policy for `s3:signatureAge`, `s3:authType` and network conditions, and find where URLs are generated with long-term keys (search code and IaC for `generate_presigned_url`, `getSignedUrl`, `presign`, `ExpiresIn`, `expires_in`).
5. CORS:

   ```bash
   aws s3api get-bucket-cors --bucket example-app-uploads | jq '.CORSRules'
   ```

#### Observation

Record URL lifetimes, signing identity type, and any URL the app signs for a key the requesting user should not reach.

#### Evaluation

**Pass:** URLs signed by a role session with short expiry (minutes for downloads, matching the upload window for uploads), keys chosen server-side, content type fixed in the signature for uploads, and URLs never logged. **Fail:** the app signs URLs for keys the user does not own (rate as the IDOR it is: High for personal or financial data); seven-day URLs signed with IAM user keys for sensitive content (Medium); client-controlled content type served from a first-party origin (rate as XSS). CORS: `AllowedOrigins: ["*"]` on a bucket that only serves public assets is fine; on a bucket that serves user content through presigned URLs, restrict to the app's origins. CORS alone is not an access-control finding.

#### Automated coverage

None in Security Hub CSPM or Prowler; this is a code and application test.

#### Detection

CloudTrail data events record presigned requests under the signing principal, which is why per-user attribution needs application logs. Bucket policy denies on `s3:signatureAge` show as `AccessDenied`.

### GT-AWS-S3-11: Predictable bucket names and shadow resources

*Guler Tech methodology.*

#### What it checks

Whether any tool, service or pipeline the client uses writes to or reads from a bucket whose name an outsider can predict, and whether that name is already held by another account in a Region the client might use.

#### Prerequisites

The client's account IDs and Regions in use and planned; their IaC and deployment tooling (CDK, Serverless Framework, SAM, Terraform modules, internal scripts); `s3:ListAllMyBuckets` and the ability to call `HeadBucket`.

#### Steps

1. Build the list of names the client's tooling expects. Patterns from public research and tools (verify against the versions the client uses):
   - AWS CDK bootstrap staging bucket: `cdk-<qualifier>-assets-<account-id>-<region>`, default qualifier `hnb659fds`.
   - Service defaults from Aqua's *Bucket Monopoly* research (fixed by AWS in 2024 by adding randomness or prompting): `aws-glue-assets-<account-id>-<region>`, `aws-emr-studio-<account-id>-<region>`, `sagemaker-<region>-<account-id>`, `cf-templates-<hash>-<region>`.
   - The client's own conventions: `<company>-<env>-<region>-logs`, `<app>-releases`, and anything a script creates "if it does not exist".
2. For each expected name in each Region (enabled or not), check existence and ownership without touching content:

   ```bash
   for r in $REGIONS; do
     n="cdk-hnb659fds-assets-$ACCOUNT_ID-$r"
     code=$(aws s3api head-bucket --bucket "$n" --expected-bucket-owner "$ACCOUNT_ID" 2>&1 | grep -oE '\(4[0-9]{2}\)|Not Found|Forbidden' | head -1)
     echo -e "$n\t${code:-exists-owned}"
   done
   ```

   `exists-owned` means the client owns it; `404`/`Not Found` means the name is free (and claimable by anyone); `403`/`Forbidden` with `--expected-bucket-owner` means a bucket exists and **someone else owns it**.
3. Check the CDK bootstrap version and the file publishing role's policy in each bootstrapped Region:

   ```bash
   aws ssm get-parameter --name /cdk-bootstrap/hnb659fds/version --region eu-west-2 --query Parameter.Value
   aws iam list-roles --query "Roles[?starts_with(RoleName,'cdk-hnb659fds-file-publishing-role')].RoleName" --output text
   ```

   Read the role's inline policy: newer bootstraps (CDK v2.149.0 and later) restrict it to buckets in the same account; older ones do not.
4. Search IaC and scripts for bucket names built from account ID and Region, and for code that writes to a bucket without `ExpectedBucketOwner`/`--expected-bucket-owner` or an `aws:ResourceAccount` condition on the writing role.

#### Observation

A table of expected names with their state per Region; the CDK bootstrap version per Region; roles that write to pattern-named buckets without an ownership guard.

#### Evaluation

**Fail (High–Critical):** an expected name is **already owned by another account** in a Region the client uses or might deploy to. Treat it as a potential compromise path: stop deployments to that Region and investigate with the client. **Fail (Medium):** deployment roles that write to predictable names without `aws:ResourceAccount` or expected-owner checks, or CDK bootstraps older than v2.149.0, even if no name is taken today (the name is claimable at any time). **Pass:** buckets created in the account regional namespace or with unpredictable suffixes, deployment roles restricted with `aws:ResourceAccount`, and bootstraps current. This is a check on names derived from the client's own account ID, not a scan of other organisations' buckets.

#### Automated coverage

Prowler `s3_bucket_shadow_resource_vulnerability` (covers known service default patterns; check its metadata for the current list). No Security Hub CSPM control.

#### Detection

There is nothing to detect in the client's account when an outsider creates a bucket with a predictable name; prevention (namespace, ownership guards) is the control. After the fact, look for deployment failures such as `AccessDenied` on `HeadBucket` or `PutObject` to expected staging buckets (a bucket that suddenly exists but is not yours is the signal).

### GT-AWS-S3-12: Dangling bucket references and writable served content

*Guler Tech methodology.*

#### What it checks

Two ways S3 becomes an attacker's delivery channel to the client's users: references to buckets that no longer exist (claimable by anyone), and existing buckets that serve code or content to users and can be written by too many principals.

#### Prerequisites

Route 53 and CloudFront read access (`route53:ListResourceRecordSets`, `cloudfront:ListDistributions`); the client's web front ends, mobile apps and installers in scope; PMapper graph or `simulate-principal-policy` access.

#### Steps

1. DNS records pointing at S3:

   ```bash
   for z in $(aws route53 list-hosted-zones --query 'HostedZones[].Id' --output text); do
     aws route53 list-resource-record-sets --hosted-zone-id "$z" \
       --query "ResourceRecordSets[?contains(to_string(ResourceRecords), 's3') || contains(to_string(AliasTarget), 's3')].[Name,Type,ResourceRecords[0].Value,AliasTarget.DNSName]" \
       --output text
   done | tee dns-s3.tsv
   ```

2. CloudFront origins on S3:

   ```bash
   aws cloudfront list-distributions \
     --query 'DistributionList.Items[].{id:Id,aliases:Aliases.Items,origins:Origins.Items[].DomainName}' --output json \
     | jq -r '.[] | .id as $id | .origins[] | select(test("s3")) | "\($id)\t\(.)"' | tee cf-s3-origins.tsv
   ```

3. Bucket names referenced by apps: grep the client's front-end bundles, mobile app packages ([keys and endpoints in apps](/mobile/maswe-0004-sensitive-data-hardcoded-app-package/)), installers, documentation and IaC for `s3.amazonaws.com`, `s3-website`, `s3://` and `amazonaws.com/<bucket>`.
4. For every referenced bucket, confirm it exists and the client owns it:

   ```bash
   aws s3api head-bucket --bucket example-old-assets --expected-bucket-owner "$ACCOUNT_ID"
   curl -s "http://example-old-assets.s3-website-eu-west-1.amazonaws.com/" | grep -o 'NoSuchBucket'
   ```

   A `NoSuchBucket` response through the client's hostname, or a `404` from `head-bucket`, is a dangling reference. Do **not** register the bucket to prove it; report it. AWS's [penetration testing policy](https://aws.amazon.com/security/penetration-testing/) lists "S3 bucket takeover" as a prohibited activity. Re-creating the bucket is the client's remediation step, done in their own account.
5. Who can write to buckets that serve users (CloudFront origins, website buckets, app asset and update buckets):

   ```bash
   pmapper --account 111122223333 query 'who can do s3:PutObject with arn:aws:s3:::example-web-assets/*'
   ```

   Add principals from other accounts granted in the bucket policy (GT-AWS-S3-4) and third-party CI integrations.

#### Observation

A list of dangling references with where each is referenced, and for each served bucket the set of principals that can write, including CI, developer roles and external accounts.

#### Evaluation

**Fail (High–Critical):** a client hostname, CloudFront origin, app or installer references a non-existent bucket. Impact depends on what is loaded: script or update content is Critical (code execution in users' browsers or devices); images and documents are Medium–High (defacement, phishing on a trusted domain). **Fail (High):** a broad set of principals (all developers, a shared CI role used by many pipelines, an external account) can overwrite JavaScript or update packages served to users. **Pass:** every reference resolves to a client-owned bucket, served buckets are private behind CloudFront OAC, and write access is limited to the deployment pipeline for that site. Dangling DNS in general, including other services, is covered in the [VPC, edge and DNS note](/cloud/aws-vpc-edge-dns-security/).

#### Automated coverage

None in Security Hub CSPM; Prowler has Route 53 dangling-record checks (see the NET note). Write-path analysis needs PMapper or manual review.

#### Detection

For writable content: CloudTrail `PutObject` data events on the served bucket by unexpected principals, S3 event notifications to a change-review queue, and GuardDuty `Impact:S3/AnomalousBehavior.Write`. For dangling references: nothing in AWS; only inventory and DNS hygiene prevent it.

## Hardening

**Turn public access off at the top and enforce it.** Use the organisation-level Amazon S3 policy for BPA where it is available to you; otherwise enable account-level BPA everywhere and guard it with an SCP:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ProtectS3PublicAccessBlock",
      "Effect": "Deny",
      "Action": ["s3:PutAccountPublicAccessBlock", "s3:PutBucketPublicAccessBlock"],
      "Resource": "*",
      "Condition": {
        "ArnNotLike": { "aws:PrincipalArn": "arn:aws:iam::*:role/org-security-admin" }
      }
    }
  ]
}
```

Serve public content through CloudFront with OAC from a private bucket, so even public websites can keep BPA on.

**Organisation-wide data perimeter with RCPs.** RCPs apply to every request to your S3 resources, including from outside the organisation. A common baseline: TLS only, no SSE-C, and no access from principals outside the organisation except AWS services acting for you:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "EnforceTLS",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": "*",
      "Condition": { "Bool": { "aws:SecureTransport": "false" } }
    },
    {
      "Sid": "BlockSSEC",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObject",
      "Resource": "*",
      "Condition": { "Null": { "s3:x-amz-server-side-encryption-customer-algorithm": "false" } }
    },
    {
      "Sid": "OrgPrincipalsOnly",
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

Test the third statement carefully before attaching it: intentionally public buckets, partner access and some service integrations need exceptions (AWS's data perimeter examples show the patterns).

**Bucket baseline in IaC.** A Terraform baseline for a private bucket:

```hcl
resource "aws_s3_bucket" "data" {
  bucket = "example-data-111122223333-eu-west-2-an"
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket                  = aws_s3_bucket.data.id
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "data" {
  bucket = aws_s3_bucket.data.id
  rule { object_ownership = "BucketOwnerEnforced" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "data" {
  bucket = aws_s3_bucket.data.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.data.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_versioning" "data" {
  bucket = aws_s3_bucket.data.id
  versioning_configuration { status = "Enabled" }
}

data "aws_iam_policy_document" "data" {
  statement {
    sid     = "DenyInsecureTransport"
    effect  = "Deny"
    actions = ["s3:*"]
    resources = [aws_s3_bucket.data.arn, "${aws_s3_bucket.data.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
  statement {
    sid       = "OnlyOurKmsKey"
    effect    = "Deny"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.data.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "StringNotEqualsIfExists"
      variable = "s3:x-amz-server-side-encryption-aws-kms-key-id"
      values   = [aws_kms_key.data.arn]
    }
  }
}

resource "aws_s3_bucket_policy" "data" {
  bucket = aws_s3_bucket.data.id
  policy = data.aws_iam_policy_document.data.json
}
```

The bucket name uses the account regional namespace suffix; check that your AWS provider version supports the namespace parameter when creating it, or create it with `aws s3api create-bucket --bucket-namespace account-regional`. In CloudFormation, use `BucketNamespace: account-regional` with `BucketNamePrefix` or a `!Sub` name built from `${AWS::AccountId}` and `${AWS::Region}`.

**Block SSE-C explicitly** on existing buckets that do not need it (new buckets already have it blocked):

```bash
aws s3api put-bucket-encryption --bucket example-legacy-exports \
  --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"},"BlockedEncryptionTypes":{"EncryptionType":["SSE-C"]} }]}'
```

**Make destruction hard.** Versioning on critical buckets, Object Lock in compliance mode for backups and logs, a separate backup account receiving replicated copies with its own lock, and writer roles that do not hold `s3:DeleteObjectVersion`, `s3:PutLifecycleConfiguration` or `s3:PutBucketVersioning`.

**Stop bucket sniping.** Require new buckets in the account regional namespace:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "RequireAccountRegionalBucketCreation",
      "Effect": "Deny",
      "Action": "s3:CreateBucket",
      "Resource": "*",
      "Condition": { "StringNotEquals": { "s3:x-amz-bucket-namespace": "account-regional" } }
    }
  ]
}
```

and give deployment and service roles that write to buckets an ownership guard:

```json
{
  "Sid": "OnlyOurBuckets",
  "Effect": "Deny",
  "Action": ["s3:PutObject", "s3:GetObject"],
  "Resource": "*",
  "Condition": { "StringNotEquals": { "aws:ResourceAccount": "111122223333" } }
}
```

Upgrade CDK to v2.149.0 or later and re-run `cdk bootstrap` in every Region. Never delete a bucket that is still referenced anywhere; empty it and keep it, or remove every reference first.

**Least-privilege writers for served content.** One deployment role per site, assumable only by that site's pipeline (OIDC with a repository and branch condition, see the [CI/CD note](/cloud/aws-cicd-iac-security/)), with S3 event notifications or CloudTrail-based alerts on writes from anyone else. Add Subresource Integrity to third-party script tags you load from S3-backed CDNs where you can.

**Logging and detection.** CloudTrail data events for sensitive buckets into a log archive account; server access logs (or their CloudWatch Logs delivery) for public and website buckets; GuardDuty S3 Protection on in every account and Region; Macie automated discovery on buckets with personal data; IAM Access Analyzer with an organisation zone of trust. AWS Config rules behind the Security Hub CSPM controls above (`s3-bucket-level-public-access-prohibited`, `s3-bucket-ssl-requests-only`, `s3-bucket-acl-prohibited`, `s3-bucket-versioning-enabled`, `s3-bucket-logging-enabled`) give you continuous evaluation.

## Real-world cases

- **Codefinger: S3 ransom with SSE-C (January 2025).** Attackers used compromised AWS keys with `s3:GetObject` and `s3:PutObject` to re-encrypt objects in place with SSE-C under keys only they held, and set seven-day lifecycle deletion to pressure victims. No AWS vulnerability was involved. AWS's response is in [Preventing unintended encryption of Amazon S3 objects](https://aws.amazon.com/blogs/security/preventing-unintended-encryption-of-amazon-s3-objects/) and the later [advance notice of SSE-C being disabled by default](https://aws.amazon.com/blogs/storage/advanced-notice-amazon-s3-to-disable-the-use-of-sse-c-encryption-by-default-for-all-new-buckets-and-select-existing-buckets-in-april-2026/); press coverage in [The Register](https://www.theregister.com/2025/01/13/ransomware_crew_abuses_compromised_aws/). The lesson for testers: SSE-C exposure is a function of leaked-key likelihood and recovery controls, so rate it together with GT-AWS-S3-8.
- **Bucket Monopoly and shadow resources (Aqua, August 2024).** Aqua showed that CloudFormation, Glue, EMR, SageMaker, Service Catalog and CodeStar used predictable bucket names; an attacker who created the name first in an unused Region received the victim's templates or code and could modify them, up to account takeover. AWS fixed the services in 2024. [Bucket Monopoly: Breaching AWS Accounts Through Shadow Resources](https://www.aquasec.com/blog/bucket-monopoly-breaching-aws-accounts-through-shadow-resources/). A follow-up showed the same pattern for CDK bootstrap staging buckets when the bucket had been deleted, fixed for new bootstraps in CDK v2.149.0: [AWS CDK Risk: Exploiting a Missing S3 Bucket Allowed Account Takeover](https://www.aquasec.com/blog/aws-cdk-risk-exploiting-a-missing-s3-bucket-allowed-account-takeover/).
- **Abandoned buckets still trusted by software (watchTowr, February 2025).** watchTowr re-registered about 150 abandoned buckets that had been used by software vendors, governments and deployment pipelines, and logged more than eight million requests in two months for binaries, VM images, JavaScript, CloudFormation templates and VPN configurations. AWS sinkholed the buckets afterwards. [8 Million Requests Later, We Made The SolarWinds Supply Chain Attack Look Amateur](https://labs.watchtowr.com/8-million-requests-later-we-made-the-solarwinds-supply-chain-attack-look-amateur/). This is the research behind GT-AWS-S3-12, and the reason AWS introduced the account regional namespace in 2026.
- **flaws.cloud (lab).** Scott Piper's [flaws.cloud](http://flaws.cloud/) walks through bucket listing, any-authenticated-user access and key discovery in S3 hands-on; it is the fastest way to train a new tester on GT-AWS-S3-6.

## Rating findings

| Finding | Typical severity | Reasoning |
|---|---|---|
| Anonymous or any-AWS-account read of sensitive data (confirmed in GT-AWS-S3-6) | Critical | Unauthenticated internet attacker, direct data access, often found by scanners; blast radius is everything in the bucket. |
| Anonymous or any-account write to a bucket that serves scripts, updates or templates | Critical | Code execution in users' browsers or devices, or in the client's deployment; the bucket is a supply-chain foothold. |
| Dangling reference to a deleted bucket loaded as script, update or template | Critical | Anyone can claim the name and serve code under the client's trust; no credentials needed. |
| Predictable deployment bucket name already owned by another account | High–Critical | Deployment content may already flow to an outsider; Critical when the deploying role is administrative (CDK default). |
| Anonymous or any-account write to a non-served bucket, or public ACL write | High | Content tampering, malware hosting, cost abuse; ACL write lets the attacker grant themselves full control. |
| Dangling reference loaded as images or documents | Medium–High | Defacement or phishing on a trusted domain; no code execution. |
| Bucket policy granting a whole external account or weakly conditioned `"*"` read to sensitive data | High | Any principal in that account, or anyone who can satisfy the weak condition, reads the data; lower to Medium for a named, contracted partner role with read-only access. |
| Cross-account `PutBucketPolicy`, `PutBucketAcl` or `PutObjectAcl` | High | The external party can widen its own access at will. |
| Broad principals can overwrite served JavaScript or update packages | High | A single leaked developer or CI credential becomes a user-facing compromise. |
| Presigned URL issuance signs keys the user does not own | High | Application IDOR with direct data access; severity follows the data. |
| SSE-C unblocked with no versioning or Object Lock on critical data | High | One leaked writer key leads to unrecoverable encryption; Medium when versioning with separated delete rights exists. |
| Replication to an account outside the organisation that the client cannot explain | High (escalate) | Possible ongoing exfiltration; treat as an incident until explained. |
| No CloudTrail data events on sensitive buckets | Medium | Breach scope cannot be determined; High when the bucket is internet-exposed or regulated. |
| Account-level BPA off with no public bucket found | Medium | No current exposure, but no safety net against a single policy mistake. |
| Deployment roles writing to predictable names without ownership guard; CDK bootstrap older than v2.149.0 | Medium | Exploitable whenever the bucket is missing in a Region; prevention is cheap. |
| ACLs still enabled with no public or unexpected grants | Low | Legacy attack surface, objects possibly owned by other accounts; no current exposure. |
| No TLS-only deny in bucket policy | Low | Requires a misconfigured client to send data over HTTP; no attacker-forced path. |
| MFA delete off; SSE-S3 instead of SSE-KMS on non-sensitive data | Info–Low | Hygiene; stronger controls (Object Lock, KMS where required) matter more. |

## Mapping

| Test | Security Hub CSPM | CIS AWS Foundations Benchmark | MITRE ATT&CK |
|---|---|---|---|
| GT-AWS-S3-1 | S3.1 | v3.0.0 2.1.4; v1.4.0 2.1.5 | T1530 |
| GT-AWS-S3-2 | S3.8, S3.2, S3.3 | v3.0.0 2.1.4; v1.4.0 2.1.5 | T1530, T1619 |
| GT-AWS-S3-3 | S3.12 | – | T1530, T1619 |
| GT-AWS-S3-4 | S3.5, S3.6, S3.2, S3.3 | v3.0.0 2.1.1; v1.4.0 2.1.2 | T1530, T1537 |
| GT-AWS-S3-5 | S3.19, S3.24 | – | T1530 |
| GT-AWS-S3-6 | (confirms S3.2, S3.3) | – | T1530, T1619 |
| GT-AWS-S3-7 | S3.17 | – | T1486 |
| GT-AWS-S3-8 | S3.14, S3.15, S3.20, S3.7, S3.10, S3.13 | v3.0.0 2.1.2; v1.4.0 2.1.3 | T1485, T1486, T1537 |
| GT-AWS-S3-9 | S3.9, S3.22, S3.23 | v3.0.0 3.8, 3.9 | – (detection gap) |
| GT-AWS-S3-10 | – | – | T1530 |
| GT-AWS-S3-11 | – | – | T1583.006, T1195.002 |
| GT-AWS-S3-12 | – | – | T1583.006, T1565.001, T1195.002 |

CIS numbers are taken from the Security Hub CSPM control pages at the time of writing; CIS v5.0.0 uses the same numbers for these S3 controls. *Security Hub CSPM* is the name AWS gave the original Security Hub posture product in 2025, when it launched the new unified Security Hub; the control IDs did not change.

## References

- Amazon S3 User Guide: [Blocking public access to your Amazon S3 storage](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html)
- Amazon S3 User Guide: [Controlling ownership of objects and disabling ACLs](https://docs.aws.amazon.com/AmazonS3/latest/userguide/about-object-ownership.html)
- Amazon S3 User Guide: [Namespaces for general purpose buckets](https://docs.aws.amazon.com/AmazonS3/latest/userguide/gpbucketnamespaces.html)
- Amazon S3 User Guide: [Download and upload objects with presigned URLs](https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-presigned-url.html)
- Amazon S3 User Guide: [Blocking or unblocking SSE-C for a general purpose bucket](https://docs.aws.amazon.com/AmazonS3/latest/userguide/blocking-unblocking-s3-c-encryption-gpb.html) and [Default SSE-C setting for new buckets FAQ](https://docs.aws.amazon.com/AmazonS3/latest/userguide/default-s3-c-encryption-setting-faq.html)
- Amazon S3 User Guide: [Logging options for Amazon S3](https://docs.aws.amazon.com/AmazonS3/latest/userguide/logging-with-S3.html)
- Amazon S3 User Guide: [Security best practices for directory buckets](https://docs.aws.amazon.com/AmazonS3/latest/userguide/s3-express-security-best-practices.html)
- Amazon S3 User Guide: [Amazon S3 Object Lambda availability change](https://docs.aws.amazon.com/AmazonS3/latest/userguide/amazons3-ol-change.html)
- AWS What's New: [Amazon S3 Block Public Access now supports organization-level enforcement](https://aws.amazon.com/about-aws/whats-new/2025/11/amazon-s3-block-public-access-organization-level-enforcement/)
- AWS Organizations User Guide: [Amazon S3 policies](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_s3.html)
- AWS Security Hub User Guide: [Security Hub CSPM controls for Amazon S3](https://docs.aws.amazon.com/securityhub/latest/userguide/s3-controls.html)
- Amazon GuardDuty User Guide: [GuardDuty S3 Protection finding types](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-s3.html)
- AWS Security Blog: [Preventing unintended encryption of Amazon S3 objects](https://aws.amazon.com/blogs/security/preventing-unintended-encryption-of-amazon-s3-objects/)
- Aqua Security: [Bucket Monopoly: Breaching AWS Accounts Through Shadow Resources](https://www.aquasec.com/blog/bucket-monopoly-breaching-aws-accounts-through-shadow-resources/) and [AWS CDK Risk: Exploiting a Missing S3 Bucket Allowed Account Takeover](https://www.aquasec.com/blog/aws-cdk-risk-exploiting-a-missing-s3-bucket-allowed-account-takeover/)
- watchTowr Labs: [8 Million Requests Later, We Made The SolarWinds Supply Chain Attack Look Amateur](https://labs.watchtowr.com/8-million-requests-later-we-made-the-solarwinds-supply-chain-attack-look-amateur/)
- MITRE ATT&CK: [T1530 Data from Cloud Storage](https://attack.mitre.org/techniques/T1530/), [T1619 Cloud Storage Object Discovery](https://attack.mitre.org/techniques/T1619/), [T1537 Transfer Data to Cloud Account](https://attack.mitre.org/techniques/T1537/), [T1486 Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/), [T1485 Data Destruction](https://attack.mitre.org/techniques/T1485/), [T1565.001 Stored Data Manipulation](https://attack.mitre.org/techniques/T1565/001/), [T1195.002 Compromise Software Supply Chain](https://attack.mitre.org/techniques/T1195/002/), [T1583.006 Acquire Infrastructure: Web Services](https://attack.mitre.org/techniques/T1583/006/)
- Tools: [Prowler](https://github.com/prowler-cloud/prowler), [ScoutSuite](https://github.com/nccgroup/ScoutSuite), [CloudFox](https://github.com/BishopFox/cloudfox), [PMapper](https://github.com/nccgroup/PMapper), [Pacu](https://github.com/RhinoSecurityLabs/pacu), [CloudGoat](https://github.com/RhinoSecurityLabs/cloudgoat), [flaws.cloud](http://flaws.cloud/)
- Related notes: [AWS security testing guide](/cloud/aws-security-testing-guide/), [unauthenticated recon](/cloud/aws-unauthenticated-recon/), [VPC, edge and DNS](/cloud/aws-vpc-edge-dns-security/), [CloudTrail logging](/cloud/aws-cloudtrail-logging/), [detection and posture services](/cloud/aws-detection-posture-services/), [Secrets Manager, Parameter Store and KMS](/cloud/aws-secrets-manager-parameter-store-kms/)
