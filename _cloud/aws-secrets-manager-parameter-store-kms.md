---
title: "AWS Secrets Manager, Parameter Store and KMS"
date: 2026-11-12 18:11:00 +0000
subcategory: aws
summary: "Reviewing who can read secrets, parameters and KMS keys in AWS: resource and key policies, grants, rotation, destructive key actions and secrets left elsewhere."
refs: [SecretsManager.1, SecretsManager.3, SecretsManager.4, KMS.1, KMS.2, KMS.3, KMS.4, KMS.5, ECS.8, CodeBuild.2, CloudWatch.7, "CIS AWS v3.0.0 3.6", "CIS AWS v1.4.0 4.7", T1555.006, T1552.001, T1078.004, T1485, T1486]
tags: [aws, secrets-manager, kms, parameter-store, encryption, credentials]
---

This note is part of our [AWS security testing guide](/cloud/aws-security-testing-guide/) and covers the three services an AWS account uses to keep secrets secret: **AWS Secrets Manager**, **Systems Manager Parameter Store** and **AWS Key Management Service (KMS)**. They are usually reviewed as "is rotation on?" and "is it encrypted?", which misses the point. Encryption in AWS is an *authorisation* control: whoever can make KMS decrypt for them can read the data, and whoever can delete or disable a key can destroy everything it protects. So the questions that matter are who can call `GetSecretValue`, `GetParametersByPath` with decryption and `kms:Decrypt`; whether a key policy quietly trusts the whole account, another account or everyone; whether grants hand out decryption outside the policy you are reading; and whether anyone can schedule a key for deletion without an alarm going off. The note ends with the places secrets end up when they are *not* in a vault (Lambda environment variables, ECS task definitions, EC2 user data, CloudFormation parameters, CodeBuild variables), because in most assessments that is where the plaintext credentials are.

## Contents

- [How it works](#how-it-works)
  - [Secrets Manager](#secrets-manager)
  - [Parameter Store](#parameter-store)
  - [KMS: key policies are the root of trust](#kms-key-policies-are-the-root-of-trust)
  - [KMS: grants](#kms-grants)
  - [KMS: condition keys that narrow use](#kms-condition-keys-that-narrow-use)
  - [KMS: key types, rotation, Regions and material](#kms-key-types-rotation-regions-and-material)
  - [KMS: deletion, disabling and the destructive path](#kms-deletion-disabling-and-the-destructive-path)
  - [CloudHSM and external key stores](#cloudhsm-and-external-key-stores)
- [What goes wrong](#what-goes-wrong)
- [Testing](#testing)
  - [Before you start](#before-you-start)
  - [GT-AWS-SEC-1: Secrets Manager inventory and resource policies](#gt-aws-sec-1-secrets-manager-inventory-and-resource-policies)
  - [GT-AWS-SEC-2: Who can read each secret](#gt-aws-sec-2-who-can-read-each-secret)
  - [GT-AWS-SEC-3: Rotation, staleness and the rotation function](#gt-aws-sec-3-rotation-staleness-and-the-rotation-function)
  - [GT-AWS-SEC-4: Parameter Store types, names and read breadth](#gt-aws-sec-4-parameter-store-types-names-and-read-breadth)
  - [GT-AWS-SEC-5: KMS key policies](#gt-aws-sec-5-kms-key-policies)
  - [GT-AWS-SEC-6: Broad decrypt and grant permissions in IAM](#gt-aws-sec-6-broad-decrypt-and-grant-permissions-in-iam)
  - [GT-AWS-SEC-7: KMS grants review](#gt-aws-sec-7-kms-grants-review)
  - [GT-AWS-SEC-8: Key rotation, key material and multi-Region keys](#gt-aws-sec-8-key-rotation-key-material-and-multi-region-keys)
  - [GT-AWS-SEC-9: Destructive key actions, pending deletion and alerting](#gt-aws-sec-9-destructive-key-actions-pending-deletion-and-alerting)
  - [GT-AWS-SEC-10: Secrets outside the vault](#gt-aws-sec-10-secrets-outside-the-vault)
- [Hardening](#hardening)
- [Real-world cases](#real-world-cases)
- [Rating findings](#rating-findings)
- [Mapping](#mapping)
- [References](#references)

## How it works

### Secrets Manager

A secret is a named, versioned blob (usually JSON) with metadata: name, description, tags, rotation configuration and the ARN of the KMS key that protects it. Only the value is encrypted. The name, description, rotation settings, key ARN and tags are not, so a secret called `prod/payments/stripe-live-key` already tells anyone with `secretsmanager:ListSecrets` what it is.

**Envelope encryption.** Every time the value changes, Secrets Manager asks KMS for a fresh data key (`GenerateDataKey`), encrypts the value with it outside KMS, and stores the encrypted data key with the secret. Reading the value (`GetSecretValue`, `BatchGetSecretValue`) makes Secrets Manager call `kms:Decrypt` **on behalf of the caller**, so the caller needs permission on the secret *and* on the key. Secrets Manager always passes an encryption context of `SecretARN` and `SecretVersionId`, which you can use in key policies to tie a key to particular secrets (shown in [Hardening](#hardening)).

**Two kinds of key.**

- The AWS managed key `aws/secretsmanager` has a fixed key policy that lets **every principal in the account** use it, but only through Secrets Manager (`kms:CallerAccount` plus `kms:ViaService`). It adds no access control of its own: anyone allowed `GetSecretValue` on the secret can decrypt it. It also cannot be used cross-account.
- A customer managed key has a policy you write. That turns the key into a second, independent gate: a principal needs both `secretsmanager:GetSecretValue` and `kms:Decrypt` on that key. When `ListSecrets` or `DescribeSecret` returns no `KmsKeyId`, the secret uses `aws/secretsmanager`.

**Resource policies.** A secret can carry a resource policy. Within one account, either the identity policy or the resource policy can allow access. Cross-account, **three** things must line up: the secret's resource policy allows the external principal, that principal's own IAM policy allows the action, and the **KMS key policy** allows the external principal to decrypt, which is why cross-account secrets must use a customer managed key. `PutResourcePolicy` takes a `BlockPublicPolicy` parameter that rejects policies granting broad access (for example a `*` principal); the API default is not to block, so infrastructure-as-code has to ask for it. `ValidateResourcePolicy` runs the same check without applying anything. A resource policy that grants `secretsmanager:PutResourcePolicy` lets the grantee rewrite the policy and give itself everything else; AWS's own documentation calls this out.

**Rotation.** Three forms exist at the time of writing:

- **Managed rotation** for secrets owned by another service: RDS and Aurora master user passwords (`ManageMasterUserPassword`), Redshift admin passwords, DocumentDB, ECS Service Connect TLS material, and "managed external secrets" held by Secrets Manager partners. No Lambda function; the owning service rotates.
- **Lambda rotation** for everything else. Secrets Manager invokes your function four times per rotation (`create_secret`, `set_secret`, `test_secret`, `finish_secret`) and moves the staging labels `AWSPENDING` → `AWSCURRENT` → `AWSPREVIOUS`. Strategies are *single user* (change the password of the one login) and *alternating users* (two logins, swapped each rotation, so in-flight connections survive).
- Schedules are `rate()` or `cron()` expressions, as often as every four hours.

The rotation function is itself a privileged identity: it can read and write the secret and, for database secrets, change database passwords. Its execution role, its resource-based policy (who may invoke it) and its network path to the database are all in scope.

**Replication.** `ReplicateSecretToRegions` copies the encrypted value, tags and the resource policy to other Regions; each replica is encrypted with a key in its own Region (`aws/secretsmanager` unless you choose otherwise). Rotation happens on the primary and propagates. Newer releases also support replicating a secret to another *account*, which requires a customer managed key in the replica account whose policy lets the primary account call `kms:Encrypt`; check the current documentation for the exact flow. A replica is another copy of the secret with another key policy and another set of readers, so it is another place to review.

**Deletion.** `DeleteSecret` schedules deletion with a 7 to 30 day recovery window, or deletes immediately with `ForceDeleteWithoutRecovery`. `RestoreSecret` cancels a scheduled deletion.

### Parameter Store

Parameter Store is a hierarchical key-value store (`/app/prod/db/password`) inside AWS Systems Manager. Three types:

| Type | Stored as | Who can read the value |
|---|---|---|
| `String` | Plaintext | Anyone with `ssm:GetParameter*` on the name |
| `StringList` | Plaintext, comma-separated | Same |
| `SecureString` | Encrypted with a KMS key (`aws/ssm` by default) | `ssm:GetParameter*` **and** `kms:Decrypt` on the key, with `WithDecryption=true` |

A secret in a `String` parameter is a plaintext secret with an IAM policy in front of it, and it shows up in plaintext wherever the parameter's value is logged or echoed (CloudFormation, CI logs, `describe` output in tickets).

**Tiers.** Standard (default, up to 10,000 parameters per account and Region, 4 KB values, free) and Advanced (up to 100,000, 8 KB values, charged). Only Advanced parameters support **parameter policies** (`Expiration`, `ExpirationNotification`, `NoChangeNotification`) and **cross-account sharing** through AWS RAM. You can upgrade a parameter from Standard to Advanced but never back. An account can also set a default tier, including `Intelligent-Tiering`.

**The `aws/ssm` key** behaves like `aws/secretsmanager`: every principal in the account may decrypt through SSM. With `aws/ssm`, the `SecureString` type protects against people reading the raw storage, not against anyone with `ssm:GetParameter*`.

**Breadth of path reads.** `GetParametersByPath` with `--recursive --with-decryption` returns every value under a path in one call. IAM authorises it against the *path* resource (`arn:aws:ssm:<region>:<account>:parameter/app/*`), and the `ssm:Recursive` condition key can restrict recursion. A role allowed `ssm:GetParametersByPath` on `parameter/*` with access to the decrypting key can read every parameter in the Region. That is a common shape for "the app needs its config" policies.

**No resource policies** for parameters themselves (sharing goes through RAM), and no rotation. Parameter Store can *reference* Secrets Manager secrets through the `/aws/reference/secretsmanager/` prefix, in which case the Secrets Manager permissions apply.

### KMS: key policies are the root of trust

Every KMS key has exactly one **key policy**, and it is unlike any other resource policy in AWS: no principal, **not even the account's administrators or root**, can use or manage the key unless the key policy says so. IAM policies only count if the key policy delegates to them. The statement that does that is the default one:

```json
{
  "Sid": "Enable IAM User Permissions",
  "Effect": "Allow",
  "Principal": { "AWS": "arn:aws:iam::111122223333:root" },
  "Action": "kms:*",
  "Resource": "*"
}
```

The `:root` principal here means *the account*, not the root user. The statement does not give anyone access by itself; it lets IAM policies in account 111122223333 grant `kms:*` on this key. Keys created through the API without a policy get only this statement. Keys created in the console also get *key administrators* (`kms:Create*`, `kms:Put*`, `kms:ScheduleKeyDeletion`, and so on, but no cryptographic use), *key users* (`Encrypt`, `Decrypt`, `ReEncrypt*`, `GenerateDataKey*`, `DescribeKey`) and a grant statement limited by `kms:GrantIsForAWSResource`.

Three consequences for a reviewer:

1. **With the delegation statement, IAM decides.** Any identity policy in the account that allows `kms:Decrypt` on `*` decrypts with this key. Your IAM review (see [IAM fundamentals](/cloud/aws-iam-fundamentals-policy-evaluation/)) is the KMS review.
2. **Without it, only the key policy decides.** That is stronger, but a key whose policy names only one role becomes unmanageable when that role is deleted; recovery needs AWS Support. KMS has a "policy lockout safety check" to prevent setting a policy that locks out the caller; a `CreateKey` or `PutKeyPolicy` with `BypassPolicyLockoutSafetyCheck=true` is worth noticing in CloudTrail.
3. **Key administrators can make themselves key users.** Anyone with `kms:PutKeyPolicy` or `kms:CreateGrant` on a key can give themselves (or anyone) decryption. So can anyone who can change the tags or aliases that a policy's ABAC conditions rely on. Treat these as decrypt permissions in your analysis.

**AWS managed keys** (`aws/s3`, `aws/ebs`, `aws/secretsmanager`, `aws/ssm`, ...) have policies set by the service: every principal in the account, via that service only. You cannot edit them, share them cross-account, disable them or delete them, and AWS rotates them yearly (every three years before May 2022). **AWS owned keys** live in AWS's accounts and do not appear in yours at all. **Customer managed keys** are the only ones whose policy, rotation and lifecycle you control and therefore the only ones that create findings of the "policy is too broad" kind.

A key policy with `"Principal": {"AWS": "*"}` or `"Principal": "*"` and no restricting condition lets **any AWS principal in any account** perform the listed actions, subject to that principal's own IAM policy, which an attacker controls in their own account. The legitimate pattern uses `*` with `kms:CallerAccount` and `kms:ViaService`, exactly like the AWS managed keys.

### KMS: grants

A grant is a second, separate way to give a principal permission to use a key. It names a key, a **grantee principal** (any IAM principal or service principal, in any account), a list of **operations** (`Decrypt`, `Encrypt`, `GenerateDataKey`, `CreateGrant`, `RetireGrant`, `DescribeKey`, ...), optional **constraints** on encryption context, and optionally a retiring principal. Grants do not appear in the key policy, and IAM Access Analyzer's policy view does not show them as policy text, so a key whose policy looks tight can still be readable by someone through a grant.

AWS services use grants constantly: EBS creates one to attach an encrypted volume, RDS for encrypted instances, Lambda for environment variables, and so on. Those grants are normal; the console's default key user statement allows `CreateGrant` only with `"kms:GrantIsForAWSResource": true`, which means only an integrated service can create the grant on the user's behalf.

`kms:CreateGrant` **without** that condition is a privilege escalation primitive: the holder can create a grant for themselves (or for a principal in another account) with `Decrypt`, then decrypt anything the key protects, without touching the key policy. A grant that includes the `CreateGrant` operation lets the grantee mint further grants. Grants take effect within seconds to minutes (eventual consistency; a grant token makes them usable immediately) and remain until retired or revoked. `ListGrants` (needs `kms:ListGrants` on the key) is the only way to see them.

### KMS: condition keys that narrow use

| Condition key | What it restricts | Typical use |
|---|---|---|
| `kms:ViaService` | Request must come from a named service in a Region on the principal's behalf | Allow decrypt only through `secretsmanager.eu-west-2.amazonaws.com`, `ssm.<region>.amazonaws.com`, `s3.<region>.amazonaws.com` |
| `kms:CallerAccount` | The caller's account | Pair with `"Principal": {"AWS": "*"}` to mean "everyone in this account" |
| `kms:EncryptionContext:<key>` | A specific encryption context pair | Tie a key to one secret (`SecretARN`), one bucket (`aws:s3:arn`), one table |
| `kms:EncryptionContextKeys` | Which context keys must be present | Require that any context is supplied |
| `kms:GrantIsForAWSResource` | Grants created by integrated services only | Default key user grant statement |
| `kms:GrantOperations`, `kms:GranteePrincipal` | What a new grant may allow, and to whom | Stop `CreateGrant` from issuing `Decrypt` to arbitrary principals |
| `kms:ScheduleKeyDeletionPendingWindowInDays` | Waiting period requested | Deny deletion with a window under 30 days |
| `kms:TrailingDaysWithoutKeyUsage` | Days since the key last did a cryptographic operation | Deny `DisableKey` / `ScheduleKeyDeletion` on keys used recently (new; check current docs) |
| `kms:RotationPeriodInDays` | Rotation period requested | Enforce a maximum rotation period |

`kms:ViaService` is the most useful and the most misunderstood. It does not stop a principal from reading the data through the named service (that is the point), it stops them calling `kms:Decrypt` directly on ciphertext they obtained elsewhere, such as a copied EBS snapshot's data key or an exfiltrated encrypted backup.

### KMS: key types, rotation, Regions and material

**Rotation.** For customer managed symmetric keys with KMS-generated material (`Origin: AWS_KMS`), automatic rotation is optional and off by default. Since April 2024 you choose the period, from **90 to 2,560 days** (default 365), and you can also rotate on demand (`RotateKeyOnDemand`, limited to 25 on-demand rotations per key at the time of writing). Old material is kept, so existing ciphertext still decrypts. Asymmetric keys, HMAC keys and keys in custom key stores cannot be rotated automatically; you rotate them by creating a new key and moving aliases. Rotation limits how much data one piece of material protects; it does **not** re-encrypt data or invalidate data keys that have already leaked. It is a hygiene control and is rated accordingly.

**Imported key material** (`Origin: EXTERNAL`, "bring your own key"). You generate the material, wrap it with a KMS public key from `GetParametersForImport`, and import it, optionally with an expiry. Two risks: whoever holds the original material outside AWS holds the key, and `DeleteImportedKeyMaterial` makes the key **unusable immediately**, with no waiting period, which makes it the fastest destructive action in KMS. Imported-material keys now support on-demand rotation after you import new material.

**Multi-Region keys** share key ID and key material across Regions (primary plus replicas), so ciphertext from one Region decrypts in another. Key policy, grants, aliases and enabled state are **not** shared: each replica has its own key policy. A tight policy on the primary and a loose one on a forgotten replica in another Region expose the same material. Rotation is controlled on the primary.

### KMS: deletion, disabling and the destructive path

- `ScheduleKeyDeletion` puts a key in `PendingDeletion` for **7 to 30 days** (default 30). During that window the key cannot be used, and `CancelKeyDeletion` restores it. After it, the key and all its material are gone, and **every piece of data encrypted under it is unrecoverable**, including backups and snapshots encrypted with the same key.
- `DisableKey` makes a key unusable immediately and reversibly with `EnableKey`. Workloads fail at once (new decrypts fail; attached EBS volumes keep working until detached).
- `DeleteImportedKeyMaterial` makes an imported-material key unusable immediately.
- `PutKeyPolicy` that removes all usable principals has the same effect for everyone except AWS Support.

This is a ransomware and sabotage path that needs no data exfiltration: an attacker with key administration rights on the key that protects production databases and their backups only needs to schedule deletion with a 7-day window and wait for nobody to notice. The related "attacker's own key" variant encrypts victim data under a key in the attacker's account (see [Real-world cases](#real-world-cases)). Detection and prevention (SCPs, key policy denies, CloudWatch alarm on `DisableKey` / `ScheduleKeyDeletion`) are covered in GT-AWS-SEC-9 and [Hardening](#hardening).

### CloudHSM and external key stores

**AWS CloudHSM** gives you single-tenant HSMs in your VPC. Cryptographic operations are authorised by **HSM users** (crypto users and officers) inside the cluster, not by IAM: IAM only controls the cluster's management API (`cloudhsm:*`). A review therefore covers who holds the crypto user credentials, where the client and its credentials live (often on application EC2 instances), backups and the cluster's security group. A **custom key store** backed by CloudHSM, or an **external key store (XKS)** backed by your own HSM through a proxy, lets KMS keys keep their material outside standard KMS storage; KMS policies still authorise use, and availability now depends on the cluster or proxy. Neither is needed for most organisations; when present, include the HSM user model and the XKS proxy's authentication in scope.

## What goes wrong

**Secret readable by too many principals.** The most common real finding: `secretsmanager:GetSecretValue` or `ssm:GetParameter*` on `*` in an application role, a developer role, a CI role or a "read-only" role, combined with `aws/secretsmanager` or `aws/ssm`, so there is no second gate. Why it matters: anyone who compromises any of those principals (a Lambda function with an SSRF, a leaked CI token) reads every secret in the account, often including database master passwords and third-party API keys that lead outside AWS.

**Resource policy grants cross-account or public access.** A secret policy with `"Principal": "*"`, a whole external account (`arn:aws:iam::444455556666:root`), or an `aws:PrincipalOrgID` condition when the organisation includes untrusted accounts. Why it matters: it extends the blast radius beyond the account, and it often survives the partnership or migration that justified it.

**`PutResourcePolicy` in a resource policy.** Lets the grantee rewrite the policy and escalate on that secret.

**Plaintext `String` parameters holding secrets.** `/prod/db/password` stored as `String`. Why it matters: no decryption step, value echoed in plaintext by every tool that touches it, readable by any principal with `ssm:GetParameter*`, and frequently included in "read-only" access.

**Secrets never rotated or rotation broken.** Static third-party keys and database passwords from years ago, or rotation that fails silently (Lambda timeout, no network path to the database, `RotationOccurringAsScheduled` false). Why it matters: every past leak (old laptop, former employee, CI log) is still valid. Severity depends on exposure, not the age alone.

**Key policy trusts everyone or another account.** `"Principal": "*"` without conditions, or an external account root with `kms:Decrypt`. Why it matters: the external party can decrypt any ciphertext it obtains (shared snapshots, copied objects, intercepted data keys).

**Broad `kms:Decrypt` in IAM.** `kms:Decrypt` on `"Resource": "*"` (Security Hub KMS.1 and KMS.2). Combined with the default delegation statement, it removes the KMS layer for every key in the account.

**Unconstrained `kms:CreateGrant` or `kms:PutKeyPolicy`.** A path to decryption that looks like administration.

**Destructive key actions unguarded.** No SCP or key policy deny on `ScheduleKeyDeletion` / `DisableKey` / `DeleteImportedKeyMaterial`, deletion windows of 7 days, no alarm, and backups encrypted with the same key as production. Why it matters: data destruction with a short, quiet window.

**Customer managed keys without rotation.** Hygiene and compliance (CIS, PCI DSS). Low impact on its own.

**Replica keys and replica secrets forgotten.** A multi-Region replica key with a looser policy, or a replica secret in a Region nobody reviews.

**Secrets outside the vault.** Credentials in Lambda environment variables, ECS task definition `environment`, EC2 user data, CloudFormation parameters without `NoEcho` or in `Outputs`, CodeBuild `PLAINTEXT` variables, SSM documents. Anyone with the matching `Get`/`Describe` permission, which includes many audit and read-only roles, reads them in plaintext. This is the finding we raise most often in this area.

## Testing

Every test below assumes an **authorised engagement** against the client's own AWS accounts, with written scope, and respects the [AWS penetration testing policy](https://aws.amazon.com/security/penetration-testing/). They are read-only unless marked otherwise, and **none of them reads a secret value by default**: a configuration review proves *who could* read a secret; it does not need to read it. Reading a value (for example to confirm a plaintext parameter really is a live credential) is **lab or explicitly approved only**, and the value goes nowhere but the client's chosen channel. Outputs shown are **illustrative**, not from a real account.

### Before you start

**Permissions.** `SecurityAudit` plus `ViewOnlyAccess` covers listing and describing everything here, including `kms:GetKeyPolicy`, `kms:ListGrants`, `kms:GetKeyRotationStatus`, `secretsmanager:GetResourcePolicy`, `secretsmanager:DescribeSecret` and `ssm:DescribeParameters`. Two caveats:

- A key policy that does not delegate to IAM, or that names only specific principals, will deny your audit role `GetKeyPolicy` and `ListGrants`. That is a result in itself (record the key as "not reviewable with audit access") and the client has to run the check from a key administrator.
- Describing Lambda functions, ECS task definitions and EC2 user data returns their plaintext environment and scripts. That is intended for GT-AWS-SEC-10, and the client should know their audit role sees it.

**Profiles and the region loop.**

```bash
export AWS_PROFILE=client-audit
aws sts get-caller-identity
REGIONS=$(aws ec2 describe-regions --query 'Regions[].RegionName' --output text)
for r in $REGIONS; do
  echo "== $r"
  aws secretsmanager list-secrets --region "$r" --query 'length(SecretList)'
  aws ssm describe-parameters --region "$r" --query 'length(Parameters)'
  aws kms list-keys --region "$r" --query 'length(Keys)'
done
```

**Tools.**

- [Prowler](https://github.com/prowler-cloud/prowler): `prowler aws --services secretsmanager kms ssm` plus the "secrets in X" checks listed per test.
- [CloudFox](https://github.com/BishopFox/cloudfox): `cloudfox aws -p client-audit secrets` (lists Secrets Manager and SSM names, no values), `cloudfox aws -p client-audit env-vars`, `cloudfox aws -p client-audit resource-trusts --include-kms`.
- [PMapper](https://github.com/nccgroup/PMapper) for "who can reach this" questions, and `aws iam simulate-principal-policy`.
- IAM Access Analyzer external access findings (KMS keys and Secrets Manager secrets are supported resource types).
- [Steampipe](https://github.com/turbot/steampipe) tables `aws_secretsmanager_secret`, `aws_ssm_parameter`, `aws_kms_key` if you prefer SQL.
- [trufflehog](https://github.com/trufflesecurity/trufflehog) or [gitleaks](https://github.com/gitleaks/gitleaks) over exported configuration (GT-AWS-SEC-10).
- Pacu has `secrets__enum` and `systemsmanager__download_parameters`, but both **retrieve secret values**. Do not run them on a client account without explicit approval; in practice you rarely need to.

For hands-on practice, CloudGoat's `secrets_in_the_cloud` style scenarios and [IAM Vulnerable](https://github.com/BishopFox/iam-vulnerable) cover several of these paths in a lab.

### GT-AWS-SEC-1: Secrets Manager inventory and resource policies

*Guler Tech methodology.*

#### What it checks

Every secret in every Region, the key that protects it, and whether its resource policy grants access to principals outside the account, to everyone, or grants `PutResourcePolicy`.

#### Prerequisites

`secretsmanager:ListSecrets`, `secretsmanager:DescribeSecret`, `secretsmanager:GetResourcePolicy` in all Regions.

#### Steps

1. Inventory, including secrets pending deletion and the key in use:

   ```bash
   for r in $REGIONS; do
     aws secretsmanager list-secrets --region "$r" --include-planned-deletion \
       --query 'SecretList[].[Name,KmsKeyId || `aws/secretsmanager`,OwningService || `-`,DeletedDate || `-`]' \
       --output text | sed "s/^/$r\t/"
   done > secrets-inventory.tsv
   ```

2. Pull each resource policy:

   ```bash
   while IFS=$'\t' read -r r name key owner deleted; do
     pol=$(aws secretsmanager get-resource-policy --region "$r" --secret-id "$name" \
           --query ResourcePolicy --output text)
     [ "$pol" != "None" ] && printf '%s\t%s\t%s\n' "$r" "$name" "$pol"
   done < secrets-inventory.tsv > secret-policies.tsv
   ```

3. Flag wildcard principals, external accounts and dangerous actions:

   ```bash
   ACCT=$(aws sts get-caller-identity --query Account --output text)
   cut -f3 secret-policies.tsv | jq -c --arg a "$ACCT" '
     .Statement[] | select(.Effect=="Allow")
     | {p: (.Principal.AWS // .Principal), a: .Action, c: (.Condition // null)}
     | select( (.p|tostring|test("\\*")) or (.p|tostring|test($a)|not)
               or (.a|tostring|test("PutResourcePolicy|secretsmanager:\\*")) )'
   ```

4. Cross-check with IAM Access Analyzer (an external access analyzer must exist in each Region, zone of trust = account or organisation):

   ```bash
   aws accessanalyzer list-analyzers --type ACCOUNT --query 'analyzers[].arn'
   aws accessanalyzer list-findings-v2 --analyzer-arn <ANALYZER_ARN> \
     --filter '{"resourceType": {"eq": ["AWS::SecretsManager::Secret"]} }'
   ```

5. For any policy that grants cross-account access, record which KMS key the secret uses (step 1). If it is `aws/secretsmanager`, cross-account reads cannot work; the grant is ineffective today but becomes live the moment someone switches the key.

#### Observation

A table: Region, secret, key, owning service, policy summary (principals, actions, conditions), Access Analyzer finding ID.

```text
eu-west-2  prod/partner-api   arn:aws:kms:...:key/1111...  -   Allow arn:aws:iam::444455556666:root  secretsmanager:GetSecretValue  (no condition)
eu-west-2  shared/smtp        aws/secretsmanager           -   Allow *  secretsmanager:*  Condition aws:PrincipalOrgID=o-exampleorg
```

#### Evaluation

**Fail** if a policy allows `*` without a restricting condition (`aws:PrincipalOrgID`, `aws:PrincipalAccount`, `aws:SourceVpce`), allows an external account that is not documented and approved, or grants `secretsmanager:PutResourcePolicy`, `DeleteResourcePolicy` or `secretsmanager:*` to anyone except an administrative role. **Fail (lower severity)** for organisation-wide `aws:PrincipalOrgID` grants on production secrets if the organisation contains sandbox or third-party accounts. **Pass** if no resource policies exist or every grant is to named principals with a documented reason. Note the result of `BlockPublicPolicy` in the IaC (GT-AWS-SEC-10 in the [CI/CD note](/cloud/aws-cicd-iac-security/) scans for it).

#### Automated coverage

Prowler `secretsmanager_not_publicly_accessible`, `secretsmanager_has_restrictive_resource_policy`. IAM Access Analyzer external access findings. Security Hub CSPM has no control for secret resource policies at the time of writing.

#### Detection

CloudTrail `PutResourcePolicy`, `DeleteResourcePolicy`, `ValidateResourcePolicy` (eventSource `secretsmanager.amazonaws.com`); `GetSecretValue` / `BatchGetSecretValue` where `userIdentity.accountId` differs from `recipientAccountId`. Access Analyzer raises a new finding when a policy change opens external access.

### GT-AWS-SEC-2: Who can read each secret

*Guler Tech methodology.*

#### What it checks

The identity side: which roles and users can call `GetSecretValue` / `BatchGetSecretValue` on which secrets, and whether the KMS key adds a second gate.

#### Prerequisites

IAM read access (`iam:GetAccountAuthorizationDetails`), `iam:SimulatePrincipalPolicy`, PMapper graph for the account.

#### Steps

1. Find every policy that allows reading secrets:

   ```bash
   aws iam get-account-authorization-details --output json > gaad.json
   jq -r '
     def stmts: (if type=="array" then .[] else . end);
     def reads: (.Action|tostring) | test("secretsmanager:(GetSecretValue|BatchGetSecretValue|Get\\*|\\*)|\"\\*\"");
     ( .Policies[] | .PolicyName as $n | .PolicyVersionList[] | select(.IsDefaultVersion)
       | .Document.Statement | stmts | select(.Effect=="Allow" and reads) | "managed:\($n)\t\(.Resource|tostring)" ),
     ( .RoleDetailList[] | .RoleName as $n | .RolePolicyList[]? | .PolicyDocument.Statement | stmts
       | select(.Effect=="Allow" and reads) | "inline-role:\($n)\t\(.Resource|tostring)" ),
     ( .UserDetailList[] | .UserName as $n | .UserPolicyList[]? | .PolicyDocument.Statement | stmts
       | select(.Effect=="Allow" and reads) | "inline-user:\($n)\t\(.Resource|tostring)" )' gaad.json | sort -u
   ```

   Add `GroupDetailList` the same way if groups are used. Then check which principals the matching managed policies are attached to (`AttachedManagedPolicies` in the same file).

2. Simulate for the principals that matter (workload roles, CI roles, developer and support roles, "read-only" roles):

   ```bash
   aws iam simulate-principal-policy \
     --policy-source-arn arn:aws:iam::111122223333:role/ci-deploy \
     --action-names secretsmanager:GetSecretValue secretsmanager:BatchGetSecretValue \
     --resource-arns 'arn:aws:secretsmanager:eu-west-2:111122223333:secret:prod/*' \
     --query 'EvaluationResults[].[EvalActionName,EvalDecision]' --output text
   ```

   The simulator evaluates identity policies, permissions boundaries and (with `--resource-policy`) a resource policy you supply. It does **not** evaluate the KMS key policy or SCPs, so treat an "allowed" as "allowed by IAM" and finish the job in step 3.

3. For each secret on a customer managed key, read the key policy (GT-AWS-SEC-5) and decide whether the principal also gets `kms:Decrypt`. For secrets on `aws/secretsmanager`, the IAM result is the final answer.

4. Check AWS managed "read-only" style policies attached in the account for value-reading actions. Do not trust the name; read the current version:

   ```bash
   for p in ReadOnlyAccess ViewOnlyAccess SecurityAudit; do
     arn="arn:aws:iam::aws:policy/$p"; [ "$p" = ViewOnlyAccess ] && arn="arn:aws:iam::aws:policy/job-function/$p"
     v=$(aws iam get-policy --policy-arn "$arn" --query Policy.DefaultVersionId --output text)
     aws iam get-policy-version --policy-arn "$arn" --version-id "$v" --output json \
       | jq -r --arg p "$p" '.PolicyVersion.Document.Statement[] | .Action | if type=="array" then .[] else . end
           | select(test("^(ssm:Get|ssm:\\*|secretsmanager:Get|secretsmanager:\\*|kms:Decrypt)")) | "\($p)\t\(.)"'
   done
   ```

5. Use PMapper (it collects Secrets Manager resource policies and KMS key policies during `graph create`) to answer "who can reach a principal that can read `prod/*`", which includes escalation paths: `pmapper --profile client-audit query 'who can do secretsmanager:GetSecretValue with arn:aws:secretsmanager:eu-west-2:111122223333:secret:prod/db-AbCdEf'`.

#### Observation

A matrix of principals against secret groups (prod, non-prod, shared), with the gate that applies (IAM only, IAM plus key policy).

#### Evaluation

**Fail** if a workload, CI or human role can read secrets it does not need, typically `GetSecretValue` on `*` or on a whole environment prefix, and the secrets use `aws/secretsmanager` (no second gate). **Fail** if any role marketed as read-only, audit or support can read secret values. **Pass** if each workload role can read only its own secrets (by ARN or by ABAC tag condition) and human access goes through a break-glass process.

#### Automated coverage

No Security Hub control. Prowler has no direct check; cloudsplaining flags credential-exposure actions (`secretsmanager:GetSecretValue`, `ssm:GetParameter*`) in its "Credentials Exposure" category: `cloudsplaining download && cloudsplaining scan --input-file default.json`.

#### Detection

`GetSecretValue` and `BatchGetSecretValue` from principals or source IPs that do not normally read a given secret; a burst of reads across many secrets; `ListSecrets` followed by reads (enumeration then collection, ATT&CK T1555.006). GuardDuty's anomaly-based IAM findings (for example `CredentialAccess:IAMUser/AnomalousBehavior`) cover unusual credential-access API use; check the current GuardDuty documentation for which APIs are modelled.

### GT-AWS-SEC-3: Rotation, staleness and the rotation function

*Guler Tech methodology.*

#### What it checks

Secrets without rotation, rotation that is configured but failing, secrets nobody uses, and the privileges and exposure of rotation Lambda functions.

#### Prerequisites

`secretsmanager:DescribeSecret`, `lambda:GetFunction`, `lambda:GetPolicy`, `iam:Get*`.

#### Steps

1. Rotation status, last rotation and last access:

   ```bash
   for r in $REGIONS; do
     aws secretsmanager list-secrets --region "$r" --output json | jq -r --arg r "$r" '
       .SecretList[] | [ $r, .Name, (.RotationEnabled // false),
         (.RotationRules.AutomaticallyAfterDays // .RotationRules.ScheduleExpression // "-"),
         (.LastRotatedDate // "never"), (.LastAccessedDate // "never"),
         (.OwningService // "-"), (.RotationLambdaARN // "-") ] | @tsv'
   done | column -t > rotation.txt
   ```

2. Rotation configured but failing: `describe-secret` per secret and look at whether `NextRotationDate` is in the past and `LastRotatedDate` is older than the schedule. Security Hub's SecretsManager.2 reports `RotationOccurringAsScheduled`. CloudTrail records `RotationFailed` and `RotationAbandoned` service events.

3. Database master passwords: confirm whether RDS and Aurora use managed master passwords.

   ```bash
   aws rds describe-db-instances --query 'DBInstances[].[DBInstanceIdentifier,MasterUserSecret.SecretArn || `NOT MANAGED`]' --output text
   aws rds describe-db-clusters --query 'DBClusters[].[DBClusterIdentifier,MasterUserSecret.SecretArn || `NOT MANAGED`]' --output text
   ```

4. Rotation function review: execution role permissions (it should reach only the secrets it rotates and nothing else), resource-based policy (who may invoke it), and environment variables:

   ```bash
   aws lambda get-policy --function-name <ROTATION_FN> --query Policy --output text | jq .
   aws lambda get-function-configuration --function-name <ROTATION_FN> \
     --query '[Role,VpcConfig.SubnetIds,Environment.Variables]'
   ```

   The invoke permission should be for `secretsmanager.amazonaws.com` with `aws:SourceAccount` or `aws:SourceArn` scoped to the secrets; a function invocable by any principal in the account lets callers trigger rotation steps directly.

5. For secrets with no rotation, establish with the client what they are (third-party API keys often cannot be rotated by AWS) and when they were last changed outside AWS.

#### Observation

```text
eu-west-2  prod/db-master          false  -    never                 2026-11-10  -    -
eu-west-2  prod/stripe-api-key     false  -    never                 2026-11-12  -    -
eu-west-2  rds!db-1a2b...          true   7    2026-11-06T00:00:00Z  2026-11-12  rds  -
eu-west-2  legacy/ftp-password     false  -    never                 never       -    -
```

#### Evaluation

**Fail** if production credentials that *can* be rotated by AWS (database passwords, IAM-style keys issued by services that support it) have no rotation, or rotation is enabled but has not succeeded within its schedule. **Fail** if a rotation function's role can read or change secrets beyond those it rotates, or it can be invoked by principals other than Secrets Manager. **Observation** (not a fail on its own) for third-party secrets that cannot be rotated by Secrets Manager, provided there is a documented manual rotation process. **Fail (Low)** for secrets unused for 90+ days that should be deleted. Rotation never raises a finding to High by itself; it adjusts the severity of exposure findings (a broadly readable secret that never changes is worse than one rotated daily).

#### Automated coverage

Security Hub CSPM SecretsManager.1 (rotation enabled), SecretsManager.2 (rotates successfully), SecretsManager.3 (unused, default 90 days), SecretsManager.4 (rotated within N days, default 90). Prowler `secretsmanager_automatic_rotation_enabled`, `secretsmanager_secret_rotated_periodically`, `secretsmanager_secret_unused`. AWS Config rules `secretsmanager-rotation-enabled-check`, `secretsmanager-scheduled-rotation-success-check`, `secretsmanager-secret-periodic-rotation`, `secretsmanager-secret-unused`.

#### Detection

`RotateSecret`, `CancelRotateSecret` (someone turning rotation off), `UpdateSecretVersionStage` (moving `AWSCURRENT` by hand), `PutSecretValue` from a principal other than the rotation function, and the `RotationFailed` / `RotationAbandoned` events.

### GT-AWS-SEC-4: Parameter Store types, names and read breadth

*Guler Tech methodology.*

#### What it checks

Plaintext `String` / `StringList` parameters whose names or descriptions suggest secrets, `SecureString` parameters protected only by `aws/ssm`, and IAM policies that allow reading whole parameter trees with decryption.

#### Prerequisites

`ssm:DescribeParameters` in all Regions; IAM read access.

#### Steps

1. List non-secure parameters with secret-like names (metadata only, no values):

   ```bash
   PAT='pass(word)?|pwd|secret|token|api[-_]?key|private[-_]?key|credential|conn(ection)?[-_]?string|dsn|auth|bearer|client[-_]?secret|smtp|jdbc'
   for r in $REGIONS; do
     aws ssm describe-parameters --region "$r" \
       --parameter-filters 'Key=Type,Values=String,StringList' --output json \
     | jq -r --arg r "$r" --arg pat "$PAT" '.Parameters[]
         | select((.Name + " " + (.Description // "")) | test($pat; "i"))
         | [$r, .Name, .Type, .Tier, .LastModifiedDate, (.LastModifiedUser // "-")] | @tsv'
   done > string-params-suspect.tsv
   ```

2. `SecureString` parameters and their keys:

   ```bash
   aws ssm describe-parameters --parameter-filters 'Key=Type,Values=SecureString' \
     --query 'Parameters[].[Name,KeyId,Tier]' --output text
   ```

   `KeyId` of `alias/aws/ssm` means the only gate is IAM `ssm:GetParameter*`.

3. Parameter policies on Advanced parameters (expiry and change notifications):

   ```bash
   aws ssm describe-parameters --parameter-filters 'Key=Tier,Values=Advanced' \
     --query 'Parameters[].[Name,Policies[].PolicyText]' --output json
   ```

4. Read breadth: find identity policies that allow `ssm:GetParametersByPath`, `ssm:GetParameters` or `ssm:GetParameter*` on `*`, `parameter/*` or a top-level path, and simulate the important roles:

   ```bash
   aws iam simulate-principal-policy \
     --policy-source-arn arn:aws:iam::111122223333:role/app-orders \
     --action-names ssm:GetParametersByPath ssm:GetParameter \
     --resource-arns arn:aws:ssm:eu-west-2:111122223333:parameter/prod/payments/stripe-key \
     --query 'EvaluationResults[].[EvalActionName,EvalDecision]' --output text
   ```

5. **Approved only:** if the client wants proof that a suspect `String` parameter holds a live credential, read that one parameter (`aws ssm get-parameter --name ...`), record only a redacted fingerprint (first and last two characters, length) and hand it to the client. Do not test the credential against its target system unless that is separately in scope.

#### Observation

```text
eu-west-2  /prod/orders/db_password      String      Standard  2023-02-14  arn:aws:sts::111122223333:assumed-role/admin/jo
eu-west-2  /shared/smtp/api-key          String      Standard  2022-09-01  -
eu-west-2  /prod/payments/stripe-key     SecureString  alias/aws/ssm
```

#### Evaluation

**Fail** for any secret stored as `String` or `StringList`. False positives are common (`/app/feature/token-ttl` holding `3600`, `password-min-length`); confirm by context (type of value expected, who reads it) before reporting, and only read values with approval. **Fail** if roles that do not need them can call `GetParametersByPath` recursively over the environment's tree with decryption. **Observation** for `SecureString` on `aws/ssm` where the IAM side is tight; **fail** if the IAM side is broad, because the KMS layer adds nothing. **Pass** if secrets are `SecureString` (or Secrets Manager references), reads are scoped to each application's path, and sensitive parameters use a customer managed key with a scoped policy.

#### Automated coverage

No Security Hub control covers parameter types. Prowler has no parameter-type check; its `ssm_document_secrets` covers SSM *documents* (GT-AWS-SEC-10). Steampipe: `select name, type from aws_ssm_parameter where type <> 'SecureString' and name ~* 'pass|secret|token|key';`.

#### Detection

`GetParametersByPath` with `recursive=true` and `withDecryption=true` in `requestParameters`, especially from human roles or new source IPs; bursts of `GetParameter` across many names; `PutParameter` with `overwrite=true` on secret paths (tampering with application config).

### GT-AWS-SEC-5: KMS key policies

*Guler Tech methodology.*

#### What it checks

For every customer managed key: whether the policy delegates to IAM, trusts other accounts, allows a `*` principal without restricting conditions, gives decrypt or administration to broad sets of principals, or lets `CreateGrant` happen without `kms:GrantIsForAWSResource`.

#### Prerequisites

`kms:ListKeys`, `kms:DescribeKey`, `kms:ListAliases`, `kms:GetKeyPolicy` (subject to each key's own policy).

#### Steps

1. Inventory customer managed keys with state, origin and Region type:

   ```bash
   for r in $REGIONS; do
     for k in $(aws kms list-keys --region "$r" --query 'Keys[].KeyId' --output text); do
       aws kms describe-key --region "$r" --key-id "$k" --query \
        'KeyMetadata.[KeyManager,KeyId,KeyState,Origin,KeySpec,KeyUsage,MultiRegion,MultiRegionConfiguration.MultiRegionKeyType || `-`]' \
        --output text | sed "s/^/$r\t/"
     done
   done | awk -F'\t' '$2=="CUSTOMER"' > cmk.tsv
   ```

2. Fetch policies:

   ```bash
   mkdir -p keypol
   while IFS=$'\t' read -r r mgr k rest; do
     aws kms get-key-policy --region "$r" --key-id "$k" --policy-name default \
       --query Policy --output text > "keypol/$r-$k.json" 2>/dev/null \
       || echo "$r $k NOT READABLE with audit role"
   done < cmk.tsv
   ```

3. Flag dangerous statements:

   ```bash
   ACCT=$(aws sts get-caller-identity --query Account --output text)
   for f in keypol/*.json; do
     jq -c --arg f "$f" --arg a "$ACCT" '.Statement[] | select(.Effect=="Allow")
       | {f:$f, sid:.Sid, p:(.Principal.AWS // .Principal), act:.Action, cond:(.Condition // null)}
       | select(
           ((.p|tostring) == "*" or (.p|tostring|test("\"\\*\""))) and (.cond == null)
           or ((.p|tostring|test("arn:aws:iam::[0-9]{12}")) and ((.p|tostring|test($a))|not))
           or ((.act|tostring|test("kms:CreateGrant|kms:\\*")) and ((.cond|tostring|test("GrantIsForAWSResource"))|not)
               and ((.p|tostring|test(":root\""))|not))
         )' "$f"
   done
   ```

4. For each key, write down in one line who can **use** it and who can **administer** it:
   - Delegation statement present? Then the IAM review decides use and administration (GT-AWS-SEC-6).
   - Named principals with `kms:Decrypt`, `kms:ReEncrypt*`, `kms:*`.
   - Named principals with `kms:PutKeyPolicy`, `kms:CreateGrant`, `kms:ScheduleKeyDeletion`, `kms:DisableKey`, `kms:DeleteImportedKeyMaterial`.
   - External accounts, with or without conditions.
   - Conditions that actually narrow use (`kms:ViaService`, `kms:CallerAccount`, encryption context) versus ones that do not.

5. Cross-check with Access Analyzer findings for `AWS::KMS::Key`, which also accounts for grants to external principals:

   ```bash
   aws accessanalyzer list-findings-v2 --analyzer-arn <ANALYZER_ARN> \
     --filter '{"resourceType": {"eq": ["AWS::KMS::Key"]} }'
   ```

#### Observation

```json
{"f":"keypol/eu-west-2-1111aaaa.json","sid":"AllowPartner","p":"arn:aws:iam::444455556666:root","act":["kms:Decrypt","kms:DescribeKey"],"cond":null}
{"f":"keypol/eu-west-2-2222bbbb.json","sid":"Allow use of the key","p":"*","act":["kms:Encrypt","kms:Decrypt","kms:GenerateDataKey*"],"cond":null}
```

#### Evaluation

**Fail (Critical)** if a policy allows `kms:Decrypt` (or `kms:*`, `kms:CreateGrant`, `kms:PutKeyPolicy`) to `*` with no condition that limits callers to the account or organisation; Security Hub KMS.5 reports this. **Fail** if an external account has `kms:Decrypt` or `kms:CreateGrant` without documented need, or if a cross-account grant is to the external account's `:root` rather than to a named role (the external account then decides who among its principals uses the key). **Fail** if `kms:CreateGrant` is allowed to non-administrators without `kms:GrantIsForAWSResource` or `kms:GrantOperations` / `kms:GranteePrincipal` limits. **Observation** for keys whose policies your audit role cannot read; they must be reviewed by the client. **Pass** if every key has a documented owner, administration is limited to a small set of roles that cannot also use the key (separation of duties), use is limited by principal and `kms:ViaService` where the key backs one service, and cross-account access is to named roles.

#### Automated coverage

Security Hub CSPM KMS.5 (KMS keys should not be publicly accessible; Config rule `kms-key-policy-no-public-access`; note it fails if Config cannot read the policy, and it ignores conditions with wildcards or variables). Prowler `kms_key_not_publicly_accessible`. CloudFox `resource-trusts --include-kms`. Access Analyzer external access.

#### Detection

CloudTrail `PutKeyPolicy` (diff `requestParameters.policy` against the previous version), `CreateKey` with `bypassPolicyLockoutSafetyCheck: true`, `Decrypt` / `GenerateDataKey` where `userIdentity.accountId` is not the key owner. Alert on any `PutKeyPolicy` outside a change window; key policies change rarely.

### GT-AWS-SEC-6: Broad decrypt and grant permissions in IAM

*Guler Tech methodology.*

#### What it checks

Identity policies that allow `kms:Decrypt`, `kms:ReEncryptFrom`, `kms:CreateGrant` or key administration on `"Resource": "*"`, which, combined with the default delegation statement, cover every key that delegates to IAM.

#### Prerequisites

`gaad.json` from GT-AWS-SEC-2; the list of keys that delegate to IAM from GT-AWS-SEC-5.

#### Steps

1. Find the statements:

   ```bash
   jq -r '
     def stmts: (if type=="array" then .[] else . end);
     ( .Policies[] | .PolicyName as $n | .PolicyVersionList[] | select(.IsDefaultVersion)
       | .Document.Statement | stmts | select(.Effect=="Allow") | {n:$n, a:.Action, r:.Resource, c:.Condition} ),
     ( .RoleDetailList[] | .RoleName as $n | .RolePolicyList[]? | .PolicyDocument.Statement | stmts
       | select(.Effect=="Allow") | {n:("inline:"+$n), a:.Action, r:.Resource, c:.Condition} )
     | select((.a|tostring|test("kms:(Decrypt|ReEncrypt|CreateGrant|PutKeyPolicy|\\*)|\"\\*\"")) and (.r|tostring|test("\"\\*\"|^\\*$")))
     | "\(.n)\t\(.a|tostring)\t\(.c|tostring)"' gaad.json | sort -u
   ```

2. For each hit, note whether a condition (`kms:ViaService`, `aws:ResourceTag`, `kms:EncryptionContext:*`) actually narrows it. Security Hub KMS.1 and KMS.2 ignore conditions, so expect false positives where `kms:ViaService` is set.

3. Identify which principals hold these policies and whether they include workloads exposed to the internet (Lambda behind API Gateway, EC2 web tier) or CI.

4. Escalation check: for principals with `kms:CreateGrant` or `kms:PutKeyPolicy` on `*`, record that they can grant themselves decryption on every delegating key. PMapper collects key policies and uses them in `query`, but its escalation edges do not model grant creation or key policy rewrites, so reason this one out from the policies and state it explicitly in the report.

#### Observation

```text
AppServerPolicy          ["kms:Decrypt","kms:GenerateDataKey"]   null
inline:ci-deploy         "kms:*"                                  null
DataTeamKms              "kms:Decrypt"                            {"StringEquals": {"kms:ViaService": "s3.eu-west-2.amazonaws.com"} }
```

#### Evaluation

**Fail** for `kms:Decrypt` or `kms:ReEncryptFrom` on `*` without a narrowing condition in any role that does not need every key, and for `kms:*`, `kms:CreateGrant` or `kms:PutKeyPolicy` on `*` outside a key administration role. **Pass (with note)** where a `kms:ViaService` condition limits the statement to one service and that service's own permissions are scoped. **Pass** where decryption is scoped to key ARNs or to tags controlled by a protected process.

#### Automated coverage

Security Hub CSPM KMS.1 (customer managed policies) and KMS.2 (inline policies); Config rules `iam-customer-policy-blocked-kms-actions` and `iam-inline-policy-blocked-kms-actions`. Prowler `iam_policy_no_full_access_to_kms`, `iam_inline_policy_no_full_access_to_kms`. cloudsplaining also lists these under data exfiltration and privilege escalation categories.

#### Detection

CloudTrail `Decrypt` from a principal against keys it has never used before (baseline per principal and key); `CreateGrant` by a human or CI role (normally grants are created by services, `userIdentity.invokedBy` is a service).

### GT-AWS-SEC-7: KMS grants review

*Guler Tech methodology.*

#### What it checks

All grants on customer managed keys: who the grantee is, what operations they allow, whether they are constrained, whether they include `CreateGrant`, and whether any grantee is outside the account.

#### Prerequisites

`kms:ListGrants` on each key (subject to the key policy), `cmk.tsv` from GT-AWS-SEC-5.

#### Steps

1. Dump grants:

   ```bash
   while IFS=$'\t' read -r r mgr k rest; do
     aws kms list-grants --region "$r" --key-id "$k" --output json 2>/dev/null \
     | jq -r --arg r "$r" --arg k "$k" '.Grants[] | [ $r, $k, .GrantId, (.Name // "-"),
         .GranteePrincipal, (.RetiringPrincipal // "-"), (.Operations|join(",")),
         (.Constraints|tostring), .IssuingAccount, .CreationDate ] | @tsv'
   done < cmk.tsv > grants.tsv
   ```

2. Separate service grants from the rest. Grants created by integrated services usually have a service-style grantee (for example a service principal or a role that the service uses) and are created through the service (in CloudTrail, `CreateGrant` with `userIdentity.invokedBy` set to the service). Everything else needs a reason.

3. Flag:
   - `GranteePrincipal` in another account;
   - `Operations` containing `Decrypt` with no `Constraints`;
   - `Operations` containing `CreateGrant` (re-delegation);
   - grants to IAM users or to roles that no longer exist (the grant survives the role; a new role with the same name is a new principal and does not inherit it, but stale grants are noise that hides real ones);
   - grants created by a human or CI principal (look up the `CreateGrant` event by `GrantId` in CloudTrail Lake or Athena if the client retains logs).

4. Find grants retirable by a given principal, useful when a workload role is in scope:

   ```bash
   aws kms list-retirable-grants --retiring-principal arn:aws:iam::111122223333:role/app-orders
   ```

#### Observation

```text
eu-west-2  1111aaaa  0c1f...  -  arn:aws:iam::444455556666:role/etl   -  Decrypt,DescribeKey  null  111122223333  2024-03-02
eu-west-2  1111aaaa  7a9e...  -  arn:aws:iam::111122223333:role/dev-jo  -  Decrypt,CreateGrant  null  111122223333  2025-06-11
```

#### Evaluation

**Fail** for unconstrained `Decrypt` grants to principals outside the key's intended users, cross-account grants with no documented need, and any grant including `CreateGrant` to a non-service principal. **Pass** if all non-service grants are documented, constrained by encryption context where the data allows it, and retired when no longer needed.

#### Automated coverage

None in Security Hub CSPM or Prowler at the time of writing. IAM Access Analyzer considers grants when it evaluates external access to KMS keys.

#### Detection

`CreateGrant` events where `userIdentity.invokedBy` is absent (called directly, not by a service), where `requestParameters.granteePrincipal` is in another account, or where `requestParameters.operations` includes `CreateGrant`. `RetireGrant` / `RevokeGrant` en masse can also indicate someone covering tracks or sabotaging a workload.

### GT-AWS-SEC-8: Key rotation, key material and multi-Region keys

*Guler Tech methodology.*

#### What it checks

Rotation status and period for eligible customer managed keys, imported key material and its expiry, and the key policies of multi-Region replicas.

#### Prerequisites

`kms:GetKeyRotationStatus`, `kms:DescribeKey`, `kms:ListKeyRotations`, `cmk.tsv`.

#### Steps

1. Rotation on symmetric, KMS-origin keys:

   ```bash
   awk -F'\t' '$5=="AWS_KMS" && $6=="SYMMETRIC_DEFAULT" {print $1"\t"$3}' cmk.tsv |
   while IFS=$'\t' read -r r k; do
     aws kms get-key-rotation-status --region "$r" --key-id "$k" \
       --query '[KeyId,KeyRotationEnabled,RotationPeriodInDays || `-`,NextRotationDate || `-`]' --output text
   done
   ```

2. Rotation history where the client needs evidence: `aws kms list-key-rotations --key-id <KEY>`.

3. Imported material:

   ```bash
   awk -F'\t' '$5=="EXTERNAL" {print $1"\t"$3}' cmk.tsv | while IFS=$'\t' read -r r k; do
     aws kms describe-key --region "$r" --key-id "$k" \
       --query 'KeyMetadata.[KeyId,KeyState,ExpirationModel,ValidTo]' --output text
   done
   ```

   Ask the client where the original material is held and who can access it. Note who has `kms:DeleteImportedKeyMaterial` and `kms:ImportKeyMaterial`.

4. Multi-Region keys: for each primary, list replicas and compare the key policy of each replica with the primary:

   ```bash
   aws kms describe-key --key-id <MRK_PRIMARY> \
     --query 'KeyMetadata.MultiRegionConfiguration.ReplicaKeys[].[Region,Arn]' --output text
   diff <(aws kms get-key-policy --key-id <MRK_PRIMARY> --policy-name default --output text | jq -S .) \
        <(aws kms get-key-policy --region eu-west-1 --key-id <MRK_ID> --policy-name default --output text | jq -S .)
   ```

5. Asymmetric and HMAC keys: record their age; they need manual rotation (new key, move aliases) if the client's policy requires rotation.

#### Observation

```text
1111aaaa-...  True   180  2027-01-08T10:12:00+00:00
2222bbbb-...  False  -    -
```

#### Evaluation

**Fail (Low/Medium)** for eligible customer managed keys without automatic rotation where the client's standard, CIS or PCI DSS requires it. **Fail** if a multi-Region replica's policy is broader than the primary's (rate as GT-AWS-SEC-5, since the material is the same). **Fail** for imported material whose originals are held without controls, or whose expiry will take a production key offline without a plan. **Pass** if rotation is on with a period that meets the client's standard, and replicas match the primary.

#### Automated coverage

Security Hub CSPM KMS.4 (rotation enabled; CIS v1.2.0 2.8, v1.4.0 3.8, v3.0.0 3.6, v5.0.0 3.6; Config rule `cmk-backing-key-rotation-enabled`). Prowler `kms_cmk_rotation_enabled`, `kms_cmk_not_multi_region` (informational; multi-Region keys are not wrong in themselves).

#### Detection

`DisableKeyRotation`, `EnableKeyRotation` with a changed `rotationPeriodInDays`, `RotateKeyOnDemand`, `ImportKeyMaterial`, `DeleteImportedKeyMaterial`, `ReplicateKey`, `UpdatePrimaryRegion`. KMS also emits a `KMS CMK Rotation` event to EventBridge when it rotates.

### GT-AWS-SEC-9: Destructive key actions, pending deletion and alerting

*Guler Tech methodology.*

#### What it checks

Keys currently pending deletion or disabled, who can delete or disable keys, whether guardrails exist (SCP, key policy deny, minimum waiting period), and whether `DisableKey`, `ScheduleKeyDeletion` and `DeleteImportedKeyMaterial` raise an alert.

#### Prerequisites

`cmk.tsv`, organisation SCP read access (`organizations:ListPolicies`, `DescribePolicy`) from the management or delegated administrator account if in scope, CloudWatch and EventBridge read access.

#### Steps

1. Keys pending deletion or disabled, with their deletion date:

   ```bash
   awk -F'\t' '$4=="PendingDeletion" || $4=="Disabled" || $4=="PendingImport" {print $1"\t"$3}' cmk.tsv |
   while IFS=$'\t' read -r r k; do
     aws kms describe-key --region "$r" --key-id "$k" \
       --query 'KeyMetadata.[KeyId,KeyState,DeletionDate || `-`,PendingDeletionWindowInDays || `-`,Description]' --output text
   done
   ```

   For each, find what uses the key before anyone lets the deletion complete: aliases (`list-aliases --key-id`), last cryptographic use (`aws kms get-key-last-usage --key-id`, a recent API; it records only operations since its tracking start date), and resources that reference the key (RDS, EBS, S3 default encryption, Secrets Manager, CloudTrail, backups).

2. Who can destroy keys: from GT-AWS-SEC-5 and GT-AWS-SEC-6, list principals with `kms:ScheduleKeyDeletion`, `kms:DisableKey`, `kms:DeleteImportedKeyMaterial`, `kms:PutKeyPolicy`. In the console's default key policy every *key administrator* has `ScheduleKeyDeletion` unless the "allow key administrators to delete this key" option was cleared.

3. Guardrails: look for SCPs or key policy statements that deny these actions to everyone except a break-glass role, or that use `kms:ScheduleKeyDeletionPendingWindowInDays` or `kms:TrailingDaysWithoutKeyUsage`:

   ```bash
   aws organizations list-policies --filter SERVICE_CONTROL_POLICY --query 'Policies[].Id' --output text |
   tr '\t' '\n' | while read -r p; do
     aws organizations describe-policy --policy-id "$p" --query Policy.Content --output text |
     jq -c --arg p "$p" 'select(tostring|test("ScheduleKeyDeletion|DisableKey|DeleteImportedKeyMaterial")) | {p:$p}'
   done
   grep -l 'ScheduleKeyDeletionPendingWindowInDays\|TrailingDaysWithoutKeyUsage' keypol/*.json
   ```

4. Alerting: confirm a metric filter and alarm (CIS) or an EventBridge rule exists for these events:

   ```bash
   aws logs describe-metric-filters --query \
     'metricFilters[?contains(filterPattern, `ScheduleKeyDeletion`)].[logGroupName,filterName,filterPattern]' --output text
   aws events list-rules --query 'Rules[?contains(EventPattern || ``, `ScheduleKeyDeletion`)].[Name,State]' --output text
   ```

   Also confirm the CloudTrail trail is not excluding KMS events (`ExcludeManagementEventSources` containing `kms.amazonaws.com` in basic event selectors, or an advanced event selector that filters out `eventSource` `kms.amazonaws.com`; see the [CloudTrail note](/cloud/aws-cloudtrail-logging/)). Teams sometimes exclude KMS events to cut volume, and a trail that does so sees none of the events this test relies on.

5. **Lab or explicitly approved only:** to prove the alert works end to end, create a throwaway key in an approved test account, schedule its deletion with the 30-day window, confirm the alert fires, then `cancel-key-deletion` and schedule it again only if the client wants it removed. Never schedule deletion of an existing client key.

#### Observation

```text
3333cccc-...  PendingDeletion  2026-11-19T09:00:00+00:00  7  legacy-rds-key
metric filter: none
EventBridge rule: none
SCP: none mentions kms:ScheduleKeyDeletion
```

#### Evaluation

**Fail (High)** if production or backup keys can be scheduled for deletion or disabled by roles beyond a small, controlled administrative set, with no SCP or key policy guardrail **and** no alerting. **Fail (Medium)** if guardrails exist but alerting does not, or vice versa. **Fail (Critical, raise immediately)** if a key in use by production data or backups is currently `PendingDeletion` and the client did not intend it. **Pass** if deletion and disabling are denied except to a break-glass role, the minimum waiting period is enforced at 30 days, alerts reach a monitored channel, and backups are protected by a different key (ideally in a separate account; see the [Organizations note](/cloud/aws-organizations-multi-account-security/)).

#### Automated coverage

Security Hub CSPM KMS.3 (KMS keys should not be deleted unintentionally; Critical) and CloudWatch.7 (metric filter and alarm for disabling or scheduled deletion of customer managed keys; CIS v1.2.0 3.7, v1.4.0 4.7). Prowler `kms_cmk_not_deleted_unintentionally`, `cloudwatch_log_metric_filter_disable_or_scheduled_deletion_of_kms_cmk`. AWS Config managed rule `kms-cmk-not-scheduled-for-deletion`.

#### Detection

The CIS metric filter pattern is `{($.eventSource=kms.amazonaws.com) && (($.eventName=DisableKey) || ($.eventName=ScheduleKeyDeletion))}`. Extend it with `DeleteImportedKeyMaterial`, `PutKeyPolicy` and `DisableKeyRotation`. An EventBridge rule alerts within seconds:

```json
{
  "source": ["aws.kms"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventSource": ["kms.amazonaws.com"],
    "eventName": ["ScheduleKeyDeletion", "DisableKey", "DeleteImportedKeyMaterial", "PutKeyPolicy"]
  }
}
```

During the waiting period, KMS logs failed uses of the key (attempts against a key pending deletion), which tells you what breaks if the deletion completes. GuardDuty's `Impact:IAMUser/AnomalousBehavior` family covers anomalous impact-style API activity; do not rely on it alone for a 7-day window.

### GT-AWS-SEC-10: Secrets outside the vault

*Guler Tech methodology.*

#### What it checks

Plaintext credentials in places that are not designed to hold them: Lambda environment variables, ECS task definitions, EC2 user data and launch templates, CloudFormation parameters, outputs and templates, CodeBuild environment variables, SSM documents, and similar.

#### Prerequisites

`lambda:GetFunctionConfiguration`, `ecs:DescribeTaskDefinition`, `ec2:DescribeInstanceAttribute`, `ec2:DescribeLaunchTemplateVersions`, `cloudformation:DescribeStacks`, `cloudformation:GetTemplate`, `codebuild:BatchGetProjects`, `ssm:GetDocument`. The client must accept that the review handles plaintext values; keep the output in the engagement's encrypted evidence store and redact before reporting.

#### Steps

1. Collect configuration into a local directory and scan it rather than eyeballing JSON:

   ```bash
   mkdir -p loot && cd loot
   for r in $REGIONS; do
     aws lambda list-functions --region "$r" --query 'Functions[].FunctionName' --output text | tr '\t' '\n' |
       while read -r f; do [ -n "$f" ] && aws lambda get-function-configuration --region "$r" --function-name "$f" \
         --query '{Name:FunctionName,Env:Environment.Variables,Kms:KMSKeyArn}' > "lambda-$r-$f.json"; done
     for td in $(aws ecs list-task-definitions --region "$r" --status ACTIVE --query 'taskDefinitionArns[]' --output text); do
       aws ecs describe-task-definition --region "$r" --task-definition "$td" \
         --query 'taskDefinition.containerDefinitions[].{c:name,env:environment,secrets:secrets}' > "ecs-$r-$(basename "$td").json"
     done
     for i in $(aws ec2 describe-instances --region "$r" --query 'Reservations[].Instances[].InstanceId' --output text); do
       aws ec2 describe-instance-attribute --region "$r" --instance-id "$i" --attribute userData \
         --query UserData.Value --output text | grep -v '^None$' | base64 -d > "userdata-$r-$i.txt" 2>/dev/null
     done
     aws cloudformation describe-stacks --region "$r" \
       --query 'Stacks[].{s:StackName,p:Parameters,o:Outputs}' > "cfn-$r.json"
     projects=$(aws codebuild list-projects --region "$r" --query 'projects[]' --output text)
     [ -n "$projects" ] && aws codebuild batch-get-projects --region "$r" --names $projects \
       --query 'projects[].{n:name,env:environment.environmentVariables}' > "codebuild-$r.json"
   done
   trufflehog filesystem . --no-verification --json > ../trufflehog.json
   gitleaks dir . --report-path ../gitleaks.json
   cd ..
   ```

   Run trufflehog with `--no-verification` unless the client has approved live verification of found credentials against their providers; verification sends the credential to the provider.

2. Look beyond the scanners for names that suggest secrets in the JSON (`PASSWORD`, `SECRET`, `TOKEN`, `API_KEY`, `DB_URL` containing `user:pass@`), and for AWS keys (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`), which also fail Security Hub ECS.8 and CodeBuild.2.

3. CloudFormation specifics:
   - Parameters without `NoEcho: true` return their values in `DescribeStacks`. Parameters with `NoEcho` are masked there, but **not** if the template copies the value into `Outputs`, `Metadata` or a resource's `Metadata` attribute.
   - `GetTemplate` returns the template, including any `Default` values for parameters (a common place for a default password).
   - The template bucket used by the pipeline may also hold rendered templates.

   ```bash
   for s in $(aws cloudformation list-stacks --stack-status-filter CREATE_COMPLETE UPDATE_COMPLETE \
              --query 'StackSummaries[].StackName' --output text); do
     aws cloudformation get-template --stack-name "$s" --query TemplateBody --output json > "loot/tpl-$s.json"
   done
   ```

4. Check what *does* use references correctly, to recommend the right fix: ECS `secrets` with `valueFrom` (Secrets Manager or SSM ARNs), CodeBuild variables of type `SECRETS_MANAGER` or `PARAMETER_STORE`, CloudFormation dynamic references to Secrets Manager or SSM SecureString, Lambda reading from Secrets Manager at runtime (or the Parameters and Secrets Lambda extension).

5. Record **who can read** each location: `lambda:GetFunctionConfiguration`, `ecs:DescribeTaskDefinition`, `ec2:DescribeInstanceAttribute` and `cloudformation:DescribeStacks` are in many read-only and audit policies, so a plaintext secret here is usually readable by far more people than the same secret in Secrets Manager.

Depth for each source lives in its own note: [Lambda](/cloud/aws-lambda-serverless-security/), [containers](/cloud/aws-containers-ecs-eks-ecr-security/), [EC2 user data](/cloud/aws-ec2-imds-ebs-ssm-security/) and [CodeBuild and CloudFormation](/cloud/aws-cicd-iac-security/).

#### Observation

```text
lambda-eu-west-2-orders-api.json   DB_PASSWORD=<redacted, 24 chars>   (env encrypted with aws/lambda)
ecs-eu-west-2-web:41.json          AWS_SECRET_ACCESS_KEY=<redacted>   (environment, not secrets)
userdata-eu-west-2-i-0abc....txt   mysql -u admin -p<redacted> ...
cfn-eu-west-2.json                 stack shop-db  Parameter DBPassword = <redacted>   (no NoEcho)
codebuild-eu-west-2.json           NPM_TOKEN type PLAINTEXT
```

#### Evaluation

**Fail** for every live credential found in plaintext configuration. Severity follows what the credential unlocks and who can read the location: an AWS access key for an admin user readable by every developer is Critical; a staging SMTP password readable by two roles is Low. Lambda environment variables are encrypted at rest with KMS, but the console and `GetFunctionConfiguration` return them decrypted to anyone with that permission (and with `kms:Decrypt` on a customer managed key, if one is set), so "encrypted at rest" is not a pass. **Pass** when configuration contains only references (ARNs or parameter names) and the referenced secrets are scoped per workload.

#### Automated coverage

Security Hub CSPM ECS.8 (secrets as container environment variables; checks only `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `ECS_ENGINE_AUTH_DATA`), CodeBuild.2 (clear text AWS credentials in project variables). Prowler `awslambda_function_no_secrets_in_variables`, `awslambda_function_no_secrets_in_code`, `ecs_task_definitions_no_environment_secrets`, `ec2_instance_secrets_user_data`, `ec2_launch_template_no_secrets`, `cloudformation_stack_outputs_find_secrets`, `codebuild_project_no_secrets_in_variables`, `ssm_document_secrets`, `stepfunctions_statemachine_no_secrets_in_definition`, `glue_etl_jobs_no_secrets_in_arguments`, `elasticbeanstalk_environment_no_secrets_in_configuration`, `batch_job_definition_no_secrets`. CloudFox `env-vars` and `cloudformation`.

#### Detection

Mass `GetFunctionConfiguration`, `DescribeTaskDefinition`, `DescribeInstanceAttribute` (with `attribute: userData`) or `GetTemplate` calls from one principal in a short period (ATT&CK T1552.001 style collection). These are management read events; make sure the trail records read events.

## Hardening

**Secrets Manager: per-workload access, customer managed key, no public policy.** A resource policy that denies everything except the owning workload role and an admin role, applied with `BlockPublicPolicy`:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyAllButOwnerAndAdmin",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "secretsmanager:GetSecretValue",
      "Resource": "*",
      "Condition": {
        "ArnNotLike": {
          "aws:PrincipalArn": [
            "arn:aws:iam::111122223333:role/app-orders",
            "arn:aws:iam::111122223333:role/secrets-admin"
          ]
        }
      }
    }
  ]
}
```

```hcl
resource "aws_kms_key" "orders_secrets" {
  description             = "orders service secrets"
  enable_key_rotation     = true
  rotation_period_in_days = 180
  deletion_window_in_days = 30
  policy                  = data.aws_iam_policy_document.orders_secrets_key.json
}

resource "aws_secretsmanager_secret" "orders_db" {
  name       = "prod/orders/db"
  kms_key_id = aws_kms_key.orders_secrets.arn
}

resource "aws_secretsmanager_secret_policy" "orders_db" {
  secret_arn          = aws_secretsmanager_secret.orders_db.arn
  policy              = data.aws_iam_policy_document.orders_db_secret.json
  block_public_policy = true
}

resource "aws_secretsmanager_secret_rotation" "orders_db" {
  secret_id           = aws_secretsmanager_secret.orders_db.id
  rotation_lambda_arn = aws_lambda_function.rotate_orders_db.arn
  rotation_rules {
    automatically_after_days = 30
  }
}
```

For RDS and Aurora master users, prefer managed rotation (`manage_master_user_password = true` on `aws_db_instance` / `aws_rds_cluster`, `ManageMasterUserPassword: true` in CloudFormation) and give applications their own least-privileged database users with alternating-users rotation.

**Key policy that binds a key to Secrets Manager and to specific secrets.** Delegation to IAM is kept for manageability; the key users statement adds `kms:ViaService` and the encryption context:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "EnableIAMPolicies",
      "Effect": "Allow",
      "Principal": { "AWS": "arn:aws:iam::111122223333:root" },
      "Action": "kms:*",
      "Resource": "*"
    },
    {
      "Sid": "OrdersSecretsOnlyViaSecretsManager",
      "Effect": "Allow",
      "Principal": { "AWS": "arn:aws:iam::111122223333:role/app-orders" },
      "Action": ["kms:Decrypt", "kms:DescribeKey"],
      "Resource": "*",
      "Condition": {
        "StringEquals": { "kms:ViaService": "secretsmanager.eu-west-2.amazonaws.com" },
        "StringLike": { "kms:EncryptionContext:SecretARN": "arn:aws:secretsmanager:eu-west-2:111122223333:secret:prod/orders/*" }
      }
    },
    {
      "Sid": "DenyDestructiveExceptBreakGlass",
      "Effect": "Deny",
      "Principal": "*",
      "Action": ["kms:ScheduleKeyDeletion", "kms:DisableKey", "kms:PutKeyPolicy", "kms:DeleteImportedKeyMaterial"],
      "Resource": "*",
      "Condition": {
        "ArnNotLike": { "aws:PrincipalArn": "arn:aws:iam::111122223333:role/kms-break-glass" }
      }
    }
  ]
}
```

Test any `Deny` on `kms:PutKeyPolicy` carefully in a lab first: a mistake leaves the key unmanageable except by the break-glass role, which is the point, but the role must exist and be usable.

**Organisation guardrails (SCP).** Deny destructive KMS actions and short deletion windows everywhere except a break-glass role, and deny creating secrets on the AWS managed key in production OUs if the client standard requires customer managed keys:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ProtectKeys",
      "Effect": "Deny",
      "Action": ["kms:ScheduleKeyDeletion", "kms:DisableKey", "kms:DeleteImportedKeyMaterial"],
      "Resource": "*",
      "Condition": {
        "ArnNotLike": { "aws:PrincipalArn": "arn:aws:iam::*:role/kms-break-glass" }
      }
    },
    {
      "Sid": "MinimumDeletionWindow",
      "Effect": "Deny",
      "Action": "kms:ScheduleKeyDeletion",
      "Resource": "*",
      "Condition": {
        "NumericLessThan": { "kms:ScheduleKeyDeletionPendingWindowInDays": "30" }
      }
    },
    {
      "Sid": "SecretsRequireBlockPublicPolicy",
      "Effect": "Deny",
      "Action": "secretsmanager:PutResourcePolicy",
      "Resource": "*",
      "Condition": {
        "Bool": { "secretsmanager:BlockPublicPolicy": "false" }
      }
    }
  ]
}
```

**Data perimeter (RCP).** Resource control policies (November 2024) apply to KMS and Secrets Manager among the first supported services. An RCP that denies access by principals outside the organisation stops a mistaken key or secret policy from opening data to the world:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "EnforceOrgIdentities",
      "Effect": "Deny",
      "Principal": "*",
      "Action": ["kms:*", "secretsmanager:*"],
      "Resource": "*",
      "Condition": {
        "StringNotEqualsIfExists": { "aws:PrincipalOrgID": "o-exampleorg" },
        "BoolIfExists": { "aws:PrincipalIsAWSService": "false" }
      }
    }
  ]
}
```

Check the current RCP documentation for supported services and for exceptions you need (for example, legitimate third-party access); the [Organizations note](/cloud/aws-organizations-multi-account-security/) covers RCP design.

**Parameter Store.** Store secrets only as `SecureString` with a customer managed key per application or environment, grant `ssm:GetParameter*` on the application's own path, deny `ssm:GetParametersByPath` with `ssm:Recursive` on the root, and use Advanced tier `Expiration` policies for temporary credentials. Better still, keep credentials in Secrets Manager and reference them.

**Secrets outside the vault.** Replace plaintext with references: ECS `secrets` / `valueFrom`; CodeBuild `type: SECRETS_MANAGER` or `PARAMETER_STORE`; CloudFormation dynamic references and `NoEcho` (never echo into `Outputs`); Lambda reading at runtime; EC2 user data fetching from Secrets Manager at boot with the instance role. CloudFormation dynamic references use double braces, which is why this block is wrapped for the site generator:

{% raw %}
```yaml
Resources:
  OrdersDb:
    Type: AWS::RDS::DBInstance
    Properties:
      MasterUsername: '{{resolve:secretsmanager:prod/orders/db:SecretString:username}}'
      MasterUserPassword: '{{resolve:secretsmanager:prod/orders/db:SecretString:password}}'
```
{% endraw %}

**Detective controls.** Turn on Security Hub CSPM controls SecretsManager.1 to .4, KMS.1 to .5, CloudWatch.7, ECS.8 and CodeBuild.2; keep an IAM Access Analyzer external access analyzer in every Region with the organisation as zone of trust; alert on the EventBridge pattern in GT-AWS-SEC-9; and keep backups under a key in a separate account so one compromised administrator cannot destroy both copies.

## Real-world cases

- **Leaked `.env` files to cloud extortion (Unit 42, August 2024).** Attackers harvested AWS access keys from publicly exposed `.env` files on tens of thousands of domains, enumerated the accounts, created an administrator role, and exfiltrated and deleted S3 data before leaving ransom notes. A reminder that the vault only helps if secrets live in it. [Unit 42: Leaked Environment Variables Allow Large-Scale Extortion Operation of Cloud Environments](https://unit42.paloaltonetworks.com/large-scale-cloud-extortion-operation/).
- **SCARLETEEL (Sysdig, 2023).** After a container compromise, the actor collected credentials from Lambda environment variables and from Terraform state files in S3, then used them to move into other accounts. [Sysdig: SCARLETEEL, operation leveraging Terraform, Kubernetes and AWS for data theft](https://sysdig.com/blog/cloud-breach-terraform-data-theft/).
- **Encryption as impact with a key the victim does not control (Rhino Security Labs).** Research describing how an attacker with write access re-encrypts S3 objects under a KMS key in the attacker's account (whose policy lets anyone encrypt but nobody else decrypt), then schedules that key for deletion with the minimum 7-day window. [Rhino Security Labs: S3 Ransomware Part 1, Attack Vector](https://rhinosecuritylabs.com/aws/s3-ransomware-part-1-attack-vector/).
- **Codefinger and SSE-C (Halcyon, January 2025).** A ransomware campaign used stolen AWS keys to re-encrypt S3 objects with SSE-C, customer-provided keys that AWS never stores, then set lifecycle rules to delete them. It is not KMS, but it is the same lesson: whoever controls the key controls the data, and destructive encryption needs guardrails and alerts. [Halcyon: Abusing AWS native services, ransomware encrypting S3 buckets with SSE-C](https://www.halcyon.ai/blog/abusing-aws-native-services-ransomware-encrypting-s3-buckets-with-sse-c).

More incidents are collected in [AWS security incidents and writeups](/cloud/aws-security-incidents-and-writeups/).

## Rating findings

| Finding | Typical severity | Reasoning |
|---|---|---|
| KMS key policy allows `kms:Decrypt` / `kms:*` to `*` with no condition | Critical | Any AWS principal anywhere can decrypt ciphertext under the key once they obtain it (shared snapshots, copied objects); no account compromise needed |
| Secret resource policy allows `*` or an unknown external account to `GetSecretValue`, with a CMK that also allows them | Critical | Direct read of credentials from outside the account; value often leads to further systems |
| Live AWS access key or admin credential in plaintext config readable by broad roles | Critical–High | One read gives a second identity, often more privileged than the reader, and survives the reader's session |
| Workload or CI role can read all secrets/parameters (`*`) with AWS managed keys | High | Compromise of any such role (SSRF, CI token leak) yields every credential in the account |
| `kms:CreateGrant` or `kms:PutKeyPolicy` on `*` for non-admin roles | High | Self-service path to decrypt every delegating key; looks like administration so it survives reviews |
| Destructive key actions unguarded and unalerted on keys protecting production and backups | High | Data destruction with a 7-day quiet window; no exfiltration needed; Medium if one of guardrails or alerting exists |
| Production key currently `PendingDeletion` unintentionally | Critical (time-bound) | Irreversible loss on a known date; report immediately |
| Cross-account key grant or key policy to an external `:root` without documented need | High–Medium | External account decides which of its principals decrypt; rate by data sensitivity |
| Secrets stored as `String` parameters | Medium–High | Plaintext, widely readable, echoed by tools; High if values are production credentials |
| Plaintext secrets in Lambda/ECS/user data/CFN/CodeBuild (non-AWS credentials) | Medium–High | Read by anyone with common describe permissions; rate by credential value |
| Rotation absent or failing on rotatable production secrets | Medium–Low | Extends the life of any past leak; raises the severity of exposure findings rather than standing alone |
| `BlockPublicPolicy` not used, no current public policy | Low | Missing guardrail, no demonstrated exposure |
| CMK without automatic rotation | Low | Compliance and hygiene; rotation does not undo a leak |
| Multi-Region replica policy broader than primary | As the broader policy | Same key material, so the weakest policy wins |
| Unused secrets (90+ days) | Low/Info | Attack surface and cost; becomes Medium if broadly readable |

## Mapping

| Test | Security Hub CSPM | CIS AWS Foundations | ATT&CK |
|---|---|---|---|
| GT-AWS-SEC-1 | (none; Access Analyzer) | — | T1555.006 |
| GT-AWS-SEC-2 | (none) | — | T1555.006, T1078.004 |
| GT-AWS-SEC-3 | SecretsManager.1, SecretsManager.2, SecretsManager.3, SecretsManager.4 | — | T1555.006 |
| GT-AWS-SEC-4 | (none) | — | T1555.006, T1552.001 |
| GT-AWS-SEC-5 | KMS.5 | — | T1555.006 |
| GT-AWS-SEC-6 | KMS.1, KMS.2 | — | T1555.006, T1078.004 |
| GT-AWS-SEC-7 | (none) | — | T1555.006 |
| GT-AWS-SEC-8 | KMS.4 | v1.2.0 2.8; v1.4.0 3.8; v3.0.0 3.6; v5.0.0 3.6 | — |
| GT-AWS-SEC-9 | KMS.3, CloudWatch.7 | CloudWatch.7: v1.2.0 3.7; v1.4.0 4.7 | T1485, T1486, T1490 |
| GT-AWS-SEC-10 | ECS.8, CodeBuild.2 | — | T1552.001 |

## References

- AWS Secrets Manager: [Rotate secrets](https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotating-secrets.html), [Managed rotation](https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotate-secrets_managed.html), [Rotation by Lambda function](https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotate-secrets_lambda.html), [Cross-account access](https://docs.aws.amazon.com/secretsmanager/latest/userguide/auth-and-access_examples_cross.html), [Encryption and decryption](https://docs.aws.amazon.com/secretsmanager/latest/userguide/security-encryption.html), [Replicate secrets](https://docs.aws.amazon.com/secretsmanager/latest/userguide/replicate-secrets.html)
- AWS Systems Manager: [Parameter tiers](https://docs.aws.amazon.com/systems-manager/latest/userguide/parameter-store-advanced-parameters.html), [Parameter policies](https://docs.aws.amazon.com/systems-manager/latest/userguide/parameter-store-policies.html)
- AWS KMS: [Default key policy](https://docs.aws.amazon.com/kms/latest/developerguide/key-policy-default.html), [Condition keys](https://docs.aws.amazon.com/kms/latest/developerguide/conditions-kms.html), [Grants](https://docs.aws.amazon.com/kms/latest/developerguide/grants.html), [Rotate keys](https://docs.aws.amazon.com/kms/latest/developerguide/rotate-keys.html), [On-demand rotation](https://docs.aws.amazon.com/kms/latest/developerguide/rotating-keys-on-demand.html), [Determine past usage](https://docs.aws.amazon.com/kms/latest/developerguide/monitoring-keys-determining-usage.html), [Deleting keys](https://docs.aws.amazon.com/kms/latest/developerguide/deleting-keys.html), [Multi-Region keys](https://docs.aws.amazon.com/kms/latest/developerguide/multi-region-keys-overview.html), [Importing key material](https://docs.aws.amazon.com/kms/latest/developerguide/importing-keys.html), [What's new: flexible automatic key rotation (April 2024)](https://aws.amazon.com/about-aws/whats-new/2024/04/aws-kms-automatic-key-rotation)
- AWS CloudHSM: [User guide](https://docs.aws.amazon.com/cloudhsm/latest/userguide/introduction.html)
- Security Hub CSPM control references: [KMS](https://docs.aws.amazon.com/securityhub/latest/userguide/kms-controls.html), [Secrets Manager](https://docs.aws.amazon.com/securityhub/latest/userguide/secretsmanager-controls.html), [CloudWatch](https://docs.aws.amazon.com/securityhub/latest/userguide/cloudwatch-controls.html), [ECS](https://docs.aws.amazon.com/securityhub/latest/userguide/ecs-controls.html), [CodeBuild](https://docs.aws.amazon.com/securityhub/latest/userguide/codebuild-controls.html), [CIS AWS Foundations Benchmark in Security Hub CSPM](https://docs.aws.amazon.com/securityhub/latest/userguide/cis-aws-foundations-benchmark.html). Security Hub CSPM is the original Security Hub, renamed in 2025 when the new Security Hub launched; control IDs are unchanged.
- MITRE ATT&CK: [T1555.006 Cloud Secrets Management Stores](https://attack.mitre.org/techniques/T1555/006/), [T1552.001 Credentials In Files](https://attack.mitre.org/techniques/T1552/001/), [T1078.004 Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/), [T1485 Data Destruction](https://attack.mitre.org/techniques/T1485/), [T1486 Data Encrypted for Impact](https://attack.mitre.org/techniques/T1486/), [T1490 Inhibit System Recovery](https://attack.mitre.org/techniques/T1490/)
- Tools: [Prowler](https://github.com/prowler-cloud/prowler), [CloudFox](https://github.com/BishopFox/cloudfox), [PMapper](https://github.com/nccgroup/PMapper), [cloudsplaining](https://github.com/salesforce/cloudsplaining), [Steampipe](https://github.com/turbot/steampipe), [trufflehog](https://github.com/trufflesecurity/trufflehog), [gitleaks](https://github.com/gitleaks/gitleaks), [Pacu](https://github.com/RhinoSecurityLabs/pacu), [Secrets Manager rotation Lambda samples](https://github.com/aws-samples/aws-secrets-manager-rotation-lambdas)
- Labs: [CloudGoat](https://github.com/RhinoSecurityLabs/cloudgoat), [IAM Vulnerable](https://github.com/BishopFox/iam-vulnerable), [Stratus Red Team](https://github.com/DataDog/stratus-red-team) (includes KMS and secrets attack techniques for detection testing in a lab)
- Related notes: [IAM fundamentals](/cloud/aws-iam-fundamentals-policy-evaluation/), [IAM privilege escalation](/cloud/aws-iam-privilege-escalation/), [CloudTrail](/cloud/aws-cloudtrail-logging/), [CloudWatch and EventBridge](/cloud/aws-cloudwatch-eventbridge-monitoring/), [detection services](/cloud/aws-detection-posture-services/), [keys hardcoded in mobile apps](/mobile/maswe-0004-sensitive-data-hardcoded-app-package/)
