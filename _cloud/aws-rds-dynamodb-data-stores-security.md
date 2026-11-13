---
title: "AWS Data Stores: RDS, Aurora, DynamoDB and Snapshots"
date: 2026-11-12 18:10:00 +0000
subcategory: aws
summary: "Reviewing RDS, Aurora, DynamoDB, ElastiCache, Redshift and OpenSearch: exposure, shared snapshots, auth, TLS, IAM paths to data, and how to rate them."
refs: [RDS.1, RDS.2, RDS.3, RDS.4, RDS.7, RDS.8, RDS.9, RDS.10, RDS.11, RDS.12, RDS.27, RDS.38, RDS.39, RDS.46, DynamoDB.2, DynamoDB.6, ElastiCache.4, ElastiCache.5, ElastiCache.6, Redshift.1, Redshift.2, Redshift.15, Opensearch.2, Opensearch.7, DocumentDB.3, CIS AWS 3.0.0 2.3.1, CIS AWS 3.0.0 2.3.3, T1213.006, T1537, T1578.001, T1078.004, T1110, T1098, T1485, T1490, T1555.006, T1557]
tags: [aws, rds, dynamodb, databases, snapshots, opensearch]
---

This note is part of our [AWS security testing guide](/cloud/aws-security-testing-guide/) and covers AWS's managed data stores from a reviewer's point of view: Amazon RDS and Aurora, the RDS Data API, DynamoDB, ElastiCache and MemoryDB, Redshift, OpenSearch Service and, briefly, DocumentDB. Managed databases remove the operating system from your attack surface, but they add a second one that many teams never look at: the AWS control plane. An attacker who cannot reach port 5432 may still be able to share a snapshot with their own account, restore it, reset the master password of a copy, export a table to a bucket they own, or read the master secret from Secrets Manager. The classic network questions (is it public, which security group, is TLS required) still matter and are where most findings start. Below are the security models, what goes wrong and why, twelve tests with commands and pass/fail criteria, the hardening that closes each gap, and how we rate the findings.

## Contents

- [How it works](#how-it-works)
- [What goes wrong](#what-goes-wrong)
- [Testing](#testing)
  - [Before you start](#before-you-start)
  - [GT-AWS-DB-1: RDS and Aurora network exposure](#gt-aws-db-1-rds-and-aurora-network-exposure)
  - [GT-AWS-DB-2: Public and cross-account DB snapshots](#gt-aws-db-2-public-and-cross-account-db-snapshots)
  - [GT-AWS-DB-3: Encryption at rest and KMS key exposure](#gt-aws-db-3-encryption-at-rest-and-kms-key-exposure)
  - [GT-AWS-DB-4: Database authentication and transport encryption](#gt-aws-db-4-database-authentication-and-transport-encryption)
  - [GT-AWS-DB-5: Deletion protection, backups and recovery](#gt-aws-db-5-deletion-protection-backups-and-recovery)
  - [GT-AWS-DB-6: Logging, Performance Insights and Data API visibility](#gt-aws-db-6-logging-performance-insights-and-data-api-visibility)
  - [GT-AWS-DB-7: IAM paths to database data](#gt-aws-db-7-iam-paths-to-database-data)
  - [GT-AWS-DB-8: DynamoDB resource policies and fine-grained access control](#gt-aws-db-8-dynamodb-resource-policies-and-fine-grained-access-control)
  - [GT-AWS-DB-9: DynamoDB encryption, PITR, deletion protection and exports](#gt-aws-db-9-dynamodb-encryption-pitr-deletion-protection-and-exports)
  - [GT-AWS-DB-10: ElastiCache and MemoryDB authentication and encryption](#gt-aws-db-10-elasticache-and-memorydb-authentication-and-encryption)
  - [GT-AWS-DB-11: OpenSearch Service domain access](#gt-aws-db-11-opensearch-service-domain-access)
  - [GT-AWS-DB-12: Redshift and DocumentDB exposure and snapshot sharing](#gt-aws-db-12-redshift-and-documentdb-exposure-and-snapshot-sharing)
- [Hardening](#hardening)
- [Real-world cases](#real-world-cases)
- [Rating findings](#rating-findings)
- [Mapping](#mapping)
- [References](#references)

## How it works

### Two planes: the database and the AWS API

Every managed data store has two separate ways in, and a review must cover both:

| Plane | What it is | Who controls access | Typical attacker step |
|---|---|---|---|
| **Data plane (engine)** | The database protocol: PostgreSQL, MySQL, SQL Server, Oracle, Redis/Valkey, the OpenSearch REST API | Network (VPC, subnets, security groups, public endpoint), then database users, passwords, IAM tokens, engine roles | Connect and authenticate, brute force, steal credentials, sniff non-TLS traffic |
| **Control plane (AWS API)** | `rds:*`, `dynamodb:*` management calls, `elasticache:*`, `es:*` configuration, `redshift:*` | IAM identity policies, resource policies (DynamoDB, OpenSearch), SCPs and RCPs | Snapshot and share, restore elsewhere, reset the master password, export to S3, change the access policy |

DynamoDB blurs the line: its data operations (`GetItem`, `Query`, `Scan`) are AWS API calls authorised by IAM, so there is no database user layer at all. The RDS Data API does the same for Aurora by turning SQL into an HTTPS API call.

### RDS and Aurora

**Network exposure** has three parts that must all line up for an instance to be reachable from the internet: `PubliclyAccessible` is `true` (the endpoint's DNS name resolves to a public IP from outside the VPC), the DB subnet group's subnets route to an internet gateway, and a security group allows the source. The API default is not "private": if you create an instance without naming a DB subnet group, `PubliclyAccessible` defaults to `true` for non-Aurora engines, and it also defaults to `true` when the subnet group is called `default`. Templates and scripts that omit the flag therefore produce public instances in default VPCs.

**Encryption at rest** uses a KMS key, either the AWS managed key `aws/rds` or a customer managed key. It is chosen at creation and cannot be switched on in place: the path is snapshot, copy the snapshot with encryption, restore. Snapshots, read replicas and automated backups inherit the instance's encryption.

**Snapshots** are where data most often leaves an account:

- Automated snapshots cannot be shared; manual ones can, with up to 20 accounts, or with **everyone** by adding `all` to the snapshot's `restore` attribute.
- **Unencrypted** manual snapshots can be shared publicly and restored directly by the receiving account.
- **Encrypted** snapshots cannot be made public. They can be shared with specific accounts only if they use a **customer managed** key whose key policy also lets those accounts use the key; snapshots encrypted with `aws/rds` cannot be shared at all.
- Aurora uses **DB cluster snapshots** with the same `restore` attribute; Neptune and DocumentDB snapshots follow the same model.
- When another account copies or restores a public snapshot, **nothing is logged in the owner's account**, as Mitiga's 2022 research pointed out. If a snapshot was public, you cannot prove it was not taken.

**Authentication** options:

- **Master user and password.** The master user is the most privileged engine user. Since late 2022, RDS can generate the password and manage it in **Secrets Manager** (`--manage-master-user-password`), rotating it every seven days by default, with a secret named `rds!db-...` or `rds!cluster-...`. The condition key `rds:ManageMasterUserPassword` lets you require this.
- **IAM database authentication** (MySQL, MariaDB, PostgreSQL, Aurora): the client calls `generate-db-auth-token`, which signs a token valid for 15 minutes, and connects with it as the password. Authorisation is the IAM action `rds-db:connect` on `arn:aws:rds-db:<region>:<account>:dbuser:<DbiResourceId or cluster resource ID>/<db-user>`. In the engine, the user must be marked for IAM (`AWSAuthenticationPlugin` on MySQL, `GRANT rds_iam` on PostgreSQL). It removes static passwords from applications but turns database access into an IAM question.
- **Kerberos** (Active Directory) is available for several engines and is out of scope here.

**Transport encryption** is enforced by parameters, not by the endpoint:

- RDS for PostgreSQL: `rds.force_ssl`. The default is `1` (on) for PostgreSQL 15 and later and `0` for 14 and earlier. Aurora PostgreSQL has the same parameter in the cluster parameter group.
- RDS for MySQL and Aurora MySQL: `require_secure_transport`, default `OFF`.
- SQL Server and MariaDB have their own equivalents (Security Hub CSPM `RDS.41`, `RDS.44`).
- Clients matter as much: `psql` and JDBC default to `sslmode=prefer`, which falls back to plaintext and does not verify the server certificate. Only `verify-full` (or the driver's equivalent) protects against an on-path attacker.

**Resilience:** deletion protection (`DeletionProtection`), automated backups (`BackupRetentionPeriod` 1 to 35 days; `0` disables them for RDS instances), AWS Backup plans, and Aurora backtracking (Aurora MySQL). Note that deleting an instance deletes its automated backups unless the caller asks to retain them.

**Visibility:** engine logs exported to CloudWatch Logs (`EnabledCloudwatchLogsExports`), audit plugins (Aurora MySQL advanced auditing, MariaDB audit plugin, `pgaudit`), Enhanced Monitoring, and Performance Insights, whose "top SQL" view shows statement text. AWS set **31 July 2026** as the end of life of the Performance Insights console experience; instances moved to the Standard mode of **CloudWatch Database Insights**. Whoever can read either sees your queries, and sometimes the literals in them.

**RDS Data API** (Aurora PostgreSQL and Aurora MySQL, serverless and provisioned) is an HTTPS endpoint you enable per cluster. A caller sends `rds-data:ExecuteStatement` with the cluster ARN and a **Secrets Manager secret ARN**; Data API fetches the secret on the caller's behalf. The caller therefore needs `rds-data:*` on the cluster and `secretsmanager:GetSecretValue` on the secret, and nothing at the network layer: a Lambda or a laptop outside the VPC can run SQL. Data API calls are CloudTrail **data events** (event source `rdsdataapi.amazonaws.com`), not logged unless you enable them, and the logged events mask the SQL text.

### DynamoDB

All DynamoDB access is IAM. Since **20 March 2024**, tables, indexes and streams can also carry a **resource-based policy** (up to 20 KB), which is how cross-account access is granted without role chaining. DynamoDB applies **Block Public Access** to those policies automatically: it uses automated reasoning to refuse any policy that would grant access to the public, unless conditions on keys such as `aws:PrincipalAccount`, `aws:PrincipalOrgID`, `aws:SourceVpc` or `aws:SourceVpce` (with fixed values) make it non-public. There is no setting to turn that off. IAM Access Analyzer reports external access granted by these policies. In February 2026 AWS added DynamoDB to the services covered by **resource control policies**.

**Fine-grained access control** is IAM conditions on items and attributes:

- `dynamodb:LeadingKeys` restricts items by partition key value, typically to `${cognito-identity.amazonaws.com:sub}` or another web identity variable so each user sees only their own rows. It must be used with `ForAllValues`, and **`ForAllValues` evaluates to true when the key is absent from the request**. `Scan` carries no partition key, so a policy that allows `Scan` with only a `LeadingKeys` condition allows the whole table. AWS's own guidance now adds a `Null` condition on `dynamodb:LeadingKeys` to close this.
- `dynamodb:Attributes`, `dynamodb:Select` and `dynamodb:ReturnValues` restrict which attributes can be read or returned. Attribute conditions are evaluated against the attributes **named in the request**, so a read without a projection returns everything unless the policy also requires `Select` = `SPECIFIC_ATTRIBUTES`, and writes can leak whole items through `ReturnValues` = `ALL_OLD` or `ALL_NEW`.

**Encryption at rest** is always on, with one of three keys: an AWS owned key (the default, invisible to you), the AWS managed key `aws/dynamodb`, or a customer managed key. Only the last lets you control and audit decryption through your own key policy.

**Recovery:** point-in-time recovery (PITR) is off by default; when on, the recovery period is configurable from 1 to 35 days (`RecoveryPeriodInDays`). Deletion protection is a per-table flag. Deleting a table with PITR enabled creates a system backup retained for 35 days.

**Exports to S3** need PITR, can be full or incremental, and can target a bucket **in another account and Region** (`--s3-bucket-owner`). For an attacker with `dynamodb:ExportTableToPointInTime`, that is a one-call exfiltration path that never touches the table's read capacity.

**Network:** DynamoDB is a public AWS endpoint. A gateway VPC endpoint (and, since 2024, interface endpoints) keep traffic private and let you write endpoint policies and `aws:SourceVpce` conditions. CloudTrail **data events** for DynamoDB (`AWS::DynamoDB::Table`) are off by default.

### ElastiCache and MemoryDB

ElastiCache (Valkey, Redis OSS, Memcached) and MemoryDB are VPC services; reachability is subnets and security groups. Authentication for Valkey and Redis OSS has three generations:

- **AUTH token**: one shared password, only with in-transit encryption enabled (Security Hub CSPM `ElastiCache.6` checks it for Redis OSS earlier than 6.0).
- **RBAC user groups** (Redis OSS 6 and later, Valkey): users with access strings such as `on ~app:* +@read`. The built-in `default` user ships with `on ~* +@all` and no password; if the user group still contains that `default` user, anyone who reaches the port has full access.
- **IAM authentication** (Valkey 7.2+, Redis OSS 7.0+): users with authentication mode `iam`; clients present a 15-minute SigV4 token; requires TLS; connections are cut after 12 hours. The IAM action is `elasticache:Connect` on both the cache and the user.

**In-transit encryption** can be `preferred` (accepts plaintext and TLS, a migration state) or `required`. At-rest encryption is set at creation. MemoryDB uses **ACLs** with the same user model; its default ACL, `open-access`, allows all.

### OpenSearch Service

AWS describes three layers:

1. **Network:** a domain is created with a **public endpoint** or **VPC access**, and cannot be switched later.
2. **Domain access policy:** a resource policy on `es:ESHttp*` actions. `"Principal": {"AWS": "*"}` with no condition on a public domain lets anyone on the internet send requests.
3. **Fine-grained access control (FGAC):** OpenSearch Security plugin roles, users and mappings, with index-, document- and field-level security. It requires HTTPS, node-to-node encryption and encryption at rest, and cannot be disabled once on. The master user is either an IAM ARN or a user in the **internal user database** (HTTP basic auth).

The combinations matter. AWS itself recommends, with FGAC on, a domain access policy that does not require signed requests, so "open policy" is not automatically a finding: on a domain with FGAC and strong credentials, the policy lets requests reach FGAC, which authenticates them. Without FGAC, an open policy on a public domain is an open database. Two more subtleties: when the master user is an IAM principal, OpenSearch ignores that principal's IAM permissions (anyone who can become that role is a cluster administrator), and enabling FGAC on an existing domain can turn on a 30-day **migration period** (`AnonymousAuthEnabled`) during which the old open or IP-based access keeps working.

### Redshift

Provisioned clusters and Serverless workgroups have a `PubliclyAccessible` flag, security groups, KMS encryption and a `require_ssl` parameter. AWS changed the defaults for **new provisioned clusters created after 10 January 2025** (and clusters restored from snapshots): public access off, encryption on, and a new default parameter group `default.redshift-2.0` with `require_ssl` set to true. Clusters created before then keep their settings. Snapshots are shared with specific accounts (`authorize-snapshot-access`, visible as `AccountsWithRestoreAccess`), and **datashares** grant live, cross-account read access to tables.

### DocumentDB

DocumentDB clusters are VPC-only (no public endpoint). The `tls` cluster parameter controls in-transit encryption (`enabled`, `tls1.2+`, `tls1.3+`, `fips-140-3`, or `disabled`), encryption at rest is set at creation, and manual cluster snapshots follow the RDS sharing model (public possible when unencrypted).

### Detection services

GuardDuty **RDS Protection** profiles login activity on supported Aurora and RDS engines and raises findings such as `CredentialAccess:RDS/AnomalousBehavior.SuccessfulBruteForce`, `CredentialAccess:RDS/MaliciousIPCaller.SuccessfulLogin` and, with its newer database activity monitoring, `Exfiltration:RDS/AnomalousBehavior` and `Impact:RDS/AnomalousBehavior.Drop`. Check the GuardDuty documentation for the current engine list. GuardDuty's foundational CloudTrail analysis covers control-plane calls for all of these services. Configuration of GuardDuty, Security Hub CSPM and Config is in the [detection and posture note](/cloud/aws-detection-posture-services/).

## What goes wrong

**Publicly accessible databases.** `PubliclyAccessible` true, a public subnet and a security group open to `0.0.0.0/0` (or to "the office" `/16` that now includes a cloud provider's range). Why it matters: the engine's authentication becomes the only control, and it is reachable by every brute-force bot, plus any engine vulnerability that predates the next maintenance window.

**Public or over-shared snapshots.** A manual snapshot with `restore` = `all`, or shared with an account nobody recognises: a former vendor, a test account that left the organisation, a typo. Why it matters: the receiving account restores the database, sets its own master password and reads everything, and the owner sees nothing in CloudTrail.

**Unencrypted storage, or encryption that is not a barrier.** Unencrypted instances (still possible on old estates) are the only ones whose snapshots can be made public. Encrypted ones are only as private as the KMS key policy: a customer managed key that grants `kms:Decrypt` and `kms:CreateGrant` to a partner account, or to the whole account with `kms:ViaService` only, makes sharing easy for anyone who can modify snapshot attributes. Why it matters: encryption is the control that blocks public sharing; key policy is the control that limits private sharing.

**Static master passwords in many places.** Master passwords in Terraform state, CloudFormation parameters without `NoEcho`, Lambda environment variables, CI variables and wiki pages, never rotated. Why it matters: the master user can do anything in the engine, and these stores are read by far more people and systems than the database.

**IAM database authentication with wildcards.** `rds-db:connect` on `dbuser:*/*`, or on the admin user's name, granted to application or developer roles. Why it matters: any principal with that permission connects as any IAM-enabled database user, including administrative ones, without knowing a password.

**TLS optional.** `rds.force_ssl` = 0 on older PostgreSQL, `require_secure_transport` off on MySQL, ElastiCache transit encryption `preferred` or off, Redshift `require_ssl` false on pre-2025 clusters, clients using `sslmode=prefer`. Why it matters: credentials and data cross the VPC (and any peered network, VPN or Direct Connect) in plaintext, and a client that does not verify certificates can be redirected.

**Control-plane paths to data.** Roles that can `ModifyDBInstance` (reset the master password), `CreateDBSnapshot` plus `ModifyDBSnapshotAttribute` (share to another account), `RestoreDBInstanceFromDBSnapshot` (restore a copy in a network they control), `StartExportTask` (export to S3), `ExportTableToPointInTime` (DynamoDB export to another account), or `secretsmanager:GetSecretValue` on master secrets. Why it matters: this is how data is stolen without ever touching the database port, and it is routinely granted to "developer" or "ops" roles that nobody thinks of as data readers.

**DynamoDB fine-grained access control written incorrectly.** `Scan` included with a `LeadingKeys` condition, no `Null` guard, attribute conditions without `Select` and `ReturnValues` restrictions, or an identity pool role with `dynamodb:*` on the table. Why it matters: the typical victim is a mobile app talking to DynamoDB directly with Cognito credentials, where one modified request reads every user's rows (see the [Cognito note](/cloud/aws-cognito-security/)).

**Cache and search clusters without authentication.** ElastiCache with the `default` user enabled, MemoryDB on `open-access`, OpenSearch domains with an open access policy and no FGAC, or FGAC with a weak internal master password. Why it matters: these stores hold session tokens, cached personal data, logs and search indexes of the main database, and are often treated as "just a cache".

**No recovery and no visibility.** Deletion protection off, backup retention zero, PITR off, no AWS Backup plan or no vault lock, no log exports, no Data API or DynamoDB data events. Why it matters: destructive attacks become permanent and data access cannot be scoped after an incident.

## Testing

All tests assume an **authorised** engagement against the client's own AWS accounts, with written scope, within the [AWS penetration testing policy](https://aws.amazon.com/security/penetration-testing/). They are read-only unless marked otherwise; no data is read from databases unless the client explicitly approves a specific proof. Command outputs below are **illustrative**, not captured from a real environment.

### Before you start

**Credentials.** A role with `SecurityAudit` and `ViewOnlyAccess` in each in-scope account. Between them they cover the `rds:Describe*`, `dynamodb:Describe*`/`List*`, `elasticache:Describe*`, `redshift:Describe*`, `es:Describe*` and `docdb` (RDS API) calls used here. `dynamodb:GetResourcePolicy`, `pi:*` read actions, `memorydb:Describe*` and `redshift-serverless:List*` may be missing in some versions of those policies; ask for them explicitly. You do not need, and should not ask for, `secretsmanager:GetSecretValue` or `rds-db:connect`.

**Network position.** For reachability tests, an approved external host with a fixed IP that the client knows about, and optionally a host inside the VPC (SSM Session Manager into a test instance) for TLS checks.

**Region loop and output folder.**

```bash
export AWS_PROFILE=client-audit
ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text)
REGIONS=$(aws ec2 describe-regions --query 'Regions[].RegionName' --output text)
mkdir -p db-review && cd db-review
for r in $REGIONS; do
  n=$(aws rds describe-db-instances --region "$r" --query 'length(DBInstances)' --output text 2>/dev/null)
  c=$(aws rds describe-db-clusters --region "$r" --query 'length(DBClusters)' --output text 2>/dev/null)
  t=$(aws dynamodb list-tables --region "$r" --query 'length(TableNames)' --output text 2>/dev/null)
  echo -e "$r\trds=$n\tclusters=$c\tddb=$t"
done | grep -v 'rds=0.*clusters=0.*ddb=0'
```

**Tools.** AWS CLI v2 and `jq`; [Prowler](https://github.com/prowler-cloud/prowler) (`prowler aws --service rds dynamodb elasticache redshift opensearch documentdb`); [ScoutSuite](https://github.com/nccgroup/ScoutSuite); [CloudFox](https://github.com/BishopFox/cloudfox) (`cloudfox aws databases`, `cloudfox aws resource-trusts`, `cloudfox aws endpoints`); [PMapper](https://github.com/nccgroup/PMapper) for "who can reach this data through IAM"; [Pacu](https://github.com/RhinoSecurityLabs/pacu) enumeration modules `rds__enum`, `rds__enum_snapshots` and `dynamodb__enum` (read-only; `rds__explore_snapshots` restores snapshots and is **lab only**). [CloudGoat](https://github.com/RhinoSecurityLabs/cloudgoat) includes RDS snapshot scenarios for practice.

### GT-AWS-DB-1: RDS and Aurora network exposure

*Guler Tech methodology.*

#### What it checks

Which RDS instances and Aurora cluster instances are reachable from the internet, combining `PubliclyAccessible`, subnet routing and security group rules, and confirming with a connection attempt from an approved external host.

#### Prerequisites

`rds:DescribeDBInstances`, `rds:DescribeDBSubnetGroups`, `ec2:DescribeSecurityGroups`, `ec2:DescribeRouteTables`; an approved external host for step 4.

#### Steps

1. Inventory the security-relevant fields:

   ```bash
   for r in $REGIONS; do
     aws rds describe-db-instances --region "$r" --output json --query 'DBInstances[].{
       id:DBInstanceIdentifier, engine:Engine, version:EngineVersion, cluster:DBClusterIdentifier,
       public:PubliclyAccessible, endpoint:Endpoint.Address, port:Endpoint.Port,
       subnetGroup:DBSubnetGroup.DBSubnetGroupName, vpc:DBSubnetGroup.VpcId,
       sgs:VpcSecurityGroups[].VpcSecurityGroupId, encrypted:StorageEncrypted, kms:KmsKeyId,
       iamAuth:IAMDatabaseAuthenticationEnabled, deletionProtection:DeletionProtection,
       backupDays:BackupRetentionPeriod, masterSecret:MasterUserSecret.SecretArn,
       logs:EnabledCloudwatchLogsExports, pi:PerformanceInsightsEnabled,
       paramGroups:DBParameterGroups[].DBParameterGroupName}' \
       | jq --arg r "$r" '.[] + {region:$r}'
   done | jq -s . > rds-instances.json
   jq -r '.[] | select(.public==true) | "\(.region)\t\(.id)\t\(.engine)\t\(.endpoint):\(.port)\t\(.sgs|join(","))"' rds-instances.json
   ```

2. For each public instance, the security group ingress on the database port:

   ```bash
   aws ec2 describe-security-groups --group-ids sg-0example1 --region eu-west-2 \
     | jq -r '.SecurityGroups[].IpPermissions[] | select(.FromPort<=5432 and .ToPort>=5432)
         | [.IpProtocol, .FromPort, .ToPort, ([.IpRanges[].CidrIp, .Ipv6Ranges[].CidrIpv6, .UserIdGroupPairs[].GroupId] | join(","))] | @tsv'
   ```

3. Subnet routing (instances not marked public can still sit in public subnets, which `RDS.46` flags):

   ```bash
   aws rds describe-db-subnet-groups --db-subnet-group-name example-db-subnets --region eu-west-2 \
     --query 'DBSubnetGroups[0].Subnets[].SubnetIdentifier' --output text
   aws ec2 describe-route-tables --region eu-west-2 \
     --filters Name=association.subnet-id,Values=subnet-0example1 \
     --query 'RouteTables[].Routes[?GatewayId!=null && starts_with(GatewayId, `igw-`)].[DestinationCidrBlock,GatewayId]' --output text
   ```

4. From the approved external host, resolve the endpoint and attempt a TCP connection only (no authentication attempts unless separately approved):

   ```bash
   dig +short example-db.abcdefexample.eu-west-2.rds.amazonaws.com
   nc -vz -w 5 example-db.abcdefexample.eu-west-2.rds.amazonaws.com 5432
   ```

#### Observation

Illustrative non-compliant result: `public: true`, a subnet with a `0.0.0.0/0` route to an internet gateway, an ingress rule `tcp 5432 5432 0.0.0.0/0`, the endpoint resolving to `203.0.113.40` and `nc` reporting the port open.

#### Evaluation

**Pass:** `PubliclyAccessible` false, subnets without internet gateway routes, and security groups that reference application security groups rather than CIDRs. **Fail:** reachable from the internet (all three conditions true and confirmed by step 4); rate by who can reach it: `0.0.0.0/0` is High (Critical if weak or default credentials, an unpatched engine, or IAM-only data is behind it); a narrow, known client range is Medium–Low with a recommendation to move behind a bastion, VPN or RDS Proxy. `PubliclyAccessible` true but a closed security group is a latent finding (Medium): one rule change exposes it.

#### Automated coverage

Security Hub CSPM `RDS.2` (CIS v3.0.0 2.3.3, v5.0.0 2.2.3), `RDS.46`, `RDS.23` (default port). Prowler `rds_instance_no_public_access`, `rds_instance_inside_vpc`, `rds_instance_non_default_port`. CloudFox `cloudfox aws databases`, `cloudfox aws endpoints`.

#### Detection

CloudTrail `ModifyDBInstance` with `publiclyAccessible` in `requestParameters`, `AuthorizeSecurityGroupIngress`, `CreateDBInstance`. GuardDuty `CredentialAccess:RDS/AnomalousBehavior.FailedLogin`, `CredentialAccess:RDS/MaliciousIPCaller.FailedLogin`, `Discovery:RDS/MaliciousIPCaller`, `CredentialAccess:RDS/AnomalousBehavior.SuccessfulBruteForce`.

### GT-AWS-DB-2: Public and cross-account DB snapshots

*Guler Tech methodology.*

#### What it checks

Every manual DB snapshot and DB cluster snapshot (RDS, Aurora, Neptune, DocumentDB) for public sharing and for sharing with accounts outside the client's organisation, plus snapshots shared **into** the client's accounts by others.

#### Prerequisites

`rds:DescribeDBSnapshots`, `rds:DescribeDBSnapshotAttributes`, `rds:DescribeDBClusterSnapshots`, `rds:DescribeDBClusterSnapshotAttributes`; the client's list of account IDs (from AWS Organizations) to classify recipients.

#### Steps

1. Instance snapshots:

   ```bash
   for r in $REGIONS; do
     for s in $(aws rds describe-db-snapshots --region "$r" --snapshot-type manual \
                  --query 'DBSnapshots[].DBSnapshotIdentifier' --output text); do
       v=$(aws rds describe-db-snapshot-attributes --region "$r" --db-snapshot-identifier "$s" \
            --query "DBSnapshotAttributesResult.DBSnapshotAttributes[?AttributeName=='restore'].AttributeValues[]" \
            --output text)
       [ -n "$v" ] && echo -e "$r\t$s\t$v"
     done
   done | tee shared-db-snapshots.tsv
   ```

2. Cluster snapshots (Aurora, DocumentDB and Neptune use the same API):

   ```bash
   for r in $REGIONS; do
     for s in $(aws rds describe-db-cluster-snapshots --region "$r" --snapshot-type manual \
                  --query 'DBClusterSnapshots[].DBClusterSnapshotIdentifier' --output text); do
       v=$(aws rds describe-db-cluster-snapshot-attributes --region "$r" --db-cluster-snapshot-identifier "$s" \
            --query "DBClusterSnapshotAttributesResult.DBClusterSnapshotAttributes[?AttributeName=='restore'].AttributeValues[]" \
            --output text)
       [ -n "$v" ] && echo -e "$r\t$s\t$v"
     done
   done | tee shared-cluster-snapshots.tsv
   ```

3. Classify each recipient: `all` (public), an account in the client's organisation, a known partner, or unknown. For each shared snapshot record encryption and key:

   ```bash
   aws rds describe-db-snapshots --region eu-west-2 --db-snapshot-identifier example-pre-migration \
     --query 'DBSnapshots[0].{created:SnapshotCreateTime,encrypted:Encrypted,kms:KmsKeyId,engine:Engine,master:MasterUsername}'
   ```

4. Inbound shares (snapshots others have shared with this account; restoring an unknown one into production is a supply-chain risk):

   ```bash
   aws rds describe-db-snapshots --region eu-west-2 --snapshot-type shared \
     --query 'DBSnapshots[].[DBSnapshotArn,SnapshotCreateTime]' --output text
   ```

Do not use `--include-public` to browse other organisations' public snapshots; it is out of scope.

#### Observation

Illustrative non-compliant line: `eu-west-2  example-pre-migration  all` on an unencrypted MySQL snapshot created three years ago.

#### Evaluation

**Fail (Critical):** any snapshot with `restore` = `all` that contains non-public data. Report it immediately; the client should remove the attribute, then treat the data as exposed for the period it was public, because copies and restores by other accounts are not logged in theirs. **Fail (High):** shared with an account outside the organisation that the client cannot identify or no longer has a relationship with. **Pass:** no public snapshots, cross-account shares only to the client's own backup or analytics accounts, documented. Note that encrypted snapshots cannot be public; finding only encrypted snapshots means `all` is impossible, not that sharing is controlled.

#### Automated coverage

Security Hub CSPM `RDS.1` (covers instance and cluster snapshots, including Neptune and DocumentDB; AWS notes the Config rule may take up to 12 hours to notice a change), `DocumentDB.3`. Prowler `rds_snapshots_public_access`, `documentdb_cluster_public_snapshot`, `neptune_cluster_public_snapshot`. Pacu `rds__enum_snapshots`.

#### Detection

CloudTrail `ModifyDBSnapshotAttribute` and `ModifyDBClusterSnapshotAttribute` with `attributeName` `restore` and `valuesToAdd`; `CopyDBSnapshot`, `CopyDBClusterSnapshot`, `CreateDBSnapshot`, `CreateDBClusterSnapshot`. An EventBridge rule on the first two with `valuesToAdd` containing `all` or a non-organisation account is cheap and high-signal.

### GT-AWS-DB-3: Encryption at rest and KMS key exposure

*Guler Tech methodology.*

#### What it checks

Which instances, clusters and snapshots are unencrypted, which use the AWS managed key versus customer managed keys, and whether customer managed key policies would let other accounts or broad roles decrypt snapshots shared with them.

#### Prerequisites

`rds:Describe*`, `kms:DescribeKey`, `kms:GetKeyPolicy`, `kms:ListGrants`.

#### Steps

1. Unencrypted resources:

   ```bash
   jq -r '.[] | select(.encrypted==false) | "\(.region)\t\(.id)\t\(.engine)"' rds-instances.json
   for r in $REGIONS; do
     aws rds describe-db-clusters --region "$r" \
       --query 'DBClusters[?StorageEncrypted==`false`].[DBClusterIdentifier,Engine]' --output text | sed "s/^/$r\t/"
     aws rds describe-db-snapshots --region "$r" --snapshot-type manual \
       --query 'DBSnapshots[?Encrypted==`false`].[DBSnapshotIdentifier,SnapshotCreateTime]' --output text | sed "s/^/$r\t/"
   done
   ```

2. Key type for each encrypted resource (`KeyManager` is `AWS` for `aws/rds`, `CUSTOMER` otherwise):

   ```bash
   aws kms describe-key --key-id arn:aws:kms:eu-west-2:111122223333:key/EXAMPLE-KEY-ID \
     --query 'KeyMetadata.{manager:KeyManager,state:KeyState,desc:Description}'
   ```

3. For customer managed keys, read the policy and grants for external principals and broad statements:

   ```bash
   aws kms get-key-policy --key-id arn:aws:kms:eu-west-2:111122223333:key/EXAMPLE-KEY-ID \
     --policy-name default --query Policy --output text \
     | jq '.Statement[] | {Sid, Principal, Action, Condition}'
   aws kms list-grants --key-id arn:aws:kms:eu-west-2:111122223333:key/EXAMPLE-KEY-ID \
     --query 'Grants[].{grantee:GranteePrincipal,ops:Operations}'
   ```

#### Observation

A list of unencrypted resources with their age, and for each customer managed key the principals outside the account that hold `kms:Decrypt`, `kms:CreateGrant` or `kms:ReEncrypt*`.

#### Evaluation

**Pass:** all storage encrypted; regulated or high-value data on customer managed keys whose policies grant use only to the account's RDS service path and named administrators, with cross-account grants limited to the client's backup account. **Fail:** unencrypted production instances or snapshots (Medium; the main risk is that their snapshots can be made public, so rate High if GT-AWS-DB-2 found any shared); a key policy that grants decrypt or grant creation to unknown external accounts (High). The AWS managed key on non-regulated data is acceptable and stops cross-account sharing entirely, which some clients prefer.

#### Automated coverage

Security Hub CSPM `RDS.3` (CIS v3.0.0 2.3.1, v1.4.0 2.3.1, v5.0.0 2.2.1), `RDS.4`, `RDS.27`, `DocumentDB.1`, `Redshift.10`, `Opensearch.1`, `ElastiCache.4`. Prowler `rds_instance_storage_encrypted`, `rds_cluster_storage_encrypted`, `rds_snapshots_encrypted`.

#### Detection

CloudTrail `PutKeyPolicy`, `CreateGrant` from unexpected principals, `CopyDBSnapshot` with a new `kmsKeyId`. Key policy design is covered in the [Secrets Manager, Parameter Store and KMS note](/cloud/aws-secrets-manager-parameter-store-kms/).

### GT-AWS-DB-4: Database authentication and transport encryption

*Guler Tech methodology.*

#### What it checks

How the master credential is managed, whether IAM database authentication is used and scoped, whether TLS is required by the server, and whether clients verify the server.

#### Prerequisites

`rds:DescribeDBInstances`, `rds:DescribeDBClusters`, `rds:DescribeDBParameters`, `rds:DescribeDBClusterParameters`, `iam:GetAccountAuthorizationDetails` (or PMapper data); read access to application configuration and IaC if in scope; optionally a test host inside the VPC.

#### Steps

1. Master credential management and IAM authentication:

   ```bash
   jq -r '.[] | "\(.region)\t\(.id)\tsecret=\(.masterSecret // "none")\tiamAuth=\(.iamAuth)"' rds-instances.json
   aws rds describe-db-clusters --region eu-west-2 \
     --query 'DBClusters[].{id:DBClusterIdentifier,secret:MasterUserSecret.SecretArn,iam:IAMDatabaseAuthenticationEnabled,dataApi:HttpEndpointEnabled}'
   ```

2. Who can connect through IAM, and as whom. Search all policies for `rds-db:connect` and read the resource ARNs:

   ```bash
   aws iam get-account-authorization-details --output json > iam-auth-details.json
   jq -r '.. | objects | select(has("Statement")) | .Statement[]? |
          select((.Action|tostring)|test("rds-db:connect|rds-db:\\*|\"\\*\"")) |
          [(.Action|tostring), (.Resource|tostring)] | @tsv' iam-auth-details.json | sort -u
   ```

   Treat `arn:aws:rds-db:*:*:dbuser:*/*` or a resource that names the admin user as a finding.
3. Server-side TLS enforcement in parameter groups:

   ```bash
   aws rds describe-db-parameters --db-parameter-group-name example-pg15 --region eu-west-2 \
     --query "Parameters[?ParameterName=='rds.force_ssl'].[ParameterName,ParameterValue,Source]" --output text
   aws rds describe-db-parameters --db-parameter-group-name example-mysql80 --region eu-west-2 \
     --query "Parameters[?ParameterName=='require_secure_transport'].[ParameterName,ParameterValue,Source]" --output text
   aws rds describe-db-cluster-parameters --db-cluster-parameter-group-name example-aurora-pg --region eu-west-2 \
     --query "Parameters[?ParameterName=='rds.force_ssl'].[ParameterValue]" --output text
   ```

   A `ParameterValue` of `None` means the engine default applies; resolve it from the engine version (on for PostgreSQL 15+, off for MySQL).
4. Client side: search application configuration and IaC for `sslmode=disable|prefer|require`, `useSSL=false`, `ssl-mode=DISABLED`, `rejectUnauthorized: false` and connection strings with embedded passwords. If you have an approved in-VPC host, confirm the server refuses plaintext:

   ```bash
   psql "host=example-db.abcdefexample.eu-west-2.rds.amazonaws.com dbname=postgres user=gt_probe sslmode=disable" -c 'select 1'
   ```

   A `no pg_hba.conf entry ... SSL off` error before the password prompt is the compliant result; it proves enforcement without credentials.
5. Hard-coded master passwords: search IaC, Terraform state access, CloudFormation templates (`MasterUserPassword` without `NoEcho` or a dynamic reference), Lambda environment variables (`aws lambda get-function-configuration --query Environment`), and CI variables for database passwords. Record locations; do not use any password you find.

#### Observation

Per instance: secret managed by RDS or not; IAM auth on or off and which roles can connect as which users; TLS required or optional; client verification mode where known.

#### Evaluation

**Pass:** master passwords managed by RDS in Secrets Manager (or an equivalent rotation process), with `GetSecretValue` on the master secret limited to break-glass roles; applications using their own least-privilege engine users or IAM auth scoped to specific users; TLS required on the server and `verify-full` (or equivalent) in clients. **Fail:** master passwords in code, state files or environment variables (High when reachable by broad groups, see [Secrets](/cloud/aws-secrets-manager-parameter-store-kms/)); `rds-db:connect` wildcards that include administrative users (High); TLS not required (Medium, raise to High when traffic crosses VPN, peering or Direct Connect links outside the client's control); applications connecting as the master user (Medium).

#### Automated coverage

Security Hub CSPM `RDS.10`, `RDS.12`, `RDS.38`, `RDS.39`, `RDS.41`, `RDS.44`, `RDS.43` (RDS Proxy TLS), `RDS.24`/`RDS.25` (custom admin username). Prowler `rds_instance_iam_authentication_enabled`, `rds_cluster_iam_authentication_enabled`, `rds_instance_transport_encrypted`, `rds_instance_default_admin`, `rds_cluster_default_admin`.

#### Detection

CloudTrail `ModifyDBInstance`/`ModifyDBCluster` with `masterUserPassword` (value redacted) or `manageMasterUserPassword` false, `ModifyDBParameterGroup` and `ModifyDBClusterParameterGroup` touching TLS parameters, `GetSecretValue` on `rds!` secrets by unexpected principals. GuardDuty RDS Protection login findings for credential misuse.

### GT-AWS-DB-5: Deletion protection, backups and recovery

*Guler Tech methodology.*

#### What it checks

Whether production databases can be deleted in one call, whether backups exist with a useful retention, and whether the principals that can delete databases can also delete their backups.

#### Prerequisites

`rds:Describe*`, `backup:ListBackupPlans`, `backup:ListProtectedResources`, `backup:DescribeBackupVault`; the client's view of which databases are production.

#### Steps

1. Flags per instance and cluster:

   ```bash
   jq -r '.[] | "\(.region)\t\(.id)\tdeletionProtection=\(.deletionProtection)\tbackupDays=\(.backupDays)"' rds-instances.json
   aws rds describe-db-clusters --region eu-west-2 \
     --query 'DBClusters[].{id:DBClusterIdentifier,del:DeletionProtection,backupDays:BackupRetentionPeriod,backtrack:BacktrackWindow}'
   ```

2. AWS Backup coverage and vault lock:

   ```bash
   aws backup list-protected-resources --region eu-west-2 \
     --query "Results[?ResourceType=='RDS' || ResourceType=='Aurora'].ResourceArn" --output text
   aws backup list-backup-vaults --region eu-west-2 \
     --query 'BackupVaultList[].{name:BackupVaultName,locked:Locked,minDays:MinRetentionDays}'
   ```

3. Who can destroy: simulate the operations roles against delete actions on production ARNs:

   ```bash
   aws iam simulate-principal-policy \
     --policy-source-arn arn:aws:iam::111122223333:role/platform-ops \
     --action-names rds:DeleteDBInstance rds:DeleteDBCluster rds:ModifyDBInstance rds:DeleteDBSnapshot \
                    rds:DeleteDBClusterSnapshot backup:DeleteRecoveryPoint backup:DeleteBackupVault \
     --query 'EvaluationResults[].[EvalActionName,EvalDecision]' --output table
   ```

#### Observation

A table of production databases with deletion protection, retention, AWS Backup coverage, vault lock status, and the roles able to delete both the database and its backups.

#### Evaluation

**Pass:** deletion protection on production instances and clusters, automated backups with retention matched to the recovery objective (7 days or more is a common floor), AWS Backup copies in a separate account or a locked vault, and no single day-to-day role able to delete the database, its snapshots and its recovery points. **Fail:** production with deletion protection off (Medium), backups disabled (`BackupRetentionPeriod` 0) on production (High), or one role able to delete everything including backups (High: a single compromised credential causes permanent loss).

#### Automated coverage

Security Hub CSPM `RDS.7`, `RDS.8`, `RDS.11`, `RDS.26`, `RDS.50`, `RDS.14` (backtracking). Prowler `rds_instance_deletion_protection`, `rds_cluster_deletion_protection`, `rds_instance_backup_enabled`, `rds_instance_protected_by_backup_plan`, `rds_cluster_protected_by_backup_plan`.

#### Detection

CloudTrail `DeleteDBInstance`, `DeleteDBCluster`, `ModifyDBInstance` with `deletionProtection` false or `backupRetentionPeriod` 0, `DeleteDBSnapshot`, `DeleteRecoveryPoint`. GuardDuty `Impact:RDS/AnomalousBehavior.Drop` and `Impact:RDS/AnomalousBehavior.Delete` cover destructive SQL on supported engines.

### GT-AWS-DB-6: Logging, Performance Insights and Data API visibility

*Guler Tech methodology.*

#### What it checks

Whether database activity is recorded where the security team can see it, whether logs and query telemetry leak sensitive data to people who should not have it, and whether the Data API is enabled and logged.

#### Prerequisites

`rds:Describe*`, `cloudtrail:GetEventSelectors`, `logs:DescribeLogGroups`, `pi:DescribeDimensionKeys` (read-only, to confirm what PI exposes, only with the client's approval).

#### Steps

1. Log exports and audit settings:

   ```bash
   jq -r '.[] | "\(.region)\t\(.id)\t\(.engine)\tlogs=\(.logs // [] | join(","))\tpi=\(.pi)"' rds-instances.json
   aws rds describe-db-parameters --db-parameter-group-name example-pg15 --region eu-west-2 \
     --query "Parameters[?ParameterName=='log_statement' || ParameterName=='pgaudit.log' || ParameterName=='log_min_duration_statement'].[ParameterName,ParameterValue]" --output text
   ```

2. Who can read those logs and Performance Insights or Database Insights data. Simulate the broad roles:

   ```bash
   aws iam simulate-principal-policy \
     --policy-source-arn arn:aws:iam::111122223333:role/developer \
     --action-names logs:GetLogEvents logs:StartQuery pi:GetResourceMetrics pi:DescribeDimensionKeys rds:DownloadDBLogFilePortion \
     --query 'EvaluationResults[].[EvalActionName,EvalDecision]' --output table
   ```

3. Data API state and CloudTrail data events for it:

   ```bash
   aws rds describe-db-clusters --region eu-west-2 --query 'DBClusters[?HttpEndpointEnabled==`true`].DBClusterIdentifier' --output text
   for t in $(aws cloudtrail describe-trails --query 'trailList[].TrailARN' --output text); do
     aws cloudtrail get-event-selectors --trail-name "$t" \
       | jq --arg t "$t" '{trail:$t, selectors:[.AdvancedEventSelectors[]? | select((.FieldSelectors|tostring)|test("AWS::RDS::DBCluster|AWS::DynamoDB::Table"))]}'
   done
   ```

#### Observation

Per production database: what is logged (connections, DDL, all statements), where it goes, who can read it; whether statement logging captures literals (passwords in `ALTER USER`, personal data in `WHERE` clauses); Data API enabled clusters and whether their calls are recorded.

#### Evaluation

**Pass:** connection and DDL auditing exported to CloudWatch Logs with restricted readers; full statement logging only where justified and with readers limited accordingly; Data API disabled where unused, and CloudTrail data events on for clusters where it is enabled. **Fail:** no engine logs at all on production (Medium); statement logs or PI data containing secrets or personal data readable by broad developer roles (Medium–High depending on content); Data API enabled with no data events (Medium: SQL can be run from anywhere with IAM credentials, unrecorded).

#### Automated coverage

Security Hub CSPM `RDS.9`, `RDS.34`, `RDS.36`, `RDS.37`, `RDS.40`, `RDS.42`, `RDS.45`, `RDS.6` (Enhanced Monitoring). Prowler `rds_instance_integration_cloudwatch_logs`, `rds_cluster_integration_cloudwatch_logs`, `rds_instance_enhanced_monitoring_enabled`.

#### Detection

CloudTrail `ModifyDBInstance` changing `cloudwatchLogsExportConfiguration`, `ModifyDBParameterGroup` changing logging parameters, `EnableHttpEndpoint`/`ModifyDBCluster` turning on the Data API; Data API data events (`ExecuteStatement`, `BatchExecuteStatement`) from unusual principals or IPs.

### GT-AWS-DB-7: IAM paths to database data

*Guler Tech methodology.*

#### What it checks

Which principals can obtain database data **through the AWS API** without network access or database credentials: master password reset, snapshot share or restore, export to S3, Data API with a readable secret, `rds-db:connect` wildcards and direct secret reads.

#### Prerequisites

PMapper graph of the account, or `iam:SimulatePrincipalPolicy` and `iam:GetAccountAuthorizationDetails`. A list of roles in scope (application, developer, operations, CI, third-party).

#### Steps

1. Simulate each role against the data-path actions:

   ```bash
   ACTIONS="rds:ModifyDBInstance rds:ModifyDBCluster rds:CreateDBSnapshot rds:CreateDBClusterSnapshot
   rds:CopyDBSnapshot rds:ModifyDBSnapshotAttribute rds:ModifyDBClusterSnapshotAttribute
   rds:RestoreDBInstanceFromDBSnapshot rds:RestoreDBClusterFromSnapshot rds:RestoreDBInstanceToPointInTime
   rds:StartExportTask rds-data:ExecuteStatement rds-db:connect secretsmanager:GetSecretValue
   dynamodb:Scan dynamodb:ExportTableToPointInTime dynamodb:PutResourcePolicy dynamodb:RestoreTableToPointInTime"
   for role in app-backend developer platform-ops ci-deploy vendor-support; do
     echo "== $role"
     aws iam simulate-principal-policy \
       --policy-source-arn "arn:aws:iam::111122223333:role/$role" \
       --action-names $ACTIONS \
       --query "EvaluationResults[?EvalDecision=='allowed'].EvalActionName" --output text
   done | tee data-paths.txt
   ```

2. Confirm with PMapper, which also follows role assumption chains:

   ```bash
   pmapper --account 111122223333 graph create
   pmapper --account 111122223333 query 'who can do rds:ModifyDBSnapshotAttribute with *'
   pmapper --account 111122223333 query 'who can do secretsmanager:GetSecretValue with arn:aws:secretsmanager:eu-west-2:111122223333:secret:rds!db-*'
   ```

3. For each allowed combination, write the chain explicitly: for example, `developer` can `CreateDBSnapshot` and `ModifyDBSnapshotAttribute` on production, and the snapshot is unencrypted, so a compromised developer credential shares production with any account. Check resource conditions (tags, ARNs) the simulator may not reflect, and SCPs that would block it.
4. **Benign proof, lab or explicitly approved only.** If the client wants proof beyond simulation, use a non-production copy: create a manual snapshot of a test database, share it with a client-owned test account, confirm it appears there with `describe-db-snapshots --snapshot-type shared`, then unshare and delete. Never share production data with any account you control.

#### Observation

A matrix of roles against data paths, with the chain for each "allowed" result and any guardrail that would stop it.

#### Evaluation

**Fail (High–Critical):** a role used by many people, by CI, or by a third party can reach production data through snapshot share or restore, export, master password reset, Data API with a readable secret, or `GetSecretValue` on master secrets. Critical when the role is reachable from the internet-facing workload (an application role) or from outside the organisation. **Pass:** these actions are limited to break-glass and backup roles, snapshot sharing is blocked by SCP outside the organisation, and exports go only to approved buckets. Escalation from these paths to wider account control is covered in the [privilege escalation note](/cloud/aws-iam-privilege-escalation/).

#### Automated coverage

None in Security Hub CSPM. PMapper and CloudFox (`cloudfox aws permissions`) support the analysis; Prowler's IAM checks flag some overly broad policies.

#### Detection

CloudTrail `ModifyDBInstance`/`ModifyDBCluster` with `masterUserPassword`, `ModifyDBSnapshotAttribute`, `ModifyDBClusterSnapshotAttribute`, `RestoreDBInstanceFromDBSnapshot`, `RestoreDBClusterFromSnapshot`, `StartExportTask`, `ExportTableToPointInTime`, `GetSecretValue` on `rds!` secrets. Alert on any of these from principals outside a short allow list.

### GT-AWS-DB-8: DynamoDB resource policies and fine-grained access control

*Guler Tech methodology.*

#### What it checks

DynamoDB resource-based policies for cross-account and broad access, IAM policies (especially Cognito identity pool roles) for fine-grained access control mistakes, and VPC endpoint conditions.

#### Prerequisites

`dynamodb:ListTables`, `dynamodb:GetResourcePolicy`, `dynamodb:DescribeTable`, IAM read access; for the application-level proof, test users at two privilege levels in the client's app (with approval).

#### Steps

1. Resource policies on tables and streams:

   ```bash
   for r in $REGIONS; do
     for t in $(aws dynamodb list-tables --region "$r" --query 'TableNames[]' --output text); do
       arn="arn:aws:dynamodb:$r:$ACCOUNT_ID:table/$t"
       p=$(aws dynamodb get-resource-policy --resource-arn "$arn" --region "$r" --query Policy --output text 2>/dev/null)
       [ -n "$p" ] && echo "$p" > "ddb-policy-$r-$t.json" && echo "policy: $r $t"
       s=$(aws dynamodb describe-table --table-name "$t" --region "$r" --query 'Table.LatestStreamArn' --output text)
       [ "$s" != "None" ] && aws dynamodb get-resource-policy --resource-arn "$s" --region "$r" \
            --query Policy --output text 2>/dev/null > "ddb-stream-policy-$r-$t.json"
     done
   done
   find . -name 'ddb-*policy-*.json' -size 0 -delete
   ```

2. Read each policy: principals (accounts, roles), actions (`dynamodb:*`, `Scan`, `PutItem`, `PutResourcePolicy`), and conditions. Cross-check with IAM Access Analyzer findings for `AWS::DynamoDB::Table` and `AWS::DynamoDB::Stream`.
3. Find IAM policies that grant DynamoDB access to federated or Cognito identities and read their conditions:

   ```bash
   jq -r '.RoleDetailList[] | select((.AssumeRolePolicyDocument|tostring)|test("cognito-identity.amazonaws.com")) | .RoleName' iam-auth-details.json
   jq '.RoleDetailList[] | select(.RoleName=="Cognito_ExampleAuth_Role") | .RolePolicyList[].PolicyDocument.Statement[]
       | select((.Action|tostring)|test("dynamodb"))' iam-auth-details.json
   ```

   Check for: `dynamodb:Scan` or `dynamodb:*` allowed alongside a `LeadingKeys` condition; `ForAllValues:StringEquals` on `dynamodb:LeadingKeys` without a `Null` condition; `dynamodb:Attributes` without `Select` and `ReturnValues` restrictions; tables named by wildcard.
4. Application proof (approved, test accounts only): with user A's Cognito credentials, call `Query` for user B's partition key and `Scan` on the table. Record the request IDs; stop at the first item that is not user A's.

   ```bash
   aws dynamodb scan --table-name ExampleUserData --max-items 1 --profile gt-user-a
   ```

#### Observation

Illustrative vulnerable statement:

```json
{
  "Effect": "Allow",
  "Action": ["dynamodb:GetItem", "dynamodb:Query", "dynamodb:Scan", "dynamodb:PutItem"],
  "Resource": "arn:aws:dynamodb:eu-west-2:111122223333:table/ExampleUserData",
  "Condition": {
    "ForAllValues:StringEquals": { "dynamodb:LeadingKeys": ["${cognito-identity.amazonaws.com:sub}"] }
  }
}
```

`Scan` has no partition key, `ForAllValues` over an empty set is true, so any signed-in user can read every row.

#### Evaluation

**Fail (Critical):** an app user can read or write other users' items (confirmed in step 4) or an identity pool role grants table-wide access; unauthenticated identity pool roles with any DynamoDB data access to user data. **Fail (High):** a resource policy granting an external account broad data or `PutResourcePolicy` access without business justification. **Pass:** per-user conditions with `Null` guard, no `Scan`, attribute controls complete, resource policies limited to named principals in known accounts, and `aws:SourceVpce` conditions where tables should only be reached from the VPC.

#### Automated coverage

Prowler `dynamodb_table_cross_account_access`. No Security Hub CSPM control evaluates DynamoDB resource policies or fine-grained conditions at the time of writing; IAM Access Analyzer covers external access.

#### Detection

CloudTrail `PutResourcePolicy`, `DeleteResourcePolicy` (management events). Item-level reads (`Scan`, `Query`, `GetItem`) need DynamoDB data events, which are off by default; without them a fine-grained access control bypass leaves no AWS-side trace.

### GT-AWS-DB-9: DynamoDB encryption, PITR, deletion protection and exports

*Guler Tech methodology.*

#### What it checks

The key type protecting each table, recovery settings, deletion protection, and existing or possible exports to S3, including to other accounts.

#### Prerequisites

`dynamodb:DescribeTable`, `dynamodb:DescribeContinuousBackups`, `dynamodb:ListExports`, `dynamodb:DescribeExport`.

#### Steps

1. Per table:

   ```bash
   for r in $REGIONS; do
     for t in $(aws dynamodb list-tables --region "$r" --query 'TableNames[]' --output text); do
       d=$(aws dynamodb describe-table --table-name "$t" --region "$r" \
            --query 'Table.{sse:SSEDescription.SSEType,key:SSEDescription.KMSMasterKeyArn,del:DeletionProtectionEnabled}' --output json)
       p=$(aws dynamodb describe-continuous-backups --table-name "$t" --region "$r" \
            --query 'ContinuousBackupsDescription.PointInTimeRecoveryDescription.{pitr:PointInTimeRecoveryStatus,days:RecoveryPeriodInDays}' --output json)
       echo "$d $p" | jq -s --arg t "$t" --arg r "$r" 'add + {table:$t, region:$r}'
     done
   done | jq -s . > ddb-tables.json
   jq -r '.[] | "\(.region)\t\(.table)\tsse=\(.sse // "AWS_OWNED")\tdel=\(.del)\tpitr=\(.pitr)/\(.days)"' ddb-tables.json
   ```

   An absent `SSEDescription` normally means the AWS owned key. `ContinuousBackupsStatus` is always `ENABLED`; read `PointInTimeRecoveryStatus`.
2. Past exports and their destinations:

   ```bash
   aws dynamodb list-exports --region eu-west-2 --query 'ExportSummaries[].ExportArn' --output text \
     | tr '\t' '\n' | while read -r e; do
       aws dynamodb describe-export --export-arn "$e" --region eu-west-2 \
         --query 'ExportDescription.{table:TableArn,bucket:S3Bucket,owner:S3BucketOwner,time:ExportTime,status:ExportStatus}'
     done
   ```

3. Who can export (from GT-AWS-DB-7) and whether an SCP or RCP limits export destinations.

#### Observation

Per table: key type, PITR status and window, deletion protection; a list of exports with destination bucket and bucket owner account.

#### Evaluation

**Pass:** PITR on for tables that cannot be rebuilt, with a window matching the recovery objective; deletion protection on production tables; customer managed keys where the client must control or audit decryption; exports only to client-owned buckets. **Fail:** production tables without PITR or deletion protection (Medium); exports to a bucket owned by an account outside the organisation (High, escalate as a possible incident); broad roles with `ExportTableToPointInTime` (rated in GT-AWS-DB-7).

#### Automated coverage

Security Hub CSPM `DynamoDB.2`, `DynamoDB.4`, `DynamoDB.6`, `DynamoDB.3` and `DynamoDB.7` (DAX). Prowler `dynamodb_tables_pitr_enabled`, `dynamodb_table_deletion_protection_enabled`, `dynamodb_tables_kms_cmk_encryption_enabled`, `dynamodb_table_protected_by_backup_plan`.

#### Detection

CloudTrail `ExportTableToPointInTime` (watch `s3BucketOwner`), `UpdateContinuousBackups` disabling PITR, `UpdateTable` disabling deletion protection, `DeleteTable`, `DeleteBackup`.

### GT-AWS-DB-10: ElastiCache and MemoryDB authentication and encryption

*Guler Tech methodology.*

#### What it checks

Whether caches require authentication, which users and access strings exist, whether the default user is still active, and whether transit and at-rest encryption are on.

#### Prerequisites

`elasticache:Describe*`, `memorydb:Describe*`; optionally an approved in-VPC host with `valkey-cli` or `redis-cli`.

#### Steps

1. Replication groups and serverless caches:

   ```bash
   aws elasticache describe-replication-groups --region eu-west-2 --query 'ReplicationGroups[].{
       id:ReplicationGroupId, transit:TransitEncryptionEnabled, mode:TransitEncryptionMode,
       rest:AtRestEncryptionEnabled, authToken:AuthTokenEnabled, userGroups:UserGroupIds}'
   aws elasticache describe-serverless-caches --region eu-west-2 \
     --query 'ServerlessCaches[].{name:ServerlessCacheName,userGroup:UserGroupId,sgs:SecurityGroupIds}'
   aws elasticache describe-cache-clusters --region eu-west-2 \
     --query "CacheClusters[?Engine=='memcached'].[CacheClusterId,TransitEncryptionEnabled,SecurityGroups[].SecurityGroupId]" --output text
   ```

2. Users and user groups:

   ```bash
   aws elasticache describe-user-groups --region eu-west-2 --query 'UserGroups[].{id:UserGroupId,users:UserIds}'
   aws elasticache describe-users --region eu-west-2 \
     --query 'Users[].{id:UserId,name:UserName,auth:Authentication.Type,access:AccessString,status:Status}'
   ```

   Flag any group containing a user with `auth` = `no-password` and an access string of `on ~* +@all` (the stock `default` user).
3. MemoryDB:

   ```bash
   aws memorydb describe-clusters --region eu-west-2 --query 'Clusters[].{name:Name,tls:TLSEnabled,acl:ACLName}'
   aws memorydb describe-acls --region eu-west-2 --query 'ACLs[].{name:Name,users:UserNames}'
   ```

4. Optional, approved in-VPC check: connect without credentials and run only `PING`:

   ```bash
   valkey-cli -h master.example-cache.abcdef.euw2.cache.amazonaws.com -p 6379 --tls PING
   ```

   `NOAUTH Authentication required` is the compliant answer; `PONG` proves unauthenticated access. Do not run `KEYS`, `GET` or anything else.

#### Observation

Per cache: auth mechanism (none, token, RBAC, IAM), whether the default user is active, transit mode (`required`, `preferred`, off), at-rest encryption.

#### Evaluation

**Fail (High):** no authentication or the open default user, on a cache that holds sessions, tokens or personal data (Critical if the cache's security group is reachable from broad networks); MemoryDB clusters on `open-access`. **Fail (Medium):** transit encryption off or `preferred` long after a migration; AUTH token in application config without rotation. **Pass:** RBAC or IAM authentication with least-privilege access strings, default user disabled or removed from groups, transit encryption `required`, at-rest encryption on. Memcached has no user authentication in this model; it must be isolated by security groups and should not hold sensitive data.

#### Automated coverage

Security Hub CSPM `ElastiCache.4`, `ElastiCache.5`, `ElastiCache.6`, `ElastiCache.7`. Prowler `elasticache_redis_replication_group_auth_enabled`, `elasticache_redis_cluster_in_transit_encryption_enabled`, `elasticache_redis_cluster_rest_encryption_enabled`, `elasticache_cluster_uses_public_subnet`, `memorydb_cluster_in_transit_encryption_enabled`.

#### Detection

CloudTrail `ModifyReplicationGroup` (auth or transit changes), `CreateUser`, `ModifyUser`, `ModifyUserGroup`, `ModifyServerlessCache`; for MemoryDB, `UpdateCluster`, `UpdateACL`. Engine-level access is not in CloudTrail.

### GT-AWS-DB-11: OpenSearch Service domain access

*Guler Tech methodology.*

#### What it checks

For each OpenSearch Service domain: endpoint type, domain access policy, fine-grained access control and master user type, anonymous access, and HTTPS and TLS policy.

#### Prerequisites

`es:ListDomainNames`, `es:DescribeDomain` (CLI `aws opensearch`); an approved external host for a single unauthenticated request to client-owned public endpoints.

#### Steps

1. Domain configuration:

   ```bash
   for d in $(aws opensearch list-domain-names --region eu-west-2 --query 'DomainNames[].DomainName' --output text); do
     aws opensearch describe-domain --domain-name "$d" --region eu-west-2 --query 'DomainStatus.{
       name:DomainName, publicEndpoint:Endpoint, vpcEndpoints:Endpoints,
       fgac:AdvancedSecurityOptions.Enabled, internalDb:AdvancedSecurityOptions.InternalUserDatabaseEnabled,
       anonymous:AdvancedSecurityOptions.AnonymousAuthEnabled, https:DomainEndpointOptions.EnforceHTTPS,
       tls:DomainEndpointOptions.TLSSecurityPolicy, n2n:NodeToNodeEncryptionOptions.Enabled,
       rest:EncryptionAtRestOptions.Enabled, policy:AccessPolicies}' > "os-$d.json"
   done
   ```

2. Analyse the access policy for wildcard principals without conditions:

   ```bash
   for f in os-*.json; do
     jq -r --arg f "$f" '(.policy | fromjson).Statement[]
       | select(.Effect=="Allow")
       | select((.Principal=="*") or (.Principal.AWS=="*") or ((.Principal.AWS|type)=="array" and (.Principal.AWS|index("*"))))
       | "\($f)\t\(.Action|tostring)\tcondition=\(.Condition // "none"|tostring)"' "$f"
   done
   ```

3. From the approved external host, a single unauthenticated request to each **client-owned public** endpoint, reading only cluster metadata:

   ```bash
   curl -s -o /dev/null -w '%{http_code}\n' "https://search-example-logs-abcdefexample.eu-west-2.es.amazonaws.com/"
   ```

   `200` with a cluster banner means anonymous access; `401` means FGAC is asking for credentials; `403` with `not authorized` means the access policy denied the request.

#### Observation

Illustrative non-compliant domain: `publicEndpoint` set, `fgac: false`, policy statement `{"Principal":{"AWS":"*"},"Action":"es:*"}` with no condition, `curl` returning `200`.

#### Evaluation

**Fail (Critical):** a public endpoint that accepts unauthenticated requests (open policy without FGAC, or `AnonymousAuthEnabled` still true after migration) on a domain holding logs, documents or user data. **Fail (High):** public endpoint with only an IP-based policy covering broad ranges and no FGAC; FGAC with an internal master user whose password is shared or weak; an IAM master role assumable by broad principals. **Fail (Medium):** HTTPS not enforced or an old TLS policy, node-to-node or at-rest encryption off. **Pass:** VPC access, or a public endpoint with FGAC, SAML or Cognito for Dashboards, mapped least-privilege roles, and a TLS 1.2+ policy. An open domain access policy with FGAC enabled and properly configured is AWS's documented pattern, not a finding by itself.

#### Automated coverage

Security Hub CSPM `Opensearch.1`, `Opensearch.2`, `Opensearch.3`, `Opensearch.4`, `Opensearch.5`, `Opensearch.7`, `Opensearch.8`, `Opensearch.10`. Prowler `opensearch_service_domains_not_publicly_accessible`, `opensearch_service_domains_access_control_enabled`, `opensearch_service_domains_internal_user_database_enabled`, `opensearch_service_domains_https_communications_enforced`, `opensearch_service_domains_audit_logging_enabled`.

#### Detection

CloudTrail `UpdateDomainConfig` (access policy, advanced security options), `CreateDomain`. Request-level access is visible only through OpenSearch audit logs (`Opensearch.5`) published to CloudWatch Logs.

### GT-AWS-DB-12: Redshift and DocumentDB exposure and snapshot sharing

*Guler Tech methodology.*

#### What it checks

Redshift provisioned clusters and Serverless workgroups for public access, encryption, TLS and snapshot sharing; datashares to other accounts; DocumentDB clusters for TLS, encryption and public snapshots.

#### Prerequisites

`redshift:Describe*`, `redshift-serverless:List*`/`Get*`, `rds:Describe*` (DocumentDB uses the RDS API, also available as `aws docdb`).

#### Steps

1. Redshift clusters and Serverless workgroups:

   ```bash
   aws redshift describe-clusters --region eu-west-2 --query 'Clusters[].{
       id:ClusterIdentifier, public:PubliclyAccessible, encrypted:Encrypted, kms:KmsKeyId,
       endpoint:Endpoint.Address, params:ClusterParameterGroups[].ParameterGroupName,
       enhancedVpcRouting:EnhancedVpcRouting, created:ClusterCreateTime}'
   aws redshift describe-cluster-parameters --parameter-group-name example-redshift-params --region eu-west-2 \
     --query "Parameters[?ParameterName=='require_ssl'].[ParameterValue]" --output text
   aws redshift-serverless list-workgroups --region eu-west-2 \
     --query 'workgroups[].{name:workgroupName,public:publiclyAccessible,sgs:securityGroupIds}'
   ```

2. Snapshot sharing and datashares:

   ```bash
   aws redshift describe-cluster-snapshots --region eu-west-2 --snapshot-type manual \
     --query 'Snapshots[?AccountsWithRestoreAccess!=null].{id:SnapshotIdentifier,accounts:AccountsWithRestoreAccess[].AccountId,enc:Encrypted}'
   aws redshift describe-data-shares --region eu-west-2 \
     --query 'DataShares[].{arn:DataShareArn,consumers:DataShareAssociations[].ConsumerIdentifier}'
   ```

3. DocumentDB:

   ```bash
   aws docdb describe-db-clusters --region eu-west-2 --query "DBClusters[?Engine=='docdb'].{
       id:DBClusterIdentifier, enc:StorageEncrypted, del:DeletionProtection,
       params:DBClusterParameterGroup, logs:EnabledCloudwatchLogsExports, backupDays:BackupRetentionPeriod}"
   aws docdb describe-db-cluster-parameters --db-cluster-parameter-group-name example-docdb-params --region eu-west-2 \
     --query "Parameters[?ParameterName=='tls' || ParameterName=='audit_logs'].[ParameterName,ParameterValue]" --output text
   ```

   DocumentDB cluster snapshots are covered by step 2 of GT-AWS-DB-2.

#### Observation

Per Redshift cluster: public flag, encryption, `require_ssl`, creation date (before or after the January 2025 default change), snapshot recipients and datashare consumers. Per DocumentDB cluster: TLS parameter, encryption, audit logging, deletion protection.

#### Evaluation

**Fail (High):** a Redshift cluster or workgroup publicly accessible with a security group open to the internet (Critical with default admin username `awsuser` and a weak password, or when it holds personal data); snapshots or datashares to accounts the client cannot identify. **Fail (Medium):** `require_ssl` false, unencrypted clusters (older estates), DocumentDB `tls` set to `disabled` or `enabled` without a minimum version (Security Hub CSPM treats both as failing), audit logging off. **Pass:** private, encrypted, TLS required, shares only to known accounts in the organisation.

#### Automated coverage

Security Hub CSPM `Redshift.1`, `Redshift.2`, `Redshift.4`, `Redshift.8`, `Redshift.10`, `Redshift.15`, `DocumentDB.1` to `DocumentDB.6`. Prowler `redshift_cluster_public_access`, `redshift_cluster_in_transit_encryption_enabled`, `redshift_cluster_encrypted_at_rest`, `redshift_cluster_audit_logging`, `redshift_cluster_non_default_username`, `documentdb_cluster_storage_encrypted`, `documentdb_cluster_cloudwatch_log_export`.

#### Detection

CloudTrail `AuthorizeSnapshotAccess`, `ModifyCluster` (`publiclyAccessible`), `ModifyClusterParameterGroup`, `AuthorizeDataShare`, `AssociateDataShareConsumer`; for DocumentDB, `ModifyDBClusterSnapshotAttribute`, `ModifyDBClusterParameterGroup`.

## Hardening

**Keep databases private by construction.** Put DB subnet groups only in subnets without internet gateway routes, reference application security groups instead of CIDRs, and block public creation with an SCP:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyPublicRDS",
      "Effect": "Deny",
      "Action": ["rds:CreateDBInstance", "rds:CreateDBInstanceReadReplica", "rds:RestoreDBInstanceFromDBSnapshot",
                 "rds:RestoreDBInstanceFromS3", "rds:RestoreDBInstanceToPointInTime"],
      "Resource": "*",
      "Condition": { "Bool": { "rds:PubliclyAccessible": "true" } }
    },
    {
      "Sid": "DenyUnencryptedRDS",
      "Effect": "Deny",
      "Action": ["rds:CreateDBInstance", "rds:CreateDBCluster"],
      "Resource": "*",
      "Condition": { "Bool": { "rds:StorageEncrypted": "false" } }
    },
    {
      "Sid": "RequireManagedMasterPassword",
      "Effect": "Deny",
      "Action": ["rds:CreateDBInstance", "rds:CreateDBCluster"],
      "Resource": "*",
      "Condition": { "Bool": { "rds:ManageMasterUserPassword": "false" } }
    }
  ]
}
```

Check the condition keys against the current RDS service authorisation reference before deploying, and test against your IaC; some engines and features (for example, read replicas with managed passwords) have exceptions. At the time of writing `rds:PubliclyAccessible` is supported on create and restore actions but not on `rds:ModifyDBInstance`, so making an existing instance public is not blocked by this SCP: alert on `ModifyDBInstance` events with `publiclyAccessible` set to true, and restrict `rds:ModifyDBInstance` itself to platform roles.

**Stop snapshots leaving the organisation.** Use customer managed keys for production so snapshots cannot be public, and keep the key policy limited to your own accounts. Add an EventBridge rule on `ModifyDBSnapshotAttribute` and `ModifyDBClusterSnapshotAttribute`, and restrict the action itself to the backup role:

```json
{
  "Sid": "OnlyBackupRoleSharesSnapshots",
  "Effect": "Deny",
  "Action": ["rds:ModifyDBSnapshotAttribute", "rds:ModifyDBClusterSnapshotAttribute"],
  "Resource": "*",
  "Condition": { "ArnNotLike": { "aws:PrincipalArn": "arn:aws:iam::*:role/org-backup-operator" } }
}
```

**Terraform baseline for an RDS instance:**

```hcl
resource "aws_db_instance" "app" {
  identifier                          = "example-app-db"
  engine                              = "postgres"
  engine_version                      = "16"
  instance_class                      = "db.r6g.large"
  allocated_storage                   = 100
  db_subnet_group_name                = aws_db_subnet_group.private.name
  vpc_security_group_ids              = [aws_security_group.db.id]
  publicly_accessible                 = false
  storage_encrypted                   = true
  kms_key_id                          = aws_kms_key.rds.arn
  username                            = "app_admin"
  manage_master_user_password         = true
  iam_database_authentication_enabled = true
  deletion_protection                 = true
  backup_retention_period             = 14
  copy_tags_to_snapshot               = true
  enabled_cloudwatch_logs_exports     = ["postgresql"]
  parameter_group_name                = aws_db_parameter_group.pg16.name
  auto_minor_version_upgrade          = true
}

resource "aws_db_parameter_group" "pg16" {
  name   = "example-pg16"
  family = "postgres16"
  parameter {
    name  = "rds.force_ssl"
    value = "1"
  }
  parameter {
    name  = "log_connections"
    value = "1"
  }
}
```

**Scope IAM database authentication** to one database user per role:

```json
{
  "Effect": "Allow",
  "Action": "rds-db:connect",
  "Resource": "arn:aws:rds-db:eu-west-2:111122223333:dbuser:db-EXAMPLERESOURCEID/app_reader"
}
```

and never mark administrative engine users for IAM authentication unless only break-glass roles can connect as them.

**Restrict control-plane data paths.** Keep `rds:ModifyDBInstance` (password reset), snapshot creation and sharing, `rds:StartExportTask`, `rds-data:*`, `dynamodb:ExportTableToPointInTime` and `GetSecretValue` on `rds!` secrets out of developer and CI roles. Use permission boundaries for roles that teams create themselves. Limit DynamoDB exports to approved buckets with an RCP or SCP that denies `dynamodb:ExportTableToPointInTime` unless the destination is in the organisation (test the condition support for your Regions first), and deny `s3:PutObject` to buckets outside the organisation from the DynamoDB service path through your S3 data perimeter (see the [S3 note](/cloud/aws-s3-security/)).

**DynamoDB fine-grained access control done right:**

```json
{
  "Effect": "Allow",
  "Action": ["dynamodb:GetItem", "dynamodb:Query", "dynamodb:PutItem", "dynamodb:UpdateItem", "dynamodb:DeleteItem"],
  "Resource": "arn:aws:dynamodb:eu-west-2:111122223333:table/ExampleUserData",
  "Condition": {
    "ForAllValues:StringEquals": { "dynamodb:LeadingKeys": ["${cognito-identity.amazonaws.com:sub}"] },
    "Null": { "dynamodb:LeadingKeys": "false" },
    "StringEqualsIfExists": { "dynamodb:ReturnValues": ["NONE", "UPDATED_OLD", "UPDATED_NEW"] }
  }
}
```

No `Scan`, a `Null` guard, and restricted `ReturnValues`. The IAM service reference also lists a newer Boolean condition key, `dynamodb:FullTableScan`, for blocking full table scans; check the current DynamoDB documentation for its semantics before relying on it. Prefer an API layer over direct client access to tables for anything beyond simple per-user records.

**DynamoDB resilience:** PITR (`RecoveryPeriodInDays` matched to your recovery objective), deletion protection, AWS Backup copies to a separate account, and a customer managed key where you need to control decryption.

**Caches and search.** ElastiCache with RBAC or IAM authentication, the `default` user removed from user groups (or replaced with a disabled user named `default`), transit encryption `required`; MemoryDB ACLs other than `open-access`. OpenSearch domains in a VPC, FGAC on with SAML or Cognito for Dashboards, IAM master role assumable only by administrators, TLS policy `Policy-Min-TLS-1-2-PFS-2023-10` or later, audit logs to CloudWatch Logs.

**Redshift and DocumentDB.** Private clusters, encryption, `require_ssl` true (the `default.redshift-2.0` parameter group does this), non-default admin username, audit logging; DocumentDB `tls` set to `tls1.2+` or stronger and audit logs exported.

**Detection.** GuardDuty RDS Protection in every account and Region with supported engines; CloudTrail data events for the Data API and for DynamoDB tables with personal data; EventBridge rules for snapshot attribute changes, export tasks and master password changes; AWS Config rules behind the Security Hub CSPM controls listed above.

## Real-world cases

- **Public RDS snapshots leaking personal data (Mitiga, November 2022).** In a month-long scan (September to October 2022) Mitiga saw 2,783 publicly shared RDS snapshots, many of them public for weeks; samples they restored contained customer records, password hashes and access tokens. They also noted that copying or restoring a public snapshot leaves no log in the owner's account. [Oops, I Leaked It Again: How Mitiga Found PII in Exposed Amazon RDS Snapshots](https://www.mitiga.io/blog/how-mitiga-found-pii-in-exposed-amazon-rds-snapshots). This is the basis for GT-AWS-DB-2 and for rating any public snapshot as Critical regardless of how long it was public.
- **Redshift secure-by-default change (2025).** AWS changed the defaults for new Redshift provisioned clusters after 10 January 2025 to private, encrypted and TLS-required, after years of findings on publicly accessible warehouses. [Amazon Redshift enhances security by changing default behavior in 2025](https://aws.amazon.com/blogs/security/amazon-redshift-enhances-security-by-changing-default-behavior-in-2025/). For testers the lesson is the cut-off date: clusters created before it keep their old, often public, settings.

## Rating findings

| Finding | Typical severity | Reasoning |
|---|---|---|
| Public DB or cluster snapshot with non-public data | Critical | Any AWS account can restore and read it; copies are not logged in the owner's account, so exposure must be assumed. |
| OpenSearch public endpoint answering unauthenticated requests | Critical | Unauthenticated internet read and often write of indexed data. |
| App users can read other users' DynamoDB items (FGAC bypass confirmed) | Critical | Any registered user, often any app installer, reads every user's data; no AWS-side trace without data events. |
| Database reachable from the internet with weak, default or leaked credentials | Critical | Unauthenticated path to full engine access. |
| Database reachable from `0.0.0.0/0`, credentials not known to be weak | High | Internet brute force and engine vulnerabilities apply; one credential leak away from compromise. |
| Broad, CI or third-party roles with snapshot share/restore, export, password reset, Data API or master secret access | High–Critical | Data theft without network access; Critical when the role belongs to an internet-facing workload or an external party. |
| Snapshot, datashare or export to an unidentified external account | High (escalate) | Possible ongoing exfiltration; treat as an incident until explained. |
| ElastiCache/MemoryDB without authentication holding sessions or personal data | High | Anyone who reaches the port reads or alters sessions; Critical when the port is broadly reachable. |
| `rds-db:connect` wildcards covering administrative users | High | Any holder connects as an admin without a password. |
| Master passwords in code, state, environment variables or CI | High | The highest engine privilege, readable by many; Medium if only a small admin group can read the location. |
| Production backups disabled, or one role can delete database and all backups | High | A single credential causes permanent loss. |
| TLS not required by the server | Medium | Plaintext on internal paths; High when traffic crosses links outside the client's control. |
| Unencrypted production storage | Medium | Enables public snapshot sharing and fails most compliance regimes; High when combined with shared snapshots. |
| Deletion protection off on production; PITR off on DynamoDB tables that cannot be rebuilt | Medium | Destructive actions become one call; recovery depends on luck. |
| Data API enabled without data events; no engine logs on production | Medium | SQL and data access cannot be attributed after an incident. |
| Default admin usernames, default ports, Performance Insights readable by broad roles without sensitive SQL | Low | Hygiene; raise if query text exposes secrets or personal data. |

## Mapping

| Test | Security Hub CSPM | CIS AWS Foundations Benchmark | MITRE ATT&CK |
|---|---|---|---|
| GT-AWS-DB-1 | RDS.2, RDS.46, RDS.23 | v3.0.0 2.3.3; v5.0.0 2.2.3 | T1190, T1110, T1046 |
| GT-AWS-DB-2 | RDS.1, DocumentDB.3 | – | T1578.001, T1537 |
| GT-AWS-DB-3 | RDS.3, RDS.4, RDS.27 | v3.0.0 2.3.1; v1.4.0 2.3.1; v5.0.0 2.2.1 | T1537 |
| GT-AWS-DB-4 | RDS.10, RDS.12, RDS.38, RDS.39, RDS.41, RDS.43, RDS.44, RDS.24, RDS.25 | – | T1078.004, T1557, T1555.006 |
| GT-AWS-DB-5 | RDS.7, RDS.8, RDS.11, RDS.26, RDS.50 | – | T1485, T1490 |
| GT-AWS-DB-6 | RDS.9, RDS.34, RDS.36, RDS.37, RDS.40, RDS.42, RDS.45, RDS.6 | – | – (detection gap) |
| GT-AWS-DB-7 | – | – | T1098, T1578.001, T1537, T1555.006, T1213.006 |
| GT-AWS-DB-8 | – | – | T1213.006, T1078.004 |
| GT-AWS-DB-9 | DynamoDB.2, DynamoDB.4, DynamoDB.6 | – | T1537, T1485, T1490 |
| GT-AWS-DB-10 | ElastiCache.4, ElastiCache.5, ElastiCache.6, ElastiCache.7 | – | T1213.006, T1557 |
| GT-AWS-DB-11 | Opensearch.1, Opensearch.2, Opensearch.3, Opensearch.4, Opensearch.5, Opensearch.7, Opensearch.8 | – | T1190, T1213.006 |
| GT-AWS-DB-12 | Redshift.1, Redshift.2, Redshift.4, Redshift.8, Redshift.10, Redshift.15, DocumentDB.1–6 | – | T1190, T1537, T1557 |

CIS numbers are taken from the Security Hub CSPM control pages at the time of writing. `RDS.13` (automatic minor version upgrades, CIS v3.0.0 2.3.2) is part of patch management and not tested separately here. *Security Hub CSPM* is the name AWS gave the original Security Hub posture product in 2025, when it launched the new unified Security Hub; the control IDs did not change.

## References

- Amazon RDS API Reference: [CreateDBInstance](https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_CreateDBInstance.html) (`PubliclyAccessible` defaults)
- Amazon RDS User Guide: [Sharing a DB snapshot](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_ShareSnapshot.html)
- Amazon RDS User Guide: [Password management with Amazon RDS and AWS Secrets Manager](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/rds-secrets-manager.html)
- Amazon RDS User Guide: [Using SSL with a PostgreSQL DB instance](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/PostgreSQL.Concepts.General.SSL.html) and [Requiring SSL/TLS for all connections to a MySQL DB instance](https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/mysql-ssl-connections.require-ssl.html)
- Amazon Aurora User Guide: [Using the Amazon RDS Data API](https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/data-api.html), [Authorizing access to the Data API](https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/data-api.access.html), [Logging Data API calls with CloudTrail](https://docs.aws.amazon.com/AmazonRDS/latest/AuroraUserGuide/logging-using-cloudtrail-data-api.html)
- Amazon CloudWatch User Guide: [CloudWatch Database Insights](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/Database-Insights.html)
- Amazon DynamoDB Developer Guide: [Using resource-based policies](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/access-control-resource-based.html), [Blocking public access with resource-based policies](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/rbac-bpa-rbp.html), [Using IAM policy conditions for fine-grained access control](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/specifying-conditions.html), [Point-in-time recovery](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/PointInTimeRecovery_Howitworks.html), [Export to Amazon S3](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/S3DataExport.HowItWorks.html)
- AWS What's New: [Amazon DynamoDB now supports resource-based policies](https://aws.amazon.com/about-aws/whats-new/2024/03/amazon-dynamodb-resource-based-policies/) (March 2024) and [AWS expands Resource Control Policies support to Amazon DynamoDB](https://aws.amazon.com/about-aws/whats-new/2026/02/aws-expands-resource-control-policies-amazon/) (February 2026)
- Amazon ElastiCache User Guide: [Authenticating with IAM](https://docs.aws.amazon.com/AmazonElastiCache/latest/dg/auth-iam.html)
- Amazon OpenSearch Service Developer Guide: [Fine-grained access control](https://docs.aws.amazon.com/opensearch-service/latest/developerguide/fgac.html)
- AWS Security Blog: [Amazon Redshift enhances security by changing default behavior in 2025](https://aws.amazon.com/blogs/security/amazon-redshift-enhances-security-by-changing-default-behavior-in-2025/)
- AWS Security Hub User Guide: Security Hub CSPM controls for [RDS](https://docs.aws.amazon.com/securityhub/latest/userguide/rds-controls.html), [DynamoDB](https://docs.aws.amazon.com/securityhub/latest/userguide/dynamodb-controls.html), [ElastiCache](https://docs.aws.amazon.com/securityhub/latest/userguide/elasticache-controls.html), [Redshift](https://docs.aws.amazon.com/securityhub/latest/userguide/redshift-controls.html), [OpenSearch](https://docs.aws.amazon.com/securityhub/latest/userguide/opensearch-controls.html), [DocumentDB](https://docs.aws.amazon.com/securityhub/latest/userguide/documentdb-controls.html)
- Amazon GuardDuty User Guide: [RDS Protection finding types](https://docs.aws.amazon.com/guardduty/latest/ug/findings-rds-protection.html)
- Mitiga: [Oops, I Leaked It Again: How Mitiga Found PII in Exposed Amazon RDS Snapshots](https://www.mitiga.io/blog/how-mitiga-found-pii-in-exposed-amazon-rds-snapshots)
- MITRE ATT&CK: [T1213.006 Databases](https://attack.mitre.org/techniques/T1213/006/), [T1537 Transfer Data to Cloud Account](https://attack.mitre.org/techniques/T1537/), [T1578.001 Create Snapshot](https://attack.mitre.org/techniques/T1578/001/), [T1098 Account Manipulation](https://attack.mitre.org/techniques/T1098/), [T1555.006 Cloud Secrets Management Stores](https://attack.mitre.org/techniques/T1555/006/), [T1078.004 Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/), [T1110 Brute Force](https://attack.mitre.org/techniques/T1110/), [T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/), [T1557 Adversary-in-the-Middle](https://attack.mitre.org/techniques/T1557/), [T1485 Data Destruction](https://attack.mitre.org/techniques/T1485/), [T1490 Inhibit System Recovery](https://attack.mitre.org/techniques/T1490/)
- Tools: [Prowler](https://github.com/prowler-cloud/prowler), [ScoutSuite](https://github.com/nccgroup/ScoutSuite), [CloudFox](https://github.com/BishopFox/cloudfox), [PMapper](https://github.com/nccgroup/PMapper), [Pacu](https://github.com/RhinoSecurityLabs/pacu), [CloudGoat](https://github.com/RhinoSecurityLabs/cloudgoat)
- Related notes: [AWS security testing guide](/cloud/aws-security-testing-guide/), [IAM privilege escalation](/cloud/aws-iam-privilege-escalation/), [Cognito](/cloud/aws-cognito-security/), [Secrets Manager, Parameter Store and KMS](/cloud/aws-secrets-manager-parameter-store-kms/), [VPC, edge and DNS](/cloud/aws-vpc-edge-dns-security/), [detection and posture services](/cloud/aws-detection-posture-services/)
