---
title: "AWS Lambda and Serverless Security"
date: 2026-11-12 18:07:00 +0000
subcategory: aws
summary: "Reviewing Lambda for public invoke paths, function URLs, secrets in env vars and code, layers, over-privileged roles, event injection and runtimes."
refs: [Lambda.1, Lambda.2, Lambda.3, Lambda.5, CloudFront.16, StepFunctions.1, T1648, T1190, T1078.004, T1552, T1552.001, T1195.002, T1059, T1496.001, T1499.003]
tags: [aws, lambda, serverless, function-urls, event-injection, step-functions]
---

This note is part of our [AWS security testing guide](/cloud/aws-security-testing-guide/) and covers AWS Lambda from a reviewer's point of view, with short sections on Lambda@Edge, CloudFront Functions and Step Functions. Lambda looks small from the outside: a handler, a role, a trigger. In practice every function sits at the junction of two policies (the execution role that decides what the code can do, and the resource-based policy that decides who can make the code run), carries configuration that often holds secrets, and receives events whose content an attacker frequently controls. Most serious Lambda findings are not bugs in Lambda. They are a public invoke permission nobody meant to grant, a database password in an environment variable readable by every `ViewOnlyAccess` user, a function with `AdministratorAccess` that shells out with an S3 object key, or a role that lets a developer replace the code of a function that runs as something more powerful than they are. Below is how the security model works, what goes wrong, twelve tests with commands, the guardrails that fix it, and how to rate what you find.

## Contents

- [How it works](#how-it-works)
- [What goes wrong](#what-goes-wrong)
- [Testing](#testing)
  - [Before you start](#before-you-start)
  - [GT-AWS-LAMBDA-1: Public or unconstrained function resource policies](#gt-aws-lambda-1-public-or-unconstrained-function-resource-policies)
  - [GT-AWS-LAMBDA-2: Function URLs with AuthType NONE and permissive CORS](#gt-aws-lambda-2-function-urls-with-authtype-none-and-permissive-cors)
  - [GT-AWS-LAMBDA-3: Secrets in environment variables and who can read them](#gt-aws-lambda-3-secrets-in-environment-variables-and-who-can-read-them)
  - [GT-AWS-LAMBDA-4: Who can download function code, and what is in it](#gt-aws-lambda-4-who-can-download-function-code-and-what-is-in-it)
  - [GT-AWS-LAMBDA-5: Layer sharing and third-party layers](#gt-aws-lambda-5-layer-sharing-and-third-party-layers)
  - [GT-AWS-LAMBDA-6: Execution role over-privilege](#gt-aws-lambda-6-execution-role-over-privilege)
  - [GT-AWS-LAMBDA-7: Deployment integrity, code signing and who can change code](#gt-aws-lambda-7-deployment-integrity-code-signing-and-who-can-change-code)
  - [GT-AWS-LAMBDA-8: Deprecated runtimes and pinned runtime versions](#gt-aws-lambda-8-deprecated-runtimes-and-pinned-runtime-versions)
  - [GT-AWS-LAMBDA-9: Event sources, event injection and execution environment state](#gt-aws-lambda-9-event-sources-event-injection-and-execution-environment-state)
  - [GT-AWS-LAMBDA-10: Concurrency, recursion and denial of wallet](#gt-aws-lambda-10-concurrency-recursion-and-denial-of-wallet)
  - [GT-AWS-LAMBDA-11: Network placement and egress](#gt-aws-lambda-11-network-placement-and-egress)
  - [GT-AWS-LAMBDA-12: Step Functions and edge functions](#gt-aws-lambda-12-step-functions-and-edge-functions)
- [Hardening](#hardening)
- [Real-world cases](#real-world-cases)
- [Rating findings](#rating-findings)
- [Mapping](#mapping)
- [References](#references)

## How it works

### Two policies per function

Every Lambda function has two independent authorisation surfaces, and you need to review both.

**The execution role** is an IAM role that trusts `lambda.amazonaws.com`. Lambda assumes it and hands the temporary credentials to the runtime as the reserved environment variables `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` and `AWS_SESSION_TOKEN`. Anything the code can be made to do (by a bug, an injected command, a malicious dependency) it does with those credentials. A function's blast radius is its role. The role is also shared with everything else in the execution environment: extensions and layer code run in the same sandbox and see the same credentials and environment.

**The resource-based policy** (the "function policy") says who may call Lambda API actions on the function, most importantly `lambda:InvokeFunction`. It is how S3, SNS, EventBridge, API Gateway and other services get permission to trigger a function, and how other accounts get to call it. It can be built statement by statement with `AddPermission` (which supports only `aws:SourceArn`, `aws:SourceAccount` and `aws:PrincipalOrgID` conditions) or, at the time of writing, replaced wholesale with a full JSON document through the newer `PutResourcePolicy` API, which supports the full condition language and explicit `Deny`. Policies can be attached to the unqualified function **and separately to versions and aliases**, which matters when you enumerate them.

Three properties of the resource policy cause most findings:

- `"Principal": "*"` without a restricting condition makes the function invocable by any AWS principal in any account. Security Hub CSPM control **Lambda.1** (Critical) fails on this.
- A **service principal** statement (`s3.amazonaws.com`, `sns.amazonaws.com`, `events.amazonaws.com`, `apigateway.amazonaws.com`) without `aws:SourceArn` or `aws:SourceAccount` is a confused-deputy hole: any bucket, topic, rule or API in *any* account can be wired to invoke your function, because the service, not the attacker, makes the call. Lambda.1 also fails when an S3 invoke statement lacks `aws:SourceAccount`.
- Lambda.1 does not evaluate conditions containing wildcards or policy variables, so a policy with `"aws:SourceArn": "arn:aws:s3:::*"` may pass the control while being functionally open. Read the policy, not just the control result.

### Function URLs

A function URL is a dedicated HTTPS endpoint of the form `https://<url-id>.lambda-url.<region>.on.aws` attached to a function or alias. Its `AuthType` is either:

- `AWS_IAM`: callers must SigV4-sign requests, and IAM evaluates their identity policy and the function's resource policy (cross-account callers need both).
- `NONE`: Lambda performs no authentication, but the resource policy must still allow public access. When you create a `NONE` URL in the console or with AWS SAM, Lambda writes that public statement for you; with the CLI, CloudFormation or Terraform you add it yourself.

AWS changed the permission model in October 2025: new function URLs require **both** `lambda:InvokeFunctionUrl` and `lambda:InvokeFunction`, and the recommended statements scope `InvokeFunction` with the condition key `lambda:InvokedViaFunctionUrl` so the public grant cannot be used through the ordinary `Invoke` API. The default public policy AWS now documents has two statements, `Principal "*"` on `lambda:InvokeFunctionUrl` with `lambda:FunctionUrlAuthType = NONE`, and `Principal "*"` on `lambda:InvokeFunction` with `lambda:InvokedViaFunctionUrl = true`. A public `InvokeFunction` statement **without** that condition is broader than a function URL needs, because it also opens the regular Invoke API to every AWS account. Two more details: deleting a `NONE` URL does not remove the public policy statement, and CORS configured on the URL (`AllowOrigins`, `AllowCredentials`, `AllowHeaders`) is a browser read control, not authentication.

When a function URL is meant to sit behind CloudFront, the supported pattern is `AuthType AWS_IAM` plus CloudFront origin access control (OAC) signing requests to the URL. Security Hub CSPM **CloudFront.16** checks that distributions with function URL origins use OAC.

### Configuration, environment variables and code

Environment variables are part of the function configuration and are returned by `GetFunctionConfiguration`, `GetFunction` and **`ListFunctions`**. Lambda always encrypts them at rest with KMS, by default with the AWS managed key `aws/lambda`; with that default key no KMS permission is needed to read them, so **anyone who can list or describe functions sees the plaintext**. With a customer managed key (`KMSKeyArn`), a caller also needs `kms:Decrypt` on that key to see values. The optional "encryption helpers" encrypt individual values client-side, so they appear as ciphertext in the configuration and the function decrypts them at runtime. AWS's own guidance is to put database credentials in Secrets Manager rather than environment variables. Note which AWS managed policies reach this data: at the time of writing `ViewOnlyAccess` and `SecurityAudit` both grant `lambda:List*` (and `SecurityAudit` adds `lambda:GetFunctionConfiguration`), which is enough to read environment variables encrypted with the default key.

Function code is returned by `GetFunction`: the response includes `Code.Location`, a presigned URL to the deployment package that is **valid for 10 minutes**, or `Code.ImageUri` for container images (pulling the image then needs ECR permissions). `SecurityAudit` does not grant `lambda:GetFunction`; `ReadOnlyAccess` does, through `lambda:Get*`. So "read-only" users can usually download every function's source, including any keys hard-coded in it.

**Published versions are immutable snapshots**, including their environment variables. Rotating a secret in `$LATEST` leaves the old value readable in every published version until those versions are deleted. Enumerate with `--function-version ALL`.

### Layers

A layer is a .zip archive extracted into `/opt` in the execution environment. A function can use up to five layers, and layers are only for .zip-deployed functions (container images bundle their dependencies). Layer versions are immutable and each has its own resource policy, granted with `AddLayerVersionPermission` to one account, all accounts (`--principal '*'`) or an organisation (`--principal '*' --organization-id o-...`). Permissions apply to a single version. Anyone granted `lambda:GetLayerVersion` can attach the layer *and* download its content. Two risks follow: your layers leaking code or secrets to the world, and your functions running code from layers owned by accounts you do not control (a supply-chain dependency that can change only if the owner publishes a new version you then adopt, but which you cannot audit after the fact if they delete it).

### Execution environment and `/tmp`

Lambda runs each function in a Firecracker microVM-based execution environment and **reuses environments across invocations of the same function version**. After an invocation the environment is frozen and may be thawed for the next one. Global variables, open connections, background processes and the contents of `/tmp` (configurable from 512 MB to 10,240 MB) survive into later invocations, and AWS's documentation notes that even a reset after an invoke failure does not clear `/tmp`. Environments are not reused across different functions, but they are reused across *callers* of the same function, so per-user data cached in a global or in `/tmp` can leak to the next caller. AWS added a **tenant isolation mode** (configured at creation with `TenancyConfig`, immutable afterwards, invoked with a tenant identifier) that guarantees environments are never reused across tenants; at the time of writing it is not supported with function URLs, provisioned concurrency or SnapStart. SnapStart (Java, Python, .NET) restores many environments from one snapshot, so anything generated during init, such as random seeds or unique IDs, can be duplicated across environments unless the code regenerates it after restore.

### Runtimes and deprecation

Managed runtimes (for example `python3.13`, `nodejs22.x`, `java21`) are patched by AWS and, by default, updated automatically. When a runtime's language or OS reaches end of support, Lambda **deprecates** it: AWS may stop applying security patches, functions lose technical support, and later Lambda blocks function creation and then function updates (by default at least 30 and 60 days after deprecation, though AWS has pushed many recent block dates out to mid-2027). Deprecated functions **keep running and keep accepting invocations indefinitely**, which is why they linger. AWS notifies at least 180 days ahead through email, the Health Dashboard and Trusted Advisor. Container-image functions get no deprecation notifications at all, and patching the base image is your job. Security Hub CSPM **Lambda.2** (Medium) checks .zip functions against the current supported list and ignores `PackageType: Image`.

### Code signing

With AWS Signer you create a signing profile, sign deployment packages, and attach a **code signing configuration** (CSC) to functions. On deployment Lambda checks integrity, expiry, mismatch (signed by an allowed profile) and revocation. The CSC's `UntrustedArtifactOnDeployment` policy is `Warn` by default, which only logs; `Enforce` blocks. Integrity failures are always blocked. When a CSC is attached, layers must also be signed by an allowed profile. A CSC added to an existing function only affects new deployments. AWS's documentation now states that code signing applies to both .zip and container-image Event Functions (historically it was .zip only), so check the current docs for your packaging model. The IAM condition key `lambda:CodeSigningConfigArn` lets an SCP require a CSC on `CreateFunction`.

### Scaling, recursion and cost

Lambda scales by running more concurrent environments, up to a Regional account concurrency quota (commonly 1,000; check `get-account-settings`, newer accounts can start lower). Reserved concurrency caps a single function and guarantees it capacity. A public function with no cap can therefore consume all of the account's concurrency (starving other functions) and generate cost on every request. Lambda's **recursive loop detection**, on by default, stops a chain after roughly 16 invocations when the loop passes through SQS, S3, SNS or EventBridge custom buses and the function uses a supported SDK version; loops through other services (DynamoDB Streams, for example) are not detected.

### Network placement

By default a function runs in an AWS-managed network with outbound internet access and no access to your VPC. Attached to a VPC, it gets elastic network interfaces in your subnets, inherits their routing and security groups, and only reaches the internet through a NAT gateway or VPC endpoints. Security Hub CSPM **Lambda.3** (Low) flags functions not in a VPC; **Lambda.5** (Medium) flags VPC functions in fewer than two Availability Zones. VPC placement is an egress and reachability control, not an access control on invocation. Routing and endpoint design is in the [VPC and edge note](/cloud/aws-vpc-edge-dns-security/).

### Newer form factors

AWS's documentation now calls classic functions **Lambda Event Functions**, alongside **Lambda Managed Instances** (functions on customer-owned EC2 capacity with multi-concurrent environments), durable functions, and **Lambda Web Functions**, announced in October 2026 as an HTTP-native, multi-concurrent model that gets a public HTTPS endpoint per deployment (AWS's launch post shows access restricted with CloudFront OAC). This note tests Event Functions. If a client uses the newer form factors, treat their endpoints like function URLs, check the current docs for their auth options and condition keys (the Service Authorization Reference already lists `lambda:Request/WebFunctionAuthType`), and remember that multi-concurrent environments make cross-request state leaks more likely, not less.

### Lambda@Edge and CloudFront Functions

**Lambda@Edge** functions are created in `us-east-1`, published as versions and replicated to CloudFront edge locations, where they run on viewer or origin requests and responses. They must be numbered versions (not `$LATEST` or aliases), their execution role must trust both `lambda.amazonaws.com` and `edgelambda.amazonaws.com`, and they do not support environment variables (other than the reserved ones), VPC access or layers. That last point matters for review: with no environment variables, teams hard-code keys and signing secrets straight into edge code. They often implement authentication (cookie or JWT checks, signed-URL logic) in front of an origin, so a logic bug is an auth bypass for the whole distribution. **CloudFront Functions** are lightweight JavaScript functions running in CloudFront itself, with no network access and no IAM role, typically used for header manipulation, redirects and simple token checks, sometimes with data in a CloudFront KeyValueStore. Both are configured on distributions (see the [VPC and edge note](/cloud/aws-vpc-edge-dns-security/)).

### Step Functions

A Step Functions state machine orchestrates Lambda and other services with its own IAM role. Two security-relevant properties: the **execution history** (and `DescribeExecution`) stores the input and output of each state, so anything passed between steps, including secrets fetched in one step, is readable by anyone with `states:GetExecutionHistory` or `states:DescribeExecution`; and CloudWatch logging (`loggingConfiguration.level` `ALL`, `ERROR`, `FATAL` or `OFF`, with `includeExecutionData`) copies that data into logs. Security Hub CSPM **StepFunctions.1** checks that logging is on.

### OWASP serverless context

OWASP's [Top 10 Serverless Interpretation](https://owasp.org/www-project-serverless-top-10/) (an incubator project from 2018) maps the classic Top 10 to functions. Its key point still holds: in serverless, **injection input arrives through event sources, not just HTTP**. An S3 object key, an SQS message body, an SNS message attribute, a DynamoDB stream record, a Cognito trigger attribute or an IoT payload is attacker-controlled whenever an attacker can influence what lands in that source, and functions often trust these "internal" events far more than they would trust an HTTP parameter.

## What goes wrong

**Public invoke permissions.** A `Principal "*"` statement on `lambda:InvokeFunction`, often left by a quick test, a framework default, or a deleted function URL. Any AWS account can then run the function with its role, pass arbitrary event JSON and read the response. Impact equals whatever the function does with untrusted input plus whatever its role can reach.

**Service-principal grants without source conditions.** `s3.amazonaws.com` allowed to invoke with no `aws:SourceAccount`, or `apigateway.amazonaws.com` with no `aws:SourceArn`. An attacker in another account configures their own bucket notification or API integration to invoke your function with events they craft. This is the Lambda version of the confused-deputy problem covered in the [STS and cross-account note](/cloud/aws-sts-cross-account-trust-federation/).

**Unauthenticated function URLs.** `AuthType NONE` used for webhooks, internal tools or "temporary" endpoints, with authentication either absent or implemented badly in code. Function URLs are not behind WAF unless fronted by CloudFront, have no built-in throttling beyond the function's concurrency, and are easy to find in client code, mobile apps and browser history.

**Secrets in environment variables.** Database passwords, API keys, signing secrets and third-party tokens in plaintext configuration, readable by every principal with `lambda:List*` or `lambda:GetFunctionConfiguration`, copied into every published version, and shown in the console to anyone who opens the function. CloudTrail deliberately omits the `Environment` parameter from `CreateFunction` and `UpdateFunctionConfiguration` events, but CI/CD logs, Terraform state and CloudFormation templates often do not.

**Code readable by "read-only" principals.** `ReadOnlyAccess` (and any policy with `lambda:Get*`) downloads deployment packages, which routinely contain hard-coded keys, internal endpoints and business logic. This is how attackers turn a low-privilege key into the next credential.

**Layers shared publicly or consumed from strangers.** A layer version granted to `*` exposes its contents. A function using a layer ARN from an unknown account runs that code with the function's role.

**Over-privileged execution roles.** `AdministratorAccess`, `"Action": "*"`, `s3:*` on `*`, `secretsmanager:GetSecretValue` on `*`, `iam:PassRole` on `*`, or one shared role for dozens of functions. Any code execution in the function (event injection, vulnerable dependency, malicious layer) becomes account compromise.

**Writable code paths to powerful roles.** A principal with `lambda:UpdateFunctionCode` on a function whose role is more powerful than the principal can escalate by replacing the code; `iam:PassRole` plus `lambda:CreateFunction` (and a way to invoke) lets a principal run code as any passable role. These are classic [privilege escalation paths](/cloud/aws-iam-privilege-escalation/). Code signing in `Enforce` mode and tight IAM are the controls.

**Event injection.** Handlers that pass event fields to `subprocess` with a shell, `os.system`, `child_process.exec`, `eval`, SQL string building, template rendering, XML parsers, `pickle.loads` or `yaml.load`, or that build file paths in `/tmp` from S3 keys. Once code runs, the attacker reads `/proc/self/environ` for role credentials and environment secrets.

**State leaking between invocations.** Per-user data cached in globals or `/tmp`, secrets written to `/tmp` and left there, background work continuing into the next caller's invocation, and multi-tenant functions that assume each invocation starts clean.

**Deprecated runtimes.** Functions on `python3.8`, `nodejs16.x`, `go1.x` or the original `provided` runtime that keep running for years without OS or language patches, sometimes with runtime updates pinned to `Manual` so they never receive even the patches that are available.

**Denial of wallet and concurrency exhaustion.** Public or high-volume functions with no reserved concurrency, no API throttling in front, generous memory and timeouts, and no budget alarms; recursive loops through services the loop detector does not cover.

**Logging data, not just events.** Handlers that log the full event (tokens, personal data, card numbers) to CloudWatch Logs, where retention is often infinite and readers are many. See the [CloudWatch and EventBridge note](/cloud/aws-cloudwatch-eventbridge-monitoring/).

## Testing

Every test here assumes an **authorised** engagement against the client's own AWS accounts, with written scope, and respects the [AWS penetration testing policy](https://aws.amazon.com/security/penetration-testing/). The defaults are read-only API calls. Anything that invokes a function, downloads client code or changes state is marked, and you only run it with explicit approval. Output shown below is **illustrative**: we ran nothing against AWS to produce it, and account IDs are AWS's documentation examples.

### Before you start

**Permissions.** `SecurityAudit` covers almost everything below except `lambda:GetFunction` (code download) and `lambda:GetLayerVersion` (layer content); request those separately if code review is in scope. Add `iam:SimulatePrincipalPolicy` if it is not already granted, and `kms:DescribeKey`/`kms:GetKeyPolicy` for the key checks. Remember that your own audit role can read every environment variable encrypted with the default key: handle the output as client secrets (encrypted storage, no pasting into tickets, delete at end of engagement).

**Profile and Region loop.** Lambda is Regional and functions hide in Regions nobody uses. Loop over every enabled Region:

```bash
export AWS_PROFILE=client-audit
aws sts get-caller-identity
REGIONS=$(aws ec2 describe-regions --query 'Regions[].RegionName' --output text)
mkdir -p out/lambda
for r in $REGIONS; do
  aws lambda list-functions --region "$r" --function-version ALL \
    --output json > "out/lambda/functions-$r.json"
done
jq -r '.Functions[] | [.FunctionArn, .Runtime // .PackageType, .Role] | @tsv' out/lambda/functions-*.json | sort -u | head
```

`--function-version ALL` includes every published version, which is where stale secrets and stale runtimes live. Lambda@Edge functions live in `us-east-1`, so make sure it is in your list even if the workload is elsewhere.

**Tools.**

- [Prowler](https://github.com/prowler-cloud/prowler): `prowler aws --services awslambda stepfunctions cloudfront` runs the Lambda, Step Functions and CloudFront checks named in each test.
- [CloudFox](https://github.com/BishopFox/cloudfox): `cloudfox aws --profile client-audit lambda`, `env-vars`, `resource-trusts` and `permissions` give fast attack-surface tables.
- [Pacu](https://github.com/RhinoSecurityLabs/pacu): `lambda__enum` enumerates functions, configuration and policies (read-only). Do not run the `lambda__backdoor_*` modules on client accounts.
- [PMapper](https://github.com/nccgroup/PMapper) and [cloudsplaining](https://github.com/salesforce/cloudsplaining) for role and principal analysis; `aws iam simulate-principal-policy` for precise yes/no answers.
- [trufflehog](https://github.com/trufflesecurity/trufflehog) and [gitleaks](https://github.com/gitleaks/gitleaks) for secret scanning. Run trufflehog with `--no-verification`: verification calls third-party APIs with the found credential, which is outside "stop at identification".
- Steampipe's `aws_lambda_function` table (`policy_std`, `environment_variables`, `url_config`, `layers`) if you prefer SQL across accounts.
- IAM Access Analyzer external access analysers cover Lambda functions and layers; read their active findings before you start.

For hands-on practice, [CloudGoat](https://github.com/RhinoSecurityLabs/cloudgoat) has Lambda privilege-escalation scenarios, [IAM Vulnerable](https://github.com/BishopFox/iam-vulnerable) builds `PassRole`/`CreateFunction` and `UpdateFunctionCode` paths, and OWASP's [ServerlessGoat](https://github.com/OWASP/Serverless-Goat) and [DVSA](https://github.com/OWASP/DVSA) are deliberately vulnerable serverless apps for event injection.

### GT-AWS-LAMBDA-1: Public or unconstrained function resource policies

*Guler Tech methodology.*

#### What it checks

Whether any function, version or alias has a resource-based policy that lets principals outside the account invoke or manage it: `Principal "*"` without a restricting condition, cross-account principals that are not documented, and service principals without `aws:SourceArn` or `aws:SourceAccount`.

#### Prerequisites

`lambda:ListFunctions`, `lambda:ListAliases`, `lambda:GetPolicy` (all in `SecurityAudit`).

#### Steps

Pull every policy, including those on aliases, and flag risky statements:

```bash
for r in $REGIONS; do
  for fn in $(jq -r '.Functions[] | select(.Version == "$LATEST") | .FunctionName' "out/lambda/functions-$r.json"); do
    for q in "" $(aws lambda list-aliases --region "$r" --function-name "$fn" --query 'Aliases[].Name' --output text); do
      args=(--region "$r" --function-name "$fn"); [ -n "$q" ] && args+=(--qualifier "$q")
      pol=$(aws lambda get-policy "${args[@]}" --query Policy --output text 2>/dev/null) || continue
      echo "$pol" | jq -c --arg fn "$fn${q:+:$q}" --arg r "$r" '
        .Statement[] | select(.Effect == "Allow")
        | {region: $r, fn: $fn, sid: .Sid, principal: .Principal, action: .Action, condition: .Condition}'
    done
  done
done | tee out/lambda/policies.jsonl
```

Then triage:

```bash
# Anyone in any account, no condition at all
jq -c 'select((.principal == "*" or .principal.AWS == "*") and .condition == null)' out/lambda/policies.jsonl
# Service principals with no source scoping
jq -c 'select(.principal.Service != null)
       | select((.condition // {} | tostring | test("SourceArn|SourceAccount")) | not)' out/lambda/policies.jsonl
# Public InvokeFunction not limited to function URL calls
jq -c 'select((.principal == "*" or .principal.AWS == "*") and (.action | tostring | test("InvokeFunction\"|InvokeFunction$")))
       | select((.condition // {} | tostring | test("InvokedViaFunctionUrl|PrincipalOrgID|SourceArn|SourceAccount")) | not)' out/lambda/policies.jsonl
```

For each cross-account `AWS` principal, check the account ID against the client's account inventory (`aws organizations list-accounts` from the management or delegated admin account).

**Lab or explicitly approved only:** to prove reachability from outside, invoke the function from a separate tester-owned account with a benign, schema-valid test event agreed with the client and read only the response metadata:

```bash
aws lambda invoke --profile tester-external --region eu-west-2 \
  --function-name arn:aws:lambda:eu-west-2:111122223333:function:orders-export \
  --payload '{"healthcheck": true}' --cli-binary-format raw-in-base64-out /dev/stdout
```

#### Observation

Illustrative non-compliant statement:

```json
{
  "Sid": "s3-trigger",
  "Effect": "Allow",
  "Principal": { "Service": "s3.amazonaws.com" },
  "Action": "lambda:InvokeFunction",
  "Resource": "arn:aws:lambda:eu-west-2:111122223333:function:thumbnailer"
}
```

Compliant equivalent:

```json
{
  "Sid": "s3-trigger",
  "Effect": "Allow",
  "Principal": { "Service": "s3.amazonaws.com" },
  "Action": "lambda:InvokeFunction",
  "Resource": "arn:aws:lambda:eu-west-2:111122223333:function:thumbnailer",
  "Condition": {
    "StringEquals": { "aws:SourceAccount": "111122223333" },
    "ArnLike": { "aws:SourceArn": "arn:aws:s3:::example-uploads-bucket" }
  }
}
```

#### Evaluation

- **Fail (Critical candidate):** `Principal "*"` or `{"AWS": "*"}` on `lambda:InvokeFunction` (or `lambda:*`) with no condition that limits callers to the client's accounts or organisation, outside a deliberate function URL pattern. Rate by what the function does with input and what its role reaches.
- **Fail (High candidate):** service principal statements without `aws:SourceArn` *and* without `aws:SourceAccount`; cross-account principals that are not in the client's inventory; any grant of management actions (`lambda:UpdateFunctionCode`, `lambda:AddPermission`, `lambda:UpdateFunctionConfiguration`) to another account.
- **Fail (Medium):** conditions using wildcards that defeat their purpose (`"aws:SourceArn": "arn:aws:s3:::*"`), or public `InvokeFunction` paired with a function URL but missing `lambda:InvokedViaFunctionUrl`.
- **Pass:** only same-account or documented, organisation-scoped principals; every service principal carries `aws:SourceArn` (and, for S3, `aws:SourceAccount`).
- **False positives:** `"aws:PrincipalOrgID": "o-..."` with `Principal "*"` is organisation-scoped, not public. API Gateway statements often use `aws:SourceArn` with a wildcard path (`arn:aws:execute-api:eu-west-2:111122223333:abc123/*`), which is fine when the API ID is fixed.

#### Automated coverage

Security Hub CSPM **Lambda.1**. Prowler `awslambda_function_not_publicly_accessible`. IAM Access Analyzer external access findings for `AWS::Lambda::Function`.

#### Detection

CloudTrail management events `AddPermission20150331v2`, `RemovePermission20150331v2` and `PutResourcePolicy` (Lambda appends version suffixes to many event names, so match on prefix, for example `eventName` starting with `AddPermission`). Alert on statements whose principal is `*` or an account outside the organisation. Invocations themselves are data events (`Invoke` on `AWS::Lambda::Function`) and are only logged if the client enabled Lambda data events; without them you see the effect (CloudWatch `Invocations` metric, function logs) but not the caller.

### GT-AWS-LAMBDA-2: Function URLs with AuthType NONE and permissive CORS

*Guler Tech methodology.*

#### What it checks

Which functions and aliases have function URLs, their `AuthType`, whether the public policy is limited to URL invocation, whether CloudFront fronts them with OAC, and whether the CORS configuration lets arbitrary origins read responses.

#### Prerequisites

`lambda:ListFunctionUrlConfigs`, `lambda:GetFunctionUrlConfig`, `lambda:GetPolicy`; `cloudfront:ListDistributions` and `cloudfront:ListOriginAccessControls` for the CloudFront check.

#### Steps

```bash
for r in $REGIONS; do
  for fn in $(jq -r '.Functions[] | select(.Version == "$LATEST") | .FunctionName' "out/lambda/functions-$r.json"); do
    aws lambda list-function-url-configs --region "$r" --function-name "$fn" \
      --query 'FunctionUrlConfigs[].[FunctionArn, FunctionUrl, AuthType, InvokeMode]' --output text
  done
done | tee out/lambda/urls.tsv

awk '$3 == "NONE"' out/lambda/urls.tsv
```

For each URL, record the CORS block:

```bash
aws lambda get-function-url-config --region eu-west-2 --function-name partner-webhook \
  --query '[AuthType, Cors]'
```

Check whether a CloudFront distribution uses the URL as an origin, and with OAC:

```bash
aws cloudfront list-distributions --query \
  'DistributionList.Items[].{id:Id, origins:Origins.Items[?contains(DomainName, `lambda-url`)].[DomainName, OriginAccessControlId]}'
```

**Explicitly approved only:** confirm unauthenticated reachability with a benign request, and probe CORS with a preflight that does not execute business logic:

```bash
curl -s -o /dev/null -w '%{http_code}\n' https://abcdefexample.lambda-url.eu-west-2.on.aws/
curl -s -i -X OPTIONS https://abcdefexample.lambda-url.eu-west-2.on.aws/ \
  -H 'Origin: https://attacker.example' -H 'Access-Control-Request-Method: POST' | grep -i '^access-control'
```

Then review the handler: does it implement its own authentication (HMAC signature on webhooks, JWT validation, shared secret)? A `NONE` URL is acceptable for a webhook that verifies the sender's signature with a constant-time comparison and rejects replays; it is not acceptable for an admin tool that trusts a header.

#### Observation

Illustrative:

```text
arn:aws:lambda:eu-west-2:111122223333:function:partner-webhook   https://abcdefexample.lambda-url.eu-west-2.on.aws/   NONE      BUFFERED
arn:aws:lambda:eu-west-2:111122223333:function:report-builder    https://ghijklexample.lambda-url.eu-west-2.on.aws/   AWS_IAM   BUFFERED
```

```json
{ "AllowOrigins": ["*"], "AllowMethods": ["*"], "AllowHeaders": ["*"], "AllowCredentials": false }
```

#### Evaluation

- **Fail:** `AuthType NONE` on a function that returns non-public data or performs state-changing actions without strong in-code authentication. Severity follows the data and the role (Critical when it exposes sensitive data or privileged actions unauthenticated).
- **Fail:** a function URL used as a CloudFront origin with `AuthType NONE` or no OAC, so the URL bypasses WAF, geo-restrictions and any CloudFront-side auth (CloudFront.16).
- **Fail (Low to Medium):** `AllowOrigins ["*"]` on an endpoint that returns user-specific data to browsers; reflected origins with credentials. CORS never makes an unauthenticated URL safe, and on an `AWS_IAM` URL it rarely matters, because browsers cannot SigV4-sign without credentials in the page.
- **Fail (Low):** orphaned public policy statements left after a URL was deleted.
- **Pass:** `AWS_IAM` with documented callers, or `NONE` with verified in-code authentication, throttling (reserved concurrency) and a narrow CORS allowlist.

#### Automated coverage

Prowler `awslambda_function_url_public` and `awslambda_function_url_cors_policy`; Security Hub CSPM **Lambda.1** (via the public statement) and **CloudFront.16**.

#### Detection

CloudTrail `CreateFunctionUrlConfig` and `UpdateFunctionUrlConfig` with `authType` `NONE`, plus `AddPermission*` with `functionUrlAuthType` `NONE`. Function URL requests are not CloudTrail management events; rely on function logs and CloudWatch metrics (`Url4xxCount`, `Url5xxCount`, `UrlRequestCount`) for traffic.

### GT-AWS-LAMBDA-3: Secrets in environment variables and who can read them

*Guler Tech methodology.*

#### What it checks

Whether environment variables of any function version contain credentials, which key encrypts them, and which principals can read them.

#### Prerequisites

The `list-functions --function-version ALL` output from Before you start; `kms:DescribeKey`; `iam:SimulatePrincipalPolicy`.

#### Steps

Extract variables to a working file kept inside the engagement's encrypted store:

```bash
jq -r '.Functions[] | select(.Environment.Variables != null)
       | .FunctionArn as $a | .KMSKeyArn as $k
       | .Environment.Variables | to_entries[]
       | [$a, ($k // "aws/lambda"), .key, .value] | @tsv' out/lambda/functions-*.json > out/lambda/env.tsv

# Suspicious names
cut -f1,2,3 out/lambda/env.tsv | grep -Ei 'pass|secret|token|api_?key|private|credential|conn(ection)?_?str|dsn|webhook|signing'

# Pattern scan of the values without verifying anything
trufflehog filesystem out/lambda/env.tsv --no-verification
gitleaks dir -v out/lambda/env.tsv
```

Distinguish pointers from secrets. `DB_SECRET_ARN=arn:aws:secretsmanager:...` or `/prod/db/password` (a Parameter Store name) is good practice; `DB_PASSWORD=...` is the finding.

Who can read them: with the default key, anyone with `lambda:ListFunctions`, `lambda:GetFunctionConfiguration` or `lambda:GetFunction`. List candidate principals with PMapper (`pmapper query 'who can do lambda:GetFunctionConfiguration with *'`) or CloudFox `permissions`, then confirm specific ones:

```bash
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::111122223333:role/developer-readonly \
  --action-names lambda:ListFunctions lambda:GetFunctionConfiguration kms:Decrypt \
  --resource-arns '*' \
  --query 'EvaluationResults[].[EvalActionName, EvalDecision]' --output table
```

If a customer managed key is used, read the key policy (`aws kms get-key-policy --key-id <id> --policy-name default`) to see who has `kms:Decrypt`; the protection is only as narrow as that list.

#### Observation

Illustrative `env.tsv` lines (values redacted in reports, always):

```text
arn:aws:lambda:eu-west-2:111122223333:function:billing-sync:7   aws/lambda   STRIPE_API_KEY   <REDACTED>
arn:aws:lambda:eu-west-2:111122223333:function:billing-sync     aws/lambda   STRIPE_SECRET_ARN arn:aws:secretsmanager:eu-west-2:111122223333:secret:billing/stripe-EXAMPLE
```

The first line is published version 7, from before the team moved to Secrets Manager: the live configuration is clean, the old version is not.

#### Evaluation

- **Fail (High, Critical when the secret grants broad access):** live credentials in any version's environment, readable with the default key by principals beyond the function's owners (in most accounts that includes every holder of `ViewOnlyAccess`, `SecurityAudit`, `ReadOnlyAccess` or developer roles).
- **Fail (Medium):** secrets protected by a customer managed key whose policy grants `kms:Decrypt` broadly; secrets present only in old published versions.
- **Pass:** variables contain only references (secret ARNs, parameter names, non-sensitive settings), or secrets are client-side encrypted with a tightly scoped key and decrypted in code.
- **Report hygiene:** never include a secret value; give the variable name, function version and the fact that it matched a credential format. If the client approves, `sts get-caller-identity` with an AWS key found here is the furthest you go, then recommend rotation.

#### Automated coverage

Prowler `awslambda_function_no_secrets_in_variables` and `awslambda_function_env_vars_not_encrypted_with_cmk`. No Security Hub CSPM control covers environment-variable content.

#### Detection

`GetFunctionConfiguration*`, `GetFunction*` and `ListFunctions*` are management events, so bulk reading by an unusual principal is visible in CloudTrail; GuardDuty's `Discovery:IAMUser/AnomalousBehavior` may fire on anomalous enumeration. Use of an exfiltrated secret happens outside AWS and needs detection at the third-party service.

### GT-AWS-LAMBDA-4: Who can download function code, and what is in it

*Guler Tech methodology.*

#### What it checks

Which principals can call `lambda:GetFunction` (and therefore download every deployment package), and whether packages contain hard-coded credentials or sensitive logic.

#### Prerequisites

`iam:SimulatePrincipalPolicy` for the access question. For the content review, `lambda:GetFunction` and, for container functions, `ecr:BatchGetImage`/`ecr:GetDownloadUrlForLayer`, with **explicit client approval to copy their code**.

#### Steps

Access question first, because it is a finding on its own:

```bash
for p in $(aws iam list-roles --query 'Roles[].Arn' --output text); do
  d=$(aws iam simulate-principal-policy --policy-source-arn "$p" --action-names lambda:GetFunction \
        --resource-arns '*' --query 'EvaluationResults[0].EvalDecision' --output text 2>/dev/null)
  [ "$d" = "allowed" ] && echo "$p"
done
```

Expect to see `ReadOnlyAccess` holders, CI roles and developer roles. Also look for resource-policy grants of `lambda:GetFunction` to other accounts in `policies.jsonl` from LAMBDA-1.

**Approved only:** download into a dedicated, empty directory and scan without executing anything:

```bash
mkdir -p loot/billing-sync && cd loot/billing-sync
url=$(aws lambda get-function --region eu-west-2 --function-name billing-sync --query Code.Location --output text)
curl -s -o package.zip "$url" && unzip -q package.zip -d src
trufflehog filesystem src --no-verification
gitleaks dir -v src
grep -RniE 'BEGIN (RSA|EC|OPENSSH) PRIVATE|password *=|secret *=|Authorization: *Bearer' src | head
```

The presigned URL expires after 10 minutes. Treat downloaded code as client data and as untrusted input for your own machine.

#### Observation

Illustrative: 41 roles can call `lambda:GetFunction` on `*`, including `role/support-readonly` (with `ReadOnlyAccess`). The `billing-sync` package contains `config/settings.py` with a third-party API key and an internal admin endpoint.

#### Evaluation

- **Fail (High):** hard-coded live credentials in code readable by principals beyond the deploying pipeline; severity rises with what the credential reaches.
- **Fail (Medium):** broad `lambda:GetFunction` (for example, `ReadOnlyAccess` granted widely) without secrets in code: it exposes intellectual property and attack-relevant logic, and turns any future hard-coded secret into an immediate leak.
- **Pass:** code access limited to the deployment pipeline and owners, no secrets in packages, and secrets fetched at runtime from Secrets Manager or Parameter Store.

#### Automated coverage

Prowler `awslambda_function_no_secrets_in_code` (it downloads and scans packages, so it needs `lambda:GetFunction`). No Security Hub CSPM control.

#### Detection

CloudTrail `GetFunction*` management events. A burst of `GetFunction` across many functions from one principal, especially followed by `ListVersionsByFunction*`, is the SCARLETEEL pattern (see [Real-world cases](#real-world-cases)). The package download itself goes to a Lambda-owned S3 location and is not in the client's CloudTrail.

### GT-AWS-LAMBDA-5: Layer sharing and third-party layers

*Guler Tech methodology.*

#### What it checks

Whether the client's layer versions are shared publicly or with unknown accounts, and whether functions use layers owned by accounts outside the organisation.

#### Prerequisites

`lambda:ListLayers`, `lambda:ListLayerVersions`, `lambda:GetLayerVersionPolicy`; the function inventory.

#### Steps

```bash
for r in $REGIONS; do
  for l in $(aws lambda list-layers --region "$r" --query 'Layers[].LayerName' --output text); do
    for v in $(aws lambda list-layer-versions --region "$r" --layer-name "$l" --query 'LayerVersions[].Version' --output text); do
      aws lambda get-layer-version-policy --region "$r" --layer-name "$l" --version-number "$v" \
        --query Policy --output text 2>/dev/null \
      | jq -c --arg id "$r/$l:$v" '.Statement[] | {layer: $id, principal: .Principal, condition: .Condition}'
    done
  done
done

# Layers in use whose owning account is not one of ours
OURS="111122223333|444455556666"
jq -r '.Functions[] | .FunctionArn as $f | (.Layers // [])[] | [$f, .Arn] | @tsv' out/lambda/functions-*.json \
  | awk -F'\t' '{split($2,a,":"); print a[5] "\t" $0}' | grep -Ev "^($OURS)\b"
```

For each foreign layer, identify the publisher: AWS-published layers (for example AWS Parameters and Secrets Lambda Extension, AWS Distro for OpenTelemetry) and well-known vendors document their account IDs; anything else needs an owner and a reason.

#### Observation

Illustrative:

```text
{"layer":"eu-west-2/shared-utils:12","principal":"*","condition":null}
123456789012  arn:aws:lambda:eu-west-2:111122223333:function:pdf-render  arn:aws:lambda:eu-west-2:123456789012:layer:chromium:31
```

#### Evaluation

- **Fail (Medium, High if the layer holds secrets or proprietary code):** a layer version granted to `*` without `aws:PrincipalOrgID` scoping; layers granted to accounts outside the client's inventory.
- **Fail (Medium):** functions using layers from unidentified accounts, especially functions with powerful roles. The layer's code runs with the function's credentials.
- **Pass:** layers shared only within the organisation (`--organization-id`), foreign layers limited to documented vendors, and an SCP or review that enforces it.

#### Automated coverage

Prowler `awslambda_function_using_cross_account_layers` and `awslambda_layer_no_secrets_in_content`. IAM Access Analyzer covers layer versions for external access.

#### Detection

CloudTrail `AddLayerVersionPermission*` (alert on principal `*` without an organisation condition), `PublishLayerVersion20181031`, and `UpdateFunctionConfiguration20150331v2` where the `layers` parameter changes.

### GT-AWS-LAMBDA-6: Execution role over-privilege

*Guler Tech methodology.*

#### What it checks

Whether each function's execution role is limited to what the code needs, whether roles are shared, and whether any role offers an escalation path if the function is compromised.

#### Prerequisites

`iam:GetRole`, `iam:ListAttachedRolePolicies`, `iam:ListRolePolicies`, `iam:GetRolePolicy`, `iam:GetPolicyVersion`, `iam:GenerateServiceLastAccessedDetails`, `iam:GetServiceLastAccessedDetails`.

#### Steps

```bash
# Roles and how many functions share them
jq -r '.Functions[] | select(.Version == "$LATEST") | .Role' out/lambda/functions-*.json | sort | uniq -c | sort -rn | head

# Managed policies on each role
for role in $(jq -r '.Functions[].Role' out/lambda/functions-*.json | sort -u | awk -F/ '{print $NF}'); do
  echo "== $role"
  aws iam list-attached-role-policies --role-name "$role" --query 'AttachedPolicies[].PolicyName' --output text
  aws iam list-role-policies --role-name "$role" --query 'PolicyNames' --output text
done
```

Run cloudsplaining over the account authorisation details for a ranked view of privilege escalation, data exfiltration and resource exposure actions per role:

```bash
aws iam get-account-authorization-details > out/iam-auth.json
cloudsplaining scan --input-file out/iam-auth.json --output out/cloudsplaining
```

Compare granted versus used permissions with Access Advisor (or IAM Access Analyzer unused access findings if the client has an unused access analyser):

```bash
job=$(aws iam generate-service-last-accessed-details \
  --arn arn:aws:iam::111122223333:role/billing-sync-role --query JobId --output text)
aws iam get-service-last-accessed-details --job-id "$job" \
  --query 'ServicesLastAccessed[?TotalAuthenticatedEntities==`0`].ServiceNamespace' --output text
```

Answer the escalation question for the role with [PMapper](https://github.com/nccgroup/PMapper) (`pmapper query 'can role/billing-sync-role do iam:CreateAccessKey with *'`) and the patterns in the [privilege escalation note](/cloud/aws-iam-privilege-escalation/).

#### Observation

Illustrative: `lambda-shared-role` is used by 23 functions, has `AmazonS3FullAccess`, `AmazonDynamoDBFullAccess` and an inline `iam:PassRole` on `*`; Access Advisor shows DynamoDB unused for 400 days.

#### Evaluation

- **Fail (High to Critical):** a role with administrative or escalation-capable permissions (`*:*`, `iam:*`, `iam:PassRole` on `*` with a compute-creation permission, `sts:AssumeRole` on `*`) on any function that processes external input or is publicly invocable. Critical when combined with a LAMBDA-1, -2 or -9 finding.
- **Fail (Medium):** service-wide wildcards on data services (`s3:*` on `*`, `secretsmanager:GetSecretValue` on `*`), a single role shared by unrelated functions, large unused permission sets.
- **Pass:** one role per function or per tightly related group, actions and resources scoped to what the code calls, `AWSLambdaBasicExecutionRole` (or equivalent scoped logging permissions) plus specific grants.

#### Automated coverage

No Security Hub CSPM Lambda control; IAM-level controls such as `IAM.1` (no full `*:*` admin in customer managed policies) and `IAM.21` (no wildcard service actions in customer managed policies) catch some cases, as described in the [IAM fundamentals note](/cloud/aws-iam-fundamentals-policy-evaluation/). Prowler's IAM checks, cloudsplaining and Access Analyzer unused access findings.

#### Detection

Compromised function credentials used from outside AWS raise GuardDuty `UnauthorizedAccess:IAMUser/ResourceCredentialExfiltration.OutsideAWS` (or `.InsideAWS` from another account), which explicitly covers credentials created for Lambda functions. Unusual API calls by a function role (for example `iam:*`, `sts:GetCallerIdentity` from a role that never calls it) are a strong CloudTrail signal because function behaviour is usually very regular.

### GT-AWS-LAMBDA-7: Deployment integrity, code signing and who can change code

*Guler Tech methodology.*

#### What it checks

Whether code signing is configured and enforced, and which principals can change a function's code, configuration, layers or role, or create functions with passable roles.

#### Prerequisites

`lambda:ListCodeSigningConfigs`, `lambda:GetFunctionCodeSigningConfig`, `iam:SimulatePrincipalPolicy`, `organizations:ListPolicies`/`DescribePolicy` if you can read SCPs.

#### Steps

```bash
aws lambda list-code-signing-configs --region eu-west-2 \
  --query 'CodeSigningConfigs[].[CodeSigningConfigArn, CodeSigningPolicies.UntrustedArtifactOnDeployment]' --output text

for fn in $(jq -r '.Functions[] | select(.Version == "$LATEST") | .FunctionName' out/lambda/functions-eu-west-2.json); do
  printf '%s\t' "$fn"
  aws lambda get-function-code-signing-config --region eu-west-2 --function-name "$fn" \
    --query 'CodeSigningConfigArn' --output text
done
```

Then map write access. For each high-value function (powerful role, sensitive data), list who can change it:

```bash
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::111122223333:role/developer \
  --action-names lambda:UpdateFunctionCode lambda:UpdateFunctionConfiguration lambda:CreateFunction iam:PassRole \
  --resource-arns arn:aws:lambda:eu-west-2:111122223333:function:billing-sync \
  --query 'EvaluationResults[].[EvalActionName, EvalDecision]' --output table
```

`simulate-principal-policy` does not apply SCPs or resource policies in every case, so read relevant SCPs separately. PMapper's graph shows `lambda` edges (principals that can reach a role through function creation or update) directly. A benign lab proof of an `UpdateFunctionCode` path is replacing the code of a **test** function with one that returns `sts get-caller-identity` output, never a client production function.

#### Observation

Illustrative: no code signing configurations exist; `role/developer` can call `lambda:UpdateFunctionCode` on all functions, including `billing-sync`, whose role has `iam:PassRole` on `*`.

#### Evaluation

- **Fail (High to Critical):** a lower-privileged principal can update code or configuration of a function whose role is more privileged, or can create a function with a more privileged passable role and invoke it. Rate as privilege escalation by the gap between the two.
- **Fail (Medium):** production functions without code signing where the client's threat model includes pipeline or credential compromise; CSCs in `Warn` mode on production (they only log).
- **Pass:** code changes only through a pipeline role, CSCs in `Enforce` on production functions and layers, and an SCP requiring a CSC on `CreateFunction`.

#### Automated coverage

No Security Hub CSPM control or Prowler check for code signing at the time of writing; PMapper and Pacu `iam__privesc_scan --scan-only` (without `--scan-only` the module offers to exploit what it finds) for the escalation side.

#### Detection

CloudTrail `UpdateFunctionCode20150331v2`, `UpdateFunctionConfiguration20150331v2` (role, layers, handler changes), `CreateFunction20150331`, `PublishVersion20150331`, `UpdateAlias20150331`, `PutFunctionCodeSigningConfig`, `DeleteFunctionCodeSigningConfig`. Code changes outside the pipeline's role or deployment window are high-signal. With CSCs in `Warn`, the CloudWatch metric `SignatureValidationErrors` records unsigned deployments.

### GT-AWS-LAMBDA-8: Deprecated runtimes and pinned runtime versions

*Guler Tech methodology.*

#### What it checks

Whether any function or published version uses a deprecated runtime, whether runtime updates are pinned, and whether container-image functions are built from current base images.

#### Prerequisites

The function inventory; `lambda:GetRuntimeManagementConfig`; ECR or Amazon Inspector read access for images.

#### Steps

```bash
jq -r '.Functions[] | [.FunctionArn, (.Runtime // ("image:" + .PackageType))] | @tsv' out/lambda/functions-*.json \
  | sort -k2 | awk -F'\t' '{c[$2]++} END {for (k in c) print c[k], k}' | sort -rn
```

Compare the identifiers against AWS's current [runtime tables](https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html). At the time of writing the deprecated list includes `python3.10`, `python3.9`, `python3.8`, `nodejs20.x`, `nodejs18.x`, `nodejs16.x`, `dotnet8`, `dotnet6`, `ruby3.2`, `provided.al2`, `java8` (Amazon Linux 1), `go1.x` and `provided`; Amazon Linux 2-based runtimes that are still supported receive only critical and selected important OS patches after AL2's end of life on 30 June 2026. Re-check the table on the day: it moves every few months.

Runtime update mode:

```bash
aws lambda get-runtime-management-config --region eu-west-2 --function-name billing-sync
```

`UpdateRuntimeOn: Manual` pins a runtime version ARN and stops automatic patching. For image functions, check the image's base and age with Amazon Inspector findings or `aws ecr describe-images`, as covered in the [containers note](/cloud/aws-containers-ecs-eks-ecr-security/).

#### Observation

Illustrative:

```text
14 python3.12
 6 nodejs22.x
 3 python3.8
 2 nodejs16.x
 1 go1.x
 4 image:Image
```

#### Evaluation

- **Fail (Medium):** functions on deprecated runtimes that process external input or hold sensitive roles; `Manual` runtime pinning without a patch process.
- **Fail (Low):** deprecated runtimes on internal, low-privilege functions; functions on runtimes within 180 days of deprecation without a migration plan.
- **High** only when you can tie the runtime to an exploitable vulnerability reachable through the function's input.
- **Pass:** supported runtimes, automatic runtime updates, and a rebuild cadence for images.

#### Automated coverage

Security Hub CSPM **Lambda.2** (ignores image functions). Prowler `awslambda_function_using_supported_runtimes`. Trusted Advisor's "AWS Lambda Functions Using Deprecated Runtimes" check.

#### Detection

Not an abuse signal; track with Security Hub CSPM, AWS Health events and Trusted Advisor.

### GT-AWS-LAMBDA-9: Event sources, event injection and execution environment state

*Guler Tech methodology.*

#### What it checks

For each function, where its events come from, who can influence their content, and whether the handler passes event fields to dangerous sinks or leaks state between invocations. This is a code review guided by configuration, with a dynamic proof only in a lab or with explicit approval.

#### Prerequisites

The event-source inventory (below) and source code (from the client's repository, or from LAMBDA-4 with approval).

#### Steps

Build the event-source map:

```bash
aws lambda list-event-source-mappings --region eu-west-2 \
  --query 'EventSourceMappings[].[FunctionArn, EventSourceArn, State, FilterCriteria]' --output text
# Push-model triggers appear as service principals in function policies (LAMBDA-1)
jq -r 'select(.principal.Service != null) | [.fn, .principal.Service, (.condition | tostring)] | @tsv' out/lambda/policies.jsonl
# S3 notifications pointing at functions
aws s3api get-bucket-notification-configuration --bucket example-uploads-bucket \
  --query 'LambdaFunctionConfigurations[].[LambdaFunctionArn, Events, Filter]'
```

For each source, write down who can put data into it: an S3 bucket with public or partner upload, an SQS queue with a broad policy (see the [API Gateway, SNS and SQS note](/cloud/aws-api-gateway-sns-sqs-security/)), a DynamoDB table fed by user input, a Cognito trigger fed by sign-up attributes. "Internal" sources fed by users are external input.

Then review the handler for sinks. A quick first pass:

```bash
grep -RnE 'subprocess\.(run|call|Popen|check_output)\(.*shell=True|os\.system\(|os\.popen\(|eval\(|exec\(|pickle\.loads?\(|yaml\.load\(|marshal\.loads|child_process|execSync|new Function\(|vm\.runIn|Runtime\.getRuntime\(\)\.exec|ProcessBuilder' src/
grep -RniE '(execute|query)\(.*(\+|%|format\()' src/   # SQL built by concatenation or formatting (also review f-strings and template literals by hand)
grep -RnE "os\.path\.join\(['\"]/tmp['\"].*(key|Key|name)|path\.join\(['\"]/tmp" src/
```

Then trace event fields into them: `event['Records'][0]['s3']['object']['key']` (URL-encoded, attacker-chosen when uploads are open), SQS `body`, SNS `Message` and `MessageAttributes`, DynamoDB `NewImage`, API Gateway `queryStringParameters`, `headers`, `body` and `pathParameters`.

Review state handling:

- Globals or module-level caches keyed by nothing, or holding per-user data.
- Files written to `/tmp` with predictable names, secrets written to `/tmp`, and no cleanup.
- Multi-tenant functions that serve different customers from one function without tenant isolation mode.
- Background threads or promises that outlive the handler.
- SnapStart functions that generate secrets, nonces or IDs during init.

**Lab or explicitly approved only:** demonstrate injection with a canary that proves execution without doing anything, for example an S3 object uploaded to an approved test bucket with a key containing a shell substitution that only echoes a unique marker, then find the marker in the function's CloudWatch logs. Never read `/proc/self/environ` or call AWS APIs with the function's credentials on a client system; state that an attacker would, and stop.

#### Observation

Illustrative handler (Python):

```python
def handler(event, context):
    key = urllib.parse.unquote_plus(event["Records"][0]["s3"]["object"]["key"])
    subprocess.run(f"convert /tmp/in '{key}.png'", shell=True, check=True)   # key reaches a shell
```

An object key such as `a';<command>;'` breaks out of the quotes. With uploads open to customers, this is unauthenticated (or low-privilege) code execution with the function's role.

#### Evaluation

- **Fail (Critical):** attacker-influenced event data reaches command execution, `eval`, unsafe deserialisation or SQL in a function whose role reaches sensitive data or can escalate. Rate with the role (LAMBDA-6).
- **Fail (High):** the same with a minimal role, or path traversal in `/tmp` that leads to overwriting code or reading other invocations' files.
- **Fail (Medium):** per-user data cached across invocations in a function serving multiple users; secrets persisted to `/tmp`; logging of full events containing credentials or personal data.
- **Pass:** event fields validated against a schema, parameterised queries, no shell, safe parsers, explicit per-invocation state.

#### Automated coverage

None of the CSPM tools see code paths. Use SAST (Semgrep, CodeQL, Bandit) on the repository, and Amazon Inspector Lambda code scanning if the client has it enabled. Prowler only covers the configuration side.

#### Detection

GuardDuty Lambda Protection analyses function network activity and raises findings such as `CryptoCurrency:Lambda/BitcoinTool.B`, `Backdoor:Lambda/C&CActivity.B`, `Trojan:Lambda/BlackholeTraffic`, `Trojan:Lambda/DropPoint`, `UnauthorizedAccess:Lambda/MaliciousIPCaller.Custom`, `UnauthorizedAccess:Lambda/TorClient` and `UnauthorizedAccess:Lambda/TorRelay`. Stolen function credentials used elsewhere raise `UnauthorizedAccess:IAMUser/ResourceCredentialExfiltration.OutsideAWS`. Function errors and duration anomalies in CloudWatch are often the first sign of injection probing.

### GT-AWS-LAMBDA-10: Concurrency, recursion and denial of wallet

*Guler Tech methodology.*

#### What it checks

Whether publicly reachable or high-volume functions have concurrency caps, whether recursion detection has been switched off, and whether cost and usage anomalies alert anyone.

#### Prerequisites

`lambda:GetAccountSettings`, `lambda:GetFunctionConcurrency`, `lambda:GetFunctionRecursionConfig`, `budgets:ViewBudget`, `ce:GetAnomalyMonitors`, `cloudwatch:DescribeAlarms`.

#### Steps

```bash
aws lambda get-account-settings --region eu-west-2 \
  --query '{limit: AccountLimit.ConcurrentExecutions, unreserved: AccountLimit.UnreservedConcurrentExecutions}'

for fn in partner-webhook thumbnailer; do
  printf '%s reserved=' "$fn"
  aws lambda get-function-concurrency --region eu-west-2 --function-name "$fn" --query ReservedConcurrentExecutions --output text
  aws lambda get-function-recursion-config --region eu-west-2 --function-name "$fn" --query RecursiveLoop --output text
done

aws budgets describe-budgets --account-id 111122223333 --query 'Budgets[].[BudgetName, BudgetLimit.Amount]'
aws ce get-anomaly-monitors --query 'AnomalyMonitors[].[MonitorName, MonitorType]'
aws cloudwatch describe-alarms --query 'MetricAlarms[?Namespace==`AWS/Lambda`].[AlarmName, MetricName]' --output text
```

Focus on the functions found in LAMBDA-1 and LAMBDA-2 and on anything behind a public API (check API Gateway throttling in the [API Gateway note](/cloud/aws-api-gateway-sns-sqs-security/)). Note the timeout and memory: a 15-minute, 10 GB function behind a public URL is an expensive thing to leave uncapped. **Do not load-test** to prove this; it is a configuration finding.

#### Observation

Illustrative: account limit 1,000, unreserved 1,000; `partner-webhook` has no reserved concurrency, 900-second timeout, 3,008 MB memory, `AuthType NONE`; no AWS Budgets, no anomaly monitor, no Lambda alarms; `RecursiveLoop` set to `Allow` on `thumbnailer`, which writes to the bucket that triggers it.

#### Evaluation

- **Fail (Medium):** public or partner-facing functions without reserved concurrency or upstream throttling, combined with no budget or anomaly alerting; recursion detection set to `Allow` on a function that writes to its own trigger.
- **Fail (Low):** missing cost alerting alone; generous timeouts on functions that do not need them.
- **High** when one function can exhaust account concurrency needed by business-critical functions (an availability impact you can show from configuration).
- **Pass:** caps on exposed functions, throttling upstream, budgets and anomaly detection with owners.

#### Automated coverage

No Security Hub CSPM control; Prowler has no direct concurrency check at the time of writing (`awslambda_function_no_dead_letter_queue` covers failure handling, a related resilience gap).

#### Detection

CloudWatch metrics `ConcurrentExecutions`, `Throttles`, `Invocations` and `RecursiveInvocationsDropped`; AWS Cost Anomaly Detection; GuardDuty `CryptoCurrency:Lambda/BitcoinTool.B` for mining in compromised functions.

### GT-AWS-LAMBDA-11: Network placement and egress

*Guler Tech methodology.*

#### What it checks

Whether functions that handle sensitive data or reach internal resources run in a VPC with controlled egress, whether VPC functions span Availability Zones, and whether functions outside a VPC hold credentials to internal systems.

#### Prerequisites

The function inventory (`VpcConfig`); `ec2:DescribeSecurityGroups`, `ec2:DescribeRouteTables`, `ec2:DescribeVpcEndpoints`.

#### Steps

```bash
jq -r '.Functions[] | select(.Version == "$LATEST")
       | [.FunctionName, (.VpcConfig.VpcId // "-"), ((.VpcConfig.SubnetIds // []) | length), ((.VpcConfig.SecurityGroupIds // []) | join(","))] | @tsv' \
  out/lambda/functions-eu-west-2.json

aws ec2 describe-security-groups --group-ids sg-0123456789abcdef0 \
  --query 'SecurityGroups[].IpPermissionsEgress[].[IpProtocol, FromPort, ToPort, IpRanges[].CidrIp]'
```

For VPC functions, follow the subnets' route tables: a route to a NAT gateway or internet gateway means internet egress; VPC endpoints (and their policies) decide which AWS services are reachable privately. For non-VPC functions, check whether they hold database or internal-API credentials (LAMBDA-3), which would mean an internal service is exposed to the internet to suit the function.

#### Observation

Illustrative: `billing-sync` runs outside a VPC, holds a database connection string for an RDS instance that is publicly accessible to allow it; `ledger-writer` is in one subnet with egress `0.0.0.0/0` on all ports through a NAT gateway.

#### Evaluation

- **Fail (Medium):** a function's network needs forced weaker controls elsewhere (a public database, an internet-exposed internal API); unrestricted egress from functions that handle sensitive data, which makes exfiltration after injection trivial.
- **Fail (Low):** functions not in a VPC with no internal dependencies (Lambda.3 fails, little real risk); single-AZ VPC functions (Lambda.5, availability).
- **Pass:** VPC placement where internal access is needed, egress restricted to required destinations and VPC endpoints, multiple AZs.

#### Automated coverage

Security Hub CSPM **Lambda.3** and **Lambda.5**. Prowler `awslambda_function_inside_vpc` and `awslambda_function_vpc_multi_az`.

#### Detection

VPC Flow Logs on Lambda ENIs (interface type `lambda`) and GuardDuty Lambda Protection findings for suspicious destinations, as covered in the [detection services note](/cloud/aws-detection-posture-services/).

### GT-AWS-LAMBDA-12: Step Functions and edge functions

*Guler Tech methodology.*

#### What it checks

For Step Functions: logging, whether execution data with secrets lands in history and logs, secrets in definitions, and the state machine role. For Lambda@Edge and CloudFront Functions: which distributions use them, what they decide (especially authentication), and the edge function role.

#### Prerequisites

`states:ListStateMachines`, `states:DescribeStateMachine`, `states:ListExecutions`; `cloudfront:ListDistributions`, `cloudfront:ListFunctions`, `cloudfront:DescribeFunction`; `cloudfront:GetFunction` (downloads CloudFront Function code) with approval.

#### Steps

```bash
for sm in $(aws stepfunctions list-state-machines --region eu-west-2 --query 'stateMachines[].stateMachineArn' --output text); do
  aws stepfunctions describe-state-machine --region eu-west-2 --state-machine-arn "$sm" \
    --query '{name: name, type: type, role: roleArn, log: loggingConfiguration.level, data: loggingConfiguration.includeExecutionData, enc: encryptionConfiguration.type}'
  aws stepfunctions describe-state-machine --region eu-west-2 --state-machine-arn "$sm" --query definition --output text \
    | grep -nEi 'password|secret|token|api[_-]?key|authorization' || true
done

# Edge: which distributions run code, and where
aws cloudfront list-distributions --query 'DistributionList.Items[].{id: Id,
  edge: DefaultCacheBehavior.LambdaFunctionAssociations.Items[].[EventType, LambdaFunctionARN],
  cff: DefaultCacheBehavior.FunctionAssociations.Items[].[EventType, FunctionARN]}'
aws cloudfront list-functions --query 'FunctionList.Items[].[Name, Status, FunctionConfig.Runtime]' --output text
```

Cache behaviours other than the default can carry their own associations; check `CacheBehaviors.Items[]` too. Review edge code that makes access decisions (JWT or cookie checks, signed URL logic): algorithm handling, expiry, path normalisation, and whether every cache behaviour that should be protected actually has the association. Check Lambda@Edge roles in `us-east-1` with LAMBDA-6.

#### Observation

Illustrative: state machine `payments-flow` logs at `ALL` with `includeExecutionData: true`; a Task state calls `secretsmanager:GetSecretValue` and passes the `SecretString` to the next state, so the secret appears in execution history and logs. Distribution `E2EXAMPLE` validates a JWT in a viewer-request Lambda@Edge function on the default behaviour, but `/api/*` has its own behaviour without the association.

#### Evaluation

- **Fail (High):** secrets passed through state input/output (readable via `states:GetExecutionHistory` and logs); edge authentication missing on protected paths or bypassable.
- **Fail (Medium):** state machines with logging `OFF` for sensitive workflows (StepFunctions.1); state machine roles with broad permissions; credentials in definitions.
- **Pass:** secrets fetched inside the step that uses them and filtered with `ResultSelector`/`OutputPath` (or JSONata output), logging on with execution data included only where the data is safe, edge auth present on every relevant behaviour.

#### Automated coverage

Security Hub CSPM **StepFunctions.1**. Prowler `stepfunctions_statemachine_logging_enabled`, `stepfunctions_statemachine_no_secrets_in_definition`, `stepfunctions_statemachine_encrypted_with_cmk`.

#### Detection

CloudTrail `UpdateStateMachine`, `CreateStateMachine`, and bulk `GetExecutionHistory`/`DescribeExecution` by unusual principals; for edge, `UpdateDistribution`, `CreateFunction`/`UpdateFunction`/`PublishFunction` (CloudFront Functions) and Lambda `PublishVersion20150331` in `us-east-1`.

## Hardening

**Resource policies.** Grant service principals with both `aws:SourceArn` and `aws:SourceAccount`. Never use `Principal "*"` except for deliberate function URLs, and then pair `InvokeFunction` with `lambda:InvokedViaFunctionUrl`. Prefer `aws:PrincipalOrgID` for organisation-wide access. Remove orphaned statements when URLs or triggers are deleted.

Guardrail SCP (attach to workload OUs; adjust the exception for a break-glass role):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyPublicLambdaPermissions",
      "Effect": "Deny",
      "Action": "lambda:AddPermission",
      "Resource": "*",
      "Condition": { "StringEquals": { "lambda:Principal": "*" } }
    },
    {
      "Sid": "DenyUnauthenticatedFunctionUrls",
      "Effect": "Deny",
      "Action": ["lambda:CreateFunctionUrlConfig", "lambda:UpdateFunctionUrlConfig"],
      "Resource": "*",
      "Condition": { "StringNotEquals": { "lambda:FunctionUrlAuthType": "AWS_IAM" } }
    },
    {
      "Sid": "RequireCodeSigningOnCreate",
      "Effect": "Deny",
      "Action": "lambda:CreateFunction",
      "Resource": "*",
      "Condition": { "Null": { "lambda:CodeSigningConfigArn": "true" } }
    },
    {
      "Sid": "OnlyOrgLayers",
      "Effect": "Deny",
      "Action": ["lambda:CreateFunction", "lambda:UpdateFunctionConfiguration"],
      "Resource": "*",
      "Condition": {
        "ForAnyValue:StringNotLike": {
          "lambda:Layer": [
            "arn:aws:lambda:*:111122223333:layer:*",
            "arn:aws:lambda:*:444455556666:layer:*"
          ]
        }
      }
    }
  ]
}
```

Test SCPs in a sandbox OU first. `lambda:Principal` only constrains `AddPermission`; whole-document `PutResourcePolicy` needs its own review (deny it outright for workload roles if the client does not use it). If some teams legitimately run webhook URLs with `AuthType NONE`, scope the second statement with an exception tag or OU rather than dropping it. RCPs do not cover Lambda at the time of writing (check the [current RCP service list](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_rcps.html)), so SCPs, Access Analyzer and Config are the controls here.

**Function definition in Terraform**, showing the main controls together:

```hcl
resource "aws_lambda_code_signing_config" "prod" {
  allowed_publishers {
    signing_profile_version_arns = [aws_signer_signing_profile.prod.version_arn]
  }
  policies {
    untrusted_artifact_on_deployment = "Enforce"
  }
}

resource "aws_lambda_function" "thumbnailer" {
  function_name                  = "thumbnailer"
  role                           = aws_iam_role.thumbnailer.arn   # dedicated, least-privilege role
  runtime                        = "python3.13"
  handler                        = "app.handler"
  s3_bucket                      = "example-signed-artifacts"
  s3_key                         = "thumbnailer/signed-package.zip"
  code_signing_config_arn        = aws_lambda_code_signing_config.prod.arn
  kms_key_arn                    = aws_kms_key.lambda_env.arn
  reserved_concurrent_executions = 20
  timeout                        = 30
  memory_size                    = 512

  environment {
    variables = {
      SOURCE_SECRET_ARN = aws_secretsmanager_secret.thumbnailer.arn   # a pointer, not a secret
    }
  }

  vpc_config {
    subnet_ids         = [aws_subnet.private_a.id, aws_subnet.private_b.id]
    security_group_ids = [aws_security_group.thumbnailer.id]
  }
}

resource "aws_lambda_permission" "from_uploads" {
  statement_id   = "s3-uploads"
  action         = "lambda:InvokeFunction"
  function_name  = aws_lambda_function.thumbnailer.function_name
  principal      = "s3.amazonaws.com"
  source_arn     = aws_s3_bucket.uploads.arn
  source_account = data.aws_caller_identity.current.account_id
}

resource "aws_lambda_function_url" "report" {
  function_name      = aws_lambda_function.report.function_name
  authorization_type = "AWS_IAM"   # front with CloudFront OAC if browsers need it
}
```

**Secrets.** Move secrets to Secrets Manager or Parameter Store (the AWS Parameters and Secrets Lambda Extension caches them), scope `secretsmanager:GetSecretValue` to the specific secret ARN in the execution role, delete old published versions that contain secrets, and rotate anything that was ever in an environment variable or package. Details are in the [secrets and KMS note](/cloud/aws-secrets-manager-parameter-store-kms/). Narrow who can read configuration: `ViewOnlyAccess` and `SecurityAudit` are not secret-safe while secrets live in environment variables.

**Roles.** One role per function, generated from what the code calls (IAM Access Analyzer policy generation from CloudTrail helps), permission boundaries on roles that developers can create, and no `iam:PassRole` on `*` anywhere near Lambda.

**Code and layers.** CSCs in `Enforce` for production, code deployed only by pipeline roles, layers shared with `--organization-id` instead of `*`, and an allowlist of external layer publishers.

**Event handling.** Validate every event against a schema at the top of the handler (including "internal" sources), avoid shells and dynamic evaluation, use parameterised queries and safe parsers, and make the function idempotent and stateless per invocation. Use tenant isolation mode where one function serves multiple customers' code or data and its constraints fit.

**Runtimes.** Automatic runtime updates, a migration plan at the 180-day notice, and a scheduled rebuild for image functions.

**Cost and availability.** Reserved concurrency on exposed functions, throttling at API Gateway or CloudFront, AWS Budgets and Cost Anomaly Detection with owners, recursion detection left at `Terminate`.

**Detection.** Enable GuardDuty Lambda Protection, Lambda data events in CloudTrail for sensitive functions, and AWS Config rules `lambda-function-public-access-prohibited`, `lambda-function-settings-check` and `lambda-inside-vpc` (the rules behind Lambda.1 to Lambda.3).

## Real-world cases

- **SCARLETEEL (Sysdig, February 2023).** After exploiting a containerised workload and stealing a role's credentials, the attacker enumerated Lambda functions, retrieved code locations with `get-function`, downloaded the packages (proprietary code and the keys needed to run it), and checked environment variables of every version for more credentials. It is the textbook case for LAMBDA-3 and LAMBDA-4: "read-only" Lambda access was worth as much as data access. [Sysdig write-up](https://sysdig.com/blog/cloud-breach-terraform-data-theft/); [Cloud Security Alliance republication with the commands](https://cloudsecurityalliance.org/articles/scarleteel-operation-leveraging-terraform-kubernetes-and-aws-for-data-theft).
- **Denonia (Cado Security, April 2022).** The first publicly reported malware built to run inside Lambda: a Go binary that launched an XMRig Monero miner and used DNS over HTTPS. How it was deployed was never confirmed; the likely route was stolen access keys used to create or update functions, which is what LAMBDA-7 tests. AWS noted it exploited no weakness in Lambda itself. [Malwarebytes summary](https://www.malwarebytes.com/blog/news/2022/04/denonia-cryptominer-is-first-malware-to-target-aws-lambda); [SecurityWeek](https://www.securityweek.com/denonia-first-malware-targeting-aws-lambda).

For deliberately vulnerable practice targets, see the labs listed under [Before you start](#before-you-start); the [incidents and writeups page](/cloud/aws-security-incidents-and-writeups/) collects more cases across the series.

## Rating findings

| Finding | Typical severity | Reasoning |
|---|---|---|
| Event injection reaching command execution, `eval` or deserialisation, from an internet-influenced source, in a function with a powerful role | Critical | Unauthenticated code execution with cloud credentials; account-level blast radius. Drop to High with a minimal role |
| Public `InvokeFunction` or `AuthType NONE` URL on a function that exposes sensitive data or privileged actions without in-code auth | Critical | Unauthenticated internet path to data or actions |
| Public invoke on a function with benign behaviour and a minimal role | Medium | Reachable, but the attacker gains little; cost and availability exposure remain |
| Service principal grant without `aws:SourceArn`/`aws:SourceAccount` | High | Any account can trigger the function with crafted events; Medium when the handler ignores event content |
| Live credentials in environment variables readable by broad roles | High (Critical if the credential grants admin or broad data access) | Any authenticated insider or compromised low-privilege key obtains it; often persists in old versions |
| Hard-coded credentials in code readable via `ReadOnlyAccess` | High | Same reasoning; code access is usually wider than anyone realises |
| Broad `lambda:GetFunction` without secrets found | Medium | IP and logic exposure, latent secret leak |
| Lower-privileged principal can update code of a function with a more privileged role, or `PassRole` + `CreateFunction` | High to Critical | Privilege escalation; Critical when it reaches admin |
| Execution role with admin or escalation permissions, no exposure found | High | One bug or dependency compromise from account takeover |
| Layer shared publicly, or third-party layers from unknown accounts on sensitive functions | Medium (High if secrets or proprietary code) | Exposure or supply-chain risk without a demonstrated exploit |
| No code signing, or CSC in `Warn`, on production | Low to Medium | Defence in depth against pipeline or credential compromise |
| Deprecated runtime | Low to Medium | Unpatched components; High only with a reachable, exploitable vulnerability |
| Secrets in Step Functions execution history or logs | High | Readable by anyone with history or log access, retained long-term |
| Missing concurrency caps and cost alerting on exposed functions | Medium | Denial of wallet and concurrency starvation; High with demonstrable business-critical impact |
| Functions outside a VPC with no internal dependencies; single-AZ VPC functions | Low / Info | Control fails, little security impact on its own |

Lower a level when the account holds no production data or the function is reachable only from a tightly controlled set of principals; raise a level when the function's role spans accounts or the organisation (for example, a role that can assume roles in other accounts).

## Mapping

No CIS AWS Foundations Benchmark recommendation (v1.2.0, v1.4.0, v3.0.0 or v5.0.0, as mapped in Security Hub CSPM) covers Lambda or Step Functions directly, so the CIS column is empty. ATT&CK IDs are Enterprise techniques.

| Test | Security Hub CSPM | CIS | ATT&CK |
|---|---|---|---|
| GT-AWS-LAMBDA-1 | Lambda.1 | — | T1190, T1648, T1078.004 |
| GT-AWS-LAMBDA-2 | Lambda.1, CloudFront.16 | — | T1190 |
| GT-AWS-LAMBDA-3 | — | — | T1552 |
| GT-AWS-LAMBDA-4 | — | — | T1552.001 |
| GT-AWS-LAMBDA-5 | — | — | T1195.002 |
| GT-AWS-LAMBDA-6 | — (IAM.1, IAM.21 at IAM level) | — | T1078.004 |
| GT-AWS-LAMBDA-7 | — | — | T1648 |
| GT-AWS-LAMBDA-8 | Lambda.2 | — | T1190 |
| GT-AWS-LAMBDA-9 | — | — | T1190, T1059 |
| GT-AWS-LAMBDA-10 | — | — | T1496.001, T1499.003 |
| GT-AWS-LAMBDA-11 | Lambda.3, Lambda.5 | — | — |
| GT-AWS-LAMBDA-12 | StepFunctions.1 | — | T1648, T1552 |

## References

AWS documentation:

- [Working with resource-based policies in Lambda](https://docs.aws.amazon.com/lambda/latest/dg/access-control-resource-based.html)
- [Control access to Lambda function URLs](https://docs.aws.amazon.com/lambda/latest/dg/urls-auth.html) and [Creating and managing function URLs](https://docs.aws.amazon.com/lambda/latest/dg/urls-configuration.html)
- [Restrict access to a Lambda function URL origin (CloudFront OAC)](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/private-content-restricting-access-to-lambda.html)
- [Securing Lambda environment variables](https://docs.aws.amazon.com/lambda/latest/dg/configuration-envvars-encryption.html) and [Use Secrets Manager secrets in Lambda](https://docs.aws.amazon.com/lambda/latest/dg/with-secrets-manager.html)
- [GetFunction API](https://docs.aws.amazon.com/lambda/latest/api/API_GetFunction.html)
- [Managing dependencies with layers](https://docs.aws.amazon.com/lambda/latest/dg/chapter-layers.html) and [Granting layer access to other accounts](https://docs.aws.amazon.com/lambda/latest/dg/permissions-layer-cross-account.html)
- [Defining permissions with an execution role](https://docs.aws.amazon.com/lambda/latest/dg/lambda-intro-execution-role.html)
- [Using code signing to verify code integrity](https://docs.aws.amazon.com/lambda/latest/dg/configuration-codesigning.html) and [Lambda code signing with AWS Signer](https://docs.aws.amazon.com/lambda/latest/dg/governance-code-signing.html)
- [Lambda runtimes and deprecation policy](https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html)
- [Execution environment lifecycle](https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtime-environment.html), [Tenant isolation](https://docs.aws.amazon.com/lambda/latest/dg/tenant-isolation.html), [Handling uniqueness with SnapStart](https://docs.aws.amazon.com/lambda/latest/dg/snapstart-uniqueness.html)
- [Recursive loop detection](https://docs.aws.amazon.com/lambda/latest/dg/invocation-recursion.html), [Reserved concurrency](https://docs.aws.amazon.com/lambda/latest/dg/configuration-concurrency.html), [Scaling](https://docs.aws.amazon.com/lambda/latest/dg/lambda-concurrency.html)
- [VPC access for Lambda](https://docs.aws.amazon.com/lambda/latest/dg/configuration-vpc.html)
- [Logging Lambda API calls with CloudTrail](https://docs.aws.amazon.com/lambda/latest/dg/logging-using-cloudtrail.html)
- [Lambda@Edge](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/lambda-at-the-edge.html) and [CloudFront Functions](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/cloudfront-functions.html)
- [Step Functions logging](https://docs.aws.amazon.com/step-functions/latest/dg/cw-logs.html) and [Security in Step Functions](https://docs.aws.amazon.com/step-functions/latest/dg/security.html)
- Security Hub CSPM controls: [Lambda](https://docs.aws.amazon.com/securityhub/latest/userguide/lambda-controls.html), [CloudFront](https://docs.aws.amazon.com/securityhub/latest/userguide/cloudfront-controls.html), [Step Functions](https://docs.aws.amazon.com/securityhub/latest/userguide/stepfunctions-controls.html), [CIS mappings](https://docs.aws.amazon.com/securityhub/latest/userguide/cis-aws-foundations-benchmark.html)
- GuardDuty: [Lambda Protection](https://docs.aws.amazon.com/guardduty/latest/ug/lambda-protection.html), [finding types](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html), [IAM finding types](https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-iam.html)
- [IAM Access Analyzer supported resource types](https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-resources.html)
- [Resource control policies](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_rcps.html)
- [AWS penetration testing policy](https://aws.amazon.com/security/penetration-testing/)

Tools and labs:

- [Prowler](https://github.com/prowler-cloud/prowler), [CloudFox](https://github.com/BishopFox/cloudfox), [Pacu](https://github.com/RhinoSecurityLabs/pacu), [PMapper](https://github.com/nccgroup/PMapper), [cloudsplaining](https://github.com/salesforce/cloudsplaining), [ScoutSuite](https://github.com/nccgroup/ScoutSuite)
- [trufflehog](https://github.com/trufflesecurity/trufflehog), [gitleaks](https://github.com/gitleaks/gitleaks)
- [CloudGoat](https://github.com/RhinoSecurityLabs/cloudgoat), [IAM Vulnerable](https://github.com/BishopFox/iam-vulnerable), [OWASP ServerlessGoat](https://github.com/OWASP/Serverless-Goat), [OWASP DVSA](https://github.com/OWASP/DVSA)

Research:

- [OWASP Top 10 Serverless Interpretation](https://owasp.org/www-project-serverless-top-10/)
- [Sysdig: SCARLETEEL](https://sysdig.com/blog/cloud-breach-terraform-data-theft/)
- [Malwarebytes: Denonia](https://www.malwarebytes.com/blog/news/2022/04/denonia-cryptominer-is-first-malware-to-target-aws-lambda)
