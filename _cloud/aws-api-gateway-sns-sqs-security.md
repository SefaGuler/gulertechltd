---
title: "Amazon API Gateway, SNS and SQS Security"
date: 2026-11-12 18:08:00 +0000
subcategory: aws
summary: "Testing API Gateway authorisers, caching, private APIs and default endpoints, plus SNS topic and SQS queue policies, encryption and DLQs."
refs: [APIGateway.1, APIGateway.2, APIGateway.4, APIGateway.5, APIGateway.8, APIGateway.9, APIGateway.11, SNS.1, SNS.4, SQS.1, SQS.3, EventBridge.3, T1190, T1078.004, T1552, T1537, T1565.001, T1496.003, T1496.004, T1499.003]
tags: [aws, api-gateway, sns, sqs, authorizers, messaging]
---

This note is part of our [AWS security testing guide](/cloud/aws-security-testing-guide/) and covers the services that carry requests and messages into and between serverless workloads: Amazon API Gateway (REST, HTTP and WebSocket APIs), Amazon SNS and Amazon SQS, with a short section on EventBridge buses. They share a theme. Each has an identity-based side (who in the account may manage or use it) and a resource-based side (the API resource policy, the topic policy, the queue policy) that can open it to other accounts or to everyone, and each sits in front of code that tends to trust what arrives. API Gateway adds its own authorisation layer, and most of the interesting findings live there: routes with no authoriser, Lambda authorisers whose cached decisions are reused for requests they never evaluated, JWT authorisers that accept any token from a self-service user pool, private APIs reachable from any VPC endpoint in any account, and the default `execute-api` endpoint quietly bypassing the custom domain where mutual TLS or the WAF lives. On the messaging side, the classic findings are topic and queue policies with `"Principal": "*"`, SNS subscriptions delivering to other accounts or plain HTTP, and dead-letter queues full of sensitive payloads. Below: how each service's security model works, what goes wrong, twelve tests with commands, the guardrails, and how to rate findings. Lambda itself, including event injection in handlers, is in the [Lambda and serverless note](/cloud/aws-lambda-serverless-security/).

## Contents

- [How it works](#how-it-works)
- [What goes wrong](#what-goes-wrong)
- [Testing](#testing)
  - [Before you start](#before-you-start)
  - [GT-AWS-API-1: API inventory and the default execute-api endpoint](#gt-aws-api-1-api-inventory-and-the-default-execute-api-endpoint)
  - [GT-AWS-API-2: Methods and routes without authorisation](#gt-aws-api-2-methods-and-routes-without-authorisation)
  - [GT-AWS-API-3: Lambda authoriser caching and identity sources](#gt-aws-api-3-lambda-authoriser-caching-and-identity-sources)
  - [GT-AWS-API-4: JWT and Cognito authorisers](#gt-aws-api-4-jwt-and-cognito-authorisers)
  - [GT-AWS-API-5: Resource policies and private APIs](#gt-aws-api-5-resource-policies-and-private-apis)
  - [GT-AWS-API-6: Stage settings, logging, caching, throttling and TLS](#gt-aws-api-6-stage-settings-logging-caching-throttling-and-tls)
  - [GT-AWS-API-7: Request validation, CORS and service integrations](#gt-aws-api-7-request-validation-cors-and-service-integrations)
  - [GT-AWS-API-8: SNS topic policies and subscriptions](#gt-aws-api-8-sns-topic-policies-and-subscriptions)
  - [GT-AWS-API-9: SNS encryption, delivery endpoints and SMS abuse](#gt-aws-api-9-sns-encryption-delivery-endpoints-and-sms-abuse)
  - [GT-AWS-API-10: SQS queue policies](#gt-aws-api-10-sqs-queue-policies)
  - [GT-AWS-API-11: SQS encryption, dead-letter queues and redrive](#gt-aws-api-11-sqs-encryption-dead-letter-queues-and-redrive)
  - [GT-AWS-API-12: EventBridge event bus policies](#gt-aws-api-12-eventbridge-event-bus-policies)
- [Hardening](#hardening)
- [Real-world cases](#real-world-cases)
- [Rating findings](#rating-findings)
- [Mapping](#mapping)
- [References](#references)

## How it works

### API Gateway: three products with different security features

API Gateway offers three API types, and you need to know which one you are looking at because their security features differ.

| Feature | REST API (v1) | HTTP API (v2) | WebSocket API (v2) |
|---|---|---|---|
| Endpoint types | Edge-optimised, Regional, Private | Regional | Regional |
| IAM authorisation | Yes | Yes | Yes (on `$connect`) |
| Lambda authorisers | `TOKEN` and `REQUEST` | `REQUEST` (payload 1.0 or 2.0, optional simple responses) | `REQUEST` on `$connect` |
| Cognito / JWT | `COGNITO_USER_POOLS` authoriser | JWT authoriser (any OIDC issuer, including Cognito) | No |
| Resource policies | Yes | No | No |
| AWS WAF | Yes (on the stage) | No | No |
| Mutual TLS | Yes (custom domain) | Yes (custom domain) | No |
| API keys and usage plans | Yes | No | No |
| Request validation | Yes | No | No |
| Execution logs | Yes | No | Yes |
| Response caching | Yes | No | No |

The management plane uses IAM actions named after HTTP verbs (`apigateway:GET`, `apigateway:POST`, `apigateway:PATCH`, `apigateway:PUT`, `apigateway:DELETE`) on resource ARNs such as `arn:aws:apigateway:eu-west-2::/restapis/*`. Calling an API uses `execute-api:Invoke` on ARNs of the form `arn:aws:execute-api:region:account:api-id/stage/METHOD/path`. WebSocket backends push messages to clients through the `@connections` management API, authorised by `execute-api:ManageConnections`. The Service Authorization Reference defines condition keys that make guardrails possible, including `apigateway:Request/RouteAuthorizationType` (`NONE`, `AWS_IAM`, `CUSTOM`, `JWT`), `apigateway:Request/AuthorizerType`, `apigateway:Request/EndpointType` and `apigateway:Request/DisableExecuteApiEndpoint`.

### Authorisation types

Every REST method has an `authorizationType` (`NONE`, `AWS_IAM`, `CUSTOM` for Lambda authorisers, `COGNITO_USER_POOLS`), and every HTTP or WebSocket route has an `AuthorizationType` (`NONE`, `AWS_IAM`, `CUSTOM`, `JWT`). `NONE` means API Gateway lets the request through to the integration; the backend is then the only control. On WebSocket APIs only the `$connect` route can carry an authoriser, and every later message on the connection is trusted on the strength of that handshake.

**IAM** (`AWS_IAM`) requires SigV4-signed requests and evaluates the caller's identity policy and, on REST APIs, the API's resource policy. It suits service-to-service calls and is the strongest option when the callers are AWS principals.

**Lambda authorisers** run your function with the request's identity sources and get back an IAM-style policy (`principalId`, `policyDocument`, optional `context`), or, for HTTP APIs with simple responses, `{"isAuthorized": true|false}`. The key security property is **caching**. On REST APIs, `authorizerResultTtlInSeconds` defaults to **300 seconds** when not set (maximum 3,600; 0 disables caching). The cache key is the identity source: for a `TOKEN` authoriser, the token header; for a `REQUEST` authoriser, all configured identity sources in order. AWS's own guidance is blunt: when caching is on, the returned policy is reused for later requests with the same key, so "ensure that your policy is applicable to all resources and methods across your API." For HTTP APIs, AWS documents that the cached response is used **for all routes that use the authoriser** unless you add `$context.routeKey` to the identity sources, and that a cached simple response "fully allows or denies all API requests that match the cached identity source values." With caching enabled, a missing identity source makes API Gateway return 401 without calling the authoriser; with caching disabled on a REST `REQUEST` authoriser, every request is passed to the function.

That gives two opposite failure modes, both common:

- The authoriser returns a policy scoped to the requested `methodArn` (correct in isolation), and caching makes the *first* decision stick: the user is denied on every other path for five minutes. Developers "fix" this by returning `execute-api:Invoke` on `*` or `arn:aws:execute-api:*:*:*`.
- The authoriser makes a **per-resource** decision (can this user read order 42? is this caller an admin for `/admin/*`?) but the cache key is only the token. The first allowed request caches an `Allow` that the gateway then applies to requests for other resources, methods or tenants with the same token within the TTL. That is an authorisation bypass created entirely by configuration: the function is correct, the cache is not keyed on what the function decided about.

**JWT authorisers** (HTTP APIs) validate a token against an issuer's JWKS: signature (RSA algorithms only), `kid`, `iss` equal to the configured issuer, `aud` (or `client_id` when `aud` is absent) matching a configured audience, `exp`, `nbf`, `iat`, and, if the route has `AuthorizationScopes`, at least one matching `scope`/`scp`. AWS notes there is no standard way to tell an access token from an OpenID Connect ID token and recommends requiring scopes. A JWT authoriser proves who the caller is, not what they may do: if the issuer is a Cognito user pool with self-registration, anyone on the internet can obtain a valid token.

**Cognito authorisers** (REST `COGNITO_USER_POOLS`) behave similarly: if a method has no authorisation scopes, API Gateway treats the token as an **ID token**; with scopes, it requires an **access token** with a matching scope. The [Cognito note](/cloud/aws-cognito-security/) covers user pools themselves.

**API keys are not authentication.** AWS says so explicitly: do not use API keys for authentication or authorisation; a valid key for one API in a usage plan works for every API in that plan; keys travel in headers that get logged; and usage plan throttling and quotas are best-effort, not hard limits or a cost control. API key values can also be read back by anyone with `apigateway:GET` on the key resources (the `get-api-keys --include-values` call), a permission that `SecurityAudit`, `ViewOnlyAccess` and `ReadOnlyAccess` all include at the time of writing.

### Endpoints, custom domains and the default endpoint

Every REST, HTTP and WebSocket API gets a default endpoint, `https://{api-id}.execute-api.{region}.amazonaws.com/{stage}`. Teams then add a custom domain (with a TLS security policy, optionally mutual TLS) and often put CloudFront and AWS WAF in front. **The default endpoint stays live unless you disable it** (`disableExecuteApiEndpoint`, which for REST APIs takes effect on the next stage update or deployment). Anything enforced only at the custom domain or in front of it is bypassed through the default endpoint:

- **Mutual TLS** is a property of the custom domain. AWS's mTLS documentation says that to ensure clients can only reach the API through the mTLS domain, you must disable the default endpoint. API Gateway also does not check certificate revocation itself; that needs a Lambda authoriser.
- **WAF on CloudFront** (the usual pattern for HTTP APIs, which cannot have a WAF of their own, and for REST APIs fronted by a distribution) does not see requests to the default endpoint. A WAF web ACL associated with a REST API *stage* does apply on both hostnames.
- **Origin-verification headers** (CloudFront adds a secret header the backend checks) only help if the backend or authoriser actually rejects requests without it.
- **Base path mappings** can expose a different stage, or a stage without the path-based rules the domain enforced.

Edge-optimised REST APIs are fronted by an AWS-managed CloudFront distribution you cannot attach your own WAF to (the stage-level WAF still applies). Regional APIs are reached directly. **Private** REST APIs are reached only through an interface VPC endpoint for `execute-api`.

### Resource policies and private APIs

REST APIs (only) can carry a resource policy evaluated alongside the authorisation type. Typical uses: allow only certain source IPs (`aws:SourceIp`), allow only certain VPCs or VPC endpoints (`aws:SourceVpc`, `aws:SourceVpce`), allow other accounts' IAM principals. A **private API cannot be deployed without a resource policy**, and AWS warns that such a policy can grant access to a VPC endpoint **in any AWS account**: a private API whose policy allows `Principal "*"` to `execute-api:Invoke` with no `aws:SourceVpce`/`aws:SourceVpc` condition is reachable by anyone who creates an `execute-api` endpoint in their own VPC and sends the API ID in the `x-apigw-api-id` header (or uses the API's VPC endpoint-specific DNS name). "Private" here describes the network path, not who may use it. VPC endpoint policies on the client's own endpoints are a second, independent control in the other direction (which APIs the VPC may call).

### Stages, logging and caching

Settings live on the **stage**: throttling (stage and method level), execution logging (`loggingLevel` `OFF`, `ERROR`, `INFO`) and **data tracing** (`dataTraceEnabled`, full request and response bodies), access logging (a format of `$context` variables you choose, sent to CloudWatch Logs or Firehose), X-Ray, the WAF association, a client certificate for backend authentication, stage variables, and the response cache. AWS redacts authorisation headers and API key values in execution logs, but data tracing logs bodies, and AWS recommends not enabling it for production APIs. Execution logs go to a managed log group named `API-Gateway-Execution-Logs_{rest-api-id}/{stage_name}` (or, with the newer CloudWatch Logs delivery, to destinations you choose). Who can read those logs is a data-exposure question covered in the [CloudWatch and EventBridge note](/cloud/aws-cloudwatch-eventbridge-monitoring/).

The REST response cache (TTL default 300 seconds, maximum 3,600) caches `GET` methods by default, keyed on the method's cache key parameters. **If a method returns per-user data and the user's identity is not in the cache key, user B receives user A's cached response.** Clients can bypass the cache with `Cache-Control: max-age=0`; unless "require authorisation" is set (an `execute-api:InvalidateCache` permission check), any client can force cache refreshes. Cache data can be encrypted at rest (Security Hub CSPM **APIGateway.5**).

Stage variables are plain configuration readable through the management API. They are used in integration URIs and Lambda function names, and sometimes misused for secrets.

### Amazon SNS

A topic has an **access policy** (resource policy) controlling `sns:Publish`, `sns:Subscribe`, `sns:Receive`, `sns:SetTopicAttributes`, `sns:AddPermission` and so on. SNS-specific condition keys are `sns:Protocol` and `sns:Endpoint` (restrict what may subscribe, for example HTTPS only, or only endpoints in your domain). For services publishing to a topic (S3, CloudWatch alarms, EventBridge, CodeCommit and others), the policy should use `aws:SourceArn` and/or `aws:SourceAccount`; AWS documents `aws:SourceOwner` as deprecated for new integrations. AWS's own documentation states that SNS does not grant other accounts or services access to a new topic by default. Topics created through the console or SDK commonly carry a `__default_policy_ID` statement with `Principal {"AWS": "*"}` limited by an `AWS:SourceOwner` condition equal to the owning account; treat it as account-scoped, even though naive scanners flag the wildcard.

**Subscriptions** connect a topic to endpoints: SQS queues, Lambda functions, HTTP/HTTPS URLs, email, SMS, mobile push, Firehose. A subscription can point to a resource in **another account**, and anyone with `sns:Subscribe` on the topic can create one. HTTP(S) and email endpoints must confirm the subscription; an attacker who owns the endpoint simply confirms. SNS signs messages it delivers to HTTP(S) endpoints; `SignatureVersion` 1 uses SHA1 and 2 uses SHA256 (recommended), and the receiving endpoint is responsible for verifying the signature and the certificate URL. Delivery to plain `http` endpoints sends message content unencrypted.

**Encryption at rest:** SNS stores messages with disk encryption by default. Server-side encryption with KMS (SSE, `KmsMasterKeyId`) is opt-in and encrypts message bodies only, not topic metadata, message attributes, subject or metrics. Security Hub CSPM **SNS.1** checks for KMS SSE. Topics used by services such as CloudWatch alarms or S3 notifications need a customer managed key whose policy lets that service use it; the AWS managed `alias/aws/sns` key cannot be given to them. **Message data protection** (managed data identifiers to audit, mask or deny sensitive data in messages) is, at the time of writing, no longer available to new customers, so do not recommend it as a new control.

### Amazon SQS

A queue has a **queue policy**. `Principal "*"` without conditions opens `sqs:SendMessage`, `sqs:ReceiveMessage`, `sqs:DeleteMessage` or worse to any AWS account, and SQS even accepts **anonymous** (unsigned) requests to a queue whose policy allows them, unless the queue uses server-side encryption, in which case anonymous `SendMessage` and `ReceiveMessage` are rejected. The SNS-to-SQS pattern needs a queue policy allowing `sns.amazonaws.com` to send, and that statement must carry `aws:SourceArn` equal to the topic ARN, or any topic in any account can inject messages.

**Encryption:** since October 2022, new queues get **SSE-SQS** (SQS-managed keys) by default, except queues created through the non-TLS HTTP endpoint. **SSE-KMS** uses a KMS key, giving key-policy control and CloudTrail visibility of key use. SSE encrypts message bodies, not queue names, queue attributes, message IDs, timestamps or message attributes. Messages are encrypted only if sent after encryption was enabled, and a message keeps its encryption state when moved to a dead-letter queue. Security Hub CSPM **SQS.1** passes with either SSE-SQS or SSE-KMS. A queue encrypted with the AWS managed `alias/aws/sqs` key cannot invoke a Lambda function in another account.

**Dead-letter queues (DLQs)** receive messages that failed processing `maxReceiveCount` times (`RedrivePolicy` on the source queue). `RedriveAllowPolicy` on the DLQ controls which source queues may use it (`allowAll`, `denyAll`, `byQueue`). Retention can be up to 14 days. DLQs routinely hold the exact payloads that broke a consumer: full orders, personal data, tokens. They often have looser policies, longer retention and no consumer monitoring. Lambda's own asynchronous-invocation DLQs and on-failure destinations (SQS or SNS) receive complete event payloads in the same way.

### EventBridge buses

Custom event buses (and the default bus) can carry resource policies allowing other accounts or the organisation to `events:PutEvents`, and rules route events to Lambda, SQS, SNS and other targets. An over-broad bus policy is an event-injection path into every target, similar to a public SNS topic. Security Hub CSPM **EventBridge.3** expects custom buses to have a resource policy at all (no policy means any principal in the account with `events:PutEvents` permission can publish). Monitoring uses of EventBridge are in the [CloudWatch and EventBridge note](/cloud/aws-cloudwatch-eventbridge-monitoring/).

### Analysis tooling that understands these policies

IAM Access Analyzer external access analysers cover SNS topics and SQS queues (not API Gateway or EventBridge). The `CheckNoPublicAccess` API checks a policy document you supply against a resource type, including `AWS::ApiGateway::RestApi`, `AWS::SNS::Topic`, `AWS::SQS::Queue` and `AWS::Lambda::Function`, which is a clean, read-only way to evidence "this policy is public" without touching the resource. Resource control policies (RCPs) support `sns`, `sqs` and `events` at the time of writing, but not API Gateway.

## What goes wrong

**Routes and methods with `NONE`.** An HTTP API `$default` route or a REST `ANY /{proxy+}` method with no authoriser sends every unmatched path to the backend unauthenticated. Teams add an authoriser to the routes they know about and forget the catch-all, a new route, or an `OPTIONS` method that does more than CORS.

**API keys used as authentication.** `apiKeyRequired: true` with `authorizationType: NONE`. The key is shipped in a mobile app or SPA, shared between customers through one usage plan, and readable by every principal with `apigateway:GET`.

**Authoriser cache confusion.** Per-resource or per-tenant decisions cached on a token-only key (bypass), or wildcard policies returned to avoid cached denials (the authoriser stops authorising anything but identity). Long TTLs extend the window after token revocation, user deactivation or permission changes.

**Weak authoriser code.** Lambda authorisers that return `Allow` on exceptions, decode JWTs without verifying signatures, accept `alg: none` or the wrong key, skip `aud`/`iss` checks, or trust a header the client controls. These are covered as application bugs by the general API testing approach; here you mainly confirm where authorisation lives.

**JWT authorisers without scopes, on self-service user pools.** Any registered user (and anyone can register) can call every route that only checks token validity; ID tokens are accepted where access tokens were intended.

**Default endpoint left enabled.** mTLS, CloudFront WAF rules, geo-blocking, CloudFront-only authentication (signed cookies, edge functions) and custom-domain base path restrictions are all bypassed by calling `{api-id}.execute-api...` directly. API IDs are not secrets: they leak through client code, mobile apps, logs and error pages.

**Private API reachable from any account.** A resource policy that allows `execute-api:Invoke` to `*` without `aws:SourceVpce`/`aws:SourceVpc`.

**Logs that hold the data.** Data tracing on in production; access log formats that include tokens or personal data through `$context.authorizer.*` or custom headers; log groups readable by many and kept forever.

**Shared response cache keyed without the user.** Per-user `GET` responses cached for every caller who hits the same path within the TTL, a cross-user data leak with no attacker effort at all.

**No throttling where it matters.** No stage or method throttling, no WAF rate-based rules, Lambda integrations without reserved concurrency, so one client can exhaust account-level throttling or run up cost. Usage plans are not a hard limit.

**Missing request validation and over-broad service integrations.** REST APIs that proxy straight to AWS services (S3, DynamoDB, SQS, Step Functions) with an integration role far broader than the method needs, and mapping templates that let path or body parameters choose the bucket, key, table or queue.

**Public SNS topics.** `sns:Subscribe` open to everyone lets an attacker receive every message published to the topic by subscribing their own SQS queue or HTTPS endpoint (data exfiltration to their own account). `sns:Publish` open to everyone lets them inject messages into every subscriber: Lambda functions, queues, email and SMS recipients who trust the sender. `sns:SetTopicAttributes`/`sns:AddPermission` open to everyone is a full takeover of the topic.

**Service-to-topic and topic-to-queue grants without source conditions.** `sns.amazonaws.com` allowed to `sqs:SendMessage` without `aws:SourceArn`; `s3.amazonaws.com` allowed to `sns:Publish` without `aws:SourceAccount`. Any account's topic or bucket can then deliver into the client's pipeline.

**Unknown subscribers.** Cross-account SQS or Lambda subscriptions nobody can explain, `http://` endpoints, email subscriptions to personal or third-party addresses.

**SMS abuse with compromised credentials.** Attackers with stolen keys check whether the account can send SMS through SNS (out of the SMS sandbox, spend limit raised) and use it for smishing or SMS pumping at the client's expense.

**Public or cross-account queues.** `sqs:ReceiveMessage` to `*` (read and consume other people's messages, disrupting processing), `sqs:SendMessage` to `*` (inject work items, poison consumers), `sqs:*` to `*`.

**DLQs as data stores.** Sensitive failed messages kept for 14 days in queues with broad access, no alarms on depth, and `RedriveAllowPolicy` `allowAll`.

**"Read-only" roles that consume messages.** `ReadOnlyAccess` includes `sqs:Receive*`. `ReceiveMessage` is not read-only in effect: it hides the message from real consumers for the visibility timeout and returns its body.

## Testing

Every test assumes an **authorised** engagement against the client's own AWS accounts, with written scope, and respects the [AWS penetration testing policy](https://aws.amazon.com/security/penetration-testing/). Configuration checks are read-only. HTTP requests to the client's APIs, subscribing to topics, sending or receiving messages are marked and run only with explicit approval, against agreed test endpoints and test data. Output is **illustrative**: we ran nothing against AWS to produce it, and account IDs are AWS's documentation examples.

### Before you start

**Permissions.** `SecurityAudit` covers the reads here (`apigateway:GET`, `sns:GetTopicAttributes`, `sns:ListSubscriptionsByTopic`, `sqs:GetQueueAttributes`, `sqs:ListQueues`, `events:DescribeEventBus`). Add `access-analyzer:CheckNoPublicAccess` and `access-analyzer:ListFindings` for policy evidence, and `iam:SimulatePrincipalPolicy`. Note that `SecurityAudit` can read API key values and stage variables: treat that output as client secrets. Do **not** use a role with `sqs:ReceiveMessage` to "look" at queues.

**Region loop and inventory.**

```bash
export AWS_PROFILE=client-audit
REGIONS=$(aws ec2 describe-regions --query 'Regions[].RegionName' --output text)
mkdir -p out/api
for r in $REGIONS; do
  aws apigateway get-rest-apis --region "$r" --output json > "out/api/rest-$r.json"
  aws apigatewayv2 get-apis --region "$r" --output json > "out/api/v2-$r.json"
  aws sns list-topics --region "$r" --query 'Topics[].TopicArn' --output text | tr '\t' '\n' > "out/api/topics-$r.txt"
  aws sqs list-queues --region "$r" --query 'QueueUrls' --output text | tr '\t' '\n' > "out/api/queues-$r.txt"
done
wc -l out/api/topics-*.txt out/api/queues-*.txt | tail -1
```

ACM certificates for edge-optimised custom domains live in `us-east-1`; keep it in the loop.

**Tools.**

- [Prowler](https://github.com/prowler-cloud/prowler): `prowler aws --services apigateway apigatewayv2 sns sqs eventbridge`.
- [CloudFox](https://github.com/BishopFox/cloudfox): `api-gws` (every API endpoint with its auth type), `sns`, `sqs` and `resource-trusts` commands.
- [Pacu](https://github.com/RhinoSecurityLabs/pacu): `apigateway__enum` and `sns__enum` are read-only enumeration. `sns__subscribe` and `api_gateway__create_api_keys` change state; lab only.
- IAM Access Analyzer findings for SNS and SQS, and `aws accessanalyzer check-no-public-access` for any policy you extract.
- Steampipe tables `aws_api_gateway_rest_api`, `aws_sns_topic` and `aws_sqs_queue` expose `policy_std` (normalised policies) for SQL triage.
- Burp Suite or plain `curl` for the few approved HTTP checks.

### GT-AWS-API-1: API inventory and the default execute-api endpoint

*Guler Tech methodology.*

#### What it checks

Every API's type and endpoint configuration, which custom domains map to it, and whether the default `execute-api` endpoint is still enabled where controls (mTLS, CloudFront WAF, edge authentication) live only on the custom domain or in front of it.

#### Prerequisites

`apigateway:GET` (covers v1 and v2 reads), `cloudfront:ListDistributions`.

#### Steps

```bash
for r in $REGIONS; do
  jq -r --arg r "$r" '.items[]? | [$r, "REST", .id, .name, (.endpointConfiguration.types | join(",")), (.disableExecuteApiEndpoint // false)] | @tsv' "out/api/rest-$r.json"
  jq -r --arg r "$r" '.Items[]? | [$r, .ProtocolType, .ApiId, .Name, "REGIONAL", (.DisableExecuteApiEndpoint // false)] | @tsv' "out/api/v2-$r.json"
done | tee out/api/apis.tsv

# Custom domains and what they map to
aws apigateway get-domain-names --region eu-west-2 \
  --query 'items[].[domainName, securityPolicy, endpointConfiguration.types[0], mutualTlsAuthentication.truststoreUri]' --output text
aws apigateway get-base-path-mappings --region eu-west-2 --domain-name api.example.com \
  --query 'items[].[basePath, restApiId, stage]' --output text
aws apigatewayv2 get-domain-names --region eu-west-2 \
  --query 'Items[].[DomainName, DomainNameConfigurations[0].SecurityPolicy, MutualTlsAuthentication.TruststoreUri]' --output text
aws apigatewayv2 get-api-mappings --region eu-west-2 --domain-name app.example.com \
  --query 'Items[].[ApiMappingKey, ApiId, Stage]' --output text

# CloudFront distributions with execute-api origins (WAF and edge auth live here)
aws cloudfront list-distributions --query \
  'DistributionList.Items[].[Id, WebACLId, join(`,`, Origins.Items[?contains(DomainName, `execute-api`)].DomainName)]' --output text
```

Join the three views: for each API reached through a custom domain with mTLS, or through CloudFront with a WAF or edge authentication, is `disableExecuteApiEndpoint` true?

**Explicitly approved only:** demonstrate the bypass with one benign request to an agreed health or test path, once through the protected route and once directly:

```bash
curl -s -o /dev/null -w 'custom domain without client cert: %{http_code}\n' https://api.example.com/v1/health
curl -s -o /dev/null -w 'default endpoint:                  %{http_code}\n' \
  https://a1b2c3d4e5.execute-api.eu-west-2.amazonaws.com/prod/v1/health
```

#### Observation

Illustrative:

```text
eu-west-2  REST  a1b2c3d4e5  partner-api   REGIONAL  false
eu-west-2  HTTP  f6g7h8i9j0  web-backend   REGIONAL  false
api.example.com  TLS_1_2  REGIONAL  s3://example-truststore/partners.pem
E2EXAMPLE  arn:aws:wafv2:us-east-1:111122223333:global/webacl/edge/EXAMPLE  f6g7h8i9j0.execute-api.eu-west-2.amazonaws.com
custom domain without client cert: 000   (TLS handshake refused)
default endpoint:                  200
```

#### Evaluation

- **Fail (High, Critical when mTLS or edge auth is the only authentication):** mTLS on the custom domain, or authentication enforced at CloudFront, while the default endpoint is enabled and the API methods themselves have no other authorisation.
- **Fail (Medium):** WAF or rate limiting only on CloudFront with the default endpoint enabled (protections bypassable, authentication intact).
- **Fail (Low):** custom-domain APIs with the default endpoint enabled but no control that depends on the domain.
- **Pass:** `disableExecuteApiEndpoint: true` wherever a custom domain or CloudFront is the intended entry point, or controls that do not depend on the hostname (stage WAF, method authorisers, resource policies).

#### Automated coverage

No Security Hub CSPM control for the default endpoint. **APIGateway.4** (WAF on the stage) and **APIGateway.11** (domain TLS policy) are related. Prowler `apigateway_restapi_waf_acl_attached`; `apigateway_restapi_public` and `apigateway_restapi_public_with_authorizer` for exposure.

#### Detection

CloudTrail `UpdateRestApi` and `UpdateApi` with `disableExecuteApiEndpoint` changes, `CreateDeployment`, `CreateBasePathMapping`/`CreateApiMapping`. Traffic to the default endpoint is only visible in access logs (log `$context.domainName` so you can tell the hostnames apart; see GT-AWS-API-6).

### GT-AWS-API-2: Methods and routes without authorisation

*Guler Tech methodology.*

#### What it checks

Every REST method and every HTTP/WebSocket route with `NONE` authorisation, catch-all routes, and methods protected only by API keys.

#### Prerequisites

`apigateway:GET`.

#### Steps

REST APIs (methods are embedded per resource):

```bash
for id in $(jq -r '.items[]?.id' out/api/rest-eu-west-2.json); do
  aws apigateway get-resources --region eu-west-2 --rest-api-id "$id" --embed methods --limit 500 --output json \
  | jq -r --arg id "$id" '.items[] | .path as $p | (.resourceMethods // {}) | to_entries[]
      | [$id, .key, $p, .value.authorizationType, (.value.apiKeyRequired | tostring), (.value.authorizerId // "-")] | @tsv'
done | tee out/api/rest-methods.tsv

awk -F'\t' '$4 == "NONE" && $2 != "OPTIONS"' out/api/rest-methods.tsv
awk -F'\t' '$4 == "NONE" && $5 == "true"' out/api/rest-methods.tsv      # API key is the only gate
grep -P '\{proxy\+\}|\tANY\t' out/api/rest-methods.tsv                    # catch-alls
```

HTTP and WebSocket APIs:

```bash
for id in $(jq -r '.Items[]?.ApiId' out/api/v2-eu-west-2.json); do
  aws apigatewayv2 get-routes --region eu-west-2 --api-id "$id" \
    --query 'Items[].[RouteKey, AuthorizationType, AuthorizerId, ApiKeyRequired]' --output text | sed "s/^/$id\t/"
done | tee out/api/v2-routes.tsv
awk -F'\t' '$3 == "NONE"' out/api/v2-routes.tsv
```

Interpretation rules: `OPTIONS` with `NONE` is normal for CORS preflight if its integration is a mock returning headers only. On WebSocket APIs, only `$connect` can have an authoriser, so `NONE` on `$default`, `$disconnect` and custom routes is expected; check `$connect`. An HTTP API `$default` route is the catch-all.

For each `NONE` method, find out from the client (or the integration code) whether the backend authenticates itself. **Explicitly approved only:** confirm with one unauthenticated request to a non-destructive method.

#### Observation

Illustrative:

```text
a1b2c3d4e5  GET     /v1/orders/{id}     COGNITO_USER_POOLS  false  x1y2z3
a1b2c3d4e5  GET     /v1/internal/export NONE                true   -
a1b2c3d4e5  ANY     /{proxy+}           NONE                false  -
f6g7h8i9j0  $default  NONE  -  False
```

#### Evaluation

- **Fail (Critical to High):** `NONE` on methods or catch-all routes that reach non-public data or state-changing actions without backend authentication; `$connect` without an authoriser on a WebSocket API that pushes user data.
- **Fail (High):** API key as the only control on sensitive methods (`NONE` plus `apiKeyRequired`), especially where the key ships in a client application. See also the mobile note on [keys in app packages](/mobile/maswe-0004-sensitive-data-hardcoded-app-package/).
- **Pass:** every non-public route has an authorisation type, catch-alls are either authorised or return 404, and public routes are deliberate and documented.

#### Automated coverage

Security Hub CSPM **APIGateway.8** (HTTP and WebSocket routes should specify an authorisation type; Config rule `api-gwv2-authorization-type-configured`). Prowler `apigateway_restapi_authorizers_enabled` and `apigatewayv2_api_authorizers_enabled` (both check that authorisers exist, not that every method uses one).

#### Detection

CloudTrail `PutMethod`, `UpdateMethod`, `CreateRoute`, `UpdateRoute` with authorisation type `NONE`, and `CreateDeployment` that publishes them. Unauthenticated access shows in access logs as requests with an empty `$context.identity.*`/`$context.authorizer.principalId`.

### GT-AWS-API-3: Lambda authoriser caching and identity sources

*Guler Tech methodology.*

#### What it checks

For every Lambda authoriser: its type, identity sources, TTL, and whether the decision it makes depends on anything outside the cache key. This is the configuration-driven authorisation bypass described in [How it works](#how-it-works).

#### Prerequisites

`apigateway:GET`; the authoriser function code (from the client, or `lambda:GetFunction` with approval, see the [Lambda note](/cloud/aws-lambda-serverless-security/)).

#### Steps

```bash
aws apigateway get-authorizers --region eu-west-2 --rest-api-id a1b2c3d4e5 \
  --query 'items[].[id, name, type, identitySource, authorizerResultTtlInSeconds, identityValidationExpression]' --output table

aws apigatewayv2 get-authorizers --region eu-west-2 --api-id f6g7h8i9j0 \
  --query 'Items[].[AuthorizerId, Name, AuthorizerType, join(`,`, IdentitySource || `[]`), AuthorizerResultTtlInSeconds, EnableSimpleResponses, AuthorizerPayloadFormatVersion]' --output table
```

`authorizerResultTtlInSeconds` absent on a REST authoriser means **300**. Then read the authoriser function and answer three questions:

1. **What does the decision depend on?** List every input: token claims, `methodArn`/`routeArn` (method and path), path parameters, query strings, tenant or account headers, stage variables, source IP.
2. **What is the cache key?** The identity sources above. For HTTP APIs, is `$context.routeKey` among them?
3. **What does it return?** A policy scoped to the exact `methodArn`, a wildcard (`*`, `arn:aws:execute-api:*:*:*`, `.../*/*`), a list of resources the principal may access, or a simple `isAuthorized` boolean.

The vulnerable combination is: the decision depends on an input that is **not** in the cache key **and** the returned allow covers more than the evaluated request (a wildcard policy, or a simple response). The broken-but-safe combination is a `methodArn`-scoped policy with token-only caching: users see spurious 403s on second paths (and someone will "fix" it).

**Explicitly approved only, with two test users or tenants the client provides:** with token A, request a resource A is allowed to read; within the TTL, request with the same token a resource only B may read, using a read-only method:

```bash
TOKEN_A='<test-user-A-token>'
curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $TOKEN_A" https://api.example.com/v1/tenants/tenant-a/report
curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $TOKEN_A" https://api.example.com/v1/tenants/tenant-b/report
```

A 200 on the second request that becomes 403 after the TTL expires (or with caching disabled in a test stage) proves the cache, not the function, granted access. Check that the backend does not perform its own tenant check before you conclude the data was exposed.

#### Observation

Illustrative:

```text
|  x1y2z3 | tenant-authz | REQUEST | method.request.header.Authorization | None | None |
```

Authoriser code (Python, simplified):

```python
def handler(event, context):
    claims = verify_jwt(event["headers"]["authorization"])
    tenant = event["pathParameters"]["tenantId"]           # decision input not in the cache key
    effect = "Allow" if tenant in claims["tenants"] else "Deny"
    statement = {
        "Action": "execute-api:Invoke",
        "Effect": effect,
        "Resource": "arn:aws:execute-api:*:*:*",   # wildcard: one Allow covers every path
    }
    policy = {"Version": "2012-10-17", "Statement": [statement]}
    return {"principalId": claims["sub"], "policyDocument": policy}
```

TTL unset (300 seconds), identity source is only the `Authorization` header, decision depends on `tenantId`, and the policy is a wildcard: a user of tenant A gets five minutes of access to every tenant after one legitimate call.

#### Evaluation

- **Fail (High, Critical where it crosses tenants or reaches admin functions):** a per-resource, per-method or per-tenant decision with a cache key that omits that input and a returned allow that covers other resources.
- **Fail (Medium):** wildcard allows from an authoriser that is meant to enforce more than authentication, even with caching off (the authoriser is not doing the job its name implies); TTLs at or near 3,600 seconds where token revocation or permission changes must take effect quickly.
- **Fail (Low):** `methodArn`-scoped policies with token-only caching (availability bug that invites an insecure fix); `TOKEN` authorisers without an `identityValidationExpression` (more authoriser invocations, no direct security impact).
- **Pass:** the cache key includes every decision input (for HTTP APIs, `$context.routeKey` and relevant parameters; for REST `REQUEST` authorisers, the relevant headers, query strings and context variables), or caching is disabled, or the authoriser only authenticates and fine-grained authorisation happens in the backend.

#### Automated coverage

None. Prowler and Security Hub CSPM confirm that authorisers exist, not that they are cached safely. This test needs a human and the code.

#### Detection

CloudTrail `CreateAuthorizer`, `UpdateAuthorizer` (TTL and identity source changes). Execution logs at `INFO` show authoriser invocations and cache use; access logs can include `$context.authorizer.principalId` and the requested path, which is how you spot one principal reaching many tenants' paths.

### GT-AWS-API-4: JWT and Cognito authorisers

*Guler Tech methodology.*

#### What it checks

That JWT authorisers pin the right issuer and audiences, that routes needing authorisation require scopes, that Cognito authorisers do not accept ID tokens where access tokens with scopes were intended, and whether anyone can self-register for a valid token.

#### Prerequisites

`apigateway:GET`, `cognito-idp:DescribeUserPool`, `cognito-idp:DescribeUserPoolClient`.

#### Steps

```bash
# HTTP API JWT authorisers
aws apigatewayv2 get-authorizers --region eu-west-2 --api-id f6g7h8i9j0 \
  --query 'Items[?AuthorizerType==`JWT`].[AuthorizerId, JwtConfiguration.Issuer, join(`,`, JwtConfiguration.Audience)]' --output text
# Routes using them, and their scopes
aws apigatewayv2 get-routes --region eu-west-2 --api-id f6g7h8i9j0 \
  --query 'Items[?AuthorizationType==`JWT`].[RouteKey, join(`,`, AuthorizationScopes || `[]`)]' --output text

# REST Cognito authorisers and per-method scopes
aws apigateway get-authorizers --region eu-west-2 --rest-api-id a1b2c3d4e5 \
  --query 'items[?type==`COGNITO_USER_POOLS`].[id, join(`,`, providerARNs), identityValidationExpression]' --output text
aws apigateway get-method --region eu-west-2 --rest-api-id a1b2c3d4e5 --resource-id r4s5t6 --http-method GET \
  --query '[authorizationType, authorizerId, authorizationScopes]'

# Can anyone sign up to the issuing user pool?
aws cognito-idp describe-user-pool --user-pool-id eu-west-2_EXAMPLE \
  --query 'UserPool.AdminCreateUserConfig.AllowAdminCreateUserOnly'
```

`false` for `AllowAdminCreateUserOnly` means self-registration is enabled. For a non-Cognito issuer, find out from the client who can obtain tokens with that issuer and audience (every employee? every customer of every product using the same IdP tenant?).

#### Observation

Illustrative: the JWT authoriser trusts `https://cognito-idp.eu-west-2.amazonaws.com/eu-west-2_EXAMPLE` with audience `3exampleclientid`; 14 routes have no scopes, including `DELETE /v1/accounts/{id}`; the user pool allows self-registration; the backend for that route does not compare `{id}` with the token's `sub`.

#### Evaluation

- **Fail (High to Critical):** routes that perform privileged or cross-user actions protected only by "has a valid token" from an issuer anyone can obtain tokens from, without backend authorisation (rate by the action; this is the cloud-configuration face of an IDOR or broken function-level authorisation).
- **Fail (Medium):** no scopes on routes intended for access tokens (ID tokens accepted); audiences broader than the API's own clients; one issuer and audience shared by unrelated applications.
- **Pass:** issuer and audience specific to the API, scopes on every route that needs more than identity, and backend checks for object-level authorisation.

#### Automated coverage

None specific. Security Hub CSPM **APIGateway.8** only checks that some authorisation type is set.

#### Detection

CloudTrail `UpdateAuthorizer` (issuer or audience changes) and `UpdateRoute` (scope removals). Cognito sign-up spikes are visible in Cognito's CloudTrail events and metrics (see the [Cognito note](/cloud/aws-cognito-security/)).

### GT-AWS-API-5: Resource policies and private APIs

*Guler Tech methodology.*

#### What it checks

REST API resource policies: whether private APIs are restricted to the client's VPC endpoints or VPCs, whether public APIs grant `execute-api:Invoke` to other accounts, and whether IP-based restrictions are coherent.

#### Prerequisites

`apigateway:GET`, `access-analyzer:CheckNoPublicAccess`, `ec2:DescribeVpcEndpoints`.

#### Steps

```bash
for id in $(jq -r '.items[]? | select(.policy != null) | .id' out/api/rest-eu-west-2.json); do
  aws apigateway get-rest-api --region eu-west-2 --rest-api-id "$id" --query policy --output text \
    | sed 's/\\//g' > "out/api/policy-$id.json"
  echo "== $id $(jq -r '.endpointConfiguration.types[0]' <(aws apigateway get-rest-api --region eu-west-2 --rest-api-id "$id"))"
  jq -c '.Statement[] | {effect: .Effect, principal: .Principal, action: .Action, condition: .Condition}' "out/api/policy-$id.json"
  aws accessanalyzer check-no-public-access --resource-type AWS::ApiGateway::RestApi \
    --policy-document "file://out/api/policy-$id.json" --query '[result, reasons[].description]'
done

# Private APIs with no policy at all cannot be deployed; private APIs whose policy has no VPC scoping are the finding
jq -r '.items[]? | select(.endpointConfiguration.types[0] == "PRIVATE") | [.id, .name, (.endpointConfiguration.vpcEndpointIds // [] | join(","))] | @tsv' out/api/rest-eu-west-2.json

# The client's own execute-api endpoints, for comparison with any aws:SourceVpce values
aws ec2 describe-vpc-endpoints --filters Name=service-name,Values=com.amazonaws.eu-west-2.execute-api \
  --query 'VpcEndpoints[].[VpcEndpointId, VpcId, OwnerId]' --output text
```

The `get-rest-api` `policy` field is a JSON string with escaped quotes; the `sed` unescapes it. Compare every `aws:SourceVpce`/`aws:SourceVpc` value with the client's endpoint list; endpoint IDs from other accounts need an owner and a reason.

#### Observation

Illustrative non-compliant private API policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    { "Effect": "Allow", "Principal": "*", "Action": "execute-api:Invoke", "Resource": "execute-api:/*" }
  ]
}
```

Compliant pattern (allow, then deny anything not from the client's endpoint):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    { "Effect": "Allow", "Principal": "*", "Action": "execute-api:Invoke", "Resource": "execute-api:/*" },
    {
      "Effect": "Deny", "Principal": "*", "Action": "execute-api:Invoke", "Resource": "execute-api:/*",
      "Condition": { "StringNotEquals": { "aws:SourceVpce": ["vpce-0a1b2c3d4e5f6a7b8", "vpce-0f1e2d3c4b5a69788"] } }
    }
  ]
}
```

#### Evaluation

- **Fail (High, Critical if methods are `NONE`):** private APIs whose policy allows invocation without `aws:SourceVpce`/`aws:SourceVpc` restriction to the client's endpoints or VPCs; anyone with an `execute-api` endpoint in their own account can call them.
- **Fail (Medium to High):** public APIs granting `execute-api:Invoke` to unknown accounts' principals (with `AWS_IAM` methods, this is the only gate).
- **Fail (Low):** `aws:SourceIp` allowlists that include broad or stale ranges; policies on public APIs that try to restrict by VPC (the `aws:SourceVpc` key is not present for internet traffic, so such statements are usually broken in one direction or the other).
- **Pass:** private APIs scoped to known endpoints or VPCs; cross-account access only to documented principals; `CheckNoPublicAccess` returns `PASS` or the public grant is deliberate and backed by method authorisation.

#### Automated coverage

No Security Hub CSPM control for API resource policies. Prowler `apigateway_restapi_public` (endpoint type) and `apigateway_restapi_public_with_authorizer`. IAM Access Analyzer does not generate findings for API Gateway, so `CheckNoPublicAccess` is the automated aid.

#### Detection

CloudTrail `UpdateRestApi` with a `/policy` patch operation (and `CreateDeployment`, since policy changes need a deployment to take effect). Access logs with `$context.identity.vpceId` show which endpoints call a private API; an unknown `vpce-` ID is a high-signal alert.

### GT-AWS-API-6: Stage settings, logging, caching, throttling and TLS

*Guler Tech methodology.*

#### What it checks

For each stage: execution and access logging (on, at what level, with or without data tracing), response cache keys and encryption, cache invalidation authorisation, throttling, WAF, X-Ray, client certificate to the backend, stage variables, and the custom domain TLS policy.

#### Prerequisites

`apigateway:GET`, `logs:DescribeLogGroups`.

#### Steps

```bash
aws apigateway get-stages --region eu-west-2 --rest-api-id a1b2c3d4e5 --output json \
| jq '.item[] | {stage: .stageName, waf: .webAclArn, backendCert: .clientCertificateId, xray: .tracingEnabled,
                cache: .cacheClusterEnabled, accessLog: .accessLogSettings.destinationArn,
                accessFormat: .accessLogSettings.format, vars: .variables,
                defaults: .methodSettings["*/*"]}'

aws apigatewayv2 get-stages --region eu-west-2 --api-id f6g7h8i9j0 \
  --query 'Items[].[StageName, AccessLogSettings.DestinationArn, DefaultRouteSettings.ThrottlingRateLimit, DefaultRouteSettings.ThrottlingBurstLimit, DefaultRouteSettings.DataTraceEnabled]' --output text

# Cache keys on cached GET methods that return per-user data
aws apigateway get-integration --region eu-west-2 --rest-api-id a1b2c3d4e5 --resource-id r4s5t6 --http-method GET \
  --query 'cacheKeyParameters'

# Who reads the execution logs, and for how long are they kept
aws logs describe-log-groups --log-group-name-prefix 'API-Gateway-Execution-Logs_a1b2c3d4e5' \
  --query 'logGroups[].[logGroupName, retentionInDays, kmsKeyId]' --output text
```

In `methodSettings` (keys are `"*/*"` for stage defaults or `"resource/METHOD"` overrides) read `loggingLevel`, `dataTraceEnabled`, `throttlingRateLimit`, `throttlingBurstLimit`, `cachingEnabled`, `cacheDataEncrypted`, `requireAuthorizationForCacheControl` and `unauthorizedCacheControlHeaderStrategy`. Scan stage variables and the access log format for secrets and for `$context.authorizer.*` fields that carry personal data.

#### Observation

Illustrative:

```json
{
  "stage": "prod", "waf": null, "backendCert": null, "xray": false, "cache": true,
  "accessLog": null, "accessFormat": null,
  "vars": { "backendHost": "internal.example.com", "partnerToken": "<REDACTED>" },
  "defaults": { "loggingLevel": "INFO", "dataTraceEnabled": true, "cachingEnabled": true,
                "cacheDataEncrypted": false, "requireAuthorizationForCacheControl": false,
                "throttlingRateLimit": 10000.0, "throttlingBurstLimit": 5000 }
}
```

`GET /v1/me` is cached with `cacheKeyParameters: []`: every caller within the TTL receives the first caller's profile.

#### Evaluation

- **Fail (High to Critical):** per-user responses cached without the user in the cache key (cross-user data exposure; Critical with sensitive data and no further precondition than being a user).
- **Fail (High):** secrets in stage variables; data tracing on a production stage that handles credentials or personal data, with broad log readers or indefinite retention.
- **Fail (Medium):** no execution or access logging on production stages (APIGateway.1, APIGateway.9); unencrypted cache for sensitive responses (APIGateway.5); no throttling below account defaults on expensive or public methods; `requireAuthorizationForCacheControl` false (any client can force backend calls); no WAF on internet-facing REST APIs (APIGateway.4); domain TLS policy below the recommended policies (APIGateway.11).
- **Fail (Low):** no client certificate for backend authentication where the backend is reachable from the internet (APIGateway.2); no X-Ray (APIGateway.3, operational).
- **Pass:** logging at `ERROR` or `INFO` without data tracing in production, access logs with a deliberate format, cache keys that include identity for per-user responses (or no caching), encrypted cache, explicit throttling, WAF where supported.

#### Automated coverage

Security Hub CSPM **APIGateway.1**, **APIGateway.2**, **APIGateway.4**, **APIGateway.5**, **APIGateway.9**, **APIGateway.11**. Prowler `apigateway_restapi_logging_enabled`, `apigateway_restapi_cache_encrypted`, `apigateway_restapi_client_certificate_enabled`, `apigateway_restapi_waf_acl_attached`, `apigateway_restapi_tracing_enabled`, `apigateway_restapi_no_secrets_in_stage_variables`, `apigatewayv2_api_access_logging_enabled`.

#### Detection

CloudTrail `UpdateStage` (logging, data trace, cache, throttling and WAF changes), `CreateStage`, `UpdateDomainName`. Turning logging off on a production stage deserves an alert in the same way as CloudTrail changes do; see the [CloudTrail note](/cloud/aws-cloudtrail-logging/).

### GT-AWS-API-7: Request validation, CORS and service integrations

*Guler Tech methodology.*

#### What it checks

Whether REST methods validate requests before they reach the backend, whether CORS settings let arbitrary origins read authenticated responses, and whether direct AWS service integrations use narrowly scoped roles and fixed resource targets.

#### Prerequisites

`apigateway:GET`, `iam:GetRole`/`iam:GetRolePolicy`.

#### Steps

```bash
aws apigateway get-request-validators --region eu-west-2 --rest-api-id a1b2c3d4e5 \
  --query 'items[].[id, name, validateRequestBody, validateRequestParameters]' --output text
aws apigateway get-method --region eu-west-2 --rest-api-id a1b2c3d4e5 --resource-id r4s5t6 --http-method POST \
  --query '[requestValidatorId, requestModels, requestParameters]'

# HTTP API CORS
aws apigatewayv2 get-api --region eu-west-2 --api-id f6g7h8i9j0 --query CorsConfiguration
# REST API CORS lives in OPTIONS integration responses and gateway responses
aws apigateway get-integration-response --region eu-west-2 --rest-api-id a1b2c3d4e5 --resource-id r4s5t6 \
  --http-method OPTIONS --status-code 200 --query responseParameters
aws apigateway get-gateway-responses --region eu-west-2 --rest-api-id a1b2c3d4e5 \
  --query 'items[].[responseType, responseParameters]' --output json

# Service integrations: which role, which target
aws apigateway get-integration --region eu-west-2 --rest-api-id a1b2c3d4e5 --resource-id r4s5t6 --http-method GET \
  --query '[type, uri, credentials, requestTemplates]'
```

For `AWS` integrations, read the role in `credentials` and the mapping template: does the URI or template insert `$input.params()` or path parameters into the bucket, key, table name or queue URL? Then compare with the role's permissions.

**Explicitly approved only:** confirm CORS with a preflight and a credentialed request from a test origin, reading headers only:

```bash
curl -s -i https://api.example.com/v1/me -H 'Origin: https://attacker.example' -H "Authorization: Bearer $TOKEN_A" \
  | grep -i '^access-control-allow'
```

#### Observation

Illustrative: no request validators; HTTP API `CorsConfiguration` has `AllowOrigins ["*"]`; REST `GET /v1/files/{key}` is an S3 integration with role `apigw-s3-role` (`s3:GetObject` on `arn:aws:s3:::*`) and URI `arn:aws:apigateway:eu-west-2:s3:path/example-docs/{key}`, so `{key}` is caller-controlled but confined to one bucket, while the role could read any bucket in the account.

#### Evaluation

- **Fail (High):** service integrations where caller input chooses the target resource beyond what the method intends (another bucket, table or queue), or a role whose permissions would make a template mistake catastrophic; CORS that reflects arbitrary origins with credentials on authenticated endpoints that use cookies.
- **Fail (Medium):** `AllowOrigins ["*"]` on browser-facing endpoints returning user data with bearer tokens (lower risk, since browsers will not attach the token automatically, but it removes a defence); no request validation in front of backends known to be fragile.
- **Fail (Low):** missing request validation in general (it is input hygiene, not an access control).
- **Pass:** validators on methods with bodies and parameters, CORS allowlists naming the client's front-end origins, service integration roles scoped to the exact resources.

#### Automated coverage

None in Security Hub CSPM or Prowler. Review is manual; CORS behaviour can be confirmed with the approach in our web testing notes.

#### Detection

CloudTrail `UpdateIntegration`, `PutIntegration`, `UpdateGatewayResponse`, `UpdateApi` (CORS). Abuse of a service integration appears in CloudTrail as calls by the integration role (S3 data events, DynamoDB data events if enabled).

### GT-AWS-API-8: SNS topic policies and subscriptions

*Guler Tech methodology.*

#### What it checks

Whether topic policies let anyone (or unknown accounts, or services without source conditions) publish, subscribe or administer, and whether existing subscriptions deliver to unknown accounts or insecure endpoints.

#### Prerequisites

`sns:ListTopics`, `sns:GetTopicAttributes`, `sns:ListSubscriptionsByTopic`, `access-analyzer:CheckNoPublicAccess`.

#### Steps

```bash
for r in $REGIONS; do
  while read -r t; do
    [ -z "$t" ] && continue
    aws sns get-topic-attributes --region "$r" --topic-arn "$t" --query 'Attributes.Policy' --output text > out/api/topic-policy.json
    jq -c --arg t "$t" '.Statement[] | select(.Effect == "Allow")
      | {topic: $t, sid: .Sid, principal: .Principal, action: .Action, condition: .Condition}' out/api/topic-policy.json
    aws accessanalyzer check-no-public-access --region "$r" --resource-type AWS::SNS::Topic \
      --policy-document file://out/api/topic-policy.json --query '[result]' --output text | sed "s|^|$t public-check: |" >&2
  done < "out/api/topics-$r.txt"
done > out/api/sns-policies.jsonl

# Wildcard principals, excluding the account-scoped default statement
jq -c 'select((.principal == "*" or .principal.AWS == "*"))
       | select((.condition // {} | tostring | test("SourceOwner|SourceAccount|SourceArn|PrincipalOrgID|PrincipalAccount|SourceVpce")) | not)' out/api/sns-policies.jsonl
# Service principals without source scoping
jq -c 'select(.principal.Service != null) | select((.condition // {} | tostring | test("SourceArn|SourceAccount")) | not)' out/api/sns-policies.jsonl

# Subscriptions: protocol, endpoint, owning account
TOPIC=arn:aws:sns:eu-west-2:111122223333:order-events
aws sns list-subscriptions-by-topic --topic-arn "$TOPIC" \
  --query 'Subscriptions[].[Protocol, Endpoint, Owner]' --output text
```

Flag subscriptions where `Owner` or the account in the endpoint ARN is not one of the client's, `http` (not `https`) endpoints, and `email` subscriptions to non-corporate domains.

**Lab or explicitly approved only:** to prove that `sns:Subscribe` is open, subscribe a tester-owned SQS queue from a tester account, confirm that the subscription is created, then unsubscribe immediately without consuming production messages, or (better) prove it with `CheckNoPublicAccess` and an Access Analyzer finding instead.

#### Observation

Illustrative:

```json
{"topic":"arn:aws:sns:eu-west-2:111122223333:order-events","sid":"partners","principal":{"AWS":"*"},"action":["SNS:Subscribe","SNS:Receive"],"condition":null}
```

```text
sqs    arn:aws:sqs:eu-west-2:444455556666:order-mirror      444455556666
https  https://hooks.partner.example/sns                    111122223333
http   http://203.0.113.10/notify                           111122223333
```

#### Evaluation

- **Fail (Critical):** `sns:Subscribe`/`sns:Receive` open to everyone on a topic carrying sensitive data (any account can mirror the stream into its own queue); `sns:SetTopicAttributes`, `sns:AddPermission` or `sns:*` open to everyone.
- **Fail (High):** `sns:Publish` open to everyone on a topic whose subscribers act on messages (Lambda, SQS workers, customer email/SMS); service principals without `aws:SourceArn`/`aws:SourceAccount`; subscriptions owned by unknown accounts.
- **Fail (Medium):** `http` endpoints; email subscriptions outside the organisation for sensitive topics.
- **Pass:** account- or organisation-scoped principals, documented cross-account grants with conditions, `sns:Protocol` restrictions where subscriptions are delegated, all subscribers known.

#### Automated coverage

Security Hub CSPM **SNS.4** (Critical; Config rule `sns-topic-no-public-access`, which ignores conditions with wildcards or variables). Prowler `sns_topics_not_publicly_accessible`, `sns_subscription_not_using_http_endpoints`. IAM Access Analyzer external access findings for `AWS::SNS::Topic`.

#### Detection

CloudTrail management events `SetTopicAttributes` (policy changes), `AddPermission`, `Subscribe`, `ConfirmSubscription`, `Unsubscribe`. Alert on `Subscribe` calls from principals outside the organisation and on subscriptions whose endpoint is in an unknown account. Unauthenticated `ConfirmSubscription`/`Unsubscribe` (the email link) are not logged. `Publish` and `PublishBatch` are data events, logged only if SNS data events are enabled for the topic.

### GT-AWS-API-9: SNS encryption, delivery endpoints and SMS abuse

*Guler Tech methodology.*

#### What it checks

KMS encryption of topics carrying sensitive data, the signature version used for HTTP(S) delivery and whether receivers verify it, and the account's SMS posture (sandbox, spend limit) as a target for abuse with stolen credentials.

#### Prerequisites

`sns:GetTopicAttributes`, `sns:GetSMSAttributes`, `sns:GetSMSSandboxAccountStatus`, `kms:GetKeyPolicy`.

#### Steps

```bash
aws sns get-topic-attributes --topic-arn "$TOPIC" \
  --query 'Attributes.[KmsMasterKeyId, SignatureVersion, DisplayName]' --output text

aws sns get-sms-sandbox-account-status
aws sns get-sms-attributes --attributes MonthlySpendLimit DefaultSMSType
```

For KMS-encrypted topics, read the key policy: a key that every principal in the account can use for `kms:Decrypt` adds little. For HTTPS subscribers the client controls, review the receiving code: does it verify the message signature, check that `SigningCertURL` is an SNS host over HTTPS, reject unexpected `TopicArn` values, and handle `SubscriptionConfirmation` messages deliberately (not auto-confirming any topic)?

#### Observation

Illustrative: `order-events` has no `KmsMasterKeyId`; `SignatureVersion` is `1`; the partner webhook receiver auto-confirms any `SubscriptionConfirmation` and does not verify signatures; the account is out of the SMS sandbox with a monthly spend limit raised for a marketing campaign that ended a year ago.

#### Evaluation

- **Fail (High):** HTTP(S) receivers that act on SNS messages without verifying signatures (anyone who can reach the endpoint can forge "SNS" messages); receivers that auto-confirm subscriptions to arbitrary topics.
- **Fail (Medium):** SMS enabled outside the sandbox with a high spend limit and no use, in accounts where long-lived access keys exist (the precondition for SMS abuse); sensitive topics without KMS SSE (SNS.1).
- **Fail (Low):** `SignatureVersion` 1 (SHA1); topics with KMS SSE using a key with a broad decrypt policy.
- **Pass:** KMS SSE on sensitive topics with scoped key policies, `SignatureVersion` 2, receivers that verify signatures with the SDK helpers, SMS only where needed with a spend limit matched to use.

#### Automated coverage

Security Hub CSPM **SNS.1**. Prowler `sns_topics_kms_encryption_at_rest_enabled`, `sns_subscription_not_using_http_endpoints`.

#### Detection

CloudTrail `SetSMSAttributes`, `GetSMSAttributes`, `GetSMSSandboxAccountStatus`, `CreateSMSSandboxPhoneNumber`, `ListOriginationNumbers` from unusual principals are the reconnaissance pattern reported in SMS abuse cases. Direct `Publish` to phone numbers is not in CloudTrail at all (SNS documents that the `AWS::SNS::PhoneNumber` resource type is not logged), so spend and delivery metrics are the main signal. CloudWatch metrics `SMSMonthToDateSpentUSD` and `NumberOfNotificationsFailed` show the effect. GuardDuty's `AnomalousBehavior` IAM findings may flag the access pattern.

### GT-AWS-API-10: SQS queue policies

*Guler Tech methodology.*

#### What it checks

Whether queue policies open send, receive, delete or administrative actions to everyone or to unknown accounts, whether SNS-to-SQS (and other service) grants carry `aws:SourceArn`, and whether unencrypted public queues accept anonymous requests.

#### Prerequisites

`sqs:ListQueues`, `sqs:GetQueueAttributes`, `access-analyzer:CheckNoPublicAccess`.

#### Steps

```bash
for r in $REGIONS; do
  while read -r q; do
    [ -z "$q" ] && continue
    aws sqs get-queue-attributes --region "$r" --queue-url "$q" \
      --attribute-names Policy SqsManagedSseEnabled KmsMasterKeyId --output json \
    | jq -c --arg q "$q" '.Attributes as $a | ($a.Policy // "{\"Statement\":[]}" | fromjson | .Statement[])
        | select(.Effect == "Allow")
        | {queue: $q, sseSqs: $a.SqsManagedSseEnabled, kms: $a.KmsMasterKeyId, principal: .Principal, action: .Action, condition: .Condition}'
  done < "out/api/queues-$r.txt"
done | tee out/api/sqs-policies.jsonl

jq -c 'select((.principal == "*" or .principal.AWS == "*") and .condition == null)' out/api/sqs-policies.jsonl
jq -c 'select(.principal.Service == "sns.amazonaws.com") | select((.condition // {} | tostring | test("SourceArn")) | not)' out/api/sqs-policies.jsonl
# Public and unencrypted: anonymous requests may work
jq -c 'select((.principal == "*" or .principal.AWS == "*") and .condition == null and .sseSqs != "true" and .kms == null)' out/api/sqs-policies.jsonl
```

Use `aws accessanalyzer check-no-public-access --resource-type AWS::SQS::Queue` on extracted policies for evidence. **Never call `ReceiveMessage` on a client queue to prove access**: it changes message visibility and can disrupt processing. If the client wants a dynamic proof, use a test queue with the same policy, or `SendMessage` of one clearly labelled, harmless test message to a non-production queue they nominate.

#### Observation

Illustrative:

```json
{"queue":"https://sqs.eu-west-2.amazonaws.com/111122223333/order-intake","sseSqs":"false","kms":null,"principal":"*","action":"SQS:SendMessage","condition":null}
{"queue":"https://sqs.eu-west-2.amazonaws.com/111122223333/order-fanout","sseSqs":"true","kms":null,"principal":{"Service":"sns.amazonaws.com"},"action":"sqs:SendMessage","condition":null}
```

`order-intake` predates default encryption and allows anyone, including unsigned requests, to send work items; `order-fanout` accepts messages from any SNS topic in any account.

#### Evaluation

- **Fail (Critical):** `sqs:ReceiveMessage`/`sqs:DeleteMessage`/`sqs:*` open to everyone on queues with sensitive data, or `sqs:SetQueueAttributes`/`sqs:AddPermission` open to everyone.
- **Fail (High):** `sqs:SendMessage` open to everyone on queues whose consumers act on messages (payments, provisioning, emails); SNS (or other service) grants without `aws:SourceArn`, which let any topic inject.
- **Fail (Medium):** cross-account grants to accounts outside the client's inventory with no documentation.
- **Pass:** account- or organisation-scoped principals, service grants pinned with `aws:SourceArn`, and consumers that validate message content regardless.

#### Automated coverage

Security Hub CSPM **SQS.3** (Critical; Config rule `sqs-queue-no-public-access`). Prowler `sqs_queues_not_publicly_accessible`. IAM Access Analyzer external access findings for `AWS::SQS::Queue`.

#### Detection

CloudTrail management events `SetQueueAttributes` and `AddPermission`. `SendMessage`, `ReceiveMessage`, `DeleteMessage` and (at the time of writing) `GetQueueAttributes` are data events for `AWS::SQS::Queue`, logged only with data event selectors; enable them for sensitive queues so that calls from other accounts are visible. CloudWatch `NumberOfMessagesSent` anomalies show injection.

### GT-AWS-API-11: SQS encryption, dead-letter queues and redrive

*Guler Tech methodology.*

#### What it checks

Encryption at rest (SSE-SQS or SSE-KMS) for queues carrying sensitive data, how DLQs are configured and protected, and which principals can read message bodies from queues and DLQs.

#### Prerequisites

`sqs:GetQueueAttributes`, `sqs:ListDeadLetterSourceQueues`, `iam:SimulatePrincipalPolicy`, `kms:GetKeyPolicy`.

#### Steps

```bash
Q=https://sqs.eu-west-2.amazonaws.com/111122223333/payments
aws sqs get-queue-attributes --queue-url "$Q" \
  --attribute-names SqsManagedSseEnabled KmsMasterKeyId RedrivePolicy RedriveAllowPolicy MessageRetentionPeriod \
  --query Attributes

DLQ=https://sqs.eu-west-2.amazonaws.com/111122223333/payments-dlq
aws sqs list-dead-letter-source-queues --queue-url "$DLQ" --query queueUrls
aws sqs get-queue-attributes --queue-url "$DLQ" \
  --attribute-names Policy SqsManagedSseEnabled KmsMasterKeyId MessageRetentionPeriod RedriveAllowPolicy \
  --query Attributes
aws cloudwatch describe-alarms --query \
  'MetricAlarms[?Namespace==`AWS/SQS` && MetricName==`ApproximateNumberOfMessagesVisible`].[AlarmName, Dimensions[0].Value]' --output text

# Who can read message bodies (ReadOnlyAccess includes sqs:Receive*)
aws iam simulate-principal-policy \
  --policy-source-arn arn:aws:iam::111122223333:role/support-readonly \
  --action-names sqs:ReceiveMessage kms:Decrypt \
  --resource-arns arn:aws:sqs:eu-west-2:111122223333:payments-dlq \
  --query 'EvaluationResults[].[EvalActionName, EvalDecision]' --output table
```

Also check Lambda asynchronous DLQs and on-failure destinations (`aws lambda get-function-event-invoke-config`, `DeadLetterConfig.TargetArn` in the function configuration): they receive whole events.

#### Observation

Illustrative: `payments` uses SSE-KMS with a customer managed key; `payments-dlq` uses SSE-SQS, retains messages for 14 days (`1209600`), has `RedriveAllowPolicy` `allowAll`, no depth alarm, and `role/support-readonly` (with `ReadOnlyAccess`) can call `sqs:ReceiveMessage` on it. Because the DLQ is SSE-SQS, no KMS permission stands in the way.

#### Evaluation

- **Fail (High):** DLQs (or source queues) holding sensitive payloads readable by broad "read-only" or support roles, especially without KMS key-policy gating.
- **Fail (Medium):** queues with sensitive data and no SSE at all (SQS.1, typically pre-October 2022 queues); DLQs with weaker policies than their source queues; no alarm on DLQ depth (failed sensitive messages accumulate unnoticed); `RedriveAllowPolicy` `allowAll` on DLQs that hold sensitive data.
- **Fail (Low):** SSE-SQS rather than SSE-KMS where the client's policy requires customer managed keys or key-use audit.
- **Pass:** SSE on every queue, SSE-KMS with scoped key policies for sensitive queues, DLQs with matching protection, alarms and a retention matched to the reprocessing process, `byQueue` redrive allow policies.

#### Automated coverage

Security Hub CSPM **SQS.1**. Prowler `sqs_queues_server_side_encryption_enabled`.

#### Detection

`ReceiveMessage` data events (if enabled) from principals that are not the consumer; `StartMessageMoveTask` (DLQ redrive, a management event) outside runbooks; with SSE-KMS, KMS `Decrypt` events in CloudTrail attributed to the reading principal.

### GT-AWS-API-12: EventBridge event bus policies

*Guler Tech methodology.*

#### What it checks

Whether default or custom event buses allow other accounts, the whole world, or the whole organisation to put events that rules then deliver to Lambda, SQS, SNS and other targets. Monitoring and rule configuration are covered in the [CloudWatch and EventBridge note](/cloud/aws-cloudwatch-eventbridge-monitoring/); this test only looks at the bus as an injection path into the services in this note.

#### Prerequisites

`events:ListEventBuses`, `events:DescribeEventBus`, `events:ListRules`, `events:ListTargetsByRule`.

#### Steps

```bash
for b in $(aws events list-event-buses --query 'EventBuses[].Name' --output text); do
  echo "== $b"
  aws events describe-event-bus --name "$b" --query Policy --output text 2>/dev/null \
    | jq -c '.Statement[]? | {sid: .Sid, principal: .Principal, action: .Action, condition: .Condition}'
done
aws events list-rules --event-bus-name partner-bus --query 'Rules[].[Name, EventPattern]' --output text
aws events list-targets-by-rule --event-bus-name partner-bus --rule partner-orders --query 'Targets[].Arn'
```

For each bus that accepts external events, check what the rules match on: a pattern on `source` alone is weak, because `source` is caller-supplied for custom events (except the reserved `aws.` prefix); `account` in the event is set by EventBridge and is a stronger filter.

#### Observation

Illustrative: `partner-bus` allows `events:PutEvents` to `Principal "*"` with no condition; rule `partner-orders` matches `{"source": ["partner.orders"]}` and targets the `order-intake` Lambda function.

#### Evaluation

- **Fail (High):** buses open to everyone (or to unknown accounts) whose rules deliver to targets that act on events.
- **Fail (Medium):** organisation-wide `PutEvents` on buses feeding sensitive targets where only a few accounts should publish; rules that trust `source` alone for cross-account events.
- **Fail (Low):** custom buses with no resource policy (EventBridge.3), meaning any principal in the account with `events:PutEvents` can publish.
- **Pass:** bus policies listing specific accounts or using `aws:PrincipalOrgID` plus narrower conditions, rules that match on `account` as well as `source`, and targets that validate events.

#### Automated coverage

Security Hub CSPM **EventBridge.3**. Prowler `eventbridge_bus_exposed` and `eventbridge_bus_cross_account_access`.

#### Detection

CloudTrail `PutPermission`, `RemovePermission`, `PutRule`, `PutTargets` (management events). `PutEvents` from other accounts is visible to the receiving account as a data event only where enabled; use the target's own logs.

## Hardening

**API Gateway.**

- Give every non-public route an authorisation type; make catch-all routes authorised or remove them. Use IAM for service-to-service callers, JWT or Cognito authorisers with **scopes** for user-facing APIs, and keep object-level authorisation in the backend.
- For Lambda authorisers, either key the cache on every decision input (HTTP APIs: add `$context.routeKey` and relevant parameters; REST `REQUEST` authorisers: add the headers, query strings and context variables the decision reads) and return policies covering exactly what was evaluated, or set the TTL to 0. Keep TTLs short where revocation must be fast.
- Disable the default endpoint whenever a custom domain, mTLS or CloudFront is the intended entry point.
- Scope private API policies with `aws:SourceVpce` or `aws:SourceVpc`.
- Treat API keys as client identifiers for metering only. Never as authentication, never as secrets.
- Execution logging at `ERROR` or `INFO`, data tracing off in production, access logging with a deliberate format, encrypted log groups with retention.
- Cache only responses that are identical for all callers, or include identity in the cache key; encrypt the cache; require authorisation for cache invalidation.
- Throttle at the stage and method level and with WAF rate-based rules; back Lambda integrations with reserved concurrency.

Terraform for an HTTP API with the main controls:

```hcl
resource "aws_apigatewayv2_api" "web" {
  name                         = "web-backend"
  protocol_type                = "HTTP"
  disable_execute_api_endpoint = true   # only reachable through the custom domain / CloudFront
  cors_configuration {
    allow_origins = ["https://app.example.com"]
    allow_methods = ["GET", "POST"]
    allow_headers = ["authorization", "content-type"]
  }
}

resource "aws_apigatewayv2_authorizer" "tenant" {
  api_id                            = aws_apigatewayv2_api.web.id
  authorizer_type                   = "REQUEST"
  authorizer_uri                    = aws_lambda_function.authz.invoke_arn
  authorizer_payload_format_version = "2.0"
  enable_simple_responses           = false
  identity_sources                  = ["$request.header.Authorization", "$context.routeKey"]
  authorizer_result_ttl_in_seconds  = 60
}

resource "aws_apigatewayv2_route" "report" {
  api_id             = aws_apigatewayv2_api.web.id
  route_key          = "GET /v1/tenants/{tenantId}/report"
  authorization_type = "CUSTOM"
  authorizer_id      = aws_apigatewayv2_authorizer.tenant.id
  target             = "integrations/${aws_apigatewayv2_integration.report.id}"
}

resource "aws_apigatewayv2_stage" "prod" {
  api_id      = aws_apigatewayv2_api.web.id
  name        = "prod"
  auto_deploy = true
  default_route_settings {
    throttling_rate_limit  = 200
    throttling_burst_limit = 400
  }
  access_log_settings {
    destination_arn = aws_cloudwatch_log_group.api_access.arn
    format = jsonencode({
      requestId = "$context.requestId", ip = "$context.identity.sourceIp", domain = "$context.domainName",
      route = "$context.routeKey", status = "$context.status", principal = "$context.authorizer.principalId"
    })
  }
}
```

Including `$context.routeKey` in the cache key separates routes; if the decision also depends on `tenantId`, add it as an identity source too (or drop caching). For REST APIs the equivalents are `disable_execute_api_endpoint` on `aws_api_gateway_rest_api` and `aws_api_gateway_method_settings` with `logging_level`, `data_trace_enabled = false`, `cache_data_encrypted`, `require_authorization_for_cache_control` and throttling settings.

Preventive guardrails with the API Gateway condition keys (test carefully: WebSocket routes other than `$connect` legitimately use `NONE`, so scope this to HTTP APIs by OU or tag, or run it as a detective Config rule instead):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyUnauthenticatedRoutes",
      "Effect": "Deny",
      "Action": ["apigateway:POST", "apigateway:PATCH", "apigateway:PUT"],
      "Resource": "arn:aws:apigateway:*::/apis/*/routes*",
      "Condition": { "ForAnyValue:StringEquals": { "apigateway:Request/RouteAuthorizationType": "NONE" } }
    },
    {
      "Sid": "DenyPrivateApiPolicyChangesOutsidePipeline",
      "Effect": "Deny",
      "Action": "apigateway:PATCH",
      "Resource": "arn:aws:apigateway:*::/restapis/*",
      "Condition": {
        "StringEquals": { "apigateway:Resource/EndpointType": "PRIVATE" },
        "ArnNotLike": { "aws:PrincipalArn": "arn:aws:iam::*:role/platform-deploy" }
      }
    }
  ]
}
```

**SNS and SQS.**

- No `Principal "*"` without organisation, account or source conditions; service grants with `aws:SourceArn` and `aws:SourceAccount`; `sns:Protocol`/`sns:Endpoint` conditions where subscription rights are delegated.
- KMS SSE on sensitive topics and SSE-KMS on sensitive queues, with key policies limited to producers and consumers; SSE-SQS at minimum everywhere.
- DLQs with the same protection as their sources, alarms on depth, `byQueue` redrive allow policies, and a retention that fits the reprocessing process.
- Deny non-TLS requests (`aws:SecureTransport` false) in topic and queue policies.
- HTTPS-only subscriptions, `SignatureVersion` 2, signature verification in receivers.
- SMS only where needed, spend limits matched to use, and no long-lived access keys in accounts that can send SMS.

SQS queue policy for SNS fan-out, in Terraform:

```hcl
resource "aws_sqs_queue" "orders" {
  name                       = "order-fanout"
  kms_master_key_id          = aws_kms_key.messaging.arn
  message_retention_seconds  = 345600
  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.orders_dlq.arn
    maxReceiveCount     = 5
  })
}

resource "aws_sqs_queue_policy" "orders" {
  queue_url = aws_sqs_queue.orders.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowOrderTopicOnly"
        Effect    = "Allow"
        Principal = { Service = "sns.amazonaws.com" }
        Action    = "sqs:SendMessage"
        Resource  = aws_sqs_queue.orders.arn
        Condition = {
          ArnEquals = { "aws:SourceArn" = aws_sns_topic.orders.arn }
        }
      },
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "sqs:*"
        Resource  = aws_sqs_queue.orders.arn
        Condition = {
          Bool = { "aws:SecureTransport" = "false" }
        }
      }
    ]
  })
}
```

Organisation-wide, an RCP enforces the data perimeter for `sns` and `sqs` even when a team writes a bad policy. This follows AWS's data-perimeter pattern; add exceptions for any legitimate third-party integrations before attaching it:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "EnforceOrgIdentities",
      "Effect": "Deny",
      "Principal": "*",
      "Action": ["sns:*", "sqs:*"],
      "Resource": "*",
      "Condition": {
        "StringNotEqualsIfExists": { "aws:PrincipalOrgID": "o-exampleorgid" },
        "BoolIfExists": { "aws:PrincipalIsAWSService": "false" }
      }
    },
    {
      "Sid": "EnforceConfusedDeputyProtection",
      "Effect": "Deny",
      "Principal": "*",
      "Action": ["sns:*", "sqs:*"],
      "Resource": "*",
      "Condition": {
        "StringNotEqualsIfExists": { "aws:SourceOrgID": "o-exampleorgid" },
        "Null": { "aws:SourceAccount": "false" },
        "Bool": { "aws:PrincipalIsAWSService": "true" }
      }
    }
  ]
}
```

RCPs cover `events` too, so the same pattern can protect EventBridge buses. For API Gateway, which RCPs do not cover, rely on resource policies, SCPs on the management plane, and AWS Config rules (`api-gw-execution-logging-enabled`, `api-gwv2-authorization-type-configured`, `api-gw-associated-with-waf`, `api-gw-cache-encrypted`). Organisation-level policy design is in the [Organizations note](/cloud/aws-organizations-multi-account-security/).

## Real-world cases

- **API Gateway header remapping and authoriser cache confusion (Omegapoint, disclosed to AWS; AWS post June 2023).** Researchers at Omegapoint showed that API Gateway's header remapping feature let a client send two sets of header values, one evaluated by API Gateway and one delivered to the backend, which could defeat backend authorisation logic; they also showed cached authorisations being reused with different `multivalueheader` values within the TTL. AWS removed header remapping on 14 June 2023 and stopped using cached authorisations in the `multivalueheader` case. It is the clearest public example that authoriser caching is a security boundary. [AWS Security Blog](https://aws.amazon.com/blogs/security/removing-header-remapping-from-amazon-api-gateway-and-notes-about-our-work-with-security-researchers/).
- **Authoriser caching keyed on the token alone (2025 analysis).** Warren Parad's write-up walks through the GT-AWS-API-3 pattern: a per-resource decision (can this user read this order?) cached on a token-only key, so one legitimate request grants access to other objects for the TTL, and argues the default should key on method and path. [DEV Community (AWS Community Builders)](https://dev.to/aws-builders/api-gateway-vulnerabilities-by-design-be-careful-2094). A Classmethod engineer reproduced the same behaviour (in Japanese): [DevelopersIO](https://dev.classmethod.jp/articles/api-gateway-authorizor-cache-policy/).
- **SNS used for smishing with stolen keys (Permiso, 2023; SentinelLABS "SNS Sender", February 2024).** Permiso investigated an AWS access key exposed in a newly published mobile application; the attacker's first SNS actions checked SMS capability (`GetSMSAttributes`, and the reconnaissance pattern of sandbox status, origination numbers, topics and subscriptions). SentinelLABS later documented "SNS Sender", a script that uses compromised AWS credentials with SNS to send bulk USPS-themed smishing messages. Both are GT-AWS-API-9 in practice, and both start with long-lived keys in places they should not be. [Permiso](https://permiso.io/blog/s/smishing-attack-on-aws-sms-new-phone-who-dis/); [SentinelLABS](https://www.sentinelone.com/labs/sns-sender-active-campaigns-unleash-messaging-spam-through-the-cloud/).

More cases are collected on the [incidents and writeups page](/cloud/aws-security-incidents-and-writeups/) and the [bug bounty reading list](/bug-bounty-writeups/).

## Rating findings

| Finding | Typical severity | Reasoning |
|---|---|---|
| Unauthenticated (`NONE`) route or catch-all reaching sensitive data or actions | Critical | Internet attacker, no preconditions |
| Per-user responses in the REST cache without identity in the cache key | Critical (High for low-sensitivity data) | Any user receives other users' data without trying |
| Authoriser cache confusion crossing tenants or reaching admin functions | High to Critical | Any authenticated user escalates; precondition is one legitimate token |
| Default endpoint enabled where mTLS or edge auth is the only authentication | High to Critical | Bypasses the entire authentication layer |
| Private API reachable from any account's VPC endpoint | High (Critical with `NONE` methods) | Network "private" but open to anyone with an AWS account |
| JWT/Cognito authoriser without scopes, self-registration open, no backend authorisation on privileged routes | High | Anyone can register and call privileged routes |
| API key as the only gate on sensitive methods | High | Keys are shipped to clients and readable by many principals |
| Secrets in stage variables, data tracing on production with sensitive payloads | High | Credential or data exposure to log and config readers |
| Default endpoint bypassing CloudFront WAF only | Medium | Protection bypass, authentication intact |
| Missing logging, throttling, WAF, cache encryption, request validation | Medium / Low | Hygiene and detectability gaps; raise with demonstrated impact |
| SNS topic with public `Subscribe`/`Receive` on sensitive data, or public admin actions | Critical | Any AWS account mirrors the stream or takes over the topic |
| SNS topic or SQS queue with public `Publish`/`SendMessage` feeding consumers that act | High | Message injection into business processes |
| SQS queue with public `ReceiveMessage`/`DeleteMessage` | Critical with sensitive data | Read and destroy messages from any account (or anonymously without SSE) |
| Service grants (SNS→SQS, S3→SNS) without `aws:SourceArn`/`aws:SourceAccount` | High | Any account's topic or bucket can inject |
| HTTP(S) receivers not verifying SNS signatures | High | Forged notifications accepted |
| DLQs with sensitive payloads readable by broad roles | High | Insider or low-privilege read of sensitive data |
| SMS enabled with high spend limit and unused | Medium | Abuse target for stolen keys; cost and reputational impact |
| Missing SSE on queues/topics, SHA1 signatures, `http` subscriptions | Medium / Low | Defence in depth; raise for regulated data |
| EventBridge bus open to all accounts feeding acting targets | High | Event injection path |

Lower severity when the affected API, topic or queue carries only public or synthetic data, or when compensating controls (backend authorisation, message validation, organisation-scoped RCPs) demonstrably block the path. Raise it when the target is shared across many accounts or feeds payment, identity or provisioning workflows.

## Mapping

No CIS AWS Foundations Benchmark recommendation (v1.2.0, v1.4.0, v3.0.0 or v5.0.0, as mapped in Security Hub CSPM) covers API Gateway, SNS, SQS or EventBridge buses, so the CIS column is empty. ATT&CK IDs are Enterprise techniques.

| Test | Security Hub CSPM | CIS | ATT&CK |
|---|---|---|---|
| GT-AWS-API-1 | APIGateway.4, APIGateway.11 | — | T1190 |
| GT-AWS-API-2 | APIGateway.8 | — | T1190, T1552 |
| GT-AWS-API-3 | — | — | T1190, T1078.004 |
| GT-AWS-API-4 | APIGateway.8 | — | T1190, T1078.004 |
| GT-AWS-API-5 | — | — | T1190 |
| GT-AWS-API-6 | APIGateway.1, APIGateway.2, APIGateway.4, APIGateway.5, APIGateway.9, APIGateway.11 | — | T1552, T1499.003 |
| GT-AWS-API-7 | — | — | T1190 |
| GT-AWS-API-8 | SNS.4 | — | T1537, T1565.001 |
| GT-AWS-API-9 | SNS.1 | — | T1496.003, T1496.004 |
| GT-AWS-API-10 | SQS.3 | — | T1565.001, T1537 |
| GT-AWS-API-11 | SQS.1 | — | T1552 |
| GT-AWS-API-12 | EventBridge.3 | — | T1565.001 |

## References

AWS documentation:

- [Choose between REST APIs and HTTP APIs](https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-vs-rest.html)
- [Use API Gateway Lambda authorizers](https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-use-lambda-authorizer.html), [CreateAuthorizer API](https://docs.aws.amazon.com/apigateway/latest/api/API_CreateAuthorizer.html), [HTTP API Lambda authorizers](https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-lambda-authorizer.html)
- [HTTP API JWT authorizers](https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-jwt-authorizer.html) and [REST API with Cognito user pools](https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-enable-cognito-user-pool.html)
- [Disable the default endpoint for REST APIs](https://docs.aws.amazon.com/apigateway/latest/developerguide/rest-api-disable-default-endpoint.html) and [for HTTP APIs](https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-disable-default-endpoint.html)
- [Mutual TLS for REST APIs](https://docs.aws.amazon.com/apigateway/latest/developerguide/rest-api-mutual-tls.html)
- [API Gateway resource policies](https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-resource-policies.html) and [Create a private API](https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-private-api-create.html)
- [Usage plans and API keys](https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-api-usage-plans.html), [Throttling](https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-request-throttling.html)
- [Execution logging for REST APIs](https://docs.aws.amazon.com/apigateway/latest/developerguide/rest-api-execution-logging.html), [Cache settings](https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-caching.html), [Stage variables](https://docs.aws.amazon.com/apigateway/latest/developerguide/stage-variables.html)
- [Request validation](https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-method-request-validation.html), [CORS for REST APIs](https://docs.aws.amazon.com/apigateway/latest/developerguide/how-to-cors.html)
- [WebSocket API access control](https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-websocket-api-control-access.html)
- SNS: [access control examples](https://docs.aws.amazon.com/sns/latest/dg/sns-access-policy-use-cases.html), [server-side encryption](https://docs.aws.amazon.com/sns/latest/dg/sns-server-side-encryption.html), [verifying message signatures](https://docs.aws.amazon.com/sns/latest/dg/sns-verify-signature-of-message.html), [message data protection](https://docs.aws.amazon.com/sns/latest/dg/sns-message-data-protection.html), [security best practices](https://docs.aws.amazon.com/sns/latest/dg/sns-security-best-practices.html), [CloudTrail logging](https://docs.aws.amazon.com/sns/latest/dg/sns-logging-using-cloudtrail.html)
- SQS: [encryption at rest](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-server-side-encryption.html), [dead-letter queues](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-dead-letter-queues.html), [policy examples](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-basic-examples-of-sqs-policies.html), [security best practices](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-security-best-practices.html), [CloudTrail logging](https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/logging-using-cloudtrail.html)
- [Amazon SQS SSE-SQS by default (What's New, October 2022)](https://aws.amazon.com/about-aws/whats-new/2022/10/amazon-sqs-announces-server-side-encryption-ssq-managed-sse-sqs-default/)
- [EventBridge resource-based policies](https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-use-resource-based.html)
- Security Hub CSPM controls: [API Gateway](https://docs.aws.amazon.com/securityhub/latest/userguide/apigateway-controls.html), [SNS](https://docs.aws.amazon.com/securityhub/latest/userguide/sns-controls.html), [SQS](https://docs.aws.amazon.com/securityhub/latest/userguide/sqs-controls.html), [EventBridge](https://docs.aws.amazon.com/securityhub/latest/userguide/eventbridge-controls.html), [CIS mappings](https://docs.aws.amazon.com/securityhub/latest/userguide/cis-aws-foundations-benchmark.html)
- [IAM Access Analyzer supported resource types](https://docs.aws.amazon.com/IAM/latest/UserGuide/access-analyzer-resources.html) and [CheckNoPublicAccess](https://docs.aws.amazon.com/access-analyzer/latest/APIReference/API_CheckNoPublicAccess.html)
- [Resource control policies](https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_rcps.html)
- [AWS penetration testing policy](https://aws.amazon.com/security/penetration-testing/)

Tools:

- [Prowler](https://github.com/prowler-cloud/prowler), [CloudFox](https://github.com/BishopFox/cloudfox), [Pacu](https://github.com/RhinoSecurityLabs/pacu), [ScoutSuite](https://github.com/nccgroup/ScoutSuite)

Research and incidents:

- [AWS: Removing header remapping from API Gateway (Omegapoint research)](https://aws.amazon.com/blogs/security/removing-header-remapping-from-amazon-api-gateway-and-notes-about-our-work-with-security-researchers/)
- [Warren Parad: API Gateway vulnerabilities by design](https://dev.to/aws-builders/api-gateway-vulnerabilities-by-design-be-careful-2094)
- [Classmethod: Lambda authoriser cache policy test (Japanese)](https://dev.classmethod.jp/articles/api-gateway-authorizor-cache-policy/)
- [Permiso: smishing via AWS SNS](https://permiso.io/blog/s/smishing-attack-on-aws-sms-new-phone-who-dis/)
- [SentinelLABS: SNS Sender](https://www.sentinelone.com/labs/sns-sender-active-campaigns-unleash-messaging-spam-through-the-cloud/)
