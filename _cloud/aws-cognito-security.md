---
title: "Amazon Cognito Security: User Pools and Identity Pools"
date: 2026-11-12 18:12:00 +0000
subcategory: aws
summary: "Testing Cognito user pools and identity pools: self-sign-up, writable attributes, account takeover, token validation, guest credentials and role trust."
refs: [Cognito.1, Cognito.2, Cognito.3, Cognito.4, Cognito.5, Cognito.6, T1078.004, T1087.004, T1136.003, T1098, T1110.001, T1110.004, T1550.001, T1528, T1552.001]
tags: [aws, cognito, authentication, jwt, identity-federation, iam]
---

This note is part of our [AWS security testing guide](/cloud/aws-security-testing-guide/) and covers Amazon Cognito: **user pools**, which are a user directory and OpenID Connect provider for your application, and **identity pools**, which exchange a sign-in (or no sign-in at all) for temporary AWS credentials. Cognito is unusual among AWS services because a large part of its API is meant to be called by anonymous internet users with nothing more than a client ID, and because its tokens are consumed by code the client wrote, not by AWS. Most real Cognito findings sit in the gap between the two: a setting that is safe for the Cognito-hosted flow but unsafe for how the application uses the result. A user who can sign up through the API when the UI has no sign-up button. A user who can write `custom:role` on their own profile. An API that accepts an ID token where it should require an access token. An identity pool that gives anyone on the internet credentials for a role that can read DynamoDB tables. This note explains the model, then gives twelve tests with benign proofs, the configuration that fixes each, and how to rate what you find.

## Contents

- [How it works](#how-it-works)
- [What goes wrong](#what-goes-wrong)
- [Testing](#testing)
  - [Before you start](#before-you-start)
  - [GT-AWS-COG-1: Inventory user pools, app clients and identity pools](#gt-aws-cog-1-inventory-user-pools-app-clients-and-identity-pools)
  - [GT-AWS-COG-2: Self-sign-up enabled where the application does not expect it](#gt-aws-cog-2-self-sign-up-enabled-where-the-application-does-not-expect-it)
  - [GT-AWS-COG-3: Writable attributes used for authorisation](#gt-aws-cog-3-writable-attributes-used-for-authorisation)
  - [GT-AWS-COG-4: Email and phone changes without verification and account takeover](#gt-aws-cog-4-email-and-phone-changes-without-verification-and-account-takeover)
  - [GT-AWS-COG-5: User enumeration through error responses](#gt-aws-cog-5-user-enumeration-through-error-responses)
  - [GT-AWS-COG-6: MFA, password policy and threat protection](#gt-aws-cog-6-mfa-password-policy-and-threat-protection)
  - [GT-AWS-COG-7: Token validation in APIs and back ends](#gt-aws-cog-7-token-validation-in-apis-and-back-ends)
  - [GT-AWS-COG-8: App client secrets, authentication flows and token lifetimes](#gt-aws-cog-8-app-client-secrets-authentication-flows-and-token-lifetimes)
  - [GT-AWS-COG-9: Managed login callback URLs and client registration](#gt-aws-cog-9-managed-login-callback-urls-and-client-registration)
  - [GT-AWS-COG-10: Identity pool guest access and the unauthenticated role](#gt-aws-cog-10-identity-pool-guest-access-and-the-unauthenticated-role)
  - [GT-AWS-COG-11: Basic (classic) flow and role trust policies](#gt-aws-cog-11-basic-classic-flow-and-role-trust-policies)
  - [GT-AWS-COG-12: Role mapping rules and token-based role selection](#gt-aws-cog-12-role-mapping-rules-and-token-based-role-selection)
- [Hardening](#hardening)
- [Real-world cases](#real-world-cases)
- [Rating findings](#rating-findings)
- [Mapping](#mapping)
- [References](#references)

## How it works

### User pools

A user pool is a directory of users plus an OAuth 2.0 / OpenID Connect authorisation server. Applications talk to it through **app clients**. Each app client has its own ID, optionally a client secret, a list of allowed authentication flows, OAuth settings (grants, scopes, callback and sign-out URLs), token lifetimes, attribute read and write permissions, and a few security switches. Several applications (web, mobile, admin portal, partner integration) usually share one pool through different clients, and that sharing is where several problems start.

The user pool API has three kinds of operation, and knowing which kind you are calling explains most of what follows:

| Kind | Examples | Authorised by |
|---|---|---|
| Unauthenticated (public) | `SignUp`, `ConfirmSignUp`, `InitiateAuth`, `RespondToAuthChallenge`, `ForgotPassword`, `ConfirmForgotPassword`, `ResendConfirmationCode` | Only the app client ID, plus `SECRET_HASH` if the client has a secret |
| Token-authorised (self-service) | `GetUser`, `UpdateUserAttributes`, `VerifyUserAttribute`, `ChangePassword`, `DeleteUser`, `GlobalSignOut`, MFA association | The user's access token, which must carry the `aws.cognito.signin.user.admin` scope |
| Administrative | `AdminCreateUser`, `AdminUpdateUserAttributes`, `AdminInitiateAuth`, `ListUsers`, `UpdateUserPool` | IAM (SigV4) credentials in the owning account |

The first two kinds are reachable from the internet by design. If the application's UI doesn't offer a feature (sign-up, profile editing), that tells you nothing about whether the API allows it.

**Sign-up and confirmation.** `AdminCreateUserConfig.AllowAdminCreateUserOnly` decides whether `SignUp` works. When it is `false` (self-service sign-up allowed), anyone who knows a client ID can register. New users are confirmed by a code sent to email or phone, by an administrator, or automatically by a **pre sign-up Lambda trigger** that sets `autoConfirmUser` (and optionally `autoVerifyEmail` / `autoVerifyPhone`).

**Attributes.** Every user has standard attributes from the OIDC specification (`email`, `phone_number`, `name`, ...), a fixed `sub`, and up to 50 **custom attributes** with the `custom:` prefix. Custom attributes are permanent once added; they are *mutable* or *immutable*, and an immutable attribute can still be written once, at creation, including through `SignUp`. Per app client you set `ReadAttributes` and `WriteAttributes`. AWS's documentation is blunt about the default: when you don't specify `WriteAttributes`, the client can write all standard and custom attributes, and users can change them for themselves with `UpdateUserAttributes`. No app client can write `email_verified` or `phone_number_verified`; only administrators and the verification flow can.

**Sign-in identifiers.** A pool uses either *username attributes* (users sign in with email or phone as the username) or *alias attributes* (a username plus verified email, phone or `preferred_username` as alternative sign-in names). Aliases only become usable once verified. `UsernameConfiguration.CaseSensitive` decides whether sign-in names are case-sensitive; it cannot be changed after creation.

**Attribute updates.** By default, when a user changes `email` or `phone_number`, the new value becomes active and *unverified* immediately. With **"Keep original attribute value active when an update is pending"** (`UserAttributeUpdateSettings.AttributesRequireVerificationBeforeUpdate`), the old value stays active until the user verifies the new one.

**Tokens.** A successful sign-in returns three tokens. All are JWTs except the refresh token, which is opaque.

| | ID token | Access token |
|---|---|---|
| `token_use` | `id` | `access` |
| Audience | `aud` = app client ID | `client_id` = app client ID (and `aud` only when bound to a resource server) |
| Content | User attributes the client can read, including `custom:*`, `email`, `email_verified`, `cognito:groups`, `cognito:username`; `cognito:roles` and `cognito:preferred_role` when groups have IAM roles | `scope`, `username`, `cognito:groups`; no profile attributes unless an access-token customisation trigger adds claims |
| Meant for | The client, to learn who signed in | Resource servers and APIs, to decide what the caller may do |

Both are signed with RS256 by keys published at `https://cognito-idp.<region>.amazonaws.com/<userPoolId>/.well-known/jwks.json`, and both carry `iss` = `https://cognito-idp.<region>.amazonaws.com/<userPoolId>`. AWS's own verification guidance is: check the signature against that JWKS, check `exp`, check `aud` (ID token) or `client_id` (access token) against your app client ID, check `iss` against your pool, and check `token_use`. Revocation (`RevokeToken`, `GlobalSignOut`) cannot be detected by offline verification alone.

**Feature plans, threat protection and managed login.** Since late 2024 user pools have feature plans: **Lite**, **Essentials** (the default for new pools) and **Plus**. **Threat protection**, which AWS formerly called *advanced security features*, is in Plus: compromised-credential detection, adaptive authentication with risk-based responses, IP allow and block lists, and exportable user activity logs. It runs in *audit-only* or *full-function* mode, separately for standard and custom authentication. **Managed login** (Essentials and Plus) is the successor to the **classic hosted UI** (all plans), the Cognito-hosted sign-in pages behind a user pool domain.

### Identity pools

An identity pool hands out temporary AWS credentials. It maintains **identities** (IDs of the form `<region>:<uuid>`), accepts proof of sign-in from configured providers (a user pool ID token, an OIDC or SAML provider, social providers, or "developer authenticated" identities backed by the customer's own servers), and maps each identity to an IAM role.

- **Guest access.** With `AllowUnauthenticatedIdentities` set, anyone can call `GetId` with just the pool ID and receive an identity, then exchange it for credentials for the *unauthenticated role*. No sign-in, no secret.
- **Enhanced (simplified) flow.** `GetId` then `GetCredentialsForIdentity`. Cognito chooses the role (default role, token-based role from user pool groups, or rule-based mapping) and calls `AssumeRoleWithWebIdentity` itself. For **guest** identities Cognito also applies a scope-down: an inline session policy and the `AmazonCognitoUnAuthedIdentitiesSessionPolicy` managed session policy, which together limit guest sessions to a fixed list of services (among them S3, DynamoDB, Lambda, SQS, SNS, Kinesis and Firehose, API Gateway `execute-api`, IoT, Cognito user pools, Rekognition, Polly, Translate, a subset of KMS and Location Service actions, and CloudWatch). Anything the role grants inside that list is fully usable by any internet user.
- **Basic (classic) flow.** `GetId`, then `GetOpenIdToken`, then the client itself calls `sts:AssumeRoleWithWebIdentity` naming *any* role ARN. Off unless `AllowClassicFlow` is set, and AWS recommends leaving it off. There is no Cognito scope-down session policy in this flow: the role's own policies are the limit. And because the client picks the role, the role's trust policy is the only thing that decides who may assume it.
- **Role trust.** Roles that identity pools assume trust the federated principal `cognito-identity.amazonaws.com` for `sts:AssumeRoleWithWebIdentity`. Three condition keys come from the identity pool's token: `cognito-identity.amazonaws.com:aud` (which identity pool), `cognito-identity.amazonaws.com:amr` (`authenticated` or `unauthenticated`, plus the provider for authenticated identities) and `cognito-identity.amazonaws.com:sub` (the identity ID). IAM now refuses to save a trust policy for this principal without an `aud` condition, and STS rejects cross-account web-identity assumption of roles without one, but **older trust policies without `aud` still work for same-account requests** until someone edits them.
- **Role mapping.** Per provider, an identity pool can choose roles from the token (`cognito:preferred_role` / `cognito:roles`, which come from user pool group membership) or from rules that compare a claim to a value (`Equals`, `NotEqual`, `StartsWith`, `Contains`). When no rule matches, `AmbiguousRoleResolution` either uses the default authenticated role or denies.

### Logging

User pool API calls, including the unauthenticated ones such as `SignUp` and `InitiateAuth`, are CloudTrail **management events** under `cognito-idp.amazonaws.com`, with sensitive fields replaced by `HIDDEN_DUE_TO_SECURITY_REASONS` and users identified by `sub`. Hosted UI and managed login page requests are logged as `AwsServiceEvent` entries (for example `Login_GET`, `Signup_POST`, `login_POST`, `signup_POST`). Identity pool `GetId`, `GetCredentialsForIdentity`, `GetOpenIdToken`, `GetOpenIdTokenForDeveloperIdentity` and `UnlinkIdentity` are **data events** that CloudTrail does not log unless you add an event selector for `AWS::Cognito::IdentityPool`. Configuration changes (`UpdateIdentityPool`, `SetIdentityPoolRoles`, `UpdateUserPool`, `UpdateUserPoolClient`) are management events.

## What goes wrong

**Self-sign-up left on.** The pool allows `SignUp` because a template or the console default allowed it, although the application is internal or invite-only and shows no sign-up page. Anyone with the client ID (which is in the front-end) can create an account, and every "authenticated users only" control, including the identity pool's authenticated role, now means "anyone on the internet".

**Writable attributes used for authorisation.** `custom:role`, `custom:tenant_id`, `custom:is_admin`, `custom:plan` written by the client app at sign-up and read by the back end, a Lambda authoriser or an identity pool rule to make access decisions. With default `WriteAttributes`, the user writes the value. Immutable attributes don't help when the client may write them at `SignUp`.

**Unverified email or phone trusted for identity.** The application (or a downstream service provider federating through Cognito) identifies users by `email` rather than `sub`, or links accounts by email, and either ignores `email_verified` or normalises case differently from Cognito. A user changes their own email to the victim's (or a case variant) and becomes the victim in the application. Variations: pre sign-up triggers that auto-verify emails, and triggers that link a federated sign-in to an existing native user by email without checking that the external IdP verified it.

**User enumeration.** `PreventUserExistenceErrors` is `LEGACY` on an app client (the API default for new clients), so sign-in and password reset return `UserNotFoundException` for unknown users. `SignUp` always reveals whether a *username* is taken; alias-based pools avoid revealing whether an *email* is registered.

**No MFA, weak password policy, no threat protection.** Password-only sign-in for privileged users, minimum length 6, and nothing that reacts to credential stuffing. Threat protection is a paid plan, so its absence is often a deliberate cost decision; the finding is about the combination with MFA and the value of the accounts.

**Token validation mistakes in the consuming code.** Accepting ID tokens as API credentials, not checking `token_use`, not checking `aud`/`client_id` (so a token from a less-trusted client of the same pool works), fetching JWKS from whatever `iss` the token claims (so a token from the attacker's own user pool works), not checking `exp`, decoding without verifying, or trusting claims from the ID token held in browser storage.

**App client secrets in public clients.** A confidential client (with a secret) used from a mobile app or SPA. The secret is extractable. On its own that only lets an attacker compute `SECRET_HASH` for public operations, but if the same client is allowed the `client_credentials` grant, the secret yields machine-to-machine access tokens with every custom scope the client holds.

**Risky OAuth configuration.** Implicit grant enabled (tokens in the URL fragment), production clients with `http://localhost` callback URLs, callback URLs on domains the client no longer controls (see the [recon note](/cloud/aws-unauthenticated-recon/)), custom URL schemes any app can claim, no PKCE in public clients, very long refresh token lifetimes, token revocation disabled. A newer feature, **dynamic client registration**, lets applications register their own app clients at runtime; with *open registration* on, anyone can register a client with callback URLs they choose.

**Guest credentials for an over-privileged role.** The identity pool allows unauthenticated identities and the unauthenticated role can read S3 buckets, scan DynamoDB tables, invoke Lambda functions, call `cognito-idp:ListUsers` or publish to SNS. All of those survive the enhanced-flow scope-down.

**Classic flow plus loose trust policies.** Classic flow enabled, and the authenticated role (or any role in the account trusting `cognito-identity.amazonaws.com` for this pool) has no `amr` condition. A guest identity gets an OpenID token and assumes the *authenticated* role, or another privileged role, directly through STS. Older roles with no `aud` condition at all can be assumed with a token from *any* identity pool in the same account, including one an attacker can reach.

**Role mapping on user-controlled claims.** Rules that map `custom:department Equals Admin` or `email Contains @example.com` to a privileged role, where the user can write the claim.

**Lambda trigger logic.** Pre sign-up triggers that auto-confirm and auto-verify, custom authentication challenge triggers with weak or replayable challenges, pre token generation triggers that copy user-writable attributes into authorisation claims (`cognito:groups` overrides, scopes). Triggers run the client's own code; review them like any other authentication code.

## Testing

Every test assumes an authorised engagement against the client's own AWS accounts and applications, with written scope, and respects the [AWS penetration testing policy](https://aws.amazon.com/security/penetration-testing/). Commands that create users, change attributes or assume roles are marked **lab or explicitly approved only**; run them only against test accounts the client created for you or agreed you may create. Output shown is **illustrative**; we ran nothing against real accounts while writing this note.

### Before you start

**From the client:** the user pool IDs, app client IDs and identity pool IDs in scope (and which application uses which client), two test users in each pool (call them A and B) with mailboxes you control, permission to create additional test users with self-sign-up if you find it enabled, and a list of the APIs that consume Cognito tokens. Agree that you will not run password guessing beyond a handful of attempts against your own test users.

**Inside view:** a read-only role with `SecurityAudit` and `ViewOnlyAccess` (profile `client-audit` below), plus `iam:SimulatePrincipalPolicy` if not already granted. Be aware that `SecurityAudit` includes `cognito-idp:ListUsers` and `ListUsersInGroup`, which return customer PII; don't call them, and if you must confirm a user exists, use your own test users.

**Outside view:** most user pool and identity pool public operations need no AWS credentials; pass `--no-sign-request`. For tests that compare against "a user pool the attacker controls" (COG-7), use a pool in your own testing account, never a third party's.

**Tools:** AWS CLI v2, `jq`, `curl`, Burp Suite (or your proxy of choice) to capture tokens from the real application, a JWT decoder that runs locally, [Prowler](https://github.com/prowler-cloud/prowler), and optionally [Pacu](https://github.com/RhinoSecurityLabs/pacu) `cognito__enum` (inside view). Pacu's `cognito__attack` module signs up users and modifies attributes; use it only where those state changes are approved. For SRP sign-in from a script, the open-source `pycognito` library implements the SRP exchange. Practise on CloudGoat's Cognito scenario or on [Hacking The Cloud's Cognito pages](https://hackingthe.cloud/aws/exploitation/cognito_user_self_signup/) before a live test.

Helpers used throughout:

```bash
# Decode a JWT payload locally (never paste real tokens into websites)
jwt() { python3 -c 'import sys,json,base64;p=sys.argv[1].split(".")[1];p+="="*(-len(p)%4);print(json.dumps(json.loads(base64.urlsafe_b64decode(p)),indent=2))' "$1"; }

# SECRET_HASH for app clients that have a secret: Base64(HMAC-SHA256(secret, username + client_id))
secret_hash() { python3 -c 'import sys,hmac,hashlib,base64;print(base64.b64encode(hmac.new(sys.argv[1].encode(),(sys.argv[2]+sys.argv[3]).encode(),hashlib.sha256).digest()).decode())' "$1" "$2" "$3"; }

export AWS_REGION=eu-west-2
POOL=eu-west-2_EXAMPLE11
CLIENT=1example23456789abcdefghij
IDPOOL=eu-west-2:00000000-1111-2222-3333-444444444444
```

Region loop for the inside view:

```bash
for r in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text --profile client-audit); do
  aws cognito-idp list-user-pools --max-results 60 --region "$r" --profile client-audit \
    --query 'UserPools[].[Id,Name]' --output text | sed "s/^/$r\t/"
  aws cognito-identity list-identity-pools --max-results 60 --region "$r" --profile client-audit \
    --query 'IdentityPools[].[IdentityPoolId,IdentityPoolName]' --output text | sed "s/^/$r\t/"
done
```

### GT-AWS-COG-1: Inventory user pools, app clients and identity pools

*Guler Tech methodology.*

#### What it checks

The security-relevant configuration of every pool and client, in one table, so that the later tests target the right settings and nothing is missed. Many later evaluations come straight out of this inventory.

#### Prerequisites

Inside view.

#### Steps

User pool settings:

```bash
aws cognito-idp describe-user-pool --user-pool-id "$POOL" --profile client-audit --query 'UserPool.{
  SelfSignUpBlocked: AdminCreateUserConfig.AllowAdminCreateUserOnly,
  Tier: UserPoolTier,
  ThreatProtection: UserPoolAddOns.AdvancedSecurityMode,
  Mfa: MfaConfiguration,
  UsernameAttributes: UsernameAttributes,
  AliasAttributes: AliasAttributes,
  CaseSensitive: UsernameConfiguration.CaseSensitive,
  AutoVerified: AutoVerifiedAttributes,
  VerifyBeforeUpdate: UserAttributeUpdateSettings.AttributesRequireVerificationBeforeUpdate,
  PasswordPolicy: Policies.PasswordPolicy,
  Triggers: LambdaConfig,
  DeletionProtection: DeletionProtection,
  Domain: Domain, CustomDomain: CustomDomain}'
aws cognito-idp describe-user-pool --user-pool-id "$POOL" --profile client-audit \
  --query "UserPool.SchemaAttributes[?starts_with(Name,'custom:')].[Name,Mutable,AttributeDataType]" --output table
```

App clients. `DescribeUserPoolClient` returns the client secret in clear; the query below records only whether one exists:

```bash
for c in $(aws cognito-idp list-user-pool-clients --user-pool-id "$POOL" --max-results 60 \
             --profile client-audit --query 'UserPoolClients[].ClientId' --output text); do
  aws cognito-idp describe-user-pool-client --user-pool-id "$POOL" --client-id "$c" --profile client-audit \
    --query 'UserPoolClient.{Client: ClientId, Name: ClientName, HasSecret: ClientSecret != `null`,
      AuthFlows: ExplicitAuthFlows, OAuthFlows: AllowedOAuthFlows, Scopes: AllowedOAuthScopes,
      Callbacks: CallbackURLs, Logouts: LogoutURLs, Read: ReadAttributes, Write: WriteAttributes,
      PreventUserExistence: PreventUserExistenceErrors, Revocation: EnableTokenRevocation,
      Access: AccessTokenValidity, Id: IdTokenValidity, Refresh: RefreshTokenValidity, Units: TokenValidityUnits,
      IdPs: SupportedIdentityProviders}'
done
```

Identity pools and their roles:

```bash
aws cognito-identity describe-identity-pool --identity-pool-id "$IDPOOL" --profile client-audit \
  --query '{Guest: AllowUnauthenticatedIdentities, Classic: AllowClassicFlow, UserPools: CognitoIdentityProviders,
            Social: SupportedLoginProviders, Developer: DeveloperProviderName,
            Oidc: OpenIdConnectProviderARNs, Saml: SamlProviderARNs}'
aws cognito-identity get-identity-pool-roles --identity-pool-id "$IDPOOL" --profile client-audit
```

Threat protection, MFA and WAF details:

```bash
aws cognito-idp get-user-pool-mfa-config --user-pool-id "$POOL" --profile client-audit
aws cognito-idp describe-risk-configuration --user-pool-id "$POOL" --profile client-audit
aws wafv2 get-web-acl-for-resource --profile client-audit \
  --resource-arn "arn:aws:cognito-idp:eu-west-2:111122223333:userpool/$POOL"
```

Prowler covers the same ground in bulk: `prowler aws --services cognito`.

#### Observation

One row per pool and client. An empty `Write` (or `Read`) in `describe-user-pool-client` means the default: **all attributes readable and writable**, because the API only returns these lists when they differ from the default.

#### Evaluation

Inventory, not a finding by itself. Mark for follow-up: `SelfSignUpBlocked: false` (COG-2), any `custom:` attribute plus an empty or broad `Write` list (COG-3), `VerifyBeforeUpdate` empty (COG-4), `PreventUserExistence` `LEGACY` or null (COG-5), `Mfa: OFF`, threat protection `OFF` (COG-6), `HasSecret: true` on clients used by apps (COG-8), `implicit` or `client_credentials` flows (COG-8), callback URLs (COG-9), `Guest: true` (COG-10), `Classic: true` (COG-11), any `RoleMappings` (COG-12), `DeletionProtection: INACTIVE` on production pools (Low).

#### Automated coverage

Security Hub CSPM `Cognito.6` (deletion protection). Prowler `cognito_user_pool_deletion_protection_enabled`, `cognito_user_pool_waf_acl_attached`, and the per-test checks listed below.

#### Detection

Read-only inventory calls are `Describe*`/`List*`/`Get*` management events under `cognito-idp.amazonaws.com` and `cognito-identity.amazonaws.com`.

### GT-AWS-COG-2: Self-sign-up enabled where the application does not expect it

*Guler Tech methodology.*

#### What it checks

Whether anyone can create a user in a pool whose application is invite-only, internal or B2B, and what such a user can then reach.

#### Prerequisites

The client ID from the front-end. Approval to create one test user if self-sign-up turns out to be enabled.

#### Steps

Inside view: `AllowAdminCreateUserOnly` from COG-1. `false` means `SignUp` is open to any holder of a client ID.

Outside view, without creating a user first. Send a sign-up with a deliberately invalid password; when self-sign-up is disabled the response is `NotAuthorizedException` ("SignUp is not permitted for this user pool"), and when it is enabled you usually get a password-policy error instead. The order in which Cognito evaluates these errors isn't documented, so confirm against the inside view.

```bash
aws cognito-idp sign-up --no-sign-request --client-id "$CLIENT" \
  --username gt-probe-$(date +%s)@gt-test.example.com --password 'a' \
  --user-attributes Name=email,Value=gt-probe@gt-test.example.com
```

If the client has a secret, add `--secret-hash "$(secret_hash "$SECRET" "$USERNAME" "$CLIENT")"`.

**Create a test user, lab or explicitly approved only.** Use a mailbox you control on a domain agreed with the client:

```bash
aws cognito-idp sign-up --no-sign-request --client-id "$CLIENT" \
  --username gt-selfsignup@gt-test.example.com --password '<STRONG_TEST_PASSWORD>' \
  --user-attributes Name=email,Value=gt-selfsignup@gt-test.example.com
# "UserConfirmed": true here means a pre sign-up trigger auto-confirms users
aws cognito-idp confirm-sign-up --no-sign-request --client-id "$CLIENT" \
  --username gt-selfsignup@gt-test.example.com --confirmation-code <CODE_FROM_EMAIL>
```

Sign in through the application with Burp running (or with `initiate-auth` if the client allows `USER_PASSWORD_AUTH`) and capture the tokens:

```bash
aws cognito-idp initiate-auth --no-sign-request --client-id "$CLIENT" \
  --auth-flow USER_PASSWORD_AUTH \
  --auth-parameters USERNAME=gt-selfsignup@gt-test.example.com,PASSWORD='<STRONG_TEST_PASSWORD>' \
  --query 'AuthenticationResult.[IdToken,AccessToken]' --output text
```

Then establish what the self-registered user reaches: the application's own authenticated pages and APIs (benign read-only calls), and the identity pool's authenticated role:

```bash
LOGINS="cognito-idp.eu-west-2.amazonaws.com/$POOL=$ID_TOKEN"
ID=$(aws cognito-identity get-id --no-sign-request --identity-pool-id "$IDPOOL" --logins "$LOGINS" \
       --query IdentityId --output text)
aws cognito-identity get-credentials-for-identity --no-sign-request --identity-id "$ID" --logins "$LOGINS"
# export the returned credentials, then:
aws sts get-caller-identity
```

Delete the test user at the end (`aws cognito-idp delete-user --access-token "$ACCESS_TOKEN"`), or leave it for the client to delete as agreed.

#### Observation

Non-compliant (illustrative): sign-up succeeds for an invite-only application, and `get-caller-identity` returns `assumed-role/Cognito_ExampleAuth_Role/CognitoIdentityCredentials`.

Compliant:

```text
An error occurred (NotAuthorizedException) when calling the SignUp operation: SignUp is not permitted for this user pool
```

#### Evaluation

- **Fail:** self-sign-up is enabled on a pool whose application is not meant to allow public registration. Severity follows what the new user reaches: High to Critical when it unlocks tenant data, internal tools or a privileged authenticated role; Medium when it reaches only an empty account shell.
- **Pass:** `AllowAdminCreateUserOnly: true`, or public registration is an intended feature *and* every authenticated-user control (APIs, authenticated IAM role) is designed for untrusted registrants.
- **False positive:** consumer apps where public sign-up is the product. Then the question becomes whether "authenticated" is treated as "trusted" anywhere (it shouldn't be).

#### Automated coverage

Prowler `cognito_user_pool_self_registration_disabled`. No Security Hub CSPM control at the time of writing.

#### Detection

CloudTrail `SignUp` and `ConfirmSignUp` (management events, `eventSource` `cognito-idp.amazonaws.com`), and `Signup_POST` / `signup_POST` for the hosted pages. A spike of sign-ups from new IP ranges, or any sign-up on an invite-only pool, is worth an alert.

### GT-AWS-COG-3: Writable attributes used for authorisation

*Guler Tech methodology.*

#### What it checks

Whether users can set attributes that the application, a Lambda authoriser, a pre token generation trigger or an identity pool rule uses to make authorisation decisions.

#### Prerequisites

Test user A's access token (with the `aws.cognito.signin.user.admin` scope, which tokens from `InitiateAuth` always carry). Knowledge of which claims the back end uses (code review, the client's developers, or observing role-dependent behaviour).

#### Steps

Inside view: from COG-1, list `custom:` attributes and each client's `WriteAttributes`. An empty list means every attribute is writable. Grep the back-end code, authoriser Lambdas and pre token generation triggers for the claim names:

```bash
grep -rnE "custom:(role|admin|is_admin|tenant|tenant_id|org|plan|tier|group|permissions)" ./backend ./lambdas
```

Outside view, read-only first: see which attributes the token holder can read:

```bash
aws cognito-idp get-user --no-sign-request --access-token "$ACCESS_TOKEN_A" --query 'UserAttributes'
```

**Change an attribute on your own test user, lab or explicitly approved only:**

```bash
aws cognito-idp update-user-attributes --no-sign-request --access-token "$ACCESS_TOKEN_A" \
  --user-attributes Name=custom:role,Value=admin
```

A `NotAuthorizedException` stating that the client cannot write the attribute is a pass for that client; repeat with every client ID in the pool, because attribute values are shared across clients and one permissive client is enough.

Refresh the tokens and confirm the claim changed:

```bash
aws cognito-idp initiate-auth --no-sign-request --client-id "$CLIENT" --auth-flow REFRESH_TOKEN_AUTH \
  --auth-parameters REFRESH_TOKEN="$REFRESH_TOKEN_A" --query 'AuthenticationResult.IdToken' --output text > id.jwt
jwt "$(cat id.jwt)" | jq '{sub, "custom:role", token_use, aud}'
```

Then perform one benign, read-only action that only the elevated value should allow (for example, viewing the admin settings page or calling a read-only admin endpoint) and capture the response. Revert the attribute afterwards.

Also test **immutable attributes at sign-up** (when self-sign-up is enabled and approved): `custom:tenant_id` being immutable does not stop a client with write permission from setting it in `SignUp`:

```bash
aws cognito-idp sign-up --no-sign-request --client-id "$CLIENT" \
  --username gt-tenant@gt-test.example.com --password '<STRONG_TEST_PASSWORD>' \
  --user-attributes Name=email,Value=gt-tenant@gt-test.example.com Name=custom:tenant_id,Value=<OTHER_TEST_TENANT>
```

Use a second test tenant the client created for you as the target value, never a real customer's tenant.

#### Observation

Non-compliant (illustrative):

```json
{
  "sub": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
  "custom:role": "admin",
  "token_use": "id",
  "aud": "1example23456789abcdefghij"
}
```

followed by a `200 OK` from an admin-only endpoint.

#### Evaluation

- **Fail (High to Critical):** a user can write an attribute that grants privileges or crosses tenant boundaries. Critical when it reaches administrative functions or other tenants' data.
- **Fail (Medium):** an authorisation-relevant attribute is writable but the back end currently ignores it (latent; one code change from exploitable).
- **Pass:** authorisation data lives in user pool groups (only administrators change group membership), in the client's own database keyed by `sub`, or in attributes excluded from every client's `WriteAttributes`.

#### Automated coverage

None in Security Hub CSPM or Prowler; `WriteAttributes` needs context to judge.

#### Detection

CloudTrail `UpdateUserAttributes` (self-service, authorised by access token) and `AdminUpdateUserAttributes`. Changes to authorisation attributes by anyone other than an admin process should alert. The event identifies the user by `sub`.

### GT-AWS-COG-4: Email and phone changes without verification and account takeover

*Guler Tech methodology.*

#### What it checks

Whether a user can make the application (or a downstream service) treat them as another user by changing `email` or `phone_number`, and whether triggers and federation link or verify identities unsafely.

#### Prerequisites

Two test users A (attacker) and B (victim) created by the client, each with a mailbox you control. Approval to change A's email.

#### Steps

Inside view:

- `UserAttributeUpdateSettings.AttributesRequireVerificationBeforeUpdate` should include `email` (and `phone_number` if used for sign-in or recovery).
- `UsernameAttributes` / `AliasAttributes` and `UsernameConfiguration.CaseSensitive`. Pools created through the API without a `UsernameConfiguration` have historically been case-sensitive; check rather than assume.
- `LambdaConfig.PreSignUp` code: look for `autoVerifyEmail`, `autoVerifyPhone`, and calls to `AdminLinkProviderForUser` that match by email.
- Federated IdPs: `aws cognito-idp describe-identity-provider --user-pool-id "$POOL" --provider-name <name>` and read `AttributeMapping`. Mapping an external `email_verified` (or a constant) into Cognito's `email_verified` trusts the external IdP's verification.
- Back-end code: is the user looked up by `sub` or by `email`? Is `email_verified` checked? Is the email lowercased before lookup?

**Outside view, lab or explicitly approved only.** As A, change A's email to B's address, then to a case variant of B's address:

```bash
aws cognito-idp update-user-attributes --no-sign-request --access-token "$ACCESS_TOKEN_A" \
  --user-attributes Name=email,Value=gt-victim-b@gt-test.example.com
aws cognito-idp get-user --no-sign-request --access-token "$ACCESS_TOKEN_A" \
  --query "UserAttributes[?Name=='email' || Name=='email_verified']"
```

Three outcomes:

1. The request fails with an alias conflict, or the old value remains active pending verification (verification-before-update is on): Cognito-side pass.
2. The new, unverified value becomes active. Refresh A's tokens, decode the ID token (`email` is B's, `email_verified` is `false`), then sign in to the application as A and check whose profile and data you see. If the application shows B's account, that is account takeover.
3. With `GT-Victim-B@...` (case variant), sign in to the application with that address and A's password. If the application lowercases the address and maps it to B, that is the Flickr pattern.

Never use a real customer's email address as the target. Restore A's email afterwards.

#### Observation

The ID token claims after the change, and screenshots of the application session showing which account was reached.

#### Evaluation

- **Fail (Critical):** A reaches B's account in the application or in a federated downstream service.
- **Fail (Medium):** the email changes to an unverified value that the application displays or uses for notifications (password reset links, invoices sent to the attacker's chosen address), but identity is keyed on `sub`.
- **Fail (Medium):** a pre sign-up trigger auto-verifies emails or links federated identities by unverified email; Critical if you can show the takeover.
- **Pass:** verification is required before update, the application keys on `sub`, and any use of `email` checks `email_verified`.

#### Automated coverage

None.

#### Detection

`UpdateUserAttributes` followed by sign-ins (`InitiateAuth`, `login_POST`) for the same `sub` with a new email; `VerifyUserAttribute` events show completed verifications. Threat protection user activity logs (Plus plan) add device and location context.

### GT-AWS-COG-5: User enumeration through error responses

*Guler Tech methodology.*

#### What it checks

Whether sign-in, password reset and confirmation responses reveal which usernames or emails are registered.

#### Prerequisites

Test user A's username and a username that certainly doesn't exist (a random string on your test domain). No real customer identifiers.

#### Steps

Inside view: `PreventUserExistenceErrors` per client from COG-1. `ENABLED` is the target; `LEGACY` (or absent) means existence errors are returned.

Outside view, two requests per client:

```bash
for u in gt-user-a@gt-test.example.com gt-nobody-$(openssl rand -hex 6)@gt-test.example.com; do
  aws cognito-idp initiate-auth --no-sign-request --client-id "$CLIENT" --auth-flow USER_PASSWORD_AUTH \
    --auth-parameters USERNAME="$u",PASSWORD='Wrong-Password-1!' 2>&1 | tail -1
done
```

```text
An error occurred (NotAuthorizedException) when calling the InitiateAuth operation: Incorrect username or password.
An error occurred (UserNotFoundException) when calling the InitiateAuth operation: User does not exist.
```

If the client doesn't allow `USER_PASSWORD_AUTH`, run the same comparison through the application's own sign-in (SRP) in Burp, or with `pycognito`. Also compare `forgot-password` for the non-existent user (with `LEGACY` it returns `UserNotFoundException`; don't run it for A unless A's mailbox is yours, because it sends a code). Note that `SignUp` always returns `UsernameExistsException` for a taken *username* regardless of this setting; in pools that use email as an alias it does not reveal registered *emails*.

#### Observation

Distinguishable responses (`UserNotFoundException` versus `NotAuthorizedException`) on any client.

#### Evaluation

- **Fail (Low to Medium):** existence errors returned. Medium when the identifiers are emails or phone numbers of a sensitive user base (healthcare, finance, dating) or when enumeration feeds a credential-stuffing risk with no MFA (COG-6).
- **Pass:** `ENABLED` on every client, and the application's own pages don't reintroduce the difference in wording, status code or timing.
- **Caveat:** with `ENABLED`, AWS notes that SRP sign-in may still reveal users in pools with email, phone or preferred username aliases; test that path specifically.

#### Automated coverage

Prowler `cognito_user_pool_client_prevent_user_existence_errors`.

#### Detection

CloudTrail `InitiateAuth` with `errorCode` `UserNotFoundException` or `NotAuthorizedException` at volume from one source; the CloudWatch Logs Insights queries in AWS's Cognito logging documentation group these by `sourceIPAddress`.

### GT-AWS-COG-6: MFA, password policy and threat protection

*Guler Tech methodology.*

#### What it checks

Whether password-based sign-in is backed by MFA, a reasonable password policy, and detection of compromised credentials and risky sign-ins, in proportion to the value of the accounts.

#### Prerequisites

Inside view. Optionally test user A for observing behaviour.

#### Steps

From COG-1: `MfaConfiguration` (`OFF`, `OPTIONAL`, `ON`), enabled factors (`SoftwareTokenMfaConfiguration`, `SmsMfaConfiguration`, `EmailMfaConfiguration`), the password policy (`MinimumLength`, character classes, `TemporaryPasswordValidityDays`, `PasswordHistorySize`), `UserPoolTier`, `UserPoolAddOns.AdvancedSecurityMode` (`OFF`, `AUDIT`, `ENFORCED`), the custom-authentication mode, the risk configuration (`describe-risk-configuration`) and any associated WAF web ACL.

For pools with `OPTIONAL` MFA, ask how many privileged users have MFA registered; the client can answer from their own tooling without you calling `ListUsers`.

Outside view (limited and approved): a few failed sign-ins against test user A to observe lockout and any WAF rate limiting. Do not run password spraying or credential stuffing against real accounts.

#### Observation

The settings, and for threat protection whether compromised-credential actions are `BLOCK` and which adaptive authentication actions apply at each risk level.

#### Evaluation

- **Fail (Medium):** MFA `OFF` (or `OPTIONAL` with privileged users unenrolled) on a pool with password sign-in protecting sensitive data or administrative functions; High for workforce/admin pools reachable from the internet.
- **Fail (Low to Medium):** password policy below the client's standard or below Security Hub CSPM's default (minimum 8 with all four character classes, temporary passwords valid at most 7 days). Length matters more than character classes; we recommend a minimum of 12 to 14 for password-only pools.
- **Fail (Low):** threat protection off or in audit mode. Treat as a recommendation when MFA is enforced; Medium when the pool is password-only, high-value, and has no other credential-stuffing control (WAF rate rules, bot control).
- **Pass:** MFA `ON` (TOTP or passkeys preferred over SMS) or passwordless sign-in, a sensible password policy, and threat protection in full-function mode or an equivalent control in front of the pool.

#### Automated coverage

Security Hub CSPM `Cognito.1` (threat protection full function for standard authentication), `Cognito.4` (same for custom authentication), `Cognito.3` (password policy), `Cognito.5` (MFA for password-only sign-in). Prowler `cognito_user_pool_mfa_enabled`, `cognito_user_pool_advanced_security_enabled`, `cognito_user_pool_blocks_compromised_credentials_sign_in_attempts`, `cognito_user_pool_blocks_potential_malicious_sign_in_attempts`, the `cognito_user_pool_password_policy_*` checks, `cognito_user_pool_temporary_password_expiration`, `cognito_user_pool_account_recovery_sms_not_preferred`, `cognito_user_pool_waf_acl_attached`. Prowler's minimum-length check uses 14 characters, stricter than Security Hub CSPM's default of 8.

#### Detection

`InitiateAuth` / `RespondToAuthChallenge` failures by source IP; changes to `SetUserPoolMfaConfig`, `UpdateUserPool` (password policy, add-ons) and `SetRiskConfiguration`. With threat protection, risk events and user activity logs can be exported to CloudWatch Logs, S3 or Firehose.

### GT-AWS-COG-7: Token validation in APIs and back ends

*Guler Tech methodology.*

#### What it checks

Whether every API that accepts Cognito tokens validates them the way AWS documents: signature against the right JWKS, `iss` pinned to the right pool, `aud`/`client_id` pinned to the right client, `token_use` matching the token type the API expects, `exp`, and revocation where it matters.

#### Prerequisites

Tokens for test user A from each relevant app client. A user pool in **your own testing account** with a user, to produce validly signed tokens from a different issuer. The list of token-consuming APIs.

#### Steps

Inside view, managed authorisers:

```bash
# REST APIs: Cognito authorisers and which methods require OAuth scopes
aws apigateway get-authorizers --rest-api-id a1b2c3d4e5 --profile client-audit \
  --query 'items[?type==`COGNITO_USER_POOLS`].[name,providerARNs]'
aws apigateway get-method --rest-api-id a1b2c3d4e5 --resource-id abc123 --http-method GET \
  --profile client-audit --query '{auth: authorizationType, scopes: authorizationScopes}'
# HTTP APIs: JWT authorisers
aws apigatewayv2 get-authorizers --api-id a1b2c3d4e5 --profile client-audit \
  --query 'Items[?AuthorizerType==`JWT`].JwtConfiguration'
```

For REST API Cognito authorisers, a method with no authorisation scopes accepts an ID token, and a method with scopes expects an access token carrying them; check the current API Gateway documentation for your API type. HTTP API JWT authorisers validate `iss`, the audience (`aud`, or `client_id` when there is no `aud`), expiry and scopes; AWS's documentation does not describe a `token_use` check, so without required scopes an ID token from the same client may be accepted where an access token is intended.

For custom code (Lambda authorisers, back-end middleware), find the verification call. A correct Node.js implementation with AWS's library looks like this:

```javascript
const { CognitoJwtVerifier } = require("aws-jwt-verify");
const verifier = CognitoJwtVerifier.create({
  userPoolId: "eu-west-2_EXAMPLE11",
  tokenUse: "access",
  clientId: "1example23456789abcdefghij",
});
const payload = await verifier.verify(token); // throws on bad signature, iss, client_id, token_use or exp
```

Red flags in code review: `jwt.decode` without verify, JWKS fetched from the token's own `iss`, `clientId: null`, no `tokenUse`, `ignoreExpiration`, and algorithm lists that include `HS256` or `none`.

Outside view, against each API with a benign read-only request:

```bash
API=https://api.example.com/v1/me
call() { curl -s -o /dev/null -w "%{http_code}  $1\n" -H "Authorization: Bearer $2" "$API"; }
call "access token (expected)"          "$ACCESS_TOKEN_A"
call "ID token instead of access"       "$ID_TOKEN_A"
call "token from another app client"    "$ACCESS_TOKEN_A_OTHER_CLIENT"
call "token from tester-owned pool"     "$ACCESS_TOKEN_FROM_GT_POOL"
call "expired token"                    "$EXPIRED_ACCESS_TOKEN_A"
call "payload edited, signature kept"   "$TAMPERED_TOKEN_A"
```

For revocation, sign A out globally (approved; A is your user), then call again with the old access token:

```bash
aws cognito-idp global-sign-out --no-sign-request --access-token "$ACCESS_TOKEN_A"
call "after global sign-out" "$ACCESS_TOKEN_A"
```

Standard JWT attacks (`alg: none`, key confusion, `kid` injection) apply to custom verifiers as to any JWT consumer; test them with your usual tooling.

#### Observation

Non-compliant (illustrative):

```text
200  access token (expected)
200  ID token instead of access
200  token from another app client
401  token from tester-owned pool
401  expired token
401  payload edited, signature kept
200  after global sign-out
```

#### Evaluation

- **Fail (Critical):** a token from a pool you control, an unsigned or tampered token, or an expired token is accepted. This is authentication bypass.
- **Fail (High):** a token from a different app client of the same pool is accepted by an API meant for another client, and that other client is less trusted (self-sign-up enabled, partner client, test client), or an ID token is accepted and the API trusts profile claims inside it that users can write (COG-3).
- **Fail (Low to Medium):** tokens still work after global sign-out or revocation for their full lifetime; severity depends on lifetime and the sensitivity of the API. AWS documents that offline verification can't see revocation, so this is a design decision to make explicitly, with short access token lifetimes.
- **Pass:** only the expected token type from the expected client and pool is accepted, and lifetimes are short.

#### Automated coverage

None. This is application testing.

#### Detection

Little on the AWS side: token validation happens in the client's code. API Gateway access logs and application logs should record authoriser failures (`401`/`403` counts by reason). Cognito logs `GlobalSignOut` and `RevokeToken`.

### GT-AWS-COG-8: App client secrets, authentication flows and token lifetimes

*Guler Tech methodology.*

#### What it checks

Whether each app client's type and settings fit where it runs: no secrets in public clients, no `client_credentials` on a client whose secret is exposed, only the authentication flows the app uses, no implicit grant, reasonable token lifetimes, and token revocation enabled.

#### Prerequisites

COG-1 inventory, the mapping of clients to applications, and the decompiled mobile apps and web bundles from the [recon note](/cloud/aws-unauthenticated-recon/).

#### Steps

Inside view, from COG-1, per client:

- `HasSecret: true` on a client used by a mobile app or SPA.
- `OAuthFlows` containing `client_credentials`, with the custom scopes in `Scopes`; `implicit`.
- `AuthFlows` containing `ALLOW_USER_PASSWORD_AUTH` (password sent to Cognito rather than SRP; acceptable if deliberate, for example to get compromised-credential checks), `ALLOW_ADMIN_USER_PASSWORD_AUTH` on clients that are not server-side, `ALLOW_CUSTOM_AUTH` (review the challenge triggers).
- `RefreshTokenValidity` and units; `EnableTokenRevocation`.

Outside view: search the apps for the secret next to the client ID (the [hardcoded data in the app package note](/mobile/maswe-0004-sensitive-data-hardcoded-app-package/) covers extraction):

```bash
grep -rnE "client_?secret|clientSecret|appClientSecret" app-src site-mirror | head
```

If you find a secret for a client that allows `client_credentials`, **lab or explicitly approved only**, obtain one token to prove the grant and decode it; don't use it against APIs beyond a single read-only call if the client approves that:

```bash
curl -s -u "$CLIENT:$SECRET" -d 'grant_type=client_credentials' \
  "https://example-auth.auth.eu-west-2.amazoncognito.com/oauth2/token" | jq -r .access_token > m2m.jwt
jwt "$(cat m2m.jwt)" | jq '{client_id, scope, token_use}'
```

#### Observation

Clients with secrets embedded in public apps, and the scopes a leaked secret yields.

#### Evaluation

- **Fail (High to Critical):** a secret embedded in a public app for a client that allows `client_credentials`; rate by what the custom scopes authorise on the resource servers.
- **Fail (Medium):** implicit grant enabled on a production client; refresh tokens valid for very long periods (months or years) with revocation disabled.
- **Fail (Low):** a secret embedded in a public app for a client without `client_credentials` (it adds nothing an attacker can't do with the client ID; the finding is the false sense of security), unused authentication flows enabled.
- **Pass:** public clients have no secret and use the authorisation code grant with PKCE; confidential clients' secrets stay server-side; only the flows in use are enabled; token revocation is on; access and ID tokens last no more than an hour, refresh tokens as short as the user experience allows.

AWS has also introduced a `GetClientToken` API with an `ALLOW_CLIENT_TOKEN_AUTH` flow that issues M2M access tokens to clients with a secret without a user pool domain; check `AuthFlows` for it on any client whose secret could be exposed.

#### Automated coverage

Prowler `cognito_user_pool_client_token_revocation_enabled`. No Security Hub CSPM control.

#### Detection

`Token_POST` events for client-credentials grants (hosted endpoint) and `GetClientToken` API calls; a confidential client suddenly requesting tokens from new IP ranges.

### GT-AWS-COG-9: Managed login callback URLs and client registration

*Guler Tech methodology.*

#### What it checks

Whether the callback and sign-out URL allow-lists only contain URLs the client controls and needs, whether the authorisation server enforces them, and whether dynamic client registration lets outsiders add their own clients.

#### Prerequisites

COG-1 inventory. The user pool domain.

#### Steps

Inside view, review every client's `CallbackURLs` and `LogoutURLs`. Flag:

- `http://localhost` or `127.0.0.1` on production clients (any local process on a victim machine can receive codes);
- staging, preview, tunnelling-service or third-party hosting domains;
- domains that no longer resolve or point at deleted resources (cross-check with the [recon note's](/cloud/aws-unauthenticated-recon/) dangling DNS test);
- custom URL schemes such as `myapp://callback` on clients without PKCE, because other apps can register the same scheme;
- callbacks on pages with open redirects or third-party scripts that could leak the code or tokens via `Referer` or script access.

Check dynamic client registration:

```bash
aws cognito-idp describe-user-pool --user-pool-id "$POOL" --profile client-audit --query 'UserPool.DcrConfiguration'
curl -s "https://cognito-idp.eu-west-2.amazonaws.com/$POOL/.well-known/openid-configuration" | jq '.registration_endpoint'
```

A `registration_endpoint` in the discovery document means registration is on; the configuration tells you whether open (unauthenticated) registration is allowed and which grants and scopes registered clients may request. List registered clients and review their callback URLs (AWS documents filtering `ListUserPoolClients` by a client type of `DCR`).

Outside view, confirm exact matching of `redirect_uri` with variations of a registered URL (no user interaction needed, nothing is created):

```bash
AUTH="https://example-auth.auth.eu-west-2.amazoncognito.com/oauth2/authorize"
for ru in "https://app.example.com/callback" \
          "https://app.example.com/callback/../evil" \
          "https://app.example.com.gt-test.example.com/callback" \
          "https://gt-test.example.com/callback"; do
  printf '%s  ' "$ru"
  curl -s -o /dev/null -w '%{http_code} %{redirect_url}\n' \
    "$AUTH?client_id=$CLIENT&response_type=code&scope=openid&redirect_uri=$(jq -rn --arg u "$ru" '$u|@uri')"
done
```

Registered URLs should redirect to the login page; anything else should produce an error (a redirect to the domain's error page indicating a redirect mismatch), never a redirect to the supplied URL.

Do not register a client through open registration unless the client explicitly approves it; if they do, register one client with a callback on a domain you control, prove that an already-signed-in test user is sent there with a code, and delete the client.

#### Observation

The allow-lists with flagged entries, the result of the `redirect_uri` variations, and the registration configuration.

#### Evaluation

- **Fail (High):** a callback URL on a domain the client does not control (dangling or third-party), or open dynamic client registration that allows the authorisation code grant without restrictions the client has thought through; both lead to authorisation code or token theft for signed-in users.
- **Fail (Medium):** `localhost` callbacks or custom schemes without PKCE on production clients; implicit grant combined with callbacks that load third-party scripts.
- **Pass:** exact HTTPS callbacks on domains the client controls, PKCE in public clients, registration off or authenticated only.

#### Automated coverage

None.

#### Detection

CloudTrail `Register_POST` events for dynamic client registration (including rejected requests), `UpdateUserPoolClient` for allow-list changes, and `OAuth2_Authorize_GET` / `Error_GET` events for authorisation requests that fail.

### GT-AWS-COG-10: Identity pool guest access and the unauthenticated role

*Guler Tech methodology.*

#### What it checks

Whether the identity pool issues AWS credentials to anyone, and what those credentials can actually do after Cognito's scope-down.

#### Prerequisites

The identity pool ID (from the front-end or COG-1). Inside view for the role policies.

#### Steps

Outside view, the benign proof (the same as in the recon note):

```bash
ID=$(aws cognito-identity get-id --no-sign-request --identity-pool-id "$IDPOOL" --query IdentityId --output text)
aws cognito-identity get-credentials-for-identity --no-sign-request --identity-id "$ID" > guest.json
export AWS_ACCESS_KEY_ID=$(jq -r .Credentials.AccessKeyId guest.json)
export AWS_SECRET_ACCESS_KEY=$(jq -r .Credentials.SecretKey guest.json)
export AWS_SESSION_TOKEN=$(jq -r .Credentials.SessionToken guest.json)
aws sts get-caller-identity
unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN
```

Inside view, work out what the unauthenticated role can do by reading its policies, not by trying actions with guest credentials:

```bash
ROLE=$(aws cognito-identity get-identity-pool-roles --identity-pool-id "$IDPOOL" --profile client-audit \
         --query 'Roles.unauthenticated' --output text | awk -F/ '{print $NF}')
aws iam list-attached-role-policies --role-name "$ROLE" --profile client-audit
for p in $(aws iam list-role-policies --role-name "$ROLE" --profile client-audit --query 'PolicyNames[]' --output text); do
  aws iam get-role-policy --role-name "$ROLE" --policy-name "$p" --profile client-audit --query PolicyDocument
done
aws iam simulate-principal-policy --profile client-audit \
  --policy-source-arn "arn:aws:iam::111122223333:role/$ROLE" \
  --action-names s3:ListBucket s3:GetObject s3:PutObject dynamodb:Scan dynamodb:GetItem \
                 lambda:InvokeFunction cognito-idp:ListUsers sns:Publish sqs:SendMessage kms:Decrypt \
  --query 'EvaluationResults[].[EvalActionName,EvalDecision]' --output table
```

Two corrections to the simulation:

- `simulate-principal-policy` doesn't know about the enhanced-flow **session policies**. Intersect the result with the scope-down list in AWS's documentation: actions outside it are denied to guests in the enhanced flow even if the role allows them. Actions inside it (S3, DynamoDB, Lambda, SQS, SNS, Cognito user pools and more) are not reduced at all.
- If classic flow is enabled (COG-11), there is no Cognito session policy, so the role's permissions apply in full.

Resource policies matter too: a bucket or function policy may grant the role more (or deny it). Check the resources the role points at, and pass `--resource-policy` to the simulation where relevant.

Prowler and cloudsplaining can flag over-broad statements in the role's policies; [PMapper](https://github.com/nccgroup/PMapper) shows whether the role can reach other principals.

#### Observation

`get-caller-identity` showing the unauthenticated role, and a table of effective guest permissions on named resources.

#### Evaluation

- **Fail (Critical):** guests can read or write sensitive data (S3 objects, DynamoDB items, other users' records), list user pool users, invoke functions that perform privileged actions, decrypt with KMS keys that protect sensitive data, or reach any path to privilege escalation (see the [privilege escalation note](/cloud/aws-iam-privilege-escalation/)).
- **Fail (Medium):** guests have permissions broader than the anonymous feature needs (wildcard resources, write where read suffices) without demonstrated sensitive data.
- **Pass:** guest access is off, or the unauthenticated role allows only the narrow actions the anonymous feature needs (for example `mobiletargeting:PutEvents` on one application or `rum:PutRumEvents` on one app monitor), scoped to specific resources and, where possible, to `${cognito-identity.amazonaws.com:sub}` prefixes or keys.

#### Automated coverage

Security Hub CSPM `Cognito.2` (identity pools should not allow unauthenticated identities). Prowler `cognito_identity_pool_guest_access_disabled`. Neither evaluates what the role can do; that is this test's job.

#### Detection

`GetId` and `GetCredentialsForIdentity` are data events (enable the `AWS::Cognito::IdentityPool` selector to see them). Every action taken with guest credentials appears in CloudTrail under `assumed-role/<unauth role>/CognitoIdentityCredentials`; alert on guest-role calls to APIs the app never uses. GuardDuty's `*/AnomalousBehavior` and `MaliciousIPCaller` findings apply to these sessions like any other role session.

### GT-AWS-COG-11: Basic (classic) flow and role trust policies

*Guler Tech methodology.*

#### What it checks

Whether the classic flow is enabled, and whether every role that trusts `cognito-identity.amazonaws.com` restricts the identity pool (`aud`) and the authentication state (`amr`), so that guests cannot assume authenticated or other privileged roles directly through STS.

#### Prerequisites

Inside view. For the proof: an identity pool with classic flow and guest access enabled, and approval.

#### Steps

Inside view, `AllowClassicFlow` from COG-1, then every role in the account that trusts the Cognito federated principal, with its conditions:

```bash
aws iam list-roles --profile client-audit --output json | jq -r '
  .Roles[] | select(any(.AssumeRolePolicyDocument.Statement[];
      (.Principal.Federated // "") == "cognito-identity.amazonaws.com"))
  | [.RoleName,
     (.AssumeRolePolicyDocument.Statement[] | .Condition | tostring)] | @tsv'
```

For each role, record: is there a `cognito-identity.amazonaws.com:aud` condition, which pool IDs does it list, and do those pools allow guests; is there an `amr` condition, and does it require `authenticated` for roles meant for signed-in users.

**Proof, lab or explicitly approved only** (classic flow on, guest access on, a role that should be authenticated-only lacks an `amr` condition):

```bash
ID=$(aws cognito-identity get-id --no-sign-request --identity-pool-id "$IDPOOL" --query IdentityId --output text)
TOKEN=$(aws cognito-identity get-open-id-token --no-sign-request --identity-id "$ID" --query Token --output text)
jwt "$TOKEN" | jq '{aud, amr}'
aws sts assume-role-with-web-identity --no-sign-request \
  --role-arn arn:aws:iam::111122223333:role/Cognito_ExampleAuth_Role \
  --role-session-name gt-classic-flow-test --web-identity-token "$TOKEN" \
  --query 'AssumedRoleUser.Arn'
```

Stop at the returned ARN (or at `sts get-caller-identity` with the returned credentials). The token's `amr` shows `unauthenticated`; a successful assumption of the authenticated role is the finding.

#### Observation

Non-compliant (illustrative) trust policy:

```json
{
  "Effect": "Allow",
  "Principal": { "Federated": "cognito-identity.amazonaws.com" },
  "Action": "sts:AssumeRoleWithWebIdentity",
  "Condition": {
    "StringEquals": { "cognito-identity.amazonaws.com:aud": "eu-west-2:00000000-1111-2222-3333-444444444444" }
  }
}
```

on a role named for authenticated users, in an account whose identity pool has `AllowClassicFlow: true` and `AllowUnauthenticatedIdentities: true`.

#### Evaluation

- **Fail (High to Critical):** a guest identity can assume a role meant for authenticated users or any more privileged role; rate by that role's permissions.
- **Fail (High):** a legacy trust policy with no `aud` condition on any role: any identity pool in the same account (including a guest-enabled one) can produce tokens that satisfy it in the classic flow.
- **Fail (Low):** classic flow enabled but every trust policy has correct `aud` and `amr` conditions (unnecessary surface; also removes the guest scope-down).
- **Pass:** classic flow off; every Cognito-trusting role has `aud` limited to the intended pool and `amr` set to `authenticated` or `unauthenticated` as appropriate.

#### Automated coverage

None in Security Hub CSPM or Prowler for classic flow or Cognito trust conditions. IAM Access Analyzer external access findings consider trust policies; review its findings for these roles.

#### Detection

`AssumeRoleWithWebIdentity` management events where `userIdentity.identityProvider` is `cognito-identity.amazonaws.com` and the request was not made by the Cognito service (in the classic flow the client calls STS directly, from its own IP address); `GetOpenIdToken` data events; `UpdateIdentityPool` events that set `AllowClassicFlow`.

### GT-AWS-COG-12: Role mapping rules and token-based role selection

*Guler Tech methodology.*

#### What it checks

Whether role mapping in the identity pool can be steered by claims users control, and whether the fallback for unmatched users is safe.

#### Prerequisites

Inside view. For the proof, test user A and approval to change one of A's attributes (COG-3).

#### Steps

Inside view:

```bash
aws cognito-identity get-identity-pool-roles --identity-pool-id "$IDPOOL" --profile client-audit \
  --query 'RoleMappings' --output json
```

For `Type: Rules`, list each rule's `Claim`, `MatchType`, `Value` and `RoleARN`. A rule is dangerous when the claim is writable by the user (`custom:*` in a client's `WriteAttributes`, `email`, `name`, `locale`, `website`...) or comes from a federated IdP where users control the value, and especially with `Contains` or `StartsWith`. For `Type: Token`, list user pool groups and their roles (`aws cognito-idp list-groups --user-pool-id "$POOL"`), check that privileged group membership is admin-controlled, and check that `RoleArn` values are what the group name suggests. For both, `AmbiguousRoleResolution` should be `Deny` unless the default authenticated role is deliberately minimal.

**Proof, lab or explicitly approved only:** after setting a mapped attribute on test user A (COG-3), get fresh tokens and credentials and show the role changed:

```bash
LOGINS="cognito-idp.eu-west-2.amazonaws.com/$POOL=$ID_TOKEN_A"
ID=$(aws cognito-identity get-id --no-sign-request --identity-pool-id "$IDPOOL" --logins "$LOGINS" --query IdentityId --output text)
aws cognito-identity get-credentials-for-identity --no-sign-request --identity-id "$ID" --logins "$LOGINS" > a.json
# export the credentials from a.json, then:
aws sts get-caller-identity --query Arn
```

#### Observation

The rule set, and the role ARN before and after the attribute change.

#### Evaluation

- **Fail (High to Critical):** a user-controlled claim selects a more privileged role; rate by that role.
- **Fail (Medium):** `AmbiguousRoleResolution: AuthenticatedRole` where the default authenticated role is broader than an unmatched user should get.
- **Pass:** rules use only claims users cannot set (admin-managed groups, IdP claims the IdP asserts and users can't edit), exact matching, and `Deny` as the fallback.

#### Automated coverage

None.

#### Detection

`SetIdentityPoolRoles` changes (management events); role sessions under privileged Cognito-mapped roles for identities that normally receive the default role.

## Hardening

**User pool baseline** (Terraform). Attribute names and settings are illustrative; `user_pool_tier` and threat protection settings need a recent AWS provider version, so check your provider's documentation.

```hcl
resource "aws_cognito_user_pool" "app" {
  name                = "example-app"
  deletion_protection = "ACTIVE"
  mfa_configuration   = "ON"
  user_pool_tier      = "PLUS"

  admin_create_user_config {
    allow_admin_create_user_only = true            # invite-only applications
  }

  username_attributes = ["email"]
  username_configuration {
    case_sensitive = false
  }

  auto_verified_attributes = ["email"]
  user_attribute_update_settings {
    attributes_require_verification_before_update = ["email"]
  }

  software_token_mfa_configuration {
    enabled = true
  }

  password_policy {
    minimum_length                   = 14
    require_lowercase                = true
    require_uppercase                = true
    require_numbers                  = true
    require_symbols                  = true
    temporary_password_validity_days = 3
  }

  user_pool_add_ons {
    advanced_security_mode = "ENFORCED"
  }

  schema {
    name                = "tenant_id"
    attribute_data_type = "String"
    mutable             = false
    string_attribute_constraints {
      min_length = 1
      max_length = 64
    }
  }
}
```

**App client baseline** for a public (browser or mobile) client:

```hcl
resource "aws_cognito_user_pool_client" "web" {
  name                                 = "web"
  user_pool_id                         = aws_cognito_user_pool.app.id
  generate_secret                      = false
  explicit_auth_flows                  = ["ALLOW_USER_SRP_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]
  allowed_oauth_flows_user_pool_client = true
  allowed_oauth_flows                  = ["code"]
  allowed_oauth_scopes                 = ["openid", "email", "profile"]
  supported_identity_providers         = ["COGNITO"]
  callback_urls                        = ["https://app.example.com/callback"]
  logout_urls                          = ["https://app.example.com/"]
  prevent_user_existence_errors        = "ENABLED"
  enable_token_revocation              = true
  access_token_validity                = 60
  id_token_validity                    = 60
  refresh_token_validity               = 7
  token_validity_units {
    access_token  = "minutes"
    id_token      = "minutes"
    refresh_token = "days"
  }
  read_attributes  = ["email", "email_verified", "name", "custom:tenant_id"]
  write_attributes = ["name"]   # never authorisation attributes, never email unless verification-before-update is on
}
```

Keep authorisation data out of user-writable attributes altogether: use user pool groups (admin-managed), or the application's own database keyed by `sub`. If you need claims in tokens, add them in a pre token generation trigger from a trusted source, not from attributes the user can write.

**Back-end verification**: always verify with a library that pins the pool, client and token type (`aws-jwt-verify` for Node.js, shown in COG-7; equivalent options exist for other languages), identify users by `sub`, check `email_verified` before using `email`, and keep access tokens short-lived. For HTTP APIs with JWT authorisers, require scopes on routes so that only access tokens pass.

**Identity pool baseline:**

```hcl
resource "aws_cognito_identity_pool" "app" {
  identity_pool_name               = "example_app"
  allow_unauthenticated_identities = false
  allow_classic_flow               = false

  cognito_identity_providers {
    provider_name           = aws_cognito_user_pool.app.endpoint
    client_id               = aws_cognito_user_pool_client.web.id
    server_side_token_check = true
  }
}
```

`server_side_token_check` makes the identity pool check with the user pool that the user hasn't been signed out globally or deleted before issuing credentials.

**Role trust policies** with both conditions, for every role an identity pool uses (the authenticated example; use `unauthenticated` for the guest role):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": { "Federated": "cognito-identity.amazonaws.com" },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": { "cognito-identity.amazonaws.com:aud": "eu-west-2:00000000-1111-2222-3333-444444444444" },
        "ForAnyValue:StringLike": { "cognito-identity.amazonaws.com:amr": "authenticated" }
      }
    }
  ]
}
```

Re-save any legacy Cognito trust policy that lacks `aud`; IAM will now insist on the condition, which is the point.

**Guest role, if you need guest access at all:** grant only what the anonymous feature uses, on named resources, partitioned per identity where data is involved:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "rum:PutRumEvents",
      "Resource": "arn:aws:rum:eu-west-2:111122223333:appmonitor/example-web"
    }
  ]
}
```

and for per-user storage, scope S3 keys or DynamoDB partition keys to `${cognito-identity.amazonaws.com:sub}` as AWS's examples show (authenticated identities only; guests have no stable identity).

**Role mapping**: use token-based mapping from admin-managed groups, or rules on claims users cannot change, with `AmbiguousRoleResolution` set to `Deny`.

**Managed login and registration**: exact HTTPS callback URLs on domains the client controls, PKCE in public clients, implicit grant off, dynamic client registration off unless needed and then authenticated-only, with rate-based WAF rules on `/oauth2/register` as AWS recommends.

**WAF**: associate a web ACL with each user pool for rate limiting and bot control on sign-in, sign-up and password reset; threat protection does not apply rate limits.

**Logging**: enable CloudTrail data events for `AWS::Cognito::IdentityPool`, export threat protection logs, and alert on `UpdateUserPool`, `UpdateUserPoolClient`, `UpdateIdentityPool`, `SetIdentityPoolRoles` and `SetRiskConfiguration` changes outside your deployment pipeline (see the [CloudTrail note](/cloud/aws-cloudtrail-logging/) and the [monitoring note](/cloud/aws-cloudwatch-eventbridge-monitoring/)).

**AWS Config rules**: `cognito-identity-pool-unauth-access-check`, `cognito-user-pool-mfa-enabled`, `cognito-user-pool-advanced-security-enabled`, `cognito-userpool-cust-auth-threat-full-check`, `cognito-user-pool-password-policy-check`, `cognito-user-pool-deletion-protection-enabled` (these are the rules behind `Cognito.1` to `Cognito.6`).

## Real-world cases

- **Flickr account takeover (Lauritz Holtmann, 2021).** Flickr's login ran on Cognito. A signed-in attacker used their own access token with `UpdateUserAttributes` to set their `email` to a case variant of the victim's address; Cognito marked it unverified, but Flickr lowercased emails, ignored `email_verified` and identified users by email, so the attacker could sign in as the victim with their own password. Reported in September 2021 and fixed within a day. [Flickr Account Takeover](https://security.lauritz-holtmann.de/advisories/flickr-account-takeover/).
- **Self-sign-up to administrator (NotSoSecure, 2020).** A login page with no sign-up option, but the user pool allowed `SignUp`. The self-registered user received identity pool credentials with full Lambda access, which led through a Lambda function's environment to administrator. [Hacking AWS Cognito Misconfigurations](https://notsosecure.com/hacking-aws-cognito-misconfigurations).
- **Case-variant email takeover (Cobalt, 2026).** The same three conditions as Flickr (writable email, email-keyed identity, lowercase normalisation) in a 2026 penetration test write-up, showing the pattern is still common. [Full Account Takeover via AWS Cognito Misconfiguration](https://www.cobalt.io/blog/full-account-takeover-via-aws-cognito-misconfiguration).
- **Hacking The Cloud** documents both [self-sign-up abuse](https://hackingthe.cloud/aws/exploitation/cognito_user_self_signup/) and [identity pool excessive privileges](https://hackingthe.cloud/aws/exploitation/cognito_identity_pool_excessive_privileges/) with lab-friendly walkthroughs.

More in our [AWS incidents and writeups](/cloud/aws-security-incidents-and-writeups/) page and the [bug bounty reading list](/bug-bounty-writeups/).

## Rating findings

| Finding | Typical severity | Reasoning |
|---|---|---|
| API accepts tokens from another pool, unsigned, tampered or expired tokens | Critical | Authentication bypass for any internet user |
| Email change leads to another user's account (verification or normalisation flaw) | Critical | Account takeover of any user whose email is known; needs only a self-registered or existing account |
| Guest credentials can read or write sensitive data or escalate | Critical | Unauthenticated internet attacker gets AWS access; account-level blast radius when escalation exists |
| Guest can assume the authenticated or a privileged role via classic flow | High to Critical | Rated by the assumed role; precondition is only the public identity pool ID |
| User-writable attribute drives authorisation or tenant selection | High to Critical | Any authenticated user (or any internet user, with self-sign-up) becomes admin or crosses tenants |
| User-controlled claim selects a privileged role in role mapping | High to Critical | Same as above, in AWS rather than in the app |
| Self-sign-up on an invite-only application | Medium to Critical | Rated by what an authenticated user reaches; turns "authenticated" into "public" |
| Leaked secret for a client with `client_credentials` | High to Critical | M2M tokens with the client's custom scopes |
| Callback on an uncontrolled domain, or open client registration | High | Authorisation code or token theft for signed-in users; needs victim interaction |
| Token from another client of the same pool accepted | High | Cross-client confusion; High when the other client is less trusted |
| Legacy trust policy without `aud` | High | Any same-account identity pool's tokens satisfy it in the classic flow |
| MFA off for privileged or workforce users | Medium to High | Password compromise equals account compromise; High for admin pools |
| Over-broad guest role without demonstrated sensitive access | Medium | Excess privilege for anonymous users; one data change away from Critical |
| Implicit grant, very long refresh tokens, revocation off | Medium | Widens token theft impact and lifetime |
| Unverified email used for notifications only | Medium | Misdirected resets or data; not identity takeover |
| User enumeration | Low to Medium | Medium for sensitive populations or combined with password-only sign-in |
| Threat protection off or audit-only | Low to Medium | Cost-driven design choice; Medium when password-only and high-value |
| Password policy below standard | Low to Medium | Depends on MFA and other controls |
| Secret in a public app for a client without `client_credentials` | Low | Adds nothing beyond the client ID; misleading security assumption |
| Deletion protection off | Low | Availability and recovery; not exploitable without IAM access |

## Mapping

| Test | Security Hub CSPM | CIS AWS Foundations | MITRE ATT&CK |
|---|---|---|---|
| GT-AWS-COG-1 | Cognito.6 | None | None (inventory) |
| GT-AWS-COG-2 | None | None | T1136.003, T1078.004 |
| GT-AWS-COG-3 | None | None | T1098 |
| GT-AWS-COG-4 | None | None | T1098, T1078.004 |
| GT-AWS-COG-5 | None | None | T1087.004 |
| GT-AWS-COG-6 | Cognito.1, Cognito.3, Cognito.4, Cognito.5 | None | T1110.001, T1110.004 |
| GT-AWS-COG-7 | None | None | T1550.001 |
| GT-AWS-COG-8 | None | None | T1552.001, T1528 |
| GT-AWS-COG-9 | None | None | T1528 |
| GT-AWS-COG-10 | Cognito.2 | None | T1078.004 |
| GT-AWS-COG-11 | None | None | T1078.004 |
| GT-AWS-COG-12 | None | None | T1078.004, T1098 |

Security Hub CSPM maps no CIS AWS Foundations Benchmark recommendation (v1.2.0, v1.4.0, v3.0.0 or v5.0.0) to its Cognito controls, and we found no Cognito-specific recommendation in those versions.

## References

- AWS: [Security Hub CSPM controls for Amazon Cognito](https://docs.aws.amazon.com/securityhub/latest/userguide/cognito-controls.html)
- AWS: [Application-specific settings with app clients](https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-client-apps.html)
- AWS: [Working with user attributes](https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-attributes.html)
- AWS: [Configuring email or phone verification](https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-email-phone-verification.html)
- AWS: [Managing user existence error responses](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pool-managing-errors.html)
- AWS: [Advanced security with threat protection](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pool-settings-threat-protection.html)
- AWS: [User pool feature plans](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-sign-in-feature-plans.html)
- AWS: [Verifying JSON web tokens](https://docs.aws.amazon.com/cognito/latest/developerguide/amazon-cognito-user-pools-using-tokens-verifying-a-jwt.html)
- AWS: [Dynamic client registration](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-pools-dynamic-client-registration.html)
- AWS: [Identity pools authentication flow](https://docs.aws.amazon.com/cognito/latest/developerguide/authentication-flow.html)
- AWS: [IAM roles for identity pools (trust policies, scope-down session policies)](https://docs.aws.amazon.com/cognito/latest/developerguide/iam-roles.html)
- AWS: [Using role-based access control](https://docs.aws.amazon.com/cognito/latest/developerguide/role-based-access-control.html)
- AWS: [Amazon Cognito logging in AWS CloudTrail](https://docs.aws.amazon.com/cognito/latest/developerguide/logging-using-cloudtrail.html)
- AWS: [Control access to REST APIs using Cognito user pools](https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-integrate-with-cognito.html), [JWT authorizers for HTTP APIs](https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-jwt-authorizer.html)
- AWS: [Penetration testing policy](https://aws.amazon.com/security/penetration-testing/)
- Libraries and tools: [aws-jwt-verify](https://github.com/awslabs/aws-jwt-verify), [Prowler](https://github.com/prowler-cloud/prowler), [Pacu](https://github.com/RhinoSecurityLabs/pacu), [PMapper](https://github.com/nccgroup/PMapper), [CloudGoat](https://github.com/RhinoSecurityLabs/cloudgoat)
- Research: [Flickr Account Takeover](https://security.lauritz-holtmann.de/advisories/flickr-account-takeover/), [Hacking AWS Cognito Misconfigurations](https://notsosecure.com/hacking-aws-cognito-misconfigurations), [Full Account Takeover via AWS Cognito Misconfiguration](https://www.cobalt.io/blog/full-account-takeover-via-aws-cognito-misconfiguration), Hacking The Cloud on [self-sign-up](https://hackingthe.cloud/aws/exploitation/cognito_user_self_signup/) and [identity pool privileges](https://hackingthe.cloud/aws/exploitation/cognito_identity_pool_excessive_privileges/)
- MITRE ATT&CK: [T1078.004](https://attack.mitre.org/techniques/T1078/004/), [T1087.004](https://attack.mitre.org/techniques/T1087/004/), [T1136.003](https://attack.mitre.org/techniques/T1136/003/), [T1098](https://attack.mitre.org/techniques/T1098/), [T1110.001](https://attack.mitre.org/techniques/T1110/001/), [T1110.004](https://attack.mitre.org/techniques/T1110/004/), [T1550.001](https://attack.mitre.org/techniques/T1550/001/), [T1528](https://attack.mitre.org/techniques/T1528/), [T1552.001](https://attack.mitre.org/techniques/T1552/001/)
