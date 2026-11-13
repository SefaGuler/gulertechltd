---
title: "AWS Network, Edge and DNS Security: VPC, Load Balancers, CloudFront and Route 53"
date: 2026-11-12 18:06:00 +0000
subcategory: aws
summary: "Reviewing AWS network exposure end to end: security groups, VPC endpoints, load balancer and CloudFront settings, WAF, and dangling DNS takeovers."
refs: [EC2.2, EC2.6, EC2.18, EC2.19, EC2.21, EC2.22, EC2.23, EC2.53, EC2.54, EC2.172, ELB.1, ELB.4, ELB.12, ELB.16, ELB.17, CloudFront.3, CloudFront.12, CloudFront.13, CloudFront.15, Route53.2, "CIS AWS v3.0.0 5.1-5.4", "CIS AWS v3.0.0 3.7", "CIS AWS v5.0.0 5.2-5.5", "CIS AWS v5.0.0 3.7", T1190, T1133, T1046, T1584.001, T1686.001, T1599, T1530, T1498]
tags: [aws, vpc, elb, cloudfront, route53, waf]
---

This note is part of our [AWS security testing guide](/cloud/aws-security-testing-guide/) and covers everything between the internet and a workload: security groups and network ACLs, the routes that make a subnet public, VPC endpoints and the data perimeter they enable, peering and Transit Gateway trust, Application and Network Load Balancers, CloudFront, AWS WAF and Shield, and Route 53, including the dangling records that let someone else serve content on the client's domain. In AWS, "network security" is mostly configuration you can read through the API, so a configuration review finds more than a port scan ever will: a security group open to `::/0` that nobody noticed because everyone checks `0.0.0.0/0`, a CloudFront distribution whose origin answers anyone who asks it directly, a listener created from the CLI with a 2016 TLS policy, a `CNAME` to an Elastic Beanstalk environment deleted two years ago. The tests below are read-only by default and tell you what each setting really controls, where the defaults are weaker than people assume, and how to rate what you find.

## Contents

- [How it works](#how-it-works)
  - [Security groups and network ACLs](#security-groups-and-network-acls)
  - [Reachability: internet gateways, public IPs, NAT and VPC Block Public Access](#reachability-internet-gateways-public-ips-nat-and-vpc-block-public-access)
  - [VPC endpoints, PrivateLink and the data perimeter](#vpc-endpoints-privatelink-and-the-data-perimeter)
  - [Connecting networks: peering and Transit Gateway](#connecting-networks-peering-and-transit-gateway)
  - [Load balancers](#load-balancers)
  - [CloudFront](#cloudfront)
  - [AWS WAF and Shield](#aws-waf-and-shield)
  - [Route 53 and DNS](#route-53-and-dns)
  - [Global Accelerator](#global-accelerator)
  - [Flow logs](#flow-logs)
- [What goes wrong](#what-goes-wrong)
- [Testing](#testing)
  - [Before you start](#before-you-start)
  - [GT-AWS-NET-1: Security groups open to the internet on administrative and data ports](#gt-aws-net-1-security-groups-open-to-the-internet-on-administrative-and-data-ports)
  - [GT-AWS-NET-2: Default, unused and stale security groups, and network ACLs](#gt-aws-net-2-default-unused-and-stale-security-groups-and-network-acls)
  - [GT-AWS-NET-3: Public IP and internet path inventory](#gt-aws-net-3-public-ip-and-internet-path-inventory)
  - [GT-AWS-NET-4: VPC endpoint policies and endpoint-based resource policies](#gt-aws-net-4-vpc-endpoint-policies-and-endpoint-based-resource-policies)
  - [GT-AWS-NET-5: Peering, Transit Gateway and endpoint service trust](#gt-aws-net-5-peering-transit-gateway-and-endpoint-service-trust)
  - [GT-AWS-NET-6: Load balancer TLS policies, redirects and HTTP hardening](#gt-aws-net-6-load-balancer-tls-policies-redirects-and-http-hardening)
  - [GT-AWS-NET-7: CloudFront origin protection and origin bypass](#gt-aws-net-7-cloudfront-origin-protection-and-origin-bypass)
  - [GT-AWS-NET-8: CloudFront viewer TLS, access restrictions and cache behaviour](#gt-aws-net-8-cloudfront-viewer-tls-access-restrictions-and-cache-behaviour)
  - [GT-AWS-NET-9: WAF and Shield coverage of internet-facing endpoints](#gt-aws-net-9-waf-and-shield-coverage-of-internet-facing-endpoints)
  - [GT-AWS-NET-10: Dangling DNS records in client hosted zones](#gt-aws-net-10-dangling-dns-records-in-client-hosted-zones)
  - [GT-AWS-NET-11: DNSSEC, DNS query logging and Resolver DNS Firewall](#gt-aws-net-11-dnssec-dns-query-logging-and-resolver-dns-firewall)
  - [GT-AWS-NET-12: VPC Flow Logs coverage](#gt-aws-net-12-vpc-flow-logs-coverage)
- [Hardening](#hardening)
- [Real-world cases](#real-world-cases)
- [Rating findings](#rating-findings)
- [Mapping](#mapping)
- [References](#references)

## How it works

### Security groups and network ACLs

A **security group** (SG) is a stateful, allow-only firewall attached to an elastic network interface (ENI), not to a subnet or an instance as such. Anything with an ENI has security groups: EC2 instances, load balancers, RDS, Lambda functions in a VPC, interface endpoints, EKS nodes. Rules allow traffic from a CIDR (`CidrIpv4`, `CidrIpv6`), a prefix list, or **another security group** (membership-based: "anything carrying `sg-app` may reach me on 5432"). Inbound is denied unless allowed; outbound is allowed to everything by default. Responses to allowed traffic are allowed automatically.

Security group referencing is the most useful control in AWS networking, and its reach has grown: within a VPC, across peered VPCs in the same Region, across VPCs attached to a Transit Gateway (inbound rules only, opt-in on the TGW and each attachment, since September 2024), and across VPCs in the same account and Region through *security group VPC associations*. Check the current documentation for the exact limits.

Every VPC has a **default security group** that allows all inbound traffic from other members of the same group and all outbound traffic. Anything launched without an explicit group lands in it, so two unrelated resources launched carelessly can talk to each other on every port. It cannot be deleted, only emptied.

A **network ACL** is stateless, applies to a whole subnet, has numbered allow *and deny* rules evaluated in order, and must allow return traffic on ephemeral ports explicitly. The default NACL allows everything both ways. NACLs are the only place you can write a deny, which makes them useful as a coarse guardrail ("nothing reaches this subnet on 22 or 3389"), but most estates leave them at the default and rely on security groups.

Two corrections to common mental models: the **IPv6** rule `::/0` is just as open as `0.0.0.0/0`, and dual-stack subnets make it reachable; and an open security group on a **private** instance is not exposed to the internet by itself, but it is exposed to everything that can route to it, which after peering, Transit Gateway and VPN is often most of the company.

### Reachability: internet gateways, public IPs, NAT and VPC Block Public Access

A resource is reachable from the internet when three things line up: it has a public IP (an auto-assigned public IPv4, an Elastic IP, or a global IPv6 address), its subnet's route table sends `0.0.0.0/0` or `::/0` to an **internet gateway**, and its security group and NACL allow the traffic. Internet-facing load balancers, NAT gateways and CloudFront are the deliberate front doors; anything else with a public IP is worth asking about. AWS has charged for every public IPv4 address since February 2024, which has made public IP sprawl a cost conversation as well as a security one.

**NAT gateways** give private subnets outbound internet access without inbound reachability. They do not filter: any process in a private subnet can reach any internet host unless you add AWS Network Firewall, a proxy, or Route 53 Resolver DNS Firewall. Egress-only internet gateways do the same for IPv6.

**VPC Block Public Access** (November 2024) is an account-level, per-Region switch that overrides route tables and security groups: `block-bidirectional` blocks all traffic through internet and egress-only gateways, `block-ingress` blocks inbound internet traffic but keeps NAT and egress-only gateways working. VPCs and subnets can be excluded. It can also be set organisation-wide through a declarative policy. Where it is on, a misconfigured security group in a non-excluded VPC is no longer an internet exposure.

### VPC endpoints, PrivateLink and the data perimeter

**VPC endpoints** let resources reach AWS services without going through the internet:

- **Gateway endpoints** (S3 and DynamoDB only) are route table entries pointing at a prefix list. Free, no ENI, no security group.
- **Interface endpoints** (most services, and third-party services through **PrivateLink**) are ENIs in your subnets with private IPs, security groups and, optionally, private DNS that makes the normal service hostname resolve to them.

Both kinds have an **endpoint policy**, a resource policy evaluated in addition to IAM. The default policy allows everything (`"Principal": "*", "Action": "*", "Resource": "*"`). A restrictive endpoint policy is how you stop data leaving through the endpoint to an **attacker's** bucket or account: with the default policy, a compromised instance can copy data to any S3 bucket in the world via the gateway endpoint, and your egress controls never see it. The usual data-perimeter conditions are `aws:PrincipalOrgID` (only our principals), `aws:ResourceOrgID` (only our resources) and `aws:ResourceAccount`.

The reverse direction is the **resource policy that requires an endpoint**: an S3 bucket policy that denies requests unless `aws:SourceVpce` (or `aws:SourceVpc`) matches. These keys are only present when the request arrived through a VPC endpoint, which is exactly why they work as a deny condition, and also why they lock out the console and any access path that is not via the endpoint. Two frequent mistakes: using them in an `Allow` statement only (IAM principals with their own permissions still reach the bucket from anywhere), and using `aws:SourceIp` with private ranges (source IP for endpoint traffic is evaluated through `aws:VpcSourceIp`, not `aws:SourceIp`).

When the client **publishes** a PrivateLink endpoint service, its *allowed principals* list decides who may create an endpoint to it, and *acceptance required* decides whether each connection is reviewed. An allowed principal of `*` with auto-accept is an internal service offered to every AWS account.

### Connecting networks: peering and Transit Gateway

**VPC peering** connects two VPCs (same or different accounts and Regions); it is not transitive, and traffic flows only where both route tables point at the peering connection and security groups allow it. Peering with an account outside the organisation, routed to whole VPC CIDRs, is a trust relationship to review like a cross-account IAM role.

**Transit Gateway** is a regional hub. Attachments (VPCs, VPNs, Direct Connect, peering to other TGWs) associate with TGW route tables and propagate routes into them. With the defaults (`DefaultRouteTableAssociation` and `DefaultRouteTablePropagation` enabled), every attachment can reach every other: production, development, the partner VPN and the shared-services VPC in one flat network. A TGW shared through AWS RAM with `AutoAcceptSharedAttachments` enabled lets any account it is shared with attach a VPC without review (Security Hub CSPM **EC2.23**). Segmentation in a TGW design lives in its route tables; read them.

### Load balancers

**Application Load Balancers** (HTTP/HTTPS, layer 7) and **Network Load Balancers** (TCP/UDP/TLS, layer 4) are either `internet-facing` or `internal` (the `Scheme`); an internal load balancer has only private IPs. What matters for security:

- **Listener protocol and TLS policy.** An HTTPS (ALB) or TLS (NLB) listener needs a security policy. At the time of writing, AWS documents that the console default is a TLS 1.2+/1.3 post-quantum policy (`ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09`) but **the default for listeners created through the CLI, CloudFormation or the CDK without an explicit policy is `ELBSecurityPolicy-2016-08`**, which still accepts TLS 1.0 and 1.1 and CBC ciphers. Infrastructure as code that omits `SslPolicy` therefore produces weak listeners. Security Hub CSPM **ELB.17** passes only a list of current TLS 1.2/1.3 policies.
- **HTTP to HTTPS.** An HTTP:80 listener should only redirect to HTTPS (ELB.1).
- **HTTP parsing hardening.** `routing.http.desync_mitigation_mode` (`monitor`, `defensive` (default), `strictest`) classifies requests by desync risk and blocks the ambiguous or severe ones; `routing.http.drop_invalid_header_fields.enabled` (default `false`) drops header names outside `[-A-Za-z0-9]+`. Both exist because of HTTP request smuggling research (below). `routing.http.xff_header_processing.mode` (`append`, `preserve`, `remove`) and `routing.http.preserve_host_header.enabled` affect what the application trusts.
- **WAF.** An ALB can have one AWS WAF web ACL; `waf.fail_open.enabled` (default `false`) decides whether traffic passes when WAF is unreachable.
- **ALB authentication.** Listener rules can authenticate users through OIDC or Cognito and pass identity to targets in the signed `x-amzn-oidc-data` header. AWS's guidance is that targets must verify the signature **and check the `signer` field is their own load balancer's ARN**, and must accept traffic only from that load balancer (target security group referencing the ALB's security group). Without both, anyone who can reach the target directly, or who runs their own ALB, can forge identities (the ALBeast research, below).

Classic Load Balancers have their own desync mode and predefined policies (ELB.3, ELB.8, ELB.14); treat any remaining CLB as a migration item.

### CloudFront

A CloudFront distribution has **origins** and **cache behaviours**. The questions for a reviewer:

- **Can viewers bypass CloudFront and hit the origin directly?** For an S3 origin, **origin access control (OAC)** signs CloudFront's requests with SigV4 as the `cloudfront.amazonaws.com` service principal, and the bucket policy allows only that principal with `AWS:SourceArn` equal to the distribution ARN; the bucket stays private behind S3 Block Public Access. The legacy **origin access identity (OAI)** is a special IAM-like principal; it still works but does not support SSE-KMS, `PUT`/`DELETE`/`POST`, or opt-in Regions launched since December 2022. An **S3 website endpoint** origin cannot use either, so the bucket must be public and anyone can read it without going through CloudFront's WAF, geo restriction or signed URLs. For custom origins (ALB, EC2, API Gateway), CloudFront adds whatever **origin custom header** you configure; the origin should require that secret header, accept connections only from the CloudFront **origin-facing managed prefix list** (`com.amazonaws.global.cloudfront.origin-facing`), or, since November 2024, not be internet-facing at all by using **VPC origins** (private ALB, NLB or EC2 as origin).
- **Viewer side.** `ViewerProtocolPolicy` per cache behaviour (`allow-all`, `redirect-to-https`, `https-only`); the **security policy** (minimum TLS version and ciphers) for custom certificates, from `TLSv1` up to `TLSv1.2_2021`, `TLSv1.2_2025` and `TLSv1.3_2025`. With the default `*.cloudfront.net` certificate CloudFront sets the policy to `TLSv1` automatically.
- **Origin side.** `OriginProtocolPolicy` (`http-only`, `match-viewer`, `https-only`) and `OriginSslProtocols` for custom origins.
- **Access restrictions.** Signed URLs and signed cookies, verified against **trusted key groups** (current) or legacy **trusted signers** (CloudFront key pairs that only the root user can manage); geographic restrictions; field-level encryption, which encrypts specific POST form fields at the edge with your public key so only the component holding the private key can read them.
- **Routing and caching.** CloudFront picks the distribution by the `Host` header, not by the IP or SNI, and blocks cross-account domain fronting; alternate domain names require a trusted certificate that covers them, and the same name cannot exist on two distributions. Cache keys and origin request policies decide which headers, cookies and query strings reach the origin and which ones vary the cache; a value forwarded to the origin but not included in the cache key is the classic web cache poisoning setup, and path-based cache behaviours (`*.css`, `/static/*`) that cache authenticated responses enable web cache deception.

### AWS WAF and Shield

**AWS WAF** web ACLs attach to CloudFront (scope `CLOUDFRONT`, managed in `us-east-1`) or to regional resources (scope `REGIONAL`: ALB, API Gateway REST APIs, AppSync, Cognito user pools, App Runner, Verified Access). Rules match requests and `Allow`, `Block`, `Count`, or challenge them; AWS managed rule groups (`AWSManagedRulesCommonRuleSet`, `AWSManagedRulesKnownBadInputsRuleSet`, `AWSManagedRulesAmazonIpReputationList` and others) are the baseline. Three properties to remember when you rate WAF findings: rules in `Count` mode block nothing; body inspection is limited (fixed at 8 KB for ALB, 16 KB by default and up to 64 KB for CloudFront and some other resources, at the time of writing), and the oversize handling setting decides what happens beyond it; and a WAF on CloudFront protects nothing if the origin can be reached directly.

**Shield Standard** is automatic and free for all customers at layers 3 and 4. **Shield Advanced** is a paid subscription that adds protections per resource, the Shield Response Team, layer 7 automatic mitigation through WAF, and cost protection. Whether Shield Advanced is needed is a business decision; whether it is configured for the resources it is paid for is a test.

### Route 53 and DNS

Route 53 hosts **public** and **private** hosted zones. Besides standard records, **alias** records point a name (including the zone apex) at an AWS resource: CloudFront, an ELB, an S3 website endpoint, Elastic Beanstalk, API Gateway and others. Three security topics live here:

- **Dangling records.** A record that still points at a resource that has been deleted. Whether that is exploitable depends on whether someone else can create a resource with the same target name. **S3 website endpoints** use the bucket name, which for general purpose buckets is a global namespace, so a deleted bucket's name can be registered by anyone and served on the client's subdomain. **Elastic Beanstalk** environment CNAME prefixes (`<prefix>.<region>.elasticbeanstalk.com`) can be claimed by any account once the environment is terminated. **CloudFront** and **ELB** hostnames are generated by AWS, so they are not directly claimable; community references list them as not vulnerable, and CloudFront's certificate requirement for alternate domain names closes the old "add their CNAME to my distribution" trick. A records pointing at **released Elastic IPs** are a probabilistic risk: the address returns to the pool and may be assigned to another customer. **NS delegations** to deleted hosted zones are a separate class that Route 53 only partly protects against. According to an AWS Security Blog post from June 2026, buckets created in S3's newer account regional namespace are not affected by the bucket-name problem; check the current S3 documentation.
- **DNSSEC.** Route 53 can sign public hosted zones (the key-signing key is an asymmetric KMS key you control, in `us-east-1`) and validate DNSSEC on the Resolver. Signing protects resolvers that validate from spoofed answers and, as AWS notes, adds protection against dangling delegation abuse.
- **Logging and filtering.** **Public DNS query logging** for a hosted zone sends queries that reach Route 53 to CloudWatch Logs in `us-east-1` (Security Hub CSPM **Route53.2**). **Resolver query logging** records DNS queries made *from* your VPCs, the useful one for detecting compromised workloads and DNS exfiltration. **Route 53 Resolver DNS Firewall** filters those queries with domain lists, including AWS managed lists such as `AWSManagedDomainsMalwareDomainList`, `AWSManagedDomainsBotnetCommandandControl`, `AWSManagedDomainsAggregateThreatList` and `AWSManagedDomainsAmazonGuardDutyThreatList`.

### Global Accelerator

AWS Global Accelerator gives an application two static anycast IPs on the AWS edge and routes them to endpoints (ALB, NLB, EC2, Elastic IP) in one or more Regions. Security relevance is mostly architectural: it is a second front door. If the same ALB sits behind both CloudFront (with WAF, geo restrictions and signed URLs) and an accelerator, the accelerator path skips all of the CloudFront controls, and the ALB must carry its own WAF and access rules. Include accelerators in the exposure inventory; their API lives in `us-west-2`.

### Flow logs

**VPC Flow Logs** record accepted and rejected IP flows for a VPC, subnet or ENI, to CloudWatch Logs, S3 or Firehose. They are metadata only (no payloads), aggregated over a window, and they do not record some traffic, including traffic to the Amazon DNS server and to the instance metadata service. They are the evidence source for "did anything talk to that open port" and a data source for GuardDuty (which reads them independently, whether or not you enable them). The [detection services note](/cloud/aws-detection-posture-services/) covers them in depth; here we only check coverage.

## What goes wrong

**Administrative and data ports open to the internet.** SSH, RDP, database, cache, search and container API ports allowed from `0.0.0.0/0` or `::/0`, often added "temporarily" by a launch wizard or during an incident. IPv6 rules are missed because tooling and people look for `0.0.0.0/0`.

**Flat internal networks.** Security groups that allow whole VPC or RFC 1918 ranges instead of referencing groups; the default security group in use; Transit Gateways with default association and propagation so every VPC reaches every other; NACLs never used. One compromised workload then reaches everything.

**Public IP sprawl.** Subnets that auto-assign public IPs, instances with Elastic IPs that should sit behind a load balancer, forgotten test hosts, unused Elastic IPs that later become dangling DNS targets.

**Endpoints without policies.** Default full-access endpoint policies, so a gateway endpoint is an unmonitored exfiltration path to any S3 bucket; bucket policies that "restrict to the VPC endpoint" in an `Allow` only, which restricts nothing.

**Untrusted connectivity.** Peering and TGW attachments to accounts outside the organisation, auto-accepted attachments, PrivateLink services open to `*`.

**Weak edge configuration.** Load balancer listeners on `ELBSecurityPolicy-2016-08` because IaC omitted the policy; HTTP listeners that forward instead of redirect; desync mitigation set to `monitor`; WAF missing or in count mode; ALB authentication whose targets do not validate the token signer.

**CloudFront origins reachable directly.** S3 website endpoints as origins (public bucket), ALB origins open to the internet without a secret header or prefix list, non-existent S3 origins, OAI on buckets that need SSE-KMS (so someone "fixed" it by making the bucket public). Every edge control is then optional for an attacker.

**Dangling DNS.** Records pointing at deleted S3 website buckets, terminated Beanstalk environments, released Elastic IPs and deleted hosted zones. Result: subdomain takeover, which gives an attacker content on a trusted domain, cookies scoped to the parent domain, valid OAuth redirect URIs and phishing that passes every visual check.

**Missing visibility.** No flow logs, no Resolver query logs, no DNS Firewall, no WAF logs; when something happens, there is nothing to investigate with.

## Testing

Every test below assumes an **authorised** engagement against the client's own AWS accounts, with written scope, and respects AWS's [penetration testing policy](https://aws.amazon.com/security/penetration-testing/). Configuration checks are read-only. Anything that sends traffic to the client's endpoints is limited to the endpoints in scope and marked **explicitly approved only**; nothing here involves scanning anyone else's resources. Outputs shown are **illustrative**, not from a real account.

### Before you start

**Credentials.** `SecurityAudit` plus `ViewOnlyAccess` cover most reads below at the time of writing (EC2, ELB, CloudFront, Route 53, Route 53 Resolver, WAF, Shield and Global Accelerator describe/list/get calls). Check two additions before you start: `s3:ListBucket` on candidate bucket names in the client's own accounts, which `head-bucket` uses in GT-AWS-NET-10, and `route53domains:GetDomainDetail` if registered domains are in scope.

**Region loop and global services.** VPC, ELB, regional WAF and Resolver settings are per Region. CloudFront and its WAF scope are managed in `us-east-1`; Route 53 hosted zones are global; Global Accelerator's API is in `us-west-2`.

```bash
export AWS_PROFILE=client-audit
REGIONS=$(aws ec2 describe-regions --query 'Regions[].RegionName' --output text)
each_region() { for r in $REGIONS; do "$@" --region "$r" 2>/dev/null | sed "s/^/$r\t/"; done; }
```

**Tools.**

- [Prowler](https://github.com/prowler-cloud/prowler): `prowler aws --services ec2 vpc elbv2 elb cloudfront route53 wafv2 shield`.
- [ScoutSuite](https://github.com/nccgroup/ScoutSuite) for a browsable network view; [Steampipe](https://hub.steampipe.io/plugins/turbot/aws) tables such as `aws_vpc_security_group_rule`, `aws_ec2_application_load_balancer`, `aws_cloudfront_distribution`, `aws_route53_record`.
- [CloudFox](https://github.com/BishopFox/cloudfox): `cloudfox aws network-ports` (which ports are reachable from where, computed from configuration), `cloudfox aws endpoints` (every service endpoint the account exposes), `cloudfox aws elastic-network-interfaces`, `cloudfox aws route53`.
- [Pacu](https://github.com/RhinoSecurityLabs/pacu) enumeration modules: `vpc__enum_lateral_movement`, `route53__enum`, `waf__enum`, `elb__enum_logging`.
- For dangling DNS: [dnsReaper](https://github.com/punk-security/dnsReaper) (`aws` provider reads Route 53 directly), AWS's [sample-dangling-dns-detection](https://github.com/aws-samples/sample-dangling-dns-detection) Config rule, and [Can I take over XYZ](https://github.com/EdOverflow/can-i-take-over-xyz) for service fingerprints.
- For TLS verification from outside (approved targets only): `testssl.sh` or `sslscan`.

### GT-AWS-NET-1: Security groups open to the internet on administrative and data ports

*Guler Tech methodology.*

#### What it checks

Inbound security group rules that allow `0.0.0.0/0` or `::/0` (directly or through a prefix list) to administrative, database and other sensitive ports, and which of those groups are actually attached to something.

#### Prerequisites

`ec2:DescribeSecurityGroupRules`, `ec2:DescribeNetworkInterfaces`, `ec2:GetManagedPrefixListEntries`.

#### Steps

1. **Find world-open rules hitting sensitive ports** (TCP list; extend for UDP services the client runs):

   ```bash
   PORTS='[20,21,22,23,25,135,139,445,1433,1521,2049,2375,2376,2379,3306,3389,5432,5601,5900,5985,5986,6379,6443,8080,8443,9200,9300,10250,11211,27017]'
   for r in $REGIONS; do
     aws ec2 describe-security-group-rules --region "$r" --output json |
     jq -r --arg r "$r" --argjson ports "$PORTS" '
       .SecurityGroupRules[]
       | select(.IsEgress == false)
       | select((.CidrIpv4 // "") == "0.0.0.0/0" or (.CidrIpv6 // "") == "::/0")
       | . as $x
       | [ $ports[] | select($x.IpProtocol == "-1" or ($x.FromPort <= . and . <= $x.ToPort)) ] as $hit
       | select(($hit | length) > 0)
       | [ $r, $x.GroupId, $x.IpProtocol, ($x.FromPort|tostring), ($x.ToPort|tostring), ($x.CidrIpv4 // $x.CidrIpv6), ($hit|map(tostring)|join(",")) ]
       | @tsv'
   done
   ```

   `IpProtocol` `-1` is all traffic; a `FromPort` of 0 to `ToPort` 65535 is all TCP ports.
2. **Expand prefix lists.** Rules with `PrefixListId` hide their CIDRs. For customer-managed lists: `aws ec2 get-managed-prefix-list-entries --prefix-list-id pl-0123456789abcdef0` and repeat the check for `0.0.0.0/0`, `::/0` and very wide ranges.
3. **Is the group in use, and by what?**

   ```bash
   aws ec2 describe-network-interfaces --filters Name=group-id,Values=sg-0123456789abcdef0 \
     --query 'NetworkInterfaces[].[NetworkInterfaceId,InterfaceType,Description,Association.PublicIp,Attachment.InstanceId]' --output text
   ```

   A world-open group on an ENI with no public IP in a private subnet is a latent finding (the next public IP or route change exposes it), not a live exposure.
4. **Optional external confirmation (explicitly approved only):** from an approved source IP, scan only the client's public IPs from GT-AWS-NET-3 for the ports you found, e.g. `nmap -Pn -sT -p 22,3389,5432 203.0.113.10`.

#### Observation

```text
eu-west-2  sg-0123456789abcdef0  tcp  22    22     0.0.0.0/0  22
eu-west-2  sg-0aaaabbbbccccdddd0 tcp  0     65535  ::/0       21,22,23,25,...
eu-west-2  sg-0fedcba9876543210  -1   -1    -1     0.0.0.0/0  20,21,22,...
```

#### Evaluation

- **Fail (High)** for any world-open administrative or database port on a group attached to an ENI with a public IP. Raise to Critical with a known-vulnerable or unauthenticated service behind it (Redis, Elasticsearch, Docker API, kubelet).
- **Fail (High)** for `-1` (all traffic) from the internet on any attached group.
- **Fail (Medium)** for the same rules on groups without a public path today.
- **Pass / expected**: 80 and 443 open on internet-facing load balancers and CloudFront-fronted origins (but see GT-AWS-NET-7), and documented service ports on deliberately public services.
- False positives: the AWS managed CloudFront prefix list (not world-open), groups used only by internal load balancers with no public IPs.

#### Automated coverage

Security Hub CSPM: **EC2.53** / **EC2.54** (0.0.0.0/0 and ::/0 to 22/3389; CIS v3.0.0 5.2/5.3, v5.0.0 5.3/5.4), **EC2.13**/**EC2.14** (CIS v1.2.0 4.1/4.2), **EC2.18** (only authorised ports unrestricted), **EC2.19** (high-risk ports). Prowler: `ec2_securitygroup_allow_ingress_from_internet_to_all_ports`, `..._to_any_port`, `..._to_high_risk_tcp_ports`, `..._to_tcp_port_22`, `..._to_tcp_port_3389`, the per-service `..._to_tcp_port_<service>` checks, `ec2_securitygroup_allow_wide_open_public_ipv4`.

#### Detection

`AuthorizeSecurityGroupIngress` with `0.0.0.0/0` or `::/0`, `ModifySecurityGroupRules`, `CreateSecurityGroup` named `launch-wizard-*`; GuardDuty `Recon:EC2/PortProbeUnprotectedPort`, `UnauthorizedAccess:EC2/SSHBruteForce`, `UnauthorizedAccess:EC2/RDPBruteForce`. ATT&CK [T1133](https://attack.mitre.org/techniques/T1133/), [T1190](https://attack.mitre.org/techniques/T1190/), and [T1686.001 Disable or Modify System Firewall: Cloud Firewall](https://attack.mitre.org/techniques/T1686/001/) for an attacker opening rules (formerly T1562.007; renumbered in ATT&CK v20).

### GT-AWS-NET-2: Default, unused and stale security groups, and network ACLs

*Guler Tech methodology.*

#### What it checks

Whether the default security group of every VPC is empty and unused, which groups are unused or reference groups that no longer exist, whether internal rules use wide CIDRs instead of group references, and whether NACLs allow administrative ports from anywhere.

#### Prerequisites

`ec2:DescribeSecurityGroups`, `ec2:DescribeNetworkInterfaces`, `ec2:DescribeStaleSecurityGroups`, `ec2:DescribeNetworkAcls`.

#### Steps

1. **Default groups:**

   ```bash
   each_region aws ec2 describe-security-groups --filters Name=group-name,Values=default \
     --query 'SecurityGroups[].[GroupId,VpcId,length(IpPermissions),length(IpPermissionsEgress)]' --output text
   each_region aws ec2 describe-network-interfaces --filters Name=group-name,Values=default \
     --query 'NetworkInterfaces[].[NetworkInterfaceId,InterfaceType,Description]' --output text
   ```

2. **Unused groups** (not on any ENI):

   ```bash
   r=eu-west-2
   comm -23 \
     <(aws ec2 describe-security-groups --region $r --query 'SecurityGroups[].GroupId' --output text | tr '\t' '\n' | sort) \
     <(aws ec2 describe-network-interfaces --region $r --query 'NetworkInterfaces[].Groups[].GroupId' --output text | tr '\t' '\n' | sort -u)
   ```

   Before calling one unused, check launch templates, Auto Scaling groups and IaC; `describe-security-group-references` shows groups in peered VPCs that reference it.
3. **Stale references** (rules pointing at deleted groups across peering): `aws ec2 describe-stale-security-groups --vpc-id vpc-0123456789abcdef0`.
4. **Wide internal rules:** list ingress rules whose source is `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` or the whole VPC CIDR on all ports; each is a candidate for a group reference.
5. **NACLs:**

   ```bash
   each_region aws ec2 describe-network-acls \
     --query 'NetworkAcls[].Entries[?Egress==`false` && RuleAction==`allow` && (CidrBlock==`0.0.0.0/0` || Ipv6CidrBlock==`::/0`)].[RuleNumber,Protocol,PortRange.From,PortRange.To]' --output text
   ```

#### Observation

```text
eu-west-2  sg-0default00000000a  vpc-0123456789abcdef0  1  1
eu-west-2  eni-0123456789abcdef0 interface  Primary network interface
```

The default group still has its original rules and an instance is using it.

#### Evaluation

- **Fail (Medium)** if a default security group has any rules (CIS requires it to restrict all traffic); **Medium–High** if resources are attached to it, because unrelated workloads can then reach each other on every port.
- **Fail (Low)** for unused and stale groups: hygiene, but they get reused with their old, unreviewed rules.
- **Fail (Medium)** for all-ports rules from entire private ranges between tiers that should be segmented.
- **Fail (Medium)** if NACLs allow 22/3389 from anywhere on subnets whose security groups also allow it (CIS expects NACLs as a second layer); **note** only, where security groups are clean.
- **Pass**: default groups empty and unattached in every VPC, tier-to-tier rules by group reference, no stale references.

#### Automated coverage

Security Hub CSPM: **EC2.2** (default SG; CIS v3.0.0 5.4, v5.0.0 5.5), **EC2.21** (NACL 22/3389; CIS v3.0.0 5.1, v5.0.0 5.2), **EC2.22** (unused SGs, Control Tower standard only), **EC2.16** (unused NACLs). Prowler: `ec2_securitygroup_default_restrict_traffic`, `ec2_securitygroup_not_used`, `ec2_securitygroup_with_many_ingress_egress_rules`, `ec2_networkacl_allow_ingress_tcp_port_22`, `ec2_networkacl_allow_ingress_tcp_port_3389`, `ec2_networkacl_allow_ingress_any_port`, `ec2_networkacl_unused`.

#### Detection

`AuthorizeSecurityGroupIngress`/`Egress` on default groups, `CreateNetworkAclEntry`, `ReplaceNetworkAclEntry`, `ReplaceNetworkAclAssociation`. ATT&CK [T1686.001](https://attack.mitre.org/techniques/T1686/001/).

### GT-AWS-NET-3: Public IP and internet path inventory

*Guler Tech methodology.*

#### What it checks

Every address and hostname the account exposes to the internet, which subnets are public by routing, whether subnets and launch templates hand out public IPs by default, and whether VPC Block Public Access is in use. This inventory feeds every other test and the client's external testing scope.

#### Prerequisites

Read-only EC2, ELB, CloudFront, Global Accelerator, API Gateway and RDS describe permissions.

#### Steps

1. **Every public address on an ENI** (covers EC2, NAT gateways, NLBs, ALB nodes, RDS, interface types you did not think of):

   ```bash
   each_region aws ec2 describe-network-interfaces \
     --query 'NetworkInterfaces[?Association.PublicIp!=`null`].[Association.PublicIp,InterfaceType,Description,Attachment.InstanceId,join(`,`,Groups[].GroupId)]' \
     --output text
   each_region aws ec2 describe-addresses --query 'Addresses[].[PublicIp,AllocationId,AssociationId,NetworkInterfaceId]' --output text
   ```

   Elastic IPs with no `AssociationId` are unused (EC2.12) and are also the addresses that become dangling DNS when released (GT-AWS-NET-10).
2. **IPv6:** subnets with IPv6 CIDRs and routes to an internet gateway make every dual-stack ENI addressable. List them and check their route tables for `::/0`:

   ```bash
   each_region aws ec2 describe-subnets \
     --query 'Subnets[?length(Ipv6CidrBlockAssociationSet || `[]`) > `0`].[SubnetId,VpcId,Ipv6CidrBlockAssociationSet[0].Ipv6CidrBlock]' --output text
   ```
3. **Public subnets by routing:**

   ```bash
   each_region aws ec2 describe-route-tables \
     --query 'RouteTables[?Routes[?starts_with(GatewayId||`x`,`igw-`)]].[RouteTableId,VpcId,join(`,`,Associations[].SubnetId||`[]`)]' --output text
   each_region aws ec2 describe-subnets --query 'Subnets[?MapPublicIpOnLaunch].[SubnetId,VpcId,CidrBlock]' --output text
   ```

4. **Front doors:** internet-facing load balancers, CloudFront distributions, Global Accelerators, API Gateway endpoints and Lambda function URLs (see the [API](/cloud/aws-api-gateway-sns-sqs-security/) and [Lambda](/cloud/aws-lambda-serverless-security/) notes). `cloudfox aws endpoints` lists most of them in one pass.

   ```bash
   each_region aws elbv2 describe-load-balancers \
     --query 'LoadBalancers[?Scheme==`internet-facing`].[LoadBalancerName,Type,DNSName]' --output text
   aws cloudfront list-distributions --query 'DistributionList.Items[].[Id,DomainName,join(`,`,Aliases.Items || `[]`)]' --output text
   aws globalaccelerator list-accelerators --region us-west-2 --query 'Accelerators[].[Name,DnsName,Enabled]' --output text
   ```
5. **VPC Block Public Access:** `each_region aws ec2 describe-vpc-block-public-access-options --query 'VpcBlockPublicAccessOptions.[InternetGatewayBlockMode,State]' --output text` and `describe-vpc-block-public-access-exclusions`.
6. **Network Access Analyzer** can prove reachability formally (e.g. "any path from an internet gateway to an ENI on port 22"). Creating an access scope and analysis writes metadata in the account but changes no traffic; agree it with the client first.

#### Observation

```text
eu-west-2  203.0.113.10   interface    Primary network interface  i-0123456789abcdef0  sg-0123456789abcdef0
eu-west-2  198.51.100.20  nat_gateway  Interface for NAT Gateway nat-0123456789abcdef0
eu-west-2  203.0.113.30   eipalloc-0123456789abcdef0  None  None
eu-west-2  off  -
```

#### Evaluation

- **Fail (Medium)** for EC2 instances with public IPs that have no business reason (should sit behind a load balancer or CloudFront), rated up when combined with GT-AWS-NET-1 findings.
- **Fail (Low)** for subnets and launch templates that auto-assign public IPs, unassociated Elastic IPs, and accounts without VPC Block Public Access where the architecture would allow it.
- **Pass**: public addresses limited to load balancers, NAT gateways and documented services; private subnets not auto-assigning; VPC BPA in `block-ingress` with documented exclusions, where it fits.

#### Automated coverage

Security Hub CSPM: **EC2.9** (instances without public IPv4), **EC2.15** (subnets do not auto-assign), **EC2.25** (launch templates), **EC2.12** (unused EIPs), **EC2.172** (VPC BPA blocks IGW traffic). Prowler: `ec2_instance_public_ip`, `vpc_subnet_no_public_ip_by_default`, `vpc_subnet_separate_private_public`, `ec2_elastic_ip_unassigned`, `elbv2_internet_facing`.

#### Detection

`AssociateAddress`, `AllocateAddress`, `ModifySubnetAttribute` (`mapPublicIpOnLaunch`), `CreateRoute`/`ReplaceRoute` to an `igw-`, `CreateInternetGateway`, `AttachInternetGateway`, `ModifyVpcBlockPublicAccessOptions`, `CreateVpcBlockPublicAccessExclusion`. ATT&CK [T1599 Network Boundary Bridging](https://attack.mitre.org/techniques/T1599/) for route and gateway changes that bridge segments.

### GT-AWS-NET-4: VPC endpoint policies and endpoint-based resource policies

*Guler Tech methodology.*

#### What it checks

Whether gateway and interface endpoints carry policies that restrict use to the organisation's principals and resources, and whether resource policies that rely on `aws:SourceVpce` / `aws:SourceVpc` are written so they actually restrict.

#### Prerequisites

`ec2:DescribeVpcEndpoints`, `s3:GetBucketPolicy` on in-scope buckets.

#### Steps

1. **List endpoints and their policies:**

   ```bash
   each_region aws ec2 describe-vpc-endpoints \
     --query 'VpcEndpoints[].[VpcEndpointId,VpcEndpointType,ServiceName,VpcId,PolicyDocument]' --output text
   ```

   Pretty-print one: `aws ec2 describe-vpc-endpoints --vpc-endpoint-ids vpce-0123456789abcdef0 --query 'VpcEndpoints[0].PolicyDocument' --output text | jq .`
2. **Classify each policy:** default (allow all), partial (restricts actions but not principals or resources), or perimeter (conditions on `aws:PrincipalOrgID` and `aws:ResourceOrgID` or explicit resource ARNs). Gateway endpoints for S3 deserve most attention because they carry bulk data.
3. **Interface endpoint security groups:** the endpoint ENIs have security groups; a group allowing 443 from `0.0.0.0/0` on an endpoint in a peered or TGW-connected VPC offers the endpoint (and the client's credentials path) to every connected network.
4. **Resource policies using endpoint keys:** search bucket policies (the [S3 note](/cloud/aws-s3-security/) has the collection loop) for `aws:SourceVpce` and `aws:SourceVpc` and read the effect. A correct pattern is a `Deny` with `StringNotEquals` on the endpoint ID (with an exception for administrative roles); an `Allow` with `StringEquals` on its own restricts nothing for principals whose IAM policies already grant access. Flag `aws:SourceIp` conditions with private ranges.

#### Observation

```json
{
  "Version": "2008-10-17",
  "Statement": [
    { "Effect": "Allow", "Principal": "*", "Action": "*", "Resource": "*" }
  ]
}
```

The default S3 gateway endpoint policy: any principal, any bucket, including buckets in other accounts.

#### Evaluation

- **Fail (Medium)** for S3 or DynamoDB gateway endpoints with the default policy in VPCs that hold sensitive data: a compromised workload can move data to an external bucket over a path no egress control inspects. Raise when other egress is tightly controlled, because the endpoint is then *the* exfiltration path.
- **Fail (Medium)** for bucket policies whose endpoint restriction is ineffective (Allow-only) where the client believes data is "only reachable from the VPC".
- **Note** default policies on interface endpoints for low-risk services; recommend perimeter policies over time.
- **Pass**: endpoint policies restricted to `aws:PrincipalOrgID` and `aws:ResourceOrgID` (with documented exceptions for AWS-owned resources the workloads need, such as package repositories or service buckets), and resource policies using `Deny` with endpoint conditions.

#### Automated coverage

Prowler: `vpc_endpoint_connections_trust_boundaries`, `vpc_endpoint_for_ec2_enabled`, `vpc_endpoint_multi_az_enabled`. Security Hub CSPM: **EC2.10** and **EC2.55–EC2.60** check that endpoints exist for specific services, not what their policies allow. Endpoint policy content is a manual check at the time of writing.

#### Detection

`ModifyVpcEndpoint` with a new `policyDocument`, `CreateVpcEndpoint`, `DeleteVpcEndpoints`; with CloudTrail network activity events enabled for VPC endpoints, requests denied by endpoint policies (`errorCode` `VpceAccessDenied`) show attempts to use the endpoint outside the perimeter. ATT&CK [T1530](https://attack.mitre.org/techniques/T1530/) and [T1537](https://attack.mitre.org/techniques/T1537/).

### GT-AWS-NET-5: Peering, Transit Gateway and endpoint service trust

*Guler Tech methodology.*

#### What it checks

Network trust relationships with other accounts: VPC peering, Transit Gateway attachments and route tables, RAM shares of network resources, and who may connect to PrivateLink services the client publishes.

#### Prerequisites

Read-only EC2 and RAM; the organisation's account list (`organizations:ListAccounts`) to separate internal from external IDs.

#### Steps

1. **Peering:**

   ```bash
   each_region aws ec2 describe-vpc-peering-connections \
     --query 'VpcPeeringConnections[].[VpcPeeringConnectionId,Status.Code,RequesterVpcInfo.OwnerId,RequesterVpcInfo.CidrBlock,AccepterVpcInfo.OwnerId,AccepterVpcInfo.CidrBlock]' --output text
   ```

   For each, read the routes that use it (`describe-route-tables --filters Name=route.vpc-peering-connection-id,Values=pcx-...`) and note whether whole VPC CIDRs are routed.
2. **Transit Gateways:**

   ```bash
   each_region aws ec2 describe-transit-gateways \
     --query 'TransitGateways[].[TransitGatewayId,OwnerId,Options.AutoAcceptSharedAttachments,Options.DefaultRouteTableAssociation,Options.DefaultRouteTablePropagation,Options.SecurityGroupReferencingSupport]' --output text
   each_region aws ec2 describe-transit-gateway-attachments \
     --query 'TransitGatewayAttachments[].[TransitGatewayAttachmentId,ResourceType,ResourceOwnerId,Association.TransitGatewayRouteTableId]' --output text
   ```

   Then `search-transit-gateway-routes` per route table to see which attachments reach which CIDRs.
3. **RAM shares of network resources:** `aws ram get-resource-shares --resource-owner SELF` and `aws ram list-principals --resource-owner SELF` (TGWs, subnets, prefix lists, Resolver rules shared outside the organisation).
4. **Published PrivateLink services:**

   ```bash
   each_region aws ec2 describe-vpc-endpoint-service-configurations \
     --query 'ServiceConfigurations[].[ServiceId,ServiceName,AcceptanceRequired]' --output text
   aws ec2 describe-vpc-endpoint-service-permissions --service-id vpce-svc-0123456789abcdef0 \
     --query 'AllowedPrincipals[].Principal' --output text
   aws ec2 describe-vpc-endpoint-connections --query 'VpcEndpointConnections[].[ServiceId,VpcEndpointOwner,VpcEndpointState]' --output text
   ```

#### Observation

```text
eu-west-2  pcx-0123456789abcdef0  active  111122223333  10.10.0.0/16  444455556666  10.50.0.0/16
eu-west-2  tgw-0123456789abcdef0  111122223333  enable  enable  enable  enable
eu-west-2  vpce-svc-0123456789abcdef0  com.amazonaws.vpce.eu-west-2.vpce-svc-0123456789abcdef0  False
arn:aws:iam::*:root
```

#### Evaluation

- **Fail (High)** for a PrivateLink service with allowed principal `*` (or `arn:aws:iam::*:root`) and `AcceptanceRequired=False` that fronts an internal API without its own strong authentication.
- **Fail (High)** for peering or TGW attachments to accounts outside the organisation with routes to production CIDRs and no restrictive security groups, unless documented and reviewed like a third-party connection.
- **Fail (Medium)** for TGWs with `AutoAcceptSharedAttachments=enable`, and for default association/propagation that flattens environments that the client believes are segmented.
- **Pass**: external connectivity documented, routed only to the CIDRs required, endpoint services restricted to named accounts with acceptance required, TGW route tables per environment.

#### Automated coverage

Security Hub CSPM: **EC2.23** (TGW auto-accept). Prowler: `ec2_transitgateway_auto_accept_vpc_attachments`, `vpc_peering_routing_tables_with_least_privilege`, `vpc_endpoint_services_allowed_principals_trust_boundaries`, `vpc_endpoint_connections_trust_boundaries`. Pacu: `vpc__enum_lateral_movement`.

#### Detection

`CreateVpcPeeringConnection`, `AcceptVpcPeeringConnection`, `CreateTransitGatewayVpcAttachment`, `AcceptTransitGatewayVpcAttachment`, `ModifyTransitGateway`, `ModifyVpcEndpointServicePermissions`, `AcceptVpcEndpointConnections`, RAM `CreateResourceShare`/`AssociateResourceShare`. ATT&CK [T1599](https://attack.mitre.org/techniques/T1599/).

### GT-AWS-NET-6: Load balancer TLS policies, redirects and HTTP hardening

*Guler Tech methodology.*

#### What it checks

For every ALB, NLB and remaining Classic Load Balancer: scheme, listener protocols and TLS security policies, HTTP-to-HTTPS redirect, desync mitigation and invalid header handling, WAF fail-open, access logging, and, for ALBs using built-in authentication, whether targets can be reached around the load balancer.

#### Prerequisites

`elasticloadbalancing:Describe*`; for external verification, approval to connect to the client's listeners.

#### Steps

1. **Listeners and policies:**

   ```bash
   for r in $REGIONS; do
     for lb in $(aws elbv2 describe-load-balancers --region "$r" --query 'LoadBalancers[].LoadBalancerArn' --output text); do
       aws elbv2 describe-listeners --region "$r" --load-balancer-arn "$lb" \
         --query 'Listeners[].[LoadBalancerArn,Port,Protocol,SslPolicy,DefaultActions[0].Type,DefaultActions[0].RedirectConfig.Protocol]' \
         --output text | sed "s/^/$r\t/"
     done
   done
   aws elbv2 describe-ssl-policies --names ELBSecurityPolicy-2016-08 --query 'SslPolicies[].SslProtocols'
   ```

2. **Attributes:**

   ```bash
   aws elbv2 describe-load-balancer-attributes --load-balancer-arn "$lb" \
     --query 'Attributes[?contains(`["routing.http.desync_mitigation_mode","routing.http.drop_invalid_header_fields.enabled","waf.fail_open.enabled","access_logs.s3.enabled","deletion_protection.enabled","routing.http.xff_header_processing.mode"]`, Key)]' \
     --output text
   ```

3. **Authentication rules:**

   ```bash
   aws elbv2 describe-rules --listener-arn <listener-arn> \
     --query 'Rules[].Actions[?Type==`authenticate-oidc` || Type==`authenticate-cognito`].Type'
   ```

   For each authenticated target group, check that the targets' security groups allow traffic only from the ALB's security group, and ask how the application validates `x-amzn-oidc-data` (signature, `signer` equals the ALB ARN, expiry). A code review of the validation function is the strongest evidence.
4. **Classic Load Balancers:** `aws elb describe-load-balancers` and `aws elb describe-load-balancer-policies --load-balancer-name <name>`.
5. **External confirmation (explicitly approved only):** `testssl.sh --protocols --server-defaults https://app.example.com` confirms what clients can actually negotiate, including through CloudFront or Global Accelerator in front.

#### Observation

```text
eu-west-2  arn:...:loadbalancer/app/web/0123456789abcdef  443  HTTPS  ELBSecurityPolicy-2016-08  forward  None
eu-west-2  arn:...:loadbalancer/app/web/0123456789abcdef  80   HTTP   None                       forward  None
routing.http.desync_mitigation_mode            monitor
routing.http.drop_invalid_header_fields.enabled false
waf.fail_open.enabled                           true
```

#### Evaluation

- **Fail (Medium)** for internet-facing HTTPS/TLS listeners on policies that allow TLS 1.0/1.1 (`ELBSecurityPolicy-2016-08`, `ELBSecurityPolicy-TLS-1-0-*`, `-TLS-1-1-*`); **Low** on internal listeners. The practical risk of TLS 1.0 today is modest, but it fails PCI DSS and most client policies, and it signals IaC that omits policies everywhere.
- **Fail (Medium)** for an HTTP listener that forwards to targets serving authenticated content rather than redirecting.
- **Fail (Medium)** for desync mitigation in `monitor` mode on internet-facing ALBs; `defensive` passes, `strictest` is stronger but may break non-compliant clients. `drop_invalid_header_fields` `false` is a **Low** where desync mode is `defensive` or `strictest` (AWS suggests ELB.4 can be disabled when ELB.12 is enabled).
- **Fail (High–Critical)** for ALB authentication where targets accept traffic from anywhere other than the ALB, or do not validate the token signer: identity can be forged by anyone who can reach the target or create their own ALB. Prove it in a lab copy, not against production.
- **Fail (Low–Medium)** for `waf.fail_open.enabled=true` on WAF-dependent applications, and for missing access logs (ELB.5) on internet-facing load balancers.
- **Pass**: current TLS 1.2/1.3 policy on every listener, redirects on port 80, `defensive` or `strictest`, logs on, authentication targets locked to the ALB.

#### Automated coverage

Security Hub CSPM: **ELB.1** (HTTP to HTTPS redirect), **ELB.4** (drop invalid headers), **ELB.5** (logging), **ELB.12** (ALB desync mode), **ELB.14** (CLB desync mode), **ELB.16** (ALB WAF), **ELB.17** (recommended security policies), **ELB.18** (secure listener protocols), **ELB.3**/**ELB.8** (Classic). Prowler: `elbv2_ssl_listeners`, `elbv2_insecure_ssl_ciphers`, `elbv2_desync_mitigation_mode`, `elbv2_alb_drop_invalid_header_fields_enabled`, `elbv2_waf_acl_attached`, `elbv2_logging_enabled`, `elbv2_internet_facing`, `elb_ssl_listeners`, `elb_insecure_ssl_ciphers`, `elb_desync_mitigation_mode`.

#### Detection

`ModifyListener` (policy downgrades), `CreateListener` without `SslPolicy`, `ModifyLoadBalancerAttributes` (desync mode, WAF fail-open, logging off), `DisassociateWebACL`. ALB access logs carry desync classification fields and TLS versions for investigation. ATT&CK [T1190](https://attack.mitre.org/techniques/T1190/).

### GT-AWS-NET-7: CloudFront origin protection and origin bypass

*Guler Tech methodology.*

#### What it checks

Whether each CloudFront origin can only be reached through CloudFront: OAC (not OAI, not public) for S3, no S3 website-endpoint origins for private content, custom origins restricted by secret header, CloudFront prefix list or VPC origins, and no origins pointing at buckets that do not exist.

#### Prerequisites

`cloudfront:ListDistributions`, `cloudfront:GetDistributionConfig`, `cloudfront:ListOriginAccessControls`, `s3:GetBucketPolicy`, `s3:GetBucketPublicAccessBlock` and `s3:ListBucket` (for `head-bucket`) on origin buckets in the client's accounts; ELB and EC2 describe for custom origins.

#### Steps

1. **Inventory origins:**

   ```bash
   aws cloudfront list-distributions --output json | jq -r '
     .DistributionList.Items[]? | .Id as $id | (.Aliases.Items // [] | join(",")) as $alias
     | .Origins.Items[]
     | [ $id, $alias, .Id, .DomainName,
         (if .OriginAccessControlId != "" and .OriginAccessControlId != null then "OAC"
          elif (.S3OriginConfig.OriginAccessIdentity // "") != "" then "OAI"
          elif .S3OriginConfig != null then "S3-no-auth"
          elif .VpcOriginConfig != null then "VPC-origin"
          else "custom:" + (.CustomOriginConfig.OriginProtocolPolicy // "?") end),
         ((.CustomHeaders.Items // []) | map(.HeaderName) | join(",")) ]
     | @tsv'
   ```

2. **S3 origins.** For `OAC` origins, read the bucket policy: the statement should allow `cloudfront.amazonaws.com` with `AWS:SourceArn` equal to *this* distribution's ARN, and S3 Block Public Access should be on. Flag `OAI` origins (migrate), `S3-no-auth` origins (bucket must be public for them to work), and any origin whose domain contains `s3-website` (website endpoint: public by design).
3. **Non-existent buckets.** For each S3 origin bucket name: `aws s3api head-bucket --bucket <name>` from the account that should own it. `404` means the bucket does not exist and anyone could create it (CloudFront.12); `403` means it exists in an account you cannot read: confirm with the client that they own it.
4. **Custom origins.** For an ALB origin, find the load balancer from its DNS name and check: is it `internet-facing`; does its security group allow 443 from `0.0.0.0/0` or only from `com.amazonaws.global.cloudfront.origin-facing` (look for that prefix list ID: `aws ec2 describe-managed-prefix-lists --filters Name=prefix-list-name,Values=com.amazonaws.global.cloudfront.origin-facing`); does the listener's default action return a fixed 403 unless the secret header matches?
5. **Direct-origin proof (explicitly approved only).** One benign `GET` straight to the origin, with the expected `Host` header:

   ```bash
   curl -sk -o /dev/null -w '%{http_code}\n' https://web-0123456789.eu-west-2.elb.amazonaws.com/ -H 'Host: app.example.com'
   curl -s -o /dev/null -w '%{http_code}\n' http://assets-bucket.s3-website.eu-west-2.amazonaws.com/index.html
   ```

   A `200` with application content means CloudFront's WAF, geo restriction and signed URL checks can be bypassed. Do not send attack payloads to the origin.

#### Observation

```text
E1ABCDEF2GHIJK  app.example.com     alb-origin     web-0123456789.eu-west-2.elb.amazonaws.com  custom:https-only
E1ABCDEF2GHIJK  app.example.com     static         assets-bucket.s3-website.eu-west-2.amazonaws.com  custom:http-only
E2LMNOPQ3RSTUV  files.example.com   s3-files       files-bucket.s3.eu-west-2.amazonaws.com  OAI
200
200
```

#### Evaluation

- **Fail (High)** when the origin of a distribution that enforces WAF, geo restriction or signed URLs answers directly from the internet: those controls are optional for an attacker. **Critical** if the bypassed control is the only authentication (signed URLs or cookies protecting private content in a public bucket).
- **Fail (High)** for an S3 origin bucket that does not exist (anyone can create it and serve content on the client's domain).
- **Fail (Medium)** for OAI origins and for S3 website-endpoint origins serving content that is meant to be private only through CloudFront; **Low** where the content is genuinely public and nothing at the edge is being relied on.
- **Pass**: OAC with distribution-scoped bucket policies; custom origins restricted by prefix list plus secret header, or VPC origins; no direct `200`.

#### Automated coverage

Security Hub CSPM: **CloudFront.13** (OAC for S3 origins), **CloudFront.12** (non-existent S3 origins), **CloudFront.16** (OAC for Lambda function URL origins), **CloudFront.9**/**CloudFront.10** (origin TLS). Prowler: `cloudfront_distributions_s3_origin_access_control`, `cloudfront_distributions_s3_origin_non_existent_bucket`, `cloudfront_distributions_origin_traffic_encrypted`, `cloudfront_distributions_using_deprecated_ssl_protocols`. Origin bypass for custom origins needs the manual steps above.

#### Detection

`UpdateDistribution` changing origins or OAC, `DeleteOriginAccessControl`, S3 `PutBucketPolicy`/`DeletePublicAccessBlock` on origin buckets, `ModifyListener`/`ModifyRule` removing the header condition, `AuthorizeSecurityGroupIngress` replacing the prefix list with `0.0.0.0/0`. ALB access logs show requests that did not come through CloudFront (no CloudFront `Via`/`X-Amz-Cf-Id` headers, source IPs outside the prefix list). ATT&CK [T1190](https://attack.mitre.org/techniques/T1190/).

### GT-AWS-NET-8: CloudFront viewer TLS, access restrictions and cache behaviour

*Guler Tech methodology.*

#### What it checks

Viewer protocol policies, the TLS security policy, use of trusted key groups for signed URLs and cookies, geo restrictions and field-level encryption where the client relies on them, logging, the default root object, and cache key settings that create poisoning or deception risks.

#### Prerequisites

`cloudfront:Get*` and `List*`; for cache testing, approval to send benign requests to the client's distributions.

#### Steps

1. **Distribution settings:**

   ```bash
   aws cloudfront list-distributions --output json | jq -r '
     .DistributionList.Items[]?
     | [ .Id, (.Aliases.Items // [] | join(",")),
         .ViewerCertificate.MinimumProtocolVersion, (.ViewerCertificate.CloudFrontDefaultCertificate|tostring),
         .DefaultCacheBehavior.ViewerProtocolPolicy,
         ([.CacheBehaviors.Items[]?.ViewerProtocolPolicy] | unique | join(",")),
         (.WebACLId // ""), .Restrictions.GeoRestriction.RestrictionType, (.DefaultRootObject // "") ]
     | @tsv'
   ```

2. **Signed content:** `aws cloudfront get-distribution-config --id E1ABCDEF2GHIJK --query 'DistributionConfig.DefaultCacheBehavior.[TrustedKeyGroups,TrustedSigners]'`. Trusted signers mean CloudFront key pairs managed by the root user; plan migration to key groups (`aws cloudfront list-key-groups`). Ask how the private signing key is stored and rotated.
3. **Logging:** `DistributionConfig.Logging.Enabled` (standard logging, legacy) and any standard logging v2 delivery configured through CloudWatch Logs delivery; check at least one is on.
4. **Field-level encryption:** `aws cloudfront list-field-level-encryption-configs`; relevant only where a design calls for it (card data, national IDs posted through the edge). Its absence is not a finding by default.
5. **Cache keys and origin requests:** for each cache behaviour, read the cache policy and origin request policy (`aws cloudfront get-cache-policy --id ...`, `get-origin-request-policy --id ...`). Flag headers, cookies or query strings forwarded to the origin but excluded from the cache key (for example `Host` or `X-Forwarded-Host` forwarded with a managed caching policy) on behaviours that cache dynamic responses, and path-pattern behaviours (`*.css`, `*.js`, `/static/*`) that route to an application origin serving authenticated pages. Then, **with approval**, test one or two behaviours with benign cache-buster requests (a unique query string per request) to confirm reflection of an unkeyed header without poisoning anything real users receive.

#### Observation

```text
E1ABCDEF2GHIJK  app.example.com  TLSv1.2_2019  false  redirect-to-https  allow-all  ""  none  ""
E3WXYZ4ABCDEFG  -                TLSv1         true   allow-all          -          ""  none  ""
```

#### Evaluation

- **Fail (Medium)** for `allow-all` on any behaviour serving authenticated or sensitive content (credentials and session cookies can travel in clear text); **Low** for public static content.
- **Fail (Low–Medium)** for custom-certificate distributions on policies older than `TLSv1.2_2021` (Security Hub's CloudFront.15 now expects `TLSv1.2_2025` or `TLSv1.3_2025`); note that distributions on the default certificate are fixed at `TLSv1` and need a custom domain to change it.
- **Fail (Medium)** for signed URLs using trusted signers (root-managed keys) instead of key groups.
- **Fail (High)** for a demonstrated cache poisoning or deception issue affecting other users' responses; rate by what is cached (stored XSS-equivalent, or another user's account page).
- **Fail (Low)** for missing logging on production distributions, and for S3-origin distributions without a default root object (CloudFront.1) where the origin would list or expose content.
- **Pass**: `redirect-to-https` or `https-only` everywhere, a current TLS policy, key groups, logging on, cache keys reviewed.

#### Automated coverage

Security Hub CSPM: **CloudFront.3** (encryption in transit), **CloudFront.15** (recommended TLS policy), **CloudFront.17** (trusted key groups), **CloudFront.5** (logging), **CloudFront.1** (default root object), **CloudFront.7**/**CloudFront.8** (custom certificate, SNI). Prowler: `cloudfront_distributions_https_enabled`, `cloudfront_distributions_custom_ssl_certificate`, `cloudfront_distributions_https_sni_enabled`, `cloudfront_distributions_field_level_encryption_enabled`, `cloudfront_distributions_geo_restrictions_enabled`, `cloudfront_distributions_logging_enabled`, `cloudfront_distributions_default_root_object`, `cloudfront_distributions_pqc_tls_enabled`. Cache behaviour issues are manual.

#### Detection

`UpdateDistribution` (viewer protocol, TLS policy, logging off), `CreateCloudFrontOriginAccessIdentity`, `UpdateCachePolicy`/`UpdateOriginRequestPolicy`, `CreatePublicKey`/`UpdateKeyGroup`. ATT&CK [T1190](https://attack.mitre.org/techniques/T1190/), [T1557](https://attack.mitre.org/techniques/T1557/) for clear-text viewer connections.

### GT-AWS-NET-9: WAF and Shield coverage of internet-facing endpoints

*Guler Tech methodology.*

#### What it checks

Which internet-facing CloudFront distributions, ALBs, API Gateway stages and other supported resources have a web ACL; whether its rules are actually blocking; whether it logs; and whether Shield Advanced, if paid for, protects the resources that matter.

#### Prerequisites

`wafv2:List*`, `wafv2:Get*`, `shield:Describe*`, `shield:List*`, and the inventory from GT-AWS-NET-3.

#### Steps

1. **Web ACLs and what they protect:**

   ```bash
   aws wafv2 list-web-acls --scope CLOUDFRONT --region us-east-1 --query 'WebACLs[].[Name,ARN]' --output text
   each_region aws wafv2 list-web-acls --scope REGIONAL --query 'WebACLs[].[Name,ARN]' --output text
   aws wafv2 list-resources-for-web-acl --web-acl-arn <arn> --resource-type APPLICATION_LOAD_BALANCER --region eu-west-2
   aws wafv2 get-web-acl-for-resource --resource-arn <alb-arn> --region eu-west-2
   ```

   For CloudFront, the association is the distribution's `WebACLId`.
2. **Rule effectiveness:**

   ```bash
   aws wafv2 get-web-acl --scope REGIONAL --region eu-west-2 --name web-acl --id <id> --output json | jq -r '
     .WebACL.DefaultAction | keys[0] as $d | "default: \($d)"' 
   aws wafv2 get-web-acl --scope REGIONAL --region eu-west-2 --name web-acl --id <id> --output json | jq -r '
     .WebACL.Rules[] | [ .Priority, .Name,
       ((.Action // .OverrideAction) | keys[0]),
       (.Statement.ManagedRuleGroupStatement.Name // "custom") ] | @tsv'
   ```

   `OverrideAction: Count` on a managed group, or `Action: Count`, means detection only. Also check `RuleActionOverrides` inside managed groups that switch individual rules to count.
3. **Logging:** `aws wafv2 get-logging-configuration --resource-arn <web-acl-arn>`.
4. **Shield:** `aws shield describe-subscription` (a `ResourceNotFoundException` means no Shield Advanced) and `aws shield list-protections --query 'Protections[].[Name,ResourceArn]' --output text`.
5. **Second front doors:** for each protected ALB, check whether it is also reachable through a Global Accelerator or directly (GT-AWS-NET-7) without the same web ACL.

#### Observation

```text
default: Allow
0  AWS-AWSManagedRulesCommonRuleSet         Count  AWSManagedRulesCommonRuleSet
1  AWS-AWSManagedRulesKnownBadInputsRuleSet None   AWSManagedRulesKnownBadInputsRuleSet
```

#### Evaluation

- **Fail (Medium)** for internet-facing ALBs and CloudFront distributions serving applications with no web ACL, where the client's policy or threat model expects one (WAF is a mitigation, not a vulnerability fix; rate accordingly).
- **Fail (Medium)** for core managed rule groups left in `Count` long after rollout, and for web ACLs without logging (WAF.11).
- **Fail (Low)** for Shield Advanced subscriptions without protections on the critical resources (paid protection not applied), and for protected resources reachable through an unprotected path.
- **Pass**: web ACLs on every internet-facing application endpoint, baseline managed groups in block, logging on, coverage consistent across front doors.

#### Automated coverage

Security Hub CSPM: **ELB.16** (ALB with WAF), **CloudFront.6** (distribution with WAF), **WAF.10** (web ACL has rules), **WAF.11** (web ACL logging), **WAF.12** (rule metrics). Prowler: `elbv2_waf_acl_attached`, `cloudfront_distributions_using_waf`, `wafv2_webacl_with_rules`, `wafv2_webacl_logging_enabled`, `wafv2_webacl_managed_rule_groups_enabled`, and the `shield_advanced_protection_in_*` checks.

#### Detection

`DisassociateWebACL`, `UpdateWebACL` (rules switched to count, default action changed), `DeleteLoggingConfiguration`, `DeleteProtection`. ATT&CK [T1498 Network Denial of Service](https://attack.mitre.org/techniques/T1498/) (Shield's domain) and [T1190](https://attack.mitre.org/techniques/T1190/).

### GT-AWS-NET-10: Dangling DNS records in client hosted zones

*Guler Tech methodology.*

#### What it checks

Records in the client's own Route 53 hosted zones that point at AWS resources which no longer exist and could be claimed by someone else: S3 website buckets, Elastic Beanstalk environments, released Elastic IPs, and delegations to deleted hosted zones. Scope is strictly the client's zones and accounts; no internet-wide enumeration.

#### Prerequisites

`route53:ListHostedZones`, `route53:ListResourceRecordSets`, `route53:GetHostedZone`; read access to S3, Elastic Beanstalk, EC2 and CloudFront in **all** of the client's accounts (records often point at resources in another account of the same organisation). Zones hosted outside Route 53 need an export from the client.

#### Steps

1. **Export all records:**

   ```bash
   mkdir -p dns && for z in $(aws route53 list-hosted-zones --query 'HostedZones[?Config.PrivateZone==`false`].Id' --output text); do
     aws route53 list-resource-record-sets --hosted-zone-id "$z" --output json |
     jq -r '.ResourceRecordSets[] | [ .Name, .Type, (.AliasTarget.DNSName // ([.ResourceRecords[]?.Value] | join(" "))) ] | @tsv'
   done > dns/records.tsv
   ```

2. **Classify targets:**

   ```bash
   grep -iE 's3-website[.-]'            dns/records.tsv > dns/s3web.tsv
   grep -iE '\.elasticbeanstalk\.com'   dns/records.tsv > dns/eb.tsv
   grep -iE '\.cloudfront\.net'         dns/records.tsv > dns/cf.tsv
   awk -F'\t' '$2=="A" || $2=="AAAA"'   dns/records.tsv | grep -vE 'amazonaws|cloudfront' > dns/ip.tsv
   awk -F'\t' '$2=="NS"'                dns/records.tsv > dns/ns.tsv
   ```

3. **Check existence in the client's estate, not by resolving.** AWS's guidance is not to rely on DNS resolution, because a resolving name may already point at an attacker's resource.
   - **S3 website**: the bucket name equals the record name (minus the trailing dot). `aws s3api head-bucket --bucket shop.example.com` from the owning account: `404 Not Found` means no bucket by that name exists and anyone could create it; `403` means a bucket exists in an account you cannot read, so confirm the client owns it, and if not, treat it as a **possible takeover in progress** and escalate immediately.
   - **Elastic Beanstalk**: take the prefix and Region from `<prefix>.<region>.elasticbeanstalk.com` and run `aws elasticbeanstalk check-dns-availability --cname-prefix <prefix> --region <region>`. `"Available": true` means the name is free to claim. Cross-check `describe-environments` in the client's accounts.
   - **CloudFront**: confirm a distribution in the client's accounts lists the record as an alternate domain name. A `CNAME` to a `cloudfront.net` name with no matching distribution is stale; exploitation is constrained by CloudFront's certificate requirement, so rate it low, but remove it.
   - **A/AAAA**: compare each IP with Elastic IPs and public IPs across the client's accounts (GT-AWS-NET-3). An address inside AWS's published ranges (`ip-ranges.json`) that the client no longer holds may now belong to another customer.
   - **NS**: for each delegated subdomain, check that a hosted zone exists (`list-hosted-zones-by-name`) and that its delegation set (`get-hosted-zone`) matches the NS records in the parent.
4. **Automate it** for the client: dnsReaper (`dnsreaper aws` with the audit profile), Prowler `route53_dangling_ip_subdomain_takeover`, CloudFox `route53`, or AWS's `sample-dangling-dns-detection` Config rule for continuous coverage.
5. **Proof.** Do not register the bucket or Beanstalk name in your own account; AWS's [penetration testing policy](https://aws.amazon.com/security/penetration-testing/) prohibits S3 bucket and subdomain takeover. If the client wants proof, they claim it in **their** account, which also removes the risk, then delete the record.

#### Observation

```text
shop.example.com.    CNAME  shop.example.com.s3-website.eu-west-2.amazonaws.com
$ aws s3api head-bucket --bucket shop.example.com
An error occurred (404) when calling the HeadBucket operation: Not Found
promo.example.com.   CNAME  promo-2022.eu-west-2.elasticbeanstalk.com
{ "Available": true, "FullyQualifiedCNAME": "promo-2022.eu-west-2.elasticbeanstalk.com" }
```

#### Evaluation

- **Fail (High)** for a claimable S3 website or Beanstalk target. **Critical** where the subdomain is trusted by the client's applications: in an OAuth or SAML redirect allow list, in a CSP or CORS allow list, or within the scope of session cookies set for the parent domain. In those cases takeover leads to account takeover, not just defacement.
- **Fail (Medium)** for A records to IPs the client no longer owns (probabilistic, but the impact is the same when it hits), and for NS delegations to hosted zones that do not exist.
- **Fail (Low)** for stale CloudFront and ELB records: not claimable in practice, but noise that hides real problems.
- **Escalate immediately** if a target name exists in an account the client does not own.
- **Pass**: every alias and CNAME target exists in the client's estate, decommissioning removes DNS first, and continuous detection is in place.

#### Automated coverage

Security Hub CSPM has no general dangling-DNS control at the time of writing; **CloudFront.12** covers the CloudFront-to-missing-bucket case. Prowler: `route53_dangling_ip_subdomain_takeover`. AWS sample: `sample-dangling-dns-detection` (custom Config rule that raises Security Hub findings).

#### Detection

Route 53 `ChangeResourceRecordSets` (records added or left behind); S3 `DeleteBucket` and Beanstalk `TerminateEnvironment` and EC2 `ReleaseAddress` events without a matching DNS change are the precursors to watch. Public DNS query logging (GT-AWS-NET-11) shows scanning of old names. ATT&CK [T1584.001 Compromise Infrastructure: Domains](https://attack.mitre.org/techniques/T1584/001/), which explicitly covers subdomain hijacking.

### GT-AWS-NET-11: DNSSEC, DNS query logging and Resolver DNS Firewall

*Guler Tech methodology.*

#### What it checks

DNSSEC signing on public hosted zones the client relies on, public DNS query logging, Resolver query logging for VPCs, and Resolver DNS Firewall coverage and fail mode. Plus registrar protections for domains registered through Route 53.

#### Prerequisites

`route53:GetDNSSEC`, `route53:ListQueryLoggingConfigs`, `route53resolver:List*`, `route53resolver:Get*`, `route53domains:GetDomainDetail` (in `us-east-1`).

#### Steps

1. **DNSSEC** for each public zone:

   ```bash
   aws route53 get-dnssec --hosted-zone-id Z0123456789EXAMPLE \
     --query '[Status.ServeSignature, KeySigningKeys[].[Name,Status,KmsArn]]'
   dig +short DS example.com
   ```

   `SIGNING` without a DS record at the parent means signing is configured but no resolver validates it.
2. **Public query logging:** `aws route53 list-query-logging-configs --query 'QueryLoggingConfigs[].[HostedZoneId,CloudWatchLogsLogGroupArn]' --output text`.
3. **Resolver query logging** per Region and VPC:

   ```bash
   each_region aws route53resolver list-resolver-query-log-config-associations \
     --query 'ResolverQueryLogConfigAssociations[].[ResourceId,Status]' --output text
   ```

4. **DNS Firewall:**

   ```bash
   each_region aws route53resolver list-firewall-rule-group-associations \
     --query 'FirewallRuleGroupAssociations[].[VpcId,FirewallRuleGroupId,Priority,MutationProtection]' --output text
   aws route53resolver list-firewall-rules --firewall-rule-group-id rslvr-frg-0123456789abcdef --region eu-west-2 \
     --query 'FirewallRules[].[Priority,Action,FirewallDomainListId]' --output text
   each_region aws route53resolver list-firewall-configs --query 'FirewallConfigs[].[ResourceId,FirewallFailOpen]' --output text
   ```

   Map `FirewallDomainListId` to names with `list-firewall-domain-lists`; look for the AWS managed lists in `BLOCK`, not only `ALERT`.
5. **Domain registration** (if domains are registered with Route 53): `aws route53domains get-domain-detail --domain-name example.com --region us-east-1 --query '[StatusList,AdminPrivacy,RegistrantPrivacy]'`; `clientTransferProhibited` should be present.

#### Observation

```text
NOT_SIGNING  []
eu-west-2  vpc-0123456789abcdef0  ACTIVE
eu-west-2  (no firewall rule group associations)
```

#### Evaluation

- **Fail (Low–Medium)** for missing Resolver query logging on production VPCs: DNS is often the only evidence of C2 and exfiltration from a private subnet; **Medium** where there is no other egress visibility.
- **Fail (Low–Medium)** for no DNS Firewall (or only `ALERT` rules) on VPCs running internet-facing or third-party code, and for `FirewallFailOpen` enabled where the client expects enforcement.
- **Fail (Low)** for public zones without query logging (Route53.2) and for missing transfer lock on registered domains.
- **DNSSEC**: report as **Low/Info** unless the client has a regulatory or threat-model requirement (government, finance) or relies on delegations that are prone to dangling; signing has operational cost and limited benefit for most web properties.
- **Pass**: Resolver query logging on all VPCs, DNS Firewall with managed lists in block and fail-closed where tolerable, query logging on key public zones, transfer lock on.

#### Automated coverage

Security Hub CSPM: **Route53.2** (public hosted zones log DNS queries). Prowler: `route53_public_hosted_zones_cloudwatch_logging_enabled`, `route53_domains_transferlock_enabled`, `route53_domains_privacy_protection_enabled`. DNSSEC and Resolver coverage are manual at the time of writing.

#### Detection

`DisableHostedZoneDNSSEC`, `DeactivateKeySigningKey`, `DeleteQueryLoggingConfig`, Resolver `DisassociateResolverQueryLogConfig`, `DisassociateFirewallRuleGroup`, `UpdateFirewallConfig`, Route 53 Domains `DisableDomainTransferLock`, `TransferDomainToAnotherAwsAccount`. GuardDuty's DNS-based findings (e.g. `Trojan:EC2/DNSDataExfiltration`) use DNS logs independently. ATT&CK [T1584.001](https://attack.mitre.org/techniques/T1584/001/) for domain hijacking.

### GT-AWS-NET-12: VPC Flow Logs coverage

*Guler Tech methodology.*

#### What it checks

That every VPC in use has flow logs capturing at least rejected traffic (ideally all), to a destination with retention, so that the exposure findings above can be investigated. Detailed analysis belongs to the [detection services note](/cloud/aws-detection-posture-services/).

#### Prerequisites

`ec2:DescribeVpcs`, `ec2:DescribeFlowLogs`, `logs:DescribeLogGroups`.

#### Steps

```bash
for r in $REGIONS; do
  comm -23 \
    <(aws ec2 describe-vpcs --region "$r" --query 'Vpcs[].VpcId' --output text | tr '\t' '\n' | sort) \
    <(aws ec2 describe-flow-logs --region "$r" --query 'FlowLogs[?FlowLogStatus==`ACTIVE`].ResourceId' --output text | tr '\t' '\n' | sort -u) \
  | sed "s/^/$r\tno flow log\t/"
done
each_region aws ec2 describe-flow-logs \
  --query 'FlowLogs[].[ResourceId,TrafficType,LogDestinationType,LogDestination,LogFormat]' --output text
```

Subnet- or ENI-level flow logs also count for the resources they cover; empty default VPCs with no ENIs are a lower priority (or should be deleted).

#### Observation

```text
eu-west-2  no flow log  vpc-0123456789abcdef0
eu-west-2  vpc-0fedcba9876543210  REJECT  s3  arn:aws:s3:::flow-logs-111122223333  ${version} ${account-id} ${interface-id} ${srcaddr} ${dstaddr} ${srcport} ${dstport} ${protocol} ${packets} ${bytes} ${start} ${end} ${action} ${log-status}
```

#### Evaluation

- **Fail (Medium)** for VPCs with workloads and no flow logs. **Low** for unused VPCs.
- **Note** `TrafficType=REJECT` only: meets CIS but cannot show what an attacker *did* reach. Recommend `ALL`, plus fields such as `pkt-srcaddr`, `pkt-dstaddr`, `tcp-flags` and `flow-direction` in a custom format.
- **Pass**: all VPCs with workloads logging `ALL` to a central, retained destination.

#### Automated coverage

Security Hub CSPM: **EC2.6** (VPC flow logging in all VPCs; CIS v3.0.0 3.7, v5.0.0 3.7). Prowler: `vpc_flow_logs_enabled`.

#### Detection

`DeleteFlowLogs` (GuardDuty's `DefenseEvasion:IAMUser/AnomalousBehavior` names it among its examples), and deletion or retention changes on the destination log group or bucket. Verify that an SCP prevents these for non-administrators; the [Organizations note](/cloud/aws-organizations-multi-account-security/) has the pattern.

## Hardening

**Security groups by reference, not by range.** Tiers reference each other's groups; world-open rules only on load balancers and deliberate public services; the default group emptied in every VPC. In Terraform, take over the default group with no rules, and use rule resources so each rule is reviewable:

```hcl
resource "aws_default_security_group" "default" {
  vpc_id = aws_vpc.main.id
  # no ingress or egress blocks: all rules removed
}

resource "aws_vpc_security_group_ingress_rule" "db_from_app" {
  security_group_id            = aws_security_group.db.id
  referenced_security_group_id = aws_security_group.app.id
  ip_protocol                  = "tcp"
  from_port                    = 5432
  to_port                      = 5432
}

resource "aws_vpc_security_group_ingress_rule" "alb_from_cloudfront" {
  security_group_id = aws_security_group.alb.id
  prefix_list_id    = data.aws_ec2_managed_prefix_list.cloudfront.id
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
}

data "aws_ec2_managed_prefix_list" "cloudfront" {
  name = "com.amazonaws.global.cloudfront.origin-facing"
}
```

**Remove administrative ports altogether.** Session Manager or an EC2 Instance Connect Endpoint instead of SSH/RDP from the internet (see the [EC2 note](/cloud/aws-ec2-imds-ebs-ssm-security/)); a NACL deny on 22/3389 from `0.0.0.0/0` on public subnets as a backstop.

**Turn on VPC Block Public Access** in `block-ingress` mode where the architecture allows, with exclusions only for the subnets that host load balancers and NAT gateways, and enforce it through a declarative policy for new accounts.

**Perimeter policies on endpoints.** Every S3 and DynamoDB gateway endpoint gets a policy that only allows the organisation's principals to reach the organisation's resources:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "OrgPrincipalsToOrgResources",
      "Effect": "Allow",
      "Principal": "*",
      "Action": "*",
      "Resource": "*",
      "Condition": {
        "StringEquals": {
          "aws:PrincipalOrgID": "o-exampleorgid",
          "aws:ResourceOrgID": "o-exampleorgid"
        }
      }
    }
  ]
}
```

Add explicit statements for AWS-owned buckets your workloads need (package repositories, service buckets) after testing. On buckets that must only be reached from the VPC, use a deny:

```json
{
  "Sid": "DenyUnlessThroughOurEndpoint",
  "Effect": "Deny",
  "Principal": "*",
  "Action": "s3:*",
  "Resource": ["arn:aws:s3:::example-data-bucket", "arn:aws:s3:::example-data-bucket/*"],
  "Condition": {
    "StringNotEquals": { "aws:SourceVpce": "vpce-0123456789abcdef0" },
    "ArnNotLike": { "aws:PrincipalArn": "arn:aws:iam::111122223333:role/break-glass-admin" }
  }
}
```

**Segment the Transit Gateway.** Disable default route table association and propagation and auto-accept; one route table per environment; inspection VPC with AWS Network Firewall for east-west and egress traffic where the risk justifies it. Restrict PrivateLink services to named principals with acceptance required.

**Load balancer baseline.** Set `SslPolicy` explicitly in every listener definition; redirect 80 to 443; `defensive` or `strictest` desync mode; drop invalid headers; logs on; WAF associated; authentication targets reachable only from the ALB's security group:

```hcl
resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.web.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09"
  certificate_arn   = aws_acm_certificate.web.arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.web.arn
  }
}

resource "aws_lb_listener" "http_redirect" {
  load_balancer_arn = aws_lb.web.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = "redirect"
    redirect {
      protocol    = "HTTPS"
      port        = "443"
      status_code = "HTTP_301"
    }
  }
}

resource "aws_lb" "web" {
  name                       = "web"
  load_balancer_type         = "application"
  internal                   = false
  security_groups            = [aws_security_group.alb.id]
  subnets                    = var.public_subnet_ids
  desync_mitigation_mode     = "strictest"
  drop_invalid_header_fields = true
  enable_deletion_protection = true

  access_logs {
    bucket  = var.alb_log_bucket
    enabled = true
  }
}
```

Check the policy name against the current [ALB security policy list](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/describe-ssl-policies.html) when you copy this; AWS adds policies regularly.

**CloudFront baseline.** OAC for every S3 origin, with distribution-scoped bucket policies and S3 Block Public Access on; no S3 website-endpoint origins for anything private; VPC origins for ALB/EC2 origins where possible, otherwise the CloudFront prefix list plus a rotated secret header; `redirect-to-https` or `https-only`; `TLSv1.2_2025` or newer with a custom certificate; trusted key groups; logging; a web ACL with managed rule groups in block. A minimal CloudFormation fragment for the S3 part:

```yaml
OriginAccessControl:
  Type: AWS::CloudFront::OriginAccessControl
  Properties:
    OriginAccessControlConfig:
      Name: assets-oac
      OriginAccessControlOriginType: s3
      SigningBehavior: always
      SigningProtocol: sigv4

AssetsBucketPolicy:
  Type: AWS::S3::BucketPolicy
  Properties:
    Bucket: !Ref AssetsBucket
    PolicyDocument:
      Version: "2012-10-17"
      Statement:
        - Sid: AllowCloudFrontServicePrincipalReadOnly
          Effect: Allow
          Principal:
            Service: cloudfront.amazonaws.com
          Action: s3:GetObject
          Resource: !Sub "arn:aws:s3:::${AssetsBucket}/*"
          Condition:
            StringEquals:
              AWS:SourceArn: !Sub "arn:aws:cloudfront::${AWS::AccountId}:distribution/${Distribution}"
```

**DNS hygiene.** Decommission in the order AWS recommends: delete the DNS record, wait for the TTL, then delete the resource. Deploy continuous dangling-record detection (AWS's sample Config rule, Prowler, or dnsReaper on a schedule). Prefer alias records to resources in the same account, so a deleted target is visible. Use S3 bucket names that are not the hostname where possible, or CloudFront with OAC instead of S3 website hosting. Delegate subdomains only to hosted zones that exist, through their immediate parent, and consider DNSSEC for high-value zones.

**Visibility.** Flow logs (`ALL`) on every VPC, Resolver query logging and DNS Firewall with AWS managed lists, WAF logging, ALB and CloudFront access logs, all to a central log archive account. Guardrail SCPs should deny `DeleteFlowLogs`, `DisassociateResolverQueryLogConfig`, `DisassociateFirewallRuleGroup`, `DeleteLoggingConfiguration` and `ModifyVpcBlockPublicAccessOptions` to everyone except the platform team; the [Organizations note](/cloud/aws-organizations-multi-account-security/) has the pattern. Config rules worth enabling: `vpc-sg-port-restriction-check`, `vpc-default-security-group-closed`, `vpc-flow-logs-enabled`, `alb-http-to-https-redirection-check`, `alb-desync-mode-check`, `elbv2-predefined-security-policy-ssl-check`, `cloudfront-s3-origin-access-control-enabled`, `cloudfront-s3-origin-non-existent-bucket`, `route53-query-logging-enabled`.

## Real-world cases

- **HTTP Desync Attacks (2019).** James Kettle's research on request smuggling between front-end and back-end servers showed practical cache poisoning and credential theft against major sites. AWS's response for ALB and Classic Load Balancers was desync mitigation mode, built on the open-source [http-desync-guardian](https://github.com/aws/http-desync-guardian) library, and the controls behind ELB.4, ELB.12 and ELB.14. [HTTP Desync Attacks: Request Smuggling Reborn](https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn).
- **ALBeast (2024).** Miggo Research showed that applications using ALB's built-in authentication could accept tokens forged through an attacker's own ALB when they did not verify the `signer` field and accepted traffic from anywhere other than their load balancer, and estimated thousands of exposed applications. AWS disputed the "vulnerability" framing and updated its documentation to require signer validation and target restriction. [Uncovering an auth vulnerability in AWS ALB: ALBeast](https://www.miggo.io/post/uncovering-auth-vulnerability-in-aws-alb-albeast).
- **BreakingWAF (2024).** Zafran mapped thousands of large organisations' domains whose origin servers behind CDN/WAF services (Akamai, Cloudflare, Fastly, Imperva) accepted traffic directly from the internet, making the WAF optional. Not AWS-specific, but it is exactly the CloudFront origin bypass in GT-AWS-NET-7. [BreakingWAF](https://zafran.io/resources/breaking-waf).
- **Subdomain takeover against AWS customers (2026).** The AWS Customer Incident Response Team reported threat actors actively scanning for public CNAME records that point at deleted S3 website buckets and terminated Elastic Beanstalk environments, and published a detection Config rule. [Threat tactic spotlight: Subdomain takeover](https://aws.amazon.com/blogs/security/threat-tactic-spotlight-subdomain-takeover/).

More cases are collected in our [AWS incidents and write-ups](/cloud/aws-security-incidents-and-writeups/) note and the [bug bounty reading list](/bug-bounty-writeups/).

## Rating findings

| Finding | Typical severity | Reasoning |
|---|---|---|
| Claimable dangling record (S3 website, Beanstalk) on a subdomain trusted for OAuth/SAML redirects, CORS, CSP or parent-domain cookies | Critical | Unauthenticated attacker serves content on a trusted origin; leads to session theft or account takeover. |
| Claimable dangling record on an untrusted marketing subdomain | High | Content and phishing on the client's domain, reputational damage, and often cookie exposure that is not obvious at first. |
| CloudFront origin bypass where signed URLs/cookies or WAF are the only protection | Critical / High | Edge authentication or filtering becomes optional for any internet user. |
| ALB authentication targets reachable directly or not validating `signer` | High–Critical | Identity forgery for any user; Critical where admin identities can be forged. |
| Admin or database port open to 0.0.0.0/0 or ::/0 on a public ENI | High (Critical with an unauthenticated or vulnerable service) | Direct internet attack surface on the most attacked services. |
| PrivateLink service open to `*` with auto-accept, fronting an internal API | High | Any AWS account can connect to an internal service; severity follows the service's own authentication. |
| External peering/TGW attachment routed to production without restriction | High | Third-party network gets a path to production; treat like an unreviewed cross-account role. |
| Non-existent S3 origin on a distribution | High | Anyone can create the bucket and serve content through the client's distribution. |
| Default gateway endpoint policy in sensitive VPCs | Medium | Unmonitored exfiltration path to any S3 bucket; needs a prior compromise. |
| Weak TLS policy (TLS 1.0/1.1) on internet-facing listener or distribution | Medium (Low internal) | Compliance failure and downgrade exposure; little direct exploitability today. |
| HTTP listener forwarding, `allow-all` viewer policy on sensitive content | Medium | Clear-text credentials or session tokens on hostile networks. |
| Desync mitigation in `monitor`, invalid headers forwarded | Medium / Low | Removes a platform defence against request smuggling; exploitability depends on the back end. |
| Default security group with rules or in use | Medium | Unintended any-port reachability between unrelated workloads. |
| No WAF / WAF in count mode on internet-facing applications | Medium | Missing mitigation layer; rate as defence in depth, not as a vulnerability. |
| Missing flow logs, Resolver query logs or WAF logs | Medium (Low for unused VPCs) | Incidents in these networks cannot be investigated. |
| Public IP sprawl, auto-assign public IP, unused Elastic IPs | Low | Hygiene; increases attack surface and creates future dangling DNS. |
| Stale CloudFront/ELB DNS records, unused or stale security groups | Low | Not exploitable in practice; confusion during incidents. |
| DNSSEC not enabled | Info / Low | Benefit limited for most web properties unless required by policy or regulation. |

## Mapping

| Test | Security Hub CSPM | CIS AWS Foundations | MITRE ATT&CK |
|---|---|---|---|
| GT-AWS-NET-1 | EC2.53, EC2.54, EC2.13, EC2.14, EC2.18, EC2.19 | v3.0.0 5.2, 5.3; v5.0.0 5.3, 5.4 (EC2.53/54); v1.2.0 4.1, 4.2 (EC2.13/14) | T1133, T1190, T1686.001 |
| GT-AWS-NET-2 | EC2.2, EC2.21, EC2.22, EC2.16 | v3.0.0 5.4, 5.1; v5.0.0 5.5, 5.2 | T1686.001 |
| GT-AWS-NET-3 | EC2.9, EC2.15, EC2.25, EC2.12, EC2.172 | — | T1046, T1599 |
| GT-AWS-NET-4 | EC2.10, EC2.55–EC2.60 (existence only) | — | T1530, T1537 |
| GT-AWS-NET-5 | EC2.23 | — | T1599 |
| GT-AWS-NET-6 | ELB.1, ELB.3, ELB.4, ELB.5, ELB.8, ELB.12, ELB.14, ELB.16, ELB.17, ELB.18 | — | T1190 |
| GT-AWS-NET-7 | CloudFront.12, CloudFront.13, CloudFront.16, CloudFront.9, CloudFront.10 | — | T1190 |
| GT-AWS-NET-8 | CloudFront.1, CloudFront.3, CloudFront.5, CloudFront.7, CloudFront.8, CloudFront.15, CloudFront.17 | — | T1190, T1557 |
| GT-AWS-NET-9 | ELB.16, CloudFront.6, WAF.10, WAF.11, WAF.12 | — | T1190, T1498 |
| GT-AWS-NET-10 | CloudFront.12 (partial) | — | T1584.001 |
| GT-AWS-NET-11 | Route53.2 | — | T1584.001 |
| GT-AWS-NET-12 | EC2.6 | v3.0.0 3.7; v5.0.0 3.7 | (detection control) |

CIS numbers are taken from the Security Hub CSPM control pages' "related requirements" at the time of writing. AWS renamed the original Security Hub product to **AWS Security Hub CSPM** in 2025 when it launched the new unified Security Hub; control IDs did not change. ATT&CK v20 moved "Disable or Modify Cloud Firewall" from T1562.007 to T1686.001; older reports and detections may still use the old ID.

## References

- AWS VPC: [Security groups](https://docs.aws.amazon.com/vpc/latest/userguide/vpc-security-groups.html), [Default security groups](https://docs.aws.amazon.com/vpc/latest/userguide/default-security-group.html), [Network ACLs](https://docs.aws.amazon.com/vpc/latest/userguide/vpc-network-acls.html), [Block public access to VPCs and subnets](https://docs.aws.amazon.com/vpc/latest/userguide/security-vpc-bpa.html), [Flow logs](https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html)
- AWS PrivateLink and endpoints: [Control access to VPC endpoints using endpoint policies](https://docs.aws.amazon.com/vpc/latest/privatelink/vpc-endpoints-access.html), [S3 bucket policies for VPC endpoints](https://docs.aws.amazon.com/AmazonS3/latest/userguide/example-bucket-policies-vpc-endpoint.html), [Global condition keys (`aws:SourceVpce`, `aws:SourceVpc`, `aws:VpcSourceIp`)](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html)
- AWS ELB: [Application Load Balancer attributes](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/application-load-balancers.html), [Security policies for ALB](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/describe-ssl-policies.html), [Authenticate users using an ALB](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/listener-authenticate-users.html)
- AWS CloudFront: [Restrict access to an S3 origin (OAC)](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/private-content-restricting-access-to-s3.html), [Restrict access to Application Load Balancers](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/restrict-access-to-load-balancer.html), [VPC origins](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/private-content-vpc-origins.html), [Supported protocols and ciphers between viewers and CloudFront](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/secure-connections-supported-viewer-protocols-ciphers.html), [Alternate domain names](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/CNAMEs.html), [Private content: signed URLs and cookies](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/PrivateContent.html), [Field-level encryption](https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/field-level-encryption.html), [Limit access to your origins using the AWS-managed prefix list](https://aws.amazon.com/blogs/networking-and-content-delivery/limit-access-to-your-origins-using-the-aws-managed-prefix-list-for-amazon-cloudfront/)
- AWS WAF and Shield: [What is AWS WAF](https://docs.aws.amazon.com/waf/latest/developerguide/what-is-aws-waf.html), [Body inspection size limits](https://docs.aws.amazon.com/waf/latest/developerguide/web-acl-setting-body-inspection-limit.html), [AWS Shield](https://docs.aws.amazon.com/waf/latest/developerguide/shield-chapter.html)
- AWS Route 53: [Protection from dangling delegation records](https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/protection-from-dangling-dns.html), [DNSSEC signing](https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/dns-configuring-dnssec.html), [Resolver query logging](https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resolver-query-logs.html), [Resolver DNS Firewall](https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resolver-dns-firewall.html), [Managed domain lists](https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resolver-dns-firewall-managed-domain-lists.html), [AWS Security Blog: Threat tactic spotlight: Subdomain takeover](https://aws.amazon.com/blogs/security/threat-tactic-spotlight-subdomain-takeover/)
- AWS Global Accelerator: [What is AWS Global Accelerator](https://docs.aws.amazon.com/global-accelerator/latest/dg/what-is-global-accelerator.html)
- AWS Security Hub CSPM: [EC2 controls](https://docs.aws.amazon.com/securityhub/latest/userguide/ec2-controls.html), [ELB controls](https://docs.aws.amazon.com/securityhub/latest/userguide/elb-controls.html), [CloudFront controls](https://docs.aws.amazon.com/securityhub/latest/userguide/cloudfront-controls.html), [Route 53 controls](https://docs.aws.amazon.com/securityhub/latest/userguide/route53-controls.html), [WAF controls](https://docs.aws.amazon.com/securityhub/latest/userguide/waf-controls.html), [CIS AWS Foundations Benchmark](https://docs.aws.amazon.com/securityhub/latest/userguide/cis-aws-foundations-benchmark.html)
- AWS: [Penetration testing policy](https://aws.amazon.com/security/penetration-testing/)
- Tools: [Prowler](https://github.com/prowler-cloud/prowler), [ScoutSuite](https://github.com/nccgroup/ScoutSuite), [CloudFox](https://github.com/BishopFox/cloudfox), [Pacu](https://github.com/RhinoSecurityLabs/pacu), [Steampipe AWS plugin](https://hub.steampipe.io/plugins/turbot/aws), [dnsReaper](https://github.com/punk-security/dnsReaper), [sample-dangling-dns-detection](https://github.com/aws-samples/sample-dangling-dns-detection), [Can I take over XYZ](https://github.com/EdOverflow/can-i-take-over-xyz), [http-desync-guardian](https://github.com/aws/http-desync-guardian)
- Research: [HTTP Desync Attacks](https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn), [ALBeast](https://www.miggo.io/post/uncovering-auth-vulnerability-in-aws-alb-albeast), [BreakingWAF](https://zafran.io/resources/breaking-waf)
- Labs: [CloudGoat](https://github.com/RhinoSecurityLabs/cloudgoat), [flaws.cloud](http://flaws.cloud/), [flaws2.cloud](http://flaws2.cloud/)
- MITRE ATT&CK: [T1190](https://attack.mitre.org/techniques/T1190/), [T1133](https://attack.mitre.org/techniques/T1133/), [T1046](https://attack.mitre.org/techniques/T1046/), [T1599](https://attack.mitre.org/techniques/T1599/), [T1584.001](https://attack.mitre.org/techniques/T1584/001/), [T1686.001](https://attack.mitre.org/techniques/T1686/001/), [T1530](https://attack.mitre.org/techniques/T1530/), [T1537](https://attack.mitre.org/techniques/T1537/), [T1557](https://attack.mitre.org/techniques/T1557/), [T1498](https://attack.mitre.org/techniques/T1498/)
- Related notes: [EC2, IMDS, EBS and SSM](/cloud/aws-ec2-imds-ebs-ssm-security/), [S3](/cloud/aws-s3-security/), [unauthenticated recon](/cloud/aws-unauthenticated-recon/), [API Gateway](/cloud/aws-api-gateway-sns-sqs-security/), [detection services](/cloud/aws-detection-posture-services/), [CloudTrail](/cloud/aws-cloudtrail-logging/), [Organizations](/cloud/aws-organizations-multi-account-security/)
