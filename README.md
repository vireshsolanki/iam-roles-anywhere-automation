# AWS IAM Roles Anywhere — Free, Scalable Certificate Authority

**A production-ready, cost-effective alternative to AWS ACM Private CA (~$400/month).** Issue temporary AWS credentials to applications, services, and developers using X.509 certificates signed by your own CA — no permanent access keys, anywhere.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Status: Production Ready](https://img.shields.io/badge/Status-Production%20Ready-brightgreen)]()

---

## Why This Exists

AWS **ACM Private CA** costs ~$400/month minimum. **AWS IAM Roles Anywhere** is free, but requires a CA — building one is non-trivial. This repo provides two complete, tested implementations:

1. **Local CA** — CA private key lives on your laptop, suitable for solo developers or small proof-of-concepts.
2. **Central CA** — CA private key lives in AWS KMS (un-extractable), suitable for teams and production workloads with 10s–1000s of users.

Both paths produce the same AWS-facing infrastructure: a **Trust Anchor** (tells AWS to accept your CA), **Profiles** (which roles can be assumed), and **Roles** (the actual permissions). The only difference is where the CA private key lives and how certificate issuance is orchestrated.

---

## How This Compares to Other Roles Anywhere Projects

A few other public repos cover related ground. Worth being precise about what each one actually is, since they solve different (sometimes overlapping) problems:

| | **This repo (Central CA)** | **This repo (Local CA)** | [aws-samples/sample-...-demo](https://github.com/aws-samples/sample-aws-iam-roles-anywhere-demo) | [aws-samples/sample-...-automation](https://github.com/aws-samples/sample-aws-iam-roles-anywhere-automation) |
|---|---|---|---|---|
| **What it is** | Full CA + issuance pipeline | Full CA + issuance pipeline | Educational demo | Full CA + issuance automation |
| **CA type** | AWS KMS (never exportable) | Laptop OpenSSL | Laptop OpenSSL (self-signed) | AWS ACM Private CA |
| **Monthly cost** | ~$1.25–2.50 (see below) | ~$0 | ~$0 | **$400+** (ACM Private CA) |
| **Says it's production-ready?** | Yes | For solo/small use | **No** — explicitly labeled "Not Production-Ready" | Claims yes |
| **Cert renewal** | Automatic, old cert auto-revoked | Manual re-run | Not implemented | Not detailed in the repo |
| **Revocation** | DynamoDB + CRL, enforced within seconds; permanent (`revoke`) or reversible (`disable`/`enable`) | Manual | Not implemented | Not detailed in the repo |
| **Audit trail** | DynamoDB (full lifecycle: issued/renewed/revoked/disabled) | None built-in | CloudTrail only | Not detailed in the repo |
| **Zero-AWS-credential onboarding** | Yes (API Gateway + API key, issuance-only) | No | No | No |

**The comparison that actually matters:** `sample-aws-iam-roles-anywhere-automation` is the closest thing to a real alternative — it's genuinely well-automated. But it deploys **ACM Private CA**, which is the $400/month cost this entire project exists to eliminate. If you're fine paying for ACM Private CA, that repo is a solid choice. If the cost is the blocker (which is why most people end up here), this project reaches the same Roles Anywhere end-state for a couple of dollars a month instead.

---

## Why Trust This Isn't Just Generated Boilerplate

A fair question for any infra repo today. Two ways to check for yourself rather than take my word for it:

**1. The cryptography is small enough to actually read.** [kms_ca.py](central-ca/lambda/kms_ca.py) is a ~240-line, dependency-free X.509/DER encoder — no `cryptography` package, no OpenSSL bindings, just `hashlib` + `base64` + hand-written ASN.1 TLV encoding. Read it in ten minutes and you've audited 100% of the certificate-generation logic. Nothing is hidden behind an imported library you have to trust blindly.

**2. The commit history documents real bugs hit against live AWS, not hypothetical ones.** A few examples that only surface when you actually deploy something, not when you generate docs about deploying something:
   - A Lambda Function URL configured with `AuthType: NONE` and a verifiably-correct public-invoke resource policy still returned a persistent `{"Message":"Forbidden"}` on a real account — traced to an AWS Organizations SCP blocking public Function URLs, not a config error. Fixed by switching to API Gateway + API key, which sidesteps that class of guardrail.
   - AWS's own Lambda console suggested granting `lambda:InvokeFunction` publicly to fix a permissions warning. That suggestion was explicitly **not followed**, because it would have let anyone with any AWS account bypass the API key entirely and reach admin-only actions via a plain `aws lambda invoke` — a real security tradeoff caught and reasoned through, not glossed over.
   - `AWS::Logs::LogGroup` failing with "already exists" because Lambda had already lazily auto-created the log group during the same deploy — fixed with an idempotent create-or-reuse custom resource instead of just telling users to manually delete the log group every time.

None of these are the kind of thing you'd write from first principles without having actually broken it against a real AWS account first. The commit history (`git log`) has the full trail.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│  Your CA (self-managed or KMS-backed)                   │
│  • Laptop OpenSSL (Local CA)                            │
│  • AWS KMS asymmetric key (Central CA)                  │
└────────────────────────┬────────────────────────────────┘
                         │
                    [Certificate Issued]
                         │
                         ▼
┌─────────────────────────────────────────────────────────┐
│  AWS IAM Roles Anywhere                                 │
│  • Trust Anchor (CA certificate uploaded)               │
│  • Profile (role binding + session duration)            │
│  • Role (IAM permissions)                               │
└────────────────────────┬────────────────────────────────┘
                         │
                    [Client connects with cert + key]
                         │
                         ▼
┌─────────────────────────────────────────────────────────┐
│  External System / Developer / CI/CD                     │
│  → Temporary AWS credentials (no permanent keys)         │
│  → Session duration and policies enforced by Role        │
└─────────────────────────────────────────────────────────┘
```

### Visual Architecture Diagrams

#### Central CA Pattern (AWS KMS-backed Production CA)
![Central CA Architecture Flow — Admin Laptop deploys via CloudFormation, which provisions a Fetcher Lambda, KMS CA Key, Issuer Lambda, S3 bucket, DynamoDB cert index, API Gateway, and Roles Anywhere Trust Anchor/Profile; a Developer Laptop reaches the Issuer Lambda through API Gateway to obtain a certificate and assume the target IAM Role](central-flow.png)

Numbered flow: (1–3) admin deploys the stack, which bootstraps the KMS key and issuer Lambda; (4) the public API Gateway and the issuer Lambda are wired together; (5, 13, 17) a developer requests and receives a certificate through the public endpoint, with no AWS credentials of their own; (9–11, 15–16) every signature and revocation is recorded in S3 and DynamoDB; (12, 14) the resulting certificate lets the developer's laptop assume the target IAM Role via the Roles Anywhere Trust Anchor/Profile.

#### Local CA Pattern (Laptop-managed CA for POCs)
![Local CA Architecture Flow — Admin Laptop holds the CA private key locally, deploys the Trust Anchor and IAM Role via CloudFormation, and issues certificates directly to a Developer Laptop, which presents its certificate to the Trust Anchor to assume the IAM Role](local-flow.png)

Numbered flow: (2–3) the admin deploys the Trust Anchor + Role via CloudFormation; (4) the admin issues a certificate directly from the laptop-held CA private key; (5–6) the developer's laptop presents that certificate to the Trust Anchor and assumes the IAM Role. No Lambda, KMS, or public endpoint in this path — everything routes through the admin's own machine, which is exactly the tradeoff that makes Central CA the better fit past a handful of users.

### Terminology — read this before anything else confuses you

This project uses the word **"Role"** and **"Profile"** for several *different* things. Getting these mixed up is the #1 source of confusion, so here's the exact meaning of each:

| Term | What it actually is | Where you'll see it |
|---|---|---|
| **IAM Role** | The actual AWS permissions container — an `AWS::IAM::Role` resource. This is what grants (or denies) access to S3, DynamoDB, etc. | `--role-arn`, `RoleArn` in CloudFormation outputs |
| **Roles Anywhere Trust Anchor** | An AWS resource that says "I trust certificates signed by this CA." One per CA, created once, shared by everyone. | `--trust-anchor-arn`, `TrustAnchorArn` output |
| **Roles Anywhere Profile** | A **different** AWS resource (not an IAM Role!) that says "certificates from this Trust Anchor may assume *these* IAM Roles, for up to *this* session duration." This is the binding between "who you are" (certificate) and "what you can do" (IAM Role). | `--profile-arn`, `ProfileArn` output |
| **AWS CLI Profile** | A **completely unrelated** concept — a named block in your local `~/.aws/config` file (e.g. `[profile alice-central-ca]`). This is a client-side convenience for selecting which credentials to use; it has nothing to do with the Roles Anywhere Profile above, despite sharing the word "profile." | `aws --profile alice-central-ca ...`, `AWS_PROFILE` env var |
| **Client** / **Client Identity** | The person, service, or CI job holding a certificate + private key. Identified by the certificate's Common Name (CN), e.g. `CN=alice`. Not an AWS resource — just "whoever has the key." | `--name alice`, `common_name` field |

**The full chain, in plain English:**

> A **Client** (e.g. Alice) has a **certificate**, signed by **your CA**, which AWS trusts because of the **Trust Anchor**. When Alice connects, AWS checks the **Roles Anywhere Profile** to see which **IAM Role(s)** her certificate is allowed to assume, and for how long (session duration). AWS then hands her **temporary credentials** for that IAM Role. Separately, on her own laptop, she might save those credentials under a named **AWS CLI Profile** so she doesn't have to type the full command every time — that last part is 100% local and has nothing to do with AWS's own Roles Anywhere Profile.

If you only remember one thing: **"Roles Anywhere Profile" (AWS-side, binds cert → IAM Role) and "AWS CLI Profile" (local, in `~/.aws/config`) are unrelated, same word, different concepts.**

---

## Two Deployment Paths

### Local CA (Single Admin / POC)

**CA private key lives on your laptop.** Suitable for:
- Solo developers testing Roles Anywhere
- Small teams (~1-10 users)
- Quick proof-of-concepts
- Environments where KMS is not available

**Deploy:** Shell scripts + AWS CloudFormation
```bash
./deploy.sh                  # Full automated pipeline
# or step-by-step:
./local-ca/setup-ca.sh       # Create Root CA (laptop)
aws cloudformation deploy... # Deploy Trust Anchor + Profile + Role
./local-ca/setup-client.sh   # Issue a client certificate
```

**Everything is documented in:**
- [CLAUDE.md](CLAUDE.md) — prerequisite tools, detailed step-by-step flow
- [local-ca-stack.yml](local-ca-stack.yml) — CloudFormation template

### Central CA (Teams / Production)

**CA private key lives in AWS KMS** (never exportable). Suitable for:
- Teams and organizations
- Onboarding 10s to 1000s of users
- Production workloads
- Zero risk of laptop-loss compromising the CA

**Deploy:** Single CloudFormation stack via AWS Console (no CLI)
```bash
# AWS Console: CloudFormation → Create Stack → Upload central-ca/central-ca-stack.yml
# That's it — everything auto-bootstraps
```

**Features:**
- Auto-bootstrapped Root CA certificate
- Public HTTPS API Gateway endpoint (dev self-onboarding, no AWS credentials needed)
- DynamoDB-backed certificate index (lifecycle tracking, revocation, renewal)
- Certificate renewal with automatic old-cert revocation
- Auto-configured AWS CLI credential_process profile
- Configurable CloudWatch log retention (no unbounded logging cost)
- Idempotent log-group setup (no "already exists" failures on re-deploy)

**Everything is documented in:**
- [central-ca/README.md](central-ca/README.md) — full architecture, deploy, onboarding, renewal, revocation

---

## Quick Start

### Prerequisites (Both Paths)

```bash
openssl version        # Need OpenSSL 1.1.1+
jq --version          # Need jq for JSON parsing
curl --version        # Need curl for HTTP
aws --version         # Need AWS CLI v2, configured with credentials
```

### Option 1: Local CA (Laptop)

```bash
cd local-ca
./setup-ca.sh                          # Create the Root CA (generates ./ca/ca-*.pem)
aws cloudformation deploy \
  --template-file local-ca-stack.yml \
  --stack-name iam-roles-anywhere-poc \
  --parameter-overrides \
    CACertificateBody="$(cat ./ca/ca-certificate.pem)" \
    SessionDurationSeconds=3600 \
    IAMPolicyArns="arn:aws:iam::aws:policy/ReadOnlyAccess" \
  --capabilities CAPABILITY_NAMED_IAM

./setup-client.sh \
  --trust-anchor-arn <arn from stack outputs> \
  --profile-arn <arn from stack outputs> \
  --role-arn <arn from stack outputs> \
  --client-name alice

cd client-alice
./test-credentials.sh                  # Verify end-to-end
```

### Option 2: Central CA (Production)

1. **AWS Console** → CloudFormation → **Create stack** → Upload `central-ca/central-ca-stack.yml`
2. Set parameters (ProjectName, CACertValidityDays, ApiKeyValue for public endpoint)
3. Wait for `CREATE_COMPLETE` (~2 min)
4. Use `central-ca/request-cert.sh` to onboard users (dev mode: via public API, no AWS credentials needed)

```bash
cd central-ca

# Dev mode (no AWS credentials needed)
./request-cert.sh \
  --url <ApiEndpoint from stack outputs> \
  --secret <ApiKeyValue you set> \
  --name alice \
  --trust-anchor-arn <TrustAnchorArn> \
  --profile-arn <ProfileArn> \
  --role-arn <RoleArn> \
  --days 365

# Auto-creates AWS CLI profile: alice-central-ca
aws sts get-caller-identity --profile alice-central-ca
```

---

## Key Features

### No Permanent AWS Access Keys

Traditional IAM users require long-lived secret access keys — a single leak compromises your account indefinitely. With Roles Anywhere:
- **Temporary credentials only** (15 min – 12 hours, configurable per role)
- **Revoke instantly** by revoking the certificate
- **Audit trail** shows certificate CN (identity) with every API call

### Automatic Certificate Lifecycle

- **Issue** certificates instantly (5–30 seconds)
- **Renew** with automatic old-cert revocation (one valid cert per identity) — the old cert's revocation is enforced immediately too, not just recorded
- **Revoke** permanently — one call marks it revoked *and* publishes the CRL to Roles Anywhere in the same step, so it's actually rejected within seconds, not just logged
- **Disable / enable** for reversible suspension (a contractor between engagements, someone on leave) — blocked identically to a revoke while disabled, restorable to the exact same certificate via `enable`, but `enable` can never touch a truly revoked serial — that stays permanent
- **Track everything** in DynamoDB (serial, CN, issued_at, revoked_reason, disabled_reason, renewed_from, etc.)

### Zero-Trust Developer Onboarding

Central CA includes a **public HTTPS API Gateway endpoint** (API key auth, no AWS IAM required) — **issuance only**, nothing else:
```bash
curl -X POST "https://api.example.com/issue" \
  -H "x-api-key: <shared-secret>" \
  -H "Content-Type: application/json" \
  -d '{"action":"sign", "common_name":"alice", "public_key":"...", "days":30}'
```
Developers **never touch AWS credentials**, and this endpoint can only ever issue a certificate — not revoke, renew, disable, or reissue anything, theirs or anyone else's. Every other lifecycle action requires admin IAM credentials. Admin shares only the endpoint URL and API key.

### Cost Breakdown

| Component | Cost | Notes |
|-----------|------|-------|
| KMS (Central CA only) | ~$1/mo | Single asymmetric key, pay-per-use signing |
| Lambda | ~$0.20/mo | Rare invocations (issuance, renewal, revocation) |
| DynamoDB | ~$0.25/mo | On-demand (pay-per-request), 1 item per cert |
| S3 | <$0.01/mo | CA cert + CRL, tiny objects |
| **Total (Central CA)** | **~$1.50/mo** | vs. $400+/mo for ACM Private CA |
| **Total (Local CA)** | **~$0** | Only EC2/RDS costs if deployed there |

### Cost at Scale — 2000 Users (Central CA)

The numbers above are for a light-traffic single-key setup. Here's a real,
verified **AWS Pricing Calculator estimate** for a **2000-user production
deployment**:

**👉 [View the live calculator.aws estimate](https://calculator.aws/#/estimate?id=8bc0d34839e2c22287a2bc891ac321ee1cdeb114)**

**Assumptions modeled:** 1 KMS asymmetric CMK (~1,500 sign/getPublicKey requests/mo,
covering new onboardings + renewals + revocations), Lambda (~800 invocations/mo,
256MB, 3s avg duration), DynamoDB on-demand (~800 read + 800 write request
units/mo, 2000 items at ~1KB each), API Gateway REST (~800 requests/mo),
CloudWatch Logs (0.5GB ingested/mo), S3 (CA cert + CRL, negligible size).

| Component | Monthly cost |
|---|---|
| KMS (1 CMK + sign requests) | ~$1.03 |
| Lambda | ~$0.00 (within free tier) |
| DynamoDB (on-demand) | ~$0.01 |
| API Gateway (REST) | ~$0.003 |
| CloudWatch Logs | ~$0.21 |
| S3 | <$0.01 |
| **Total (2000 users)** | **~$1.25/mo** |

**vs. ACM Private CA:** $400/month **flat fee**, regardless of user count, plus
per-certificate issuance charges on top. At 2000 users that's **$400+/mo vs.
~$1.25/mo** — a **>99.6% reduction**, or **~$4,785/year saved**.

This scales sub-linearly: going from 2000 to 10,000 users mostly just adds
DynamoDB/Lambda/API Gateway request volume (all still deep in free-tier or
fractions-of-a-cent territory) — KMS's flat $1/mo key fee doesn't change at
all, since it's one key regardless of how many certificates it signs.

Build your own estimate the same way: [central-ca/central-ca-stack.yml](central-ca/central-ca-stack.yml)'s
resource list maps 1:1 to calculator line items (1× KMS asymmetric CMK,
Lambda, DynamoDB on-demand, API Gateway REST, CloudWatch Logs) — plug in your
own volume assumptions at [calculator.aws](https://calculator.aws).

---

## Testing & Verification

Both paths include ready-to-run test scripts. After onboarding:

```bash
cd client-alice
./test-credentials.sh        # Fetches temp creds, runs sts:GetCallerIdentity + s3:ListBuckets
./get-credentials.sh         # Outputs raw credential JSON for use in scripts
```

Manually verify certificates:
```bash
openssl x509 -in bob-certificate.pem -text -noout          # Inspect cert
openssl verify -CAfile ca-certificate.pem bob-certificate.pem  # Verify chain
```

---

## Security Considerations

✅ **What's secure:**
- CA private key never exported (Local CA: on encrypted laptop, Central CA: in KMS only)
- Temporary credentials (not permanent access keys)
- Certificate CN validated server-side (never trusts client-supplied identity)
- Public endpoint requires shared secret (API key), enforced by API Gateway before Lambda runs
- Renewal admin-only (serial number alone isn't proof of key possession)
- Revocation immediate (CRL-based rejection by AWS)

⚠️ **What you're responsible for:**
- Protect the **root CA private key** (Local CA: encrypt your laptop, Central CA: KMS permissions)
- Protect the **shared API key** (if using public endpoint) — rotate if leaked
- Rotate **certificate CNs** (identity) regularly (use renewal, then revoke old)
- Monitor **DynamoDB revocation audit trail** (see who was revoked and when)
- Restrict **CloudFormation update permissions** (who can change CA validity, session duration, policies)

See [SECURITY.md](SECURITY.md) for detailed threat model and mitigations.

---

## Repository Structure

```
.
├── README.md                       ← You are here
├── SECURITY.md                     ← Threat model & best practices
├── CLAUDE.md                       ← Project context (for Claude Code)
├── LICENSE
│
├── local-ca/                       ← Laptop-local OpenSSL CA
│   ├── README.md
│   ├── local-ca-stack.yml          ← CloudFormation (Trust Anchor + Role + Profile)
│   ├── setup-ca.sh                 ← Create Root CA (one-time)
│   ├── setup-client.sh             ← Issue client certificate
│   ├── .gitignore                  ← Protects ./ca/ and ./client-*/ from git
│   └── [generated at runtime]
│       ├── ca/
│       │   ├── ca-private-key.pem  ← KEEP SECRET
│       │   └── ca-certificate.pem
│       └── client-alice/
│           ├── alice-private-key.pem
│           ├── alice-certificate.pem
│           ├── aws_signing_helper   ← AWS's credential_process binary
│           ├── get-credentials.sh
│           └── test-credentials.sh
│
├── central-ca/                     ← KMS-backed CA (production)
│   ├── README.md
│   ├── central-ca-stack.yml        ← CloudFormation (everything auto-bootstraps)
│   ├── request-cert.sh             ← Onboard users (admin or public endpoint)
│   ├── lambda/
│   │   ├── handler.py              ← Lambda (bootstrap, sign, renew, revoke, crl, rotate_ca)
│   │   └── kms_ca.py               ← Hand-rolled X.509/DER encoder, KMS signing
│   └── [generated at runtime]
│       └── client-bob/
│           ├── bob-private-key.pem
│           ├── bob-certificate.pem
│           ├── aws_signing_helper
│           ├── get-credentials.sh
│           └── test-credentials.sh
│
└── deploy.sh                       ← Convenience wrapper (optional, local CA only)
```

---

## Contributing

This is a **production-ready, tested project**. Contributions are welcome — open a PR with:
- Clear description of the change (feature, bug fix, security improvement)
- Tests (unit tests for crypto, integration tests for CloudFormation)
- Documentation updates
- No direct commits to `main` (branch protection enabled)

It's open source specifically so it can be useful beyond just my own setup — if you hit a bug, have a suggestion, or run into something that doesn't fit your environment, open an issue and let me know. I'll work on it. The goal is for this to hold up for anyone who needs it, not just the exact use case I originally built it for.

**Development workflow:**
```bash
git checkout -b feature/your-feature
# Make changes, commit, push
git push -u origin feature/your-feature
# Open a PR on GitHub
```

---

## Troubleshooting

### "Access Denied" when invoking Lambda (admin path)

Ensure your AWS CLI is authenticated to the **correct account**:
```bash
aws sts get-caller-identity                   # Should show your account ID
aws lambda invoke --function-name ... /dev/null  # Should work
```

### "API key invalid" on public endpoint

API Gateway rejects requests without the correct `x-api-key` header. Confirm:
```bash
curl -v -X POST "https://api.../issue" \
  -H "x-api-key: YOUR_KEY" \
  -H "Content-Type: application/json" \
  -d '...'
# Should NOT return 403 Forbidden before the Lambda runs
```

### Certificate verification fails with "unable to get local issuer certificate"

The Trust Anchor must match the CA cert that signed the client cert. Regenerating the CA without updating the Trust Anchor will break all existing certs. Use **certificate renewal** instead (reissue with the same CA, old cert revoked).

---

## FAQ

**Q: Can I use this with Kubernetes / Docker / ECS?**  
A: Yes. Mount the private key + certificate as secrets, use `aws_signing_helper` as the `credential_process` in a container's AWS CLI config.

**Q: What if I lose the root CA private key (Local CA)?**  
A: Permanently lost — all existing certs become invalid. Regenerate the CA (new Trust Anchor) and reissue all certificates. This is why I recommend Central CA (KMS) for production.

**Q: Can I export the KMS key to use it elsewhere (Central CA)?**  
A: No — KMS asymmetric keys are un-extractable by design. Signing only happens via `kms:Sign`. This is the security boundary.

**Q: Who can delete the CA's KMS key (Central CA)?**  
A: By default, only the literal AWS account **root** login — every IAM role or user is blocked regardless of its own permissions, even `AdministratorAccess`. Stack deletion never touches it either way (`DeletionPolicy: Retain`). See [SECURITY.md](SECURITY.md) for the full picture.

**Q: I revoked someone by mistake — can I undo it?**  
A: Not if you used `revoke` — that's permanent by design, and the fix is issuing them a fresh certificate. If you only wanted a temporary block (a contractor between engagements, someone on leave), use `disable` instead of `revoke` next time — it's reversible via `enable`, restoring the exact same certificate. See [central-ca/README.md](central-ca/README.md) for both.

**Q: How many users can this scale to?**  
A: Local CA: 1–10 (laptop performance/backup burden). Central CA: 1000s (DynamoDB on-demand, Lambda auto-scaling, API Gateway auto-scaling).

**Q: Can I use this with Terraform / CDK instead of CloudFormation console?**  
A: Yes — both templates are valid CloudFormation. Use `terraform`, `cdk`, or AWS CLI `aws cloudformation create-stack`.

---

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for release history and what's new in each version.

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

## Support & Contact

- **Documentation:** See [central-ca/README.md](central-ca/README.md) for deep dives
- **Issues:** Open a GitHub issue
- **Security concerns:** Email vireshsolanki1157@gmail.com

---

**Last tested:** July 2026  
**Tested on:** AWS region ap-south-1, CloudFormation, KMS, Lambda, DynamoDB, API Gateway, IAM Roles Anywhere  
**Status:** ✅ Production Ready
