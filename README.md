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
- **Renew** with automatic old-cert revocation (one valid cert per identity)
- **Revoke** immediately (CRL updated, AWS rejects within seconds)
- **Track everything** in DynamoDB (serial, CN, issued_at, revoked_reason, etc.)

### Zero-Trust Developer Onboarding

Central CA includes a **public HTTPS API Gateway endpoint** (shared secret auth, no AWS IAM required):
```bash
curl -X POST "https://api.example.com/issue" \
  -H "x-api-key: <shared-secret>" \
  -H "Content-Type: application/json" \
  -d '{"action":"sign", "common_name":"alice", "public_key":"...", "days":30}'
```
Developers **never touch AWS credentials**. Admin shares only the endpoint URL and API key.

### Cost Breakdown

| Component | Cost | Notes |
|-----------|------|-------|
| KMS (Central CA only) | ~$1/mo | Single asymmetric key, pay-per-use signing |
| Lambda | ~$0.20/mo | Rare invocations (issuance, renewal, revocation) |
| DynamoDB | ~$0.25/mo | On-demand (pay-per-request), 1 item per cert |
| S3 | <$0.01/mo | CA cert + CRL, tiny objects |
| **Total (Central CA)** | **~$1.50/mo** | vs. $400+/mo for ACM Private CA |
| **Total (Local CA)** | **~$0** | Only EC2/RDS costs if deployed there |

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
│   │   ├── handler.py              ← Lambda (bootstrap, sign, renew, revoke, crl)
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
A: Permanently lost — all existing certs become invalid. Regenerate the CA (new Trust Anchor) and reissue all certificates. This is why we recommend Central CA (KMS) for production.

**Q: Can I export the KMS key to use it elsewhere (Central CA)?**  
A: No — KMS asymmetric keys are un-extractable by design. Signing only happens via `kms:Sign`. This is the security boundary.

**Q: How many users can this scale to?**  
A: Local CA: 1–10 (laptop performance/backup burden). Central CA: 1000s (DynamoDB on-demand, Lambda auto-scaling, API Gateway auto-scaling).

**Q: Can I use this with Terraform / CDK instead of CloudFormation console?**  
A: Yes — both templates are valid CloudFormation. Use `terraform`, `cdk`, or AWS CLI `aws cloudformation create-stack`.

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
