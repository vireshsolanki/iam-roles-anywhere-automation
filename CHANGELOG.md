# Changelog

All notable changes to this project are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/en/1.0.0/); versioning follows
[Semantic Versioning](https://semver.org/).

## [1.0.0] — 2026-07-15

First public release. Two complete, independently deployable paths to AWS IAM
Roles Anywhere without paying for ACM Private CA (~$400/month minimum):
**Local CA** (laptop-held OpenSSL CA, solo/POC use) and **Central CA**
(AWS KMS-backed, production use, tested end-to-end against live AWS).

### Added — Local CA

- `setup-ca.sh` — one-time laptop-local OpenSSL Root CA creation
- `local-ca-stack.yml` — CloudFormation for Trust Anchor + IAM Role + Roles Anywhere Profile
- `setup-client.sh` — issues client certificates, downloads `aws_signing_helper`, generates `get-credentials.sh`/`test-credentials.sh` wrappers
- `deploy.sh` — end-to-end convenience wrapper (create CA → deploy stack → issue first cert)

### Added — Central CA (KMS-backed)

- **Single flat CloudFormation stack** (`central-ca-stack.yml`) — no nested stacks, no zip file committed to the repo. A tiny inline "fetcher" Lambda downloads `handler.py`/`kms_ca.py` as plain source from GitHub and zips them in-memory at deploy time.
- **Hand-rolled X.509/DER encoder** (`lambda/kms_ca.py`, ~240 lines, zero external dependencies) — auditable in full; all private-key operations go through `kms:Sign`, never extracted.
- **Auto-bootstrapped Root CA** on first stack deploy, idempotent on every update after (never accidentally regenerates and invalidates existing certificates).
- **Certificate issuance** (`sign`) — admin via `aws lambda invoke`, or a developer with **zero AWS credentials** via a public API Gateway endpoint (API key auth, issuance-only — see Security below).
- **Certificate renewal** (`renew`) — fresh cert + keypair for an existing identity; old serial automatically revoked and enforced in the same call.
- **Real revocation enforcement** (`revoke`) — one call marks the serial revoked in DynamoDB *and* publishes/registers the CRL with Roles Anywhere (`rolesanywhere:ImportCrl` the first time, `UpdateCrl` after) in the same step. Permanent; no action can ever reverse it.
- **Reversible suspension** (`disable`/`enable`) — temporarily block a certificate (contractor between engagements, planned leave) without the permanence of `revoke`. `enable` only ever works on a `disabled` serial, never a `revoked` one.
- **CRL as the single source of truth for enforcement** — every `revoke`/`disable`/`enable` republishes automatically; `crl` also available standalone for batch operations or periodic freshness-window refresh.
- **Root CA rotation** (`rotate_ca`) — re-self-signs a fresh certificate from the *same* KMS key before `CACertValidityDays` expires. Existing client certificates keep validating (same public key, same `AuthorityKeyIdentifier`) once the Trust Anchor is pointed at the new certificate.
- **DynamoDB as the complete audit trail** — every certificate's serial, common_name, status, issued_at, not_after, revoked_at/reason, disabled_at/reason, renewed_from.
- **Auto-configured AWS CLI profile** — `request-cert.sh` appends a `credential_process` block to `~/.aws/config` after issuing a certificate (additive-only, never touches existing profiles).
- **Idempotent CloudWatch log retention** — a custom resource creates-or-reuses log groups instead of the native `AWS::Logs::LogGroup` resource, which fails hard with "already exists" if Lambda already lazily created a default log group.

### Security

- **KMS key never exportable** — no `kms:GetPrivateKey` operation exists for asymmetric keys; only `Sign`/`Verify`/`GetPublicKey`.
- **KMS key deletion restricted to the literal AWS account root login by default** — every IAM role/user is blocked regardless of its own permissions, including `AdministratorAccess`. Optional `KeyDeletionBreakGlassArn` parameter to designate a different single principal instead. `DeletionPolicy`/`UpdateReplacePolicy: Retain` means stack deletion never touches the key either way — deletion is always a separate, deliberate action, with a mandatory 30-day cancelable waiting period regardless of who initiates it.
- **Public API endpoint is issuance-only** — `sign` is the *only* action reachable without AWS credentials. A developer can request their own certificate and nothing else; every other action (`revoke`, `disable`, `enable`, `renew`, `crl`, `rotate_ca`, `bootstrap`) requires admin IAM credentials via direct Lambda invoke.
- **API Gateway chosen over Lambda Function URLs** — a Function URL with `AuthType: NONE` and a verifiably-correct resource policy still returned a persistent `Forbidden` on a real account, traced to an AWS Organizations SCP blocking public Function URLs. API Gateway sidesteps that class of guardrail.
- **Certificate identity is never trusted from client input** — the subject CN is always set from the authenticated request server-side (admin path: IAM permission; public path: which action was called), never from anything the caller supplies.
- **IAM Roles and Roles Anywhere Profiles deliberately excluded from CloudFormation** — every Role/Profile is created manually per user/tier via the documented console runbook, specifically to avoid drift between a templated default and real-world per-user policy needs.

### Documentation

- Comprehensive root `README.md` — architecture, quick-start for both paths, cost breakdown (~$1.25–2.50/month for Central CA at 2000 users, verified via AWS Pricing Calculator), comparison against related AWS sample repos, terminology glossary (Role vs. Profile vs. Trust Anchor vs. AWS CLI profile — the most common source of confusion).
- `SECURITY.md` — threat model, incident response procedures, KMS key deletion/compromise scenarios, compliance/audit trail reference.
- `central-ca/README.md` — full deploy runbook, onboarding paths, renewal/revocation/suspension procedures, CA rotation runbook, verification status (what's tested locally vs. confirmed against live AWS).

### Known limitations

- The exact `rolesanywhere:ImportCrl`/`UpdateCrl` request field names are typed from documented API shapes; confirmed working against a real deployed stack, but the underlying AWS API contract should be treated as verified-in-practice rather than independently audited against AWS's source.
- No Terraform/CDK modules yet — CloudFormation only.
- No automated periodic CRL refresh (EventBridge schedule) — relies on `revoke`/`disable`/`enable` activity naturally keeping the CRL's freshness window current, or a manual periodic `crl` call for low-activity CAs.
