# Changelog

All notable changes to this project are documented here. Format loosely follows
[Keep a Changelog](https://keepachangelog.com/en/1.0.0/); versioning follows
[Semantic Versioning](https://semver.org/).

## [1.1.0] — 2026-07-16

Adds a proper PyPI package for developer onboarding, hardens the artifact
bucket, and fixes several real bugs found by actually running v1.0.0 against
live AWS with a real developer.

### Added

- **`rolesanywhere-onboard` PyPI package** (`central-ca/rolesanywhere-onboard/`)
  — installs the **`iamroles`** command. A plug-and-play replacement for
  `request-cert.sh` for the developer-facing path, and genuinely
  cross-platform: **Linux, macOS, and Windows**, where the bash script was
  Unix-only.
  - **No `jq`, no `openssl` binary, no `aws` CLI, no AWS account.** JSON and
    HTTP are standard library; RSA keygen uses the `cryptography` package
    (Windows ships no `openssl`); the only pip dependency is `cryptography`.
  - Usable as a CLI *or* imported (`request_certificate`, `get_credentials`,
    `write_aws_profile`, `onboard`) for embedding in other Python code.
  - Developer-facing by design: issuance is the only action the CA's public
    endpoint exposes, so there is deliberately no `--lambda`/`--renew`. Devs
    self-renew by re-running the same command (a fresh `sign`). Admins keep
    `request-cert.sh` for revoke/renew/disable/rotate.
  - Writes the AWS **`default`** profile, so `aws s3 ls` works with no
    `--profile` flag. Overridable with `--aws-profile-name`; an existing
    `default` (e.g. from `aws configure`) is never clobbered.
- **S3 artifact bucket hardening** — versioning enabled (so
  `ca-certificate.pem`/`crl.pem` are recoverable rather than silently
  overwritten), a bucket policy denying any non-TLS request, and lifecycle
  rules expiring noncurrent versions after 3 days plus their delete markers.

### Fixed

- **`credential_process` paths were unquoted in `~/.aws/config`.** Any
  directory containing a space (hit in practice with `~/Desktop/AWS Access/`)
  produced `No such file or directory: '/home/user/Desktop/AWS'`, because the
  AWS CLI splits that line on whitespace. Now quoted in `request-cert.sh`, and
  built with `shlex.quote` in the package — correct by construction rather
  than by remembering to add quotes.
- **`--name` had no validation** in `request-cert.sh` — it becomes a directory
  path, so `--name ../../etc` would traverse out. Now restricted to
  `[A-Za-z0-9_.-]`.
- **`[profile default]` vs `[default]`** — AWS's config format uses a bare
  `[default]` for the default profile and `[profile x]` for named ones.
  Writing `[profile default]` produces a section the CLI silently does not
  treat as the default.
- **Re-running to renew reported a misleading error.** The renewal succeeded
  (new cert written to the same paths the profile already points at) but
  ended in `Profile 'default' already exists`, telling devs to fix something
  that wasn't broken. An identical re-run is now a no-op; only a genuine
  conflict raises.
- **`test-credentials.sh` treated a scoped-down role as a failure.** Its bare
  `aws s3 ls` needs account-wide `s3:ListAllMyBuckets`, which a correctly
  least-privilege role won't have. `AccessDenied` there means the policy is
  working; the step is now best-effort with that explained.
- Missing dependencies (`jq`, `curl`, `openssl`) now print the actual install
  command for the detected package manager instead of just naming the binary.

### Changed

- `request-cert.sh` prompts for the AWS profile name when `--aws-profile-name`
  is omitted, instead of silently picking one.

### Notes

- `rolesanywhere-onboard` **1.0.0 on PyPI was published from a stale build**
  and has been superseded by **1.1.0**. It carries the pre-rename
  `rolesanywhere-onboard` command rather than `iamroles`, so it is misleading
  rather than merely outdated — 1.0.0 is yanked; install 1.1.0 or later.

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
