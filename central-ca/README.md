# Central CA (KMS + Lambda)

A **central** Certificate Authority for IAM Roles Anywhere where the CA private
key lives in **AWS KMS** and never touches a laptop or server, and where **no
long-lived AWS access keys** are used anywhere. You issue new user certificates
on demand by invoking a Lambda with your normal (SSO / role) credentials — so
onboarding 2000+ users is just an authorized call, and losing a laptop loses
nothing.

**One flat CloudFormation stack gets you the core pipeline** — KMS CA key →
issuer Lambda → auto-bootstrapped Root CA cert → Roles Anywhere Trust Anchor.
One file, one deploy, no nesting, no zip file in the repo, no manual
copy-pasting the CA cert anywhere. IAM Roles + Roles Anywhere Profiles are
**deliberately not** part of this stack — see "Giving a different user a
different policy" below for why, and how to create them.

The scalable alternative to the laptop-local OpenSSL CA in the parent directory
(`../local-ca-stack.yml`). Still no ACM Private CA, still ~$0 (KMS key ≈
$1/mo; Lambda + DynamoDB + S3 are pennies at this volume).

## Design choices

- **CA key in KMS** — the Lambda calls `kms:Sign`; the private key is
  un-extractable and never leaves AWS.
- **No static keys** — issuance is `aws lambda invoke`, which uses the default
  credential chain (SSO / IAM role). The IAM permission to invoke the function
  *is* the issuance access control. There is no API Gateway and nothing that
  reads an access-key/secret.
- **One flat stack, no zip file anywhere** — [central-ca-stack.yml](central-ca-stack.yml)
  is the only template in this directory and the only thing you deploy. The
  Lambda is 100% Python standard library (a hand-rolled DER encoder in
  [lambda/kms_ca.py](lambda/kms_ca.py)), so there's nothing to `pip install`.
  Its combined source (~16KB) is too big to inline directly (CloudFormation
  caps inline Lambda code at 4096 characters), so a tiny (~1.3KB) inline
  "fetcher" Lambda downloads `handler.py` and `kms_ca.py` as plain source from
  your GitHub repo, **zips them in-memory**, and uploads that zip to S3 before
  the real issuer Lambda is created — no `.zip` file is ever committed to the
  repo, and there's no second stack to look at.
- **Clients send a public key, not a CSR** — the user generates their keypair
  locally with `openssl` and sends only the public key; the private key never
  leaves their machine.

## Architecture

```
  New user (their own machine)
    │  1. openssl genrsa + openssl rsa -pubout   (private key stays local)
    │  2. aws lambda invoke  (your SSO/role creds — no static keys)
    ▼
  Lambda (issuer)
    │  sign the cert digest with ↓
    ▼
  KMS asymmetric key  ← the CA private key (un-extractable)
    │
    ├─►  DynamoDB   (index of EVERY cert ever issued: serial, CN, status,
    │                issued_at, not_after, renewed_from — the single
    │                source of truth for the whole CA)
    └─►  S3         (ca-certificate.pem, crl.pem)
                        │
                        ▼
          Roles Anywhere Trust Anchor  (trusts the CA cert — wired directly to
                                         CABootstrap's output, no copy-paste;
                                         created ONCE, reused by every Role/
                                         Profile you create manually)
          Roles Anywhere CRL           (rejects revoked certs)
```

Five actions, one Lambda ([lambda/handler.py](lambda/handler.py)):

| Action | Who | Purpose |
|---|---|---|
| `bootstrap` | admin | Create the self-signed Root CA cert from the KMS key (once, on stack deploy). |
| `sign` | admin, or a dev via the public endpoint | Sign a user public key → client certificate. |
| `renew` | admin only | Issue a fresh cert for an existing identity, revoke the old one. |
| `revoke` | admin, or a dev via the public endpoint | Mark a serial revoked in DynamoDB. |
| `crl` | admin / schedule | Regenerate the CRL from revoked entries. |

## Stack layout

```
central-ca-stack.yml                    (you deploy this — the only file, the only step)
  │
  ├─ ArtifactBucket                      S3: fetched code, ca-certificate.pem, crl.pem
  ├─ FetcherFunction (inline, ~1.3KB)    downloads handler.py + kms_ca.py, zips in-memory
  ├─ FetchZip                            builds lambda-code.zip from plain GitHub source
  ├─ CAKey / CAKeyAlias (KMS)            the CA private key — never exportable
  ├─ CertTable (DynamoDB)                index of every issued certificate
  ├─ CALambda                            the issuer, built from the in-memory zip
  ├─ CALambdaUrl + permission            public HTTPS endpoint (shared-secret auth)
  ├─ CABootstrap                         auto-creates the Root CA cert on deploy
  └─ TrustAnchor                         X509CertificateData: !GetAtt CABootstrap.CACertificate

  (no IAM Role, no Roles Anywhere Profile here — created manually per user/tier,
   see "Giving a different user a different policy" below)
```

## Deploy (AWS Console, one stack, no manual upload)

**Prerequisite (one time):** push this repo to GitHub — `lambda/handler.py` and
`lambda/kms_ca.py` contain no secrets (access to the CA key is controlled by
IAM, not by anything in the code), so it's safe to host publicly as plain
source. No build step, no zip to create — just commit and push the `.py` files.
```bash
git init && git add -A && git commit -m "central CA"
git remote add origin https://github.com/vireshsolanki/iam-roles-anywhere-automation.git
git push -u origin main
```

`central-ca-stack.yml`'s parameter defaults already point at your repo
(`vireshsolanki/iam-roles-anywhere-automation`, branch `main`) — adjust
`HandlerSourceUrl` / `KmsCaSourceUrl` at deploy time if your branch name differs.

**Deploy:**
1. **CloudFormation console** → **Create stack** → **With new resources** →
   upload `central-ca/central-ca-stack.yml` → **Next**.
2. **Stack name:** `central-ca`.
3. **Parameters:** leave at defaults, or override `ProjectName`, `CACommonName`,
   `CACertValidityDays` (how long the Root CA cert itself lasts — default 3650
   = 10 years, the max this stack allows), and set `ApiSecret` (required, no
   default — generate one with `openssl rand -hex 20`).
4. ✅ acknowledge IAM resource creation → **Submit**.
5. Wait for **CREATE_COMPLETE** (~1–2 min, one flat stack, no nesting).
   Everything happens automatically: fetch the code, create the CA infra,
   bootstrap the Root CA cert, and register it as the Roles Anywhere Trust
   Anchor. (No Role/Profile yet — that's the next, deliberately manual, step.)
6. Open the **Outputs** tab → `CACertificatePem`, `TrustAnchorArn`, `FunctionUrl`.

Verify the CA cert before trusting client certs it signs (paste `CACertificatePem` into a file first):
```bash
openssl x509 -in ca-certificate.pem -text -noout
openssl verify -CAfile ca-certificate.pem ca-certificate.pem   # self-signature check
```

**Updating the Lambda code later:** push new code to GitHub, then update the
`central-ca` stack with a bumped `CodeVersion` parameter (`v1` → `v2`) — that
forces the fetch to re-run and the Lambda to update. `CABootstrap` is
idempotent, so updates never regenerate or invalidate the existing CA cert.

> The separate **local-CA** path (laptop-local OpenSSL CA, `./setup-ca.sh` +
> `./setup-client.sh`) uses [`../local-ca-stack.yml`](../local-ca-stack.yml)
> instead — it's an independent stack, not something you deploy here.

## Onboard a user — two ways, depending on whether the user has AWS credentials

Both ways sign the same certificate the same way; they only differ in *how the
sign request reaches the CA*.

### A. Admin-run (`aws lambda invoke`, IAM-authenticated)

You (the admin) run this yourself, using your own AWS credentials, then hand
the result to the user. The user never touches AWS.
1. **Lambda console** → `CentralCA-issuer` → **Test** tab → new event:
   ```json
   { "action": "sign", "common_name": "alice", "public_key": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n", "days": 365 }
   ```
2. **Test** → copy the `"certificate"` field from the response → that's
   `alice-certificate.pem`. Send it back to Alice along with `TrustAnchorArn`
   (from the `central-ca` stack's Outputs) and the **Profile ARN / Role ARN**
   you created for her in "Giving a different user a different policy" below.

### B. Public endpoint (HTTPS + shared secret, NO AWS credentials needed)

For a developer who has **zero AWS access** — no IAM user, no console login —
give them the `FunctionUrl` output and the `ApiSecret` you set at deploy time.
They call it directly with `curl`:
```bash
curl -X POST "<FunctionUrl>" \
  -H "Content-Type: application/json" \
  -H "x-api-key: <ApiSecret>" \
  -d '{"action":"sign","common_name":"alice","public_key":"<their public key>","days":30}'
```
The response body has the same shape either way: `{"serial": "...", "certificate": "..."}`.

**Only `sign` and `revoke` are reachable this way** — `bootstrap` and `crl`
always return 403 over the public endpoint, even with a correct secret, since
those are admin-only operations a dev has no reason to trigger. Auth is a
single shared secret checked inside the Lambda (`hmac.compare_digest` against
the `x-api-key` header) — everyone you give the secret to can request/revoke
certificates, so **rotate it** (update the stack with a new `ApiSecret` value)
if it ever leaks, and only share it with people you're actively onboarding.

(`request-cert.sh` automates both paths — see "Automating onboarding" below.)

## Giving a different user a different policy (GUI, manual — by design)

`central-ca-stack.yml` creates **no** IAM Role and **no** Roles Anywhere
Profile — not even a default one. This CA setup is for **testing**, and every
real user or team tends to need a genuinely different, specific policy (not a
generic "tier" a template can guess at). A Role/Profile baked into
CloudFormation is also exactly the kind of resource someone eventually hand-edits
via console (adding a role, tweaking a duration) — the moment that happens,
CloudFormation reports **drift** on that resource. Keeping Roles/Profiles out
of the template entirely means there's nothing to drift. Every Role + Profile,
including your very first one, is a manual console step, same CA, same Trust
Anchor:

1. **IAM console** → **Roles** → **Create role**.
2. **Trusted entity type:** Custom trust policy. Paste:
   ```json
   {
     "Version": "2012-10-17",
     "Statement": [{
       "Effect": "Allow",
       "Principal": { "Service": "rolesanywhere.amazonaws.com" },
       "Action": ["sts:AssumeRole", "sts:TagSession", "sts:SetSourceIdentity"],
       "Condition": {
         "ArnEquals": { "aws:SourceArn": "<TrustAnchorArn from central-ca-stack Outputs>" }
       }
     }]
   }
   ```
   Optional but recommended — restrict this role to only the intended
   certificate(s) by adding a CN check to the same `Condition` block:
   ```json
         "StringEquals": { "aws:PrincipalTag/x509Subject/CN": "alice" }
   ```
   (Use a list `["alice", "bob"]` for a group that shares this role.) Without
   this, *any* certificate signed by your CA can assume this role — fine for
   solo testing, not fine once you have users you don't fully trust with each
   other's access.
3. **Permissions:** attach whatever policy this user actually needs — a
   managed policy (`AmazonS3FullAccess`, etc.) or a hand-written inline policy
   scoped to exactly their resources. This is the step a generic template
   can't do for you.
4. **Role name:** something identifying, e.g. `Alice-AccessRole` → **Create role**.
5. **IAM Roles Anywhere console** → **Profiles** → **Create profile**.
   - **Name:** e.g. `Alice-Profile`
   - **Roles:** select the role you just created
   - **Session duration:** as needed, **per this dev/tier** (900–43200 seconds)
     — this is the per-dev session control: each Profile has its own max
     duration, so a contractor can get a short-lived Profile (e.g. 900s) while
     a trusted internal service gets the full 43200s, independently of every
     other Profile.
   - **Create profile**
6. Copy the new **Role ARN** and **Profile ARN**. Give the user:
   - the same `TrustAnchorArn` as everyone else (one CA, shared)
   - their own **Profile ARN** and **Role ARN** from steps 4–5

Each user's `aws_signing_helper` call just points at their specific
Profile/Role ARN instead of anyone else's — the certificate itself doesn't
encode permissions or session length, the Role and Profile do.

## Automating onboarding

`request-cert.sh` runs the entire user-side pipeline in one command — keygen,
signing, and (if you pass the Trust Anchor/Profile/Role ARNs) downloading
`aws_signing_helper` and generating ready-to-run `get-credentials.sh` /
`test-credentials.sh` wrapper scripts, same as the local-CA path's
`setup-client.sh`. Two modes, matching the two onboarding paths above — pick one:

```bash
# Admin mode (you run this, using your own AWS credentials):
./request-cert.sh \
  --lambda CentralCA-issuer \
  --name alice \
  --trust-anchor-arn <TrustAnchorArn> \
  --profile-arn <ProfileArn> \
  --role-arn <RoleArn> \
  --days 365

# Dev mode (the developer runs this themselves — NO AWS credentials needed,
# just the FunctionUrl + ApiSecret you gave them):
./request-cert.sh \
  --url <FunctionUrl> \
  --secret <ApiSecret> \
  --name alice \
  --trust-anchor-arn <TrustAnchorArn> \
  --profile-arn <ProfileArn> \
  --role-arn <RoleArn> \
  --days 365
```

Either way, produces `client-alice/` with the private key, certificate,
signing helper binary, and both wrapper scripts. Run `cd client-alice &&
./test-credentials.sh` and you're done — that's keygen → sign → verify → live
credentials in one call. Omit the three ARN flags to only issue the
certificate (useful when you're using the "different policy per user" flow
above and want to plug in that user's specific Profile/Role ARN yourself).

## Renew a certificate (admin-only)

Before or after a certificate expires, issue the same identity a fresh one —
same `common_name`, new keypair, new serial, and the old serial gets revoked
automatically so exactly one certificate is ever valid per identity:

```bash
./request-cert.sh \
  --lambda CentralCA-issuer \
  --name alice \
  --renew <alice's old serial> \
  --trust-anchor-arn <TrustAnchorArn> \
  --profile-arn <ProfileArn> \
  --role-arn <RoleArn> \
  --days 365
```

Renewal is **admin-only** — it is never reachable over the public Function
URL, even with a correct `ApiSecret`. Knowing a serial number isn't proof you
hold the corresponding private key, so self-service renewal isn't safe without
a stronger check than this endpoint does; the admin verifying the person's
identity out-of-band before renewing is the actual security boundary here,
same as initial onboarding.

## Revoke a user

**Lambda console** → `CentralCA-issuer` → **Test** → new events:
```json
{ "action": "revoke", "serial": "<their serial>" }
```
then
```json
{ "action": "crl", "days": 7 }
```
Then point a `AWS::RolesAnywhere::CRL` resource at the regenerated
`s3://<artifact-bucket>/crl.pem` so AWS enforces the revocation.

Or over the public endpoint (dev self-revoking their own cert, if you want to
allow that): `POST` the same JSON body with the `x-api-key` header to
`FunctionUrl` — `revoke` is one of the two actions available there.

## Per-user permissions (2000 users, one role)

Don't create 2000 roles. Roles Anywhere exposes the cert's fields as session
tags — scope access in the IAM policy by the cert CN, e.g. give each user only
their own S3 prefix:

```json
{
  "Effect": "Allow",
  "Action": "s3:*",
  "Resource": "arn:aws:s3:::my-bucket/${aws:PrincipalTag/x509Subject/CN}/*"
}
```

One role, per-user isolation, driven entirely by the certificate identity.

## Verification status

The certificate/CRL encoding in `kms_ca.py` has been validated both locally
(building certs with the same algorithm KMS uses — RSASSA-PKCS1v1.5-SHA256 —
and confirming with OpenSSL) and against a **live deployment**:

- `openssl verify -CAfile ca.pem` → **CA self-verify OK**
- `openssl verify -CAfile ca.pem client.pem` → **client chains to CA OK**
- keyUsage / extKeyUsage / CRL all parse and verify correctly
- A real stack deploy produced a valid, correctly-structured, KMS-signed
  self-signed CA certificate (confirmed via `openssl x509 -text`)

Note: the CSR/public-key subject is set from the authenticated request, not
trusted from client input, so a caller cannot mint a cert for an identity they
weren't authorized for. Restrict who may run `sign`/`revoke` via the IAM policy
on `lambda:InvokeFunction` for the issuer function (admin path) — that is your
issuance access control there. For the public Function URL path, the `ApiSecret`
is the access control instead.

The `_url_handler` dispatch (secret validation, action allowlisting) has been
unit-tested locally: correct secret + `sign`/`revoke` succeed; wrong or missing
secret returns 403; `bootstrap`/`crl`/`renew` are rejected with 403 even with a
correct secret; the existing admin direct-invoke and CloudFormation
custom-resource paths are unaffected. Not yet exercised against a live
deployed `FunctionUrl` — do one real `curl` request after deploying to confirm
end-to-end.

The `renew` action has also been unit-tested locally (fake DynamoDB): renewing
an active serial issues a new cert for the same `common_name`, links it via
`renewed_from`, and revokes the old serial with `revoked_reason: "renewed"`;
renewing an already-revoked serial is rejected with a clear error; renewal is
confirmed blocked over the public Function URL even with a correct secret.
