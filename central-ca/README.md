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
  un-extractable and never leaves AWS. The key resource itself has
  `DeletionPolicy`/`UpdateReplacePolicy: Retain`, so deleting or replacing
  this stack never deletes it as a side effect — actual key deletion is
  always a separate, deliberate action. By default, **only the literal AWS
  account root user** can ever call `kms:ScheduleKeyDeletion`/`DisableKey` on
  it — every IAM role/user is blocked regardless of its own permissions,
  since `aws:PrincipalArn` only equals the root ARN when authenticated as
  root itself. Set `KeyDeletionBreakGlassArn` to swap that one exception for
  a specific IAM principal instead, if requiring a root login is too
  inconvenient long-term. Either way, a mandatory 30-day waiting period
  applies to any scheduled deletion (reversible with `kms:CancelKeyDeletion`).
- **No static keys for admin issuance** — `aws lambda invoke` uses the
  default credential chain (SSO / IAM role). The IAM permission to invoke the
  function *is* the issuance access control there, and nothing reads an
  access-key/secret. (The separate public endpoint, for devs with no AWS
  credentials at all, is API Gateway + an API key — see "Onboard a user"
  below.)
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
| `revoke` | admin only | Mark a serial revoked in DynamoDB. |
| `crl` | admin only | Regenerate the CRL from revoked entries and register it with Roles Anywhere. |
| `rotate_ca` | admin only | Re-self-sign a fresh Root CA cert from the same KMS key, before `CACertValidityDays` expires. |

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
  ├─ CApi + Method/Deployment/Stage      API Gateway REST API (POST /issue)
  ├─ CApiKey + UsagePlan                 API-key auth for the public endpoint
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
   = 10 years, the max this stack allows; see "Rotate the Root CA" below for
   what to do as that approaches), and set `ApiKeyValue` (required, no
   default — the API Gateway API key devs will use; generate one with
   `openssl rand -hex 20`). By default the CA's KMS key can only ever be
   deleted by the literal AWS account root login — set
   `KeyDeletionBreakGlassArn` if you'd rather that one exception be a
   specific IAM principal instead of root (see "Design choices" above).
4. ✅ acknowledge IAM resource creation → **Submit**.
5. Wait for **CREATE_COMPLETE** (~1–2 min, one flat stack, no nesting).
   Everything happens automatically: fetch the code, create the CA infra,
   bootstrap the Root CA cert, register it as the Roles Anywhere Trust
   Anchor, and stand up the API Gateway endpoint. (No Role/Profile yet —
   that's the next, deliberately manual, step.)
6. Open the **Outputs** tab → `CACertificatePem`, `TrustAnchorArn`, `ApiEndpoint`.

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

### B. Public endpoint (API Gateway + API key, NO AWS credentials needed)

For a developer who has **zero AWS access** — no IAM user, no console login —
give them the `ApiEndpoint` output and the `ApiKeyValue` you set at deploy time.
They call it directly with `curl`:
```bash
curl -X POST "<ApiEndpoint>" \
  -H "Content-Type: application/json" \
  -H "x-api-key: <ApiKeyValue>" \
  -d '{"action":"sign","common_name":"alice","public_key":"<their public key>","days":30}'
```
The response body has the same shape as the admin path: `{"serial": "...", "certificate": "..."}`.

**Auth is handled by API Gateway, not the Lambda** — the `/issue` method
requires an API key, so API Gateway rejects any request without a valid
`x-api-key` *before* the Lambda runs. **`sign` is the only action reachable
this way** — `bootstrap`, `renew`, `revoke`, `crl`, and `rotate_ca` all
return 403 from inside the Lambda even with a valid key, since those are
admin-only. A dev can only ever request a certificate for themselves; they
can't revoke or reissue anything, theirs or anyone else's. Anyone with the
key can still request certificates under any `common_name` they like, so
**rotate it** (update the stack with a new `ApiKeyValue`) if it ever leaks,
and only share it with people you're actively
onboarding.

> **Why API Gateway and not a Lambda Function URL?** A Function URL with
> `AuthType: NONE` is the more obvious choice, but many AWS Organizations block
> public Function URLs with a Service Control Policy (you'll see a persistent
> `{"Message":"Forbidden"}` no matter how correct the resource policy is).
> Public API Gateway REST APIs are far more commonly allowed. If your org
> *also* blocks public API Gateway, fall back to admin-run issuance (path A) —
> that path never needs a public endpoint at all.

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
# just the ApiEndpoint + ApiKeyValue you gave them):
./request-cert.sh \
  --url <ApiEndpoint> \
  --secret <ApiKeyValue> \
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

**It also configures a long-term AWS CLI profile** — appends a
`credential_process` block to `~/.aws/config` named `<client-name>-central-ca`
(e.g. `alice-central-ca`), so once it's set up you don't need
`test-credentials.sh` at all:
```bash
aws sts get-caller-identity --profile alice-central-ca
aws s3 ls --profile alice-central-ca
```
The CLI re-invokes `aws_signing_helper` automatically whenever the cached
credentials near expiry — no manual refresh, works alongside any other
profiles already in that file. This step **only ever appends** a new
`[profile ...]` block; it never edits or overwrites an existing one (if a
profile with that name already exists, it warns and leaves the file
untouched). Override the name with `--aws-profile-name <name>`, or skip this
entirely with `--no-aws-profile`.

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

Renewal is **admin-only** — it is never reachable over the public API endpoint,
even with a valid API key. Knowing a serial number isn't proof you hold the
corresponding private key, so self-service renewal isn't safe without a stronger
check than this endpoint does; the admin verifying the person's identity
out-of-band before renewing is the actual security boundary here, same as
initial onboarding.

## Rotate the Root CA (before `CACertValidityDays` runs out)

`bootstrap` deliberately **refuses to overwrite** an existing CA certificate
(`"CA certificate already exists; refusing to overwrite"`) — that's what
makes stack updates safe (a template re-apply can never accidentally
regenerate the CA and invalidate every certificate you've issued). The
tradeoff: there is **no automatic renewal**. If you deployed with the default
`CACertValidityDays: 3650` (10 years), you must manually rotate it before
that cert expires, or every certificate this CA has ever signed stops
chaining to a trusted root simultaneously.

**Good news:** the underlying **KMS key never expires** — only the X.509
wrapper certificate around it does. `rotate_ca` self-signs a **fresh**
certificate from the **same** key:
```json
{ "action": "rotate_ca", "days": 3650 }
```
Because the public key is unchanged, every already-issued client certificate's
`AuthorityKeyIdentifier` (derived from the CA's public key, not from any
particular certificate object) still matches — existing certificates keep
validating once you point the Trust Anchor at the new one. The response's
`action_required` field spells out the one manual step left: update the Trust
Anchor's `X509CertificateData` to the new certificate (**IAM Roles Anywhere
console → Trust anchors → edit**, or a CloudFormation update). Nothing else
changes — same KMS key, same Roles Anywhere Profile/Role bindings, same
onboarded users.

`rotate_ca` is admin-only, same reasoning as `renew` — never reachable over
the public API endpoint.

## Revoke a user

**Lambda console** → `CentralCA-issuer` → **Test** → new events:
```json
{ "action": "revoke", "serial": "<their serial>" }
```
then
```json
{ "action": "crl", "days": 7 }
```
`revoke` marks the serial revoked in DynamoDB. `crl` does the part that
actually matters: it regenerates `crl.pem`, writes it to S3, **and registers
it with Roles Anywhere** — `rolesanywhere:ImportCrl` the first time this ever
runs on a stack, `rolesanywhere:UpdateCrl` on every call after (the Lambda
looks up your Trust Anchor by name and remembers the resulting `crlId` in
DynamoDB, so you never have to pass it yourself). That registration step is
what makes AWS actually reject the revoked certificate — writing `crl.pem` to
S3 by itself does nothing; Roles Anywhere only enforces a CRL it has been
explicitly told about via `ImportCrl`/`UpdateCrl`. The response includes a
`roles_anywhere_registration` field confirming `imported` or `updated` (or
`skipped` with a reason, if the Trust Anchor isn't found — re-run `crl` once
it exists).

`revoke` is **admin-only** — it is never reachable over the public API
endpoint, even with a valid API key. The public endpoint's only capability is
`sign`: a dev can request their own certificate there, but can't revoke or
reissue anything, theirs or anyone else's. Revocation always goes through the
admin path above (`revoke`, then `crl` to actually make AWS start rejecting
it).

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
issuance access control there. For the public path, the API Gateway **API key**
(`ApiKeyValue`) is the access control instead.

The `_http_handler` dispatch (action allowlisting) has been unit-tested locally
against a real API Gateway REST-proxy event shape: `sign` returns a
proxy-format `{statusCode, headers, body}` response; `revoke` (confirmed
separately as still working over admin direct-invoke) plus
`bootstrap`/`renew`/`crl`/`rotate_ca` are all rejected with 403 over HTTP even
though API Gateway would have accepted the key — a dev can obtain a
certificate through the public endpoint and nothing else; malformed JSON
returns 400; the existing admin direct-invoke path still returns raw dicts,
and the CloudFormation custom-resource path is unaffected.

**Newer, not yet exercised against live AWS:** the `rolesanywhere:ImportCrl`/
`UpdateCrl` registration inside `crl`, and `rotate_ca`. Both are unit-tested
locally against mocked `boto3` clients — confirmed: `crl` skips registration
gracefully with a clear reason when no Trust Anchor exists yet, correctly
`import`s on the first real registration and caches the returned `crlId` in
DynamoDB, correctly `update`s (not re-imports) on every call after; `rotate_ca`
bypasses the bootstrap guard, validates its `days` argument, and returns the
"update the Trust Anchor" instruction — but the exact request/response field
names for `ImportCrl`/`UpdateCrl` (`crlData`, `trustAnchorArn`, etc.) are typed
from the API's documented shape, not confirmed against a real call. First real
`{"action":"crl", ...}` after deploying this should be checked against
CloudWatch Logs for that Lambda to confirm the registration actually
succeeded, same as any other newly-added AWS integration in this repo.

**Deploy-endpoint note, learned the hard way:** an earlier version used a Lambda
Function URL with `AuthType: NONE` + a resource policy granting public
`InvokeFunctionUrl`. On the target account it returned a persistent
`{"Message":"Forbidden"}` regardless of the (verifiably correct) resource
policy — almost certainly an AWS Organizations SCP / Control Tower guardrail
blocking public Lambda Function URLs. Switching to an **API Gateway REST API
with an API key** sidesteps that class of guardrail (public REST APIs are far
more commonly permitted). If your org blocks *that* too, use admin-run
issuance (onboarding path A / `--lambda` mode), which needs no public endpoint.

The `renew` action has also been unit-tested locally (fake DynamoDB): renewing
an active serial issues a new cert for the same `common_name`, links it via
`renewed_from`, and revokes the old serial with `revoked_reason: "renewed"`;
renewing an already-revoked serial is rejected with a clear error; renewal is
confirmed blocked over the public API endpoint even with a valid API key.
