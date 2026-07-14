# Central CA (KMS + Lambda)

A **central** Certificate Authority for IAM Roles Anywhere where the CA private
key lives in **AWS KMS** and never touches a laptop or server, and where **no
long-lived AWS access keys** are used anywhere. You issue new user certificates
on demand by invoking a Lambda with your normal (SSO / role) credentials — so
onboarding 2000+ users is just an authorized call, and losing a laptop loses
nothing.

The scalable alternative to the laptop-local OpenSSL CA in the parent directory.
Still no ACM Private CA, still ~$0 (KMS key ≈ $1/mo; Lambda + DynamoDB + S3 are
pennies at this volume).

## Design choices

- **CA key in KMS** — the Lambda calls `kms:Sign`; the private key is
  un-extractable and never leaves AWS.
- **No static keys** — issuance is `aws lambda invoke`, which uses the default
  credential chain (SSO / IAM role). The IAM permission to invoke the function
  *is* the issuance access control. There is no API Gateway and nothing that
  reads an access-key/secret.
- **Deploy is pure CloudFormation, console-only, one stack, no manual upload** —
  the Lambda is 100% Python standard library (a hand-rolled DER encoder in
  [lambda/kms_ca.py](lambda/kms_ca.py)), so there's nothing to `pip install`.
  Its combined source (~16KB) is too big to inline in a template directly
  (CloudFormation caps inline Lambda code at 4096 characters). Two templates
  split the concerns:
  - **[code-stack.yml](code-stack.yml)** — the one you deploy by hand. A tiny
    (~1KB) inline "fetcher" Lambda downloads `lambda.zip` *and* the infra
    template body from your GitHub repo into S3 (nested-stack templates must
    be read from S3, not a plain URL), then creates...
  - **[infra-stack.yml](infra-stack.yml)** — the actual CA (KMS, DynamoDB, the
    issuer Lambda, auto-bootstrap) — automatically, as a **nested stack**. You
    never touch S3, never deploy this one directly.
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
    ├─►  DynamoDB   (index of every issued cert: serial, CN, status)
    └─►  S3         (ca-certificate.pem, crl.pem)
                        │
                        ▼
          Roles Anywhere Trust Anchor  (trusts the CA cert)
          Roles Anywhere CRL           (rejects revoked certs)
```

Four actions, one Lambda ([lambda/handler.py](lambda/handler.py)):

| Action | Who | Purpose |
|---|---|---|
| `bootstrap` | admin | Create the self-signed Root CA cert from the KMS key (once). |
| `sign` | authorized issuers | Sign a user public key → client certificate. |
| `revoke` | authorized issuers | Mark a serial revoked in DynamoDB. |
| `crl` | admin / schedule | Regenerate the CRL from revoked entries. |

## Stack layout

```
code-stack.yml                          (you deploy this — the only manual step)
  │
  ├─ CodeBucket                          S3 staging bucket
  ├─ FetcherFunction (inline, ~1KB)      generic "download URL → S3" Lambda
  ├─ FetchZip                            fetches lambda.zip from GitHub
  ├─ FetchInfraTemplate                  fetches infra-stack.yml from GitHub
  │                                       (nested-stack templates must live in S3)
  └─ InfraStack  ───────────────────►   infra-stack.yml (nested, auto-created)
                                           ├─ CAKey (KMS)
                                           ├─ CertTable (DynamoDB)
                                           ├─ ArtifactBucket (S3)
                                           ├─ CALambda (built from the fetched zip)
                                           └─ CABootstrap → Root CA cert, auto-created
```

`code-stack.yml`'s Outputs pass straight through from the nested stack (via
`!GetAtt InfraStack.Outputs.*`), so you only ever look in one place.

## Deploy (AWS Console, one stack, no manual upload)

**Prerequisite (one time):** push this repo to GitHub — `lambda/handler.py` and
`lambda/kms_ca.py` contain no secrets (access to the CA key is controlled by
IAM, not by anything in the code), so it's safe to host publicly.
```bash
git init && git add -A && git commit -m "central CA"
git remote add origin https://github.com/vireshsolanki/iam-roles-anywhere-automation.git
git push -u origin main
```
(Rebuild the zip after any code change: `cd central-ca/lambda && zip -j ../lambda.zip handler.py kms_ca.py`, then commit + push.)

`code-stack.yml`'s parameter defaults already point at your repo
(`vireshsolanki/iam-roles-anywhere-automation`, branch `main`) — adjust the
`CodeSourceUrl` / `InfraTemplateUrl` parameters at deploy time if your branch
name differs.

**Deploy:**
1. **CloudFormation console** → **Create stack** → **With new resources** →
   upload `central-ca/code-stack.yml` → **Next**.
2. **Stack name:** `central-ca`.
3. **Parameters:** leave at defaults (or override `ProjectName`, `CACommonName`, etc.).
4. ✅ acknowledge IAM resource creation → **Submit**.
5. Wait for **CREATE_COMPLETE** (~2–3 min — it's creating a nested stack).
   Everything happens automatically: fetch the code, fetch the infra template,
   create the CA infra, bootstrap the Root CA cert.
6. Open the **Outputs** tab → copy **`CACertificatePem`**.

Verify the CA cert before trusting it (paste it into a file first):
```bash
openssl x509 -in ca-certificate.pem -text -noout
```

Then register it as the Roles Anywhere **Trust Anchor**: CloudFormation console
→ Create stack → upload `../cloudformation.yml` → set `CACertificateBody` to
the pasted cert and `IAMPolicyArns` as needed → deploy. Its Outputs give you
`TrustAnchorArn` / `ProfileArn` / `RoleArn`.

**Updating the Lambda code later:** push new code/template to GitHub, then
update the `central-ca` stack with a bumped `CodeVersion` parameter (`v1` →
`v2`) — that forces both fetches to re-run and the nested stack to update.

## Onboard a user

The user generates their own key pair locally and sends you (the admin) only
the **public** key. You sign it via the Lambda console:
1. **Lambda console** → `CentralCA-issuer` → **Test** tab → new event:
   ```json
   { "action": "sign", "common_name": "alice", "public_key": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n", "days": 365 }
   ```
2. **Test** → copy the `"certificate"` field from the response → that's
   `alice-certificate.pem`. Send it back to Alice along with the
   `TrustAnchorArn` / `ProfileArn` / `RoleArn` from the Trust Anchor stack.

(`request-cert.sh` in this directory automates both sides via `aws lambda
invoke` if you'd rather script it than click through the console.)

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

The certificate/CRL encoding in `kms_ca.py` has been validated locally by
building certs with the same algorithm KMS uses (RSASSA-PKCS1v1.5-SHA256) and
confirming with OpenSSL:

- `openssl verify -CAfile ca.pem` → **CA self-verify OK**
- `openssl verify -CAfile ca.pem client.pem` → **client chains to CA OK**
- keyUsage / extKeyUsage / CRL all parse and verify correctly

The only untested difference in production is that signing happens in KMS rather
than with a local key. After the first deploy, run the same
`openssl x509 -text` / `openssl verify` checks on a real issued cert, then do one
Roles Anywhere credential fetch end-to-end before relying on it.

Note: the CSR/public-key subject is set from the authenticated request, not
trusted from client input, so a caller cannot mint a cert for an identity they
weren't authorized for. Restrict who may run `sign`/`revoke` via the IAM policy
on `lambda:InvokeFunction` for the issuer function — that is your issuance
access control.
```
