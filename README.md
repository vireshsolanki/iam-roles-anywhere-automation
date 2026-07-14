# IAM Roles Anywhere — Free CA (no ACM Private CA)

A proof-of-concept for **AWS IAM Roles Anywhere** using a self-managed CA
instead of AWS ACM Private CA (~$400/month). External systems and developers
get **temporary AWS credentials** by presenting an X.509 client certificate
signed by a CA that AWS is told to trust — no permanent access keys, anywhere.

Two ways to run the CA, depending on scale:

| | [Local CA](#local-ca-quick-start-single-admin) | [Central CA](#central-ca-quick-start-teams--many-users) |
|---|---|---|
| CA private key lives | Your laptop (`./ca/`) | AWS KMS (never exportable) |
| Good for | Solo use, quick POC | Teams, 10s–1000s of users, no laptop-loss risk |
| Deploy | Shell scripts + AWS CLI | AWS Console, CloudFormation only |
| Issuing a cert | `./setup-client.sh` | Lambda invoke (console or `aws lambda invoke`) |

Both produce the same thing AWS actually consumes: a CA certificate registered
as a Roles Anywhere **Trust Anchor**, and per-user client certificates signed
by that CA.

## How it works (either path)

```
Your CA (self-managed, not ACM Private CA)
        │
        ▼
AWS::RolesAnywhere::TrustAnchor   ← trusts your CA cert
        │
        ▼
AWS::RolesAnywhere::Profile       ← binds allowed IAM roles + session duration
        │
        ▼
AWS::IAM::Role                    ← the permissions granted to the caller
```

A client presents its certificate + proves possession of the matching private
key via the `aws_signing_helper` binary (AWS's `credential_process` helper),
and gets back temporary AWS credentials.

---

## Local CA quick start (single admin)

Requires: `openssl`, `jq`, `curl`, AWS CLI configured.

```bash
./deploy.sh   # creates the CA, deploys CloudFormation, issues one client cert
```
Or step by step — see [CLAUDE.md](CLAUDE.md) for `setup-ca.sh` / `cloudformation.yml`
/ `setup-client.sh` details. The CA private key (`./ca/ca-private-key.pem`)
stays on this machine — back it up, since losing it means no new certs can be issued.

## Central CA quick start (teams / many users)

The CA private key lives in **AWS KMS** (physically un-extractable) instead of
a laptop, so onboarding is a Lambda call, not a local script, and losing an
admin's laptop loses nothing. See **[central-ca/README.md](central-ca/README.md)**
for full details — deploy is a single CloudFormation stack
(`central-ca/code-stack.yml`) through the AWS Console, no CLI packaging, no
manual S3 upload.

```
central-ca/code-stack.yml   ← deploy this one stack
  └─ creates central-ca/infra-stack.yml automatically (nested)
       → KMS CA key, DynamoDB cert index, issuer Lambda, auto-bootstrapped CA cert
```

---

## Teardown

```bash
aws cloudformation delete-stack --stack-name iam-roles-anywhere-poc   # Trust Anchor / Profile / Role
aws cloudformation delete-stack --stack-name central-ca               # if using the central CA
```
`./ca/`, `./client-*/`, and KMS keys are not deleted automatically — KMS keys
have a mandatory 7–30 day deletion waiting period once scheduled.
