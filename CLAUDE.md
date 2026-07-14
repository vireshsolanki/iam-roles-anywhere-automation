# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this project does

A proof-of-concept for AWS IAM Roles Anywhere using a **self-managed OpenSSL CA** instead of AWS ACM Private CA (which costs ~$400/month). External systems obtain temporary AWS credentials by presenting an X.509 client certificate signed by a local CA that is trusted by AWS.

## Prerequisites

- AWS CLI configured with permissions to deploy CloudFormation, create IAM roles, and manage IAM Roles Anywhere resources
- `openssl`
- `jq`
- `curl`

## Deployment flow

### Full end-to-end (recommended)

```bash
./deploy.sh [--stack-name <name>] [--project-name <name>] [--policy-arns <arns>] [--session-duration <seconds>] [--client-name <name>]
```

This runs all three steps in sequence: creates the CA → deploys CloudFormation → issues a client certificate.

### Step-by-step

**1. Create the local Root CA** (generates `./ca/ca-private-key.pem` and `./ca/ca-certificate.pem`):
```bash
./setup-ca.sh [validity_days]   # default: 3650 (10 years)
```
Re-running is a no-op if the CA already exists. To regenerate, delete `./ca/`.

**2. Deploy CloudFormation** (uses the CA cert as a CloudFormation parameter):
```bash
aws cloudformation deploy \
  --template-file local-ca-stack.yml \
  --stack-name iam-roles-anywhere-poc \
  --parameter-overrides \
    ProjectName=MyRolesAnywhere \
    CACertificateBody="$(cat ./ca/ca-certificate.pem)" \
    SessionDurationSeconds=3600 \
    IAMPolicyArns="arn:aws:iam::aws:policy/ReadOnlyAccess" \
  --capabilities CAPABILITY_NAMED_IAM
```

**3. Issue a client certificate** (requires ARNs from CloudFormation outputs):
```bash
./setup-client.sh \
  --trust-anchor-arn <TrustAnchorArn> \
  --profile-arn <ProfileArn> \
  --role-arn <RoleArn> \
  [--client-name <name>] \
  [--cert-validity <days>]   # default: 365, max: 3650
```

### Testing credentials

After setup, each client directory contains helper scripts:
```bash
cd client-<name>/
./test-credentials.sh    # fetches temp creds and calls sts:GetCallerIdentity + s3:ListBuckets
./get-credentials.sh     # raw credential-process output (JSON with AccessKeyId, SecretAccessKey, SessionToken)
```

## Architecture

Three CloudFormation resources form the trust chain:

```
Local OpenSSL CA (ca/ca-certificate.pem)
        │
        ▼
AWS::RolesAnywhere::TrustAnchor   ← trusts the CA cert
        │
        ▼
AWS::RolesAnywhere::Profile       ← binds allowed roles and session duration
        │
        ▼
AWS::IAM::Role                    ← the actual permissions granted to external systems
```

`setup-client.sh` downloads the `aws_signing_helper` binary from `rolesanywhere.amazonaws.com` and writes per-client wrapper scripts (`get-credentials.sh`, `test-credentials.sh`) into `./client-<name>/`. The helper implements the AWS `credential_process` protocol, so its output can be used directly with the AWS SDK or CLI.

## Key files generated at runtime

| Path | Description |
|---|---|
| `./ca/ca-private-key.pem` | Root CA private key — must be kept secret; losing it means no new client certs can be issued |
| `./ca/ca-certificate.pem` | Root CA certificate — uploaded to AWS as the Trust Anchor |
| `./client-<name>/` | Per-client directory with private key, certificate, signing helper binary, and helper scripts |

## Teardown

```bash
aws cloudformation delete-stack --stack-name iam-roles-anywhere-poc
```

The `./ca/` directory and `./client-*/` directories are local only and must be removed manually.
