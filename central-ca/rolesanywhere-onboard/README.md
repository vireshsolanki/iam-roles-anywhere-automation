# rolesanywhere-onboard

Plug-and-play client for onboarding users against a self-hosted [IAM Roles Anywhere Central CA](https://github.com/vireshsolanki/iam-roles-anywhere-automation).

Cross-platform (Linux, macOS, Windows) — the only non-stdlib dependency is
[`cryptography`](https://pypi.org/project/cryptography/) for local RSA
keypair generation (Python has no built-in asymmetric crypto, and this
avoids depending on a system `openssl` binary, which Windows doesn't ship
by default).

## Install

```bash
pip install rolesanywhere-onboard
```

The installed command is **`iamroles`** (shorter than the package name):

## CLI

```bash
iamroles --url <ApiEndpoint> --secret <ApiKeyValue> --name alice \
    --trust-anchor-arn <arn> --profile-arn <arn> --role-arn <arn> --days 365
```

Admin mode (uses your own AWS credentials instead of a shared API key):
```bash
iamroles --lambda <IssuerFunctionName> --name alice \
    --trust-anchor-arn <arn> --profile-arn <arn> --role-arn <arn>
```

### The AWS profile it creates

By default this writes the **`default`** profile to `~/.aws/config`, so
afterwards plain `aws s3 ls` just works — no `--profile` flag needed:

```bash
aws sts get-caller-identity
aws s3 ls s3://your-bucket
```

If you already have a `default` profile (e.g. from `aws configure`), it will
**not** overwrite it — you'll get an error telling you to pick a name instead:

```bash
iamroles --name alice --aws-profile-name alice-ca ...   # -> aws s3 ls --profile alice-ca
```

Skip AWS profile setup entirely with `--no-aws-profile`.

## As a library

```python
from rolesanywhere_onboard import request_certificate, get_credentials

result = request_certificate(url="...", secret="...", name="alice", days=365)
creds = get_credentials(result.cert_path, result.key_path,
                         trust_anchor_arn, profile_arn, role_arn)
# {"AccessKeyId": ..., "SecretAccessKey": ..., "SessionToken": ..., "Expiration": ...}
```

## Requirements

- Python 3.13+
- The `aws` CLI, but *only* if using `--lambda` (admin) mode — the public
  `--url`/`--secret` mode needs no AWS credentials or tooling at all.

## License

MIT
