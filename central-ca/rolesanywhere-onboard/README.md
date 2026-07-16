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

That's the whole tool. It needs **no AWS credentials, no `aws` CLI, and no AWS
account** — just the endpoint URL and API key your admin gives you.

Issuing a certificate is the only thing the CA's public endpoint allows.
Revoking, renewing, suspending, and rotating the CA are admin-only actions
gated behind real AWS IAM credentials — deliberately not reachable with an API
key, and so deliberately not in this tool. Ask your admin for those.

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

### Renewing before your certificate expires

Just run the exact same command again:

```bash
iamroles --url <ApiEndpoint> --secret <ApiKeyValue> --name alice \
    --trust-anchor-arn <arn> --profile-arn <arn> --role-arn <arn> --days 365
```

You get a fresh keypair and a fresh certificate, written over the old ones at
the same paths, so your AWS profile picks them up automatically with no config
changes — the profile write is a no-op in this case, not an error.

Two things worth knowing:

- **Your old certificate is not revoked.** It stays valid until it expires on
  its own, so for a while you have two working certificates. If your old key
  was actually compromised, don't self-renew — ask an admin to revoke it, which
  is enforced within seconds.
- **Renew before you expire, not after.** There's no grace period; an expired
  certificate stops working and you'd just be onboarding fresh anyway.

## As a library

```python
from rolesanywhere_onboard import request_certificate, get_credentials

result = request_certificate(url="...", secret="...", name="alice", days=365)
creds = get_credentials(result.cert_path, result.key_path,
                         trust_anchor_arn, profile_arn, role_arn)
# {"AccessKeyId": ..., "SecretAccessKey": ..., "SessionToken": ..., "Expiration": ...}
```

## Requirements

- Python 3.8+
- Nothing else. No `aws` CLI, no `openssl` binary, no AWS account. The only
  dependency is `cryptography` (pulled in automatically by pip), used for
  local keypair generation — Python's standard library has no asymmetric
  keygen of its own.

Linux, macOS (Intel + Apple Silicon), and Windows are all supported.

## License

MIT
