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

### Where things are stored

Nothing is written relative to your current directory — it doesn't matter where
you run `iamroles` from:

```
~/.config/rolesanywhere/
├── bin/aws_signing_helper       ← one 17MB copy, shared by every identity
├── alice/
│   ├── alice-private-key.pem    ← never leaves this machine
│   └── alice-certificate.pem
└── bob/
    └── ...
```

**Don't move these directories.** The `credential_process` line in
`~/.aws/config` stores absolute paths, and it has to: the AWS CLI (and
`kubectl`, and every SDK) invokes it from whatever directory *they* happen to
be in, so a relative path would resolve somewhere unpredictable. Moving the
files breaks the profile with a confusing `[Errno 2] No such file or
directory`. If you must move them, update the paths in `~/.aws/config` to
match, or just re-run `iamroles`.

Override the location when you need to:

| | |
|---|---|
| `--out-dir PATH` | where this identity's key + cert go |
| `$IAMROLES_DIR` | base dir for everything (default `~/.config/rolesanywhere`) |
| `$IAMROLES_HELPER` | use an existing helper binary; skips the 17MB download |

A helper already on `PATH` is detected and reused automatically.

### Production / containers

**Most production containers should not install this package at all.**

`iamroles` is an *onboarding* tool — it mints a new keypair and certificate.
A long-running workload doesn't want that on every boot:

- It would need the **API key** in the container. That key can issue a
  certificate for *any* identity, not just this workload's — a far more
  dangerous secret than the certificate it would fetch.
- Every restart mints another certificate. New serial, new DynamoDB row,
  forever. Your audit table becomes a restart log.
- Downloading a 17MB binary at boot fights read-only root filesystems and
  adds an AWS dependency to your startup path.

**Issue the certificate once, mount it, and let the container use it.** The
container then needs three things, and none of them is this package:

```dockerfile
# 1. the signing helper binary
RUN curl -fsSL -o /usr/local/bin/aws_signing_helper \
      https://rolesanywhere.amazonaws.com/releases/1.4.0/X86_64/Linux/aws_signing_helper \
 && chmod +x /usr/local/bin/aws_signing_helper

# 2. an AWS config pointing at where the cert will be mounted
RUN mkdir -p /root/.aws && printf '%s\n' \
  '[default]' \
  'credential_process = /usr/local/bin/aws_signing_helper credential-process --certificate /etc/rolesanywhere/svc.pem --private-key /etc/rolesanywhere/svc-key.pem --trust-anchor-arn arn:aws:rolesanywhere:...:trust-anchor/... --profile-arn arn:aws:rolesanywhere:...:profile/... --role-arn arn:aws:iam::...:role/...' \
  > /root/.aws/config
```

```yaml
# 3. the cert + key, mounted as secrets at runtime — never baked into the image
volumes:
  - name: rolesanywhere-cert
    secret:
      secretName: svc-rolesanywhere-cert
      defaultMode: 0400
```

Your app then just calls AWS normally. The SDK runs `credential_process`,
gets short-lived credentials, and refreshes them automatically — no static
keys anywhere, and nothing in the image that could mint a new identity.

**When the env vars *do* matter:** if you genuinely want a container or CI job
to self-onboard (ephemeral runners, a bootstrap Job), then it does need this
package — and there, pin both locations so it doesn't depend on a home
directory that may not exist:

```dockerfile
ENV IAMROLES_DIR=/etc/rolesanywhere
ENV IAMROLES_HELPER=/usr/local/bin/aws_signing_helper
```
Pass `--non-interactive` so it never blocks on a prompt, and treat the API key
as the high-value secret it is.

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
