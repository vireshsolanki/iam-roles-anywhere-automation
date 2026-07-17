# iamroles

This is an **alias package**. It contains no code — it just installs
[`rolesanywhere-onboard`](https://pypi.org/project/rolesanywhere-onboard/),
which is where everything actually lives.

It exists because the command is called `iamroles`, so `pip install iamroles`
is what people naturally type. This makes that work, and claims the name so
nobody else can publish something else under it.

```bash
pip install iamroles
```

Either package name gets you the same `iamroles` command:

```bash
iamroles --url <ApiEndpoint> --secret <ApiKeyValue> --name alice \
    --trust-anchor-arn <arn> --profile-arn <arn> --role-arn <arn> --days 365
```

**Full documentation:**
[rolesanywhere-onboard](https://pypi.org/project/rolesanywhere-onboard/) ·
[GitHub](https://github.com/vireshsolanki/iam-roles-anywhere-automation)

## What it does

Onboards a developer against a self-hosted AWS IAM Roles Anywhere Certificate
Authority: generates an RSA keypair locally (the private key never leaves the
machine), requests a signed certificate over HTTPS, and writes an AWS CLI
profile backed by `aws_signing_helper` — so `aws s3 ls` just works, with
short-lived credentials and no static access keys anywhere.

Needs Python 3.8+ and nothing else. No AWS account, no `aws` CLI, no `openssl`.
Linux, macOS, and Windows.

## License

MIT
