#!/usr/bin/env python3
"""
Plug-and-play client for onboarding a user against this project's Central CA
and setting them up with AWS credentials via IAM Roles Anywhere.

Needs only: Python 3.8+ and `openssl` on PATH (for local RSA keypair
generation -- Python's standard library has no built-in asymmetric keygen).
No `jq`, no pip install, nothing else -- JSON handling, HTTP, and the
resulting AWS CLI profile are all stdlib (json, urllib, subprocess, shlex).

Run directly:
    python3 onboard.py --url <ApiEndpoint> --secret <ApiKeyValue> --name alice \
        --trust-anchor-arn <arn> --profile-arn <arn> --role-arn <arn> [--days 365]

Or import what you need:
    from onboard import request_certificate, get_credentials

    result = request_certificate(url=..., secret=..., name="alice", days=365)
    creds = get_credentials(result.cert_path, result.key_path,
                             trust_anchor_arn, profile_arn, role_arn)
    # creds = {"AccessKeyId": ..., "SecretAccessKey": ..., "SessionToken": ..., "Expiration": ...}

Admin (--lambda) mode additionally needs the `aws` CLI on PATH -- unavoidable,
since it's a full AWS SDK, not something worth reimplementing here.
"""
from __future__ import annotations

import argparse
import json
import os
import platform
import re
import shlex
import stat
import subprocess
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

NAME_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
HELPER_VERSION_DEFAULT = "1.4.0"


class OnboardError(Exception):
    """Raised for any failure in this module -- callers catch this one type."""


def _check_name(name: str) -> None:
    # NAME becomes part of a directory path and a certificate common_name.
    # Restricting the character set closes off path traversal and means NAME
    # never needs individual shell-escaping downstream -- it can't contain
    # anything shell-meaningful in the first place.
    if not NAME_RE.match(name):
        raise OnboardError(
            f"Invalid name {name!r}: only letters, numbers, '.', '_', '-' allowed"
        )


def _run(cmd: list[str], **kwargs) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(cmd, check=True, capture_output=True, text=True, **kwargs)
    except FileNotFoundError:
        raise OnboardError(f"'{cmd[0]}' is not installed or not on PATH")
    except subprocess.CalledProcessError as exc:
        raise OnboardError(f"{cmd[0]} failed: {exc.stderr.strip() or exc.stdout.strip()}")


def generate_keypair(out_dir: Path, name: str) -> tuple[Path, Path]:
    """RSA-2048 keypair, private key left mode 600, never touches the network."""
    key_path = out_dir / f"{name}-private-key.pem"
    pub_path = out_dir / f"{name}-public-key.pem"
    _run(["openssl", "genrsa", "-out", str(key_path), "2048"])
    os.chmod(key_path, stat.S_IRUSR | stat.S_IWUSR)  # chmod 600
    _run(["openssl", "rsa", "-in", str(key_path), "-pubout", "-out", str(pub_path)])
    return key_path, pub_path


@dataclass
class CertResult:
    serial: str
    cert_path: Path
    key_path: Path
    out_dir: Path


def request_certificate(
    *,
    name: str,
    days: int = 365,
    url: str | None = None,
    secret: str | None = None,
    lambda_name: str | None = None,
    renew_serial: str | None = None,
    out_dir: str | Path | None = None,
) -> CertResult:
    """
    Issues a certificate for `name`, either over the public HTTPS endpoint
    (url + secret -- no AWS credentials needed) or via admin `aws lambda
    invoke` (lambda_name -- uses the caller's own AWS credentials, and is the
    only mode that supports renew_serial).
    """
    _check_name(name)
    if bool(url) != bool(secret):
        raise OnboardError("url and secret must be given together")
    if not url and not lambda_name:
        raise OnboardError("Provide either (url and secret) or lambda_name")
    if renew_serial and not lambda_name:
        raise OnboardError("Renewal is admin-only -- use lambda_name, not url/secret")

    out = Path(out_dir) if out_dir else Path(f"./client-{name}")
    out.mkdir(parents=True, exist_ok=True)
    key_path, pub_path = generate_keypair(out, name)
    public_key = pub_path.read_text()

    if renew_serial:
        payload = {"action": "renew", "serial": renew_serial, "public_key": public_key, "days": days}
    else:
        payload = {"action": "sign", "common_name": name, "public_key": public_key, "days": days}

    if lambda_name:
        response = _invoke_lambda(lambda_name, payload)
    else:
        response = _post_json(url, secret, payload)

    if "certificate" not in response:
        raise OnboardError(f"Signing failed: {response}")

    cert_path = out / f"{name}-certificate.pem"
    cert_path.write_text(response["certificate"])
    return CertResult(serial=str(response["serial"]), cert_path=cert_path, key_path=key_path, out_dir=out)


def _post_json(url: str, secret: str, payload: dict) -> dict:
    body = json.dumps(payload).encode()
    req = urllib.request.Request(
        url, data=body, method="POST",
        headers={"Content-Type": "application/json", "x-api-key": secret},
    )
    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return json.loads(exc.read())


def _invoke_lambda(function_name: str, payload: dict) -> dict:
    out = _run([
        "aws", "lambda", "invoke",
        "--function-name", function_name,
        "--payload", json.dumps(payload),
        "--cli-binary-format", "raw-in-base64-out",
        "/dev/stdout",
    ])
    return json.loads(out.stdout)


def download_signing_helper(out_dir: Path, version: str = HELPER_VERSION_DEFAULT) -> Path:
    system = platform.system()
    machine = platform.machine()
    arch_map = {"x86_64": "X86_64", "AMD64": "X86_64", "arm64": "ARM64", "aarch64": "ARM64"}
    arch = arch_map.get(machine)
    if system == "Linux":
        if arch != "X86_64":
            raise OnboardError(f"Unsupported Linux arch: {machine}")
        url = f"https://rolesanywhere.amazonaws.com/releases/{version}/X86_64/Linux/aws_signing_helper"
    elif system == "Darwin":
        if arch not in ("X86_64", "ARM64"):
            raise OnboardError(f"Unsupported macOS arch: {machine}")
        url = f"https://rolesanywhere.amazonaws.com/releases/{version}/{arch}/Darwin/aws_signing_helper"
    else:
        raise OnboardError(f"Unsupported platform: {system}")

    helper_path = out_dir / "aws_signing_helper"
    urllib.request.urlretrieve(url, helper_path)
    os.chmod(helper_path, 0o755)
    return helper_path


def get_credentials(
    cert_path: Path, key_path: Path, trust_anchor_arn: str, profile_arn: str, role_arn: str,
    helper_path: Path | None = None,
) -> dict:
    """Calls aws_signing_helper directly and returns the parsed credential JSON
    (AccessKeyId/SecretAccessKey/SessionToken/Expiration) -- no shelling out
    to the AWS CLI, no separate profile setup required to use this."""
    helper = str(helper_path) if helper_path else "aws_signing_helper"
    out = _run([
        helper, "credential-process",
        "--certificate", str(cert_path),
        "--private-key", str(key_path),
        "--trust-anchor-arn", trust_anchor_arn,
        "--profile-arn", profile_arn,
        "--role-arn", role_arn,
    ])
    return json.loads(out.stdout)


def write_aws_profile(
    profile_name: str, helper_path: Path, cert_path: Path, key_path: Path,
    trust_anchor_arn: str, profile_arn: str, role_arn: str,
    config_path: Path | None = None,
) -> Path:
    """Appends a [profile ...] block to ~/.aws/config. Every path/ARN is run
    through shlex.quote -- the exact bug this replaces: a bash version of
    this once wrote these paths unquoted, and broke on any directory name
    containing a space. shlex.quote handles spaces, quotes, and every other
    shell-meaningful character correctly, not just spaces."""
    config_path = config_path or Path.home() / ".aws" / "config"
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.touch(exist_ok=True)

    existing = config_path.read_text() if config_path.exists() else ""
    if f"[profile {profile_name}]" in existing:
        raise OnboardError(
            f"Profile '{profile_name}' already exists in {config_path} -- pick a different name"
        )

    cmd = [
        str(helper_path.resolve()), "credential-process",
        "--certificate", str(cert_path.resolve()),
        "--private-key", str(key_path.resolve()),
        "--trust-anchor-arn", trust_anchor_arn,
        "--profile-arn", profile_arn,
        "--role-arn", role_arn,
    ]
    credential_process_line = " ".join(shlex.quote(part) for part in cmd)

    with config_path.open("a") as f:
        f.write(f"\n[profile {profile_name}]\ncredential_process = {credential_process_line}\n")
    return config_path


def onboard(
    *, name: str, days: int = 365,
    url: str | None = None, secret: str | None = None, lambda_name: str | None = None,
    renew_serial: str | None = None,
    trust_anchor_arn: str | None = None, profile_arn: str | None = None, role_arn: str | None = None,
    aws_profile_name: str | None = None, write_profile: bool = True,
    helper_version: str = HELPER_VERSION_DEFAULT,
) -> CertResult:
    """The whole pipeline in one call: keypair -> certificate -> (optionally)
    aws_signing_helper + a ready-to-use AWS CLI profile. Mirrors what
    request-cert.sh does, minus the shell-quoting and jq dependency."""
    result = request_certificate(
        name=name, days=days, url=url, secret=secret,
        lambda_name=lambda_name, renew_serial=renew_serial,
    )
    print(f"Certificate issued. Serial: {result.serial}")
    print(f"  Private key : {result.key_path} (never left this machine)")
    print(f"  Certificate : {result.cert_path}")

    if not (trust_anchor_arn and profile_arn and role_arn):
        print("No trust_anchor_arn/profile_arn/role_arn given -- skipping AWS credential setup.")
        return result

    helper_path = download_signing_helper(result.out_dir, helper_version)
    if write_profile:
        chosen_name = aws_profile_name
        if not chosen_name:
            default_name = f"{name}-central-ca"
            chosen_name = input(f"AWS CLI profile name to create [{default_name}]: ").strip() or default_name
        config_path = write_aws_profile(
            chosen_name, helper_path, result.cert_path, result.key_path,
            trust_anchor_arn, profile_arn, role_arn,
        )
        print(f"Added profile '{chosen_name}' to {config_path}")
        print(f"  Use it with: aws sts get-caller-identity --profile {chosen_name}")
    return result


def _cli() -> None:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--name", required=True)
    p.add_argument("--days", type=int, default=365)
    p.add_argument("--url")
    p.add_argument("--secret")
    p.add_argument("--lambda", dest="lambda_name")
    p.add_argument("--renew", dest="renew_serial")
    p.add_argument("--trust-anchor-arn")
    p.add_argument("--profile-arn")
    p.add_argument("--role-arn")
    p.add_argument("--aws-profile-name")
    p.add_argument("--no-aws-profile", action="store_true")
    p.add_argument("--helper-version", default=HELPER_VERSION_DEFAULT)
    args = p.parse_args()

    try:
        onboard(
            name=args.name, days=args.days, url=args.url, secret=args.secret,
            lambda_name=args.lambda_name, renew_serial=args.renew_serial,
            trust_anchor_arn=args.trust_anchor_arn, profile_arn=args.profile_arn,
            role_arn=args.role_arn, aws_profile_name=args.aws_profile_name,
            write_profile=not args.no_aws_profile, helper_version=args.helper_version,
        )
    except OnboardError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    _cli()
