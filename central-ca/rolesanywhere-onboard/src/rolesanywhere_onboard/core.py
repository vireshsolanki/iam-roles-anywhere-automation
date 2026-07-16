"""
Core onboarding pipeline: keypair -> certificate -> (optionally) AWS
credentials via aws_signing_helper and a ready-to-use AWS CLI profile.

Developer-facing only, by design. This talks to the CA's public HTTPS
endpoint with a shared API key and nothing else -- it needs no AWS
credentials, no `aws` CLI, and no AWS account. Issuance ("sign") is the only
action that endpoint exposes; revoke/renew/disable/enable/crl/rotate_ca are
admin-only, gated behind real AWS IAM credentials on a direct Lambda invoke.
Admins use request-cert.sh for those.

Cross-platform by construction, not by testing every OS:
  - Keypair generation uses the `cryptography` package (a declared PyPI
    dependency, ships prebuilt wheels for Linux/macOS/Windows across
    manylinux/musllinux/arm64/x86_64) instead of shelling out to a system
    `openssl` binary, which is NOT guaranteed present on Windows and varies
    in version/flags across Linux distros. This is the one dependency this
    package can't avoid declaring, since Python's standard library has no
    asymmetric-key generation at all.
  - aws_signing_helper downloads cover Linux, macOS (Intel + Apple Silicon),
    and Windows (x86_64) -- AWS publishes all of these at predictable URLs.
  - No /dev/stdout, no /tmp assumptions, no os.chmod calls that assume Unix
    permission bits mean something on Windows (they don't -- Windows only
    honors the read-only flag via chmod, so file-mode calls are best-effort
    there and never treated as fatal).
  - pathlib.Path throughout for all path handling instead of string
    concatenation, so path separators are correct per-OS automatically.
"""
from __future__ import annotations

import json
import os
import platform
import re
import shlex
import subprocess
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

NAME_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
HELPER_VERSION_DEFAULT = "1.4.0"
# The AWS CLI's own default -- writing here means `aws s3 ls` works with no
# --profile flag. Override per-run with --aws-profile-name.
DEFAULT_PROFILE_NAME = "default"
IS_WINDOWS = platform.system() == "Windows"


class OnboardError(Exception):
    """Raised for any failure in this package -- callers catch this one type."""


def _check_name(name: str) -> None:
    # NAME becomes part of a directory path and a certificate common_name.
    # Restricting the character set closes off path traversal and means NAME
    # never needs individual shell-escaping downstream -- it can't contain
    # anything shell-meaningful in the first place. Same rule on every OS:
    # this charset is safe as a path component and a shell argument
    # regardless of platform-specific quoting conventions.
    if not NAME_RE.match(name):
        raise OnboardError(
            f"Invalid name {name!r}: only letters, numbers, '.', '_', '-' allowed"
        )


def _try_restrict_permissions(path: Path) -> None:
    """Best-effort private-key protection. On POSIX this sets mode 600. On
    Windows, os.chmod only controls the read-only attribute (there's no
    concept of owner-only read here without touching real ACLs via pywin32,
    which isn't worth adding as a dependency for this) -- so this degrades
    gracefully there rather than failing the whole run over it."""
    try:
        if IS_WINDOWS:
            os.chmod(path, 0o400)  # best-effort: sets read-only attribute
        else:
            os.chmod(path, 0o600)
    except OSError:
        pass  # never fatal -- the key still exists and works either way


def generate_keypair(out_dir: Path, name: str) -> tuple[Path, Path]:
    """RSA-2048 keypair via the `cryptography` package -- no system `openssl`
    binary required, so this works identically whether or not the OS ships
    one (Windows notably doesn't, by default)."""
    key_path = out_dir / f"{name}-private-key.pem"
    pub_path = out_dir / f"{name}-public-key.pem"

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    key_path.write_bytes(key_pem)
    _try_restrict_permissions(key_path)
    pub_path.write_bytes(pub_pem)
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
    url: str,
    secret: str,
    days: int = 365,
    out_dir: str | Path | None = None,
) -> CertResult:
    """
    Issues a certificate for `name` over the CA's public HTTPS endpoint, using
    only the shared API key -- no AWS credentials of any kind.

    Issuance ("sign") is the only action the public endpoint exposes. Every
    other lifecycle action (revoke, renew, disable/enable, crl, rotate_ca) is
    admin-only and reachable only by direct Lambda invoke with real AWS IAM
    credentials -- that's a deliberate boundary in the CA, not an omission
    here. Admins have request-cert.sh for those.
    """
    _check_name(name)
    if not url or not secret:
        raise OnboardError("Both url and secret are required")

    out = Path(out_dir) if out_dir else Path(f"./client-{name}")
    out.mkdir(parents=True, exist_ok=True)
    key_path, pub_path = generate_keypair(out, name)
    public_key = pub_path.read_text()

    payload = {"action": "sign", "common_name": name, "public_key": public_key, "days": days}
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


def download_signing_helper(out_dir: Path, version: str = HELPER_VERSION_DEFAULT) -> Path:
    system = platform.system()
    machine = platform.machine()
    arch_map = {
        "x86_64": "X86_64", "AMD64": "X86_64", "amd64": "X86_64",
        "arm64": "ARM64", "aarch64": "ARM64",
    }
    arch = arch_map.get(machine)

    if system == "Linux":
        if arch != "X86_64":
            raise OnboardError(
                f"Unsupported Linux arch: {machine!r} -- AWS only publishes an "
                "X86_64 aws_signing_helper build for Linux"
            )
        url = f"https://rolesanywhere.amazonaws.com/releases/{version}/X86_64/Linux/aws_signing_helper"
        filename = "aws_signing_helper"
    elif system == "Darwin":
        if arch not in ("X86_64", "ARM64"):
            raise OnboardError(f"Unsupported macOS arch: {machine!r}")
        url = f"https://rolesanywhere.amazonaws.com/releases/{version}/{arch}/Darwin/aws_signing_helper"
        filename = "aws_signing_helper"
    elif system == "Windows":
        if arch != "X86_64":
            raise OnboardError(
                f"Unsupported Windows arch: {machine!r} -- AWS only publishes an "
                "X86_64 aws_signing_helper build for Windows"
            )
        url = f"https://rolesanywhere.amazonaws.com/releases/{version}/X86_64/Windows/aws_signing_helper.exe"
        filename = "aws_signing_helper.exe"
    else:
        raise OnboardError(f"Unsupported platform: {system!r}")

    helper_path = out_dir / filename
    urllib.request.urlretrieve(url, helper_path)
    if not IS_WINDOWS:
        os.chmod(helper_path, 0o755)  # +x -- meaningless on Windows, .exe is already executable
    return helper_path


def get_credentials(
    cert_path: Path, key_path: Path, trust_anchor_arn: str, profile_arn: str, role_arn: str,
    helper_path: Path | None = None,
) -> dict:
    """Calls aws_signing_helper directly and returns the parsed credential JSON
    (AccessKeyId/SecretAccessKey/SessionToken/Expiration)."""
    helper = str(helper_path) if helper_path else ("aws_signing_helper.exe" if IS_WINDOWS else "aws_signing_helper")
    try:
        out = subprocess.run(
            [
                helper, "credential-process",
                "--certificate", str(cert_path),
                "--private-key", str(key_path),
                "--trust-anchor-arn", trust_anchor_arn,
                "--profile-arn", profile_arn,
                "--role-arn", role_arn,
            ],
            check=True, capture_output=True, text=True,
        )
    except FileNotFoundError:
        raise OnboardError(f"'{helper}' not found -- run download_signing_helper() first")
    except subprocess.CalledProcessError as exc:
        raise OnboardError(f"aws_signing_helper failed: {exc.stderr.strip() or exc.stdout.strip()}")
    return json.loads(out.stdout)


def _default_aws_config_path() -> Path:
    # AWS_CONFIG_FILE is honored on every OS (same env var name); the default
    # location differs -- ~/.aws/config on POSIX, and functionally the same
    # under %USERPROFILE%\.aws\config on Windows, which Path.home() resolves
    # to correctly without any platform-specific branching needed here.
    if os.environ.get("AWS_CONFIG_FILE"):
        return Path(os.environ["AWS_CONFIG_FILE"])
    return Path.home() / ".aws" / "config"


def _section_header(profile_name: str) -> str:
    """AWS's config file uses two different section formats, and getting this
    wrong silently produces a profile that doesn't work. Per AWS's docs:
    section names are "[default]" and "[profile user1]" -- i.e. the default
    profile is a bare "[default]", while every OTHER profile is prefixed with
    the word "profile". Writing "[profile default]" would create a section the
    CLI does not treat as the default."""
    return "[default]" if profile_name == "default" else f"[profile {profile_name}]"


def write_aws_profile(
    profile_name: str, helper_path: Path, cert_path: Path, key_path: Path,
    trust_anchor_arn: str, profile_arn: str, role_arn: str,
    config_path: Path | None = None,
) -> Path:
    """Appends a profile block to ~/.aws/config. Every path/ARN is run through
    shlex.quote -- correct POSIX shell-quoting rules, which is also exactly
    what the AWS CLI's own credential_process line parser expects on Windows
    (it uses the same shlex-style splitting internally, not native
    cmd.exe/PowerShell quoting), so a single quoting scheme works everywhere
    this string is actually consumed.

    Never overwrites an existing section -- if the target profile is already
    present this raises, so an existing `default` (e.g. from `aws configure`)
    can't be silently clobbered."""
    config_path = config_path or _default_aws_config_path()
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.touch(exist_ok=True)

    header = _section_header(profile_name)
    existing = config_path.read_text() if config_path.exists() else ""
    # Match on a full line, not a substring: "[default]" would otherwise also
    # match inside "[default]" of a longer name, and a bare `in` check can hit
    # false positives in comments or values.
    if any(line.strip() == header for line in existing.splitlines()):
        hint = (
            " -- you already have a default AWS profile; pass --aws-profile-name "
            "to add this under a different name instead"
            if profile_name == "default"
            else " -- pick a different name with --aws-profile-name"
        )
        raise OnboardError(f"Profile '{profile_name}' already exists in {config_path}{hint}")

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
        f.write(f"\n{header}\ncredential_process = {credential_process_line}\n")
    return config_path


def onboard(
    *, name: str, url: str, secret: str, days: int = 365,
    trust_anchor_arn: str | None = None, profile_arn: str | None = None, role_arn: str | None = None,
    aws_profile_name: str | None = None, write_profile: bool = True,
    helper_version: str = HELPER_VERSION_DEFAULT,
    interactive: bool = True,
) -> CertResult:
    """The whole pipeline in one call: keypair -> certificate -> (optionally)
    aws_signing_helper + a ready-to-use AWS CLI profile."""
    result = request_certificate(name=name, days=days, url=url, secret=secret)
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
            # "default" so plain `aws s3 ls` works with no --profile flag at
            # all. write_aws_profile refuses to overwrite an existing section,
            # so someone who already has a default profile gets a clear error
            # pointing at --aws-profile-name rather than losing their config.
            if interactive and sys.stdin.isatty():
                chosen_name = input(f"AWS CLI profile name to create [{DEFAULT_PROFILE_NAME}]: ").strip() or DEFAULT_PROFILE_NAME
            else:
                chosen_name = DEFAULT_PROFILE_NAME
        config_path = write_aws_profile(
            chosen_name, helper_path, result.cert_path, result.key_path,
            trust_anchor_arn, profile_arn, role_arn,
        )
        print(f"Added profile '{chosen_name}' to {config_path}")
        if chosen_name == DEFAULT_PROFILE_NAME:
            print("  Use it with: aws sts get-caller-identity   (no --profile needed)")
        else:
            print(f"  Use it with: aws sts get-caller-identity --profile {chosen_name}")
    return result
