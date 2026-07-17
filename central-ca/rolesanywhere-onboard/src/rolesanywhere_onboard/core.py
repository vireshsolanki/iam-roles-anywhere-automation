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
import shutil
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

NAME_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
# Interpolated into the download URL. It can't escape the AWS host (a path
# can't rewrite the authority), but validating keeps the URL well-formed and
# the failure mode obvious.
HELPER_VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
HELPER_VERSION_DEFAULT = "1.4.0"
HELPER_HOST = "rolesanywhere.amazonaws.com"
# The AWS CLI's own default -- writing here means `aws s3 ls` works with no
# --profile flag. Override per-run with --aws-profile-name.
DEFAULT_PROFILE_NAME = "default"
IS_WINDOWS = platform.system() == "Windows"

# Env-var overrides, for containers/CI where there's no meaningful home dir:
#   IAMROLES_DIR    -- base directory for certs and the shared helper
#   IAMROLES_HELPER -- explicit path to an aws_signing_helper binary
ENV_BASE_DIR = "IAMROLES_DIR"
ENV_HELPER = "IAMROLES_HELPER"


def base_dir() -> Path:
    """Where certs and the shared helper live.

    Deliberately NOT relative to the current directory. An earlier version
    defaulted to ./client-<name>, which meant the output landed wherever the
    user happened to be standing -- in practice, someone's ~/Downloads. They
    then (reasonably) moved it somewhere sensible, which broke every profile
    pointing at it, because credential_process paths must be absolute (the AWS
    CLI invokes them from arbitrary working directories, so a relative path
    would resolve against whatever tool is asking for credentials).

    Resolution order: $IAMROLES_DIR, then the platform's conventional
    per-user config location.
    """
    if os.environ.get(ENV_BASE_DIR):
        return Path(os.environ[ENV_BASE_DIR]).expanduser()
    if IS_WINDOWS:
        local = os.environ.get("LOCALAPPDATA")
        if local:
            return Path(local) / "rolesanywhere"
        return Path.home() / "AppData" / "Local" / "rolesanywhere"
    if os.environ.get("XDG_CONFIG_HOME"):
        return Path(os.environ["XDG_CONFIG_HOME"]) / "rolesanywhere"
    return Path.home() / ".config" / "rolesanywhere"


def client_dir(name: str) -> Path:
    """Per-identity directory holding that identity's key + certificate."""
    _check_name(name)
    return base_dir() / name


def shared_helper_path() -> Path:
    """One aws_signing_helper for every identity on this machine.

    The binary is ~17MB and identical for every client, so downloading a copy
    per identity (as this once did) wastes both bandwidth and disk for no
    benefit. Resolution order: $IAMROLES_HELPER, then one already on PATH,
    then the shared copy under base_dir().
    """
    if os.environ.get(ENV_HELPER):
        return Path(os.environ[ENV_HELPER]).expanduser()
    on_path = shutil.which("aws_signing_helper")
    if on_path:
        return Path(on_path)
    name = "aws_signing_helper.exe" if IS_WINDOWS else "aws_signing_helper"
    return base_dir() / "bin" / name


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

    out = Path(out_dir).expanduser() if out_dir else client_dir(name)
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


def _require_https(url: str) -> None:
    """Refuse to send the API key over anything but TLS.

    The key is sent as an x-api-key header, and it can mint a certificate for
    ANY identity -- it's a far more valuable secret than any single
    certificate. Over http:// it would cross the network in cleartext to
    anyone on the path. There is no legitimate reason to point this at a
    non-HTTPS endpoint (API Gateway is HTTPS-only), so this is a hard error
    rather than a warning.
    """
    scheme = urllib.parse.urlparse(url).scheme.lower()
    if scheme != "https":
        raise OnboardError(
            f"--url must be https:// (got {scheme or 'no'} scheme). The API key is sent "
            "as a header and would be readable by anyone on the network path."
        )


def _post_json(url: str, secret: str, payload: dict) -> dict:
    _require_https(url)
    body = json.dumps(payload).encode()
    req = urllib.request.Request(
        url, data=body, method="POST",
        headers={"Content-Type": "application/json", "x-api-key": secret},
    )
    try:
        # urllib verifies TLS certs and hostnames by default (CERT_REQUIRED +
        # check_hostname), so this is not silently downgradeable.
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return json.loads(exc.read())


def ensure_signing_helper(version: str = HELPER_VERSION_DEFAULT, dest: Path | None = None) -> Path:
    """Return a usable aws_signing_helper, downloading it only if needed.

    Shared across every identity on the machine rather than copied per-client
    (it's ~17MB and byte-identical each time). If $IAMROLES_HELPER is set or a
    helper is already on PATH, that one is used and nothing is downloaded --
    which is how you'd wire this up in a container image or on a server with
    the binary baked in at /usr/local/bin.
    """
    helper_path = Path(dest).expanduser() if dest else shared_helper_path()
    if helper_path.exists():
        return helper_path
    if not HELPER_VERSION_RE.match(version):
        raise OnboardError(f"Invalid helper version {version!r}: expected N.N.N (e.g. 1.4.0)")

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
    elif system == "Darwin":
        if arch not in ("X86_64", "ARM64"):
            raise OnboardError(f"Unsupported macOS arch: {machine!r}")
        url = f"https://rolesanywhere.amazonaws.com/releases/{version}/{arch}/Darwin/aws_signing_helper"
    elif system == "Windows":
        if arch != "X86_64":
            raise OnboardError(
                f"Unsupported Windows arch: {machine!r} -- AWS only publishes an "
                "X86_64 aws_signing_helper build for Windows"
            )
        url = f"https://rolesanywhere.amazonaws.com/releases/{version}/X86_64/Windows/aws_signing_helper.exe"
    else:
        raise OnboardError(f"Unsupported platform: {system!r}")

    helper_path.parent.mkdir(parents=True, exist_ok=True)
    # Download to a temp name in the same directory, then atomically rename.
    # A half-written 17MB binary left behind by an interrupted download would
    # otherwise satisfy the exists() check above forever and fail at run time.
    tmp = helper_path.with_suffix(helper_path.suffix + ".partial")
    urllib.request.urlretrieve(url, tmp)
    if not IS_WINDOWS:
        os.chmod(tmp, 0o755)  # +x -- meaningless on Windows, .exe is already executable
    tmp.replace(helper_path)
    return helper_path


# Back-compat alias: this was the name before the helper became shared.
def download_signing_helper(out_dir: Path, version: str = HELPER_VERSION_DEFAULT) -> Path:
    return ensure_signing_helper(version=version, dest=Path(out_dir) / (
        "aws_signing_helper.exe" if IS_WINDOWS else "aws_signing_helper"
    ))


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


def _read_section_setting(text: str, header: str, setting: str) -> str | None:
    """Pull one setting out of one section of an AWS config file.

    Hand-rolled rather than configparser: AWS's format allows nested settings
    (e.g. `s3 =` followed by indented sub-settings) that configparser rejects,
    and configparser would also risk rewriting/reformatting the user's file.
    This only reads.
    """
    in_section = False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("[") and stripped.endswith("]"):
            in_section = stripped == header
            continue
        if in_section and "=" in stripped and not stripped.startswith("#"):
            key, _, value = stripped.partition("=")
            if key.strip() == setting:
                return value.strip()
    return None


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

    Never overwrites or edits an existing section. Three cases:
      - section absent           -> append it
      - section present, same    -> no-op (this is the renewal path: a dev
                                    re-running to refresh an expiring cert
                                    writes the same paths/ARNs, so there is
                                    nothing to change and nothing to warn
                                    about)
      - section present, differs -> raise, so an unrelated `default` from
                                    `aws configure` is never clobbered
    """
    config_path = config_path or _default_aws_config_path()
    config_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.touch(exist_ok=True)

    cmd = [
        str(helper_path.resolve()), "credential-process",
        "--certificate", str(cert_path.resolve()),
        "--private-key", str(key_path.resolve()),
        "--trust-anchor-arn", trust_anchor_arn,
        "--profile-arn", profile_arn,
        "--role-arn", role_arn,
    ]
    credential_process_line = " ".join(shlex.quote(part) for part in cmd)

    header = _section_header(profile_name)
    existing = config_path.read_text() if config_path.exists() else ""
    # Match on a full line, not a substring: a bare `in` check would hit false
    # positives inside comments, values, or longer section names.
    if any(line.strip() == header for line in existing.splitlines()):
        current = _read_section_setting(existing, header, "credential_process")
        if current == credential_process_line:
            return config_path  # already exactly right -- renewal no-op
        if current is None:
            detail = (
                "it exists but isn't managed by this tool (no credential_process "
                "setting -- probably from `aws configure`)"
            )
        else:
            detail = "it exists with different settings"
        raise OnboardError(
            f"Profile '{profile_name}' already exists in {config_path} and {detail}. "
            f"Pass --aws-profile-name to use a different name, or remove the "
            f"existing {header} section first."
        )

    with config_path.open("a") as f:
        f.write(f"\n{header}\ncredential_process = {credential_process_line}\n")
    return config_path


def onboard(
    *, name: str, url: str, secret: str, days: int = 365,
    trust_anchor_arn: str | None = None, profile_arn: str | None = None, role_arn: str | None = None,
    aws_profile_name: str | None = None, write_profile: bool = True,
    helper_version: str = HELPER_VERSION_DEFAULT,
    out_dir: str | Path | None = None,
    interactive: bool = True,
) -> CertResult:
    """The whole pipeline in one call: keypair -> certificate -> (optionally)
    aws_signing_helper + a ready-to-use AWS CLI profile."""
    result = request_certificate(name=name, days=days, url=url, secret=secret, out_dir=out_dir)
    print(f"Certificate issued. Serial: {result.serial}")
    print(f"  Private key : {result.key_path} (never left this machine)")
    print(f"  Certificate : {result.cert_path}")

    if not (trust_anchor_arn and profile_arn and role_arn):
        print("No trust_anchor_arn/profile_arn/role_arn given -- skipping AWS credential setup.")
        return result

    existing_helper = shared_helper_path()
    reused = existing_helper.exists()
    helper_path = ensure_signing_helper(helper_version)
    print(f"  Signing helper: {helper_path}" + ("  (reused)" if reused else "  (downloaded)"))
    if write_profile:
        chosen_name = aws_profile_name
        if not chosen_name:
            # "default" so plain `aws s3 ls` works with no --profile flag at
            # all. write_aws_profile won't clobber an unrelated existing
            # default (e.g. from `aws configure`) -- it raises instead.
            if interactive and sys.stdin.isatty():
                chosen_name = input(f"AWS CLI profile name to create [{DEFAULT_PROFILE_NAME}]: ").strip() or DEFAULT_PROFILE_NAME
            else:
                chosen_name = DEFAULT_PROFILE_NAME
        header = _section_header(chosen_name)
        config_path_probe = _default_aws_config_path()
        was_present = config_path_probe.exists() and any(
            line.strip() == header for line in config_path_probe.read_text().splitlines()
        )
        config_path = write_aws_profile(
            chosen_name, helper_path, result.cert_path, result.key_path,
            trust_anchor_arn, profile_arn, role_arn,
        )
        if was_present:
            print(f"Profile '{chosen_name}' in {config_path} already points here -- left unchanged.")
            print("  Your renewed certificate is picked up automatically (same paths).")
        else:
            print(f"Added profile '{chosen_name}' to {config_path}")
        if chosen_name == DEFAULT_PROFILE_NAME:
            print("  Use it with: aws sts get-caller-identity   (no --profile needed)")
        else:
            print(f"  Use it with: aws sts get-caller-identity --profile {chosen_name}")
    return result
