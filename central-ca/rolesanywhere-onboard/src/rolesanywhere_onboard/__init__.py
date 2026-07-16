"""Plug-and-play client for onboarding users against a self-hosted IAM Roles
Anywhere Central CA (see https://github.com/vireshsolanki/iam-roles-anywhere-automation).

    from rolesanywhere_onboard import request_certificate, get_credentials, onboard
"""
from .core import (
    CertResult,
    OnboardError,
    download_signing_helper,
    generate_keypair,
    get_credentials,
    onboard,
    request_certificate,
    write_aws_profile,
)

__version__ = "1.0.0"
__all__ = [
    "CertResult",
    "OnboardError",
    "download_signing_helper",
    "generate_keypair",
    "get_credentials",
    "onboard",
    "request_certificate",
    "write_aws_profile",
]
