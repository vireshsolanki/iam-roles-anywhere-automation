"""Console entry point -- installed as `iamroles` on PATH after
`pip install rolesanywhere-onboard`."""
from __future__ import annotations

import argparse
import sys

from .core import HELPER_VERSION_DEFAULT, OnboardError, onboard


def main() -> None:
    p = argparse.ArgumentParser(
        prog="iamroles",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "Onboard a user against a self-hosted IAM Roles Anywhere Central CA: "
            "generates a local keypair, requests a signed certificate, and "
            "(optionally) sets up an AWS CLI profile backed by aws_signing_helper."
        ),
        epilog=(
            "Environment variables (useful in containers/CI, where there's no\n"
            "meaningful home directory):\n"
            "  IAMROLES_DIR     base dir for certs and the shared signing helper\n"
            "                   (default: ~/.config/rolesanywhere)\n"
            "  IAMROLES_HELPER  path to an existing aws_signing_helper binary;\n"
            "                   set this (or put one on PATH) to skip the 17MB\n"
            "                   download entirely -- e.g. baked into an image\n"
            "                   at /usr/local/bin/aws_signing_helper\n"
        ),
    )
    p.add_argument("--name", required=True, help="Client identity / common_name")
    p.add_argument("--days", type=int, default=365, help="Certificate validity in days")
    p.add_argument("--url", required=True, help="Public API Gateway endpoint (ApiEndpoint output)")
    p.add_argument("--secret", required=True, help="API Gateway API key (ApiKeyValue)")
    p.add_argument("--trust-anchor-arn")
    p.add_argument("--profile-arn")
    p.add_argument("--role-arn")
    p.add_argument("--aws-profile-name",
                    help="~/.aws/config profile name (default: 'default', so no --profile flag is "
                         "needed afterwards; prompted if omitted and running interactively)")
    p.add_argument("--no-aws-profile", action="store_true", help="Skip writing to ~/.aws/config")
    p.add_argument("--out-dir", metavar="PATH",
                    help="Where to write the key + certificate. Default: a stable "
                         "per-user location (~/.config/rolesanywhere/<name>/), NOT "
                         "the current directory -- so it doesn't matter where you "
                         "run this from. Override the base with $IAMROLES_DIR.")
    p.add_argument("--helper-version", default=HELPER_VERSION_DEFAULT)
    p.add_argument("--non-interactive", action="store_true",
                    help="Never prompt (use defaults for anything not given as a flag)")
    args = p.parse_args()

    try:
        onboard(
            name=args.name, days=args.days, url=args.url, secret=args.secret,
            trust_anchor_arn=args.trust_anchor_arn, profile_arn=args.profile_arn,
            role_arn=args.role_arn, aws_profile_name=args.aws_profile_name,
            write_profile=not args.no_aws_profile, helper_version=args.helper_version,
            out_dir=args.out_dir, interactive=not args.non_interactive,
        )
    except OnboardError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
