#!/bin/bash
# Onboard a user — full pipeline in one command. Run on the USER's own machine.
#
# The user's PRIVATE KEY is generated locally and never leaves this machine —
# only the PUBLIC key is sent to the CA. Two ways to reach the CA to get it
# signed — pick ONE:
#
#   --lambda <name>            Admin mode: `aws lambda invoke`, authenticated
#                               by the caller's own AWS IAM credentials. No
#                               secret needed (lambda:InvokeFunction on this
#                               function IS the access control).
#
#   --url <ApiEndpoint>
#   --secret <ApiKeyValue>      Dev mode: plain HTTPS via curl, NO AWS
#                               credentials needed at all — just the public
#                               API Gateway endpoint (ApiEndpoint output) +
#                               the API key (ApiKeyValue) the admin set on the
#                               central-ca-stack.yml deploy. Sent as the
#                               "x-api-key" header. This is what you give to a
#                               developer who has no AWS account/login.
#
#   --renew <old-serial>        Optional, ADMIN-ONLY (--lambda mode only —
#                               renewal is not available over the public API).
#                               Issues a fresh certificate + fresh keypair for
#                               the SAME identity as an existing serial, then
#                               revokes the old one. Use this instead of
#                               --name for renewals; the CA looks up the
#                               common_name from its own record of the old
#                               serial, not from anything you supply.
#
# Requires: openssl, jq, curl. `aws` CLI only needed for --lambda mode and for
# test-credentials.sh (to exercise the resulting temporary credentials).
#
# Usage:
#   ./request-cert.sh --lambda <IssuerLambdaName> --name <client-name> \
#       --trust-anchor-arn <arn> --profile-arn <arn> --role-arn <arn> [--days 365]
#   ./request-cert.sh --url <ApiEndpoint> --secret <ApiKeyValue> --name <client-name> \
#       --trust-anchor-arn <arn> --profile-arn <arn> --role-arn <arn> [--days 365]
#   ./request-cert.sh --lambda <IssuerLambdaName> --name <client-name> \
#       --renew <old-serial> --trust-anchor-arn <arn> --profile-arn <arn> --role-arn <arn>
#
# Optional flags:
#   --aws-profile-name <name>   Name for the ~/.aws/config profile. If
#                                omitted, you're prompted interactively for
#                                one (default suggestion: "<client-name>-central-ca",
#                                just press Enter to accept it).
#   --no-aws-profile             Skip writing to ~/.aws/config entirely (and
#                                skip the interactive prompt).
#
# If --trust-anchor-arn/--profile-arn/--role-arn are omitted, only the
# certificate is issued (no aws_signing_helper setup) — useful if this user
# gets their own Role/Profile with a different policy (see README.md,
# "Giving a different user a different policy") and you want to wire up
# get-credentials.sh yourself with their specific ARNs.
#
# Also appends a `credential_process` AWS CLI profile to ~/.aws/config (name
# prompted for interactively, or set --aws-profile-name to skip the prompt
# non-interactively — e.g. when scripting this), so you get
# `aws --profile <name> ...` working immediately, with the CLI auto-refreshing
# credentials on every call — no manual export/re-run needed. This ONLY ever
# appends a new [profile ...] block; it never edits or overwrites an existing
# one. Skip it entirely with --no-aws-profile.

set -euo pipefail

LAMBDA=""; URL=""; SECRET=""; NAME=""; DAYS=365; HELPER_VERSION="1.4.0"; RENEW_SERIAL=""
TRUST_ANCHOR_ARN=""; PROFILE_ARN=""; ROLE_ARN=""; AWS_PROFILE_NAME=""; SKIP_AWS_PROFILE="false"

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'
info() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# Checks a command exists; if not, prints the right install command for the
# current OS/package manager instead of a bare "not found" the user then has
# to go look up themselves.
require() {
  local cmd="$1"
  command -v "$cmd" &>/dev/null && return 0
  local hint=""
  if   command -v apt-get &>/dev/null; then hint="sudo apt-get update && sudo apt-get install -y $cmd"
  elif command -v dnf     &>/dev/null; then hint="sudo dnf install -y $cmd"
  elif command -v yum     &>/dev/null; then hint="sudo yum install -y $cmd"
  elif command -v brew    &>/dev/null; then hint="brew install $cmd"
  elif command -v apk     &>/dev/null; then hint="sudo apk add $cmd"
  elif command -v pacman  &>/dev/null; then hint="sudo pacman -S $cmd"
  fi
  if [[ "$cmd" == "aws" ]]; then
    hint="see https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html (not a package-manager install on most systems)"
  fi
  error "'$cmd' is not installed.$( [[ -n "$hint" ]] && echo " Install it with: $hint" )"
}

while [[ $# -gt 0 ]]; do
  case $1 in
    --lambda)           LAMBDA="$2";           shift 2 ;;
    --url)               URL="$2";              shift 2 ;;
    --secret)            SECRET="$2";           shift 2 ;;
    --name)             NAME="$2";             shift 2 ;;
    --days)             DAYS="$2";             shift 2 ;;
    --renew)             RENEW_SERIAL="$2";     shift 2 ;;
    --trust-anchor-arn) TRUST_ANCHOR_ARN="$2";  shift 2 ;;
    --profile-arn)       PROFILE_ARN="$2";      shift 2 ;;
    --role-arn)          ROLE_ARN="$2";         shift 2 ;;
    --helper-version)    HELPER_VERSION="$2";   shift 2 ;;
    --aws-profile-name)  AWS_PROFILE_NAME="$2"; shift 2 ;;
    --no-aws-profile)    SKIP_AWS_PROFILE="true"; shift 1 ;;
    *) error "Unknown option: $1" ;;
  esac
done
[[ -n "$NAME" ]] || error "Required: --name <client-name>"
if [[ -n "$LAMBDA" ]]; then
  MODE="lambda"
  require aws
elif [[ -n "$URL" && -n "$SECRET" ]]; then
  MODE="url"
  [[ -z "$RENEW_SERIAL" ]] || error "Renewal is admin-only — use --lambda mode, not --url"
else
  error "Required: either --lambda <name>  OR  --url <ApiEndpoint> --secret <ApiKeyValue>"
fi
require openssl
require jq
require curl

OUT="./client-${NAME}"
mkdir -p "$OUT"
KEY="$OUT/${NAME}-private-key.pem"
PUB="$OUT/${NAME}-public-key.pem"
CERT="$OUT/${NAME}-certificate.pem"

info "Generating private key (stays on this machine): $KEY"
openssl genrsa -out "$KEY" 2048 2>/dev/null
chmod 600 "$KEY"
openssl rsa -in "$KEY" -pubout -out "$PUB" 2>/dev/null

if [[ -n "$RENEW_SERIAL" ]]; then
  PAYLOAD=$(jq -n --arg serial "$RENEW_SERIAL" --arg pk "$(cat "$PUB")" --argjson days "$DAYS" \
    '{action:"renew", serial:$serial, public_key:$pk, days:$days}')
else
  PAYLOAD=$(jq -n --arg cn "$NAME" --arg pk "$(cat "$PUB")" --argjson days "$DAYS" \
    '{action:"sign", common_name:$cn, public_key:$pk, days:$days}')
fi

if [[ "$MODE" == "lambda" ]]; then
  info "Requesting certificate from central CA (via aws lambda invoke, admin credentials)..."
  aws lambda invoke \
    --function-name "$LAMBDA" \
    --payload "$PAYLOAD" \
    --cli-binary-format raw-in-base64-out \
    "$OUT/response.json" >/dev/null
else
  info "Requesting certificate from central CA (via HTTPS, no AWS credentials)..."
  curl -sS -X POST "$URL" \
    -H "Content-Type: application/json" \
    -H "x-api-key: $SECRET" \
    -d "$PAYLOAD" \
    -o "$OUT/response.json"
fi

if ! jq -e '.certificate' "$OUT/response.json" >/dev/null 2>&1; then
  error "Signing failed: $(cat "$OUT/response.json")"
fi
jq -r '.certificate' "$OUT/response.json" > "$CERT"
SERIAL=$(jq -r '.serial' "$OUT/response.json")
rm -f "$OUT/response.json"

info "Certificate issued."
echo "  Serial      : $SERIAL"
echo "  Private key : $KEY   (never left this machine)"
echo "  Certificate : $CERT"

if [[ -z "$TRUST_ANCHOR_ARN" || -z "$PROFILE_ARN" || -z "$ROLE_ARN" ]]; then
  warn "No --trust-anchor-arn/--profile-arn/--role-arn given — skipping aws_signing_helper setup."
  echo "  Re-run with those three flags to auto-generate get-credentials.sh / test-credentials.sh."
  exit 0
fi

info "Downloading aws_signing_helper..."
PLATFORM=$(uname -s)
ARCH=$(uname -m)
case "$PLATFORM" in
  Linux)
    [[ "$ARCH" == "x86_64" ]] || error "Unsupported Linux arch: $ARCH"
    HELPER_URL="https://rolesanywhere.amazonaws.com/releases/${HELPER_VERSION}/X86_64/Linux/aws_signing_helper"
    ;;
  Darwin)
    if   [[ "$ARCH" == "x86_64" ]]; then HELPER_URL="https://rolesanywhere.amazonaws.com/releases/${HELPER_VERSION}/X86_64/Darwin/aws_signing_helper"
    elif [[ "$ARCH" == "arm64"  ]]; then HELPER_URL="https://rolesanywhere.amazonaws.com/releases/${HELPER_VERSION}/ARM64/Darwin/aws_signing_helper"
    else error "Unsupported macOS arch: $ARCH"; fi
    ;;
  *) error "Unsupported platform: $PLATFORM" ;;
esac
curl -fsSL -o "$OUT/aws_signing_helper" "$HELPER_URL"
chmod +x "$OUT/aws_signing_helper"

info "Creating helper scripts..."
cat > "$OUT/get-credentials.sh" << EOF
#!/bin/bash
# Retrieves temporary AWS credentials via IAM Roles Anywhere
SCRIPT_DIR="\$(cd "\$(dirname "\${BASH_SOURCE[0]}")" && pwd)"
"\$SCRIPT_DIR/aws_signing_helper" credential-process \\
    --certificate "\$SCRIPT_DIR/${NAME}-certificate.pem" \\
    --private-key "\$SCRIPT_DIR/${NAME}-private-key.pem" \\
    --trust-anchor-arn "$TRUST_ANCHOR_ARN" \\
    --profile-arn "$PROFILE_ARN" \\
    --role-arn "$ROLE_ARN"
EOF
chmod +x "$OUT/get-credentials.sh"

cat > "$OUT/test-credentials.sh" << 'EOF'
#!/bin/bash
# Run this with ./test-credentials.sh or bash test-credentials.sh -- NOT
# `sh test-credentials.sh`. On Debian/Ubuntu, sh is dash, which doesn't
# support ${BASH_SOURCE[0]} or [[ ]] and will fail with confusing errors
# like "Bad substitution" even though the shebang above says bash.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
echo "Fetching temporary credentials..."
if ! CREDS=$("$SCRIPT_DIR/get-credentials.sh"); then
  echo "Failed to get credentials"
  exit 1
fi

export AWS_ACCESS_KEY_ID=$(echo "$CREDS"     | jq -r '.AccessKeyId')
export AWS_SECRET_ACCESS_KEY=$(echo "$CREDS" | jq -r '.SecretAccessKey')
export AWS_SESSION_TOKEN=$(echo "$CREDS"     | jq -r '.SessionToken')

echo "Caller identity:"
aws sts get-caller-identity

# `aws s3 ls` with no bucket needs the account-wide s3:ListAllMyBuckets
# permission, which a properly least-privilege role scoped to specific
# buckets/prefixes will correctly NOT have. AccessDenied here just means
# your policy is scoped as intended -- it doesn't mean your credentials
# are broken. Point this at a bucket you actually have access to instead:
echo ""
echo "S3 buckets (requires s3:ListAllMyBuckets -- AccessDenied here is"
echo "expected if your role is scoped to specific buckets, not a failure):"
aws s3 ls || echo "  (skipped -- try: aws s3 ls s3://<your-bucket> --profile <this profile>)"
EOF
chmod +x "$OUT/test-credentials.sh"

if [[ "$SKIP_AWS_PROFILE" == "true" ]]; then
  info "Skipping AWS CLI profile setup (--no-aws-profile given)."
else
  if [[ -z "$AWS_PROFILE_NAME" ]]; then
    DEFAULT_PROFILE_NAME="${NAME}-central-ca"
    read -rp "AWS CLI profile name to create [${DEFAULT_PROFILE_NAME}]: " AWS_PROFILE_NAME
    [[ -n "$AWS_PROFILE_NAME" ]] || AWS_PROFILE_NAME="$DEFAULT_PROFILE_NAME"
  fi
  AWS_CONFIG_FILE="${AWS_CONFIG_FILE:-$HOME/.aws/config}"
  mkdir -p "$(dirname "$AWS_CONFIG_FILE")"
  touch "$AWS_CONFIG_FILE"
  if grep -q "^\[profile ${AWS_PROFILE_NAME}\]" "$AWS_CONFIG_FILE" 2>/dev/null; then
    warn "Profile '$AWS_PROFILE_NAME' already exists in $AWS_CONFIG_FILE — left untouched."
    echo "  Use --aws-profile-name <name> to pick a different name, or edit that file manually."
  else
    ABS_OUT="$(cd "$OUT" && pwd)"
    {
      echo ""
      echo "[profile ${AWS_PROFILE_NAME}]"
      echo "credential_process = \"${ABS_OUT}/aws_signing_helper\" credential-process --certificate \"${ABS_OUT}/${NAME}-certificate.pem\" --private-key \"${ABS_OUT}/${NAME}-private-key.pem\" --trust-anchor-arn \"${TRUST_ANCHOR_ARN}\" --profile-arn \"${PROFILE_ARN}\" --role-arn \"${ROLE_ARN}\""
    } >> "$AWS_CONFIG_FILE"
    info "Added profile '$AWS_PROFILE_NAME' to $AWS_CONFIG_FILE (appended only — nothing else in that file was touched)."
    echo "  Use it with: aws sts get-caller-identity --profile $AWS_PROFILE_NAME"
    echo "  The CLI auto-refreshes credentials on every call — no manual re-run needed."
  fi
fi

info "Full pipeline complete — everything is ready in $OUT/"
echo "  Run: cd $OUT && ./test-credentials.sh"
