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
#   --url <FunctionUrl>
#   --secret <ApiSecret>        Dev mode: plain HTTPS via curl, NO AWS
#                               credentials needed at all — just the public
#                               FunctionUrl + the shared ApiSecret the admin
#                               set on the central-ca-stack.yml deploy. This
#                               is what you give to a developer who has no
#                               AWS account/login.
#
# Requires: openssl, jq, curl. `aws` CLI only needed for --lambda mode and for
# test-credentials.sh (to exercise the resulting temporary credentials).
#
# Usage:
#   ./request-cert.sh --lambda <IssuerLambdaName> --name <client-name> \
#       --trust-anchor-arn <arn> --profile-arn <arn> --role-arn <arn> [--days 365]
#   ./request-cert.sh --url <FunctionUrl> --secret <ApiSecret> --name <client-name> \
#       --trust-anchor-arn <arn> --profile-arn <arn> --role-arn <arn> [--days 365]
#
# If --trust-anchor-arn/--profile-arn/--role-arn are omitted, only the
# certificate is issued (no aws_signing_helper setup) — useful if this user
# gets their own Role/Profile with a different policy (see README.md,
# "Giving a different user a different policy") and you want to wire up
# get-credentials.sh yourself with their specific ARNs.

set -euo pipefail

LAMBDA=""; URL=""; SECRET=""; NAME=""; DAYS=365; HELPER_VERSION="1.4.0"
TRUST_ANCHOR_ARN=""; PROFILE_ARN=""; ROLE_ARN=""

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; NC='\033[0m'
info() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

while [[ $# -gt 0 ]]; do
  case $1 in
    --lambda)           LAMBDA="$2";           shift 2 ;;
    --url)               URL="$2";              shift 2 ;;
    --secret)            SECRET="$2";           shift 2 ;;
    --name)             NAME="$2";             shift 2 ;;
    --days)             DAYS="$2";             shift 2 ;;
    --trust-anchor-arn) TRUST_ANCHOR_ARN="$2";  shift 2 ;;
    --profile-arn)       PROFILE_ARN="$2";      shift 2 ;;
    --role-arn)          ROLE_ARN="$2";         shift 2 ;;
    --helper-version)    HELPER_VERSION="$2";   shift 2 ;;
    *) error "Unknown option: $1" ;;
  esac
done
[[ -n "$NAME" ]] || error "Required: --name <client-name>"
if [[ -n "$LAMBDA" ]]; then
  MODE="lambda"
  command -v aws &>/dev/null || error "aws CLI not installed (required for --lambda mode)"
elif [[ -n "$URL" && -n "$SECRET" ]]; then
  MODE="url"
else
  error "Required: either --lambda <name>  OR  --url <FunctionUrl> --secret <ApiSecret>"
fi
command -v openssl &>/dev/null || error "openssl not installed"
command -v jq      &>/dev/null || error "jq not installed"
command -v curl    &>/dev/null || error "curl not installed"

OUT="./client-${NAME}"
mkdir -p "$OUT"
KEY="$OUT/${NAME}-private-key.pem"
PUB="$OUT/${NAME}-public-key.pem"
CERT="$OUT/${NAME}-certificate.pem"

info "Generating private key (stays on this machine): $KEY"
openssl genrsa -out "$KEY" 2048 2>/dev/null
chmod 600 "$KEY"
openssl rsa -in "$KEY" -pubout -out "$PUB" 2>/dev/null

PAYLOAD=$(jq -n --arg cn "$NAME" --arg pk "$(cat "$PUB")" --argjson days "$DAYS" \
  '{action:"sign", common_name:$cn, public_key:$pk, days:$days}')

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
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
echo "Fetching temporary credentials..."
CREDS=$("$SCRIPT_DIR/get-credentials.sh")
if [[ $? -ne 0 ]]; then echo "Failed to get credentials"; exit 1; fi

export AWS_ACCESS_KEY_ID=$(echo "$CREDS"     | jq -r '.AccessKeyId')
export AWS_SECRET_ACCESS_KEY=$(echo "$CREDS" | jq -r '.SecretAccessKey')
export AWS_SESSION_TOKEN=$(echo "$CREDS"     | jq -r '.SessionToken')

echo "Caller identity:"
aws sts get-caller-identity
echo ""
echo "S3 buckets:"
aws s3 ls
EOF
chmod +x "$OUT/test-credentials.sh"

info "Full pipeline complete — everything is ready in $OUT/"
echo "  Run: cd $OUT && ./test-credentials.sh"
