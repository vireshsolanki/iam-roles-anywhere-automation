#!/bin/bash
# Onboard a user. Run on the USER's own machine.
#
# The user's PRIVATE KEY is generated locally and never leaves this machine —
# only the PUBLIC key is sent to the CA. Issuance goes through `aws lambda
# invoke`, which uses your normal AWS credentials (SSO / role) from the default
# credential chain: NO long-lived access keys are read or promoted anywhere.
#
# Requires: openssl, jq, aws CLI with permission to invoke the issuer Lambda.
#
# Usage:
#   ./request-cert.sh --lambda <IssuerLambdaName> --name <client-name> [--days 365]

set -euo pipefail

LAMBDA=""; NAME=""; DAYS=365

GREEN='\033[0;32m'; RED='\033[0;31m'; NC='\033[0m'
info() { echo -e "${GREEN}[INFO]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

while [[ $# -gt 0 ]]; do
  case $1 in
    --lambda) LAMBDA="$2"; shift 2 ;;
    --name)   NAME="$2";   shift 2 ;;
    --days)   DAYS="$2";   shift 2 ;;
    *) error "Unknown option: $1" ;;
  esac
done
[[ -n "$LAMBDA" && -n "$NAME" ]] || error "Required: --lambda <name> --name <client-name>"
command -v openssl &>/dev/null || error "openssl not installed"
command -v jq      &>/dev/null || error "jq not installed"
command -v aws     &>/dev/null || error "aws CLI not installed"

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

info "Requesting certificate from central CA (via aws lambda invoke)..."
aws lambda invoke \
  --function-name "$LAMBDA" \
  --payload "$PAYLOAD" \
  --cli-binary-format raw-in-base64-out \
  "$OUT/response.json" >/dev/null

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
echo ""
echo "  Use with aws_signing_helper (see ../setup-client.sh for the wrapper scripts)."
