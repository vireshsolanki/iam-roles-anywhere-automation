#!/bin/bash
# Issues a client certificate signed by the local OpenSSL CA and sets up credential helper

set -e

CA_DIR="./ca"
CA_KEY="$CA_DIR/ca-private-key.pem"
CA_CERT="$CA_DIR/ca-certificate.pem"

CLIENT_NAME="client-$(date +%Y%m%d-%H%M%S)"
CERT_VALIDITY_DAYS=365
SIGNING_HELPER_VERSION="1.4.0"
TRUST_ANCHOR_ARN=""
PROFILE_ARN=""
ROLE_ARN=""

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

usage() {
    echo "Usage: $0 --trust-anchor-arn <ARN> --profile-arn <ARN> --role-arn <ARN> [OPTIONS]"
    echo ""
    echo "Required:"
    echo "  --trust-anchor-arn   Trust Anchor ARN (from CloudFormation output)"
    echo "  --profile-arn        Profile ARN (from CloudFormation output)"
    echo "  --role-arn           IAM Role ARN (from CloudFormation output)"
    echo ""
    echo "Optional:"
    echo "  --client-name        Certificate CN (default: client-YYYYMMDD-HHMMSS)"
    echo "  --cert-validity      Validity in days, 1-3650 (default: 365)"
    echo "  --helper-version     aws_signing_helper version (default: 1.4.0)"
    exit 1
}

while [[ $# -gt 0 ]]; do
    case $1 in
        --trust-anchor-arn) TRUST_ANCHOR_ARN="$2"; shift 2 ;;
        --profile-arn)      PROFILE_ARN="$2";      shift 2 ;;
        --role-arn)         ROLE_ARN="$2";          shift 2 ;;
        --client-name)      CLIENT_NAME="$2";       shift 2 ;;
        --cert-validity)
            CERT_VALIDITY_DAYS="$2"
            if ! [[ "$CERT_VALIDITY_DAYS" =~ ^[0-9]+$ ]] || \
               [ "$CERT_VALIDITY_DAYS" -lt 1 ] || [ "$CERT_VALIDITY_DAYS" -gt 3650 ]; then
                error "cert-validity must be between 1 and 3650"
            fi
            shift 2 ;;
        --helper-version)   SIGNING_HELPER_VERSION="$2"; shift 2 ;;
        --help)             usage ;;
        *)                  error "Unknown parameter: $1" ;;
    esac
done

[[ -z "$TRUST_ANCHOR_ARN" || -z "$PROFILE_ARN" || -z "$ROLE_ARN" ]] && {
    error "Missing required parameters. Run with --help for usage."
}

[[ -f "$CA_KEY" && -f "$CA_CERT" ]] || error "CA not found. Run ./setup-ca.sh first."

command -v openssl &>/dev/null || error "OpenSSL is not installed"
command -v aws    &>/dev/null || error "AWS CLI is not installed"
aws sts get-caller-identity &>/dev/null || error "AWS CLI not configured or lacks permissions"

OUT_DIR="./client-${CLIENT_NAME}"
mkdir -p "$OUT_DIR"

info "Generating client private key..."
openssl genrsa -out "$OUT_DIR/${CLIENT_NAME}-private-key.pem" 2048
chmod 600 "$OUT_DIR/${CLIENT_NAME}-private-key.pem"

info "Generating Certificate Signing Request..."
openssl req -new \
    -key "$OUT_DIR/${CLIENT_NAME}-private-key.pem" \
    -out "$OUT_DIR/${CLIENT_NAME}.csr" \
    -subj "/C=US/ST=Washington/L=Seattle/O=MyOrg/OU=IT/CN=${CLIENT_NAME}"

info "Signing client certificate with local CA..."
openssl x509 -req \
    -in "$OUT_DIR/${CLIENT_NAME}.csr" \
    -CA "$CA_CERT" \
    -CAkey "$CA_KEY" \
    -CAcreateserial \
    -out "$OUT_DIR/${CLIENT_NAME}-certificate.pem" \
    -days "$CERT_VALIDITY_DAYS" \
    -sha256 \
    -extfile <(printf "extendedKeyUsage=clientAuth\nbasicConstraints=CA:FALSE")

info "Downloading aws_signing_helper..."
PLATFORM=$(uname -s)
ARCH=$(uname -m)

case "$PLATFORM" in
    Linux)
        [[ "$ARCH" == "x86_64" ]] || error "Unsupported Linux arch: $ARCH"
        HELPER_URL="https://rolesanywhere.amazonaws.com/releases/${SIGNING_HELPER_VERSION}/X86_64/Linux/aws_signing_helper"
        ;;
    Darwin)
        if   [[ "$ARCH" == "x86_64" ]]; then HELPER_URL="https://rolesanywhere.amazonaws.com/releases/${SIGNING_HELPER_VERSION}/X86_64/Darwin/aws_signing_helper"
        elif [[ "$ARCH" == "arm64"  ]]; then HELPER_URL="https://rolesanywhere.amazonaws.com/releases/${SIGNING_HELPER_VERSION}/ARM64/Darwin/aws_signing_helper"
        else error "Unsupported macOS arch: $ARCH"; fi
        ;;
    *) error "Unsupported platform: $PLATFORM" ;;
esac

curl -fsSL -o "$OUT_DIR/aws_signing_helper" "$HELPER_URL"
chmod +x "$OUT_DIR/aws_signing_helper"

info "Creating helper scripts..."

cat > "$OUT_DIR/get-credentials.sh" << EOF
#!/bin/bash
# Retrieves temporary AWS credentials via IAM Roles Anywhere
SCRIPT_DIR="\$(cd "\$(dirname "\${BASH_SOURCE[0]}")" && pwd)"
"\$SCRIPT_DIR/aws_signing_helper" credential-process \\
    --certificate "\$SCRIPT_DIR/${CLIENT_NAME}-certificate.pem" \\
    --private-key "\$SCRIPT_DIR/${CLIENT_NAME}-private-key.pem" \\
    --trust-anchor-arn "$TRUST_ANCHOR_ARN" \\
    --profile-arn "$PROFILE_ARN" \\
    --role-arn "$ROLE_ARN"
EOF
chmod +x "$OUT_DIR/get-credentials.sh"

cat > "$OUT_DIR/test-credentials.sh" << EOF
#!/bin/bash
SCRIPT_DIR="\$(cd "\$(dirname "\${BASH_SOURCE[0]}")" && pwd)"
echo "Fetching temporary credentials..."
CREDS=\$("\$SCRIPT_DIR/get-credentials.sh")
if [[ \$? -ne 0 ]]; then echo "Failed to get credentials"; exit 1; fi

export AWS_ACCESS_KEY_ID=\$(echo "\$CREDS"     | jq -r '.AccessKeyId')
export AWS_SECRET_ACCESS_KEY=\$(echo "\$CREDS" | jq -r '.SecretAccessKey')
export AWS_SESSION_TOKEN=\$(echo "\$CREDS"      | jq -r '.SessionToken')

echo "Caller identity:"
aws sts get-caller-identity
echo ""
echo "S3 buckets:"
aws s3 ls
EOF
chmod +x "$OUT_DIR/test-credentials.sh"

cat > "$OUT_DIR/setup-summary.txt" << EOF
IAM Roles Anywhere Client — Setup Summary
==========================================
Generated : $(date)
Client    : $CLIENT_NAME
Cert valid: $CERT_VALIDITY_DAYS days

Files:
  ${CLIENT_NAME}-private-key.pem   — private key (keep secret)
  ${CLIENT_NAME}-certificate.pem   — client certificate
  aws_signing_helper               — credential helper binary
  get-credentials.sh               — fetch temp AWS credentials
  test-credentials.sh              — end-to-end test

AWS Resources:
  Trust Anchor ARN : $TRUST_ANCHOR_ARN
  Profile ARN      : $PROFILE_ARN
  Role ARN         : $ROLE_ARN

Usage:
  cd $OUT_DIR
  ./test-credentials.sh
EOF

info ""
info "Client setup complete! Output: $OUT_DIR"
info "  Run: cd $OUT_DIR && ./test-credentials.sh"
warn "Never commit the private key to version control."
