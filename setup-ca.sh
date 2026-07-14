#!/bin/bash
# Creates a local OpenSSL Root CA for IAM Roles Anywhere (free alternative to ACM PCA)

set -e

CA_DIR="./ca"
CA_KEY="$CA_DIR/ca-private-key.pem"
CA_CERT="$CA_DIR/ca-certificate.pem"
CA_VALIDITY_DAYS="${1:-3650}"  # Default: 10 years

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()    { echo -e "${GREEN}[INFO]${NC} $1"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $1"; }
error()   { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

command -v openssl &>/dev/null || error "OpenSSL is not installed"

if [[ -f "$CA_CERT" ]]; then
    warn "CA already exists at $CA_CERT — skipping creation."
    info "If you want a fresh CA, delete the ./ca directory and re-run."
    exit 0
fi

mkdir -p "$CA_DIR"
chmod 700 "$CA_DIR"

info "Generating Root CA private key..."
openssl genrsa -out "$CA_KEY" 4096
chmod 600 "$CA_KEY"

info "Generating self-signed Root CA certificate (valid $CA_VALIDITY_DAYS days)..."
openssl req -new -x509 \
    -key "$CA_KEY" \
    -out "$CA_CERT" \
    -days "$CA_VALIDITY_DAYS" \
    -subj "/C=US/ST=Washington/L=Seattle/O=MyOrg/OU=Security/CN=MyOrg-RootCA" \
    -extensions v3_ca \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign"

info "Root CA created successfully."
info "  Private key : $CA_KEY  (keep this secret)"
info "  Certificate : $CA_CERT (upload this to IAM Roles Anywhere)"
