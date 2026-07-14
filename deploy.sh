#!/bin/bash
# Full end-to-end deployment: creates local CA, deploys CloudFormation, issues client cert
# Usage: ./deploy.sh --stack-name <name> --project-name <name> --policy-arns <arns>

set -e

STACK_NAME="iam-roles-anywhere-poc"
PROJECT_NAME="MyRolesAnywhere"
POLICY_ARNS="arn:aws:iam::aws:policy/ReadOnlyAccess"
SESSION_DURATION=3600
CA_VALIDITY_DAYS=3650
CLIENT_NAME=""

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()    { echo -e "${GREEN}[INFO]${NC} $1"; }
step()    { echo -e "${CYAN}[STEP]${NC} $1"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $1"; }
error()   { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --stack-name       CloudFormation stack name (default: iam-roles-anywhere-poc)"
    echo "  --project-name     Resource name prefix (default: MyRolesAnywhere)"
    echo "  --policy-arns      Comma-separated IAM policy ARNs (default: ReadOnlyAccess)"
    echo "  --session-duration Session duration in seconds, 900-43200 (default: 3600)"
    echo "  --client-name      Client certificate name (default: auto-generated)"
    echo "  --help             Show this help"
    exit 0
}

while [[ $# -gt 0 ]]; do
    case $1 in
        --stack-name)       STACK_NAME="$2";       shift 2 ;;
        --project-name)     PROJECT_NAME="$2";     shift 2 ;;
        --policy-arns)      POLICY_ARNS="$2";      shift 2 ;;
        --session-duration) SESSION_DURATION="$2"; shift 2 ;;
        --client-name)      CLIENT_NAME="$2";      shift 2 ;;
        --help)             usage ;;
        *)                  error "Unknown option: $1" ;;
    esac
done

# ── Prerequisites ────────────────────────────────────────────────────────────
step "Checking prerequisites..."
command -v aws    &>/dev/null || error "AWS CLI not installed"
command -v openssl &>/dev/null || error "OpenSSL not installed"
command -v jq     &>/dev/null || error "jq not installed (needed for test-credentials.sh)"
aws sts get-caller-identity &>/dev/null || error "AWS CLI not configured or lacks permissions"
info "Prerequisites OK"

# ── Step 1: Create local Root CA ─────────────────────────────────────────────
step "Step 1/3 — Creating local Root CA..."
chmod +x setup-ca.sh
./setup-ca.sh "$CA_VALIDITY_DAYS"

CA_CERT_BODY=$(cat ./ca/ca-certificate.pem)

# ── Step 2: Deploy CloudFormation ────────────────────────────────────────────
step "Step 2/3 — Deploying CloudFormation stack: $STACK_NAME"
aws cloudformation deploy \
    --template-file local-ca-stack.yml \
    --stack-name "$STACK_NAME" \
    --parameter-overrides \
        ProjectName="$PROJECT_NAME" \
        CACertificateBody="$CA_CERT_BODY" \
        SessionDurationSeconds="$SESSION_DURATION" \
        IAMPolicyArns="$POLICY_ARNS" \
    --capabilities CAPABILITY_NAMED_IAM

info "Stack deployed successfully."

# ── Fetch stack outputs ───────────────────────────────────────────────────────
info "Fetching stack outputs..."
OUTPUTS=$(aws cloudformation describe-stacks \
    --stack-name "$STACK_NAME" \
    --query 'Stacks[0].Outputs' \
    --output json)

TRUST_ANCHOR_ARN=$(echo "$OUTPUTS" | jq -r '.[] | select(.OutputKey=="TrustAnchorArn") | .OutputValue')
PROFILE_ARN=$(echo "$OUTPUTS"      | jq -r '.[] | select(.OutputKey=="ProfileArn")      | .OutputValue')
ROLE_ARN=$(echo "$OUTPUTS"         | jq -r '.[] | select(.OutputKey=="RoleArn")         | .OutputValue')

info "Trust Anchor ARN : $TRUST_ANCHOR_ARN"
info "Profile ARN      : $PROFILE_ARN"
info "Role ARN         : $ROLE_ARN"

# ── Step 3: Issue client certificate ─────────────────────────────────────────
step "Step 3/3 — Setting up client certificate..."
chmod +x setup-client.sh

CLIENT_ARGS=(
    --trust-anchor-arn "$TRUST_ANCHOR_ARN"
    --profile-arn      "$PROFILE_ARN"
    --role-arn         "$ROLE_ARN"
)
[[ -n "$CLIENT_NAME" ]] && CLIENT_ARGS+=(--client-name "$CLIENT_NAME")

./setup-client.sh "${CLIENT_ARGS[@]}"

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  Deployment complete!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo "  CA certificate  : ./ca/ca-certificate.pem"
echo "  Stack name      : $STACK_NAME"
echo "  Trust Anchor    : $TRUST_ANCHOR_ARN"
echo "  Profile         : $PROFILE_ARN"
echo "  Role            : $ROLE_ARN"
echo ""
echo "  Next step — test your credentials:"
echo "    cd client-*"
echo "    ./test-credentials.sh"
echo ""
warn "Back up ./ca/ca-private-key.pem securely. Losing it means you cannot issue new client certs."
