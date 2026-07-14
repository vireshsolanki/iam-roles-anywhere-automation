# Security Policy

> **Before reading this doc:** "Role" and "Profile" refer to several different
> things in this project (IAM Role vs. Roles Anywhere Profile vs. local AWS
> CLI Profile). See the **[Terminology](README.md#terminology--read-this-before-anything-else-confuses-you)**
> section in the main README first if any of the sections below are unclear —
> it'll save you a lot of confusion.

## Threat Model

### What We Protect Against

✅ **Permanent access-key compromise**  
- Traditional IAM users need long-lived secret keys. A single leak = permanent account access for the attacker.
- **This project:** Temporary credentials only (15 min – 12 hours). Even if a credential is stolen, it expires automatically.

✅ **Laptop-loss compromising the entire CA**  
- Local CA: private key on laptop. Stolen laptop = all certificates become untrusted forever.
- **This project (Central CA):** Private key in AWS KMS (un-extractable). Stolen laptop = nothing, because the key never leaves AWS.

✅ **Unauthorized users obtaining certificates**  
- A malicious person should not be able to mint a certificate for an identity they don't control.
- **This project:** Certificate subject (CN) is set server-side by the authenticated admin or public endpoint, never from client input. Certificate identity cannot be spoofed.

✅ **Revocation delays**  
- Revoke a compromised cert, but it's still valid for minutes/hours while old instances of the cert circulate.
- **This project:** AWS enforces CRL immediately (within seconds). Revoked certificates are rejected even if the client app has a cached copy.

✅ **Unauditable credential issuance**  
- Who got credentials? When? For what identity? This should be logged.
- **This project:** DynamoDB tracks every certificate: serial, common_name, issued_at, not_after, revoked_at, revoked_reason, renewed_from. Every action is traced.

### What We Don't Protect Against

❌ **Compromised IAM Roles**  
- If an attacker gains control of an IAM role that Roles Anywhere delegates to, they can abuse all credentials issued for that role.
- **Mitigation:** Use fine-grained IAM policies (least-privilege), monitor CloudTrail, rotate roles regularly.

❌ **Shared API key leaks (Central CA public endpoint)**  
- If the shared secret (API key for public cert requests) is leaked, anyone can request certificates.
- **Mitigation:** Use strong random keys (20+ chars), rotate regularly if suspected leak, restrict network access (VPC endpoints, IP whitelisting).

❌ **Admin credential compromise**  
- If an AWS admin's credentials are stolen, attacker can modify the CA configuration (change validity, policies, profiles).
- **Mitigation:** Enable MFA, use temporary credentials (SSO / roles), monitor CloudTrail for unexpected changes.

❌ **Certificate private-key compromise (client-side)**  
- If a developer's private key (`alice-private-key.pem`) is stolen, the attacker can impersonate that developer until the cert expires or is revoked.
- **Mitigation:** Encrypt private keys at rest, restrict file permissions (chmod 600), rotate certs regularly, revoke immediately if compromised.

❌ **Cryptographic weaknesses**  
- This project uses RSA-2048 + SHA-256, both industry-standard. Future cryptanalysis could theoretically weaken these (very unlikely in practice, but possible).
- **Mitigation:** Plan to rotate to RSA-4096 or ECDSA if regulatory requirements change.

---

## Security Best Practices

### For Local CA Deployments

1. **Backup the private key**
   ```bash
   cp -v ./ca/ca-private-key.pem /secure/backup/location/
   chmod 600 /secure/backup/location/ca-private-key.pem
   ```
   Loss of this key = permanent CA compromise.

2. **Encrypt the laptop**
   - Full-disk encryption (FileVault on macOS, BitLocker on Windows, LUKS on Linux)
   - If stolen, encrypted disk is safe

3. **Restrict file permissions**
   ```bash
   chmod 700 ./ca                           # Only owner can list/modify
   chmod 600 ./ca/ca-private-key.pem        # Only owner can read
   chmod 600 ./client-*/\*-private-key.pem  # Same for client keys
   ```

4. **Audit certificate issuance**
   ```bash
   # See what certs you've issued (stored in ./ca/certs/ or CloudFormation stack)
   ls -la ./client-*/*-certificate.pem
   ```

### For Central CA Deployments (Production)

1. **Restrict KMS key permissions**
   ```json
   {
     "Sid": "AllowIssuerLambda",
     "Effect": "Allow",
     "Principal": { "AWS": "arn:aws:iam::ACCOUNT:role/central-ca-lambda-role" },
     "Action": ["kms:Sign", "kms:GetPublicKey"],
     "Resource": "*"
   }
   ```
   Only the Lambda can sign; admins cannot extract the private key.

2. **Protect the CloudFormation template**
   - Don't commit `central-ca-stack.yml` to a public repo without review
   - Sensitive data: API key value (ApiKeyValue parameter)
   - Store in a private repo or AWS Secrets Manager

3. **Rotate the public API key**
   - If the shared secret (ApiKeyValue) is ever suspected leaked
   - Update the stack parameter, wait for `UPDATE_COMPLETE`
   - All subsequent requests require the new key

4. **Monitor CloudWatch Logs**
   ```bash
   # Lambda issuer logs (successful signs, failures, stack traces)
   aws logs tail /aws/lambda/central-ca-issuer --follow
   
   # Watch for repeated failures (potential attack attempts)
   aws logs filter-log-events --log-group-name /aws/lambda/central-ca-issuer \
     --filter-pattern "ERROR"
   ```

5. **Audit DynamoDB**
   ```bash
   # See all issued, renewed, revoked certificates
   aws dynamodb scan --table-name central-ca-certificates \
     --filter-expression "attribute_exists(#s)" \
     --expression-attribute-names '{"#s": "serial"}' \
     --output table
   ```

6. **CloudTrail for admin actions**
   ```bash
   # Log all CloudFormation changes, Lambda invocations, KMS key usage
   aws cloudtrail lookup-events \
     --lookup-attributes AttributeKey=ResourceName,AttributeValue=central-ca-stack \
     --output table
   ```

7. **Protect client private keys**
   ```bash
   # After downloading client-bob/bob-private-key.pem, ensure it's secure
   chmod 600 client-bob/bob-private-key.pem
   # Don't commit to git (already in .gitignore)
   # Encrypt for long-term storage
   ```

### For All Deployments

1. **Least-privilege IAM policies**
   - Don't attach ReadOnlyAccess or full S3 access to roles
   - Scope policies to the resources that role actually needs
   - Use resource-based conditions (IP, time-of-day, MFA)

2. **Certificate rotation**
   - Rotate client certificates every 90–365 days (depends on sensitivity)
   - Use the `renew` action to issue a fresh cert with the same identity
   - Old cert is revoked automatically

3. **Session duration limits**
   - Shorter duration = faster secret credential expiry
   - 15 min for sensitive operations (deployments, IAM changes)
   - 12 hours for normal workloads
   - Set per-role in the Profile configuration

4. **Revocation on employee departure**
   ```bash
   # Admin revokes alice's cert immediately on exit
   aws lambda invoke \
     --function-name central-ca-issuer \
     --payload '{"action":"revoke", "serial":"<alice serial>"}' \
     /dev/null
   ```

5. **Monitor for unusual activity**
   - CloudTrail: unexpected API calls with unusual CNs
   - DynamoDB: unexpected revocations or rapid re-issuances
   - CloudWatch: Lambda errors or timeouts

---

## Incident Response

### If a client private key is compromised

1. **Revoke immediately**
   ```bash
   aws lambda invoke \
     --function-name central-ca-issuer \
     --payload '{"action":"revoke", "serial":"<serial>"}' \
     /dev/null
   ```

2. **Renew for that identity**
   ```bash
   ./request-cert.sh \
     --lambda central-ca-issuer \
     --renew <old-serial> \
     --name alice ...
   ```

3. **Audit what happened**
   - Check CloudTrail for unexpected API calls during the window the key was exposed
   - Check DynamoDB for unauthorized certificate requests

### If the shared API key (public endpoint) is leaked

1. **Rotate immediately** (update the stack with a new ApiKeyValue)
2. **Revoke any suspicious certs** that were issued while the key was exposed
3. **Alert users** to refresh their credentials

### If the root CA private key is compromised (Local CA)

1. **Stop issuing certs immediately**
2. **Regenerate the CA** (`./setup-ca.sh`, delete `./ca/`)
3. **Update Trust Anchor** (redeploy `local-ca-stack.yml` with new CA cert)
4. **Revoke ALL existing certs** (they're now untrustworthy)
5. **Reissue for all users** (high-friction, but necessary)

### If the root CA private key is compromised (Central CA)

**This is very unlikely** (KMS keys are AWS-managed, un-extractable). If it happens:

1. **AWS incident response** (contact AWS Support immediately)
2. **Schedule KMS key deletion** (7–30 day waiting period)
3. **Create a new KMS key** with tighter permissions
4. **Update the stack** to point to the new key
5. **Revoke ALL existing certs** and reissue with new key

---

## Compliance & Auditing

### Logging & Audit Trail

**DynamoDB records every certificate:**
```
serial       | common_name | status   | issued_at              | revoked_at | revoked_reason
-------------|-------------|----------|------------------------|------------|----------------
12345...789  | alice       | active   | 2026-07-14 10:15:00    | NULL       | NULL
12346...790  | alice       | revoked  | 2026-07-14 10:15:00    | 2026-07-14 | compromised
12347...791  | alice       | active   | 2026-07-14 10:16:00    | NULL       | renewed_from: 12346...790
```

**CloudTrail records admin actions:**
- `lambda:InvokeFunction` (who issued/revoked certs, when)
- `cloudformation:UpdateStack` (who modified CA config, when)
- `kms:Sign` (how many times the key was used)

### SOC 2 / Compliance Readiness

If your org requires SOC 2, ISO 27001, etc.:

✅ **Encryption in transit** (HTTPS API Gateway, IAM authentication)  
✅ **Encryption at rest** (KMS, DynamoDB encryption at rest)  
✅ **Access logging** (CloudTrail, DynamoDB, CloudWatch)  
✅ **Secret rotation** (certificate renewal, API key rotation)  
✅ **Audit trail** (DynamoDB + CloudTrail immutable)  
✅ **Least-privilege** (IAM policies, role restrictions)  

⚠️ **What you own:**
- Writing monthly audit reports from the logs
- Defining and enforcing certificate rotation policy
- Defining revocation procedures
- MFA enforcement for admins

See [central-ca/README.md](central-ca/README.md) for DynamoDB schema and audit queries.

---

## Reporting Security Vulnerabilities

If you discover a vulnerability in this code:

1. **Do NOT open a public GitHub issue** (it alerts attackers)
2. **Email:** vireshsolanki1157@gmail.com
3. **Include:**
   - Description of the vulnerability
   - Steps to reproduce
   - Impact (who/what can be compromised)
   - Suggested fix (if any)

We'll investigate, fix, and credit you in the release notes.

---

## Version & Dependencies

- **Python:** 3.12 (Lambda runtime)
- **Cryptography:** Built on standard library only (hashlib, base64)
  - No external crypto libraries (reduces supply-chain risk)
  - Hand-rolled X.509/DER encoder
  - All signing via AWS KMS (private key never in code)

---

**Last updated:** July 2026  
**Status:** Production Ready
