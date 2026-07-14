"""
KMS-backed X.509 Certificate Authority primitives — standard library only.

The CA private key lives in AWS KMS and never leaves it. We DER-encode the
TBSCertificate (or CRL) by hand, SHA-256 it, and call kms:Sign on the digest;
the signature is wrapped into the final structure. No third-party packages, so
the Lambda deploys straight from CloudFormation with nothing to bundle.

The subject/issuer public keys are treated as opaque DER SubjectPublicKeyInfo
blobs (from KMS GetPublicKey for the CA, from the client's `openssl rsa -pubout`
for a user), so we never have to parse ASN.1 — only emit it.

NOTE: untested against live AWS from the authoring environment. After the first
deploy, bootstrap the CA and inspect it with `openssl x509 -text -noout`, then
verify an issued cert with `openssl verify -CAfile ca.pem client.pem` before use.
"""
import base64
import datetime
import hashlib
import os

import boto3

kms = boto3.client("kms")

_KMS_SIGNING_ALGORITHM = "RSASSA_PKCS1_V1_5_SHA_256"

# ── Minimal DER encoder ──────────────────────────────────────────────────────
def _der_len(n):
    if n < 0x80:
        return bytes([n])
    out = b""
    while n:
        out = bytes([n & 0xFF]) + out
        n >>= 8
    return bytes([0x80 | len(out)]) + out


def _tlv(tag, value):
    return bytes([tag]) + _der_len(len(value)) + value


def _seq(*parts):
    return _tlv(0x30, b"".join(parts))


def _set(*parts):
    return _tlv(0x31, b"".join(parts))


def _int(n):
    if n == 0:
        return _tlv(0x02, b"\x00")
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    if b[0] & 0x80:  # keep it positive
        b = b"\x00" + b
    return _tlv(0x02, b)


def _bitstring(data):
    return _tlv(0x03, b"\x00" + data)


def _octet(data):
    return _tlv(0x04, data)


def _oid(dotted):
    parts = [int(x) for x in dotted.split(".")]
    body = [40 * parts[0] + parts[1]]
    for p in parts[2:]:
        stack = [p & 0x7F]
        p >>= 7
        while p:
            stack.insert(0, (p & 0x7F) | 0x80)
            p >>= 7
        body.extend(stack)
    return _tlv(0x06, bytes(body))


def _utctime(dt):
    return _tlv(0x17, dt.strftime("%y%m%d%H%M%SZ").encode())


def _explicit(n, value):
    return _tlv(0xA0 | n, value)


# sha256WithRSAEncryption AlgorithmIdentifier (with NULL params)
_SIG_ALG = _seq(_oid("1.2.840.113549.1.1.11"), b"\x05\x00")


# ── X.509 building blocks ────────────────────────────────────────────────────
def _atv(oid, value, tag):
    return _seq(_oid(oid), _tlv(tag, value.encode()))


def _name(cn, org, country):
    return _seq(
        _set(_atv("2.5.4.6", country, 0x13)),   # C  (PrintableString)
        _set(_atv("2.5.4.10", org, 0x0C)),       # O  (UTF8String)
        _set(_atv("2.5.4.3", cn, 0x0C)),         # CN (UTF8String)
    )


def _validity(days):
    now = datetime.datetime.now(datetime.timezone.utc)
    not_before = now - datetime.timedelta(minutes=5)  # clock-skew cushion
    not_after = now + datetime.timedelta(days=days)
    return _seq(_utctime(not_before), _utctime(not_after))


def _extension(oid, value_der, critical=False):
    parts = [_oid(oid)]
    if critical:
        parts.append(_tlv(0x01, b"\xFF"))
    parts.append(_octet(value_der))
    return _seq(*parts)


def _key_id(spki_der):
    # Consistent key identifier (SHA-1 of the SPKI) used for both SKI and AKI.
    return hashlib.sha1(spki_der).digest()


def new_serial():
    return int.from_bytes(os.urandom(16), "big") | 1


# ── KMS signing ──────────────────────────────────────────────────────────────
def get_ca_spki(key_id):
    """CA public key as DER SubjectPublicKeyInfo (opaque blob)."""
    return kms.get_public_key(KeyId=key_id)["PublicKey"]


def _sign(key_id, tbs_der):
    digest = hashlib.sha256(tbs_der).digest()
    resp = kms.sign(
        KeyId=key_id,
        Message=digest,
        MessageType="DIGEST",
        SigningAlgorithm=_KMS_SIGNING_ALGORITHM,
    )
    return resp["Signature"]


# ── Public API ───────────────────────────────────────────────────────────────
def create_ca_certificate(key_id, cn, org, country, days):
    """Self-signed Root CA certificate, signed by the KMS key."""
    spki = get_ca_spki(key_id)
    ski = _key_id(spki)
    name = _name(cn, org, country)
    exts = _seq(
        _extension("2.5.29.19", _seq(_tlv(0x01, b"\xFF")), critical=True),      # basicConstraints CA:TRUE
        # keyUsage keyCertSign(bit5)+cRLSign(bit6): 1 unused bit, data 0x06
        _extension("2.5.29.15", _tlv(0x03, bytes([0x01, 0x06])), critical=True),
        _extension("2.5.29.14", _octet(ski)),                                    # subjectKeyIdentifier
    )
    tbs = _seq(
        _explicit(0, _int(2)),  # version v3
        _int(new_serial()),
        _SIG_ALG,
        name,                   # issuer == subject (self-signed)
        _validity(days),
        name,
        spki,
        _tlv(0xA3, exts),       # [3] extensions
    )
    cert = _seq(tbs, _SIG_ALG, _bitstring(_sign(key_id, tbs)))
    return _armor("CERTIFICATE", cert)


def sign_certificate(key_id, client_pubkey_pem, ca_cn, client_cn, org, country, days, serial):
    """Sign a client public key into an end-entity certificate.

    The subject CN is set by the (authenticated) caller, never read from client
    input, so nobody can obtain a cert for an identity they weren't authorized
    for. The issuer is the CA's own name so the chain validates against the
    Trust Anchor.
    """
    ca_spki = get_ca_spki(key_id)
    client_spki = _pem_to_der(client_pubkey_pem)
    exts = _seq(
        _extension("2.5.29.19", _seq(), critical=True),                          # basicConstraints CA:FALSE
        # keyUsage digitalSignature(bit0)+keyEncipherment(bit2): 5 unused bits, data 0xA0
        _extension("2.5.29.15", _tlv(0x03, bytes([0x05, 0xA0])), critical=True),
        _extension("2.5.29.37", _seq(_oid("1.3.6.1.5.5.7.3.2"))),                 # extKeyUsage clientAuth
        _extension("2.5.29.14", _octet(_key_id(client_spki))),                    # subjectKeyIdentifier
        _extension("2.5.29.35", _seq(_tlv(0x80, _key_id(ca_spki)))),              # authorityKeyIdentifier
    )
    tbs = _seq(
        _explicit(0, _int(2)),
        _int(serial),
        _SIG_ALG,
        _name(ca_cn, org, country),      # issuer  = CA subject
        _validity(days),
        _name(client_cn, org, country),  # subject = the user
        client_spki,
        _tlv(0xA3, exts),
    )
    cert = _seq(tbs, _SIG_ALG, _bitstring(_sign(key_id, tbs)))
    return _armor("CERTIFICATE", cert)


def build_crl(key_id, ca_cn, org, country, revoked, days_valid, crl_number):
    """KMS-signed CRL. `revoked` is a list of {serial:int, revoked_at:datetime}."""
    ca_spki = get_ca_spki(key_id)
    now = datetime.datetime.now(datetime.timezone.utc)
    entries = [
        _seq(_int(int(r["serial"])), _utctime(r["revoked_at"])) for r in revoked
    ]
    crl_exts = _tlv(
        0xA0,
        _seq(
            _extension("2.5.29.20", _int(crl_number)),                      # cRLNumber
            _extension("2.5.29.35", _seq(_tlv(0x80, _key_id(ca_spki)))),    # authorityKeyIdentifier
        ),
    )
    tbs_parts = [
        _int(1),  # version v2
        _SIG_ALG,
        _name(ca_cn, org, country),
        _utctime(now),
        _utctime(now + datetime.timedelta(days=days_valid)),
    ]
    if entries:
        tbs_parts.append(_seq(*entries))  # revokedCertificates (OPTIONAL — omit if none)
    tbs_parts.append(crl_exts)
    tbs = _seq(*tbs_parts)
    crl = _seq(tbs, _SIG_ALG, _bitstring(_sign(key_id, tbs)))
    return _armor("X509 CRL", crl)


# ── PEM helpers ──────────────────────────────────────────────────────────────
def _pem_to_der(pem_str):
    body = "".join(l for l in pem_str.strip().splitlines() if "-----" not in l)
    return base64.b64decode(body)


def _armor(label, der):
    b64 = base64.b64encode(der).decode()
    lines = "\n".join(b64[i : i + 64] for i in range(0, len(b64), 64))
    return f"-----BEGIN {label}-----\n{lines}\n-----END {label}-----\n".encode()
