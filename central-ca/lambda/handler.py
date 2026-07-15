"""
Central CA Lambda — the single always-on issuing authority.

Invoked directly with `aws lambda invoke` (no API Gateway, no static keys). The
caller's IAM permission to invoke this function IS the issuance access control,
and `aws lambda invoke` uses the default credential chain (SSO / role), so no
long-lived access keys are involved anywhere.

Actions (payload {"action": ...}):
  bootstrap : create the self-signed Root CA cert from the KMS key, store in S3.
  sign      : sign a client public key -> client certificate; record in DynamoDB.
  renew     : issue a fresh certificate for an EXISTING serial's common_name,
              then revoke the old serial (exactly one valid cert per identity
              at a time). Admin-only, not reachable over the HTTP API — the
              old serial alone isn't proof of key possession, so self-service
              renewal isn't safe without a stronger identity check.
  revoke    : mark an issued serial revoked in DynamoDB. Admin-only, not
              reachable over the HTTP API — a dev can request their own
              certificate there, but can never revoke or reissue anything,
              theirs or anyone else's.
  crl       : regenerate the CRL from revoked entries, store in S3, AND
              register it with Roles Anywhere (rolesanywhere:ImportCrl the
              first time, rolesanywhere:UpdateCrl after) so revocation is
              actually enforced by AWS -- writing crl.pem to S3 alone does
              nothing; Roles Anywhere only checks a CRL it has been told
              about. The Trust Anchor is found by name (no circular
              CloudFormation dependency needed), and the returned crlId is
              cached in DynamoDB so subsequent calls update in place.
  rotate_ca : re-self-sign a FRESH Root CA certificate from the SAME KMS key
              (bypasses the one-time bootstrap guard). Admin-only. The public
              key -- and therefore the AuthorityKeyIdentifier every existing
              client certificate was signed against -- doesn't change, so
              already-issued certificates keep validating once you update the
              Trust Anchor's X509CertificateData to this new certificate. Use
              this before CACertValidityDays runs out; there is no automatic
              renewal, since _bootstrap() deliberately refuses to ever
              overwrite the CA cert on its own.

DynamoDB (CertTable) is the single source of truth for every certificate ever
issued: serial, common_name, status (active/revoked), issued_at, not_after,
and (for renewals) renewed_from linking to the serial it replaced.

There are three ways this function is invoked, auto-detected from the event shape:

  1. CloudFormation custom resource (has "RequestType"/"ResponseURL") — the
     stack template invokes it directly (ServiceToken: the function's own
     ARN) so the Root CA certificate is created automatically on stack
     deploy. Routed to _cfn_bootstrap. See the CABootstrap resource in
     central-ca-stack.yml.

  2. API Gateway REST API (Lambda proxy — has top-level "httpMethod") — a
     public HTTPS endpoint (see the ApiEndpoint output) that lets a caller
     with NO AWS credentials request their OWN certificate. Authentication is
     handled ENTIRELY by API Gateway: the method requires an API key (the
     "x-api-key" header), so only requests with a valid key ever reach this
     function — there is no secret check in this code. This function is not
     directly invokable by anyone except API Gateway (its resource policy
     only trusts apigateway.amazonaws.com) and the admin (path 3, via IAM).
     "sign" is the ONLY action allowed here — every other action, including
     "revoke", returns 403 even with a valid key. A dev can obtain a
     certificate; they cannot revoke or reissue anything, theirs or anyone
     else's. Routed to _http_handler.

  3. Direct `aws lambda invoke` with a raw {"action": ...} payload — the
     admin's own tooling (request-cert.sh --lambda, the Lambda console Test
     tab). IAM-authenticated by the caller's own credentials; no key needed
     since lambda:InvokeFunction permission on this function is itself the
     access control. Supports all five actions, including "bootstrap",
     "renew", and "crl" which are intentionally never exposed publicly.

Environment: CA_KEY_ID, TABLE_NAME, BUCKET_NAME, PROJECT_NAME, CA_CN, CA_ORG,
CA_COUNTRY.
"""
import base64
import datetime
import json
import os
import urllib.request

import boto3

import kms_ca

CA_KEY_ID = os.environ["CA_KEY_ID"]
TABLE_NAME = os.environ["TABLE_NAME"]
BUCKET_NAME = os.environ["BUCKET_NAME"]
PROJECT_NAME = os.environ["PROJECT_NAME"]
CA_CN = os.environ.get("CA_CN", "Central-RootCA")
CA_ORG = os.environ.get("CA_ORG", "MyOrg")
CA_COUNTRY = os.environ.get("CA_COUNTRY", "US")

CA_CERT_KEY = "ca-certificate.pem"
CRL_KEY = "crl.pem"
CRL_ID_RECORD_KEY = "__crl_id__"
HTTP_ALLOWED_ACTIONS = {"sign"}  # issuance only -- devs can never revoke/renew/reissue over this path

s3 = boto3.client("s3")
table = boto3.resource("dynamodb").Table(TABLE_NAME)
rolesanywhere = boto3.client("rolesanywhere")


def handler(event, context):
    if isinstance(event, dict) and "RequestType" in event and "ResponseURL" in event:
        return _cfn_bootstrap(event, context)

    if _is_http_event(event):
        return _http_handler(event)

    action = (event or {}).get("action")
    try:
        if action == "bootstrap":
            return _bootstrap(int(event.get("days", 3650)))
        if action == "sign":
            return _sign(event)
        if action == "renew":
            return _renew(event)
        if action == "revoke":
            return _revoke(event["serial"])
        if action == "crl":
            return _crl(int(event.get("days", 7)))
        if action == "rotate_ca":
            return _rotate_ca(int(event.get("days", 3650)))
        return {"error": f"unknown action: {action!r}"}
    except KeyError as exc:
        return {"error": f"missing field: {exc}"}
    except Exception as exc:  # CloudWatch has the traceback
        return {"error": str(exc)}


# ── HTTP API (API Gateway REST proxy; API-key auth is enforced upstream) ────
def _is_http_event(event):
    if not isinstance(event, dict):
        return False
    # API Gateway REST proxy => top-level "httpMethod";
    # Function URL / HTTP API v2 => requestContext.http (kept for compatibility).
    return "httpMethod" in event or "http" in event.get("requestContext", {})


def _http_handler(event):
    # No secret check here on purpose: API Gateway already rejected any request
    # without a valid API key before it reached us. We only restrict WHICH
    # actions are allowed over the public path -- "sign" and nothing else.
    # A dev can request a certificate; they cannot revoke or reissue anything,
    # theirs or anyone else's. All lifecycle management past initial issuance
    # (revoke, renew, rotate_ca, crl, bootstrap) is admin-only, direct-invoke.
    try:
        body = json.loads(event.get("body") or "{}")
    except json.JSONDecodeError:
        return _http_response(400, {"error": "body must be valid JSON"})

    action = body.get("action")
    if action not in HTTP_ALLOWED_ACTIONS:
        return _http_response(403, {"error": f"action {action!r} is not available over the HTTP endpoint"})

    try:
        result = _sign(body)
        return _http_response(200, result)
    except KeyError as exc:
        return _http_response(400, {"error": f"missing field: {exc}"})
    except Exception as exc:  # CloudWatch has the traceback
        return _http_response(500, {"error": str(exc)})


def _http_response(status, payload):
    return {
        "statusCode": status,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(payload),
    }


# ── CloudFormation custom resource (auto-bootstrap on stack deploy) ─────────
def _cfn_bootstrap(event, context):
    physical_id = event.get("PhysicalResourceId") or "central-ca-root-cert"
    try:
        if event["RequestType"] in ("Create", "Update"):
            days = int(event.get("ResourceProperties", {}).get("Days", 3650))
            if _s3_exists(CA_CERT_KEY):
                ca_pem = _get_ca_cert().decode()  # idempotent: reuse the existing CA
            else:
                ca_pem = kms_ca.create_ca_certificate(CA_KEY_ID, CA_CN, CA_ORG, CA_COUNTRY, days).decode()
                s3.put_object(Bucket=BUCKET_NAME, Key=CA_CERT_KEY, Body=ca_pem.encode())
            _send_cfn_response(event, context, "SUCCESS", {"CACertificate": ca_pem}, physical_id)
        else:  # Delete: never destroy CA material automatically
            _send_cfn_response(event, context, "SUCCESS", {}, physical_id)
    except Exception as exc:  # noqa: BLE001 — must always respond, or the stack hangs
        _send_cfn_response(event, context, "FAILED", {}, physical_id, reason=str(exc))


def _send_cfn_response(event, context, status, data, physical_id, reason=None):
    body = json.dumps(
        {
            "Status": status,
            "Reason": reason or f"See CloudWatch Log Stream: {context.log_stream_name}",
            "PhysicalResourceId": physical_id,
            "StackId": event["StackId"],
            "RequestId": event["RequestId"],
            "LogicalResourceId": event["LogicalResourceId"],
            "NoEcho": False,
            "Data": data,
        }
    ).encode()
    req = urllib.request.Request(
        event["ResponseURL"], data=body, method="PUT", headers={"Content-Type": ""}
    )
    urllib.request.urlopen(req)


# ── Actions ──────────────────────────────────────────────────────────────────
def _bootstrap(days):
    if _s3_exists(CA_CERT_KEY):
        return {"error": "CA certificate already exists; refusing to overwrite"}
    ca_pem = kms_ca.create_ca_certificate(CA_KEY_ID, CA_CN, CA_ORG, CA_COUNTRY, days)
    s3.put_object(Bucket=BUCKET_NAME, Key=CA_CERT_KEY, Body=ca_pem)
    return {"ca_certificate": ca_pem.decode(), "s3": f"s3://{BUCKET_NAME}/{CA_CERT_KEY}"}


def _rotate_ca(days):
    # Deliberately bypasses _bootstrap()'s "refuse to overwrite" guard -- this
    # IS the overwrite, done on purpose when the current CA cert is nearing
    # CACertValidityDays expiry. Same KMS key, so the public key (and every
    # existing client cert's AuthorityKeyIdentifier) is unchanged; only the
    # self-signed wrapper certificate is new.
    if not 1 <= days <= 3650:
        return {"error": "days must be between 1 and 3650"}
    ca_pem = kms_ca.create_ca_certificate(CA_KEY_ID, CA_CN, CA_ORG, CA_COUNTRY, days)
    s3.put_object(Bucket=BUCKET_NAME, Key=CA_CERT_KEY, Body=ca_pem)
    return {
        "ca_certificate": ca_pem.decode(),
        "s3": f"s3://{BUCKET_NAME}/{CA_CERT_KEY}",
        "action_required": (
            "This new certificate is NOT yet trusted by AWS. Update the Trust "
            "Anchor's X509CertificateData to this certificate (console: IAM "
            "Roles Anywhere -> Trust anchors -> edit; or a CloudFormation "
            "update) for it to take effect. Existing client certificates "
            "remain valid once you do -- they were signed by the same KMS "
            "key this new cert also wraps."
        ),
    }


def _sign(event):
    common_name = event["common_name"]
    public_key = event["public_key"]  # PEM SubjectPublicKeyInfo from the client
    days = int(event.get("days", 365))
    if not 1 <= days <= 3650:
        return {"error": "days must be between 1 and 3650"}
    return _issue(common_name, public_key, days)


def _renew(event):
    old_serial = str(event["serial"])
    public_key = event["public_key"]  # a fresh keypair, same as a new sign
    days = int(event.get("days", 365))
    if not 1 <= days <= 3650:
        return {"error": "days must be between 1 and 3650"}

    old_item = table.get_item(Key={"serial": old_serial}).get("Item")
    if not old_item:
        raise KeyError(old_serial)
    if old_item.get("status") != "active":
        return {"error": f"serial {old_serial} is not active (status={old_item.get('status')!r}); cannot renew"}

    # CN comes from the CA's own record of the old cert, never from the
    # renewal request — same non-negotiable rule as _sign: identity is
    # never trusted from client-supplied input.
    common_name = old_item["common_name"]
    result = _issue(common_name, public_key, days, renewed_from=old_serial)

    table.update_item(
        Key={"serial": old_serial},
        UpdateExpression="SET #s = :r, revoked_at = :t, revoked_reason = :reason",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={":r": "revoked", ":t": _now_iso(), ":reason": "renewed"},
    )
    return result


def _issue(common_name, public_key, days, renewed_from=None):
    serial = kms_ca.new_serial()
    cert_pem = kms_ca.sign_certificate(
        CA_KEY_ID, public_key, CA_CN, common_name, CA_ORG, CA_COUNTRY, days, serial
    )
    not_after = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=days)
    item = {
        "serial": str(serial),
        "common_name": common_name,
        "status": "active",
        "issued_at": _now_iso(),
        "not_after": not_after.isoformat(),
    }
    if renewed_from:
        item["renewed_from"] = renewed_from
    table.put_item(Item=item)
    return {"serial": str(serial), "common_name": common_name, "certificate": cert_pem.decode()}


def _revoke(serial):
    serial = str(serial)
    if not table.get_item(Key={"serial": serial}).get("Item"):
        raise KeyError(serial)
    table.update_item(
        Key={"serial": serial},
        UpdateExpression="SET #s = :r, revoked_at = :t",
        ExpressionAttributeNames={"#s": "status"},
        ExpressionAttributeValues={":r": "revoked", ":t": _now_iso()},
    )
    return {"serial": serial, "status": "revoked"}


def _crl(days_valid):
    revoked = []
    kwargs = {
        "FilterExpression": "#s = :r",
        "ExpressionAttributeNames": {"#s": "status"},
        "ExpressionAttributeValues": {":r": "revoked"},
    }
    while True:
        scan = table.scan(**kwargs)
        for item in scan.get("Items", []):
            revoked.append(
                {"serial": int(item["serial"]), "revoked_at": _parse_iso(item["revoked_at"])}
            )
        if "LastEvaluatedKey" not in scan:
            break
        kwargs["ExclusiveStartKey"] = scan["LastEvaluatedKey"]

    crl_number = _next_crl_number()
    crl_pem = kms_ca.build_crl(CA_KEY_ID, CA_CN, CA_ORG, CA_COUNTRY, revoked, days_valid, crl_number)
    s3.put_object(Bucket=BUCKET_NAME, Key=CRL_KEY, Body=crl_pem)
    registration = _register_crl_with_roles_anywhere(crl_pem)
    return {
        "revoked_count": len(revoked),
        "crl_number": crl_number,
        "s3": f"s3://{BUCKET_NAME}/{CRL_KEY}",
        "roles_anywhere_registration": registration,
    }


# ── Roles Anywhere CRL registration (this is what makes revocation real) ────
def _register_crl_with_roles_anywhere(crl_pem):
    crl_der = _pem_to_der(crl_pem.decode())
    existing = table.get_item(Key={"serial": CRL_ID_RECORD_KEY}).get("Item")
    if existing and existing.get("crl_id"):
        rolesanywhere.update_crl(crlId=existing["crl_id"], crlData=crl_der)
        return {"action": "updated", "crl_id": existing["crl_id"]}

    trust_anchor_arn = _find_trust_anchor_arn()
    if not trust_anchor_arn:
        return {
            "action": "skipped",
            "reason": (
                "no Trust Anchor found (looked for a Roles Anywhere trust "
                "anchor named "
                f"'{PROJECT_NAME}-TrustAnchor'). CRL was written to S3 but "
                "NOT registered with AWS -- revocation is not yet enforced. "
                "Re-run 'crl' after the Trust Anchor exists."
            ),
        }
    resp = rolesanywhere.import_crl(
        name=f"{PROJECT_NAME}-crl",
        crlData=crl_der,
        trustAnchorArn=trust_anchor_arn,
        enabled=True,
    )
    crl_id = resp.get("crlId") or resp.get("crl", {}).get("crlId")
    table.put_item(Item={"serial": CRL_ID_RECORD_KEY, "crl_id": crl_id})
    return {"action": "imported", "crl_id": crl_id}


def _find_trust_anchor_arn():
    target_name = f"{PROJECT_NAME}-TrustAnchor"
    next_token = None
    while True:
        kwargs = {"nextToken": next_token} if next_token else {}
        resp = rolesanywhere.list_trust_anchors(**kwargs)
        for ta in resp.get("trustAnchors", []):
            if ta.get("name") == target_name:
                return ta.get("trustAnchorArn")
        next_token = resp.get("nextToken")
        if not next_token:
            return None


# ── Helpers ──────────────────────────────────────────────────────────────────
def _s3_exists(key):
    try:
        s3.head_object(Bucket=BUCKET_NAME, Key=key)
        return True
    except s3.exceptions.ClientError:
        return False


def _pem_to_der(pem_str):
    body = "".join(line for line in pem_str.strip().splitlines() if "-----" not in line)
    return base64.b64decode(body)


def _next_crl_number():
    resp = table.update_item(
        Key={"serial": "__crl_number__"},
        UpdateExpression="ADD crl_counter :one",
        ExpressionAttributeValues={":one": 1},
        ReturnValues="UPDATED_NEW",
    )
    return int(resp["Attributes"]["crl_counter"])


def _now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _parse_iso(value):
    return datetime.datetime.fromisoformat(value)
