"""
Central CA Lambda — the single always-on issuing authority.

Invoked directly with `aws lambda invoke` (no API Gateway, no static keys). The
caller's IAM permission to invoke this function IS the issuance access control,
and `aws lambda invoke` uses the default credential chain (SSO / role), so no
long-lived access keys are involved anywhere.

There are three ways this function is invoked, auto-detected from the event shape:

  1. CloudFormation custom resource (has "RequestType"/"ResponseURL") — the
     stack template invokes it directly (ServiceToken: the function's own
     ARN) so the Root CA certificate is created automatically on stack
     deploy. Routed to _cfn_bootstrap. See the CABootstrap resource in
     central-ca-stack.yml.

  2. Lambda Function URL (has "requestContext"."http") — a public HTTPS
     endpoint (see the FunctionUrl output) that lets a caller with NO AWS
     credentials request/revoke a certificate, gated by a shared secret
     (API_SECRET env var) checked against the "x-api-key" header. Only
     "sign" and "revoke" are reachable this way — "bootstrap" and "crl" stay
     admin-only via direct invoke, since a dev has no legitimate reason to
     trigger either. Routed to _url_handler.

  3. Direct `aws lambda invoke` with a raw {"action": ...} payload — the
     admin's own tooling (request-cert.sh --lambda, the Lambda console Test
     tab). IAM-authenticated by the caller's own credentials; no secret
     needed since lambda:InvokeFunction permission on this function is
     itself the access control. Supports all four actions, including
     "bootstrap" and "crl" which are intentionally never exposed publicly.

Environment: CA_KEY_ID, TABLE_NAME, BUCKET_NAME, CA_CN, CA_ORG, CA_COUNTRY,
API_SECRET (only required for path 2).
"""
import datetime
import hmac
import json
import os
import urllib.request

import boto3

import kms_ca

CA_KEY_ID = os.environ["CA_KEY_ID"]
TABLE_NAME = os.environ["TABLE_NAME"]
BUCKET_NAME = os.environ["BUCKET_NAME"]
CA_CN = os.environ.get("CA_CN", "Central-RootCA")
CA_ORG = os.environ.get("CA_ORG", "MyOrg")
CA_COUNTRY = os.environ.get("CA_COUNTRY", "US")
API_SECRET = os.environ.get("API_SECRET", "")

CA_CERT_KEY = "ca-certificate.pem"
CRL_KEY = "crl.pem"
URL_ALLOWED_ACTIONS = {"sign", "revoke"}

s3 = boto3.client("s3")
table = boto3.resource("dynamodb").Table(TABLE_NAME)


def handler(event, context):
    if isinstance(event, dict) and "RequestType" in event and "ResponseURL" in event:
        return _cfn_bootstrap(event, context)

    if isinstance(event, dict) and "http" in event.get("requestContext", {}):
        return _url_handler(event)

    action = (event or {}).get("action")
    try:
        if action == "bootstrap":
            return _bootstrap(int(event.get("days", 3650)))
        if action == "sign":
            return _sign(event)
        if action == "revoke":
            return _revoke(event["serial"])
        if action == "crl":
            return _crl(int(event.get("days", 7)))
        return {"error": f"unknown action: {action!r}"}
    except KeyError as exc:
        return {"error": f"missing field: {exc}"}
    except Exception as exc:  # CloudWatch has the traceback
        return {"error": str(exc)}


# ── Lambda Function URL (public HTTPS, shared-secret auth) ──────────────────
def _url_handler(event):
    headers = {k.lower(): v for k, v in (event.get("headers") or {}).items()}
    supplied = headers.get("x-api-key", "")
    if not API_SECRET or not hmac.compare_digest(supplied, API_SECRET):
        return _http_response(403, {"error": "invalid or missing x-api-key"})

    try:
        body = json.loads(event.get("body") or "{}")
    except json.JSONDecodeError:
        return _http_response(400, {"error": "body must be valid JSON"})

    action = body.get("action")
    if action not in URL_ALLOWED_ACTIONS:
        return _http_response(403, {"error": f"action {action!r} is not available over the public endpoint"})

    try:
        if action == "sign":
            result = _sign(body)
        else:
            result = _revoke(body["serial"])
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


def _sign(event):
    common_name = event["common_name"]
    public_key = event["public_key"]  # PEM SubjectPublicKeyInfo from the client
    days = int(event.get("days", 365))
    if not 1 <= days <= 3650:
        return {"error": "days must be between 1 and 3650"}

    serial = kms_ca.new_serial()
    cert_pem = kms_ca.sign_certificate(
        CA_KEY_ID, public_key, CA_CN, common_name, CA_ORG, CA_COUNTRY, days, serial
    )
    not_after = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=days)
    table.put_item(
        Item={
            "serial": str(serial),
            "common_name": common_name,
            "status": "active",
            "issued_at": _now_iso(),
            "not_after": not_after.isoformat(),
        }
    )
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
    return {"revoked_count": len(revoked), "crl_number": crl_number, "s3": f"s3://{BUCKET_NAME}/{CRL_KEY}"}


# ── Helpers ──────────────────────────────────────────────────────────────────
def _s3_exists(key):
    try:
        s3.head_object(Bucket=BUCKET_NAME, Key=key)
        return True
    except s3.exceptions.ClientError:
        return False


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
