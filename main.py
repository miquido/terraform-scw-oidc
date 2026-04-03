import os
import fnmatch
import base64

import requests
import jwt
from datetime import datetime, timedelta, timezone
from jwt.algorithms import RSAAlgorithm
from jwt.exceptions import InvalidAudienceError
import json

GITLAB_AUDIENCE = "scaleway-gitlab"
JWKS_URL = "https://gitlab.miquido.com/oauth/discovery/keys"
SCW_SECRET_KEY = os.getenv('SCW_SECRET_KEY')
SCW_PROJECT_ID = os.getenv('PROJECT_ID')
SCW_REGION = os.getenv('REGION')
OIDC_JSON = os.getenv('OIDC')

oidc = json.loads(OIDC_JSON)

IAM_BASE = "https://api.scaleway.com/iam/v1alpha1"
SM_BASE = f"https://api.scaleway.com/secret-manager/v1beta1/regions/{SCW_REGION}"
EXPIRY_BUFFER_SECONDS = 300  # refresh key if less than 5 min remaining


def _headers():
    return {"X-Auth-Token": SCW_SECRET_KEY, "Content-Type": "application/json"}


# ── Secret Manager helpers ────────────────────────────────────────────────────

def _secret_name(application_id):
    return f"oidc-{application_id}"


def _get_cached(name):
    """Returns (secret_id, payload) or (None, None)."""
    resp = requests.get(
        f"{SM_BASE}/secrets",
        headers=_headers(),
        params={"name": name, "project_id": SCW_PROJECT_ID},
    )
    resp.raise_for_status()
    secrets = resp.json().get("secrets", [])
    if not secrets:
        return None, None

    secret_id = secrets[0]["id"]
    resp2 = requests.get(
        f"{SM_BASE}/secrets/{secret_id}/versions/latest/access",
        headers=_headers(),
    )
    resp2.raise_for_status()
    payload = json.loads(base64.b64decode(resp2.json()["data"]).decode())
    return secret_id, payload


def _save_to_secret_manager(name, payload):
    resp = requests.post(
        f"{SM_BASE}/secrets",
        headers=_headers(),
        json={"name": name, "project_id": SCW_PROJECT_ID},
    )
    resp.raise_for_status()
    secret_id = resp.json()["id"]

    encoded = base64.b64encode(json.dumps(payload).encode()).decode()
    resp2 = requests.post(
        f"{SM_BASE}/secrets/{secret_id}/versions",
        headers=_headers(),
        json={"data": encoded},
    )
    resp2.raise_for_status()


def _delete_secret(secret_id):
    resp = requests.delete(f"{SM_BASE}/secrets/{secret_id}", headers=_headers())
    if resp.status_code != 404:
        resp.raise_for_status()


# ── IAM key helpers ───────────────────────────────────────────────────────────

def _create_iam_key(application_id, minutes):
    expires_at = (datetime.utcnow() + timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%SZ")
    payload = {
        "application_id": application_id,
        "description": "oidc-managed",
        "expires_at": expires_at,
    }
    resp = requests.post(f"{IAM_BASE}/api-keys", headers=_headers(), json=payload)
    resp.raise_for_status()
    data = resp.json()
    return {
        "access_key": data["access_key"],
        "secret_key": data["secret_key"],
        "expires_at": expires_at,
    }


def _delete_iam_key(access_key):
    resp = requests.delete(f"{IAM_BASE}/api-keys/{access_key}", headers=_headers())
    if resp.status_code != 404:
        resp.raise_for_status()


# ── Core logic ────────────────────────────────────────────────────────────────

def get_or_create_api_key(application_id, minutes):
    name = _secret_name(application_id)
    secret_id, cached = _get_cached(name)

    if cached:
        expires_at = datetime.fromisoformat(cached["expires_at"].replace("Z", "+00:00"))
        remaining = expires_at - datetime.now(timezone.utc)
        if remaining.total_seconds() > EXPIRY_BUFFER_SECONDS:
            print(f"Reusing key {cached['access_key']}, expires {cached['expires_at']}")
            return {"access_key": cached["access_key"], "secret_key": cached["secret_key"]}

        print(f"Key {cached['access_key']} expired or expiring soon — rotating")
        _delete_iam_key(cached["access_key"])
        _delete_secret(secret_id)

    keys = _create_iam_key(application_id, minutes)
    _save_to_secret_manager(name, keys)
    print(f"Created new key {keys['access_key']}, expires {keys['expires_at']}")
    return {"access_key": keys["access_key"], "secret_key": keys["secret_key"]}


# ── Function handler ──────────────────────────────────────────────────────────

def handle(event, context):
    try:
        print(f'Envs = {list(os.environ.keys())}')
        print("Event:", event)

        token = event['headers']['Authorization'].split(" ")[1]

        jwks = requests.get(JWKS_URL).json()

        def get_public_key(jwks, kid):
            for key in jwks['keys']:
                if key['kid'] == kid:
                    return RSAAlgorithm.from_jwk(json.dumps(key))
            raise ValueError("Key ID not found in JWKS")

        unverified_header = jwt.get_unverified_header(token)
        kid = unverified_header['kid']
        public_key = get_public_key(jwks, kid)

        auds = {}
        for conf in oidc:
            auds.setdefault(conf['aud'], []).append(conf)

        for aud, confs in auds.items():
            try:
                claims = jwt.decode(token, public_key, algorithms=["RS256"], audience=aud)
                for conf in confs:
                    if fnmatch.fnmatch(claims['sub'], conf['sub']):
                        keys = get_or_create_api_key(
                            conf['application_id'],
                            conf['session_length'],
                        )
                        return {"body": keys, "statusCode": 200}
            except InvalidAudienceError:
                continue

        return {"statusCode": 403, "body": {"error": "No sub match found"}}

    except Exception as e:
        print(f"Exception: {e}")
        return {"statusCode": 403, "body": {"error": str(e)}}
