import json
import base64
import pytest
import responses as responses_lib
from datetime import datetime, timedelta, timezone
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from jwt.algorithms import RSAAlgorithm
import jwt

import main

# ── RSA keypair shared across all tests ──────────────────────────────────────

_PRIVATE_KEY = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend(),
)
_PUBLIC_KEY = _PRIVATE_KEY.public_key()
KID = "test-kid"

_PRIVATE_PEM = _PRIVATE_KEY.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption(),
)

APPLICATION_ID = "test-app-id"
AUDIENCE = "test-audience"
SUB = "project_path:miquido/myproject:ref_type:branch:ref:main"

SM_BASE = main.SM_BASE
IAM_BASE = main.IAM_BASE
JWKS_URL = main.JWKS_URL


# ── Helpers ───────────────────────────────────────────────────────────────────

def make_token(sub=SUB, aud=AUDIENCE, exp_delta=timedelta(hours=1)):
    payload = {
        "sub": sub,
        "aud": aud,
        "iat": datetime.utcnow(),
        "exp": datetime.utcnow() + exp_delta,
    }
    token = jwt.encode(payload, _PRIVATE_PEM, algorithm="RS256", headers={"kid": KID})
    # PyJWT 1.x returns bytes, 2.x returns str
    return token.decode("utf-8") if isinstance(token, bytes) else token


def make_jwks():
    jwk = json.loads(RSAAlgorithm.to_jwk(_PUBLIC_KEY))
    jwk["kid"] = KID
    return {"keys": [jwk]}


def make_event(token):
    return {"headers": {"Authorization": f"Bearer {token}"}}


def cached_secret_payload(expires_at: str):
    payload = {"access_key": "CACHED_KEY", "secret_key": "cached-secret", "expires_at": expires_at}
    return base64.b64encode(json.dumps(payload).encode()).decode()


# ── Tests ─────────────────────────────────────────────────────────────────────

@responses_lib.activate
def test_valid_token_no_cache_creates_new_key():
    responses_lib.add(responses_lib.GET, JWKS_URL, json=make_jwks())
    responses_lib.add(responses_lib.GET, f"{SM_BASE}/secrets", json={"secrets": []})
    responses_lib.add(responses_lib.POST, f"{SM_BASE}/secrets", json={"id": "secret-123"})
    responses_lib.add(responses_lib.POST, f"{SM_BASE}/secrets/secret-123/versions", json={})
    responses_lib.add(responses_lib.POST, f"{IAM_BASE}/api-keys", json={
        "access_key": "NEW_ACCESS_KEY",
        "secret_key": "new-secret-key",
    })

    result = main.handle(make_event(make_token()), {})

    assert result["statusCode"] == 200
    assert result["body"]["access_key"] == "NEW_ACCESS_KEY"
    assert result["body"]["secret_key"] == "new-secret-key"


@responses_lib.activate
def test_valid_token_with_fresh_cache_reuses_key():
    future = (datetime.now(timezone.utc) + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")

    responses_lib.add(responses_lib.GET, JWKS_URL, json=make_jwks())
    responses_lib.add(responses_lib.GET, f"{SM_BASE}/secrets", json={"secrets": [{"id": "secret-123"}]})
    responses_lib.add(responses_lib.GET, f"{SM_BASE}/secrets/secret-123/versions/latest/access",
                      json={"data": cached_secret_payload(future)})

    result = main.handle(make_event(make_token()), {})

    assert result["statusCode"] == 200
    assert result["body"]["access_key"] == "CACHED_KEY"
    # No IAM or SM create calls should have been made
    iam_calls = [c for c in responses_lib.calls if IAM_BASE in c.request.url]
    assert len(iam_calls) == 0


@responses_lib.activate
def test_valid_token_with_expired_cache_rotates_key():
    past = (datetime.now(timezone.utc) - timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:%SZ")

    responses_lib.add(responses_lib.GET, JWKS_URL, json=make_jwks())
    responses_lib.add(responses_lib.GET, f"{SM_BASE}/secrets", json={"secrets": [{"id": "secret-123"}]})
    responses_lib.add(responses_lib.GET, f"{SM_BASE}/secrets/secret-123/versions/latest/access",
                      json={"data": cached_secret_payload(past)})
    responses_lib.add(responses_lib.DELETE, f"{IAM_BASE}/api-keys/CACHED_KEY", status=204)
    responses_lib.add(responses_lib.DELETE, f"{SM_BASE}/secrets/secret-123", status=204)
    responses_lib.add(responses_lib.POST, f"{IAM_BASE}/api-keys", json={
        "access_key": "ROTATED_KEY",
        "secret_key": "rotated-secret",
    })
    responses_lib.add(responses_lib.POST, f"{SM_BASE}/secrets", json={"id": "secret-456"})
    responses_lib.add(responses_lib.POST, f"{SM_BASE}/secrets/secret-456/versions", json={})

    result = main.handle(make_event(make_token()), {})

    assert result["statusCode"] == 200
    assert result["body"]["access_key"] == "ROTATED_KEY"


@responses_lib.activate
def test_invalid_token_signature_returns_403():
    import secrets
    fake_key = rsa.generate_private_key(65537, 2048, default_backend())
    fake_pem = fake_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    payload = {"sub": SUB, "aud": AUDIENCE, "exp": datetime.utcnow() + timedelta(hours=1)}
    bad_token = jwt.encode(payload, fake_pem, algorithm="RS256", headers={"kid": KID})
    if isinstance(bad_token, bytes):
        bad_token = bad_token.decode("utf-8")

    responses_lib.add(responses_lib.GET, JWKS_URL, json=make_jwks())

    result = main.handle(make_event(bad_token), {})

    assert result["statusCode"] == 403


@responses_lib.activate
def test_wrong_audience_returns_403():
    responses_lib.add(responses_lib.GET, JWKS_URL, json=make_jwks())

    result = main.handle(make_event(make_token(aud="wrong-audience")), {})

    assert result["statusCode"] == 403


@responses_lib.activate
def test_sub_not_matching_pattern_returns_403():
    responses_lib.add(responses_lib.GET, JWKS_URL, json=make_jwks())

    result = main.handle(make_event(make_token(sub="project_path:other-org/project")), {})

    assert result["statusCode"] == 403
