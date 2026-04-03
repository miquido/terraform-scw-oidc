#!/usr/bin/env python3
"""
Live integration test against real Scaleway APIs.
Usage:
  SCW_SECRET_KEY=<key> SCW_PROJECT_ID=<project_id> REGION=pl-waw python test_live.py
"""
import os
import sys
import json

# Mirror what the function does at module level
os.environ.setdefault("OIDC", json.dumps([{
    "application_id": os.environ.get("TEST_APPLICATION_ID", ""),
    "aud": "test",
    "sub": "*",
    "session_length": 10,
}]))

import main

APPLICATION_ID = os.environ.get("TEST_APPLICATION_ID")


def check_env():
    missing = [v for v in ["SCW_SECRET_KEY", "SCW_PROJECT_ID", "REGION", "TEST_APPLICATION_ID"] if not os.environ.get(v)]
    if missing:
        print(f"Missing env vars: {', '.join(missing)}")
        sys.exit(1)


def test_create_key():
    print("\n--- Test: create new key (no cache) ---")
    # Clean up any existing secret first
    name = main._secret_name(APPLICATION_ID)
    secret_id, cached = main._get_cached(name)
    if secret_id:
        print(f"Found existing secret {secret_id}, cleaning up first")
        if cached:
            main._delete_iam_key(cached["access_key"])
        main._delete_secret(secret_id)

    keys = main.get_or_create_api_key(APPLICATION_ID, 10)
    print(f"Created: access_key={keys['access_key']}")
    assert keys["access_key"] and keys["secret_key"]
    print("PASS")
    return keys


def test_reuse_key():
    print("\n--- Test: reuse existing key ---")
    keys1 = main.get_or_create_api_key(APPLICATION_ID, 10)
    keys2 = main.get_or_create_api_key(APPLICATION_ID, 10)
    assert keys1["access_key"] == keys2["access_key"], \
        f"Expected same key, got {keys1['access_key']} vs {keys2['access_key']}"
    print(f"Reused: {keys1['access_key']}")
    print("PASS")


def cleanup():
    print("\n--- Cleanup ---")
    name = main._secret_name(APPLICATION_ID)
    secret_id, cached = main._get_cached(name)
    if secret_id:
        if cached:
            main._delete_iam_key(cached["access_key"])
            print(f"Deleted IAM key: {cached['access_key']}")
        main._delete_secret(secret_id)
        print(f"Deleted secret: {secret_id}")


if __name__ == "__main__":
    check_env()
    print(f"Region: {main.SCW_REGION}")
    print(f"Project: {main.SCW_PROJECT_ID}")
    print(f"Application: {APPLICATION_ID}")

    try:
        test_create_key()
        test_reuse_key()
    finally:
        cleanup()

    print("\nAll tests passed.")
