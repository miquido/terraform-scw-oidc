#!/usr/bin/env python3
"""
Delete all expired API keys from Scaleway IAM.
Usage: SCW_SECRET_KEY=<key> python cleanup_expired_keys.py [--dry-run]
"""

import os
import sys
import requests
from datetime import datetime, timezone

SCW_SECRET_KEY = os.environ.get("SCW_SECRET_KEY")
SCW_ORGANIZATION_ID = os.environ.get("SCW_ORGANIZATION_ID")
BASE_URL = "https://api.scaleway.com/iam/v1alpha1"
DRY_RUN = "--dry-run" in sys.argv


def get_headers():
    return {
        "X-Auth-Token": SCW_SECRET_KEY,
        "Content-Type": "application/json",
    }


def list_all_api_keys():
    keys = []
    page = 1
    while True:
        resp = requests.get(
            f"{BASE_URL}/api-keys",
            headers=get_headers(),
            params={"page": page, "page_size": 100, "organization_id": SCW_ORGANIZATION_ID},
        )
        resp.raise_for_status()
        data = resp.json()
        batch = data.get("api_keys", [])
        keys.extend(batch)
        if len(keys) >= data.get("total_count", 0):
            break
        page += 1
    return keys


def delete_api_key(access_key):
    resp = requests.delete(f"{BASE_URL}/api-keys/{access_key}", headers=get_headers())
    resp.raise_for_status()


def main():
    if not SCW_SECRET_KEY:
        print("Error: SCW_SECRET_KEY environment variable not set.")
        sys.exit(1)
    if not SCW_ORGANIZATION_ID:
        print("Error: SCW_ORGANIZATION_ID environment variable not set.")
        sys.exit(1)

    print(f"Fetching API keys... {'(dry-run)' if DRY_RUN else ''}")
    all_keys = list_all_api_keys()
    print(f"Total keys found: {len(all_keys)}")

    now = datetime.now(timezone.utc)
    expired = [
        k for k in all_keys
        if k.get("expires_at") and datetime.fromisoformat(k["expires_at"].replace("Z", "+00:00")) < now
    ]

    print(f"Expired keys: {len(expired)}")

    if not expired:
        print("Nothing to delete.")
        return

    for key in expired:
        access_key = key["access_key"]
        expires_at = key["expires_at"]
        description = key.get("description", "")
        print(f"  {'[DRY-RUN] Would delete' if DRY_RUN else 'Deleting'}: {access_key}  expired={expires_at}  desc={description!r}")
        if not DRY_RUN:
            try:
                delete_api_key(access_key)
                print(f"    -> deleted")
            except requests.HTTPError as e:
                print(f"    -> ERROR: {e}")

    if not DRY_RUN:
        print(f"\nDone. Deleted {len(expired)} expired key(s).")
    else:
        print(f"\nDry-run complete. {len(expired)} key(s) would be deleted.")


if __name__ == "__main__":
    main()
