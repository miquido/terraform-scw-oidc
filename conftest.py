import os
import json

# Must be set before main.py is imported (module-level code)
os.environ.setdefault("SCW_SECRET_KEY", "test-secret-key")
os.environ.setdefault("SCW_PROJECT_ID", "test-project-id")
os.environ.setdefault("SCW_REGION", "fr-par")
os.environ.setdefault("OIDC", json.dumps([
    {
        "application_id": "test-app-id",
        "aud": "test-audience",
        "sub": "project_path:miquido/*",
        "session_length": 60,
    }
]))
