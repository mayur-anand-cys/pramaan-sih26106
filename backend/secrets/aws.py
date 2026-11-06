"""AWS Secrets Manager integration.

Reads secrets from AWS Secrets Manager when PRAMAAN_USE_AWS_SECRETS=true.
Otherwise falls back to environment variables — this keeps local dev,
DEMO_MODE, and CI fully functional without AWS credentials.

All lookups are cached per process to avoid repeated API calls.
"""

import json
import os
from functools import lru_cache
from typing import Any, Dict, Optional

_DEFAULT_REGION = "ap-south-1"


def aws_secrets_enabled() -> bool:
    """True when PRAMAAN_USE_AWS_SECRETS is set to 'true'."""
    return os.getenv("PRAMAAN_USE_AWS_SECRETS", "false").lower() == "true"


@lru_cache(maxsize=32)
def get_secret(name: str) -> Optional[Dict[str, Any]]:
    """Read a JSON secret from AWS Secrets Manager.

    Returns None if AWS integration is disabled or the secret cannot be
    fetched. Callers should fall back to env vars in that case.
    """
    if not aws_secrets_enabled():
        return None

    try:
        import boto3  # imported lazily — only needed when flag is on
    except ImportError:
        return None

    try:
        region = os.getenv("AWS_REGION", _DEFAULT_REGION)
        client = boto3.client("secretsmanager", region_name=region)
        resp = client.get_secret_value(SecretId=name)
        raw = resp.get("SecretString", "")
        if not raw:
            return None
        try:
            parsed = json.loads(raw)
            if isinstance(parsed, dict):
                return parsed
            return {"value": parsed}
        except json.JSONDecodeError:
            return {"value": raw}
    except Exception:
        return None


def get_secret_value(secret_name: str, key: str, env_var: str, default: str = "") -> str:
    """Fetch a single value from AWS Secrets Manager, falling back to env var.

    Order of precedence:
        1. AWS Secrets Manager (if PRAMAAN_USE_AWS_SECRETS=true)
        2. Environment variable (env_var)
        3. `default`
    """
    secret = get_secret(secret_name)
    if secret and key in secret:
        val = secret[key]
        if val not in (None, ""):
            return str(val)

    return os.getenv(env_var, default)