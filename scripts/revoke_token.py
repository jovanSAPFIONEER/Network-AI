#!/usr/bin/env python3
"""
Revoke Grant Token

Revoke an active permission grant token.

Usage:
    python revoke_token.py TOKEN

Example:
    python revoke_token.py grant_a1b2c3d4e5f6
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

GRANTS_FILE = Path(__file__).parent.parent / "data" / "active_grants.json"
AUDIT_LOG = Path(__file__).parent.parent / "data" / "audit_log.jsonl"


def log_audit(action: str, details: dict[str, Any]) -> None:
    """Append entry to audit log."""
    AUDIT_LOG.parent.mkdir(exist_ok=True)
    entry: dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "action": action,
        "details": details
    }
    with open(AUDIT_LOG, "a") as f:
        f.write(json.dumps(entry) + "\n")


def revoke_token(token: str) -> dict[str, Any]:
    """Revoke a grant token."""
    if not GRANTS_FILE.exists():
        return {
            "revoked": False,
            "reason": "No grants file found"
        }
    
    try:
        grants = json.loads(GRANTS_FILE.read_text())
    except json.JSONDecodeError:
        return {
            "revoked": False,
            "reason": "Invalid grants file"
        }
    
    if token not in grants:
        return {
            "revoked": False,
            "reason": "Token not found"
        }
    
    grant = grants.pop(token)
    GRANTS_FILE.write_text(json.dumps(grants, indent=2))
    
    log_audit("permission_revoked", {
        "token": token,
        "original_grant": grant
    })
    
    return {
        "revoked": True,
        "grant": grant
    }


def main():
    parser = argparse.ArgumentParser(description="Revoke a permission grant token")
    parser.add_argument("token", help="Grant token to revoke")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    
    args = parser.parse_args()
    result = revoke_token(args.token)
    
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        if result["revoked"]:
            grant = result["grant"]
            print("✅ Token REVOKED")
            print(f"   Agent: {grant.get('agent_id')}")
            print(f"   Resource: {grant.get('resource_type')}")
        else:
            print("❌ Revocation FAILED")
            print(f"   Reason: {result.get('reason')}")
    
    sys.exit(0 if result["revoked"] else 1)


if __name__ == "__main__":
    main()
