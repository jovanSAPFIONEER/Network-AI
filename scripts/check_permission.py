#!/usr/bin/env python3
"""
AuthGuardian Permission Checker

Evaluates permission requests for accessing sensitive resources
(DATABASE, PAYMENTS, EMAIL, FILE_EXPORT).

Usage:
    python check_permission.py --agent AGENT_ID --resource RESOURCE_TYPE \
        --justification "REASON" [--scope SCOPE]

Example:
    python check_permission.py --agent data_analyst --resource DATABASE \
        --justification "Need customer order history for sales report" \
        --scope "read:orders"
"""

import argparse
import json
import re
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

# Configuration
GRANT_TOKEN_TTL_MINUTES = 5
GRANTS_FILE = Path(__file__).parent.parent / "data" / "active_grants.json"
AUDIT_LOG = Path(__file__).parent.parent / "data" / "audit_log.jsonl"

# Default trust levels for known agents
DEFAULT_TRUST_LEVELS = {
    "orchestrator": 0.9,
    "data_analyst": 0.8,
    "strategy_advisor": 0.7,
    "risk_assessor": 0.85,
}

# Base risk scores for resource types
BASE_RISKS = {
    "DATABASE": 0.5,      # Internal database access
    "PAYMENTS": 0.7,      # Payment/financial systems
    "EMAIL": 0.4,         # Email sending capability
    "FILE_EXPORT": 0.6,   # Exporting data to files
}

# Default restrictions by resource type
RESTRICTIONS = {
    "DATABASE": ["read_only", "max_records:100"],
    "PAYMENTS": ["read_only", "no_pii_fields", "audit_required"],
    "EMAIL": ["rate_limit:10_per_minute"],
    "FILE_EXPORT": ["anonymize_pii", "local_only"],
}


def ensure_data_dir():
    """Ensure data directory exists."""
    data_dir = Path(__file__).parent.parent / "data"
    data_dir.mkdir(exist_ok=True)
    return data_dir


def score_justification(justification: str) -> float:
    """
    Score the quality of a justification.
    
    Criteria:
    - Length (more detail = better)
    - Contains task-related keywords
    - Contains specificity keywords
    - Doesn't contain test/debug keywords
    """
    score = 0.0
    
    if len(justification) > 20:
        score += 0.2
    if len(justification) > 50:
        score += 0.2
    if re.search(r'\b(task|purpose|need|require|generate|analyze|create|process)\b', 
                 justification, re.IGNORECASE):
        score += 0.2
    if re.search(r'\b(specific|particular|exact|quarterly|annual|report|summary)\b',
                 justification, re.IGNORECASE):
        score += 0.2
    if not re.search(r'\b(test|debug|try|experiment)\b', justification, re.IGNORECASE):
        score += 0.2
    
    return min(score, 1.0)


def assess_risk(resource_type: str, scope: Optional[str] = None) -> float:
    """
    Assess the risk level of a permission request.
    
    Factors:
    - Base risk of resource type
    - Scope breadth (broad scopes = higher risk)
    - Write operations (higher risk)
    """
    risk = BASE_RISKS.get(resource_type, 0.5)
    
    # Broad scopes increase risk
    if not scope or scope in ("*", "all"):
        risk += 0.2
    
    # Write operations increase risk
    if scope and re.search(r'\b(write|delete|update|modify|create)\b', scope, re.IGNORECASE):
        risk += 0.2
    
    return min(risk, 1.0)


def generate_grant_token() -> str:
    """Generate a unique grant token."""
    return f"grant_{uuid.uuid4().hex}"


def log_audit(action: str, details: dict[str, Any]) -> None:
    """Append entry to audit log."""
    ensure_data_dir()
    entry: dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "action": action,
        "details": details
    }
    with open(AUDIT_LOG, "a") as f:
        f.write(json.dumps(entry) + "\n")


def save_grant(grant: dict[str, Any]) -> None:
    """Save grant to persistent storage."""
    ensure_data_dir()
    grants = {}
    if GRANTS_FILE.exists():
        try:
            grants = json.loads(GRANTS_FILE.read_text())
        except json.JSONDecodeError:
            grants = {}
    
    grants[grant["token"]] = grant
    GRANTS_FILE.write_text(json.dumps(grants, indent=2))


def evaluate_permission(agent_id: str, resource_type: str, 
                       justification: str, scope: Optional[str] = None) -> dict[str, Any]:
    """
    Evaluate a permission request using weighted scoring.
    
    Weights:
    - Justification Quality: 40%
    - Agent Trust Level: 30%
    - Risk Assessment: 30%
    """
    # Log the request
    log_audit("permission_request", {
        "agent_id": agent_id,
        "resource_type": resource_type,
        "justification": justification,
        "scope": scope
    })
    
    # 1. Justification Quality (40% weight)
    justification_score = score_justification(justification)
    if justification_score < 0.3:
        return {
            "granted": False,
            "reason": "Justification is insufficient. Please provide specific task context.",
            "scores": {
                "justification": justification_score,
                "trust": None,
                "risk": None
            }
        }
    
    # 2. Agent Trust Level (30% weight)
    trust_level = DEFAULT_TRUST_LEVELS.get(agent_id, 0.5)
    if trust_level < 0.4:
        return {
            "granted": False,
            "reason": "Agent trust level is below threshold. Escalate to human operator.",
            "scores": {
                "justification": justification_score,
                "trust": trust_level,
                "risk": None
            }
        }
    
    # 3. Risk Assessment (30% weight)
    risk_score = assess_risk(resource_type, scope)
    if risk_score > 0.8:
        return {
            "granted": False,
            "reason": "Risk assessment exceeds acceptable threshold. Narrow the requested scope.",
            "scores": {
                "justification": justification_score,
                "trust": trust_level,
                "risk": risk_score
            }
        }
    
    # Calculate weighted approval score
    weighted_score = (
        justification_score * 0.4 +
        trust_level * 0.3 +
        (1 - risk_score) * 0.3
    )
    
    if weighted_score < 0.5:
        return {
            "granted": False,
            "reason": f"Combined evaluation score ({weighted_score:.2f}) below threshold (0.5).",
            "scores": {
                "justification": justification_score,
                "trust": trust_level,
                "risk": risk_score,
                "weighted": weighted_score
            }
        }
    
    # Generate grant
    token = generate_grant_token()
    expires_at = (datetime.now(timezone.utc) + timedelta(minutes=GRANT_TOKEN_TTL_MINUTES)).isoformat()
    restrictions = RESTRICTIONS.get(resource_type, [])
    
    grant: dict[str, Any] = {
        "token": token,
        "agent_id": agent_id,
        "resource_type": resource_type,
        "scope": scope,
        "expires_at": expires_at,
        "restrictions": restrictions,
        "granted_at": datetime.now(timezone.utc).isoformat()
    }
    
    # Save grant and log
    save_grant(grant)
    log_audit("permission_granted", grant)
    
    return {
        "granted": True,
        "token": token,
        "expires_at": expires_at,
        "restrictions": restrictions,
        "scores": {
            "justification": justification_score,
            "trust": trust_level,
            "risk": risk_score,
            "weighted": weighted_score
        }
    }


def main():
    parser = argparse.ArgumentParser(
        description="AuthGuardian Permission Checker",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --agent data_analyst --resource SAP_API \\
      --justification "Need Q4 invoice data for quarterly report"
  
  %(prog)s --agent orchestrator --resource FINANCIAL_API \\
      --justification "Generating board presentation financials" \\
      --scope "read:revenue,read:expenses"
"""
    )
    
    parser.add_argument(
        "--agent", "-a",
        required=True,
        help="Agent ID requesting permission"
    )
    parser.add_argument(
        "--resource", "-r",
        required=True,
        choices=["DATABASE", "PAYMENTS", "EMAIL", "FILE_EXPORT"],
        help="Resource type to access"
    )
    parser.add_argument(
        "--justification", "-j",
        required=True,
        help="Business justification for the request"
    )
    parser.add_argument(
        "--scope", "-s",
        help="Specific scope of access (e.g., 'read:invoices')"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output result as JSON"
    )
    
    args = parser.parse_args()
    
    result = evaluate_permission(
        agent_id=args.agent,
        resource_type=args.resource,
        justification=args.justification,
        scope=args.scope
    )
    
    if args.json:
        print(json.dumps(result, indent=2))
    else:
        if result["granted"]:
            print("✅ GRANTED")
            print(f"Token: {result['token']}")
            print(f"Expires: {result['expires_at']}")
            print(f"Restrictions: {', '.join(result['restrictions'])}")
        else:
            print("❌ DENIED")
            print(f"Reason: {result['reason']}")
        
        print("\n📊 Evaluation Scores:")
        scores = result["scores"]
        if scores.get("justification") is not None:
            print(f"  Justification: {scores['justification']:.2f}")
        if scores.get("trust") is not None:
            print(f"  Trust Level:   {scores['trust']:.2f}")
        if scores.get("risk") is not None:
            print(f"  Risk Score:    {scores['risk']:.2f}")
        if scores.get("weighted") is not None:
            print(f"  Weighted:      {scores['weighted']:.2f}")
    
    sys.exit(0 if result["granted"] else 1)


if __name__ == "__main__":
    main()
