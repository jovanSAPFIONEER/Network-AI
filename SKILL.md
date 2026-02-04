---
name: swarm-orchestrator
description: Multi-agent swarm orchestration for complex workflows. Use when coordinating multiple agents, delegating tasks between sessions, managing shared state via blackboard, or enforcing permission walls for DATABASE/PAYMENTS/EMAIL access. Triggers on: agent coordination, task delegation, parallel execution, permission requests, blackboard state management.
metadata: { "openclaw": { "emoji": "🐝", "homepage": "https://github.com/jovanSAPFIONEER/Network-AI" } }
---

# Swarm Orchestrator Skill

Multi-agent coordination system for complex workflows requiring task delegation, parallel execution, and permission-controlled access to sensitive APIs.

## When to Use This Skill

- **Task Delegation**: Route work to specialized agents (data_analyst, strategy_advisor, risk_assessor)
- **Parallel Execution**: Run multiple agents simultaneously and synthesize results
- **Permission Wall**: Gate access to SAP_API, FINANCIAL_API, or DATA_EXPORT operations
- **Shared Blackboard**: Coordinate agent state via persistent markdown file

## Quick Start

### 1. Delegate a Task to Another Session

Use OpenClaw's built-in session tools to delegate work:

```
sessions_list    # See available sessions/agents
sessions_send    # Send task to another session
sessions_history # Check results from delegated work
```

**Example delegation prompt:**
```
Use sessions_send to ask the data_analyst session to:
"Analyze Q4 revenue trends from the SAP export data and summarize key insights"
```

### 2. Check Permission Before API Access

Before accessing SAP or Financial APIs, evaluate the request:

```bash
# Run the permission checker script
python {baseDir}/scripts/check_permission.py \
  --agent "data_analyst" \
  --resource "SAP_API" \
  --justification "Need Q4 invoice data for quarterly report" \
  --scope "read:invoices"
```

The script will output a grant token if approved, or denial reason if rejected.

### 3. Use the Shared Blackboard

Read/write coordination state:

```bash
# Write to blackboard
python {baseDir}/scripts/blackboard.py write "task:q4_analysis" '{"status": "in_progress", "agent": "data_analyst"}'

# Read from blackboard  
python {baseDir}/scripts/blackboard.py read "task:q4_analysis"

# List all entries
python {baseDir}/scripts/blackboard.py list
```

## Agent-to-Agent Handoff Protocol

When delegating tasks between agents/sessions:

### Step 1: Identify Target Agent
```
sessions_list  # Find available agents
```

Common agent types:
| Agent | Specialty |
|-------|-----------|
| `data_analyst` | Data processing, SQL, analytics |
| `strategy_advisor` | Business strategy, recommendations |
| `risk_assessor` | Risk analysis, compliance checks |
| `orchestrator` | Coordination, task decomposition |

### Step 2: Construct Handoff Message

Include these fields in your delegation:
- **instruction**: Clear task description
- **context**: Relevant background information
- **constraints**: Any limitations or requirements
- **expectedOutput**: What format/content you need back

### Step 3: Send via sessions_send

```
sessions_send to data_analyst:
"[HANDOFF]
Instruction: Analyze Q4 revenue by product category
Context: Using SAP export from ./data/q4_export.csv
Constraints: Focus on top 5 categories only
Expected Output: JSON summary with category, revenue, growth_pct
[/HANDOFF]"
```

### Step 4: Check Results

```
sessions_history data_analyst  # Get the response
```

## Permission Wall (AuthGuardian)

**CRITICAL**: Always check permissions before accessing:
- `SAP_API` - SAP system connections
- `FINANCIAL_API` - Financial data services
- `EXTERNAL_SERVICE` - Third-party APIs
- `DATA_EXPORT` - Exporting sensitive data

### Permission Evaluation Criteria

| Factor | Weight | Criteria |
|--------|--------|----------|
| Justification | 40% | Must explain specific task need |
| Trust Level | 30% | Agent's established trust score |
| Risk Assessment | 30% | Resource sensitivity + scope breadth |

### Using the Permission Script

```bash
# Request permission
python {baseDir}/scripts/check_permission.py \
  --agent "your_agent_id" \
  --resource "FINANCIAL_API" \
  --justification "Generating quarterly financial summary for board presentation" \
  --scope "read:revenue,read:expenses"

# Output if approved:
# ✅ GRANTED
# Token: grant_a1b2c3d4e5f6
# Expires: 2026-02-04T15:30:00Z
# Restrictions: read_only, no_pii_fields, audit_required

# Output if denied:
# ❌ DENIED
# Reason: Justification is insufficient. Please provide specific task context.
```

### Restriction Types

| Resource | Default Restrictions |
|----------|---------------------|
| SAP_API | `read_only`, `max_records:100` |
| FINANCIAL_API | `read_only`, `no_pii_fields`, `audit_required` |
| EXTERNAL_SERVICE | `rate_limit:10_per_minute` |
| DATA_EXPORT | `anonymize_pii`, `local_only` |

## Shared Blackboard Pattern

The blackboard (`swarm-blackboard.md`) is a markdown file for agent coordination:

```markdown
# Swarm Blackboard
Last Updated: 2026-02-04T10:30:00Z

## Knowledge Cache
### task:q4_analysis
{"status": "completed", "result": {...}, "agent": "data_analyst"}

### cache:revenue_summary  
{"q4_total": 1250000, "growth": 0.15}
```

### Blackboard Operations

```bash
# Write with TTL (expires after 1 hour)
python {baseDir}/scripts/blackboard.py write "cache:temp_data" '{"value": 123}' --ttl 3600

# Read (returns null if expired)
python {baseDir}/scripts/blackboard.py read "cache:temp_data"

# Delete
python {baseDir}/scripts/blackboard.py delete "cache:temp_data"

# Get full snapshot
python {baseDir}/scripts/blackboard.py snapshot
```

## Parallel Execution

For tasks requiring multiple agent perspectives:

### Strategy 1: Merge (Default)
Combine all agent outputs into unified result.
```
Ask data_analyst AND strategy_advisor to both analyze the dataset.
Merge their insights into a comprehensive report.
```

### Strategy 2: Vote
Use when you need consensus - pick the result with highest confidence.

### Strategy 3: First-Success
Use for redundancy - take first successful result.

### Strategy 4: Chain
Sequential processing - output of one feeds into next.

### Example Parallel Workflow

```
1. sessions_send to data_analyst: "Extract key metrics from Q4 data"
2. sessions_send to risk_assessor: "Identify compliance risks in Q4 data"  
3. sessions_send to strategy_advisor: "Recommend actions based on Q4 trends"
4. Wait for all responses via sessions_history
5. Synthesize: Combine metrics + risks + recommendations into executive summary
```

## Security Considerations

1. **Never bypass the permission wall** for DATABASE/PAYMENTS APIs
2. **Always include justification** explaining the business need
3. **Use minimal scope** - request only what you need
4. **Check token expiry** - tokens are valid for 5 minutes
5. **Audit trail** - all permission requests are logged

## 📝 Audit Trail Requirements (MANDATORY)

**Every sensitive action MUST be logged to `data/audit_log.jsonl`** to maintain compliance and enable forensic analysis.

### What Gets Logged Automatically

The scripts automatically log these events:
- `permission_granted` - When access is approved
- `permission_denied` - When access is rejected
- `permission_revoked` - When a token is manually revoked
- `ttl_cleanup` - When expired tokens are purged
- `result_validated` / `result_rejected` - Swarm Guard validations

### Log Entry Format

```json
{
  "timestamp": "2026-02-04T10:30:00+00:00",
  "action": "permission_granted",
  "details": {
    "agent_id": "data_analyst",
    "resource_type": "DATABASE",
    "justification": "Q4 revenue analysis",
    "token": "grant_abc123...",
    "restrictions": ["read_only", "max_records:100"]
  }
}
```

### Reading the Audit Log

```bash
# View recent entries (last 10)
tail -10 {baseDir}/data/audit_log.jsonl

# Search for specific agent
grep "data_analyst" {baseDir}/data/audit_log.jsonl

# Count actions by type
cat {baseDir}/data/audit_log.jsonl | jq -r '.action' | sort | uniq -c
```

### Custom Audit Entries

If you perform a sensitive action manually, log it:

```python
import json
from datetime import datetime, timezone
from pathlib import Path

audit_file = Path("{baseDir}/data/audit_log.jsonl")
entry = {
    "timestamp": datetime.now(timezone.utc).isoformat(),
    "action": "manual_data_access",
    "details": {
        "agent": "orchestrator",
        "description": "Direct database query for debugging",
        "justification": "Investigating data sync issue #1234"
    }
}
with open(audit_file, "a") as f:
    f.write(json.dumps(entry) + "\n")
```

## 🧹 TTL Enforcement (Token Lifecycle)

Expired permission tokens are automatically tracked. Run periodic cleanup:

```bash
# List expired tokens (without removing)
python {baseDir}/scripts/revoke_token.py --list-expired

# Remove all expired tokens
python {baseDir}/scripts/revoke_token.py --cleanup

# Output:
# 🧹 TTL Cleanup Complete
#    Removed: 3 expired token(s)
#    Remaining active grants: 2
```

**Best Practice**: Run `--cleanup` at the start of each multi-agent task to ensure a clean permission state.

## ⚠️ Swarm Guard: Preventing Common Failures

Two critical issues can derail multi-agent swarms:

### 1. The Handoff Tax 💸

**Problem**: Agents waste tokens "talking about" work instead of doing it.

**Prevention**:
```bash
# Before each handoff, check your budget:
python {baseDir}/scripts/swarm_guard.py check-handoff --task-id "task_001"

# Output:
# 🟢 Task: task_001
#    Handoffs: 1/3
#    Remaining: 2
#    Action Ratio: 100%
```

**Rules enforced**:
- **Max 3 handoffs per task** - After 3, produce output or abort
- **Max 500 chars per message** - Be concise: instruction + constraints + expected output
- **60% action ratio** - At least 60% of handoffs must produce artifacts
- **2-minute planning limit** - No output after 2min = timeout

```bash
# Record a handoff (with tax checking):
python {baseDir}/scripts/swarm_guard.py record-handoff \
  --task-id "task_001" \
  --from orchestrator \
  --to data_analyst \
  --message "Analyze sales data, output JSON summary" \
  --artifact  # Include if this handoff produces output
```

### 2. Silent Failure Detection 👻

**Problem**: One agent fails silently, others keep working on bad data.

**Prevention - Heartbeats**:
```bash
# Agents must send heartbeats while working:
python {baseDir}/scripts/swarm_guard.py heartbeat --agent data_analyst --task-id "task_001"

# Check if an agent is healthy:
python {baseDir}/scripts/swarm_guard.py health-check --agent data_analyst

# Output if healthy:
# 💚 Agent 'data_analyst' is HEALTHY
#    Last seen: 15s ago

# Output if failed:
# 💔 Agent 'data_analyst' is UNHEALTHY
#    Reason: STALE_HEARTBEAT
#    → Do NOT use any pending results from this agent.
```

**Prevention - Result Validation**:
```bash
# Before using another agent's result, validate it:
python {baseDir}/scripts/swarm_guard.py validate-result \
  --task-id "task_001" \
  --agent data_analyst \
  --result '{"status": "success", "output": {"revenue": 125000}, "confidence": 0.85}'

# Output:
# ✅ RESULT VALID
#    → APPROVED - Result can be used by other agents
```

**Required result fields**: `status`, `output`, `confidence`

### Supervisor Review

Before finalizing any task, run supervisor review:
```bash
python {baseDir}/scripts/swarm_guard.py supervisor-review --task-id "task_001"

# Output:
# ✅ SUPERVISOR VERDICT: APPROVED
#    Task: task_001
#    Age: 1.5 minutes
#    Handoffs: 2
#    Artifacts: 2
```

**Verdicts**:
- `APPROVED` - Task healthy, results usable
- `WARNING` - Issues detected, review recommended
- `BLOCKED` - Critical failures, do NOT use results

## Troubleshooting

### Permission Denied
- Provide more specific justification (mention task, purpose, expected outcome)
- Narrow the requested scope
- Check agent trust level

### Blackboard Read Returns Null
- Entry may have expired (check TTL)
- Key may be misspelled
- Entry was never written

### Session Not Found
- Run `sessions_list` to see available sessions
- Session may need to be started first

## References

- [AuthGuardian Details](references/auth-guardian.md) - Full permission system documentation
- [Blackboard Schema](references/blackboard-schema.md) - Data structure specifications
- [Agent Trust Levels](references/trust-levels.md) - How trust is calculated
