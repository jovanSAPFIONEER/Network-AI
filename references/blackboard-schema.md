# Blackboard Schema

Data structure specifications for the shared blackboard coordination system.

## File Format

The blackboard is stored as a Markdown file (`swarm-blackboard.md`) with structured sections.

### Document Structure

```markdown
# Swarm Blackboard
Last Updated: {ISO_TIMESTAMP}

## Active Tasks
| TaskID | Agent | Status | Started | Description |
|--------|-------|--------|---------|-------------|

## Knowledge Cache
### {key1}
{json_entry}

### {key2}
{json_entry}

## Coordination Signals

## Execution History
```

## Entry Schema

Each blackboard entry follows this structure:

```typescript
interface BlackboardEntry {
  key: string;           // Unique identifier
  value: any;            // The stored data (any JSON-serializable value)
  source_agent: string;  // Agent that created/updated the entry
  timestamp: string;     // ISO 8601 timestamp (e.g., "2026-02-04T10:30:00Z")
  ttl: number | null;    // Time-to-live in seconds, or null for no expiry
}
```

### JSON Representation

```json
{
  "key": "task:q4_analysis",
  "value": {
    "status": "in_progress",
    "assigned_to": "data_analyst",
    "started_at": "2026-02-04T10:00:00Z"
  },
  "source_agent": "orchestrator",
  "timestamp": "2026-02-04T10:00:00Z",
  "ttl": 3600
}
```

## Key Naming Conventions

Use prefixed keys for organization:

| Prefix | Purpose | Example |
|--------|---------|---------|
| `task:` | Active task tracking | `task:q4_analysis` |
| `cache:` | Cached computation results | `cache:revenue_summary` |
| `signal:` | Agent coordination signals | `signal:data_analyst:ready` |
| `trace:` | Execution traces | `trace:a1b2c3d4` |
| `result:` | Completed task results | `result:q4_analysis` |
| `lock:` | Resource locks | `lock:sap_connection` |

## Value Types

### Task Status

```json
{
  "status": "pending|in_progress|completed|failed",
  "assigned_to": "agent_id",
  "started_at": "ISO_TIMESTAMP",
  "completed_at": "ISO_TIMESTAMP | null",
  "error": "error_message | null",
  "result_key": "result:task_id | null"
}
```

### Cache Entry

```json
{
  "data": { /* any structured data */ },
  "computed_at": "ISO_TIMESTAMP",
  "source": "description of data source",
  "confidence": 0.95
}
```

### Agent Signal

```json
{
  "agent_id": "data_analyst",
  "status": "available|busy|waiting|offline",
  "current_task": "task:xyz | null",
  "last_heartbeat": "ISO_TIMESTAMP"
}
```

### Execution Trace

```json
{
  "trace_id": "uuid",
  "action": "delegate_task",
  "params": { /* action parameters */ },
  "start_time": "ISO_TIMESTAMP",
  "end_time": "ISO_TIMESTAMP | null",
  "status": "running|completed|failed"
}
```

## TTL (Time-to-Live)

Entries can have automatic expiration:

| Use Case | Recommended TTL |
|----------|-----------------|
| Temporary cache | 300-900 seconds (5-15 min) |
| Task tracking | 3600 seconds (1 hour) |
| Result cache | 1800-7200 seconds (30 min - 2 hours) |
| Agent signals | 60-120 seconds (1-2 min) |
| Permanent data | `null` (no expiry) |

### Expiration Behavior

- Entries are checked for expiry on read
- Expired entries return `null`
- Expired entries are removed on next write operation
- Background cleanup not implemented (lazy expiration)

## Operations

### Write

```bash
python scripts/blackboard.py write KEY VALUE [--ttl SECONDS] [--agent AGENT_ID]
```

**Behavior:**
- Creates new entry or overwrites existing
- Updates `timestamp` to current time
- Triggers disk persistence

### Read

```bash
python scripts/blackboard.py read KEY
```

**Behavior:**
- Returns entry if exists and not expired
- Returns `null` if not found or expired
- Triggers expiry cleanup if expired

### Delete

```bash
python scripts/blackboard.py delete KEY
```

**Behavior:**
- Removes entry immediately
- Returns success/failure status

### List

```bash
python scripts/blackboard.py list
```

**Behavior:**
- Returns all non-expired keys
- Triggers expiry cleanup

### Snapshot

```bash
python scripts/blackboard.py snapshot
```

**Behavior:**
- Returns full JSON of all non-expired entries
- Useful for debugging or backup

## Concurrency

**Warning:** The blackboard uses file-based storage without locking.

### Safe Usage Patterns

1. **Single writer** - Ensure only one agent writes at a time
2. **Idempotent writes** - Design writes to be repeatable
3. **Read-before-write** - Check current state before updating
4. **Use unique keys** - Include agent ID or timestamp in key names

### Conflict Resolution

If conflicts occur:
- Last write wins (no merge)
- Use version fields in values for optimistic locking:

```json
{
  "version": 3,
  "data": {...},
  "updated_by": "agent_id"
}
```

## Example Workflows

### Task Handoff

```bash
# Orchestrator creates task
python blackboard.py write "task:analyze_q4" '{"status":"pending","for":"data_analyst"}'

# Data analyst picks up
python blackboard.py write "task:analyze_q4" '{"status":"in_progress","agent":"data_analyst"}'

# Data analyst completes
python blackboard.py write "result:analyze_q4" '{"summary":"Q4 revenue up 15%"}'
python blackboard.py write "task:analyze_q4" '{"status":"completed","result_key":"result:analyze_q4"}'
```

### Agent Heartbeat

```bash
# Agent announces availability (60s TTL)
python blackboard.py write "signal:data_analyst" '{"status":"available"}' --ttl 60 --agent data_analyst

# Other agents check status
python blackboard.py read "signal:data_analyst"
```

### Cached Computation

```bash
# Cache expensive computation (1 hour TTL)
python blackboard.py write "cache:monthly_metrics" '{"revenue":1250000,"costs":800000}' --ttl 3600

# Later: check cache first
result=$(python blackboard.py read "cache:monthly_metrics")
if [ "$result" != "null" ]; then
  echo "Using cached data"
else
  echo "Need to recompute"
fi
```
