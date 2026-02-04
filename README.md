# 🐝 Swarm Orchestrator

**Multi-Agent Swarm Orchestration Skill for OpenClaw**

[![Release](https://img.shields.io/badge/release-v2.0.0-blue.svg)](https://github.com/jovanSAPFIONEER/Network-AI/releases)
[![OpenClaw](https://img.shields.io/badge/OpenClaw-v2026.2.x-red.svg)](https://github.com/OpenClaw/openclaw)
[![Python](https://img.shields.io/badge/python-3.9+-green.svg)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-brightgreen.svg)](LICENSE)
[![AgentSkills](https://img.shields.io/badge/AgentSkills-compatible-orange.svg)](https://agentskills.io)

> 🦞 **Legacy Users:** This skill works with **Clawdbot** and **Moltbot** (now OpenClaw). If you're searching for *Moltbot Security*, *Clawdbot Swarm*, or *Moltbot multi-agent* — you're in the right place!

An [AgentSkills](https://agentskills.io)-compatible skill that enables multi-agent coordination, task delegation, and permission-controlled access to sensitive APIs (databases, payments, external services, etc.).

## 🎯 Features

- **Agent-to-Agent Handoffs** - Delegate tasks between sessions using OpenClaw's `sessions_send`
- **Permission Wall (AuthGuardian)** - Gate access to sensitive APIs (databases, payments, emails) with justification-based approval
- **Shared Blackboard** - Markdown-based coordination state for agent communication
- **Parallel Execution Patterns** - Merge, vote, chain, and first-success synthesis strategies
- **Swarm Guard** - Prevents "Handoff Tax" (wasted tokens) and detects silent agent failures
- **Atomic Commits** - File-system mutexes prevent split-brain in concurrent writes
- **Cost Awareness** - Token budget tracking with automatic SafetyShutdown
- **Budget-Aware Handoffs** - `intercept-handoff` command wraps `sessions_send` with budget checks

## 📁 Skill Structure

```
swarm-orchestrator/
├── SKILL.md              # OpenClaw skill definition (frontmatter + instructions)
├── scripts/              # Executable helper scripts
│   ├── check_permission.py   # AuthGuardian permission checker
│   ├── validate_token.py     # Token validation
│   ├── revoke_token.py       # Token revocation
│   ├── blackboard.py         # Shared state management (with atomic commits)
│   └── swarm_guard.py        # Handoff tax, failure prevention, & budget tracking
├── references/           # Detailed documentation
│   ├── auth-guardian.md      # Permission system details
│   ├── blackboard-schema.md  # Data structure specs
│   ├── trust-levels.md       # Agent trust configuration
│   └── mcp-roadmap.md        # MCP networking implementation plan
├── lib/                  # TypeScript utilities
│   ├── swarm-utils.ts        # Node.js implementation
│   └── locked-blackboard.ts  # Atomic commits with file-system mutexes
└── data/                 # Runtime data (auto-created)
    ├── active_grants.json    # Current permission grants
    ├── budget_tracking.json  # Token budget per task
    └── audit_log.jsonl       # Security audit trail
```

## 🚀 Installation

### For OpenClaw Users

Copy this skill to your OpenClaw workspace:

```bash
cp -r swarm-orchestrator ~/.openclaw/workspace/skills/
```

Or install via ClawHub (when available):
```bash
openclaw skills install swarm-orchestrator
```

### For Development

```bash
git clone https://github.com/jovanSAPFIONEER/Network-AI
cd Network-AI/openclaw-swarm-skill
npm install  # For TypeScript utilities (optional)
pip install -r requirements.txt  # For Python scripts (optional - uses stdlib)
```

### Quick Install for OpenClaw

```bash
# Clone directly into OpenClaw skills directory
git clone https://github.com/jovanSAPFIONEER/Network-AI ~/.openclaw/workspace/skills/swarm-orchestrator --sparse
cd ~/.openclaw/workspace/skills/swarm-orchestrator
git sparse-checkout set openclaw-swarm-skill
mv openclaw-swarm-skill/* . && rm -rf openclaw-swarm-skill
```

Or manually copy:
```bash
cp -r /path/to/Network-AI/openclaw-swarm-skill ~/.openclaw/workspace/skills/swarm-orchestrator
```

## 📖 Usage

### 1. Initialize Budget (First!)

**Always start with a budget for cost control:**

```bash
python scripts/swarm_guard.py budget-init --task-id "task_001" --budget 10000
```

### 2. Budget-Aware Handoffs

**Use `intercept-handoff` before every `sessions_send`:**

```bash
python scripts/swarm_guard.py intercept-handoff \
  --task-id "task_001" \
  --from orchestrator \
  --to data_analyst \
  --message "Analyze Q4 revenue data"
```

Output (if allowed):
```
✅ HANDOFF ALLOWED: orchestrator → data_analyst
   Tokens spent: 156
   Budget remaining: 9,844
   Handoff #1 (remaining: 2)
   → Proceed with sessions_send
```

### 3. Delegate Tasks

Use OpenClaw's session tools to delegate work:

```
sessions_list    # See available agents
sessions_send    # Send task to another session
sessions_history # Check results
```

### 4. Check Permissions

Before accessing sensitive APIs:

```bash
python scripts/check_permission.py \
  --agent data_analyst \
  --resource DATABASE \
  --justification "Need customer order history for sales report"
```

Output:
```
✅ GRANTED
Token: grant_85364b44d987...
Expires: 2026-02-04T15:30:00Z
Restrictions: read_only, max_records:100
```

### 3. Use the Blackboard

```bash
# Write
python scripts/blackboard.py write "task:analysis" '{"status": "running"}'

# Read
python scripts/blackboard.py read "task:analysis"

# Atomic commit workflow (for multi-agent safety)
python scripts/blackboard.py propose "chg_001" "key" '{"value": 1}'
python scripts/blackboard.py validate "chg_001"
python scripts/blackboard.py commit "chg_001"

# List all keys
python scripts/blackboard.py list
```

### 4. Check Budget Status

```bash
python scripts/swarm_guard.py budget-check --task-id "task_001"
python scripts/swarm_guard.py budget-report --task-id "task_001"
```

## 🔐 Permission System

The AuthGuardian evaluates requests using:

| Factor | Weight | Description |
|--------|--------|-------------|
| Justification | 40% | Quality of business reason |
| Trust Level | 30% | Agent's established trust |
| Risk Assessment | 30% | Resource sensitivity + scope |

**Approval threshold: 0.5**

### Resource Types

| Resource | Base Risk | Default Restrictions |
|----------|-----------|---------------------|
| `DATABASE` | 0.5 | `read_only`, `max_records:100` |
| `PAYMENTS` | 0.7 | `read_only`, `no_pii_fields`, `audit_required` |
| `EMAIL` | 0.4 | `rate_limit:10_per_minute` |
| `FILE_EXPORT` | 0.6 | `anonymize_pii`, `local_only` |

## 🤝 Agent Trust Levels

| Agent | Trust | Role |
|-------|-------|------|
| `orchestrator` | 0.9 | Primary coordinator |
| `risk_assessor` | 0.85 | Compliance specialist |
| `data_analyst` | 0.8 | Data processing |
| `strategy_advisor` | 0.7 | Business strategy |
| Unknown | 0.5 | Default |

## 📋 Handoff Protocol

Format messages for delegation:

```
[HANDOFF]
Instruction: Analyze monthly sales by product category
Context: Using database export from ./data/sales_export.csv
Constraints: Focus on top 5 categories only
Expected Output: JSON summary with category, revenue, growth_pct
[/HANDOFF]
```

## 🧪 Testing

```bash
# Test permission system
python scripts/check_permission.py --agent orchestrator --resource PAYMENTS \
  --justification "Generating monthly revenue report for management" --json

# Test blackboard
python scripts/blackboard.py write "test:key" '{"value": 123}' --ttl 60
python scripts/blackboard.py read "test:key"

# Test TTL cleanup
python scripts/revoke_token.py --list-expired
python scripts/revoke_token.py --cleanup

# TypeScript tests (optional)
npm test
```

## 📋 Audit Trail

All sensitive actions are logged to `data/audit_log.jsonl`:

```bash
# View recent audit entries
tail -10 data/audit_log.jsonl

# Search for specific agent
grep "data_analyst" data/audit_log.jsonl
```

Logged events: `permission_granted`, `permission_denied`, `permission_revoked`, `ttl_cleanup`, `result_validated`

## 📚 Documentation

- [SKILL.md](SKILL.md) - Main skill instructions (includes Orchestrator protocol)
- [references/auth-guardian.md](references/auth-guardian.md) - Permission system details
- [references/blackboard-schema.md](references/blackboard-schema.md) - Data structures
- [references/trust-levels.md](references/trust-levels.md) - Trust configuration
- [references/mcp-roadmap.md](references/mcp-roadmap.md) - MCP networking implementation plan

## 🔧 Configuration

### Modify Trust Levels

Edit `scripts/check_permission.py`:

```python
DEFAULT_TRUST_LEVELS = {
    "orchestrator": 0.9,
    "my_new_agent": 0.75,  # Add your agent
}
```

### Adjust Token TTL

```python
GRANT_TOKEN_TTL_MINUTES = 5  # Change as needed
```

## 📄 License

MIT License - See [LICENSE](LICENSE)

## 🙏 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

---

**Compatible with OpenClaw 2026.2.x and AgentSkills specification**

---

<details>
<summary>🔍 Keywords (for search)</summary>

OpenClaw, Clawdbot, Moltbot, Clawdbot Swarm, Moltbot Security, Moltbot multi-agent, OpenClaw skills, multi-agent orchestration, agent coordination, swarm intelligence, AI agents, token permissions, agent handoffs, blackboard pattern, agent budget tracking, cost awareness, atomic commits, AgentSkills, Clawdbot plugins, Moltbot extensions

</details>
