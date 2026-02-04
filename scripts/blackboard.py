#!/usr/bin/env python3
"""
Shared Blackboard - Agent Coordination State Manager

A markdown-based shared state system for multi-agent coordination.
Stores key-value pairs with optional TTL (time-to-live) expiration.

Usage:
    python blackboard.py write KEY VALUE [--ttl SECONDS]
    python blackboard.py read KEY
    python blackboard.py delete KEY
    python blackboard.py list
    python blackboard.py snapshot

Examples:
    python blackboard.py write "task:analysis" '{"status": "running"}'
    python blackboard.py write "cache:data" '{"value": 123}' --ttl 3600
    python blackboard.py read "task:analysis"
    python blackboard.py list
"""

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

# Default blackboard location
BLACKBOARD_PATH = Path(__file__).parent.parent / "swarm-blackboard.md"


class SharedBlackboard:
    """Markdown-based shared state for agent coordination."""
    
    def __init__(self, path: Path = BLACKBOARD_PATH):
        self.path = path
        self.cache: dict[str, dict[str, Any]] = {}
        self._initialize()
        self._load_from_disk()
    
    def _initialize(self):
        """Create blackboard file if it doesn't exist."""
        if not self.path.exists():
            self.path.parent.mkdir(parents=True, exist_ok=True)
            initial_content = f"""# Swarm Blackboard
Last Updated: {datetime.now(timezone.utc).isoformat()}

## Active Tasks
| TaskID | Agent | Status | Started | Description |
|--------|-------|--------|---------|-------------|

## Knowledge Cache
<!-- Cached results from agent operations -->

## Coordination Signals
<!-- Agent availability status -->

## Execution History
<!-- Chronological log of completed tasks -->
"""
            self.path.write_text(initial_content, encoding="utf-8")
    
    def _load_from_disk(self):
        """Load entries from the markdown blackboard."""
        try:
            content = self.path.read_text(encoding="utf-8")
            
            # Parse Knowledge Cache section
            cache_match = re.search(
                r'## Knowledge Cache\n([\s\S]*?)(?=\n## |$)', 
                content
            )
            
            if cache_match:
                cache_section = cache_match.group(1)
                # Find all entries: ### key\n{json}
                entries = re.findall(
                    r'### (\S+)\n([\s\S]*?)(?=\n### |$)',
                    cache_section
                )
                
                for key, value_str in entries:
                    try:
                        entry = json.loads(value_str.strip())
                        self.cache[key] = entry
                    except json.JSONDecodeError:
                        # Skip malformed entries
                        pass
        except Exception as e:
            print(f"Warning: Failed to load blackboard: {e}", file=sys.stderr)
    
    def _persist_to_disk(self):
        """Save entries to the markdown blackboard."""
        sections = [
            "# Swarm Blackboard",
            f"Last Updated: {datetime.now(timezone.utc).isoformat()}",
            "",
            "## Active Tasks",
            "| TaskID | Agent | Status | Started | Description |",
            "|--------|-------|--------|---------|-------------|",
            "",
            "## Knowledge Cache",
        ]
        
        # Clean expired entries and write valid ones
        for key, entry in list(self.cache.items()):
            if self._is_expired(entry):
                del self.cache[key]
                continue
            
            sections.append(f"### {key}")
            sections.append(json.dumps(entry, indent=2))
            sections.append("")
        
        sections.extend([
            "## Coordination Signals",
            "",
            "## Execution History",
        ])
        
        self.path.write_text("\n".join(sections), encoding="utf-8")
    
    def _is_expired(self, entry: dict[str, Any]) -> bool:
        """Check if an entry has expired based on TTL."""
        ttl = entry.get("ttl")
        if ttl is None:
            return False
        
        timestamp = entry.get("timestamp")
        if not timestamp:
            return False
        
        try:
            created = datetime.fromisoformat(str(timestamp).replace("Z", "+00:00"))
            now = datetime.now(timezone.utc)
            elapsed = (now - created).total_seconds()
            return elapsed > ttl
        except Exception:
            return False
    
    def read(self, key: str) -> Optional[dict[str, Any]]:
        """Read an entry from the blackboard."""
        entry = self.cache.get(key)
        if entry is None:
            return None
        
        if self._is_expired(entry):
            del self.cache[key]
            self._persist_to_disk()
            return None
        
        return entry
    
    def write(self, key: str, value: Any, source_agent: str = "unknown", 
              ttl: Optional[int] = None) -> dict[str, Any]:
        """Write an entry to the blackboard."""
        entry: dict[str, Any] = {
            "key": key,
            "value": value,
            "source_agent": source_agent,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "ttl": ttl,
        }
        
        self.cache[key] = entry
        self._persist_to_disk()
        return entry
    
    def delete(self, key: str) -> bool:
        """Delete an entry from the blackboard."""
        if key in self.cache:
            del self.cache[key]
            self._persist_to_disk()
            return True
        return False
    
    def exists(self, key: str) -> bool:
        """Check if a key exists (and is not expired)."""
        return self.read(key) is not None
    
    def list_keys(self) -> list[str]:
        """List all valid (non-expired) keys."""
        valid_keys: list[str] = []
        for key in list(self.cache.keys()):
            if self.read(key) is not None:
                valid_keys.append(key)
        return valid_keys
    
    def get_snapshot(self) -> dict[str, dict[str, Any]]:
        """Get a snapshot of all valid entries."""
        snapshot: dict[str, dict[str, Any]] = {}
        for key in list(self.cache.keys()):
            entry = self.read(key)
            if entry is not None:
                snapshot[key] = entry
        return snapshot


def main():
    parser = argparse.ArgumentParser(
        description="Shared Blackboard - Agent Coordination State Manager",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Commands:
  write KEY VALUE [--ttl SECONDS]  Write a value (JSON) with optional TTL
  read KEY                         Read a value
  delete KEY                       Delete a key
  list                             List all keys
  snapshot                         Get full snapshot as JSON

Examples:
  %(prog)s write "task:analysis" '{"status": "running", "agent": "data_analyst"}'
  %(prog)s write "cache:temp" '{"data": [1,2,3]}' --ttl 3600
  %(prog)s read "task:analysis"
  %(prog)s list
  %(prog)s snapshot
"""
    )
    
    parser.add_argument(
        "command",
        choices=["write", "read", "delete", "list", "snapshot"],
        help="Command to execute"
    )
    parser.add_argument(
        "key",
        nargs="?",
        help="Key name (required for write/read/delete)"
    )
    parser.add_argument(
        "value",
        nargs="?",
        help="JSON value (required for write)"
    )
    parser.add_argument(
        "--ttl",
        type=int,
        help="Time-to-live in seconds (for write)"
    )
    parser.add_argument(
        "--agent",
        default="cli",
        help="Source agent ID (for write)"
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output as JSON"
    )
    parser.add_argument(
        "--path",
        type=Path,
        default=BLACKBOARD_PATH,
        help="Path to blackboard file"
    )
    
    args = parser.parse_args()
    bb = SharedBlackboard(args.path)
    
    if args.command == "write":
        if not args.key or not args.value:
            print("Error: write requires KEY and VALUE", file=sys.stderr)
            sys.exit(1)
        
        try:
            value = json.loads(args.value)
        except json.JSONDecodeError:
            # Treat as string if not valid JSON
            value = args.value
        
        entry = bb.write(args.key, value, args.agent, args.ttl)
        
        if args.json:
            print(json.dumps(entry, indent=2))
        else:
            print(f"✅ Written: {args.key}")
            if args.ttl:
                print(f"   TTL: {args.ttl} seconds")
    
    elif args.command == "read":
        if not args.key:
            print("Error: read requires KEY", file=sys.stderr)
            sys.exit(1)
        
        entry = bb.read(args.key)
        
        if entry is None:
            if args.json:
                print("null")
            else:
                print(f"❌ Key not found or expired: {args.key}")
            sys.exit(1)
        
        if args.json:
            print(json.dumps(entry, indent=2))
        else:
            print(f"📖 {args.key}:")
            print(f"   Value: {json.dumps(entry.get('value'))}")
            print(f"   Source: {entry.get('source_agent')}")
            print(f"   Timestamp: {entry.get('timestamp')}")
            if entry.get('ttl'):
                print(f"   TTL: {entry['ttl']} seconds")
    
    elif args.command == "delete":
        if not args.key:
            print("Error: delete requires KEY", file=sys.stderr)
            sys.exit(1)
        
        if bb.delete(args.key):
            print(f"✅ Deleted: {args.key}")
        else:
            print(f"❌ Key not found: {args.key}")
            sys.exit(1)
    
    elif args.command == "list":
        keys = bb.list_keys()
        
        if args.json:
            print(json.dumps(keys, indent=2))
        else:
            if keys:
                print(f"📋 Blackboard keys ({len(keys)}):")
                for key in sorted(keys):
                    entry = bb.read(key)
                    ttl_info = f" [TTL: {entry['ttl']}s]" if entry and entry.get('ttl') else ""
                    print(f"   • {key}{ttl_info}")
            else:
                print("📋 Blackboard is empty")
    
    elif args.command == "snapshot":
        snapshot = bb.get_snapshot()
        print(json.dumps(snapshot, indent=2))


if __name__ == "__main__":
    main()
