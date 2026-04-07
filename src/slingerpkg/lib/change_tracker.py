import json
import os
from datetime import datetime

from tabulate import tabulate


class ChangeTracker:
    """Tracks all write operations performed on the remote target."""

    CATEGORIES = {
        "FILE": "File Operations",
        "SERVICE": "Service Control",
        "TASK": "Task Scheduler",
        "REGISTRY": "Registry",
        "AGENT": "Agent Management",
        "EXEC": "Command Execution",
    }

    def __init__(self, host, username):
        self.host = host
        self.username = username
        self.changes = []
        self.session_start = datetime.now().isoformat()

    def track(self, category, action, target, details="", status="success"):
        """Record a change operation."""
        self.changes.append(
            {
                "timestamp": datetime.now().isoformat(),
                "category": category,
                "action": action,
                "target": target,
                "details": details,
                "status": status,
            }
        )

    def get_changes(self, category=None):
        """Return changes, optionally filtered by category."""
        if category:
            return [c for c in self.changes if c["category"] == category.upper()]
        return self.changes

    def summary(self, category=None):
        """Return a formatted summary of changes."""
        changes = self.get_changes(category)
        if not changes:
            if category:
                return f"No {category} changes recorded this session."
            return "No changes recorded this session."

        counts = {}
        for c in changes:
            cat = c["category"]
            counts[cat] = counts.get(cat, 0) + 1

        table = []
        for c in changes:
            table.append(
                [
                    c["timestamp"].split("T")[1][:8],
                    c["category"],
                    c["action"],
                    c["target"][:60],
                    c["details"][:40] if c["details"] else "",
                    c["status"],
                ]
            )

        headers = ["Time", "Category", "Action", "Target", "Details", "Status"]
        output = tabulate(table, headers=headers, tablefmt="grid")

        total = len(changes)
        cat_summary = ", ".join(f"{v} {k.lower()}" for k, v in counts.items())
        output += f"\n\nTotal: {total} change(s) ({cat_summary})"
        return output

    def save(self, filepath=None):
        """Save changes to JSON file. Returns the filepath."""
        if not filepath:
            log_dir = os.path.expanduser("~/.slinger/logs/changes")
            os.makedirs(log_dir, exist_ok=True)
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            filepath = os.path.join(log_dir, f"changes_{self.host}_{ts}.json")

        report = {
            "host": self.host,
            "username": self.username,
            "session_start": self.session_start,
            "session_end": datetime.now().isoformat(),
            "total_changes": len(self.changes),
            "changes": self.changes,
        }
        with open(filepath, "w") as f:
            json.dump(report, f, indent=2)
        return filepath
