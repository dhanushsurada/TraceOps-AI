#!/usr/bin/env python3
"""
TraceOps Local Developer Telemetry Collector & Addon Daemon

Captures local development activity:
1. Terminal command executions
2. Git hook automation (auto-injecting [TRO-<task_id>])
3. Active file touch / edit events
4. Transmits securely to TraceOps Backend API
"""
import argparse
import json
import os
import sys
import time
from datetime import datetime
import urllib.request
import urllib.error

TRACEOPS_API_DEFAULT = os.environ.get("TRACEOPS_API_URL", "http://localhost:8000")


def send_event(event_type: str, metadata: dict, task_id: str = None, api_url: str = TRACEOPS_API_DEFAULT):
    url = f"{api_url}/event"
    payload = {
        "event_type": event_type,
        "task_id": task_id,
        "source": "collector:cli",
        "timestamp": datetime.utcnow().isoformat(),
        "metadata": metadata,
    }
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read().decode())
    except Exception as e:
        sys.stderr.write(f"[TraceOps Collector] Failed to send event: {e}\n")
        return None


def install_git_hook():
    """Install prepare-commit-msg hook to auto-inject active TRO task ID."""
    hook_path = os.path.join(".git", "hooks", "prepare-commit-msg")
    if not os.path.exists(".git"):
        print("Error: Must run inside a Git repository root.")
        return 1

    hook_script = """#!/bin/sh
# TraceOps Git Hook
ACTIVE_TASK_FILE=".traceops_active_task"
if [ -f "$ACTIVE_TASK_FILE" ]; then
    TASK_ID=$(cat "$ACTIVE_TASK_FILE" | tr -d '[:space:]')
    if [ -n "$TASK_ID" ]; then
        COMMIT_MSG_FILE=$1
        FIRST_LINE=$(head -n 1 "$COMMIT_MSG_FILE")
        if ! echo "$FIRST_LINE" | grep -q "\\[TRO-"; then
            sed -i.bak -e "1s/^/[TRO-$TASK_ID] /" "$COMMIT_MSG_FILE"
            rm -f "${COMMIT_MSG_FILE}.bak"
        fi
    fi
fi
"""
    with open(hook_path, "w") as fh:
        fh.write(hook_script)
    os.chmod(hook_path, 0o755)
    print(f"✅ TraceOps Git hook installed at {hook_path}")
    return 0


def set_active_task(task_id: str):
    with open(".traceops_active_task", "w") as fh:
        fh.write(task_id.strip())
    print(f"✅ Active TraceOps task set to: {task_id}")
    send_event("task_active", {"active_task_id": task_id}, task_id=task_id)


def record_command(cmd: str, exit_code: int = 0):
    task_id = None
    if os.path.exists(".traceops_active_task"):
        with open(".traceops_active_task") as fh:
            task_id = fh.read().strip() or None

    send_event("terminal_command", {"command": cmd, "exit_code": exit_code}, task_id=task_id)
    print(f"Recorded command: {cmd} (exit {exit_code})")


def main():
    parser = argparse.ArgumentParser(description="TraceOps Local Telemetry Collector")
    subparsers = parser.add_subparsers(dest="action")

    # install-hook
    subparsers.add_parser("install-hook", help="Install git commit hook")

    # set-task
    task_parser = subparsers.add_parser("set-task", help="Set active task ID for current workspace")
    task_parser.add_argument("task_id", help="UUID of active task")

    # record-cmd
    cmd_parser = subparsers.add_parser("record-cmd", help="Record terminal command execution")
    cmd_parser.add_argument("command", help="Command executed")
    cmd_parser.add_argument("--exit-code", type=int, default=0, help="Command exit code")

    args = parser.parse_args()

    if args.action == "install-hook":
        return install_git_hook()
    elif args.action == "set-task":
        set_active_task(args.task_id)
    elif args.action == "record-cmd":
        record_command(args.command, args.exit_code)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
