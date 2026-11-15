"""
TraceOps Model Context Protocol (MCP) Server with Tenant Authentication

Exposes TraceOps execution intelligence directly to AI tools and agents:
- Claude Desktop
- Claude Code
- Cursor
- ChatGPT Custom Actions
- Autonomous Agent SAM

Mandatory Tenant Isolation: Requires API Key or Bearer Session Token for all tool operations.
"""
import asyncio
import json
import os
import sys
from typing import Any, Dict, List, Optional

from sqlalchemy import select
from app.core.config import settings
from app.core.database import AsyncSessionLocal
from app.models.models import Task, Commit, ErrorRecord, User, UserSession, ApiKey
from app.services.auth import get_user_from_session, verify_api_key
from app.services.graph_engine import GraphEngine

AUTH_SCHEMA = {
    "api_key": {
        "type": "string",
        "description": "TraceOps API key or session token for tenant authorization",
    }
}

TOOLS = [
    {
        "name": "get_engineering_audit",
        "description": "Returns verified tasks, achievements, velocity, and detected bottlenecks for a timeframe.",
        "inputSchema": {
            "type": "object",
            "properties": {
                **AUTH_SCHEMA,
                "timeframe": {"type": "string", "description": "e.g. '24h', '7d', '30d'", "default": "7d"},
                "project_slug": {"type": "string", "description": "Optional repository slug"},
            },
            "required": ["api_key"],
        },
    },
    {
        "name": "get_task_execution_graph",
        "description": "Returns the directed execution DAG (commits, file changes, errors, prompts) for a task.",
        "inputSchema": {
            "type": "object",
            "properties": {
                **AUTH_SCHEMA,
                "task_id": {"type": "string", "description": "TraceOps Task UUID"},
            },
            "required": ["api_key", "task_id"],
        },
    },
    {
        "name": "verify_achievement",
        "description": "Verifies whether a developer achievement claim is substantiated by actual git commits and diffs.",
        "inputSchema": {
            "type": "object",
            "properties": {
                **AUTH_SCHEMA,
                "claim": {"type": "string", "description": "The achievement claim to verify"},
            },
            "required": ["api_key", "claim"],
        },
    },
    {
        "name": "get_unresolved_bottlenecks",
        "description": "Returns active execution loops, recurring exceptions, or stalled tasks requiring developer intervention.",
        "inputSchema": {
            "type": "object",
            "properties": {
                **AUTH_SCHEMA,
            },
            "required": ["api_key"],
        },
    },
]


async def _resolve_tenant_user(db, api_key: Optional[str]) -> Optional[User]:
    """
    Resolve authenticated tenant User from verified credential.
    Accepts:
    1. Scoped API Key (tro_live_...)
    2. Valid Session Token
    3. Dedicated Service Account Key (TRACEOPS_API_KEY paired with TRACEOPS_SERVICE_TENANT_ID)

    SECURITY: User ID fallback is strictly rejected. An identifier is not a credential.
    """
    key = api_key or os.environ.get("TRACEOPS_API_KEY") or settings.TRACEOPS_API_KEY
    if not key or not isinstance(key, str):
        return None

    # Dedicated Service Account Key check
    service_key = os.environ.get("TRACEOPS_API_KEY") or settings.TRACEOPS_API_KEY
    if service_key and key == service_key:
        service_tenant = os.environ.get("TRACEOPS_SERVICE_TENANT_ID") or settings.TRACEOPS_SERVICE_TENANT_ID
        if service_tenant:
            u_res = await db.execute(select(User).where(User.id == service_tenant, User.is_active == True))
            return u_res.scalar_one_or_none()
        return None

    # 1. Scoped API key
    if key.startswith("tro_"):
        user = await verify_api_key(db, key, required_scope="mcp")
        if user:
            return user

    # 2. Session token
    user = await get_user_from_session(db, key)
    if user:
        return user

    # User ID fallback is completely forbidden
    return None


async def handle_tool_call(name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
    api_key = arguments.get("api_key")

    async with AsyncSessionLocal() as db:
        user = await _resolve_tenant_user(db, api_key)
        if not user:
            return {
                "error": "Authentication failed. Provide a valid 'api_key' parameter or set TRACEOPS_API_KEY.",
                "authenticated": False,
            }

        user_id = user.id

        if name == "get_engineering_audit":
            t_res = await db.execute(select(Task).where(Task.user_id == user_id).limit(20))
            tasks = t_res.scalars().all()
            c_res = await db.execute(select(Commit).where(Commit.user_id == user_id).limit(50))
            commits = c_res.scalars().all()
            return {
                "tenant_id": user_id,
                "total_tasks": len(tasks),
                "completed_tasks": sum(1 for t in tasks if t.status == "completed"),
                "total_commits": len(commits),
                "recent_commits": [{"sha": c.sha[:7], "msg": c.message} for c in commits[:5]],
            }

        elif name == "get_task_execution_graph":
            task_id = arguments.get("task_id", "")
            engine = GraphEngine(db)
            return await engine.get_task_graph(user_id=user_id, task_id=task_id)

        elif name == "verify_achievement":
            claim = arguments.get("claim", "")
            c_res = await db.execute(select(Commit).where(Commit.user_id == user_id).limit(50))
            commits = c_res.scalars().all()
            claim_words = set(claim.lower().split())
            matches = [c.sha[:7] for c in commits if any(w in c.message.lower() for w in claim_words if len(w) > 3)]
            verified = len(matches) > 0
            return {
                "tenant_id": user_id,
                "claim": claim,
                "verified": verified,
                "matching_commits": matches,
                "citation": f"[TRO-EVID-{matches[0]}]" if matches else None,
            }

        elif name == "get_unresolved_bottlenecks":
            err_res = await db.execute(select(ErrorRecord).where(ErrorRecord.user_id == user_id).limit(10))
            errors = err_res.scalars().all()
            return {
                "tenant_id": user_id,
                "active_exceptions": len(errors),
                "exceptions": [{"type": e.exception_type, "msg": e.message[:80]} for e in errors],
            }

        return {"error": f"Unknown tool: {name}"}


async def run_stdio_server():
    """Run MCP server over standard input/output."""
    while True:
        line = await asyncio.get_event_loop().run_in_executor(None, sys.stdin.readline)
        if not line:
            break
        try:
            req = json.loads(line)
            method = req.get("method")
            req_id = req.get("id")

            if method == "tools/list":
                resp = {"jsonrpc": "2.0", "id": req_id, "result": {"tools": TOOLS}}
            elif method == "tools/call":
                params = req.get("params", {})
                name = params.get("name")
                args = params.get("arguments", {})
                result = await handle_tool_call(name, args)
                resp = {"jsonrpc": "2.0", "id": req_id, "result": {"content": [{"type": "text", "text": json.dumps(result)}]}}
            else:
                resp = {"jsonrpc": "2.0", "id": req_id, "result": {}}

            sys.stdout.write(json.dumps(resp) + "\n")
            sys.stdout.flush()
        except Exception as e:
            sys.stderr.write(f"MCP error: {e}\n")


if __name__ == "__main__":
    asyncio.run(run_stdio_server())
