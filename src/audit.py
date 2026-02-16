"""Audit logging for MCP tool calls."""

import json
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any

import structlog

logger = structlog.get_logger()


def _sanitize_params(params: dict[str, Any]) -> dict[str, Any]:
    """Sanitize parameters for logging (truncate long values, mask sensitive data)."""
    sanitized = {}
    sensitive_keys = {"password", "secret", "token", "key", "credential"}

    for key, value in params.items():
        # Mask sensitive values
        if any(s in key.lower() for s in sensitive_keys):
            sanitized[key] = "***REDACTED***"
        # Truncate long strings
        elif isinstance(value, str) and len(value) > 500:
            sanitized[key] = value[:500] + "...[truncated]"
        else:
            sanitized[key] = value

    return sanitized


@contextmanager
def audit_log(tool_name: str, params: dict[str, Any]):
    """Context manager for audit logging tool calls.

    Usage:
        with audit_log("mssql_query", {"query": "SELECT * FROM users"}):
            result = execute_query(...)
    """
    start_time = time.perf_counter()
    sanitized_params = _sanitize_params(params)

    log_entry = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "tool": tool_name,
        "params": sanitized_params,
    }

    try:
        yield
        duration_ms = (time.perf_counter() - start_time) * 1000
        log_entry["duration_ms"] = round(duration_ms, 2)
        log_entry["success"] = True
        print(json.dumps(log_entry), flush=True)
        logger.info("tool_call", **log_entry)
    except Exception as e:
        duration_ms = (time.perf_counter() - start_time) * 1000
        log_entry["duration_ms"] = round(duration_ms, 2)
        log_entry["success"] = False
        log_entry["error"] = str(e)
        print(json.dumps(log_entry), flush=True)
        logger.error("tool_call_failed", **log_entry)
        raise
