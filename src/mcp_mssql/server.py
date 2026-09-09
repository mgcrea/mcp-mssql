"""MCP MSSQL Tool Server — read-only SQL Server access for AI agents."""

import contextlib
import json
import os
import pathlib

import structlog

structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.JSONRenderer(),
    ],
    wrapper_class=structlog.stdlib.BoundLogger,
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    cache_logger_on_first_use=True,
)

from mcp.server.mcpserver import MCPServer  # noqa: E402
from mcp.server.transport_security import TransportSecuritySettings  # noqa: E402
from mcp_policy_guard import routes as guard_routes  # noqa: E402

from .tools.mssql import guard, register_mssql_tools  # noqa: E402

logger = structlog.get_logger()

NAME = "mcp-mssql"
VERSION = "0.1.0"

# K8S internal service — no DNS rebinding protection needed.
#
# This must be passed explicitly, and passing nothing is NOT equivalent. On SDK 2.x
# `streamable_http_app()` defaults `host` to "127.0.0.1", and on that default it
# *auto-enables* rebinding protection with a localhost-only allow-list. Every request
# reaching this pod under its real service hostname would then be answered
# `421 Invalid Host header` — in K8S, that is every request there is.
security_settings = TransportSecuritySettings(enable_dns_rebinding_protection=False)

# Transport options left the constructor in 2.x; they now live only on the app builders,
# which `guard_routes` forwards to via `app_kwargs`.
mcp = MCPServer(name=NAME, version=VERSION)

register_mssql_tools(mcp)
logger.info("registered_mssql_tools")


_resources_cache: dict | None = None
_resources_mtime: float | None = None


def _load_platform_resources() -> dict:
    """The platform's assigned resources, as {slug: {name, description, text}}.

    Two delivery routes, and the file wins. `MCP_RESOURCES_PATH` points at a file mounted from
    the worker's ConfigMap; `MCP_RESOURCES` is the original environment variable, which Linux
    caps at 131071 bytes for the whole `NAME=VALUE` — a limit the assigned documents outgrew.
    The platform writes both while the value still fits, so an old image and a new one both
    work and the two sides can be released in either order.

    Parsed once and re-parsed only when the file's mtime moves. A `stat` per call is free; the
    parse is not, since one payload runs to a couple of hundred kilobytes. The mtime check
    rather than a plain import-time parse is what lets a ConfigMap update reach a running pod
    later, when the platform learns to rewrite it outside a deploy — today nothing does, so
    this is equivalent to parsing once, and it costs eight lines to not have to remember.
    """
    global _resources_cache, _resources_mtime

    path = os.environ.get("MCP_RESOURCES_PATH")
    if path:
        try:
            mtime = pathlib.Path(path).stat().st_mtime
        except FileNotFoundError:
            # The variable is injected before every runtime can read the file, so a missing
            # mount is a rollout state rather than an error. Fall through to the env var.
            pass
        else:
            if _resources_cache is None or mtime != _resources_mtime:
                _resources_cache = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
                _resources_mtime = mtime
            return _resources_cache

    raw = os.environ.get("MCP_RESOURCES")
    return json.loads(raw) if raw else {}


def register_platform_resources(mcp: MCPServer) -> int:
    """Register resources the platform assigned to this worker.

    The platform serializes assigned resources as a JSON object:
    {"slug": {"name": "...", "description": "...", "text": "..."}, ...}
    """
    resources = _load_platform_resources()
    if not resources:
        return 0

    for slug, meta in resources.items():
        text = meta["text"]

        def _make_reader(s: str, m: dict, content: str):
            @mcp.resource(
                f"resource://{s}",
                name=m.get("name", s),
                description=m.get("description", ""),
                mime_type="text/plain",
            )
            def _read() -> str:
                # Resolved through the loader rather than returned from the closure, so a
                # refreshed file is picked up. `content` is the value captured at registration
                # and is the fallback for a slug that has since been removed — the resource
                # list itself is fixed at import either way.
                return _load_platform_resources().get(s, {}).get("text", content)

        _make_reader(slug, meta, text)

    return len(resources)


resource_count = register_platform_resources(mcp)
if resource_count:
    logger.info("registered_platform_resources", count=resource_count)


def main():
    """Entry point for the MCP MSSQL server."""
    import uvicorn
    from starlette.applications import Starlette
    from starlette.responses import JSONResponse
    from starlette.routing import Route

    port = int(os.environ.get("MCP_PORT", "8080"))
    host = os.environ.get("MCP_HOST", "0.0.0.0")

    async def healthz(request):
        return JSONResponse(
            {
                "status": "healthy",
                "server": NAME,
                "version": VERSION,
                "git_commit": os.environ.get("GIT_COMMIT_SHORT"),
            }
        )

    async def root(request):
        transports = {"streamable-http": "/mcp"}
        if guard.config.sse_allowed:
            transports["sse"] = "/sse"
        return JSONResponse(
            {
                "name": NAME,
                "version": VERSION,
                "protocol": "mcp",
                "transports": transports,
            }
        )

    @contextlib.asynccontextmanager
    async def lifespan(app):
        async with mcp.session_manager.run():
            yield

    # `mcp_policy_guard.routes` wraps the MCP app rather than the whole Starlette app — Knative's
    # readiness probe hits /healthz, and a Starlette-level middleware would demand a bearer
    # token from the kubelet — and mounts SSE, when permitted, at its own path.
    #
    # It replaces a hand-built list that appended `Mount("/", app=mcp.sse_app())` after the
    # guarded `Mount("/")`. Starlette returns on the first `Match.FULL` and `Mount("/")`
    # matches every path, so that second mount was unreachable: SSE was never actually
    # served, and the branch that looked like it enabled it did nothing.
    if not guard.config.sse_allowed:
        # Under SSE the long-lived connection that carried the Authorization header is not
        # the request that carries a tool call, so the principal established at connect time
        # cannot be attributed to the call. Mounting it while requiring auth would leave a
        # second, unauthenticated door onto the same tools.
        logger.info("sse_transport_disabled", reason="MCP_REQUIRE_AUTH is enabled")

    app = Starlette(
        routes=guard_routes(
            mcp,
            guard.config,
            extra_routes=[Route("/healthz", healthz), Route("/", root)],
            app_kwargs={"transport_security": security_settings, "streamable_http_path": "/mcp"},
            sse_app_kwargs={"transport_security": security_settings},
        ),
        lifespan=lifespan,
    )

    logger.info(
        "starting_server",
        host=host,
        port=port,
        require_auth=guard.config.require_auth,
        policy_enabled=guard.config.policy_enabled,
        fail_mode=guard.config.fail_mode,
    )
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    main()
