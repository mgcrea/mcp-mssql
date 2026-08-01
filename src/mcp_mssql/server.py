"""MCP MSSQL Tool Server — read-only SQL Server access for AI agents."""

import contextlib
import json
import os

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

from mcp.server.fastmcp import FastMCP  # noqa: E402
from mcp.server.transport_security import TransportSecuritySettings  # noqa: E402
from mcp_guard import routes as guard_routes  # noqa: E402

from .tools.mssql import guard, register_mssql_tools  # noqa: E402

logger = structlog.get_logger()

NAME = "mcp-mssql"
VERSION = "0.1.0"

# K8S internal service — no DNS rebinding protection needed
security_settings = TransportSecuritySettings(enable_dns_rebinding_protection=False)

mcp = FastMCP(name=NAME, transport_security=security_settings, streamable_http_path="/mcp")

register_mssql_tools(mcp)
logger.info("registered_mssql_tools")


def register_platform_resources(mcp: FastMCP) -> int:
    """Register resources injected by the platform via MCP_RESOURCES env var.

    The platform serializes assigned resources as a JSON object:
    {"slug": {"name": "...", "description": "...", "text": "..."}, ...}
    """
    raw = os.environ.get("MCP_RESOURCES")
    if not raw:
        return 0

    resources = json.loads(raw)
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
                return content

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

    # `mcp_guard.routes` wraps the MCP app rather than the whole Starlette app — Knative's
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
