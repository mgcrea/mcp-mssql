"""MCP MSSQL Tool Server — read-only SQL Server access for AI agents."""

import contextlib
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

from tools.mssql import register_mssql_tools  # noqa: E402

logger = structlog.get_logger()

NAME = "mcp-mssql"
VERSION = "0.1.0"

# K8S internal service — no DNS rebinding protection needed
security_settings = TransportSecuritySettings(enable_dns_rebinding_protection=False)

mcp = FastMCP(name=NAME, transport_security=security_settings, streamable_http_path="/")

register_mssql_tools(mcp)
logger.info("registered_mssql_tools")


def main():
    """Entry point for the MCP MSSQL server."""
    import uvicorn
    from starlette.applications import Starlette
    from starlette.responses import JSONResponse
    from starlette.routing import Mount, Route

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
        return JSONResponse(
            {
                "name": NAME,
                "version": VERSION,
                "protocol": "mcp",
                "transports": {
                    "streamable-http": "/mcp",
                    "sse": "/sse",
                },
            }
        )

    @contextlib.asynccontextmanager
    async def lifespan(app):
        async with mcp.session_manager.run():
            yield

    app = Starlette(
        routes=[
            Route("/healthz", healthz),
            Route("/", root),
            Mount("/mcp", app=mcp.streamable_http_app()),
            Mount("/", app=mcp.sse_app()),
        ],
        lifespan=lifespan,
    )

    logger.info("starting_server", host=host, port=port)
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    main()
