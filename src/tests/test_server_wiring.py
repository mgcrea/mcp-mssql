"""The wiring that makes the guard actually apply.

Both things asserted here are invisible in review and fail silently in production, which is
why they are pinned by tests rather than trusted to care:

* A tool registered without `@guarded` authorizes every call on a session against whoever
  sent `initialize`. It behaves perfectly in single-user testing.
* A route list that mounts SSE after the catch-all `Mount("/")` never serves SSE at all,
  because Starlette returns on the first `Match.FULL`.
"""

from __future__ import annotations

import asyncio
from dataclasses import replace

import pytest
from mcp_policy_guard import GuardConfig, is_guarded
from mcp_policy_guard import routes as guard_routes

import mcp_mssql.server as server


def _registered_tool_fns() -> dict[str, object]:
    names = [tool.name for tool in asyncio.run(server.mcp.list_tools())]
    return {name: server.mcp._tool_manager.get_tool(name).fn for name in names}


class TestEveryToolIsGuarded:
    def test_all_registered_tools_carry_the_per_message_binding(self):
        """The test that catches the fourth tool somebody adds later.

        Forgetting `@guarded` on one handler is the realistic failure mode: it reviews
        cleanly, passes every single-user test, and only misbehaves when two people share a
        session — at which point the second one is authorized against the first one's grants
        and the audit row names the wrong person.
        """
        unguarded = [name for name, fn in _registered_tool_fns().items() if not is_guarded(fn)]
        assert unguarded == [], f"tools registered without @guarded: {unguarded}"

    def test_there_are_tools_to_check(self):
        # Guards the guard: if registration ever moved, the assertion above would pass
        # vacuously over an empty set.
        assert set(_registered_tool_fns()) == {
            "mssql_query",
            "mssql_list_tables",
            "mssql_describe_table",
        }

    @pytest.mark.parametrize(
        ("tool", "expected"),
        [
            ("mssql_query", {"query"}),
            ("mssql_list_tables", {"schema"}),
            ("mssql_describe_table", {"table_name", "schema"}),
        ],
    )
    def test_the_decorator_does_not_flatten_the_published_schema(self, tool, expected):
        # The SDK builds each tool's JSON schema from `inspect.signature`. A decorator that
        # dropped `functools.wraps` would publish a tool taking `(*args, **kwargs)` — no
        # parameters at all — and the model would simply stop being able to call it.
        published = next(t for t in asyncio.run(server.mcp.list_tools()) if t.name == tool)
        assert set(published.inputSchema["properties"]) == expected


class TestRouteOrdering:
    def _config(self, *, require_auth: bool) -> GuardConfig:
        return replace(server.guard.config, require_auth=require_auth, issuer="https://idp.test/realms/demo")

    def test_sse_is_reachable_when_it_is_mounted_at_all(self):
        built = guard_routes(server.mcp, self._config(require_auth=False), extra_routes=[])
        paths = [getattr(route, "path", None) for route in built]
        # SSE must come *before* the catch-all. Mounted after it, `Mount("/")` matches every
        # path first and the SSE mount is unreachable dead code — which is what the
        # hand-built list in this server used to do.
        assert paths.index("/sse") < paths.index("")

    def test_no_sse_mount_while_authentication_is_required(self):
        built = guard_routes(server.mcp, self._config(require_auth=True), extra_routes=[])
        paths = [getattr(route, "path", None) for route in built]
        # Under SSE the connection carrying the Authorization header is not the request
        # carrying the tool call, so a call cannot be attributed to a caller. Mounting it
        # anyway is a second, unauthenticated door onto the same tools.
        assert "/sse" not in paths

    def test_health_and_root_stay_ahead_of_the_guarded_mount(self):
        from starlette.routing import Route

        extra = [Route("/healthz", lambda r: None), Route("/", lambda r: None)]
        built = guard_routes(server.mcp, self._config(require_auth=True), extra_routes=extra)
        paths = [getattr(route, "path", None) for route in built]
        # The readiness probe must not be asked for a bearer token by the kubelet.
        assert paths.index("/healthz") < paths.index("")
