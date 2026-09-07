"""Failures that happen before policy could decide anything.

The distinction under test is the one that is easy to lose: a call refused because the
database would not answer is **not** a denial, and must not be recorded, reported or worded
as one. Equally, the identical database failure *after* a decision was reached is an
execution failure and must not be reported at all — reporting it would file a second row
for a call the PDP already ruled on.
"""

from __future__ import annotations

import asyncio
import time
from types import SimpleNamespace
from unittest.mock import MagicMock

import pymssql
import pytest
from mcp_policy_guard import Decision

from mcp_mssql.tools import mssql as tools

from .test_tool_authorization import StubMCP

ALLOWED = Decision(decision="allow", effect="allow", enforcing=True, reason="granted")


@pytest.fixture(autouse=True)
def _allow_by_default(monkeypatch):
    monkeypatch.setattr(tools.guard, "require", lambda *_a, **_k: ALLOWED)
    monkeypatch.setattr(tools.guard, "filter_resources", lambda _kind, values, **_kw: list(values))


@pytest.fixture
def reports(monkeypatch):
    """Capture what the tool reports to the PDP."""
    calls: list[tuple] = []
    monkeypatch.setattr(
        tools.guard,
        "report_not_evaluated",
        lambda function_name, reason, resources=(), **_kw: calls.append((function_name, reason, resources)),
    )
    return calls


@pytest.fixture
def governed(monkeypatch):
    """A tool with a PDP configured, which is the only shape that reads the catalogue.

    Without this the pre-decision connection never happens: `_column_resources` returns `[]`
    when `policy_enabled` is false, so an ungoverned tool opens its first connection at
    execution and there is no precondition step to fail. That is correct — an ungoverned tool
    has no PDP to report to either — and it is why these tests must enable policy explicitly.
    """

    def _governed():
        monkeypatch.setattr(tools.guard, "config", SimpleNamespace(policy_enabled=True))
        monkeypatch.setattr(tools.guard, "snapshot", lambda *_a, **_k: SimpleNamespace(allows=lambda *_: True))

    return _governed


@pytest.fixture
def call_with(monkeypatch):
    def _call(tool_name: str, *args, connect):
        monkeypatch.setattr(tools.pymssql, "connect", connect)
        stub = StubMCP()
        tools.register_mssql_tools(stub)
        return asyncio.run(stub.tools[tool_name](*args))

    return _call


class TestPreDecisionFailureReports:
    # The exact failure Arkadi hit: pymssql 18456 out of the schema read, which escaped both
    # existing handlers and propagated raw, leaving nothing anywhere.
    def test_a_login_failure_while_establishing_the_read_set_is_reported(self, call_with, reports, governed):
        governed()
        connect = MagicMock(side_effect=pymssql.OperationalError("18456 Login failed for user 'svc'"))

        result = call_with("mssql_query", "SELECT id FROM dbo.orders", connect=connect)

        assert len(reports) == 1
        function_name, reason, _resources = reports[0]
        assert function_name == "mssql_query"
        assert "18456" in reason
        assert "Error" in result

    # The whole point: the user must be able to tell "the database is down" from "policy said
    # no". Before this, both produced the same sentence.
    def test_the_message_says_it_was_not_an_access_decision(self, call_with, reports, governed):
        governed()
        connect = MagicMock(side_effect=pymssql.OperationalError("connection refused"))

        result = call_with("mssql_query", "SELECT id FROM dbo.orders", connect=connect)

        assert "not an access decision" in result
        assert "access to" not in result

    def test_list_tables_reports_too(self, call_with, reports):
        connect = MagicMock(side_effect=pymssql.OperationalError("connection refused"))

        result = call_with("mssql_list_tables", "dbo", connect=connect)

        assert len(reports) == 1
        assert reports[0][0] == "mssql_list_tables"
        assert "not an access decision" in result


class TestPostDecisionFailureDoesNotReport:
    # The asymmetry that is easy to lose. With a warm schema cache the first connection opens
    # at EXECUTION — after guard.require passed and after the PDP already wrote an allow row.
    # Reporting there would file a second row for a call that was decided.
    def test_a_failure_after_the_decision_is_not_reported(self, call_with, reports, monkeypatch, governed):
        # Warm the schema cache so `_column_resources` needs no connection of its own.
        governed()
        monkeypatch.setitem(tools._schema_cache, "dbo.orders", (time.monotonic() + 3600, frozenset({"id"})))
        connect = MagicMock(side_effect=pymssql.OperationalError("connection dropped mid-query"))

        # This used to assert the exception PROPAGATED, which was never the property under
        # test — it was the absence of a handler, and FastMCP turned it into a generic string
        # the model could not act on (see `test_execution_errors.py`). The execution path now
        # returns a sentence; what must still hold, and what this test is for, is that it
        # reports nothing to the PDP.
        result = call_with("mssql_query", "SELECT id FROM dbo.orders", connect=connect)

        assert reports == []
        assert result.startswith("Error: ")


class TestParseFailuresDoNotReport:
    # Routine model noise. Reporting each malformed query would bury the infrastructure
    # failures this endpoint exists to surface.
    def test_an_unparseable_query_is_denied_without_reporting(self, call_with, reports):
        never = MagicMock(side_effect=AssertionError("should not connect"))

        result = call_with("mssql_query", "SELECT FROM WHERE ((", connect=never)

        assert reports == []
        assert "Error" in result
