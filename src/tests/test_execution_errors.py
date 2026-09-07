"""What the model is told when SQL Server rejects the statement it wrote.

Every other refusal path in `_sync_mssql_query` returns a sentence. Execution did not: the
`pymssql` exception escaped into FastMCP, which replaced it with `Error executing tool
mssql_query` and nothing else — 208 occurrences across 72 chats, 11 users and 5 assistants
between 2026-06-12 and 2026-09-03. Blind, the model cannot correct its own SQL; on 2026-09-07
one reply re-sent a single failing query eleven times because the real message never reached it.

The error tuples below are the ones pymssql actually produced against Sheffield on 2026-09-07,
copied verbatim rather than invented, because the two packings are what the sanitiser
discriminates on.
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

# --- measured against Sheffield, 2026-09-07 -------------------------------------------------
INVALID_COLUMN = pymssql.ProgrammingError(
    207,
    b"Invalid column name 'StatusName'.DB-Lib error message 20018, severity 16:\n"
    b"General SQL Server error: Check messages from the SQL Server\n",
)
BAD_CONVERSION = pymssql.OperationalError(
    245,
    b"Conversion failed when converting the varchar value 'EUR' to data type int."
    b"DB-Lib error message 20018, severity 16:\n"
    b"General SQL Server error: Check messages from the SQL Server\n",
)
# Note the shape: one arg, itself a tuple, and the text names the server.
UNREACHABLE = pymssql.OperationalError(
    (
        20009,
        b"DB-Lib error message 20009, severity 9:\nUnable to connect: Adaptive Server is "
        b"unavailable or does not exist (10.255.255.1)\nNet-Lib error during Operation timed out (110)\n",
    )
)


@pytest.fixture(autouse=True)
def _allow_by_default(monkeypatch):
    monkeypatch.setattr(tools.guard, "require", lambda *_a, **_k: ALLOWED)
    monkeypatch.setattr(tools.guard, "filter_resources", lambda _kind, values, **_kw: list(values))
    monkeypatch.setattr(tools.guard, "config", SimpleNamespace(policy_enabled=False))


@pytest.fixture
def reports(monkeypatch):
    calls: list[tuple] = []
    monkeypatch.setattr(
        tools.guard,
        "report_not_evaluated",
        lambda function_name, reason, resources=(), **_kw: calls.append((function_name, reason, resources)),
    )
    return calls


@pytest.fixture
def failing_execute(monkeypatch):
    """Connect succeeds; `cur.execute` raises. That is where a rejected statement fails."""

    def _install(exc):
        cursor = MagicMock()
        cursor.execute.side_effect = exc
        cursor.__enter__ = MagicMock(return_value=cursor)
        cursor.__exit__ = MagicMock(return_value=False)
        conn = MagicMock()
        conn.cursor.return_value = cursor
        conn.__enter__ = MagicMock(return_value=conn)
        conn.__exit__ = MagicMock(return_value=False)
        monkeypatch.setattr(tools.pymssql, "connect", MagicMock(return_value=conn))
        # Warm the cache so no connection is needed before the decision.
        monkeypatch.setitem(tools._schema_cache, "dbo.orders", (time.monotonic() + 3600, frozenset({"id"})))
        stub = StubMCP()
        tools.register_mssql_tools(stub)
        return asyncio.run(stub.tools["mssql_query"]("SELECT id FROM dbo.orders"))

    return _install


class TestTheModelIsToldWhatWentWrong:
    def test_an_invalid_column_names_the_column(self, failing_execute):
        result = failing_execute(INVALID_COLUMN)

        assert "Invalid column name 'StatusName'." in result
        assert result.startswith("Error: ")

    def test_a_failed_conversion_names_the_value_and_the_type(self, failing_execute):
        result = failing_execute(BAD_CONVERSION)

        assert "Conversion failed when converting the varchar value 'EUR' to data type int." in result

    # The trailer is identical on every SQL Server error and tells the caller nothing.
    def test_the_db_lib_trailer_is_dropped(self, failing_execute):
        result = failing_execute(INVALID_COLUMN)

        assert "DB-Lib" not in result
        assert "severity" not in result

    # The regression that started this: it must no longer escape into FastMCP's generic string.
    def test_the_exception_does_not_propagate(self, failing_execute):
        result = failing_execute(BAD_CONVERSION)

        assert isinstance(result, str)


class TestTransportFailuresSayNothingAboutTheQuery:
    # The client-side text quotes the server address. It must never reach a prompt.
    def test_the_server_address_is_not_leaked(self, failing_execute):
        result = failing_execute(UNREACHABLE)

        assert "10.255.255.1" not in result
        assert "Adaptive Server" not in result
        assert "DB-Lib" not in result

    def test_it_is_not_described_as_an_access_decision_or_a_bad_query(self, failing_execute):
        result = failing_execute(UNREACHABLE)

        assert "not an access decision" in result
        assert "not a problem with the query" in result


class TestExecutionFailuresAreStillNotReported:
    # The asymmetry the pre-decision handler documents: guard.require already passed and the
    # PDP already wrote an allow row, so reporting here would file a second row for one call.
    def test_a_rejected_statement_reports_nothing(self, failing_execute, reports):
        failing_execute(INVALID_COLUMN)

        assert reports == []

    def test_an_unreachable_server_at_execution_reports_nothing(self, failing_execute, reports):
        failing_execute(UNREACHABLE)

        assert reports == []


class TestTheSanitiser:
    def test_a_long_message_is_bounded_before_it_reaches_a_prompt(self):
        huge = pymssql.OperationalError(245, b"x" * 5000)

        assert len(tools._sql_server_error_text(huge)) == tools.MAX_ERROR_CHARS

    def test_a_client_side_number_yields_nothing(self):
        assert tools._sql_server_error_text(UNREACHABLE) is None

    # A positive control for the discriminator: it does return text when there is text.
    def test_a_server_side_number_yields_the_text(self):
        assert tools._sql_server_error_text(INVALID_COLUMN) == "Invalid column name 'StatusName'."

    def test_an_unrecognised_shape_yields_nothing_rather_than_guessing(self):
        assert tools._sql_server_error_text(pymssql.Error("no structure at all")) is None
