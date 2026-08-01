"""How the tools behave once the guard is wired in.

The call *ordering* is what is under test here, not the policy semantics — those live in
mcp-guard's own suite. Specifically: nothing may open a database connection before the
decision has been made, and a denial must not be distinguishable from absence in the
responses where that distinction would be an enumeration oracle.
"""

from __future__ import annotations

import asyncio
from unittest.mock import MagicMock

import pytest
from mcp_guard import Decision, PolicyDenied

import mcp_mssql.tools.mssql as tools

ALLOWED = Decision(decision="allow", effect="allow", enforcing=True, reason="ok")


class FakeCursor:
    def __init__(self, rows, description):
        self._rows = list(rows)
        self.description = description

    def execute(self, sql, params=None):
        pass

    def fetchall(self):
        rows, self._rows = self._rows, []
        return rows

    def fetchmany(self, size):
        taken, self._rows = self._rows[:size], self._rows[size:]
        return taken

    def fetchone(self):
        return self._rows.pop(0) if self._rows else None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False


class FakeConnection:
    def __init__(self, cursor):
        self._cursor = cursor

    def cursor(self):
        return self._cursor

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False


class StubMCP:
    """Captures the tool functions `register_mssql_tools` decorates."""

    def __init__(self):
        self.tools: dict[str, object] = {}

    def tool(self, *_args, **_kwargs):
        def decorator(fn):
            self.tools[fn.__name__] = fn
            return fn

        return decorator


@pytest.fixture
def call(monkeypatch):
    """Invoke one tool with a fake database behind it.

    `pymssql.connect` is the seam rather than the module's private `_get_connection`, which
    is a closure created inside `register_mssql_tools` and cannot be reached from here.
    """

    def _call(tool_name: str, *args, rows=(), description=(("col1",), ("col2",)), connect=None):
        cursor = FakeCursor(rows, description)
        connect_fn = connect or MagicMock(return_value=FakeConnection(cursor))
        monkeypatch.setattr(tools.pymssql, "connect", connect_fn)

        stub = StubMCP()
        tools.register_mssql_tools(stub)
        return asyncio.run(stub.tools[tool_name](*args))

    return _call


@pytest.fixture
def never_connects(monkeypatch):
    return MagicMock(side_effect=AssertionError("opened a database connection on a denial"))


@pytest.fixture(autouse=True)
def _allow_by_default(monkeypatch):
    monkeypatch.setattr(tools.guard, "require", lambda *_a, **_k: ALLOWED)
    monkeypatch.setattr(tools.guard, "filter_resources", lambda _kind, values, **_kw: list(values))


class TestQueryAuthorization:
    def test_a_denied_query_never_opens_a_connection(self, call, monkeypatch, never_connects):
        # The most important assertion in this file. A check that ran *after* the query
        # would have already read the data it exists to prevent reading.
        monkeypatch.setattr(
            tools.guard,
            "require",
            MagicMock(side_effect=PolicyDenied("denied", resources=("sql_table:hr.payroll",))),
        )
        result = call("mssql_query", "SELECT * FROM hr.Payroll", connect=never_connects)
        assert "do not have access to hr.payroll" in result
        never_connects.assert_not_called()

    def test_names_the_denied_table_back_to_the_model(self, call, monkeypatch):
        # The opposite of the discovery tools, and deliberately so: the model already named
        # this table, so there is no oracle to protect. Being explicit stops a retry loop.
        monkeypatch.setattr(
            tools.guard,
            "require",
            MagicMock(side_effect=PolicyDenied("denied", resources=("sql_table:hr.payroll",))),
        )
        assert "hr.payroll" in call("mssql_query", "SELECT * FROM hr.Payroll")

    def test_authorizes_every_table_a_join_touches(self, call, monkeypatch):
        seen: list[list[str]] = []
        monkeypatch.setattr(
            tools.guard,
            "require",
            lambda _fn, resources=(): (seen.append([r.value for r in resources]), ALLOWED)[1],
        )
        call("mssql_query", "SELECT * FROM dbo.Orders o JOIN hr.Payroll p ON o.id = p.id", rows=[])
        # A join cannot launder access: both tables are submitted, and the platform denies
        # the whole call if either is denied.
        assert seen == [["dbo.orders", "hr.payroll"]]

    def test_a_cte_does_not_hide_the_underlying_table(self, call, monkeypatch):
        seen: list[list[str]] = []
        monkeypatch.setattr(
            tools.guard,
            "require",
            lambda _fn, resources=(): (seen.append([r.value for r in resources]), ALLOWED)[1],
        )
        call("mssql_query", "WITH x AS (SELECT * FROM [hr].[Payroll]) SELECT * FROM x", rows=[])
        assert seen == [["hr.payroll"]]

    def test_submits_the_function_name_so_rules_can_scope_to_it(self, call, monkeypatch):
        seen: list[str] = []
        monkeypatch.setattr(
            tools.guard,
            "require",
            lambda fn, resources=(): (seen.append(fn), ALLOWED)[1],
        )
        call("mssql_query", "SELECT * FROM dbo.Orders", rows=[])
        assert seen == ["mssql_query"]

    def test_an_unanalyzable_query_is_refused_before_any_decision(self, call, monkeypatch, never_connects):
        require = MagicMock()
        monkeypatch.setattr(tools.guard, "require", require)
        result = call(
            "mssql_query",
            "SELECT * FROM dbo.A a CROSS APPLY dbo.fnSecret(a.id) f",
            connect=never_connects,
        )
        assert "cannot be authorized" in result
        # Nothing is asked of the PDP: with no provable read set there is no honest
        # question to ask, and asking a partial one would get a misleading "allow".
        require.assert_not_called()
        never_connects.assert_not_called()

    def test_read_only_validation_still_runs_first(self, call, monkeypatch, never_connects):
        # sqlglot parses DELETE perfectly happily — enumeration is not policy, so the
        # deny-list gate has to stay, and has to stay first.
        require = MagicMock()
        monkeypatch.setattr(tools.guard, "require", require)
        result = call("mssql_query", "DELETE FROM dbo.Orders", connect=never_connects)
        assert result.startswith("Error:")
        require.assert_not_called()
        never_connects.assert_not_called()

    def test_an_allowed_query_returns_its_rows(self, call):
        result = call("mssql_query", "SELECT * FROM dbo.Orders", rows=[("a", 1)])
        assert "col1 | col2" in result
        assert "a | 1" in result


class TestDiscoveryScoping:
    def test_list_tables_hides_denied_names(self, call, monkeypatch):
        monkeypatch.setattr(
            tools.guard,
            "filter_resources",
            lambda _kind, values, **_kw: [v for v in values if v != "Payroll"],
        )
        result = call(
            "mssql_list_tables",
            "dbo",
            rows=[("Orders",), ("Payroll",), ("Customers",)],
            description=[("TABLE_NAME",)],
        )
        assert "Orders" in result and "Customers" in result
        # No count, no placeholder, no "1 hidden" — the denied name must not be inferable
        # from the response at all.
        assert "Payroll" not in result
        assert "hidden" not in result.lower()

    def test_list_tables_looks_empty_when_everything_is_denied(self, call, monkeypatch):
        monkeypatch.setattr(tools.guard, "filter_resources", lambda _kind, _values, **_kw: [])
        result = call("mssql_list_tables", "dbo", rows=[("Orders",), ("Payroll",)], description=[("TABLE_NAME",)])
        # Byte-identical to a genuinely empty schema.
        assert result == "No tables found in schema 'dbo'"

    def test_list_tables_normalizes_names_the_way_rules_are_written(self, call, monkeypatch):
        seen: list[str] = []

        def fake_filter(_kind, values, **kwargs):
            key = kwargs["key"]
            seen.extend(key(v) for v in values)
            return list(values)

        monkeypatch.setattr(tools.guard, "filter_resources", fake_filter)
        call("mssql_list_tables", "HR", rows=[("Payroll",)], description=[("TABLE_NAME",)])
        # Must match what extract_referenced_tables produces, or a table would be listed
        # under one spelling and authorized under another.
        assert seen == ["hr.payroll"]

    def test_describe_table_authorizes_before_it_queries(self, call, monkeypatch, never_connects):
        monkeypatch.setattr(tools.guard, "require", MagicMock(side_effect=PolicyDenied("denied")))
        result = call("mssql_describe_table", "Payroll", "dbo", connect=never_connects)
        assert result == "Table 'dbo.Payroll' not found"
        never_connects.assert_not_called()

    def test_describe_table_denial_is_indistinguishable_from_absence(self, call, monkeypatch):
        monkeypatch.setattr(tools.guard, "require", MagicMock(side_effect=PolicyDenied("denied")))
        denied = call("mssql_describe_table", "Payroll", "dbo")

        monkeypatch.setattr(tools.guard, "require", lambda *_a, **_k: ALLOWED)
        absent = call("mssql_describe_table", "Payroll", "dbo", rows=[], description=[("COLUMN_NAME",)])

        # Distinguishing the two would confirm the table is real — the enumeration oracle
        # that filtering `mssql_list_tables` exists to avoid, rebuilt one name at a time.
        assert denied == absent


class TestRowCap:
    def test_caps_the_number_of_rows_returned(self, call, monkeypatch):
        # The tool used to call fetchall() unbounded, so `SELECT * FROM tbDat_CRM_Leads`
        # would materialise ~372K rows into the pod and then into the model's context.
        monkeypatch.setattr(tools, "MAX_ROWS", 2)
        result = call("mssql_query", "SELECT * FROM dbo.Orders", rows=[("a", 1), ("b", 2), ("c", 3)])
        assert "Truncated at 2 rows" in result
        assert "c | 3" not in result

    def test_does_not_claim_truncation_when_the_result_fits_exactly(self, call, monkeypatch):
        # Off-by-one worth pinning: exactly MAX_ROWS rows is a complete result, not a
        # truncated one, and saying otherwise would send the model chasing a next page that
        # does not exist.
        monkeypatch.setattr(tools, "MAX_ROWS", 2)
        result = call("mssql_query", "SELECT * FROM dbo.Orders", rows=[("a", 1), ("b", 2)])
        assert "Truncated" not in result

    def test_a_short_result_is_returned_whole(self, call, monkeypatch):
        monkeypatch.setattr(tools, "MAX_ROWS", 10)
        result = call("mssql_query", "SELECT * FROM dbo.Orders", rows=[("a", 1)])
        assert "a | 1" in result
        assert "Truncated" not in result
