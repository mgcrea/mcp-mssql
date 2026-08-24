"""The literal SQL the column lookup sends.

Asserted as text, and in its own file, because every other test stubs the cursor — so the
statement is never run against a real SQL Server. That gap let Postgres syntax ship green and
break every table-referencing query in production while `SELECT 1` kept working.
"""

from __future__ import annotations

from mcp_mssql.tools.mssql import schema_lookup_sql


def test_uses_ord_pairs_not_a_row_value_constructor():
    sql, params = schema_lookup_sql(["dbo.perfevents", "dbo.perfusers"])
    # The exact shape SQL Server refuses with error 4145.
    assert "(LOWER(TABLE_SCHEMA), LOWER(TABLE_NAME))" not in sql
    assert "), (" not in sql
    assert sql.count("LOWER(TABLE_SCHEMA) = %s AND LOWER(TABLE_NAME) = %s") == 2
    assert " OR " in sql
    assert params == ["dbo", "perfevents", "dbo", "perfusers"]


def test_single_table_needs_no_or():
    sql, params = schema_lookup_sql(["dbo.perfevents"])
    assert " OR " not in sql
    assert params == ["dbo", "perfevents"]


def test_table_names_stay_bound_never_interpolated():
    # A table name comes out of the caller's own SQL, so it must ride as a bound parameter
    # and never appear in the statement text.
    sql, params = schema_lookup_sql(["dbo.perfevents"])
    assert "perfevents" not in sql
    assert "perfevents" in params
