"""Adversarial tests for row-predicate rewriting.

**A security artifact, like the two extraction suites.** The failure mode here is quieter than
theirs: a predicate that is dropped, mangled or applied to the wrong table does not raise — it
returns rows the caller was never entitled to, in a response that looks exactly like a
correctly scoped one.

So the bar for every case is: does the rewritten SQL still constrain every reference to the
governed table, and does anything that cannot be done exactly refuse instead?
"""

from __future__ import annotations

import pytest
import sqlglot

from mcp_mssql.row_filters import RowFilterError, RowPredicate, apply_row_filters

SCHEMA = {
    "dbo.perfevents": {"Id", "UserId", "PPH", "District"},
    "dbo.perfusers": {"Id", "FullName", "DateOfBirth"},
}

DISTRICTS = (RowPredicate("dbo.perfevents", "District", "in_", ("D775",)),)


def rewrite(query: str, predicates=DISTRICTS, schema=None) -> str:
    return apply_row_filters(query, predicates, schema_map=schema or SCHEMA, database="rgis")


def wrappers(sql: str) -> int:
    """How many times the governed table was wrapped in a filtering subquery."""
    return sql.upper().count("WHERE DISTRICT IN")


class TestEveryReferenceIsConstrained:
    def test_a_simple_select(self):
        assert wrappers(rewrite("SELECT PPH FROM dbo.PerfEvents")) == 1

    def test_preserves_the_alias_so_outer_references_still_resolve(self):
        out = rewrite("SELECT e.PPH FROM dbo.PerfEvents e WHERE e.PPH > 1")
        assert ") AS e" in out
        # The inner reference must NOT keep the alias, or it shadows the wrapper's.
        assert "dbo.PerfEvents AS e" not in out

    def test_each_arm_of_a_union_is_wrapped_independently(self):
        # One wrapper would leave the other arm reading every district.
        assert wrappers(rewrite("SELECT PPH FROM dbo.PerfEvents UNION ALL SELECT PPH FROM dbo.PerfEvents")) == 2

    def test_a_join_wraps_only_the_governed_table(self):
        out = rewrite("SELECT u.FullName, e.PPH FROM dbo.PerfUsers u JOIN dbo.PerfEvents e ON e.UserId = u.Id")
        assert wrappers(out) == 1
        assert "dbo.PerfUsers AS u" in out

    def test_a_cte_body_is_wrapped(self):
        # The predicate has to reach inside the CTE: wrapping only the outer reference would
        # filter a result set that was already computed over every district.
        assert wrappers(rewrite("WITH x AS (SELECT PPH FROM dbo.PerfEvents) SELECT * FROM x")) == 1

    def test_a_correlated_subquery_is_wrapped(self):
        out = rewrite(
            "SELECT u.FullName FROM dbo.PerfUsers u WHERE EXISTS (SELECT 1 FROM dbo.PerfEvents e WHERE e.UserId = u.Id)"
        )
        assert wrappers(out) == 1

    def test_the_result_still_parses(self):
        out = rewrite("SELECT u.FullName, e.PPH FROM dbo.PerfUsers u JOIN dbo.PerfEvents e ON e.UserId = u.Id")
        assert sqlglot.parse_one(out, dialect="tsql") is not None


class TestValueHandling:
    def test_quotes_are_escaped_not_interpolated(self):
        out = rewrite(
            "SELECT PPH FROM dbo.PerfEvents", (RowPredicate("dbo.perfevents", "District", "in_", ("D'775",)),)
        )
        assert "'D''775'" in out
        assert sqlglot.parse_one(out, dialect="tsql") is not None

    def test_a_value_that_looks_like_sql_stays_a_literal(self):
        hostile = "') OR 1=1 --"
        out = rewrite(
            "SELECT PPH FROM dbo.PerfEvents", (RowPredicate("dbo.perfevents", "District", "in_", (hostile,)),)
        )
        # It must appear as one escaped string literal, never as syntax.
        assert "OR 1=1" not in out.replace("''", "'").split("IN (")[0]
        assert sqlglot.parse_one(out, dialect="tsql") is not None

    def test_not_in_negates(self):
        out = rewrite(
            "SELECT PPH FROM dbo.PerfEvents", (RowPredicate("dbo.perfevents", "District", "not_in", ("D775",)),)
        )
        assert "NOT" in out.upper()

    def test_eq_renders_an_equality(self):
        out = rewrite("SELECT PPH FROM dbo.PerfEvents", (RowPredicate("dbo.perfevents", "District", "eq", ("D775",)),))
        assert "District = 'D775'" in out


class TestFailsClosed:
    def test_a_column_the_table_does_not_have(self):
        with pytest.raises(RowFilterError, match="not a column"):
            rewrite("SELECT PPH FROM dbo.PerfEvents", (RowPredicate("dbo.perfevents", "Nope", "in_", ("a",)),))

    def test_a_table_whose_columns_are_unknown(self):
        with pytest.raises(RowFilterError, match="unavailable"):
            rewrite("SELECT PPH FROM dbo.PerfEvents", schema={"dbo.perfevents": set()})

    def test_eq_with_more_than_one_value(self):
        with pytest.raises(RowFilterError, match="eq"):
            rewrite("SELECT PPH FROM dbo.PerfEvents", (RowPredicate("dbo.perfevents", "District", "eq", ("a", "b")),))

    def test_an_empty_predicate(self):
        # The PDP denies rather than sending one, so reaching here means the two sides
        # disagree — and `IN ()` means different things on different engines.
        with pytest.raises(RowFilterError, match="no values"):
            rewrite("SELECT PPH FROM dbo.PerfEvents", (RowPredicate("dbo.perfevents", "District", "in_", ()),))

    def test_an_unknown_operator(self):
        with pytest.raises(RowFilterError, match="operator"):
            rewrite("SELECT PPH FROM dbo.PerfEvents", (RowPredicate("dbo.perfevents", "District", "like", ("a",)),))

    def test_a_predicate_for_a_table_the_query_does_not_read(self):
        # The read set and the decision disagree; one of them is wrong, and running unscoped
        # is the wrong way to resolve it.
        with pytest.raises(RowFilterError, match="does not read"):
            rewrite("SELECT FullName FROM dbo.PerfUsers")


class TestNoPredicates:
    def test_returns_the_query_untouched(self):
        query = "SELECT PPH FROM dbo.PerfEvents"
        assert apply_row_filters(query, (), schema_map=SCHEMA, database="rgis") is query
