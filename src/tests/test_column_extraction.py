"""Adversarial tests for column enumeration.

**Reviewed as a security artifact, like `test_table_extraction.py`.** Every assertion is an
exact set rather than a membership check: `assert "dbo.perfusers.dateofbirth" in columns`
would pass for an extractor that returned every column in the database and would say nothing
about the property that matters — that nothing was missed.

A false negative is a breach. A query that reads `NationalInsuranceNumber` but whose extracted
set omits it gets authorized against the columns it did admit to, and the personal data comes
back.
"""

from __future__ import annotations

import pytest

from mcp_mssql.column_extraction import ColumnExtractionError, extract_referenced_columns

#: The PerfTrack shape the feature exists for: personal fields sharing a join with
#: performance data a district manager may legitimately read.
SCHEMA = {
    "dbo.perfusers": {"Id", "FullName", "DateOfBirth", "NationalInsuranceNumber", "HomeAddress"},
    "dbo.perfevents": {"Id", "UserId", "PPH", "District"},
}


def columns(query: str, schema=None, **kwargs) -> set[str]:
    return extract_referenced_columns(query, schema_map=schema or SCHEMA, **kwargs)


class TestBasicShapes:
    def test_qualified_columns_resolve_through_aliases(self):
        assert columns("SELECT u.FullName, e.PPH FROM dbo.PerfUsers u JOIN dbo.PerfEvents e ON e.UserId = u.Id") == {
            "dbo.perfusers.fullname",
            "dbo.perfusers.id",
            "dbo.perfevents.pph",
            "dbo.perfevents.userid",
        }

    def test_unqualified_column_resolves_to_its_only_table(self):
        assert columns("SELECT FullName FROM dbo.PerfUsers") == {"dbo.perfusers.fullname"}

    def test_predicate_columns_count_as_reads(self):
        # A WHERE clause reads the column it filters on, and filtering on a value is a way to
        # learn it — so a column named only in a predicate must still be authorized.
        assert columns("SELECT e.PPH FROM dbo.PerfEvents e WHERE e.District = 'D775'") == {
            "dbo.perfevents.pph",
            "dbo.perfevents.district",
        }

    def test_star_expands_to_every_column_including_the_personal_ones(self):
        assert columns("SELECT * FROM dbo.PerfUsers") == {
            "dbo.perfusers.id",
            "dbo.perfusers.fullname",
            "dbo.perfusers.dateofbirth",
            "dbo.perfusers.nationalinsurancenumber",
            "dbo.perfusers.homeaddress",
        }

    def test_alias_star_expands_too(self):
        assert columns("SELECT u.* FROM dbo.PerfUsers u") == {
            "dbo.perfusers.id",
            "dbo.perfusers.fullname",
            "dbo.perfusers.dateofbirth",
            "dbo.perfusers.nationalinsurancenumber",
            "dbo.perfusers.homeaddress",
        }


class TestFailsClosed:
    def test_a_table_missing_from_the_schema_map_is_refused(self):
        # The trap this module exists to close: qualify() returns ZERO columns for a table it
        # has no schema for, which on an allow-list reads as "touches nothing" and is allowed.
        with pytest.raises(ColumnExtractionError, match="unavailable for"):
            columns("SELECT * FROM dbo.Unknown", schema={"dbo.perfusers": {"Id"}})

    def test_an_empty_schema_entry_counts_as_missing(self):
        # `_load_schema_map` returns an empty set for a table INFORMATION_SCHEMA said nothing
        # about, so the key is present while the schema is unknown. Every real table has at
        # least one column, so an empty entry must fail closed exactly like an absent one.
        with pytest.raises(ColumnExtractionError, match="unavailable for"):
            columns("SELECT * FROM dbo.PerfUsers", schema={"dbo.perfusers": set()})

    def test_an_ambiguous_column_is_refused(self):
        with pytest.raises(ColumnExtractionError):
            columns("SELECT Id FROM dbo.PerfUsers u JOIN dbo.PerfEvents e ON e.Id = u.Id")

    def test_a_column_that_does_not_exist_is_refused(self):
        with pytest.raises(ColumnExtractionError):
            columns("SELECT Nope FROM dbo.PerfUsers")

    def test_an_unanalyzable_source_is_refused_by_the_table_pass(self):
        # Inherited from `extract_referenced_tables`, which runs first: a table-valued
        # function produces no table node and so no trustworthy column set either.
        with pytest.raises(ColumnExtractionError.__mro__[1]):
            columns("SELECT * FROM dbo.PerfEvents e CROSS APPLY dbo.fnSecret(e.Id)")

    def test_unparseable_query_is_refused(self):
        with pytest.raises(ColumnExtractionError.__mro__[1]):
            columns("SELECT FROM WHERE")


class TestCommonTableExpressions:
    def test_columns_read_inside_a_cte_body_are_counted(self):
        # The outer `SELECT *` reads the CTE, but the personal column is read by the CTE body
        # against the real table — which is the read that must be authorized.
        assert columns("WITH x AS (SELECT DateOfBirth FROM dbo.PerfUsers) SELECT * FROM x") == {
            "dbo.perfusers.dateofbirth"
        }

    def test_a_cte_alias_never_becomes_a_resource(self):
        # `x.dateofbirth` would be a resource no rule could be written against, and would
        # deny under an allow-list default for a read that was already counted above.
        assert all(
            not column.startswith("x.")
            for column in columns("WITH x AS (SELECT DateOfBirth FROM dbo.PerfUsers) SELECT * FROM x")
        )


class TestAggregatesAndSubqueries:
    def test_count_star_reads_no_named_column(self):
        # Its star is an aggregate argument, not a projection: it reads rows, not fields, and
        # whether those rows may be read at all is the table-level decision.
        assert columns("SELECT COUNT(*) FROM dbo.PerfEvents") == set()

    def test_scalar_subquery_columns_are_counted(self):
        assert columns("SELECT (SELECT MAX(PPH) FROM dbo.PerfEvents) AS m FROM dbo.PerfUsers") == {"dbo.perfevents.pph"}

    def test_union_arms_are_both_counted(self):
        assert columns("SELECT FullName FROM dbo.PerfUsers UNION ALL SELECT District FROM dbo.PerfEvents") == {
            "dbo.perfusers.fullname",
            "dbo.perfevents.district",
        }


class TestTheRequirement:
    """The shape from the D775 requirement, end to end."""

    def test_the_legitimate_join_reads_no_personal_column(self):
        assert columns(
            "SELECT u.FullName, e.PPH, e.District FROM dbo.PerfUsers u "
            "JOIN dbo.PerfEvents e ON e.UserId = u.Id WHERE e.District = 'D775'"
        ) == {
            "dbo.perfusers.fullname",
            "dbo.perfusers.id",
            "dbo.perfevents.pph",
            "dbo.perfevents.district",
            "dbo.perfevents.userid",
        }

    def test_the_same_join_reaching_for_personal_data_surfaces_it(self):
        assert "dbo.perfusers.nationalinsurancenumber" in columns(
            "SELECT u.NationalInsuranceNumber, e.PPH FROM dbo.PerfUsers u JOIN dbo.PerfEvents e ON e.UserId = u.Id"
        )
