"""Adversarial tests for table enumeration.

**This file is the security artifact of the access-control work and should be reviewed as
one.** Every assertion is an exact set, never a membership check: `assert "dbo.payroll" in
tables` would pass for an extractor that returned every table in the database, and would say
nothing about the one property that matters — that *nothing was missed*.

A false negative here is a breach. A query that reads `dbo.Payroll` but whose extracted set
omits it gets authorized against the tables it did admit to, and the payroll data comes back.
So the bar for every case below is: does the extractor see through this obfuscation?
"""

from __future__ import annotations

import pytest

from mcp_mssql.table_extraction import TableExtractionError, extract_referenced_tables, normalize_table_name


def tables(query: str, **kwargs) -> set[str]:
    return extract_referenced_tables(query, **kwargs)


class TestBasicShapes:
    def test_simple_select(self):
        assert tables("SELECT * FROM dbo.Orders") == {"dbo.orders"}

    def test_unqualified_table_gets_the_default_schema(self):
        assert tables("SELECT * FROM Orders") == {"dbo.orders"}

    def test_case_is_normalized(self):
        # The model writes whatever case it likes; rules are authored in one.
        assert tables("SELECT * FROM DBO.ORDERS") == {"dbo.orders"}

    def test_explicit_non_default_schema(self):
        assert tables("SELECT * FROM hr.Payroll") == {"hr.payroll"}

    def test_join(self):
        assert tables("SELECT * FROM dbo.A a JOIN hr.Payroll p ON a.id = p.id") == {
            "dbo.a",
            "hr.payroll",
        }

    def test_three_way_join(self):
        query = "SELECT * FROM dbo.A JOIN dbo.B ON 1=1 JOIN hr.Payroll ON 1=1"
        assert tables(query) == {"dbo.a", "dbo.b", "hr.payroll"}

    def test_aliases_are_not_tables(self):
        assert tables("SELECT p.x FROM hr.Payroll AS p") == {"hr.payroll"}

    def test_trailing_semicolon(self):
        assert tables("SELECT * FROM dbo.Orders;") == {"dbo.orders"}


class TestQuotingObfuscation:
    """The exact cases the existing regex pipeline destroys before it can see them.

    `_strip_literals_and_comments` replaces bracket- and double-quoted identifiers with
    spaces, so every query in this class has its table names erased by the old machinery.
    """

    def test_bracket_quoted(self):
        assert tables("SELECT * FROM [Payroll].[Salaries]") == {"payroll.salaries"}

    def test_double_quoted(self):
        assert tables('SELECT * FROM "Payroll"."Salaries"') == {"payroll.salaries"}

    def test_mixed_quoting(self):
        assert tables("SELECT * FROM [hr].Payroll") == {"hr.payroll"}

    def test_bracket_with_spaces_in_the_name(self):
        assert tables("SELECT * FROM [My Schema].[My Table]") == {"my schema.my table"}

    def test_bracket_with_a_dot_inside_the_name(self):
        # `[a.b]` is ONE identifier, not schema `a` table `b`. Getting this backwards would
        # authorize the wrong object.
        assert tables("SELECT * FROM dbo.[a.b]") == {"dbo.a.b"}

    def test_escaped_closing_bracket(self):
        assert tables("SELECT * FROM [we]]ird]") == {"dbo.we]ird"}


class TestCommentsAndLiterals:
    def test_table_name_hidden_behind_a_block_comment(self):
        assert tables("SELECT * FROM /* dbo.Orders */ hr.Payroll") == {"hr.payroll"}

    def test_comment_inside_the_from_clause(self):
        assert tables("SELECT * FROM hr./* sneaky */Payroll") == {"hr.payroll"}

    def test_line_comment_does_not_hide_the_real_table(self):
        assert tables("SELECT * FROM hr.Payroll -- FROM dbo.Orders") == {"hr.payroll"}

    def test_a_table_name_in_a_string_literal_is_not_a_table(self):
        # The dual failure: over-reporting would deny a legitimate query.
        assert tables("SELECT * FROM dbo.Logs WHERE msg = 'SELECT * FROM hr.Payroll'") == {"dbo.logs"}


class TestCTEs:
    def test_cte_body_tables_are_reported_and_the_alias_is_not(self):
        # The plan's canonical bypass attempt: launder a denied table through a CTE.
        query = "WITH x AS (SELECT * FROM hr.Payroll) SELECT * FROM x"
        assert tables(query) == {"hr.payroll"}

    def test_chained_ctes(self):
        query = "WITH a AS (SELECT * FROM hr.Payroll), b AS (SELECT * FROM a) SELECT * FROM b"
        assert tables(query) == {"hr.payroll"}

    def test_multiple_ctes_over_different_tables(self):
        query = "WITH a AS (SELECT * FROM dbo.Orders), b AS (SELECT * FROM hr.Payroll) SELECT * FROM a, b"
        assert tables(query) == {"dbo.orders", "hr.payroll"}

    def test_a_cte_named_after_a_real_table_shadows_it(self):
        # `Payroll` here is the CTE, not the table. Reporting `dbo.payroll` would deny a
        # harmless query — the false-positive direction, but still wrong.
        assert tables("WITH Payroll AS (SELECT 1 AS a) SELECT * FROM Payroll") == set()

    def test_a_qualified_name_matching_a_cte_is_still_a_real_table(self):
        # A CTE reference is never schema-qualified, so `dbo.x` is a table even when a CTE
        # `x` exists. Subtracting it would be a false negative — the dangerous direction.
        assert tables("WITH x AS (SELECT 1 AS a) SELECT * FROM dbo.x") == {"dbo.x"}

    def test_cte_that_shadows_and_a_real_table_of_the_same_name_in_one_query(self):
        query = "WITH Payroll AS (SELECT 1 AS a) SELECT * FROM Payroll, hr.Payroll"
        assert tables(query) == {"hr.payroll"}


class TestSubqueriesAndDerivedTables:
    def test_derived_table(self):
        assert tables("SELECT * FROM (SELECT * FROM hr.Payroll) AS d") == {"hr.payroll"}

    def test_nested_derived_tables(self):
        query = "SELECT * FROM (SELECT * FROM (SELECT * FROM hr.Payroll) AS inner_d) AS outer_d"
        assert tables(query) == {"hr.payroll"}

    def test_subquery_in_where(self):
        query = "SELECT * FROM dbo.Orders WHERE id IN (SELECT id FROM hr.Payroll)"
        assert tables(query) == {"dbo.orders", "hr.payroll"}

    def test_correlated_subquery_in_the_select_list(self):
        query = "SELECT o.id, (SELECT TOP 1 salary FROM hr.Payroll p WHERE p.id = o.id) FROM dbo.Orders o"
        assert tables(query) == {"dbo.orders", "hr.payroll"}

    def test_subquery_in_having(self):
        query = "SELECT id FROM dbo.Orders GROUP BY id HAVING COUNT(*) > (SELECT COUNT(*) FROM hr.Payroll)"
        assert tables(query) == {"dbo.orders", "hr.payroll"}

    def test_exists_subquery(self):
        query = "SELECT * FROM dbo.Orders o WHERE EXISTS (SELECT 1 FROM hr.Payroll p WHERE p.id = o.id)"
        assert tables(query) == {"dbo.orders", "hr.payroll"}


class TestSetOperationsAndApply:
    def test_union_all_arms_are_both_reported(self):
        query = "SELECT id FROM dbo.Orders UNION ALL SELECT id FROM hr.Payroll"
        assert tables(query) == {"dbo.orders", "hr.payroll"}

    def test_union_of_three(self):
        query = "SELECT 1 FROM dbo.A UNION SELECT 1 FROM dbo.B UNION SELECT 1 FROM hr.Payroll"
        assert tables(query) == {"dbo.a", "dbo.b", "hr.payroll"}

    def test_intersect(self):
        assert tables("SELECT id FROM dbo.A INTERSECT SELECT id FROM hr.Payroll") == {
            "dbo.a",
            "hr.payroll",
        }

    def test_except(self):
        assert tables("SELECT id FROM dbo.A EXCEPT SELECT id FROM hr.Payroll") == {
            "dbo.a",
            "hr.payroll",
        }

    def test_cross_apply(self):
        query = "SELECT * FROM dbo.A a CROSS APPLY (SELECT * FROM hr.Payroll p WHERE p.id = a.id) x"
        assert tables(query) == {"dbo.a", "hr.payroll"}

    def test_outer_apply(self):
        query = "SELECT * FROM dbo.A a OUTER APPLY (SELECT TOP 1 * FROM hr.Payroll p WHERE p.id = a.id) x"
        assert tables(query) == {"dbo.a", "hr.payroll"}

    def test_pivot(self):
        query = "SELECT * FROM hr.Payroll PIVOT (SUM(amount) FOR yr IN ([2020], [2021])) AS p"
        assert tables(query) == {"hr.payroll"}

    def test_comma_join(self):
        assert tables("SELECT * FROM dbo.A, hr.Payroll") == {"dbo.a", "hr.payroll"}


class TestNamesWithoutTables:
    def test_select_with_no_from_reads_nothing(self):
        assert tables("SELECT 1") == set()

    def test_select_from_a_constant_derived_table(self):
        # Reads no table, so there is nothing to authorize. Safe by construction: every
        # from-source is either a named table (enumerated), a subquery (recursed), a
        # constant, or a function — and functions are refused below.
        assert tables("SELECT * FROM (VALUES (1), (2)) AS v(x)") == set()

    def test_select_from_a_constant_subquery(self):
        assert tables("SELECT * FROM (SELECT 1 AS a) AS s") == set()


class TestFailClosed:
    """Cases where the read set cannot be established. Every one must raise."""

    def test_unparseable_query(self):
        with pytest.raises(TableExtractionError):
            tables("SELECT * FROM")

    def test_four_part_name_is_refused(self):
        # sqlglot keeps only catalog/db/name, so `srv.mydb.hr.Payroll` comes back as
        # `mydb.payroll` — the SCHEMA is silently dropped and a rule denying `hr.payroll`
        # would never match. This is the single most dangerous silent-corruption case in
        # the parser, and the reason four-part names are refused outright.
        with pytest.raises(TableExtractionError, match="Four-part"):
            tables("SELECT * FROM srv.mydb.hr.Payroll")

    def test_four_part_name_in_brackets_is_refused_too(self):
        with pytest.raises(TableExtractionError, match="Four-part"):
            tables("SELECT * FROM [srv].[mydb].[hr].[Payroll]")

    def test_table_valued_function_is_refused(self):
        with pytest.raises(TableExtractionError, match="function or external source"):
            tables("SELECT * FROM dbo.fnGetPayroll(1)")

    def test_openrowset_is_refused(self):
        # Also blocked by validate_readonly_query. Two independent gates on the construct
        # that can reach an entirely different server.
        with pytest.raises(TableExtractionError):
            tables("SELECT * FROM OPENROWSET('SQLNCLI', 'x', 'SELECT * FROM Payroll')")

    def test_openjson_is_refused(self):
        with pytest.raises(TableExtractionError, match="function or external source"):
            tables("SELECT * FROM OPENJSON('[]')")

    def test_string_split_is_refused(self):
        with pytest.raises(TableExtractionError, match="function or external source"):
            tables("SELECT * FROM STRING_SPLIT('a,b', ',')")

    def test_a_function_source_alongside_a_real_table_still_refuses(self):
        # Regression, and the nastiest case in this file. A schema-qualified table-valued
        # function in CROSS APPLY parses to a Lateral over a Dot — it produces **no table
        # node at all**, so an extractor that only walked `exp.Table` would happily report
        # `{dbo.orders}`, authorize against that, and let `fnSecret` read anything it liked.
        # Caught by the source-shape allow-list, not by knowing the function's name.
        with pytest.raises(TableExtractionError, match="function or external source"):
            tables("SELECT * FROM dbo.Orders o CROSS APPLY dbo.fnSecret(o.id) f")

    def test_an_unqualified_function_in_cross_apply_is_refused(self):
        with pytest.raises(TableExtractionError, match="function or external source"):
            tables("SELECT * FROM dbo.Orders o CROSS APPLY fnSecret(o.id) f")

    def test_outer_apply_over_a_function_is_refused(self):
        with pytest.raises(TableExtractionError, match="function or external source"):
            tables("SELECT * FROM dbo.Orders o OUTER APPLY dbo.fnSecret(o.id) f")

    def test_a_subquery_in_cross_apply_is_still_fine(self):
        # The allow-list must not become a blanket ban on APPLY — that would break
        # legitimate queries and push users toward asking for the guard to be turned off.
        query = "SELECT * FROM dbo.Orders o CROSS APPLY (SELECT TOP 1 * FROM hr.Payroll) x"
        assert tables(query) == {"dbo.orders", "hr.payroll"}

    def test_multi_statement_is_refused(self):
        with pytest.raises(TableExtractionError, match="Multi-statement"):
            tables("SELECT * FROM dbo.Orders; SELECT * FROM hr.Payroll")

    def test_empty_query_is_refused(self):
        with pytest.raises(TableExtractionError):
            tables("")

    def test_whitespace_only_query_is_refused(self):
        with pytest.raises(TableExtractionError):
            tables("   \n\t ")


class TestCrossDatabase:
    def test_three_part_name_in_the_connected_database_is_accepted(self):
        assert tables("SELECT * FROM mydb.hr.Payroll", database="MyDb") == {"hr.payroll"}

    def test_three_part_name_naming_another_database_is_refused(self):
        # Otherwise a grant on `dbo.Orders` in this database would also unlock
        # `OtherDb.dbo.Orders`, which the rule never meant to cover.
        with pytest.raises(TableExtractionError, match="Cross-database"):
            tables("SELECT * FROM OtherDb.dbo.Orders", database="MyDb")

    def test_catalog_is_ignored_when_no_database_is_configured(self):
        # Without knowing the connection's own database there is nothing to compare
        # against; the schema-qualified name is still enumerated.
        assert tables("SELECT * FROM anydb.hr.Payroll") == {"hr.payroll"}


class TestInjectionStyleAttempts:
    """Cases shaped like what a prompt-injected model would actually emit.

    The point of enforcing here rather than at the model: none of these depend on the
    model's intent. The query is judged as written, after any instruction has had its say.
    """

    def test_payroll_via_a_cte_wrapped_in_a_derived_table(self):
        query = """
            WITH sneaky AS (SELECT * FROM [hr].[Payroll])
            SELECT * FROM (SELECT * FROM sneaky) AS d
        """
        assert tables(query) == {"hr.payroll"}

    def test_payroll_unioned_onto_an_allowed_query(self):
        query = "SELECT id, name FROM dbo.Orders UNION ALL SELECT id, ssn FROM [hr].[Payroll]"
        assert tables(query) == {"dbo.orders", "hr.payroll"}

    def test_payroll_reached_through_a_correlated_subquery_in_a_case_expression(self):
        query = """
            SELECT CASE WHEN 1 = 1
                   THEN (SELECT TOP 1 salary FROM hr.Payroll)
                   ELSE 0 END
            FROM dbo.Orders
        """
        assert tables(query) == {"dbo.orders", "hr.payroll"}

    def test_payroll_behind_comments_and_bracket_quoting_at_once(self):
        query = "SELECT * /* nothing to see */ FROM [hr] . /* here */ [Payroll]"
        assert tables(query) == {"hr.payroll"}

    def test_join_cannot_launder_access(self):
        # The set is what the guard authorizes against, and every member must be allowed.
        # Reporting both is what makes a join fail as a whole rather than leak the denied
        # half through the allowed one.
        query = "SELECT o.*, p.salary FROM dbo.Orders o JOIN hr.Payroll p ON o.emp = p.emp"
        assert tables(query) == {"dbo.orders", "hr.payroll"}


class TestNormalizeTableName:
    def test_matches_what_extraction_produces(self):
        # The discovery tools get names from INFORMATION_SCHEMA rather than a parsed query.
        # If the two spellings diverged, a table would be listed under one name and
        # authorized under another.
        assert normalize_table_name("dbo", "Orders") == "dbo.orders"
        assert normalize_table_name("dbo", "Orders") in tables("SELECT * FROM dbo.Orders")

    def test_defaults_a_missing_schema(self):
        assert normalize_table_name("", "Orders") == "dbo.orders"
