"""Enumerate every table a T-SQL query reads.

**This is the security-critical half of the guard, and it is the exact dual of
`sql_validation.py`.** That module is a deny-list over tokens — "does `EXEC` appear?" — where
over-approximating is safe and a false positive is an annoyed user. A table allow-list needs
the opposite: a *complete over-approximation of the read set*, where a false negative is a
breach. Missing one table means a query is authorized against a smaller set than it actually
reads.

**Why a regex cannot do this.** `_strip_literals_and_comments` in `sql_validation.py`
replaces bracket- and double-quoted identifiers with spaces, so
`SELECT * FROM [Payroll].[Salaries]` has its table names *deleted* before any scan could see
them. Beyond that, CTEs, correlated subqueries, `CROSS APPLY`, `PIVOT`, derived tables,
four-part names and `UNION` arms each defeat a `FROM\\s+(\\w+)` pattern independently. Real
parsing is not gold-plating here; it is the minimum that can be correct.

Both gates run, in order: `validate_readonly_query` first (sqlglot parses `INSERT` perfectly
happily — enumeration is not policy), then this.
"""

from __future__ import annotations

import sqlglot
from sqlglot import exp
from sqlglot.errors import SqlglotError

DEFAULT_SCHEMA = "dbo"
DIALECT = "tsql"

#: Node types a `FROM` / `JOIN` / `APPLY` may name and still be fully enumerable.
#:
#: `Table` is walked below; `Subquery`, `Select` and `Union` are recursed into, so their
#: tables surface too; `Values` and `Unnest` are constants that read nothing; `Lateral` is a
#: wrapper whose own source is checked on its own iteration.
#:
#: **Anything else is refused.** A schema-qualified table-valued function — `CROSS APPLY
#: dbo.fnSecret(o.id)` — parses to a `Dot`, not a `Table`, so it produces *no table node at
#: all* and would otherwise sail through the walk while reading whatever it likes. An
#: allow-list of source shapes catches that; a deny-list of known-bad functions would not.
_ANALYZABLE_SOURCES = (
    exp.Table,
    exp.Subquery,
    exp.Select,
    exp.Union,
    exp.Values,
    exp.Unnest,
    exp.Lateral,
)


class TableExtractionError(Exception):
    """The read set could not be established with certainty.

    Always fatal to the call. Every raise site below is a case where the extractor cannot
    prove what a query touches — and an unprovable read set must never be handed to an
    allow-list check, because the check would then be authorizing a guess.
    """


def extract_referenced_tables(query: str, *, database: str | None = None) -> set[str]:
    """Every table the query reads, as lowercase `schema.table`.

    `database` is the connection's own database name. When given, a three-part name
    naming a *different* database is refused rather than silently reduced to
    `schema.table` — otherwise a grant on `dbo.Orders` here would also unlock
    `OtherDb.dbo.Orders`, which policy never meant to cover.

    Raises `TableExtractionError` whenever the answer is not certain.
    """
    try:
        statements = sqlglot.parse(query, dialect=DIALECT)
    except SqlglotError as exc:
        raise TableExtractionError(f"Could not parse the query: {exc}") from exc
    except RecursionError as exc:
        # A deeply nested query can blow the parser's stack. Refusing is the only safe
        # answer: a half-walked tree is a partial read set.
        raise TableExtractionError("Query is too deeply nested to analyze") from exc

    real = [statement for statement in statements if statement is not None]
    if not real:
        raise TableExtractionError("Query contained no statement to analyze")
    if len(real) > 1:
        # `validate_readonly_query` rejects these first; this is defence in depth for any
        # future caller that forgets to run it.
        raise TableExtractionError("Multi-statement queries cannot be analyzed")

    statement = real[0]

    # sqlglot emits `Command` for syntax it recognises but does not model. Its contents are
    # opaque, so any table inside it would be invisible to the walk below.
    for command in statement.find_all(exp.Command):
        raise TableExtractionError(f"Query contains a construct that cannot be analyzed: {command.this}")

    _assert_analyzable_sources(statement)

    cte_names = {cte.alias_or_name.lower() for cte in statement.find_all(exp.CTE)}

    tables: set[str] = set()
    for table in statement.find_all(exp.Table):
        resolved = _resolve(table, cte_names=cte_names, database=database)
        if resolved is not None:
            tables.add(resolved)
    return tables


def _assert_analyzable_sources(statement: exp.Expression) -> None:
    """Refuse any `FROM` / `JOIN` / `APPLY` source that is not a table, subquery or constant.

    Walking `exp.Table` alone is not enough, because some sources never become a table node.
    `CROSS APPLY dbo.fnSecret(o.id)` parses to a `Lateral` over a `Dot`, so the query would
    otherwise be authorized against only the tables it *did* declare while the function read
    whatever it liked.
    """
    for node in statement.find_all(exp.From, exp.Join, exp.Lateral):
        source = node.this
        if source is None or not isinstance(source, _ANALYZABLE_SOURCES):
            raise TableExtractionError(
                "Query reads from a function or external source, which cannot be authorized: "
                f"{source.sql(dialect=DIALECT) if source is not None else node.sql(dialect=DIALECT)}"
            )


def _resolve(table: exp.Table, *, cte_names: set[str], database: str | None) -> str | None:
    """One table node to `schema.table`, or None when it is not a real table."""
    parts = list(table.parts)
    name = table.name

    if not name:
        # A table-valued function, `OPENROWSET`, `OPENJSON`, `STRING_SPLIT` — sqlglot models
        # these as a Table with an empty name and the call in a sibling node. Whatever they
        # read is not enumerable here, and `OPENROWSET`/`OPENQUERY` can reach an entirely
        # different server.
        raise TableExtractionError("Query reads from a function or external source, which cannot be authorized")

    if len(parts) > 3:
        # `server.database.schema.table`. sqlglot keeps only catalog/db/name, so the schema
        # component is silently dropped — `srv.mydb.hr.Payroll` would come back as
        # `mydb.payroll` and sail past a rule denying `hr.payroll`. Refuse; linked-server
        # access is not something policy can express today.
        raise TableExtractionError(f"Four-part table names cannot be authorized: {table.sql(dialect=DIALECT)}")

    schema = (table.db or "").lower()
    catalog = (table.catalog or "").lower()

    if not schema and not catalog and name.lower() in cte_names:
        # A CTE reference, not a table. Only ever unqualified — `WITH x AS (…) SELECT * FROM
        # dbo.x` names a real `dbo.x`, so requiring both parts empty is what keeps a CTE
        # alias from shadowing a real table of the same name.
        return None

    if catalog and database and catalog != database.lower():
        raise TableExtractionError(f"Cross-database access cannot be authorized: {table.sql(dialect=DIALECT)}")

    return f"{schema or DEFAULT_SCHEMA}.{name.lower()}"


def normalize_table_name(schema: str, table: str) -> str:
    """The same normalization, for callers that already have the parts split.

    Used by the discovery tools, which get names from `INFORMATION_SCHEMA` rather than from
    a parsed query. Both paths must produce byte-identical strings or a table would be
    listed under one spelling and authorized under another.
    """
    return f"{(schema or DEFAULT_SCHEMA).lower()}.{table.lower()}"
