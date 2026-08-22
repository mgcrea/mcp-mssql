"""Enumerate every column a T-SQL query reads.

The table allow-list in `table_extraction.py` cannot express the case this exists for: a
table that must stay *joinable* while some of its columns stay unreachable. The PerfTrack
user table is the live example — it carries national insurance number, date of birth, home
address and personal phone, and it sits on the same join as the performance data a district
manager is entitled to read. Denying the table breaks the legitimate query; allowing it
exposes the personal fields. Only a column-level read set separates the two.

**Same contract as the table extractor, for the same reason.** This feeds an allow-list, so
a false negative is a breach: a column we fail to enumerate is a column authorized against a
smaller read set than the query actually reads. Every uncertainty raises.

**The trap worth knowing about.** `qualify()` does not fail on a table it has no schema for —
`SELECT * FROM dbo.Unknown` returns *zero* columns rather than raising, which on an allow-list
reads as "touches nothing" and is allowed. So the schema map is verified to cover every
referenced table *before* its output is trusted; that check, not qualify's own errors, is what
makes this safe.
"""

from __future__ import annotations

from collections.abc import Mapping, Set

import sqlglot
from sqlglot import exp
from sqlglot.errors import SqlglotError
from sqlglot.optimizer.qualify import qualify

from .table_extraction import (
    DEFAULT_SCHEMA,
    DIALECT,
    TableExtractionError,
    extract_referenced_tables,
    resolve_table_reference,
)


class ColumnExtractionError(TableExtractionError):
    """The column read set could not be established with certainty.

    Subclasses `TableExtractionError` so every existing `except TableExtractionError` keeps
    failing closed on it — there is one fail-closed path through the tool, not two.
    """


def extract_referenced_columns(
    query: str,
    *,
    schema_map: Mapping[str, Set[str]],
    database: str | None = None,
) -> set[str]:
    """Every column the query reads, as lowercase `schema.table.column`.

    `schema_map` maps lowercase `schema.table` to that table's column names, as
    `INFORMATION_SCHEMA` reports them. It must cover every table the query references, or
    this raises — see the module docstring.

    Raises `ColumnExtractionError` whenever the answer is not certain.
    """
    referenced = extract_referenced_tables(query, database=database)

    # The load-bearing check. Without it an unknown table contributes no columns and the
    # query is authorized against an under-counted read set.
    #
    # An *empty* entry counts as missing, not as a table with no columns: every real table has
    # at least one, so an empty set means the catalogue read came back with nothing — a table
    # that does not exist, or one the tool's own credential cannot see. sqlglot happens to
    # raise on an empty column map today, but relying on that would leave this depending on an
    # internal error message for a fail-closed property.
    missing = sorted(table for table in referenced if not schema_map.get(table))
    if missing:
        raise ColumnExtractionError(
            "Column-level authorization needs the schema of every table read, and it is "
            f"unavailable for: {', '.join(missing)}"
        )

    try:
        statement = qualify(
            sqlglot.parse_one(query, dialect=DIALECT),
            schema=_nested_schema(schema_map),
            dialect=DIALECT,
        )
    except RecursionError as exc:
        raise ColumnExtractionError("Query is too deeply nested to analyze") from exc
    except SqlglotError as exc:
        # Includes the ambiguous-column and unknown-column cases, which qualify *does* raise
        # on. Both mean the same thing here: we cannot say which column was read.
        raise ColumnExtractionError(f"Could not resolve the columns this query reads: {exc}") from exc

    _assert_no_unexpanded_star(statement)

    cte_names = {cte.alias_or_name.lower() for cte in statement.find_all(exp.CTE)}
    sources = _source_map(statement, cte_names=cte_names, database=database)

    columns: set[str] = set()
    for column in statement.find_all(exp.Column):
        table = _table_for(column, sources=sources, cte_names=cte_names)
        if table is None:
            continue
        columns.add(f"{table}.{column.name.lower()}")
    return columns


def _nested_schema(schema_map: Mapping[str, Set[str]]) -> dict[str, dict[str, dict[str, str]]]:
    """`{"dbo.orders": {"id"}}` to the nested shape sqlglot's optimizer expects.

    Types are irrelevant to us — only the column *names* decide anything — so every column is
    declared as the same placeholder type.
    """
    nested: dict[str, dict[str, dict[str, str]]] = {}
    for qualified, column_names in schema_map.items():
        schema, _, table = qualified.rpartition(".")
        nested.setdefault(schema or DEFAULT_SCHEMA, {})[table] = {name.lower(): "UNKNOWN" for name in column_names}
    return nested


def _assert_no_unexpanded_star(statement: exp.Expression) -> None:
    """Refuse a `SELECT *` that qualify left in place.

    An unexpanded projection star means the read set is "whatever that table happens to
    contain", which is precisely what cannot be checked against an allow-list.

    `COUNT(*)` is deliberately *not* refused: its star is an argument to an aggregate and
    names no column, so it reads rows rather than fields. The table-level check already
    governs whether those rows may be read at all.
    """
    for select in statement.find_all(exp.Select):
        for projection in select.expressions:
            if isinstance(projection, exp.Star) or (
                isinstance(projection, exp.Column) and isinstance(projection.this, exp.Star)
            ):
                raise ColumnExtractionError(
                    "Could not expand `SELECT *` into the columns it reads, so the query cannot be authorized"
                )


def _source_map(
    statement: exp.Expression,
    *,
    cte_names: set[str],
    database: str | None,
) -> dict[str, str]:
    """Every table alias in the query, mapped to the real `schema.table` it names.

    Keyed by `alias_or_name` because that is what `qualify` writes into each column's table
    component — an alias when the source has one, the bare table name when it does not.
    """
    sources: dict[str, str] = {}
    for table in statement.find_all(exp.Table):
        resolved = resolve_table_reference(table, cte_names=cte_names, database=database)
        if resolved is None:
            continue
        sources[table.alias_or_name.lower()] = resolved
    return sources


def _table_for(column: exp.Column, *, sources: dict[str, str], cte_names: set[str]) -> str | None:
    """The real table a qualified column belongs to, or None when it reads no base table.

    Returns None for a column qualified by a **CTE alias**. That is not a gap: qualify
    resolves the columns *inside* the CTE body against the real tables, so the underlying
    read is already counted, and emitting `x.dateofbirth` for a CTE named `x` would invent a
    resource no rule could ever be written against. Mirrors `resolve_table_reference`
    returning None for a CTE reference in the table extractor.
    """
    alias = (column.table or "").lower()
    if not alias:
        # qualify() qualifies every column it can resolve, so an unqualified one that
        # survived is one it could not attribute. Guessing which table it came from is
        # exactly the guess an allow-list must not authorize.
        raise ColumnExtractionError(f"Could not determine which table `{column.name}` is read from")

    if alias in sources:
        return sources[alias]
    if alias in cte_names:
        return None

    # An alias naming neither a known source nor a CTE. Should be unreachable after qualify,
    # so treat it as the extractor being wrong about the query rather than as a benign case.
    raise ColumnExtractionError(f"Could not resolve `{alias}.{column.name}` to a table")
