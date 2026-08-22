"""Apply a policy row predicate to a query, by rewriting it.

The PDP decides *which rows* a caller may see and hands back a predicate — "district IN
('D775')". Something has to make the query obey it. Two options, and only one of them works:

**Verify** — refuse unless the query already restricts the column. Brittle (the model would
have to guess the caller's districts), and it turns a scoping rule into a puzzle for the LLM.

**Rewrite** — wrap each governed table in a subquery carrying the predicate. The model writes
whatever it likes; the predicate is applied underneath. That is what this module does:

    FROM dbo.PerfEvents e   ->   FROM (SELECT * FROM dbo.PerfEvents WHERE district IN ('D775')) AS e

Wrapping the *table node* rather than appending to the outer `WHERE` is what makes joins,
subqueries, `UNION` arms and CTE bodies work without special cases: every reference to the
table gets its own wrapper, and an outer `OR` cannot widen it back out.

**Fails closed on anything it cannot do exactly.** A predicate that could not be applied is
not a query that returns extra rows — it is a query that does not run.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence, Set
from dataclasses import dataclass

import sqlglot
from sqlglot import exp
from sqlglot.errors import SqlglotError

from .table_extraction import (
    DIALECT,
    TableExtractionError,
    extract_referenced_tables,
    resolve_table_reference,
)


class RowFilterError(TableExtractionError):
    """A predicate could not be applied exactly, so the query must not run.

    Subclasses `TableExtractionError` so the tool's existing fail-closed handler catches it —
    one path out, not two.
    """


@dataclass(frozen=True)
class RowPredicate:
    """One predicate to apply to one table, as the guard delivers it."""

    table: str
    column: str
    operator: str
    values: tuple[str, ...]


def apply_row_filters(
    query: str,
    predicates: Sequence[RowPredicate],
    *,
    schema_map: Mapping[str, Set[str]],
    database: str | None = None,
) -> str:
    """The query, rewritten so every predicate holds. Returns it unchanged when there are none.

    Raises `RowFilterError` whenever a predicate cannot be applied exactly.
    """
    if not predicates:
        return query

    before = extract_referenced_tables(query, database=database)

    try:
        tree = sqlglot.parse_one(query, dialect=DIALECT)
    except SqlglotError as exc:  # pragma: no cover - the extractor above already parsed it
        raise RowFilterError(f"Could not parse the query: {exc}") from exc

    by_table: dict[str, list[RowPredicate]] = {}
    for predicate in predicates:
        _assert_applicable(predicate, schema_map)
        by_table.setdefault(predicate.table, []).append(predicate)

    cte_names = {cte.alias_or_name.lower() for cte in tree.find_all(exp.CTE)}

    # Collected before mutating: replacing a node while walking the same iterator would have
    # the walk descend into the subquery just created and wrap its table again, forever.
    targets: list[tuple[exp.Table, list[RowPredicate]]] = []
    for table in tree.find_all(exp.Table):
        resolved = resolve_table_reference(table, cte_names=cte_names, database=database)
        if resolved is None:
            continue
        applicable = by_table.get(resolved)
        if applicable:
            targets.append((table, applicable))

    if not targets:
        # Every predicate named a table this query does not read. Applying nothing would run
        # the query unscoped, so refuse: the mismatch means the read set and the decision
        # disagree, and one of them is wrong.
        raise RowFilterError("The policy predicate names a table this query does not read")

    for table, applicable in targets:
        table.replace(_wrap(table, applicable))

    rewritten = tree.sql(dialect=DIALECT)

    # The rewrite must not have introduced a source. Cheap, and the one check that would catch
    # a wrapper built from the wrong node — which would otherwise read as a successful scope.
    after = extract_referenced_tables(rewritten, database=database)
    if after != before:
        raise RowFilterError("Applying the policy predicate changed which tables the query reads")

    return rewritten


def _assert_applicable(predicate: RowPredicate, schema_map: Mapping[str, Set[str]]) -> None:
    """Refuse a predicate the table cannot satisfy.

    A filter column that does not exist would make the rewritten query fail at the database
    with a syntax-ish error the model would then try to work around. Worse, a *typo* in a
    column name is a predicate that silently matches nothing on some engines rather than
    erroring — the fail-open direction.
    """
    columns = {column.lower() for column in schema_map.get(predicate.table, set())}
    if not columns:
        raise RowFilterError(f"Cannot apply a row filter to `{predicate.table}`: its columns are unavailable")
    if predicate.column.lower() not in columns:
        raise RowFilterError(
            f"The policy filters `{predicate.table}` on `{predicate.column}`, which is not a column of that table"
        )
    if not predicate.values:
        # The PDP denies rather than sending an empty predicate, so reaching here means the
        # two sides disagree. Refuse instead of rendering `IN ()`, whose meaning varies.
        raise RowFilterError(f"The policy filter on `{predicate.column}` carries no values")
    if predicate.operator == "eq" and len(predicate.values) != 1:
        raise RowFilterError(f"The policy filter on `{predicate.column}` uses `eq` with {len(predicate.values)} values")
    if predicate.operator not in _OPERATORS:
        raise RowFilterError(f"Unsupported policy filter operator `{predicate.operator}`")


def _wrap(table: exp.Table, predicates: Sequence[RowPredicate]) -> exp.Subquery:
    """`dbo.T AS e` -> `(SELECT * FROM dbo.T WHERE <predicates>) AS e`.

    The alias is carried onto the wrapper and dropped from the inner reference, so every
    qualified reference in the outer query keeps resolving. An unaliased table is wrapped
    under its own bare name, which is what an unqualified reference already used.
    """
    alias = table.alias_or_name
    if not alias:
        raise RowFilterError("Cannot apply a row filter to a table reference with no name to alias")

    inner_source = table.copy()
    inner_source.set("alias", None)

    inner = exp.select(exp.Star()).from_(inner_source)
    for predicate in predicates:
        inner = inner.where(_condition(predicate))

    return exp.Subquery(this=inner, alias=exp.TableAlias(this=exp.to_identifier(alias)))


def _condition(predicate: RowPredicate) -> exp.Expression:
    """One predicate as a T-SQL condition, with values as literals sqlglot escapes itself."""
    column = exp.column(predicate.column)
    literals = [exp.Literal.string(value) for value in predicate.values]
    return _OPERATORS[predicate.operator](column, literals)


#: Deliberately a closed table rather than an if-chain: an operator the guard invents but this
#: does not implement must raise in `_assert_applicable`, never fall through to "no predicate".
_OPERATORS = {
    "in_": lambda column, literals: column.isin(*literals),
    "not_in": lambda column, literals: exp.Not(this=column.isin(*literals)),
    "eq": lambda column, literals: exp.EQ(this=column, expression=literals[0]),
}
