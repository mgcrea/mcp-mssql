"""MSSQL database tools for MCP."""

import asyncio
import os
import time
from collections.abc import Sequence

import pymssql
from mcp.server.mcpserver import MCPServer
from mcp_policy_guard import Guard, PolicyDenied, Resource, audit_call, guarded

from ..column_extraction import extract_referenced_columns
from ..config import get_config
from ..row_filters import RowFilterError, RowPredicate, apply_row_filters
from ..sql_validation import ReadOnlyViolationError, validate_readonly_query
from ..table_extraction import (
    TableExtractionError,
    extract_referenced_tables,
    normalize_table_name,
)

# Timeout configuration (seconds)
# Login timeout must be generous enough to survive Knative cold-start latency
# when the DB server needs time to accept new connections.
LOGIN_TIMEOUT = int(os.environ.get("MSSQL_LOGIN_TIMEOUT", "30"))
QUERY_TIMEOUT = int(os.environ.get("MSSQL_QUERY_TIMEOUT", "30"))

# Hard ceiling on rows returned by a single query.
#
# The tool used to call `fetchall()` with no bound, so `SELECT * FROM tbDat_CRM_Leads` would
# materialise ~372K rows into the pod's memory and then into the model's context. Neither
# survives that. This is a resource bound, not an access control — an allowed table is still
# fully readable, one page at a time.
MAX_ROWS = int(os.environ.get("MSSQL_MAX_ROWS", "1000"))

# DB-Lib and Net-Lib client failures are numbered from 20000 up; anything below that number
# came from SQL Server itself and is about the statement the model wrote.
DBLIB_ERROR_FLOOR = 20000
# A SQL Server message can quote the offending value, so it is bounded before it reaches a prompt.
MAX_ERROR_CHARS = 500

#: Selector kind the platform's policy store uses for SQL tables.
SQL_TABLE = "sql_table"

#: Selector kind for a single column, as `schema.table.column`.
#:
#: Submitted alongside the tables, never instead of them: the two are independent rules, and
#: `evaluate()` requires *every* resource to be allowed, so a denied column denies the call
#: while leaving its table joinable. That is the whole point of the kind.
SQL_COLUMN = "sql_column"

#: How long a table's column list is trusted before it is read again.
#:
#: Columns change with a schema migration, not with traffic, so this is long. It is bounded at
#: all because a column *added* to a table must eventually be seen — until it is, a `SELECT *`
#: expands to a stale list and the new column is authorized against nothing. Ten minutes is
#: short enough that a migration is picked up within one deploy cycle.
SCHEMA_CACHE_TTL_SECONDS = int(os.environ.get("MSSQL_SCHEMA_CACHE_TTL", "600"))

guard = Guard()

#: `schema.table` -> (expires_at, column names). Process-local; see `_load_schema_map`.
_schema_cache: dict[str, tuple[float, frozenset[str]]] = {}


def schema_lookup_sql(tables: Sequence[str]) -> tuple[str, list[str]]:
    """The INFORMATION_SCHEMA lookup for a set of `schema.table` names, as (sql, params).

    Module-level, and returning the statement as text, so it can be asserted without a
    database. That matters here more than it looks: every other test in this suite stubs the
    cursor, so the statement itself was never executed against a real SQL Server — which is
    exactly how a **Postgres-shaped row-value constructor** shipped green:

        WHERE (LOWER(TABLE_SCHEMA), LOWER(TABLE_NAME)) IN ((%s, %s), (%s, %s))

    T-SQL has no row-value constructor in an IN list. SQL Server answers with error 4145,
    "An expression of non-boolean type specified in a context where a condition is expected,
    near ','". Because this lookup runs for every query that names a table, it broke *every*
    real query, while `SELECT 1` — which reads no table and skips the lookup — kept working.
    That asymmetry made it read as a database or permissions fault rather than a syntax one.

    OR'd pairs are the portable form. `test_schema_lookup_sql.py` pins the shape.
    """
    pairs = [table.split(".", 1) for table in tables]
    predicate = " OR ".join(["(LOWER(TABLE_SCHEMA) = %s AND LOWER(TABLE_NAME) = %s)"] * len(pairs))
    sql = f"SELECT TABLE_SCHEMA, TABLE_NAME, COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE {predicate}"
    return sql, [part for pair in pairs for part in pair]


def register_mssql_tools(mcp: MCPServer) -> None:
    """Register MSSQL tools with the MCP server."""

    def _get_connection():
        """Create MSSQL connection with timeout settings."""
        config = get_config()
        return pymssql.connect(
            server=config.host,
            port=config.port,
            user=config.user,
            password=config.password,
            database=config.database,
            login_timeout=LOGIN_TIMEOUT,
            timeout=QUERY_TIMEOUT,
            read_only=config.readonly,
        )

    def _load_schema_map(tables: set[str]) -> dict[str, frozenset[str]]:
        """The column names of each given table, from `INFORMATION_SCHEMA`.

        Cached per process because this sits on the hot path of every governed query, and a
        table's column list changes with a migration rather than with traffic.

        **This is the one place a connection may open before the policy decision**, and it is
        deliberately narrow: it reads the catalogue, never a user row, and only for tables the
        caller's cached snapshot already says they may read — see `_sync_mssql_query`. The
        property that matters is unchanged: the caller's own query still never executes until
        `guard.require` has passed.
        """
        now = time.monotonic()
        fresh = {
            table: entry[1] for table in tables if (entry := _schema_cache.get(table)) is not None and entry[0] > now
        }
        stale = sorted(tables - fresh.keys())
        if not stale:
            return fresh

        sql, params = schema_lookup_sql(stale)
        with _get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(sql, params)
                rows = cur.fetchall()

        loaded: dict[str, set[str]] = {}
        for schema, table, column in rows:
            loaded.setdefault(normalize_table_name(schema, table), set()).add(column.lower())

        expires = now + SCHEMA_CACHE_TTL_SECONDS
        for table in stale:
            # A table with no rows is cached as empty rather than skipped, so a name that does
            # not exist does not re-query on every call. `extract_referenced_columns` refuses
            # an empty entry anyway, because it cannot expand a star against it.
            columns = frozenset(loaded.get(table, set()))
            if columns:
                _schema_cache[table] = (expires, columns)
            fresh[table] = columns
        return fresh

    def _column_resources(query: str, tables: set[str]) -> list[Resource]:
        """The column read set, as policy resources — or nothing when policy cannot use it.

        Skipped entirely when no PDP is configured, so a tool running without policy behaves
        exactly as it did before columns existed: no catalogue read, and no chance of a
        column-extraction failure denying a query nothing was governing.

        Also skipped when the caller's cached snapshot already denies one of the tables. The
        call is about to be denied on that table regardless, and this is what keeps the
        catalogue read from happening for a caller who may not read the table it describes.
        """
        if not guard.config.policy_enabled:
            return []

        snapshot = guard.snapshot("mssql_query")
        if not all(snapshot.allows(SQL_TABLE, table) for table in tables):
            return []

        schema_map = _load_schema_map(tables)
        columns = extract_referenced_columns(query, schema_map=schema_map, database=get_config().database)
        return [Resource(SQL_COLUMN, column) for column in sorted(columns)]

    def _apply_policy_filters(query: str, decision, referenced: set[str]) -> str:
        """Rewrite the query so every row predicate the decision carries holds.

        Only `sql_table` predicates reach here. A column-kind filter would be a predicate on a
        thing that yields no rows of its own, and silently ignoring one would be the fail-open
        this module exists to avoid — so it is refused rather than skipped.
        """
        predicates = []
        for row_filter in getattr(decision, "filters", ()):
            if row_filter.resource.kind != SQL_TABLE:
                raise RowFilterError(
                    f"The policy carries a row filter on a {row_filter.resource.kind} resource, "
                    "which cannot be applied to a SQL query"
                )
            predicates.append(
                RowPredicate(
                    table=row_filter.resource.value,
                    column=row_filter.column,
                    operator=row_filter.operator,
                    values=tuple(row_filter.values),
                )
            )

        if not predicates:
            return query

        return apply_row_filters(
            query,
            predicates,
            schema_map=_load_schema_map(referenced),
            database=get_config().database,
        )

    def _sync_mssql_query(query: str) -> str:
        """Synchronous MSSQL query execution.

        Order matters and is deliberate:

          1. `validate_readonly_query` — a deny-list over tokens. Runs first because sqlglot
             parses `INSERT` perfectly happily; enumeration is not policy.
          2. `extract_referenced_tables` — the allow-list's input. Fails closed whenever the
             read set cannot be established.
          3. `_column_resources` — the same, one level finer, so a table can stay joinable
             while some of its columns stay unreachable. Skipped when no PDP is configured.
          4. `guard.require` — the decision, made against the tables and columns the model
             actually emitted. Anything an injected instruction persuaded the model to do is
             already in the query text by this point, which is exactly why the check lives
             here and not in the prompt.
          5. `_apply_policy_filters` — rewrite the query so any row predicate the decision
             carries holds. A predicate that cannot be applied exactly refuses the call.
          6. Execute.

        **The caller's query never runs until step 4 has passed.** Step 3 may open a
        connection before the decision, but only to read `INFORMATION_SCHEMA` — never a user
        row — and only for tables the caller's cached policy snapshot already permits. That
        narrowing is what keeps a caller who may not read a table from causing a catalogue
        lookup for it.
        """
        config = get_config()

        with audit_call("mssql_query", {"query": query}) as record:
            if config.readonly:
                try:
                    validate_readonly_query(query)
                except ReadOnlyViolationError as e:
                    record["decision"] = "deny"
                    record["reason"] = "read-only violation"
                    return f"Error: {e}"

            try:
                referenced = extract_referenced_tables(query, database=config.database)
                # `ColumnExtractionError` subclasses `TableExtractionError`, so both read
                # sets fail closed through this one handler.
                columns = _column_resources(query, referenced)
            except TableExtractionError as e:
                # Fails closed without consulting the PDP, and deliberately so: the query
                # cannot run when its read set is unknown, whatever policy would have said.
                # `mcp_policy_guard.UNDETERMINED` exists for tools that would otherwise pass `[]`
                # here — an empty list means "touches nothing" and would be *allowed*. This
                # one returns instead, which is the same answer for one fewer round trip.
                #
                # Deliberately does NOT report to the PDP. A parse failure is the model
                # emitting bad SQL, which is routine rather than exceptional; reporting each
                # one would fill the platform's audit log with model noise and bury the
                # infrastructure failures below, which are the ones worth seeing. The local
                # `emit()` record already covers it.
                record["decision"] = "deny"
                record["reason"] = f"read set could not be established: {e}"
                return f"Error: {e}"
            except pymssql.Error as e:
                # **Pre-decision infrastructure failure**, and the one this branch exists for.
                # `_column_resources` reads INFORMATION_SCHEMA, so on a cache miss it opens a
                # connection *before* any decision — and until now a login failure here escaped
                # both handlers and propagated raw. The call is refused, correctly, but policy
                # never ran, so it must not be recorded as a denial and the user must not be
                # told they lack access to something.
                #
                # Note the asymmetry with the identical failure at execution below: with a warm
                # schema cache the first connection is opened *after* `guard.require` passed and
                # after the PDP already wrote an allow row. That one is an execution failure and
                # reports nothing, or one call would produce both an allow and a not-evaluated
                # row for the same query.
                reason = f"could not establish the read set: {e}"
                record["decision"] = "not_evaluated"
                record["reason"] = reason
                guard.report_not_evaluated("mssql_query", reason, [])
                return (
                    "Error: the database could not be reached to determine what this query "
                    "reads, so it was not run. This is not an access decision — policy was "
                    "never consulted. Retry, and report it if it persists."
                )

            resources = [Resource(SQL_TABLE, table) for table in sorted(referenced)] + columns
            record["resources"] = [str(resource) for resource in resources]

            try:
                decision = guard.require("mssql_query", resources)
            except PolicyDenied as denied:
                record["decision"] = "deny"
                record["reason"] = denied.reason
                # Unlike the discovery tools, naming the table here reveals nothing: the
                # model already named it. Being explicit stops it retrying the same query
                # in a loop, and tells the user something they can act on.
                return _denial_message(denied)

            record["decision"] = decision.decision

            # The decision may allow the tables and still narrow which ROWS they yield. The
            # predicate is applied by rewriting the query, so the model never has to know the
            # caller's districts — and cannot widen them back out with an OR.
            try:
                effective_query = _apply_policy_filters(query, decision, referenced)
            except TableExtractionError as e:
                # A predicate that could not be applied exactly is not a query that returns
                # extra rows; it is a query that does not run.
                record["decision"] = "deny"
                record["reason"] = f"row filter could not be applied: {e}"
                return f"Error: {e}"

            if effective_query != query:
                record["rewritten"] = True

            try:
                with _get_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(effective_query)
                        columns = [desc[0] for desc in cur.description]
                        rows = cur.fetchmany(MAX_ROWS)
                        truncated = len(rows) == MAX_ROWS and cur.fetchone() is not None

                        result_lines = [" | ".join(columns)]
                        result_lines.append("-" * len(result_lines[0]))
                        for row in rows:
                            result_lines.append(" | ".join(str(val) for val in row))
                        if truncated:
                            result_lines.append(
                                f"\n[Truncated at {MAX_ROWS} rows. Narrow the query with WHERE or TOP.]"
                            )

                        return "\n".join(result_lines)
            except pymssql.Error as e:
                # The last unhandled path in this function, and the expensive one. Every branch
                # above returns a sentence the model can act on; this one used to let the
                # exception escape into FastMCP, which replaced it with "Error executing tool
                # mssql_query" and nothing else. Measured 2026-09-05: 208 occurrences, 72 chats,
                # 11 users, 5 assistants. Blind, the model cannot correct its own SQL — on
                # 2026-09-07 one reply re-sent a single failing query eleven times because the
                # real answer, `Conversion failed when converting the varchar value 'EUR' to data
                # type int.`, never reached it.
                #
                # Deliberately does NOT report to the PDP, which is the asymmetry the
                # pre-decision handler above documents: `guard.require` already passed and the
                # PDP already wrote an allow row, so reporting here would file a second row for
                # one call.
                detail = _sql_server_error_text(e)
                if detail is None:
                    # No SQL Server text means the statement never reached the server, so there
                    # is nothing about the query to report — and the client-side text carries the
                    # server address, which is why it is never passed on.
                    record["reason"] = "execution failed before SQL Server answered"
                    return (
                        "Error: the database could not be reached while running this query, so it did not "
                        "run. Policy allowed it — this is not an access decision, and not a problem with "
                        "the query. Retry, and report it if it persists."
                    )
                record["reason"] = f"query failed: {detail}"
                # Naming the column or table reveals nothing the model did not just write itself —
                # the same reasoning `_denial_message` uses — and it is what lets it fix the query
                # instead of re-sending it.
                return f"Error: {detail}"

    def _sync_mssql_list_tables(schema: str) -> str:
        """Synchronous MSSQL list tables, scoped to what the caller may see.

        Filtering rather than refusing is the point. A listing that said "3 tables hidden"
        would be an enumeration oracle — the caller learns the exact names of what they
        cannot reach, which is often the interesting half of the secret. A scoped caller
        simply sees a smaller database.
        """
        with audit_call("mssql_list_tables", {"schema": schema}) as record:
            # Unlike `mssql_query`, this always reads the catalogue before deciding anything —
            # the listing *is* the input to the decision — so a connection failure here is
            # unambiguously pre-decision, with no cache-warmth asymmetry to reason about.
            try:
                with _get_connection() as conn:
                    with conn.cursor() as cur:
                        cur.execute(
                            """
                            SELECT TABLE_NAME
                            FROM INFORMATION_SCHEMA.TABLES
                            WHERE TABLE_SCHEMA = %s
                            AND TABLE_TYPE = 'BASE TABLE'
                            ORDER BY TABLE_NAME
                            """,
                            (schema,),
                        )
                        tables = [row[0] for row in cur.fetchall()]
            except pymssql.Error as e:
                reason = f"could not list tables to scope them: {e}"
                record["decision"] = "not_evaluated"
                record["reason"] = reason
                guard.report_not_evaluated("mssql_list_tables", reason, [])
                return (
                    "Error: the database could not be reached to list its tables, so nothing "
                    "was returned. This is not an access decision — policy was never "
                    "consulted. Retry, and report it if it persists."
                )

            try:
                visible = guard.filter_resources(
                    SQL_TABLE,
                    tables,
                    function_name="mssql_list_tables",
                    key=lambda name: normalize_table_name(schema, name),
                )
            except PolicyDenied as denied:
                # Denied the *function*, not particular tables. Saying so plainly is not an
                # enumeration oracle — it names no table — and it stops the model retrying a
                # listing it will never be allowed to make.
                record["decision"] = "deny"
                record["reason"] = denied.reason
                return _denial_message(denied)

            record["decision"] = "allow" if len(visible) == len(tables) else "partial"
            record["resources"] = [normalize_table_name(schema, name) for name in visible]

            if not visible:
                # Byte-identical to the response for a genuinely empty schema.
                return f"No tables found in schema '{schema}'"

            return f"Tables in schema '{schema}':\n" + "\n".join(f"  - {t}" for t in visible)

    def _sync_mssql_describe_table(table_name: str, schema: str) -> str:
        """Synchronous MSSQL describe table, authorized before it queries.

        On denial this returns the **same string** the tool already returns for a table that
        does not exist. Distinguishing the two would turn every denial into a confirmation
        that the table is real — the oracle that `mssql_list_tables` filtering exists to
        avoid, reintroduced one name at a time.
        """
        qualified = normalize_table_name(schema, table_name)
        not_found = f"Table '{schema}.{table_name}' not found"

        with audit_call("mssql_describe_table", {"table_name": table_name, "schema": schema}) as record:
            record["resources"] = [qualified]
            try:
                decision = guard.require("mssql_describe_table", [Resource(SQL_TABLE, qualified)])
            except PolicyDenied as denied:
                # The real reason goes to the audit trail; the model is told nothing.
                record["decision"] = "deny"
                record["reason"] = denied.reason
                return not_found

            record["decision"] = decision.decision

            with _get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        """
                        SELECT
                            COLUMN_NAME,
                            DATA_TYPE,
                            CHARACTER_MAXIMUM_LENGTH,
                            IS_NULLABLE,
                            COLUMN_DEFAULT
                        FROM INFORMATION_SCHEMA.COLUMNS
                        WHERE TABLE_SCHEMA = %s
                        AND TABLE_NAME = %s
                        ORDER BY ORDINAL_POSITION
                        """,
                        (schema, table_name),
                    )
                    columns = cur.fetchall()

                    if not columns:
                        return not_found

                    # Filter, do not refuse — the same reasoning as `mssql_list_tables`.
                    # Naming a column in order to say it is hidden is an enumeration oracle,
                    # and for this table the column *names* are the sensitive part: knowing a
                    # `NationalInsuranceNumber` column exists is most of the secret. A scoped
                    # caller simply sees a narrower table.
                    #
                    # Decided from the cached snapshot rather than one `evaluate` per column,
                    # so describing a wide table stays a single round trip.
                    snapshot = guard.snapshot("mssql_describe_table")
                    visible = [col for col in columns if snapshot.allows(SQL_COLUMN, f"{qualified}.{col[0].lower()}")]
                    record["resources"] = [qualified] + [f"{SQL_COLUMN}:{qualified}.{c[0].lower()}" for c in visible]

                    if not visible:
                        # Every column denied is indistinguishable from the table not being
                        # there, and must stay that way for the same reason.
                        return not_found

                    result_lines = [f"Table: {schema}.{table_name}", ""]
                    result_lines.append("Column | Type | Nullable | Default")
                    result_lines.append("-" * 60)

                    for col in visible:
                        name, dtype, max_len, nullable, default = col
                        type_str = f"{dtype}({max_len})" if max_len else dtype
                        nullable_str = "YES" if nullable == "YES" else "NO"
                        default_str = str(default) if default else ""
                        result_lines.append(f"{name} | {type_str} | {nullable_str} | {default_str}")

                    return "\n".join(result_lines)

    config = get_config()
    if config.readonly:
        query_desc = "Execute a read-only SQL query on the MSSQL database.\n\nArgs:\n    query: SQL SELECT query to execute. Only SELECT statements are allowed.\n\nReturns:\n    Query results as formatted text with column headers."
    else:
        query_desc = "Execute a SQL query on the MSSQL database. Supports both read and write queries (SELECT, INSERT, UPDATE, DELETE).\n\nArgs:\n    query: SQL query to execute. SELECT returns rows; write statements return affected row count.\n\nReturns:\n    Query results as formatted text, or affected row count for write operations."

    # `@guarded` sits under `@mcp.tool()` on every handler, so the SDK registers the wrapper.
    #
    # **It is not optional and it is not decoration.** An MCP session is opened by whoever
    # sent `initialize`, and on MCP SDK 1.x every later message is dispatched inside the task
    # that spawned with it — so a principal bound only by the ASGI middleware stays the
    # session opener's for the life of the session. Without this, two users sharing a session
    # means the second one's query is authorized against the first one's grants, and the
    # audit row names the wrong person. See `mcp_policy_guard.request` for the mechanism.
    @mcp.tool(description=query_desc)
    @guarded
    async def mssql_query(query: str) -> str:
        """Execute a SQL query on the MSSQL database."""
        return await asyncio.to_thread(_sync_mssql_query, query)

    @mcp.tool()
    @guarded
    async def mssql_list_tables(schema: str = "dbo") -> str:
        """List all tables in the MSSQL database.

        Args:
            schema: Schema name to list tables from. Defaults to 'dbo'.

        Returns:
            List of table names in the specified schema.
        """
        return await asyncio.to_thread(_sync_mssql_list_tables, schema)

    @mcp.tool()
    @guarded
    async def mssql_describe_table(table_name: str, schema: str = "dbo") -> str:
        """Get the schema/structure of an MSSQL table.

        Args:
            table_name: Name of the table to describe.
            schema: Schema name. Defaults to 'dbo'.

        Returns:
            Table structure with column names, types, and constraints.
        """
        return await asyncio.to_thread(_sync_mssql_describe_table, table_name, schema)


def _sql_server_error_text(exc: pymssql.Error) -> str | None:
    """The SQL Server message inside a pymssql error, or `None` when there is not one.

    pymssql packs the two cases differently, and that difference is the whole discriminator:

        SQL Server rejected the statement
            args = (207, b"Invalid column name 'StatusName'.DB-Lib error message 20018, ...")
        the client never reached SQL Server
            args = ((20009, b"DB-Lib error message 20009, ... does not exist (10.0.0.5) ..."),)

    Only the first describes something the model wrote, and only the first is safe to pass on:
    the second quotes the server address in its text. The DB-Lib trailer is dropped from both —
    it is the same boilerplate on every error and says nothing the caller can use.
    """
    args = getattr(exc, "args", ())
    if args and isinstance(args[0], tuple):
        args = args[0]
    if len(args) < 2 or not isinstance(args[0], int):
        return None
    number, message = args[0], args[1]
    if number >= DBLIB_ERROR_FLOOR:
        return None
    if isinstance(message, bytes | bytearray):
        message = message.decode("utf-8", "replace")
    text = str(message).split("DB-Lib error message")[0].strip()
    if not text:
        return None
    return text[:MAX_ERROR_CHARS]


def _denial_message(denied: PolicyDenied) -> str:
    """What to tell the model when a call is refused.

    An outage is not a denial. `PolicyUnavailable` subclasses `PolicyDenied` so the
    fail-closed path cannot be forgotten, but saying "you do not have access to dbo.orders"
    while the decision point is down sends the user to raise an access request for a
    permission they already hold — and tells the model to stop trying something that will
    work again in a minute.
    """
    if denied.is_outage:
        return "Error: authorization is temporarily unavailable. Retry shortly; this is not a permissions problem."
    if denied.resources:
        names = ", ".join(sorted(r.split(":", 1)[-1] for r in denied.resources))
        return f"Error: You do not have access to {names}."
    return f"Error: {denied.reason}"
