"""MSSQL database tools for MCP."""

import asyncio
import os

import pymssql
from mcp.server.fastmcp import FastMCP
from mcp_policy_guard import Guard, PolicyDenied, Resource, audit_call, guarded

from ..config import get_config
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

#: Selector kind the platform's policy store uses for SQL tables.
SQL_TABLE = "sql_table"

guard = Guard()


def register_mssql_tools(mcp: FastMCP) -> None:
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

    def _sync_mssql_query(query: str) -> str:
        """Synchronous MSSQL query execution.

        Order matters and is deliberate:

          1. `validate_readonly_query` — a deny-list over tokens. Runs first because sqlglot
             parses `INSERT` perfectly happily; enumeration is not policy.
          2. `extract_referenced_tables` — the allow-list's input. Fails closed whenever the
             read set cannot be established.
          3. `guard.require` — the decision, made against the tables the model actually
             emitted. Anything an injected instruction persuaded the model to do is already
             in the query text by this point, which is exactly why the check lives here and
             not in the prompt.
          4. Execute.

        Nothing opens a database connection until step 3 has passed.
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
            except TableExtractionError as e:
                # Fails closed without consulting the PDP, and deliberately so: the query
                # cannot run when its read set is unknown, whatever policy would have said.
                # `mcp_policy_guard.UNDETERMINED` exists for tools that would otherwise pass `[]`
                # here — an empty list means "touches nothing" and would be *allowed*. This
                # one returns instead, which is the same answer for one fewer round trip.
                record["decision"] = "deny"
                record["reason"] = f"table extraction failed: {e}"
                return f"Error: {e}"

            record["resources"] = sorted(referenced)

            try:
                decision = guard.require("mssql_query", [Resource(SQL_TABLE, table) for table in sorted(referenced)])
            except PolicyDenied as denied:
                record["decision"] = "deny"
                record["reason"] = denied.reason
                # Unlike the discovery tools, naming the table here reveals nothing: the
                # model already named it. Being explicit stops it retrying the same query
                # in a loop, and tells the user something they can act on.
                return _denial_message(denied)

            record["decision"] = decision.decision

            with _get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(query)
                    columns = [desc[0] for desc in cur.description]
                    rows = cur.fetchmany(MAX_ROWS)
                    truncated = len(rows) == MAX_ROWS and cur.fetchone() is not None

                    result_lines = [" | ".join(columns)]
                    result_lines.append("-" * len(result_lines[0]))
                    for row in rows:
                        result_lines.append(" | ".join(str(val) for val in row))
                    if truncated:
                        result_lines.append(f"\n[Truncated at {MAX_ROWS} rows. Narrow the query with WHERE or TOP.]")

                    return "\n".join(result_lines)

    def _sync_mssql_list_tables(schema: str) -> str:
        """Synchronous MSSQL list tables, scoped to what the caller may see.

        Filtering rather than refusing is the point. A listing that said "3 tables hidden"
        would be an enumeration oracle — the caller learns the exact names of what they
        cannot reach, which is often the interesting half of the secret. A scoped caller
        simply sees a smaller database.
        """
        with audit_call("mssql_list_tables", {"schema": schema}) as record:
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

                    result_lines = [f"Table: {schema}.{table_name}", ""]
                    result_lines.append("Column | Type | Nullable | Default")
                    result_lines.append("-" * 60)

                    for col in columns:
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
