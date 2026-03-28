"""MSSQL database tools for MCP."""

import asyncio
import os

import pymssql
from mcp.server.fastmcp import FastMCP

from ..audit import audit_log
from ..config import get_config
from ..sql_validation import ReadOnlyViolationError, validate_readonly_query

# Timeout configuration (seconds)
# Login timeout must be generous enough to survive Knative cold-start latency
# when the DB server needs time to accept new connections.
LOGIN_TIMEOUT = int(os.environ.get("MSSQL_LOGIN_TIMEOUT", "30"))
QUERY_TIMEOUT = int(os.environ.get("MSSQL_QUERY_TIMEOUT", "30"))


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
        """Synchronous MSSQL query execution."""
        config = get_config()
        if config.readonly:
            try:
                validate_readonly_query(query)
            except ReadOnlyViolationError as e:
                return f"Error: {e}"

        with audit_log("mssql_query", {"query": query}):
            with _get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(query)
                    columns = [desc[0] for desc in cur.description]
                    rows = cur.fetchall()

                    # Format output
                    result_lines = [" | ".join(columns)]
                    result_lines.append("-" * len(result_lines[0]))
                    for row in rows:
                        result_lines.append(" | ".join(str(val) for val in row))

                    return "\n".join(result_lines)

    def _sync_mssql_list_tables(schema: str) -> str:
        """Synchronous MSSQL list tables."""
        with audit_log("mssql_list_tables", {"schema": schema}):
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

                    if not tables:
                        return f"No tables found in schema '{schema}'"

                    return f"Tables in schema '{schema}':\n" + "\n".join(f"  - {t}" for t in tables)

    def _sync_mssql_describe_table(table_name: str, schema: str) -> str:
        """Synchronous MSSQL describe table."""
        with audit_log("mssql_describe_table", {"table_name": table_name, "schema": schema}):
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
                        return f"Table '{schema}.{table_name}' not found"

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

    @mcp.tool(description=query_desc)
    async def mssql_query(query: str) -> str:
        """Execute a SQL query on the MSSQL database."""
        return await asyncio.to_thread(_sync_mssql_query, query)

    @mcp.tool()
    async def mssql_list_tables(schema: str = "dbo") -> str:
        """List all tables in the MSSQL database.

        Args:
            schema: Schema name to list tables from. Defaults to 'dbo'.

        Returns:
            List of table names in the specified schema.
        """
        return await asyncio.to_thread(_sync_mssql_list_tables, schema)

    @mcp.tool()
    async def mssql_describe_table(table_name: str, schema: str = "dbo") -> str:
        """Get the schema/structure of an MSSQL table.

        Args:
            table_name: Name of the table to describe.
            schema: Schema name. Defaults to 'dbo'.

        Returns:
            Table structure with column names, types, and constraints.
        """
        return await asyncio.to_thread(_sync_mssql_describe_table, table_name, schema)
