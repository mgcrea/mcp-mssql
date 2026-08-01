# mcp-mssql

<!-- markdownlint-disable MD033 -->
<p align="center">
  <a href="https://github.com/mgcrea/mcp-mssql/actions/workflows/ci.yml">
    <img src="https://img.shields.io/github/actions/workflow/status/mgcrea/mcp-mssql/ci.yml?style=for-the-badge&branch=main" alt="build status" />
  </a>
  <a href="https://ghcr.io/mgcrea/mcp-mssql">
    <img src="https://img.shields.io/badge/ghcr.io-mgcrea%2Fmcp--mssql-blue?style=for-the-badge" alt="docker image" />
  </a>
  <a href="https://github.com/mgcrea/mcp-mssql">
    <img src="https://img.shields.io/badge/python-3.12+-blue?style=for-the-badge" alt="python version" />
  </a>
  <a href="https://github.com/mgcrea/mcp-mssql">
    <img src="https://img.shields.io/github/license/mgcrea/mcp-mssql?style=for-the-badge" alt="license" />
  </a>
</p>
<!-- markdownlint-enable MD033 -->

MCP tool server providing SQL Server database access for AI agents.

## Tools

| Tool                   | Description                                       |
| ---------------------- | ------------------------------------------------- |
| `mssql_query`          | Execute SQL queries (read-only by default)        |
| `mssql_list_tables`    | List all tables in a schema                       |
| `mssql_describe_table` | Get table structure (columns, types, constraints) |

## Quick Start

```bash
cp .env.example .env
# Edit .env with your MSSQL connection details
make install
make server
```

## Environment Variables

| Variable         | Default     | Description               |
| ---------------- | ----------- | ------------------------- |
| `MSSQL_HOST`     | `localhost` | SQL Server host           |
| `MSSQL_PORT`     | `1433`      | SQL Server port           |
| `MSSQL_USER`     | `sa`        | Database user             |
| `MSSQL_PASSWORD` |             | Database password         |
| `MSSQL_DB`       | `master`    | Database name             |
| `MSSQL_READONLY` | `true`      | Enforce read-only queries |
| `MSSQL_MAX_ROWS` | `1000`      | Row ceiling per query     |
| `MCP_PORT`       | `8080`      | Server port               |

> Set `MSSQL_READONLY=false` to enable read/write mode (INSERT, UPDATE, DELETE, etc.).

`MSSQL_MAX_ROWS` is a resource bound, not an access control — an allowed table stays fully
readable, one page at a time. Without it a bare `SELECT *` on a large table materialises
every row into the pod and then into the model's context, and neither survives that.

## Access control

Per-caller authorization is provided by [mcp-guard](../mcp-guard), configured entirely
through the `MCP_*` variables the rgis-workers platform injects — see that package's README
for the full table. Two behaviours are specific to this worker:

**Queries are authorized against the tables they actually read.** `mssql_query` parses the
T-SQL with sqlglot, enumerates every referenced table, and submits the whole set for a
decision. Every table must be allowed, so a query joining `dbo.Orders` and `hr.Payroll` *is*
a payroll read and fails as a whole — a join cannot launder access. The check runs on the
emitted SQL, after any prompt injection has had its say, which is why it holds where a
prompt instruction would not. When the read set cannot be established with certainty —
four-part names, table-valued functions, `OPENROWSET`, a parse failure — the query is
**refused**, not guessed at. See `src/mcp_mssql/table_extraction.py` and its test suite.

**Discovery hides rather than refuses.** `mssql_list_tables` silently omits tables the
caller may not see, and `mssql_describe_table` returns the same *"not found"* string for a
denied table as for an absent one. Distinguishing the two would confirm which tables exist,
turning every denial into an enumeration oracle. The real reason is recorded in the audit
trail instead. `mssql_query` is the deliberate exception: the model already named the table,
so an explicit denial reveals nothing and stops it retrying.

With no policy URL configured the guard authenticates and then allows, which is exactly how
this tool behaved before access control existed.

## Endpoints

| Path       | Method | Description                             |
| ---------- | ------ | --------------------------------------- |
| `/healthz` | GET    | Health check for K8s probes             |
| `/`        | GET    | Server info (name, version, transports) |
| `/mcp`     | POST   | MCP Streamable-HTTP transport           |
| `/sse`     | GET    | MCP SSE transport (legacy, see below)   |

`/sse` is **not mounted** when `MCP_REQUIRE_AUTH=true`. Under SSE the long-lived connection
that carried the `Authorization` header is not the request that carries a tool call, so the
caller cannot be attributed to the call — mounting it anyway would leave a second,
unauthenticated door onto the same tools.

## Docker

```bash
make docker-build
make docker-run
```
