# mcp-mssql

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

Per-caller authorization is provided by
[mcp-policy-guard](https://github.com/mgcrea/mcp-policy-guard), configured entirely
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

**Columns are authorized too, so a table can stay joinable while some of its fields do not.**
Alongside the table set, `mssql_query` submits every column the query reads as a
`sql_column` resource — `dbo.perfusers.dateofbirth`. That is what lets a rule deny a personal
field sitting on the same join as data the caller may legitimately read: deny the table and
the legitimate query breaks, deny the column and it keeps working while the field stays
unreachable. `SELECT *` is expanded against the real schema first, so a star that would have
included a denied column is denied rather than slipping through unnamed. Column attribution
uses sqlglot's `qualify`, which **fails open on a table it has no schema for** — returning no
columns rather than raising — so the schema map is checked for coverage before the result is
trusted, and an unknown or empty table refuses the query. See
`src/mcp_mssql/column_extraction.py`.

**An allowed table can come back narrowed to some of its rows.** When the decision carries a
row predicate, the query is **rewritten** rather than checked: each governed table is wrapped
in place, `FROM dbo.PerfEvents e` becoming
`FROM (SELECT * FROM dbo.PerfEvents WHERE District IN ('D775')) AS e`. Wrapping the table node
rather than appending to the outer `WHERE` is what makes joins, `UNION` arms, correlated
subqueries and CTE bodies work with no special cases — and means an outer `OR` cannot widen it
back out. The model never learns the caller's districts and cannot write around them. Values
become bound literals, never interpolated text. After rewriting, the table set is re-extracted
and asserted unchanged, so a rewrite that introduced a new source fails instead of running.
Anything that cannot be applied exactly — a filter column absent from the table, a table
reference in a shape the transformer does not recognise — refuses the query. See
`src/mcp_mssql/row_filters.py`.

**Discovery hides rather than refuses.** `mssql_list_tables` silently omits tables the
caller may not see, and `mssql_describe_table` returns the same *"not found"* string for a
denied table as for an absent one, and omits denied *columns* from the structure it does
return — otherwise the column names leak from the one tool whose job is to describe them. Distinguishing the two would confirm which tables exist,
turning every denial into an enumeration oracle. The real reason is recorded in the audit
trail instead. `mssql_query` is the deliberate exception: the model already named the table,
so an explicit denial reveals nothing and stops it retrying.

Row predicates and column resources need **mcp-policy-guard 0.6.0 or later**. The platform
refuses to send a predicate to an older guard and denies the resource instead, so an
out-of-date image fails visibly rather than returning every row.

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
