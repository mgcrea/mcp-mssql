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
    <img src="https://img.shields.io/github/license/mgcrea/mcp-mssql?style=for-the-badge" alt="license" />
  </a>
  <a href="https://github.com/mgcrea/mcp-mssql">
    <img src="https://img.shields.io/badge/python-3.12+-blue?style=for-the-badge" alt="python version" />
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

| Variable         | Default     | Description                |
| ---------------- | ----------- | -------------------------- |
| `MSSQL_HOST`     | `localhost` | SQL Server host            |
| `MSSQL_PORT`     | `1433`      | SQL Server port            |
| `MSSQL_USER`     | `sa`        | Database user              |
| `MSSQL_PASSWORD` |             | Database password          |
| `MSSQL_DB`       | `master`    | Database name              |
| `MSSQL_READONLY` | `true`      | Enforce read-only queries  |
| `MCP_PORT`       | `8080`      | Server port                |

> Set `MSSQL_READONLY=false` to enable read/write mode (INSERT, UPDATE, DELETE, etc.).

## Endpoints

| Path       | Method | Description                             |
| ---------- | ------ | --------------------------------------- |
| `/healthz` | GET    | Health check for K8s probes             |
| `/`        | GET    | Server info (name, version, transports) |
| `/mcp`     | POST   | MCP Streamable-HTTP transport           |
| `/sse`     | GET    | MCP SSE transport (legacy)              |

## Docker

```bash
make docker-build
make docker-run
```
