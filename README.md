# mcp-mssql

MCP tool server providing read-only SQL Server database access for AI agents.

## Tools

| Tool                   | Description                                       |
| ---------------------- | ------------------------------------------------- |
| `mssql_query`          | Execute read-only SQL SELECT queries              |
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

| Variable         | Default     | Description       |
| ---------------- | ----------- | ----------------- |
| `MSSQL_HOST`     | `localhost` | SQL Server host   |
| `MSSQL_PORT`     | `1433`      | SQL Server port   |
| `MSSQL_USER`     | `sa`        | Database user     |
| `MSSQL_PASSWORD` |             | Database password |
| `MSSQL_DB`       | `master`    | Database name     |
| `MCP_PORT`       | `8080`      | Server port       |

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
