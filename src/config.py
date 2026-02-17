"""Configuration management from environment variables."""

import os
from dataclasses import dataclass


@dataclass
class MSSQLConfig:
    """MSSQL connection configuration."""

    host: str
    port: int
    user: str
    password: str
    database: str
    readonly: bool


def get_mssql_config() -> MSSQLConfig:
    """Load MSSQL configuration from environment variables."""
    return MSSQLConfig(
        host=os.environ.get("MSSQL_HOST", "localhost"),
        port=int(os.environ.get("MSSQL_PORT", "1433")),
        user=os.environ.get("MSSQL_USER", "sa"),
        password=os.environ.get("MSSQL_PASSWORD", ""),
        database=os.environ.get("MSSQL_DB", "master"),
        readonly=os.environ.get("MSSQL_READONLY", "true").lower() in ("true", "1", "yes"),
    )
