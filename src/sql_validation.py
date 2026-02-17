"""SQL validation for read-only query enforcement (MSSQL)."""

import re


class ReadOnlyViolationError(Exception):
    """Raised when a query violates read-only constraints."""


# SQL keywords that indicate write/DDL/admin operations.
# MSSQL-specific: EXEC, EXECUTE, BULK, OPENROWSET, OPENQUERY, DBCC, WAITFOR.
_FORBIDDEN_KEYWORDS: set[str] = {
    "INSERT",
    "UPDATE",
    "DELETE",
    "DROP",
    "ALTER",
    "CREATE",
    "TRUNCATE",
    "MERGE",
    "GRANT",
    "REVOKE",
    "DENY",
    "EXEC",
    "EXECUTE",
    "BULK",
    "OPENROWSET",
    "OPENQUERY",
    "INTO",
    "DBCC",
    "BACKUP",
    "RESTORE",
    "SHUTDOWN",
    "KILL",
    "RECONFIGURE",
    "WAITFOR",
}

_BLOCK_COMMENT_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
_LINE_COMMENT_RE = re.compile(r"--[^\n]*")
_STRING_LITERAL_RE = re.compile(r"'(?:[^']|'')*'")
_BRACKET_IDENT_RE = re.compile(r"\[(?:[^\]]|\]\])*\]")
_DQUOTE_IDENT_RE = re.compile(r'"(?:[^"]|"")*"')


def _strip_literals_and_comments(sql: str) -> str:
    """Remove string literals, comments, and quoted identifiers from SQL.

    Returns SQL with these elements replaced by spaces so keyword
    detection operates only on actual SQL tokens.
    """
    result = _BLOCK_COMMENT_RE.sub(" ", sql)
    result = _LINE_COMMENT_RE.sub(" ", result)
    result = _STRING_LITERAL_RE.sub(" ", result)
    result = _BRACKET_IDENT_RE.sub(" ", result)
    result = _DQUOTE_IDENT_RE.sub(" ", result)
    return result


def validate_readonly_query(query: str) -> None:
    """Validate that a SQL query is read-only.

    Raises ReadOnlyViolationError if the query appears to be non-readonly.

    Allows: SELECT, WITH...SELECT (CTEs), EXPLAIN.
    Blocks: INSERT, UPDATE, DELETE, DROP, ALTER, CREATE, TRUNCATE, EXEC,
            EXECUTE, MERGE, GRANT, REVOKE, multi-statement queries, etc.
    """
    stripped = query.strip()
    if not stripped:
        raise ReadOnlyViolationError("Empty query is not allowed.")

    cleaned = _strip_literals_and_comments(stripped)

    # Allow a single trailing semicolon, then check for multi-statement
    cleaned_trimmed = cleaned.strip().rstrip(";").strip()
    if ";" in cleaned_trimmed:
        raise ReadOnlyViolationError(
            "Multi-statement queries are not allowed. Only single SELECT statements are permitted."
        )

    # Extract uppercase word tokens from cleaned SQL
    words = set(re.findall(r"[A-Z_]+", cleaned_trimmed.upper()))
    if not words:
        raise ReadOnlyViolationError("Could not parse any SQL keywords from query.")

    # Check first keyword
    first_word_match = re.match(r"\s*([A-Za-z_]+)", cleaned_trimmed)
    if not first_word_match:
        raise ReadOnlyViolationError("Query does not start with a valid SQL keyword.")

    first_keyword = first_word_match.group(1).upper()
    if first_keyword not in {"SELECT", "WITH", "EXPLAIN"}:
        raise ReadOnlyViolationError(
            f"Query starts with '{first_keyword}'. Only SELECT, WITH (CTE), and EXPLAIN statements are allowed."
        )

    # Check for forbidden keywords anywhere in the cleaned query
    forbidden_found = words & _FORBIDDEN_KEYWORDS
    if forbidden_found:
        raise ReadOnlyViolationError(
            f"Query contains forbidden keyword(s): {', '.join(sorted(forbidden_found))}. "
            f"Only read-only queries are allowed."
        )
