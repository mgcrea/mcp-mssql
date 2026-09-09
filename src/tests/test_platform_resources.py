"""The platform's two delivery routes for assigned resources.

The same loader is pasted into all nine tool runtimes — sharing it would mean either putting
document loading in `mcp-policy-guard` (whose name would then lie, and which four of the nine
do not depend on) or renaming that package, which is a security-interlock change: the platform
reads the guard version out of a `mcp-policy-guard/<version>` User-Agent and fails closed on an
unrecognised one. These tests pin the contract for the copy the other eight are taken from.
"""

import json
import os
import pathlib

import pytest


@pytest.fixture
def load(monkeypatch):
    """The loader, evaluated in isolation so importing it does not start a server."""
    src = pathlib.Path("src/mcp_mssql/server.py").read_text()
    start = src.index("_resources_cache: dict | None = None")
    end = src.index("def register_platform_resources(")
    ns: dict = {"os": os, "json": json, "pathlib": pathlib}
    exec(compile(src[start:end], "loader", "exec"), ns)
    monkeypatch.delenv("MCP_RESOURCES", raising=False)
    monkeypatch.delenv("MCP_RESOURCES_PATH", raising=False)
    return ns["_load_platform_resources"]


def _payload(text: str) -> str:
    return json.dumps({"card": {"name": "Card", "description": "d", "text": text}})


def test_reads_the_mounted_file(load, monkeypatch, tmp_path):
    f = tmp_path / "MCP_RESOURCES"
    f.write_text(_payload("from-file"))
    monkeypatch.setenv("MCP_RESOURCES_PATH", str(f))

    assert load()["card"]["text"] == "from-file"


def test_reparses_only_when_the_file_changes(load, monkeypatch, tmp_path):
    f = tmp_path / "MCP_RESOURCES"
    f.write_text(_payload("v1"))
    monkeypatch.setenv("MCP_RESOURCES_PATH", str(f))
    assert load()["card"]["text"] == "v1"

    # Same mtime, different bytes: the cache is expected to win, which is the point of it.
    mtime = f.stat().st_mtime
    f.write_text(_payload("v2"))
    os.utime(f, (mtime, mtime))
    assert load()["card"]["text"] == "v1"

    # Moving the mtime is what a ConfigMap update does.
    os.utime(f, (mtime + 10, mtime + 10))
    assert load()["card"]["text"] == "v2"


def test_falls_back_to_the_environment_variable(load, monkeypatch):
    monkeypatch.setenv("MCP_RESOURCES", _payload("from-env"))
    assert load()["card"]["text"] == "from-env"


def test_a_path_that_does_not_exist_falls_through_rather_than_raising(load, monkeypatch, tmp_path):
    # The platform injects the path for every worker, including images that predate the mount,
    # so a missing file is a rollout state and must not take the server down.
    monkeypatch.setenv("MCP_RESOURCES_PATH", str(tmp_path / "absent"))
    monkeypatch.setenv("MCP_RESOURCES", _payload("from-env"))
    assert load()["card"]["text"] == "from-env"


def test_no_delivery_at_all_is_empty_not_an_error(load):
    assert load() == {}
