"""Shared pytest fixtures: contract fixture loader and a throwaway PostgreSQL schema.

Database tests run only when NEXUS_TEST_DB_URL is set AND its database name contains
"test", so a wrong URL can never touch real tables. Each test session creates its own
schema (nexus_pytest_<random>) and drops it at the end.
"""

from __future__ import annotations

import json
import os
import secrets
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine, make_url

FIXTURES = ROOT / "contracts" / "fixtures"
TEST_DB_URL = os.environ.get("NEXUS_TEST_DB_URL", "")


def _test_db_ok() -> bool:
    if not TEST_DB_URL:
        return False
    return "test" in (make_url(TEST_DB_URL).database or "")


requires_db = pytest.mark.skipif(
    not _test_db_ok(),
    reason="NEXUS_TEST_DB_URL unset, or its database name does not contain 'test'",
)


def load_fixture(name: str) -> Any:
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


@pytest.fixture(scope="session")
def pg_engine() -> Iterator[Engine]:
    if not _test_db_ok():
        pytest.skip("no test database")
    schema = f"nexus_pytest_{secrets.token_hex(4)}"
    admin = create_engine(TEST_DB_URL)
    with admin.begin() as conn:
        conn.execute(text(f'CREATE SCHEMA "{schema}"'))
    engine = create_engine(
        TEST_DB_URL, connect_args={"options": f"-csearch_path={schema}"}
    )
    try:
        yield engine
    finally:
        engine.dispose()
        with admin.begin() as conn:
            conn.execute(text(f'DROP SCHEMA "{schema}" CASCADE'))
        admin.dispose()


@pytest.fixture()
def engine(pg_engine: Engine) -> Iterator[Engine]:
    """Fresh, empty tables for every test."""
    from server import db

    db.create_all(pg_engine)
    yield pg_engine
    db.metadata.drop_all(pg_engine)
