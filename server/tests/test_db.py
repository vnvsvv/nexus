"""Tests for server/db.py (R2)."""

from __future__ import annotations

import pytest
from conftest import load_fixture, requires_db
from sqlalchemy import CheckConstraint, func, select
from sqlalchemy.dialects import postgresql
from sqlalchemy.schema import CreateTable

from server import db

EXPECTED_PK = {
    "endpoints": ["endpoint_id"],
    "incidents": ["endpoint_id", "incident_id"],
    "incident_connections": ["id"],
    "gateway_connections": ["gateway_connection_id"],
    "gateway_flows": ["flow_id"],
    "incident_correlations": ["id"],
    "network_alerts": ["alert_id"],
    "ti_indicators": ["type", "value"],
    "ti_lookups": ["id"],
    "response_commands": ["command_id"],
    "response_results": ["command_id"],
}


# ---------- no database needed ----------
def test_all_eleven_tables_exist() -> None:
    assert set(db.metadata.tables) == set(EXPECTED_PK)


@pytest.mark.parametrize("table,pk", sorted(EXPECTED_PK.items()))
def test_primary_keys(table: str, pk: list[str]) -> None:
    assert [c.name for c in db.metadata.tables[table].primary_key.columns] == pk


def test_gateway_connection_indexes_column_order() -> None:
    idx = {i.name: [c.name for c in i.columns] for i in db.gateway_connections.indexes}
    assert idx["ix_gwconn_fwd"] == [
        "protocol",
        "orig_src_ip",
        "orig_src_port",
        "orig_dst_ip",
        "orig_dst_port",
        "first_seen_utc",
    ]
    assert idx["ix_gwconn_rev"] == [
        "protocol",
        "orig_dst_ip",
        "orig_dst_port",
        "orig_src_ip",
        "orig_src_port",
        "first_seen_utc",
    ]


def test_postgres_types_in_ddl() -> None:
    ddl = "\n".join(
        str(CreateTable(t).compile(dialect=postgresql.dialect()))
        for t in db.metadata.sorted_tables
    )
    for token in ("JSONB", "INET", "TIMESTAMP WITH TIME ZONE", "TEXT[]"):
        assert token in ddl


def test_correlation_state_check() -> None:
    checks = [
        c
        for c in db.incident_correlations.constraints
        if isinstance(c, CheckConstraint)
    ]
    assert len(checks) == 1
    sql = str(checks[0].sqltext)
    for state in ("matched", "ambiguous", "pending", "unmatched"):
        assert f"'{state}'" in sql
    assert any(i.name == "ix_inccorr_state" for i in db.incident_correlations.indexes)


def test_cascade_foreign_keys() -> None:
    for t in (db.incident_connections, db.incident_correlations):
        fks = [
            fk for fk in t.foreign_key_constraints if fk.referred_table is db.incidents
        ]
        assert len(fks) == 1 and fks[0].ondelete == "CASCADE"


def test_iso_roundtrip() -> None:
    assert (
        db.iso_utc(db.parse_utc("2026-11-15T10:30:06.012Z"))
        == "2026-11-15T10:30:06.012Z"
    )


# ---------- real PostgreSQL ----------
def _gw_row(doc: dict) -> dict:
    row = {k: v for k, v in doc.items() if k != "flow_ids"}
    for k in ("first_seen_utc", "last_seen_utc"):
        row[k] = db.parse_utc(row[k])
    return row


@requires_db
def test_create_all_is_idempotent(engine) -> None:
    db.create_all(engine)
    db.create_all(engine)


@requires_db
def test_gateway_connection_fixture_roundtrip(engine) -> None:
    doc = load_fixture("gateway_connection_example.json")
    with engine.begin() as conn:
        conn.execute(db.gateway_connections.insert().values(**_gw_row(doc)))
        row = conn.execute(select(db.gateway_connections)).one()
    assert str(row.orig_src_ip) == doc["orig_src_ip"]
    assert db.iso_utc(row.first_seen_utc) == doc["first_seen_utc"]
    assert row.scope == "routed"


@requires_db
def test_incident_document_verbatim_and_cascade(engine) -> None:
    doc = load_fixture("incident_linux_l1.json")
    conn_doc = doc["connections"][0]
    with engine.begin() as conn:
        conn.execute(
            db.incidents.insert().values(
                endpoint_id=doc["endpoint_id"],
                incident_id=doc["incident_id"],
                incident_version=doc["incident_version"],
                document=doc,
                status=doc["status"],
                severity=doc["severity"],
                detected_at_utc=db.parse_utc(doc["detected_at_utc"]),
                received_at_utc=func.now(),
            )
        )
        conn.execute(
            db.incident_connections.insert().values(
                endpoint_id=doc["endpoint_id"],
                incident_id=doc["incident_id"],
                connection_id=conn_doc["connection_id"],
                protocol=conn_doc["protocol"],
                src_ip=conn_doc["src_ip"],
                src_port=conn_doc["src_port"],
                dst_ip=conn_doc["dst_ip"],
                dst_port=conn_doc["dst_port"],
                direction=conn_doc["direction"],
                first_seen_utc=db.parse_utc(conn_doc["first_seen_utc"]),
            )
        )
        stored = conn.execute(select(db.incidents.c.document)).scalar_one()
        assert stored == doc
        conn.execute(db.incidents.delete())
        left = conn.execute(
            select(func.count()).select_from(db.incident_connections)
        ).scalar_one()
    assert left == 0
