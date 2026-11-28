"""Tests for server/api.py (R3a): incident upsert, heartbeat, incident view."""

from __future__ import annotations

import copy
import json
from typing import Any

import pytest
from conftest import load_fixture, requires_db
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select, update

from nexus_contracts import ServerIncidentView, validate_against_schema
from server import db
from server.api import NOTIFY_INCIDENT, create_app, hash_token
from server.config import Settings

DASH = "dashtoken"
LIN_TOKEN = "linux-token"
WIN_TOKEN = "windows-token"
INC = "/api/v1/incidents"


def _client(engine) -> TestClient:
    return TestClient(
        create_app(engine, Settings(db_url="unused", dashboard_token=DASH))
    )


def _h(token: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def _incident(version: int = 1) -> dict[str, Any]:
    doc = load_fixture("incident_linux_l1.json")
    doc["incident_version"] = version
    return doc


@pytest.fixture()
def client(engine) -> TestClient:
    with engine.begin() as conn:
        conn.execute(
            db.endpoints.insert(),
            [
                {
                    "endpoint_id": "linux-vm-01",
                    "os": "linux",
                    "token_hash": hash_token(LIN_TOKEN),
                },
                {
                    "endpoint_id": "windows-vm-01",
                    "os": "windows",
                    "token_hash": hash_token(WIN_TOKEN),
                },
            ],
        )
    return _client(engine)


# ---------- no database needed ----------
def test_missing_token_is_401_with_error_shape() -> None:
    c = _client(create_engine("postgresql+psycopg://nobody@127.0.0.1:1/never_used"))
    r = c.post(INC, json=_incident())
    assert r.status_code == 401
    assert set(r.json()) == {"error"}


def test_invalid_json_is_400_with_error_shape() -> None:
    c = _client(create_engine("postgresql+psycopg://nobody@127.0.0.1:1/never_used"))
    r = c.post(
        INC,
        content=b"{not json",
        headers={**_h(DASH), "Content-Type": "application/json"},
    )
    assert r.status_code == 400
    assert r.json()["error"] and r.json()["details"]


# ---------- POST /incidents ----------
@requires_db
def test_upsert_stored_duplicate_stale(client, engine) -> None:
    r = client.post(INC, json=_incident(1), headers=_h(LIN_TOKEN))
    assert r.status_code == 200
    assert r.json() == {
        "status": "stored",
        "incident_id": _incident()["incident_id"],
        "incident_version": 1,
    }
    assert (
        client.post(INC, json=_incident(1), headers=_h(LIN_TOKEN)).json()["status"]
        == "duplicate"
    )

    v2 = _incident(2)
    v2["connections"][0]["dst_port"] = 9443
    assert client.post(INC, json=v2, headers=_h(LIN_TOKEN)).json()["status"] == "stored"
    assert client.post(INC, json=_incident(1), headers=_h(LIN_TOKEN)).json() == {
        "status": "stale",
        "incident_id": v2["incident_id"],
        "incident_version": 1,
    }
    with engine.connect() as conn:
        row = conn.execute(select(db.incidents)).one()
        conns = conn.execute(select(db.incident_connections)).all()
    assert row.incident_version == 2 and row.document == v2
    assert [(c.connection_id, c.dst_port, str(c.src_ip)) for c in conns] == [
        ("conn-000123", 9443, "192.168.10.10")
    ]


@requires_db
def test_upsert_sends_notify(client, engine) -> None:
    raw = engine.raw_connection()
    try:
        pg = raw.driver_connection
        pg.autocommit = True
        pg.execute(f"LISTEN {NOTIFY_INCIDENT}")
        assert (
            client.post(INC, json=_incident(1), headers=_h(LIN_TOKEN)).json()["status"]
            == "stored"
        )
        notes = list(pg.notifies(timeout=2, stop_after=1))
    finally:
        raw.close()
    assert len(notes) == 1
    assert json.loads(notes[0].payload) == {
        "endpoint_id": "linux-vm-01",
        "incident_id": _incident()["incident_id"],
        "incident_version": 1,
    }


@requires_db
def test_schema_violation_is_400(client) -> None:
    bad = _incident()
    del bad["rule_matches"]
    r = client.post(INC, json=bad, headers=_h(LIN_TOKEN))
    assert r.status_code == 400
    assert r.json()["error"] == "schema validation failed"
    assert any("rule_matches" in d for d in r.json()["details"])


@requires_db
def test_incident_id_must_carry_endpoint_prefix(client) -> None:
    bad = _incident()
    bad["incident_id"] = "windows-vm-01:INC-20261115T103007-0001"
    r = client.post(INC, json=bad, headers=_h(LIN_TOKEN))
    assert r.status_code == 400


@requires_db
@pytest.mark.parametrize("token", [WIN_TOKEN, DASH, "not-a-token"])
def test_wrong_token_is_401(client, token: str) -> None:
    r = client.post(INC, json=_incident(), headers=_h(token))
    assert r.status_code == 401
    assert "error" in r.json()


# ---------- POST /endpoints/{id}/heartbeat ----------
@requires_db
def test_heartbeat_updates_endpoint(client, engine) -> None:
    hb = load_fixture("heartbeat_example.json")
    r = client.post(
        "/api/v1/endpoints/linux-vm-01/heartbeat", json=hb, headers=_h(LIN_TOKEN)
    )
    assert r.status_code == 200
    body = r.json()
    assert {"server_time_utc", "ti_hashes_version"} <= set(body)
    assert body["server_time_utc"] == db.iso_utc(db.parse_utc(body["server_time_utc"]))
    with engine.connect() as conn:
        row = conn.execute(
            select(db.endpoints).where(db.endpoints.c.endpoint_id == "linux-vm-01")
        ).one()
    assert row.ip_addresses == hb["ip_addresses"]
    assert row.clock_offset_ms == hb["clock_offset_ms"]
    assert (
        row.sensor_status == "ok"
        and row.dry_run is True
        and row.agent_version == "0.1.0"
    )
    assert row.last_heartbeat_utc is not None


@requires_db
def test_heartbeat_rejects_other_endpoint(client) -> None:
    hb = load_fixture("heartbeat_example.json")
    assert (
        client.post(
            "/api/v1/endpoints/linux-vm-01/heartbeat", json=hb, headers=_h(WIN_TOKEN)
        ).status_code
        == 401
    )
    assert (
        client.post(
            "/api/v1/endpoints/windows-vm-01/heartbeat", json=hb, headers=_h(WIN_TOKEN)
        ).status_code
        == 400
    )
    bad = {k: v for k, v in hb.items() if k != "sensor_status"}
    assert (
        client.post(
            "/api/v1/endpoints/linux-vm-01/heartbeat", json=bad, headers=_h(LIN_TOKEN)
        ).status_code
        == 400
    )


# ---------- GET /incidents/{id} ----------
@requires_db
def test_get_incident_404_and_dashboard_only(client) -> None:
    iid = _incident()["incident_id"]
    assert client.get(f"{INC}/{iid}", headers=_h(DASH)).status_code == 404
    client.post(INC, json=_incident(), headers=_h(LIN_TOKEN))
    assert client.get(f"{INC}/{iid}", headers=_h(LIN_TOKEN)).status_code == 401


@requires_db
def test_view_before_correlation(client) -> None:
    doc = _incident()
    client.post(INC, json=doc, headers=_h(LIN_TOKEN))
    view = client.get(f"{INC}/{doc['incident_id']}", headers=_h(DASH)).json()
    assert validate_against_schema("server_incident_view", view) == []
    assert view["incident"] == doc
    assert (
        view["server"]["correlations"] == []
        and view["server"]["network_evidence"] == []
    )


def _seed_from_view_fixture(engine, fx: dict) -> None:
    s = fx["server"]
    inc = fx["incident"]
    with engine.begin() as conn:
        conn.execute(
            update(db.incidents)
            .where(db.incidents.c.incident_id == inc["incident_id"])
            .values(received_at_utc=db.parse_utc(s["received_at_utc"]))
        )
        for ev in s["network_evidence"]:
            gw = {k: v for k, v in ev["gateway_connection"].items() if k != "flow_ids"}
            for k in ("first_seen_utc", "last_seen_utc"):
                gw[k] = db.parse_utc(gw[k])
            conn.execute(db.gateway_connections.insert().values(**gw))
            for f in ev["flows"]:
                row = {k: v for k, v in f.items() if k != "ml"}
                for k in ("first_seen_utc", "last_seen_utc"):
                    row[k] = db.parse_utc(row[k])
                ml = f["ml"]
                row.update(
                    ml_label=ml["label"],
                    ml_score=ml["score"],
                    ml_threshold=ml["threshold"],
                    model_version=ml["model_version"],
                    ml_predicted_utc=db.parse_utc(ml["predicted_at_utc"]),
                )
                conn.execute(db.gateway_flows.insert().values(**row))
        for c in s["correlations"]:
            conn.execute(
                db.incident_correlations.insert().values(
                    endpoint_id=inc["endpoint_id"],
                    incident_id=inc["incident_id"],
                    incident_version=inc["incident_version"],
                    connection_id=c["connection_id"],
                    gateway_connection_id=c["gateway_connection_id"],
                    state=c["state"],
                    score=c["score"],
                    candidates=c["candidates"],
                    basis=c["basis"],
                    clock_offset_applied_ms=s["clock_offset_applied_ms"],
                    updated_utc=db.parse_utc(c["updated_utc"]),
                )
            )


@requires_db
def test_view_matches_fixture(client, engine) -> None:
    fx = load_fixture("server_incident_view_linux_l1.json")
    assert (
        client.post(INC, json=fx["incident"], headers=_h(LIN_TOKEN)).json()["status"]
        == "stored"
    )
    _seed_from_view_fixture(engine, fx)

    view = client.get(f"{INC}/{fx['incident']['incident_id']}", headers=_h(DASH)).json()
    assert validate_against_schema("server_incident_view", view) == []
    ServerIncidentView.model_validate(view)

    expected = copy.deepcopy(fx)
    expected["server"]["enrichment"] = []  # TODO (R7): enrichment storage
    assert view == expected


@requires_db
def test_view_response_history_and_alerts(client, engine) -> None:
    doc = _incident()
    client.post(INC, json=doc, headers=_h(LIN_TOKEN))
    cmd = load_fixture("response_command_example.json")
    res = load_fixture("response_result_example.json")
    with engine.begin() as conn:
        conn.execute(
            db.response_commands.insert().values(
                **{**cmd, "created_utc": db.parse_utc(cmd["created_utc"])}
            )
        )
        conn.execute(
            db.response_results.insert().values(
                **{**res, "executed_utc": db.parse_utc(res["executed_utc"])}
            )
        )
        conn.execute(
            db.network_alerts.insert().values(
                alert_id="alert-0001", incident_id=doc["incident_id"]
            )
        )
    view = client.get(f"{INC}/{doc['incident_id']}", headers=_h(DASH)).json()
    assert validate_against_schema("server_incident_view", view) == []
    assert view["server"]["response_history"] == [{"command": cmd, "result": res}]
    assert view["server"]["network_alert_ids"] == ["alert-0001"]
