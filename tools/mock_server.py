#!/usr/bin/env python3
"""NEXUS mock server — lets every member develop against the API before Rakan's server exists.

- Implements the agent-facing endpoints of contracts/openapi.yaml with schema validation.
- Serves fixture incidents on the dashboard endpoints so Bashar can build the UI.
- Stores everything in memory (restart = clean slate). Optional --persist writes JSONL.

Run:  pip install fastapi uvicorn
      python tools/mock_server.py --port 8000 --token devtoken
Agents then use  NEXUS_SERVER_URL=http://127.0.0.1:8000/api/v1  NEXUS_TOKEN=devtoken
(plain HTTP is fine for the mock; the real server is HTTPS 8443.)
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from fastapi import Depends, FastAPI, Header, HTTPException, Request  # noqa: E402
from fastapi.responses import PlainTextResponse, StreamingResponse  # noqa: E402

from nexus_contracts import validate_against_schema  # noqa: E402

FIX = ROOT / "contracts" / "fixtures"
app = FastAPI(title="NEXUS mock server", version="1.0")
STATE = {"incidents": {}, "heartbeats": {}, "commands": {}, "results": {}, "events": asyncio.Queue()}
TOKEN = "devtoken"


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def auth(authorization: str = Header(default="")):
    if authorization != f"Bearer {TOKEN}":
        raise HTTPException(401, {"error": "unauthorized"})


def must_validate(schema: str, body: dict):
    errs = validate_against_schema(schema, body)
    if errs:
        raise HTTPException(400, {"error": "schema validation failed", "details": errs[:20]})


async def publish(evt: dict):
    await STATE["events"].put(evt)


@app.get("/api/v1/health")
def health():
    return {"status": "ok", "components": {"mock": "ok"}, "model_version": "none", "server_time_utc": now()}


@app.post("/api/v1/endpoints/{endpoint_id}/heartbeat", dependencies=[Depends(auth)])
async def heartbeat(endpoint_id: str, body: dict):
    must_validate("heartbeat", body)
    STATE["heartbeats"][endpoint_id] = {**body, "received_utc": now()}
    await publish({"type": "endpoint.heartbeat", "id": endpoint_id})
    return {"server_time_utc": now(), "ti_hashes_version": "mock-1", "config_hints": {}}


@app.post("/api/v1/incidents", dependencies=[Depends(auth)])
async def upsert_incident(body: dict):
    must_validate("incident", body)
    key = (body["endpoint_id"], body["incident_id"])
    cur = STATE["incidents"].get(key)
    if cur and cur["incident"]["incident_version"] >= body["incident_version"]:
        return {"status": "duplicate" if cur["incident"]["incident_version"] == body["incident_version"] else "stale",
                "incident_id": body["incident_id"], "incident_version": body["incident_version"]}
    STATE["incidents"][key] = {
        "incident": body,
        "server": {"received_at_utc": now(), "clock_offset_applied_ms": 0.0,
                   "correlations": [{"connection_id": c["connection_id"], "state": "pending", "updated_utc": now()} for c in body["connections"]],
                   "network_evidence": [], "enrichment": [], "response_history": [], "network_alert_ids": []},
    }
    await publish({"type": "incident.created" if not cur else "incident.updated", "id": body["incident_id"]})
    return {"status": "stored", "incident_id": body["incident_id"], "incident_version": body["incident_version"]}


@app.get("/api/v1/incidents", dependencies=[Depends(auth)])
def list_incidents(limit: int = 50, offset: int = 0):
    items = sorted(STATE["incidents"].values(), key=lambda v: v["incident"]["detected_at_utc"], reverse=True)
    out = []
    for v in items[offset:offset + limit]:
        inc = v["incident"]
        states = [c["state"] for c in v["server"]["correlations"]]
        out.append({k: inc.get(k) for k in ("incident_id", "incident_version", "endpoint_id", "os", "status", "severity", "confidence", "title", "detected_at_utc", "technique_ids")}
                   | {"correlation_summary": {s: states.count(s) for s in ("matched", "ambiguous", "pending", "unmatched")} | {"ml_suspicious": 0},
                      "local_response_status": inc["local_response"]["status"]})
    return {"items": out, "total": len(items)}


@app.get("/api/v1/incidents/{incident_id}", dependencies=[Depends(auth)])
def get_incident(incident_id: str):
    for (ep, iid), v in STATE["incidents"].items():
        if iid == incident_id:
            return v
    raise HTTPException(404, {"error": "not found"})


@app.get("/api/v1/endpoints/{endpoint_id}/commands", dependencies=[Depends(auth)])
def poll_commands(endpoint_id: str):
    out = []
    for c in STATE["commands"].values():
        if c.get("endpoint_id") == endpoint_id and c.get("status") == "queued":
            c["status"] = "delivered"
            out.append(c)
    return out


@app.post("/api/v1/commands/{command_id}/result", dependencies=[Depends(auth)])
async def command_result(command_id: str, body: dict):
    must_validate("response_result", body)
    STATE["results"][command_id] = body
    if command_id in STATE["commands"]:
        STATE["commands"][command_id]["status"] = "completed"
    await publish({"type": "response.updated", "id": command_id})
    return {"status": "recorded"}


@app.post("/api/v1/response/commands", dependencies=[Depends(auth)], status_code=201)
async def create_command(body: dict):
    must_validate("response_command", body)
    body["status"] = "queued" if body["target_kind"] == "endpoint" else "completed"
    STATE["commands"][body["command_id"]] = body
    await publish({"type": "response.updated", "id": body["command_id"]})
    return body


@app.get("/api/v1/response/commands", dependencies=[Depends(auth)])
def list_commands(limit: int = 100):
    return [{"command": c, "result": STATE["results"].get(cid)} for cid, c in list(STATE["commands"].items())[-limit:]]


@app.get("/api/v1/endpoints", dependencies=[Depends(auth)])
def endpoints():
    return [{"endpoint_id": k, "os": v["os"], "ip_addresses": v["ip_addresses"], "last_heartbeat_utc": v["received_utc"],
             "clock_offset_ms": v.get("clock_offset_ms"), "sensor_status": v["sensor_status"], "agent_version": v["agent_version"],
             "dry_run": v.get("dry_run")} for k, v in STATE["heartbeats"].items()]


@app.get("/api/v1/network/alerts", dependencies=[Depends(auth)])
def alerts():
    return []


@app.get("/api/v1/network/connections", dependencies=[Depends(auth)])
def connections():
    return [json.loads((FIX / "gateway_connection_example.json").read_text())]


@app.get("/api/v1/ti/hashes", dependencies=[Depends(auth)], response_class=PlainTextResponse)
def ti_hashes():
    # EICAR test file sha256 (public, harmless test string) so NX-ANY-001 can be demonstrated
    return "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f\n"


@app.get("/api/v1/stats", dependencies=[Depends(auth)])
def stats():
    return {"incidents": len(STATE["incidents"]), "endpoints": len(STATE["heartbeats"]), "commands": len(STATE["commands"])}


@app.get("/api/v1/stream", dependencies=[Depends(auth)])
async def stream(request: Request):
    async def gen():
        while not await request.is_disconnected():
            try:
                evt = await asyncio.wait_for(STATE["events"].get(), timeout=15)
                yield f"event: {evt['type']}\ndata: {json.dumps(evt)}\n\n"
            except asyncio.TimeoutError:
                yield ": keepalive\n\n"
    return StreamingResponse(gen(), media_type="text/event-stream")


def seed():
    view = json.loads((FIX / "server_incident_view_linux_l1.json").read_text())
    inc = view["incident"]
    STATE["incidents"][(inc["endpoint_id"], inc["incident_id"])] = view


if __name__ == "__main__":
    import uvicorn
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--token", default="devtoken")
    ap.add_argument("--no-seed", action="store_true", help="do not preload the fixture incident")
    a = ap.parse_args()
    TOKEN = a.token
    if not a.no_seed:
        seed()
    uvicorn.run(app, host="0.0.0.0", port=a.port)
