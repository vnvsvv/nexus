"""FastAPI app implementing contracts/openapi.yaml (process: nexus-api).

Roadmap: R3. Implemented so far (R3a): bearer auth, POST /incidents (upsert),
POST /endpoints/{endpoint_id}/heartbeat, GET /incidents/{incident_id}
(ServerIncidentView assembled from the tables).
TODO (R3b): GET /incidents list, commands, response, /endpoints, /network/*, /ti/hashes,
/stream (SSE), /stats, /export/correlations, /health.

Boundaries (see server/README.md, "Processes"):
- Runs with NO Linux capabilities. It never calls nft, conntrack or packet capture.
- Writes rows and sends a NOTIFY in the same transaction; the correlator, TI and
  response workers do the work. A lost NOTIFY is harmless: every worker also sweeps.
- Response requests: validates and authorizes them, stores them in response_commands,
  and returns. It never executes a gateway command itself.

Run: uvicorn --factory server.api:create_app (needs NEXUS_DB_URL, NEXUS_DASHBOARD_TOKEN).
Route handlers are plain `def`: FastAPI runs them in its I/O thread pool, which is only
used for the blocking database calls.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Annotated, Any

from fastapi import Body, Depends, FastAPI, Header, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import ValidationError
from sqlalchemy import Engine, func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert

from nexus_contracts import Heartbeat, Incident, validate_against_schema
from server import db
from server.config import Settings, load_settings

log = logging.getLogger("nexus.api")

PREFIX = "/api/v1"
NOTIFY_INCIDENT = "nexus_incident"
TI_HASHES_VERSION_NONE = "none"  # TODO (R7): real version of the /ti/hashes list


JsonBody = Annotated[Any, Body()]


class ApiError(Exception):
    def __init__(
        self, status: int, error: str, details: list[str] | None = None
    ) -> None:
        self.status = status
        self.error = error
        self.details = details or []


@dataclass(frozen=True)
class Principal:
    kind: str  # "endpoint" or "dashboard"
    endpoint_id: str | None = None


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _validate(schema: str, model: type, body: Any) -> Any:
    """JSON Schema first, then the Pydantic model. 400 with details on failure."""
    if not isinstance(body, dict):
        raise ApiError(
            400, "schema validation failed", ["<root>: body must be a JSON object"]
        )
    errors = validate_against_schema(schema, body)
    if errors:
        raise ApiError(400, "schema validation failed", errors[:20])
    try:
        return model.model_validate(body)
    except ValidationError as exc:
        details = [
            f"{'/'.join(str(p) for p in e['loc'])}: {e['msg']}" for e in exc.errors()
        ]
        raise ApiError(400, "model validation failed", details[:20]) from exc


def authenticate(
    request: Request, authorization: Annotated[str, Header()] = ""
) -> Principal:
    settings: Settings = request.app.state.settings
    engine: Engine = request.app.state.engine
    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise ApiError(401, "missing or invalid token")
    if settings.dashboard_token and hmac.compare_digest(
        token.encode("utf-8"), settings.dashboard_token.encode("utf-8")
    ):
        return Principal("dashboard")
    with engine.connect() as conn:
        endpoint_id = conn.execute(
            select(db.endpoints.c.endpoint_id).where(
                db.endpoints.c.token_hash == hash_token(token)
            )
        ).scalar_one_or_none()
    if endpoint_id is None:
        raise ApiError(401, "missing or invalid token")
    return Principal("endpoint", endpoint_id)


Auth = Annotated[Principal, Depends(authenticate)]


def create_app(
    engine: Engine | None = None, settings: Settings | None = None
) -> FastAPI:
    settings = settings or load_settings()
    engine = engine or db.get_engine(settings.db_url)
    app = FastAPI(title="NEXUS Server API", version="1.0")
    app.state.settings = settings
    app.state.engine = engine

    @app.exception_handler(ApiError)
    def _api_error(_: Request, exc: ApiError) -> JSONResponse:
        body: dict[str, Any] = {"error": exc.error}
        if exc.details:
            body["details"] = exc.details
        return JSONResponse(status_code=exc.status, content=body)

    @app.exception_handler(RequestValidationError)
    def _bad_request(_: Request, exc: RequestValidationError) -> JSONResponse:
        details = [
            f"{'/'.join(str(p) for p in e['loc'])}: {e['msg']}" for e in exc.errors()
        ]
        return JSONResponse(
            status_code=400, content={"error": "bad request", "details": details[:20]}
        )

    def require_endpoint(principal: Principal, endpoint_id: str) -> None:
        if principal.kind != "endpoint" or principal.endpoint_id != endpoint_id:
            raise ApiError(401, "token is not valid for this endpoint")

    def require_dashboard(principal: Principal) -> None:
        if principal.kind != "dashboard":
            raise ApiError(401, "dashboard token required")

    @app.post(f"{PREFIX}/incidents")
    def upsert_incident(body: JsonBody, principal: Auth) -> dict[str, Any]:
        inc: Incident = _validate("incident", Incident, body)
        require_endpoint(principal, inc.endpoint_id)
        if not inc.incident_id.startswith(f"{inc.endpoint_id}:"):
            raise ApiError(
                400,
                "schema validation failed",
                ["incident_id: must start with '<endpoint_id>:'"],
            )
        status = _store_incident(engine, body, inc)
        log.info(
            "incident upsert",
            extra={
                "fields": {
                    "incident_id": inc.incident_id,
                    "incident_version": inc.incident_version,
                    "status": status,
                }
            },
        )
        return {
            "status": status,
            "incident_id": inc.incident_id,
            "incident_version": inc.incident_version,
        }

    @app.post(f"{PREFIX}/endpoints/{{endpoint_id}}/heartbeat")
    def heartbeat(
        endpoint_id: str,
        body: JsonBody,
        principal: Auth,
    ) -> dict[str, Any]:
        hb: Heartbeat = _validate("heartbeat", Heartbeat, body)
        require_endpoint(principal, endpoint_id)
        if hb.endpoint_id != endpoint_id:
            raise ApiError(
                400, "schema validation failed", ["endpoint_id: does not match the URL"]
            )
        now = _now()
        with engine.begin() as conn:
            conn.execute(
                db.endpoints.update()
                .where(db.endpoints.c.endpoint_id == endpoint_id)
                .values(
                    os=hb.os,
                    ip_addresses=hb.ip_addresses,
                    last_heartbeat_utc=now,
                    clock_offset_ms=hb.clock_offset_ms,
                    agent_version=hb.agent_version,
                    sensor_status=hb.sensor_status,
                    dry_run=hb.dry_run,
                )
            )
        # TODO (R3b): emit SSE endpoint.heartbeat
        return {
            "server_time_utc": db.iso_utc(now),
            "ti_hashes_version": TI_HASHES_VERSION_NONE,
            "config_hints": {},
        }

    @app.get(f"{PREFIX}/incidents/{{incident_id}}")
    def get_incident(incident_id: str, principal: Auth) -> JSONResponse:
        require_dashboard(principal)
        with engine.connect() as conn:
            view = assemble_view(conn, incident_id)
        if view is None:
            raise ApiError(404, "incident not found")
        return JSONResponse(content=view)

    return app


def _store_incident(engine: Engine, document: dict[str, Any], inc: Incident) -> str:
    """Upsert one incident. Returns 'stored', 'duplicate' or 'stale'.

    One INSERT ... ON CONFLICT DO UPDATE WHERE stored_version < new_version, so two
    concurrent posts of the same incident cannot both win.
    """
    t = db.incidents
    stmt = pg_insert(t).values(
        endpoint_id=inc.endpoint_id,
        incident_id=inc.incident_id,
        incident_version=inc.incident_version,
        document=document,
        status=inc.status,
        severity=inc.severity,
        detected_at_utc=db.parse_utc(inc.detected_at_utc),
        received_at_utc=_now(),
    )
    ex = stmt.excluded
    stmt = stmt.on_conflict_do_update(
        index_elements=[t.c.endpoint_id, t.c.incident_id],
        set_={
            "incident_version": ex.incident_version,
            "document": ex.document,
            "status": ex.status,
            "severity": ex.severity,
            "detected_at_utc": ex.detected_at_utc,
            "received_at_utc": ex.received_at_utc,
        },
        where=t.c.incident_version < ex.incident_version,
    ).returning(t.c.incident_version)

    key = (t.c.endpoint_id == inc.endpoint_id) & (t.c.incident_id == inc.incident_id)
    with engine.begin() as conn:
        if conn.execute(stmt).first() is None:
            current = conn.execute(select(t.c.incident_version).where(key)).scalar_one()
            return "duplicate" if current == inc.incident_version else "stale"
        ic = db.incident_connections
        conn.execute(
            ic.delete().where(
                (ic.c.endpoint_id == inc.endpoint_id)
                & (ic.c.incident_id == inc.incident_id)
            )
        )
        if inc.connections:
            conn.execute(
                ic.insert(),
                [
                    {
                        "endpoint_id": inc.endpoint_id,
                        "incident_id": inc.incident_id,
                        "connection_id": c.connection_id,
                        "protocol": c.protocol,
                        "src_ip": c.src_ip,
                        "src_port": c.src_port,
                        "dst_ip": c.dst_ip,
                        "dst_port": c.dst_port,
                        "direction": c.direction,
                        "first_seen_utc": db.parse_utc(c.first_seen_utc),
                    }
                    for c in inc.connections
                ],
            )
        payload = json.dumps(
            {
                "endpoint_id": inc.endpoint_id,
                "incident_id": inc.incident_id,
                "incident_version": inc.incident_version,
            }
        )
        conn.execute(select(func.pg_notify(NOTIFY_INCIDENT, payload)))
    # TODO (R3b): emit SSE incident.created / incident.updated
    return "stored"


def _clean(d: dict[str, Any]) -> dict[str, Any]:
    """exclude_none for rows read back from the database."""
    return {k: v for k, v in d.items() if v is not None}


def _ip(v: Any) -> str | None:
    return str(v) if v is not None else None


def _ts(v: datetime | None) -> str | None:
    return db.iso_utc(v) if v is not None else None


def _gateway_connection(row: Any, flow_ids: list[str]) -> dict[str, Any]:
    return _clean(
        {
            "gateway_connection_id": row.gateway_connection_id,
            "protocol": row.protocol,
            "orig_src_ip": _ip(row.orig_src_ip),
            "orig_src_port": row.orig_src_port,
            "orig_dst_ip": _ip(row.orig_dst_ip),
            "orig_dst_port": row.orig_dst_port,
            "first_seen_utc": _ts(row.first_seen_utc),
            "last_seen_utc": _ts(row.last_seen_utc),
            "ingress_interface": row.ingress_interface,
            "src_endpoint_id": row.src_endpoint_id,
            "dst_endpoint_id": row.dst_endpoint_id,
            "packets_orig": row.packets_orig,
            "bytes_orig": row.bytes_orig,
            "packets_reply": row.packets_reply,
            "bytes_reply": row.bytes_reply,
            "state": row.state,
            "scope": row.scope,
            "flow_ids": flow_ids,
        }
    )


def _flow(row: Any) -> dict[str, Any]:
    out = _clean(
        {
            "flow_id": row.flow_id,
            "gateway_connection_id": row.gateway_connection_id,
            "duplicate_of": row.duplicate_of,
            "capture_interface": row.capture_interface,
            "protocol": row.protocol,
            "src_ip": _ip(row.src_ip),
            "src_port": row.src_port,
            "dst_ip": _ip(row.dst_ip),
            "dst_port": row.dst_port,
            "first_seen_utc": _ts(row.first_seen_utc),
            "last_seen_utc": _ts(row.last_seen_utc),
            "application_name": row.application_name,
            "feature_version": row.feature_version,
            "features": row.features,
            "scope": row.scope,
        }
    )
    if row.ml_label is not None:
        out["ml"] = _clean(
            {
                "label": row.ml_label,
                "score": row.ml_score,
                "threshold": row.ml_threshold,
                "model_version": row.model_version,
                "feature_version": row.feature_version,
                "predicted_at_utc": _ts(row.ml_predicted_utc),
            }
        )
    return out


def assemble_view(conn: Any, incident_id: str) -> dict[str, Any] | None:
    """Build the ServerIncidentView: the stored document verbatim plus the server block."""
    inc = conn.execute(
        select(db.incidents).where(db.incidents.c.incident_id == incident_id)
    ).first()
    if inc is None:
        return None

    ic = db.incident_correlations
    corr_rows = conn.execute(
        select(ic)
        .where(
            (ic.c.endpoint_id == inc.endpoint_id)
            & (ic.c.incident_id == inc.incident_id)
            & (ic.c.incident_version == inc.incident_version)
        )
        .order_by(ic.c.id)
    ).all()
    correlations = [
        _clean(
            {
                "connection_id": r.connection_id,
                "state": r.state,
                "gateway_connection_id": r.gateway_connection_id,
                "score": r.score,
                "candidates": r.candidates if r.candidates is not None else [],
                "basis": r.basis,
                "note": r.note,
                "updated_utc": _ts(r.updated_utc),
            }
        )
        for r in corr_rows
    ]
    offsets = [
        r.clock_offset_applied_ms
        for r in corr_rows
        if r.clock_offset_applied_ms is not None
    ]

    network_evidence = []
    matched_ids = list(
        dict.fromkeys(
            r.gateway_connection_id
            for r in corr_rows
            if r.state == "matched" and r.gateway_connection_id
        )
    )
    for gw_id in matched_ids:
        gw = conn.execute(
            select(db.gateway_connections).where(
                db.gateway_connections.c.gateway_connection_id == gw_id
            )
        ).first()
        if gw is None:
            continue
        flows = conn.execute(
            select(db.gateway_flows)
            .where(db.gateway_flows.c.gateway_connection_id == gw_id)
            .order_by(db.gateway_flows.c.first_seen_utc, db.gateway_flows.c.flow_id)
        ).all()
        network_evidence.append(
            {
                "gateway_connection": _gateway_connection(
                    gw, [f.flow_id for f in flows]
                ),
                "flows": [_flow(f) for f in flows],
            }
        )

    rc, rr = db.response_commands, db.response_results
    history = []
    for r in conn.execute(
        select(
            rc,
            rr.c.executed_utc,
            rr.c.status.label("result_status"),
            rr.c.detail,
            rr.c.executor,
        )
        .outerjoin(rr, rr.c.command_id == rc.c.command_id)
        .where(rc.c.incident_id == incident_id)
        .order_by(rc.c.created_utc, rc.c.command_id)
    ).all():
        command = _clean(
            {
                "command_id": r.command_id,
                "target_kind": r.target_kind,
                "endpoint_id": r.endpoint_id,
                "incident_id": r.incident_id,
                "action": r.action,
                "params": r.params,
                "requested_by": r.requested_by,
                "created_utc": _ts(r.created_utc),
                "dry_run": r.dry_run,
                "status": r.status,
            }
        )
        result = None
        if r.executor is not None:
            result = {
                "command_id": r.command_id,
                "executed_utc": _ts(r.executed_utc),
                "status": r.result_status,
                "executor": r.executor,
                "detail": r.detail or {},
            }
        history.append({"command": command, "result": result})

    alert_ids = list(
        conn.execute(
            select(db.network_alerts.c.alert_id)
            .where(db.network_alerts.c.incident_id == incident_id)
            .order_by(db.network_alerts.c.alert_id)
        ).scalars()
    )

    server: dict[str, Any] = {"received_at_utc": _ts(inc.received_at_utc)}
    if offsets:
        server["clock_offset_applied_ms"] = offsets[0]
    server.update(
        {
            "correlations": correlations,
            "network_evidence": network_evidence,
            "enrichment": [],  # TODO (R7): no section 6 table links enrichment to an incident yet
            "response_history": history,
            "network_alert_ids": alert_ids,
        }
    )
    return {"incident": inc.document, "server": server}
