"""PostgreSQL schema with SQLAlchemy Core (no ORM).

The 11 tables of docs/02-CORRELATION.md section 6, plus the server-only columns needed
by the contract models (marked "ADD" below), the two composite indexes on
gateway_connections, get_engine() and create_all().
"""

from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    Column,
    Engine,
    Float,
    ForeignKey,
    ForeignKeyConstraint,
    Identity,
    Index,
    Integer,
    MetaData,
    Table,
    Text,
    UniqueConstraint,
    create_engine,
    text,
)
from sqlalchemy.dialects.postgresql import ARRAY, INET, JSONB, TIMESTAMP

metadata = MetaData()

TS = TIMESTAMP(timezone=True)

endpoints = Table(
    "endpoints",
    metadata,
    Column("endpoint_id", Text, primary_key=True),
    Column("os", Text),
    Column("ip_addresses", ARRAY(Text)),
    Column("token_hash", Text),
    Column("last_heartbeat_utc", TS),
    Column("clock_offset_ms", Float),
    Column("agent_version", Text),
    Column("sensor_status", Text, nullable=True),  # ADD: EndpointStatus / Heartbeat
    Column("dry_run", Boolean, nullable=True),  # ADD: EndpointStatus / Heartbeat
)

incidents = Table(
    "incidents",
    metadata,
    Column("endpoint_id", Text, primary_key=True),
    Column("incident_id", Text, primary_key=True),
    Column("incident_version", Integer, nullable=False),
    Column("document", JSONB, nullable=False),  # the endpoint document, verbatim
    Column("status", Text),
    Column("severity", Text),
    Column("detected_at_utc", TS),
    Column("received_at_utc", TS),
)

incident_connections = Table(
    "incident_connections",
    metadata,
    Column("id", BigInteger, Identity(), primary_key=True),
    Column("endpoint_id", Text, nullable=False),
    Column("incident_id", Text, nullable=False),
    Column("connection_id", Text, nullable=False),
    Column("protocol", Text),
    Column("src_ip", INET),
    Column("src_port", Integer),
    Column("dst_ip", INET),
    Column("dst_port", Integer),
    Column("direction", Text),
    Column("first_seen_utc", TS),
    ForeignKeyConstraint(
        ["endpoint_id", "incident_id"],
        ["incidents.endpoint_id", "incidents.incident_id"],
        ondelete="CASCADE",
    ),
    UniqueConstraint("endpoint_id", "incident_id", "connection_id", name="uq_incconn"),
)

gateway_connections = Table(
    "gateway_connections",
    metadata,
    Column("gateway_connection_id", Text, primary_key=True),
    Column("protocol", Text),
    Column("orig_src_ip", INET),
    Column("orig_src_port", Integer),
    Column("orig_dst_ip", INET),
    Column("orig_dst_port", Integer),
    Column("first_seen_utc", TS, nullable=False),
    Column("last_seen_utc", TS),
    Column("ingress_interface", Text),
    Column("src_endpoint_id", Text),
    Column("dst_endpoint_id", Text),
    Column("packets_orig", BigInteger),
    Column("bytes_orig", BigInteger),
    Column("packets_reply", BigInteger),
    Column("bytes_reply", BigInteger),
    Column("state", Text, nullable=False),
    Column(
        "scope", Text, nullable=False, server_default="routed"
    ),  # ADD: GatewayConnection
    Index(
        "ix_gwconn_fwd",
        "protocol",
        "orig_src_ip",
        "orig_src_port",
        "orig_dst_ip",
        "orig_dst_port",
        "first_seen_utc",
    ),
    Index(
        "ix_gwconn_rev",
        "protocol",
        "orig_dst_ip",
        "orig_dst_port",
        "orig_src_ip",
        "orig_src_port",
        "first_seen_utc",
    ),
)

gateway_flows = Table(
    "gateway_flows",
    metadata,
    Column("flow_id", Text, primary_key=True),
    Column(
        "gateway_connection_id",
        Text,
        ForeignKey("gateway_connections.gateway_connection_id"),
        nullable=True,
    ),
    Column("capture_interface", Text),
    Column("duplicate_of", Text, ForeignKey("gateway_flows.flow_id"), nullable=True),
    Column("protocol", Integer),
    Column("src_ip", INET),
    Column("src_port", Integer),
    Column("dst_ip", INET),
    Column("dst_port", Integer),
    Column("first_seen_utc", TS),
    Column("last_seen_utc", TS),
    Column("features", JSONB),
    Column("feature_version", Text),
    Column("ml_label", Text),
    Column("ml_score", Float),
    Column(
        "ml_threshold", Float, nullable=True
    ),  # ADD: MLPrediction.threshold (required)
    Column(
        "ml_predicted_utc", TS, nullable=True
    ),  # ADD: MLPrediction.predicted_at_utc (required)
    Column("model_version", Text),
    Column("application_name", Text),
    Column("scope", Text, nullable=False, server_default="routed"),  # ADD: FlowRecord
)

incident_correlations = Table(
    "incident_correlations",
    metadata,
    Column("id", BigInteger, Identity(), primary_key=True),
    Column("endpoint_id", Text, nullable=False),
    Column("incident_id", Text, nullable=False),
    Column("incident_version", Integer, nullable=False),
    Column("connection_id", Text, nullable=False),
    Column(
        "gateway_connection_id",
        Text,
        ForeignKey("gateway_connections.gateway_connection_id"),
        nullable=True,
    ),
    Column("state", Text, nullable=False),
    Column("score", Float),
    Column("candidates", JSONB),
    Column("clock_offset_applied_ms", Float),
    Column(
        "updated_utc", TS
    ),  # section 5.3 says matched_at; section 6 and the contract say updated_utc
    Column("basis", Text, nullable=True),  # ADD: Correlation
    Column("note", Text, nullable=True),  # ADD: Correlation (analyst pin)
    ForeignKeyConstraint(
        ["endpoint_id", "incident_id"],
        ["incidents.endpoint_id", "incidents.incident_id"],
        ondelete="CASCADE",
    ),
    CheckConstraint(
        "state IN ('matched','ambiguous','pending','unmatched')",
        name="ck_inccorr_state",
    ),
    Index("ix_inccorr_state", "state"),
)

network_alerts = Table(
    "network_alerts",
    metadata,
    Column("alert_id", Text, primary_key=True),
    Column("flow_id", Text, ForeignKey("gateway_flows.flow_id")),
    Column("gateway_connection_id", Text),
    Column("ml_label", Text),
    Column("ml_score", Float),
    Column("created_utc", TS),
    Column("incident_id", Text, nullable=True),
)

ti_indicators = Table(
    "ti_indicators",
    metadata,
    Column("type", Text, primary_key=True),
    Column("value", Text, primary_key=True),
    Column("source", Text),
    Column("first_seen", TS),
    Column("tags", ARRAY(Text)),
    Column("raw", JSONB),
)

ti_lookups = Table(
    "ti_lookups",
    metadata,
    Column("id", BigInteger, Identity(), primary_key=True),
    Column("indicator_type", Text),
    Column("value", Text),
    Column("provider", Text),
    Column("result", JSONB),
    Column("fetched_utc", TS),
)

response_commands = Table(
    "response_commands",
    metadata,
    Column("command_id", Text, primary_key=True),
    Column("target_kind", Text),
    Column("endpoint_id", Text, nullable=True),
    Column("action", Text),
    Column("params", JSONB),
    Column("requested_by", Text),
    Column("created_utc", TS),
    Column("status", Text),
    Column("dry_run", Boolean, nullable=False, server_default=text("true")),
    Column("incident_id", Text, nullable=True),  # ADD: ResponseCommand
)

response_results = Table(
    "response_results",
    metadata,
    Column(
        "command_id", Text, ForeignKey("response_commands.command_id"), primary_key=True
    ),
    Column("executed_utc", TS),
    Column("status", Text),
    Column("detail", JSONB),
    Column("executor", Text, nullable=False),  # ADD: response_result.schema.json
)


def get_engine(url: str | None = None) -> Engine:
    """Engine for `url`, or for NEXUS_DB_URL when url is None."""
    if url is None:
        from server.config import load_settings

        url = load_settings().db_url
    return create_engine(url, pool_pre_ping=True)


def create_all(engine: Engine) -> None:
    """Create missing tables and indexes. Safe to run repeatedly."""
    metadata.create_all(engine, checkfirst=True)


def parse_utc(value: str) -> datetime:
    """Contract timestamp (ISO-8601, trailing Z) -> aware datetime."""
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def iso_utc(value: datetime) -> str:
    """Aware datetime -> contract timestamp: UTC, milliseconds, trailing Z."""
    v = value.astimezone(timezone.utc)
    return v.strftime("%Y-%m-%dT%H:%M:%S.") + f"{v.microsecond // 1000:03d}Z"
