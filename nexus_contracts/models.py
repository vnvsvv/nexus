from __future__ import annotations

import secrets
from datetime import datetime, timezone
from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

SCHEMA_VERSION = "1.0"
FEATURE_VERSION = "nf-lite-1"

OS = Literal["linux", "windows"]
EventType = Literal["process_start", "process_exit", "file_access", "network_connect", "dns_query"]
Severity = Literal["low", "medium", "high", "critical"]
Confidence = Literal["low", "medium", "high"]
Basis = Literal["observed", "inferred"]
Direction = Literal["outbound", "inbound"]
Proto = Literal["TCP", "UDP"]


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def new_event_id(endpoint_id: str) -> str:
    return f"{endpoint_id}:evt-{secrets.token_hex(8)}"


def new_incident_id(endpoint_id: str) -> str:
    return f"{endpoint_id}:INC-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')}-{secrets.token_hex(3)}"


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)


# ---------- HostEvent ----------
class FileInfo(_Strict):
    path: str
    operation: Literal["read", "write", "create", "delete", "rename", "execute"]
    new_path: Optional[str] = None


class NetworkInfo(_Strict):
    protocol: Proto
    src_ip: str
    src_port: int = Field(ge=0, le=65535)
    dst_ip: str
    dst_port: int = Field(ge=0, le=65535)
    direction: Direction


class DnsInfo(_Strict):
    query: str
    answers: list[str] = Field(default_factory=list)


class ExitInfo(_Strict):
    exit_code: Optional[int] = None
    signal: Optional[int] = None


class HostEvent(_Strict):
    schema_version: Literal["1.0"] = SCHEMA_VERSION
    event_id: str
    endpoint_id: str
    os: OS
    timestamp_utc: str
    event_type: EventType
    process_instance_id: str
    parent_process_instance_id: Optional[str] = None
    pid: int = Field(ge=0)
    ppid: Optional[int] = None
    binary: str
    command_line: Optional[str] = None
    user: Optional[str] = None
    sha256: Optional[str] = None
    process_start_time_utc: Optional[str] = None
    file: Optional[FileInfo] = None
    network: Optional[NetworkInfo] = None
    dns: Optional[DnsInfo] = None
    exit: Optional[ExitInfo] = None
    attributes: dict[str, Any] = Field(default_factory=dict)

    @field_validator("sha256")
    @classmethod
    def _sha(cls, v):
        if v is not None and (len(v) != 64 or any(c not in "0123456789abcdef" for c in v)):
            raise ValueError("sha256 must be 64 lowercase hex chars")
        return v

    def model_post_init(self, __context: Any) -> None:
        need = {"file_access": "file", "network_connect": "network", "dns_query": "dns"}.get(self.event_type)
        if need and getattr(self, need) is None:
            raise ValueError(f"{self.event_type} requires '{need}'")


# ---------- Incident ----------
class HostConnection(_Strict):
    connection_id: str
    process_instance_id: str
    protocol: Proto
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    direction: Direction
    first_seen_utc: str
    last_seen_utc: Optional[str] = None
    evidence_event_ids: list[str] = Field(min_length=1)


class ProcessNode(_Strict):
    process_instance_id: str
    parent_process_instance_id: Optional[str] = None
    pid: int
    binary: str
    command_line: Optional[str] = None
    user: Optional[str] = None
    sha256: Optional[str] = None
    start_time_utc: Optional[str] = None
    end_time_utc: Optional[str] = None
    placeholder: bool = False
    role: Optional[Literal["root", "matched", "context"]] = None


class Relationship(_Strict):
    type: Literal["PARENT_OF", "ACCESSED_FILE", "CONNECTED_TO", "RESOLVED"]
    from_: str = Field(alias="from")
    to: str
    basis: Basis
    evidence_event_ids: list[str]
    note: Optional[str] = None

    model_config = ConfigDict(extra="forbid", populate_by_name=True, serialize_by_alias=True)


class EvidenceItem(_Strict):
    event_id: str
    role: Literal["matched", "context"]
    event: HostEvent


class Gap(_Strict):
    code: Literal["PARENT_NOT_OBSERVED", "FILE_READ_NOT_OBSERVABLE_ON_WINDOWS", "EVIDENCE_TRUNCATED",
                  "PROCESS_SET_TRUNCATED", "IDENTITY_INFERRED", "SENSOR_EVENT_LOSS", "NO_GATEWAY_RECORD", "OTHER"]
    message: str
    related: list[str] = Field(default_factory=list)


class RuleMatch(_Strict):
    rule_id: str
    rule_version: Optional[str] = None
    matched_at_utc: str
    bindings: dict[str, str]


class LocalResponse(_Strict):
    action: Literal["none", "terminate_process"] = "none"
    status: Literal["not_requested", "dry_run", "executed", "denied", "failed"] = "not_requested"
    target_process_instance_id: Optional[str] = None
    command_id: Optional[str] = None
    detail: Optional[str] = None


class Incident(_Strict):
    schema_version: Literal["1.0"] = SCHEMA_VERSION
    incident_id: str
    incident_version: int = Field(ge=1)
    endpoint_id: str
    os: OS
    status: Literal["open", "closed"]
    detected_at_utc: str
    updated_at_utc: str
    severity: Severity
    confidence: Confidence
    title: Optional[str] = None
    rule_matches: list[RuleMatch] = Field(min_length=1)
    technique_ids: list[str]
    root_process_instance_id: str
    process_nodes: list[ProcessNode] = Field(min_length=1, max_length=50)
    relationships: list[Relationship]
    evidence: list[EvidenceItem] = Field(max_length=200)
    connections: list[HostConnection]
    gaps: list[Gap]
    local_response: LocalResponse
    related_incident_ids: list[str] = Field(default_factory=list)
    agent_version: Optional[str] = None


# ---------- Gateway ----------
class GatewayConnection(_Strict):
    gateway_connection_id: str
    protocol: Literal["TCP", "UDP", "ICMP"]
    orig_src_ip: str
    orig_src_port: int
    orig_dst_ip: str
    orig_dst_port: int
    first_seen_utc: str
    last_seen_utc: Optional[str] = None
    ingress_interface: Optional[str] = None
    src_endpoint_id: Optional[str] = None
    dst_endpoint_id: Optional[str] = None
    packets_orig: Optional[int] = None
    bytes_orig: Optional[int] = None
    packets_reply: Optional[int] = None
    bytes_reply: Optional[int] = None
    state: Literal["new", "established", "closed"]
    scope: Literal["routed", "gateway-internal"] = "routed"
    flow_ids: list[str] = Field(default_factory=list)


class NfLite1(_Strict):
    protocol: int
    l4_dst_port: int
    in_bytes: int
    out_bytes: int
    in_pkts: int
    out_pkts: int
    flow_duration_ms: int
    duration_in_ms: int
    duration_out_ms: int
    tcp_flags: int
    client_tcp_flags: int
    server_tcp_flags: int
    longest_flow_pkt: int
    shortest_flow_pkt: int
    mean_pkt_size: float
    src_to_dst_second_bytes: float
    dst_to_src_second_bytes: float
    src_to_dst_avg_throughput: float
    dst_to_src_avg_throughput: float
    num_pkts_up_to_128_bytes: int
    num_pkts_128_to_256_bytes: int
    num_pkts_256_to_512_bytes: int
    num_pkts_512_to_1024_bytes: int
    num_pkts_1024_to_1514_bytes: int

    ORDER: tuple[str, ...] = Field(default=(
        "protocol", "l4_dst_port", "in_bytes", "out_bytes", "in_pkts", "out_pkts", "flow_duration_ms",
        "duration_in_ms", "duration_out_ms", "tcp_flags", "client_tcp_flags", "server_tcp_flags",
        "longest_flow_pkt", "shortest_flow_pkt", "mean_pkt_size", "src_to_dst_second_bytes",
        "dst_to_src_second_bytes", "src_to_dst_avg_throughput", "dst_to_src_avg_throughput",
        "num_pkts_up_to_128_bytes", "num_pkts_128_to_256_bytes", "num_pkts_256_to_512_bytes",
        "num_pkts_512_to_1024_bytes", "num_pkts_1024_to_1514_bytes"), exclude=True, frozen=True)

    def vector(self) -> list[float]:
        return [float(getattr(self, k)) for k in self.ORDER]


class MLPrediction(_Strict):
    label: Literal["benign", "suspicious"]
    score: float = Field(ge=0, le=1)
    threshold: float = Field(ge=0, le=1)
    model_version: str
    feature_version: Literal["nf-lite-1"] = FEATURE_VERSION
    predicted_at_utc: str


class FlowRecord(_Strict):
    flow_id: str
    gateway_connection_id: Optional[str] = None
    duplicate_of: Optional[str] = None
    capture_interface: str
    protocol: int
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    first_seen_utc: str
    last_seen_utc: str
    application_name: Optional[str] = None
    feature_version: Literal["nf-lite-1"] = FEATURE_VERSION
    features: NfLite1
    ml: Optional[MLPrediction] = None
    scope: Literal["routed", "gateway-internal"] = "routed"


# ---------- Response / heartbeat ----------
class ResponseParams(_Strict):
    process_instance_id: Optional[str] = None
    pid: Optional[int] = None
    binary: Optional[str] = None
    protocol: Optional[Proto] = None
    src_ip: Optional[str] = None
    src_port: Optional[int] = None
    dst_ip: Optional[str] = None
    dst_port: Optional[int] = None
    timeout_seconds: Optional[int] = Field(default=None, ge=10, le=86400)
    block_id: Optional[str] = None


class ResponseCommand(_Strict):
    command_id: str
    target_kind: Literal["endpoint", "gateway"]
    endpoint_id: Optional[str] = None
    incident_id: Optional[str] = None
    action: Literal["terminate_process", "block_connection", "block_destination", "unblock"]
    params: ResponseParams
    requested_by: str
    created_utc: str
    dry_run: bool
    status: Optional[Literal["queued", "delivered", "completed", "expired"]] = None


class ResponseResult(_Strict):
    command_id: str
    executed_utc: str
    status: Literal["executed", "dry_run", "denied", "failed"]
    executor: str
    detail: dict[str, Any]


class Heartbeat(_Strict):
    endpoint_id: str
    os: OS
    sent_at_utc: str
    agent_version: str
    ip_addresses: list[str]
    clock_offset_ms: Optional[float] = None
    sensor_status: Literal["ok", "degraded", "down"]
    events_per_minute: Optional[float] = None
    dropped_events: Optional[int] = None
    outbox_depth: Optional[int] = None
    dry_run: Optional[bool] = None


# ---------- Server view ----------
class Correlation(_Strict):
    connection_id: str
    state: Literal["matched", "ambiguous", "pending", "unmatched"]
    gateway_connection_id: Optional[str] = None
    score: Optional[float] = None
    candidates: list[dict[str, Any]] = Field(default_factory=list)
    basis: Optional[Basis] = None
    note: Optional[str] = None
    updated_utc: Optional[str] = None


class Enrichment(_Strict):
    indicator_type: Literal["sha256", "ip", "domain", "url", "ip_port"]
    value: str
    source: str
    verdict: Literal["malicious", "suspicious", "unknown", "clean", "lab-test"]
    tags: list[str] = Field(default_factory=list)
    detail: dict[str, Any] = Field(default_factory=dict)
    fetched_utc: str


class NetworkEvidence(_Strict):
    gateway_connection: GatewayConnection
    flows: list[FlowRecord] = Field(default_factory=list)


class ResponseHistoryItem(_Strict):
    command: ResponseCommand
    result: Optional[ResponseResult] = None


class ServerBlock(_Strict):
    received_at_utc: str
    clock_offset_applied_ms: Optional[float] = None
    correlations: list[Correlation]
    network_evidence: list[NetworkEvidence]
    enrichment: list[Enrichment]
    response_history: list[ResponseHistoryItem]
    network_alert_ids: list[str]


class ServerIncidentView(_Strict):
    incident: Incident
    server: ServerBlock
