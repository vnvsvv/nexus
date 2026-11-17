"""nexus_contracts — the single source of truth for NEXUS data structures.

Pydantic v2 models mirroring contracts/schemas/*.json. Tests assert that every fixture
validates against BOTH the JSON Schema and the Pydantic model, so the two cannot drift.

Install (editable, from repo root):  pip install -e ./nexus_contracts_pkg   (see pyproject.toml)
"""
from .models import (  # noqa: F401
    SCHEMA_VERSION, FEATURE_VERSION,
    HostEvent, FileInfo, NetworkInfo, DnsInfo, ExitInfo,
    HostConnection, ProcessNode, Relationship, EvidenceItem, Gap, RuleMatch, LocalResponse, Incident,
    GatewayConnection, NfLite1, MLPrediction, FlowRecord,
    ResponseCommand, ResponseParams, ResponseResult, Heartbeat,
    Correlation, Enrichment, ServerBlock, ServerIncidentView,
    new_event_id, new_incident_id, utc_now_iso,
)
from .loader import load_schema, validate_against_schema  # noqa: F401

__version__ = "1.0.0"
