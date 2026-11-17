# contracts/ — the shared truth

Nothing in `endpoint-core/`, `endpoint-linux/`, `endpoint-windows/`, `server/`, `ml/` or `dashboard/` may define its own version of anything that lives here.

| Path | What | Who consumes |
|---|---|---|
| `schemas/host_event.schema.json` | Normalized endpoint event | adapters (produce), endpoint-core (consume) |
| `schemas/incident.schema.json` + `connection.schema.json` | Endpoint incident (versioned) | endpoint-core (produce), server (store/correlate), dashboard |
| `schemas/gateway_connection.schema.json` | conntrack-derived connection | server |
| `schemas/flow_record.schema.json` + `ml_prediction.schema.json` | NFStream flow + `nf-lite-1` features + ML verdict | server flow_service, nexus_ml, dashboard |
| `schemas/response_command.schema.json` / `response_result.schema.json` | Closed-set response actions and audit results | server, endpoint-core, dashboard |
| `schemas/heartbeat.schema.json` | Agent heartbeat | endpoint-core, server |
| `schemas/server_incident_view.schema.json` | Incident + server block | server (produce), dashboard (consume) |
| `openapi.yaml` | HTTP API | server implements; agents and dashboard call; TS types generated |
| `rules/RULE-FORMAT.md` + `rules/NX-*.yaml` | Detection rules | endpoint-core |
| `flow-features.md` | `nf-lite-1` feature contract | nexus_ml + server flow_service |
| `attack-mapping.yaml` | Rule → ATT&CK | endpoint-core, dashboard |
| `fixtures/` | Canonical examples; **every test suite uses these** | everyone |

## Workflow
1. `pip install -e .` from the repo root (installs `nexus_contracts`).
2. `python tools/validate_fixtures.py` must pass before any push.
3. To change a contract: open a PR titled `contracts: ...`, bump `schema_version` only for breaking changes, regenerate fixtures with `python tools/generate_fixtures.py`, update `openapi.yaml`, notify the team in the `#contracts` channel. **Freeze date: end of Day 2.** After that, additive changes only (new optional fields), no renames.

## Conventions every agent must follow
- Timestamps: UTC, ISO-8601, millisecond precision, trailing `Z`.
- IDs: `endpoint_id` is a lowercase slug (`linux-vm-01`, `windows-vm-01`); event/incident/connection IDs are prefixed as the schemas specify.
- Optional sub-objects are **omitted** when absent (never `null`): serialize with `exclude_none=True`.
- JSON only; UTF-8; no comments in JSON files.
- Paths: Windows paths keep backslashes in data; rule predicates normalize at evaluation time.
- Never add fields to a document you did not produce (the server adds its data in the `server` block, not inside `incident`).
