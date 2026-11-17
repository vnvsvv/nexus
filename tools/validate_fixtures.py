#!/usr/bin/env python3
"""Validates every fixture against the JSON Schemas AND the Pydantic models.

Run from repo root:  python tools/validate_fixtures.py
Exit code 0 = all good. Used by CI and by every member before pushing a contract change.
Optional checks run only if the relevant package is importable:
  - nexus_endpoint_core: runs rule fixtures (events -> expected rule match)
  - nexus_ml: checks feature parity fixture (dataset row vs NFStream fields -> identical vector)
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from nexus_contracts import (  # noqa: E402
    HostEvent, Incident, GatewayConnection, FlowRecord, ResponseCommand, ResponseResult, Heartbeat, ServerIncidentView,
    validate_against_schema,
)

FIX = ROOT / "contracts" / "fixtures"
failures: list[str] = []


def check(schema: str, model, path: Path, instance: dict):
    errs = validate_against_schema(schema, instance)
    if errs:
        failures.append(f"{path.name} [schema {schema}]: " + "; ".join(errs[:5]))
    try:
        model.model_validate(instance)
    except Exception as e:  # noqa: BLE001
        failures.append(f"{path.name} [pydantic {model.__name__}]: {e}")


for p in sorted(FIX.rglob("*.jsonl")):
    for i, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
        if line.strip():
            check("host_event", HostEvent, p, json.loads(line))

single = {
    "incident_linux_l1.json": ("incident", Incident),
    "gateway_connection_example.json": ("gateway_connection", GatewayConnection),
    "flow_record_example.json": ("flow_record", FlowRecord),
    "response_command_example.json": ("response_command", ResponseCommand),
    "response_result_example.json": ("response_result", ResponseResult),
    "heartbeat_example.json": ("heartbeat", Heartbeat),
    "server_incident_view_linux_l1.json": ("server_incident_view", ServerIncidentView),
}
for name, (schema, model) in single.items():
    p = FIX / name
    check(schema, model, p, json.loads(p.read_text(encoding="utf-8")))

# every rule yaml must parse and reference known techniques
try:
    import yaml  # type: ignore
    mapping = yaml.safe_load((ROOT / "contracts" / "attack-mapping.yaml").read_text(encoding="utf-8"))
    for rp in sorted((ROOT / "contracts" / "rules").glob("NX-*.yaml")):
        r = yaml.safe_load(rp.read_text(encoding="utf-8"))
        for k in ("id", "version", "title", "kind", "os", "severity", "technique_ids", "context"):
            if k not in r:
                failures.append(f"{rp.name}: missing '{k}'")
        for tid in r.get("technique_ids", []):
            if tid not in mapping["techniques"]:
                failures.append(f"{rp.name}: technique {tid} not in attack-mapping.yaml")
        if mapping["rules"].get(r.get("id")) != r.get("technique_ids"):
            failures.append(f"{rp.name}: technique_ids differ from attack-mapping.yaml")
        if r["kind"] in ("single", "sequence") and not r.get("steps"):
            failures.append(f"{rp.name}: steps required")
        if r["kind"] == "threshold" and not r.get("threshold"):
            failures.append(f"{rp.name}: threshold block required")
except ImportError:
    print("pyyaml not installed; skipping rule checks")

# optional: rule engine fixtures
try:
    from nexus_endpoint_core.replay import run_rule_fixture  # type: ignore
    for ep in sorted((FIX / "rules").glob("*.events.jsonl")):
        exp = json.loads(ep.with_name(ep.name.replace(".events.jsonl", ".expect.json")).read_text())
        ok, msg = run_rule_fixture(ep, exp, ROOT / "contracts" / "rules")
        if not ok:
            failures.append(f"rule fixture {ep.name}: {msg}")
    print("rule-engine fixtures executed")
except ImportError:
    print("nexus_endpoint_core not installed; rule fixtures schema-checked only")

# optional: feature parity
try:
    from nexus_ml.features import from_dataset_row, from_nflow_fields  # type: ignore
    fx = json.loads((FIX / "flow_feature_fixture.json").read_text())
    a = from_dataset_row(fx["dataset_row"])
    b = from_nflow_fields(fx["nflow_fields"])
    if a != fx["expected_vector"] or b != fx["expected_vector"]:
        failures.append("feature parity fixture: vectors differ\n dataset=%s\n nflow=%s\n expected=%s" % (a, b, fx["expected_vector"]))
    else:
        print("feature parity fixture OK")
except ImportError:
    print("nexus_ml not installed; feature parity fixture skipped")

if failures:
    print("\nFAILURES:")
    for f in failures:
        print(" -", f)
    sys.exit(1)
print("all fixtures valid")
