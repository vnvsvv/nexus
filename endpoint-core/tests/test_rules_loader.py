"""Rule loader tests (task A2): loading, validation, YAML safety, ATT&CK mapping, immutability.

Nothing here evaluates a rule against events; that is task A3.
"""
from __future__ import annotations

import copy
import json
import logging
import re
import shutil
from pathlib import Path
from typing import Callable

import pytest
import yaml
from nexus_contracts import HostEvent
from nexus_contracts.models import DnsInfo, FileInfo, NetworkInfo
from pydantic import ValidationError

from nexus_endpoint_core import rules as rules_module
from nexus_endpoint_core.rules import (FIELD_PATHS, AttackMapping, AttackMappingError, Rule, RuleError, RuleLoadError,
                                       RuleSet, Scope, load_attack_mapping, load_rule, load_rules)

ROOT = Path(__file__).resolve().parents[2]
RULES = ROOT / "contracts" / "rules"
MAPPING = ROOT / "contracts" / "attack-mapping.yaml"
SHIPPED = sorted(p.stem for p in RULES.glob("*.yaml"))


# ------------------------------------------------------------------ helpers
def shipped(rule_id: str) -> dict:
    return yaml.safe_load((RULES / f"{rule_id}.yaml").read_text(encoding="utf-8"))


def dump(data: object) -> str:
    return yaml.safe_dump(json.loads(json.dumps(data)), sort_keys=False)      # json round trip: no shared objects, no anchors


def write(directory: Path, data: dict, name: str) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_text(dump(data), encoding="utf-8")
    return path


def _walk(data, path):
    for key in path[:-1]:
        data = data[key]
    return data, path[-1]


def put(*path, value) -> Callable[[dict], None]:
    def apply(d: dict) -> None:
        parent, last = _walk(d, path)
        parent[last] = value
    return apply


def drop(*path) -> Callable[[dict], None]:
    def apply(d: dict) -> None:
        parent, last = _walk(d, path)
        del parent[last]
    return apply


def rejected(tmp_path: Path, base: str, mutate: Callable[[dict], None], *needles: str, name: str | None = None,
             mapping: AttackMapping | None = None) -> RuleError:
    data = shipped(base)
    mutate(data)
    path = write(tmp_path, data, name or f"{base}.yaml")
    with pytest.raises(RuleError) as caught:
        load_rule(path, attack_mapping=mapping)
    text = str(caught.value)
    for needle in needles:
        assert needle in text, f"{needle!r} not in {text!r}"
    return caught.value


def loaded(tmp_path: Path, base: str, mutate: Callable[[dict], None]) -> Rule:
    data = shipped(base)
    mutate(data)
    return load_rule(write(tmp_path, data, f"{base}.yaml"))


def raw(tmp_path: Path, text: str | bytes, name: str = "NX-WIN-001.yaml") -> Path:
    path = tmp_path / name
    path.write_bytes(text if isinstance(text, bytes) else text.encode("utf-8"))
    return path


# ------------------------------------------------------------------ the seven shipped rules
def test_all_seven_shipped_rules_load_with_zero_errors():
    assert SHIPPED == ["NX-ANY-001", "NX-LIN-001", "NX-LIN-002", "NX-LIN-003", "NX-WIN-001", "NX-WIN-002", "NX-WIN-003"]
    result = load_rules(RULES, strict=True)                       # strict: any problem would raise
    assert result.errors == () and [r.id for r in result] == SHIPPED and len(result) == 7
    explicit = load_rules(RULES, attack_mapping=MAPPING, strict=True)
    assert explicit.rules == result.rules                           # discovery and an explicit path agree
    for rule in result:
        assert rule.source == RULES / f"{rule.id}.yaml"


def test_shipped_rule_details():
    rs = load_rules(RULES)
    w1 = rs.get("NX-WIN-001")
    assert (w1.kind, w1.os, w1.severity, w1.window_seconds, w1.ordered) == ("sequence", ("windows",), "high", 60, True)
    assert [s.name for s in w1.steps] == ["ps", "stage", "net"] and w1.technique_ids == ("T1059.001", "T1074.001", "T1105")
    assert w1.context.max_ancestors == 3 and w1.context.incident_window_seconds == 120
    stage = w1.steps[1].lineage
    assert (stage.relation, stage.of, stage.max_depth, stage.include_self) == ("descendant_of", "ps", 2, True)
    assert w1.steps[0].lineage is None and w1.steps[1].event_type == "file_access"
    by_op = {(p.field, p.op): p for p in w1.steps[2].where}
    cidr = by_op[("network.dst_ip", "not_in_cidr")]
    assert [str(n) for n in cidr.compiled] == ["127.0.0.0/8", "192.168.20.1/32"] and cidr.operand == ("127.0.0.0/8", "192.168.20.1/32")
    assert by_op[("network.direction", "equals")].operand == "outbound"
    ps = {(p.field, p.op): p for p in w1.steps[0].where}
    assert ps[("binary", "endswith_any")].operand == ("\\powershell.exe", "\\pwsh.exe")
    assert ps[("command_line", "contains_any")].operand[-1] == "-ep bypass"
    assert {(p.field, p.op) for p in w1.steps[1].where} == {("file.operation", "in"), ("file.path", "prefix_any")}

    l3 = rs.get("NX-LIN-003")
    assert l3.steps[1].lineage.relation == "same" and l3.steps[1].lineage.of == "bin" and l3.steps[1].lineage.max_depth is None
    assert (l3.response.action, l3.response.target_step) == ("terminate_process", "bin") and l3.window_seconds == 30

    any1 = rs.get("NX-ANY-001")
    assert any1.os == ("linux", "windows") and any1.ordered is None and any1.severity == "critical"
    flag = any1.steps[0].where[0]
    assert (flag.field, flag.op, flag.operand) == ("attributes.ti_hash_hit", "equals", True)

    w2 = rs.get("NX-WIN-002")
    assert w2.kind == "single" and w2.response.target_step == "bin" and w2.steps[0].where[0].op == "prefix_any"

    for rid in ("NX-LIN-002", "NX-WIN-003"):
        t = rs.get(rid)
        assert t.kind == "threshold" and t.steps == () and t.window_seconds is None and t.response is None
        spec = t.threshold
        assert (spec.event_type, spec.scope, spec.distinct_field, spec.group_by, spec.min_distinct, spec.window_seconds) == (
            "network_connect", Scope(kind="process"), "network.dst_port", "network.dst_ip", 15, 10)
        assert [(p.field, p.op, p.operand) for p in spec.where] == [("network.direction", "equals", "outbound")]
    assert rs.get("NX-LIN-001").steps[3].lineage.of == "shell" and len(rs.get("NX-LIN-001").steps) == 4
    assert [r.id for r in rs.for_os("windows")] == ["NX-ANY-001", "NX-WIN-001", "NX-WIN-002", "NX-WIN-003"]
    assert [r.id for r in rs.for_os("linux")] == ["NX-ANY-001", "NX-LIN-001", "NX-LIN-002", "NX-LIN-003"]
    assert rs.get("NX-NOPE-000") is None


def test_every_allowed_field_path_exists_on_a_host_event():
    event = HostEvent(event_id="ep-01:evt-000000000001", endpoint_id="ep-01", os="windows", timestamp_utc="2026-11-15T10:00:00.000Z",
                      event_type="network_connect", process_instance_id="ep-01:p", pid=1, binary="C:\\a.exe",
                      file=FileInfo(path="C:\\a", operation="read"),
                      network=NetworkInfo(protocol="TCP", src_ip="10.0.0.1", src_port=1, dst_ip="10.0.0.2", dst_port=2, direction="outbound"),
                      dns=DnsInfo(query="a.test"))
    for path in FIELD_PATHS:
        value = event
        for part in path.split("."):
            value = getattr(value, part)                              # AttributeError would mean the rule format drifted from HostEvent
    assert len(FIELD_PATHS) == 12


# ------------------------------------------------------------------ valid variations
def test_context_max_ancestors_defaults_to_three_but_other_keys_are_required(tmp_path):
    assert loaded(tmp_path, "NX-WIN-001", drop("context", "max_ancestors")).context.max_ancestors == 3
    rejected(tmp_path, "NX-WIN-001", drop("context", "max_descendant_depth"), "context.max_descendant_depth: required key is missing")


def test_several_operators_on_one_field_are_all_kept_and_compiled(tmp_path):
    rule = loaded(tmp_path, "NX-WIN-001", put("steps", 2, "where", "network.dst_ip",
                                              value={"in_cidr": ["10.0.0.0/8"], "not_in_cidr": ["10.1.0.0/16", "::1/128"]}))
    ops = {p.op: p for p in rule.steps[2].where if p.field == "network.dst_ip"}
    assert set(ops) == {"in_cidr", "not_in_cidr"} and [str(n) for n in ops["not_in_cidr"].compiled] == ["10.1.0.0/16", "::1/128"]


def test_a_regex_is_compiled_once_without_flags(tmp_path):
    rule = loaded(tmp_path, "NX-WIN-001", put("steps", 0, "where", "command_line", value={"regex": r"-e(nc)?\s"}))
    predicate = next(p for p in rule.steps[0].where if p.op == "regex")
    assert isinstance(predicate.compiled, re.Pattern) and predicate.compiled.flags & re.IGNORECASE == 0
    assert predicate.compiled.search("powershell -enc AAA") and not predicate.compiled.search("powershell -ENC AAA")


def test_numeric_and_membership_operators_on_ports(tmp_path):
    rule = loaded(tmp_path, "NX-WIN-001", put("steps", 2, "where", "network.dst_port", value={"gte": 1024, "lte": 65535, "in": [8080, 8443]}))
    assert {(p.op, p.operand) for p in rule.steps[2].where if p.field == "network.dst_port"} == {
        ("gte", 1024), ("lte", 65535), ("in", (8080, 8443))}


def test_attribute_predicates_accept_any_scalar(tmp_path):
    for value in (True, "yes", 7, 1.5):
        rule = loaded(tmp_path, "NX-ANY-001", put("steps", 0, "where", "attributes.ti_hash_hit", value={"equals": value}))
        assert rule.steps[0].where[0].operand == value
    rule = loaded(tmp_path, "NX-ANY-001", put("steps", 0, "where", "attributes.score", value={"gte": 3}))
    assert {(p.field, p.op, p.operand) for p in rule.steps[0].where} == {("attributes.ti_hash_hit", "equals", True), ("attributes.score", "gte", 3)}


def test_a_lineage_scope_keeps_its_depth_and_is_not_interpreted(tmp_path):
    rule = loaded(tmp_path, "NX-LIN-002", put("threshold", "scope", value="lineage(3)"))
    assert rule.threshold.scope == Scope(kind="lineage", depth=3)
    assert "A3" in rules_module.__doc__ and "NOT defined by RULE-FORMAT.md" in rules_module.__doc__    # the open question is documented


def test_an_unordered_sequence_may_refer_to_a_later_step(tmp_path):
    rule = loaded(tmp_path, "NX-WIN-001", lambda d: (d.__setitem__("ordered", False), d["steps"][1].__setitem__(
        "lineage", {"relation": "child_of", "of": "net"})))              # stage -> net -> ps: no cycle
    assert rule.ordered is False and rule.steps[1].lineage.of == "net"


def test_a_child_of_lineage_needs_no_depth(tmp_path):
    rule = loaded(tmp_path, "NX-WIN-001", put("steps", 2, "lineage", value={"relation": "child_of", "of": "ps"}))
    assert rule.steps[2].lineage.relation == "child_of" and rule.steps[2].lineage.max_depth is None


# ------------------------------------------------------------------ invalid rules
@pytest.mark.parametrize("key", ["version", "title", "kind", "os", "severity", "technique_ids", "context"])
def test_each_required_top_level_key(tmp_path, key):
    rejected(tmp_path, "NX-WIN-001", drop(key), f"{key}: required key is missing")


def test_a_missing_id_is_reported(tmp_path):
    rejected(tmp_path, "NX-WIN-001", drop("id"), "id: required key is missing")


TOP_LEVEL = [
    ("unknown top-level key", "NX-WIN-001", put("windows_seconds", value=5), ["windows_seconds: unknown key"]),
    ("bad kind", "NX-WIN-001", put("kind", value="sequential"), ["kind:"]),
    ("unknown os", "NX-WIN-001", put("os", value=["macos"]), ["os[0]"]),
    ("empty os", "NX-WIN-001", put("os", value=[]), ["os:"]),
    ("os as string", "NX-WIN-001", put("os", value="windows"), ["os:"]),
    ("duplicate os", "NX-ANY-001", put("os", value=["linux", "linux"]), ["os:"]),
    ("bad severity", "NX-WIN-001", put("severity", value="urgent"), ["severity:"]),
    ("unquoted version", "NX-WIN-001", put("version", value=1.0), ["version:"]),
    ("empty title", "NX-WIN-001", put("title", value=""), ["title:"]),
    ("bad id", "NX-WIN-001", put("id", value="NX-WIN-1"), ["id:"]),
    ("technique format", "NX-WIN-001", put("technique_ids", value=["T12"]), ["technique_ids[0]"]),
    ("duplicate techniques", "NX-WIN-001", put("technique_ids", value=["T1105", "T1105"]), ["technique_ids: duplicate"]),
    ("no techniques", "NX-WIN-001", put("technique_ids", value=[]), ["technique_ids:"]),
    ("references not a list", "NX-WIN-001", put("references", value="sigma"), ["references:"]),
    ("context extra key", "NX-WIN-001", put("context", "depth", value=1), ["context.depth: unknown key"]),
    ("max_ancestors negative", "NX-WIN-001", put("context", "max_ancestors", value=-1), ["context.max_ancestors:"]),
    ("max_ancestors too big", "NX-WIN-001", put("context", "max_ancestors", value=11), ["context.max_ancestors:"]),
    ("max_ancestors string", "NX-WIN-001", put("context", "max_ancestors", value="3"), ["context.max_ancestors:"]),
    ("incident window zero", "NX-WIN-001", put("context", "incident_window_seconds", value=0), ["context.incident_window_seconds:"]),
    ("incident window bool", "NX-WIN-001", put("context", "incident_window_seconds", value=True), ["context.incident_window_seconds:"]),
]


@pytest.mark.parametrize("label, base, mutate, needles", TOP_LEVEL, ids=[c[0] for c in TOP_LEVEL])
def test_top_level_and_context_validation(tmp_path, label, base, mutate, needles):
    rejected(tmp_path, base, mutate, *needles, name=f"{base}.yaml")


def test_an_id_must_match_its_file_name_and_its_os(tmp_path):
    rejected(tmp_path, "NX-WIN-001", put("id", value="NX-WIN-009"), "id: the file must be named NX-WIN-009.yaml, not NX-WIN-001.yaml")
    rejected(tmp_path, "NX-WIN-001", put("id", value="NX-LIN-009"), "os: a NX-LIN rule must declare os ['linux']", name="NX-LIN-009.yaml")
    rejected(tmp_path, "NX-ANY-001", put("os", value=["linux"]), "os: a NX-ANY rule must declare os ['linux', 'windows']")


def _more_steps(count: int):
    def apply(d: dict) -> None:
        first = d["steps"][0]
        d["steps"] = [{**copy.deepcopy(first), "step": f"s{i}"} for i in range(count)]
    return apply


KINDS = [
    ("single with two steps", "NX-WIN-002", lambda d: d["steps"].append({**copy.deepcopy(d["steps"][0]), "step": "other"}), ["exactly one step"]),
    ("single with ordered", "NX-WIN-002", put("ordered", value=True), ["ordered: only allowed on a sequence"]),
    ("single with threshold", "NX-WIN-002", put("threshold", value=shipped("NX-LIN-002")["threshold"]), ["threshold: not allowed on a single rule"]),
    ("sequence with one step", "NX-WIN-001", lambda d: d["steps"].__delitem__(slice(1, None)), ["2 to 5 steps"]),
    ("sequence with six steps", "NX-WIN-001", _more_steps(6), ["2 to 5 steps"]),
    ("sequence without window", "NX-WIN-001", drop("window_seconds"), ["window_seconds: required"]),
    ("window zero", "NX-WIN-001", put("window_seconds", value=0), ["window_seconds:"]),
    ("window string", "NX-WIN-001", put("window_seconds", value="60"), ["window_seconds:"]),
    ("window bool", "NX-WIN-001", put("window_seconds", value=True), ["window_seconds:"]),
    ("sequence with threshold block", "NX-WIN-001", put("threshold", value=shipped("NX-LIN-002")["threshold"]), ["threshold: not allowed on a sequence rule"]),
    ("sequence without steps", "NX-WIN-001", drop("steps"), ["steps:"]),
    ("threshold with window", "NX-LIN-002", put("window_seconds", value=10), ["window_seconds: not allowed on a threshold rule"]),
    ("threshold with ordered", "NX-LIN-002", put("ordered", value=True), ["ordered: not allowed on a threshold rule"]),
    ("threshold with steps", "NX-LIN-002", put("steps", value=shipped("NX-LIN-003")["steps"]), ["steps: not allowed on a threshold rule"]),
    ("threshold with response", "NX-LIN-002", put("response", value={"action": "terminate_process", "target_step": "bin"}),
     ["response: not allowed on a threshold rule"]),
    ("threshold without block", "NX-LIN-002", drop("threshold"), ["threshold: required for kind threshold"]),
]


@pytest.mark.parametrize("label, base, mutate, needles", KINDS, ids=[c[0] for c in KINDS])
def test_rule_kind_consistency(tmp_path, label, base, mutate, needles):
    rejected(tmp_path, base, mutate, *needles)


STEPS = [
    ("duplicate step names", "NX-WIN-001", put("steps", 1, "step", value="ps"), ["steps: step names must be unique"]),
    ("name starts with a digit", "NX-WIN-001", put("steps", 0, "step", value="1bad"), ["steps[0].step:"]),
    ("name with a space", "NX-WIN-001", put("steps", 0, "step", value="two words"), ["steps[0].step:"]),
    ("missing step name", "NX-WIN-001", drop("steps", 0, "step"), ["steps[0].step: required key is missing"]),
    ("missing event_type", "NX-WIN-001", drop("steps", 0, "event_type"), ["steps[0].event_type: required key is missing"]),
    ("bad event_type", "NX-WIN-001", put("steps", 0, "event_type", value="registry_write"), ["steps[0].event_type:"]),
    ("missing where", "NX-WIN-001", drop("steps", 0, "where"), ["steps[0].where: required key is missing"]),
    ("empty where", "NX-WIN-001", put("steps", 0, "where", value={}), ["where must be a non-empty mapping"]),
    ("where as list", "NX-WIN-001", put("steps", 0, "where", value=["binary"]), ["where must be a non-empty mapping"]),
    ("unknown step key", "NX-WIN-001", put("steps", 0, "bogus", value=1), ["steps[0].bogus: unknown key"]),
    ("step not a mapping", "NX-WIN-001", put("steps", 1, value="stage"), ["steps[1]"]),
]


@pytest.mark.parametrize("label, base, mutate, needles", STEPS, ids=[c[0] for c in STEPS])
def test_step_validation(tmp_path, label, base, mutate, needles):
    rejected(tmp_path, base, mutate, *needles)


LINEAGE = [
    ("unknown target", "NX-WIN-001", put("steps", 1, "lineage", "of", value="nope"), ["steps[1].lineage.of: unknown step 'nope'"]),
    ("self reference", "NX-WIN-001", put("steps", 1, "lineage", "of", value="stage"), ["cannot refer to itself"]),
    ("forward reference in an ordered rule", "NX-WIN-001", put("steps", 1, "lineage", "of", value="net"), ["must be an earlier step"]),
    ("first step with lineage", "NX-WIN-001", put("steps", 0, "lineage", value={"relation": "same", "of": "stage"}), ["steps[0].lineage.of"]),
    ("cycle in an unordered rule", "NX-WIN-001", lambda d: (d.__setitem__("ordered", False), d["steps"][0].__setitem__(
        "lineage", {"relation": "same", "of": "stage"})), ["lineage forms a cycle"]),
    ("descendant_of without depth", "NX-WIN-001", drop("steps", 1, "lineage", "max_depth"), ["max_depth is required for relation descendant_of"]),
    ("depth zero", "NX-WIN-001", put("steps", 1, "lineage", "max_depth", value=0), ["steps[1].lineage.max_depth:"]),
    ("depth eleven", "NX-WIN-001", put("steps", 1, "lineage", "max_depth", value=11), ["steps[1].lineage.max_depth:"]),
    ("depth as string", "NX-WIN-001", put("steps", 1, "lineage", "max_depth", value="2"), ["steps[1].lineage.max_depth:"]),
    ("include_self not a bool", "NX-WIN-001", put("steps", 1, "lineage", "include_self", value="yes"), ["steps[1].lineage.include_self:"]),
    ("include_self on same", "NX-LIN-003", put("steps", 1, "lineage", "include_self", value=True), ["include_self is only allowed with relation descendant_of"]),
    ("max_depth on same", "NX-LIN-003", put("steps", 1, "lineage", "max_depth", value=2), ["max_depth is only allowed with relation descendant_of"]),
    ("unknown relation", "NX-WIN-001", put("steps", 1, "lineage", "relation", value="ancestor_of"), ["steps[1].lineage.relation:"]),
    ("lineage without target", "NX-WIN-001", drop("steps", 1, "lineage", "of"), ["steps[1].lineage.of: required key is missing"]),
    ("lineage extra key", "NX-WIN-001", put("steps", 1, "lineage", "bogus", value=1), ["steps[1].lineage.bogus: unknown key"]),
]


@pytest.mark.parametrize("label, base, mutate, needles", LINEAGE, ids=[c[0] for c in LINEAGE])
def test_lineage_validation(tmp_path, label, base, mutate, needles):
    rejected(tmp_path, base, mutate, *needles)


def _where(step: int, field: str, value) -> Callable[[dict], None]:
    return put("steps", step, "where", field, value=value)


PREDICATES = [
    ("unknown field", _where(0, "file.name", {"equals": "x"}), ["where['file.name']: unknown field path"]),
    ("field that was not listed", _where(2, "network.src_ip", {"equals": "10.0.0.1"}), ["where['network.src_ip']: unknown field path"]),
    ("attribute key with a space", _where(0, "attributes.bad key", {"equals": 1}), ["unknown field path"]),
    ("empty attribute key", _where(0, "attributes.", {"equals": 1}), ["unknown field path"]),
    ("file field on a process step", _where(0, "file.path", {"equals": "x"}), ["only present on ['file_access'] events, not process_start"]),
    ("network field on a file step", _where(1, "network.dst_port", {"equals": 80}), ["only present on ['network_connect'] events, not file_access"]),
    ("unknown operator", _where(0, "binary", {"startswith": ["a"]}), ["unknown operator 'startswith'"]),
    ("field without operators", _where(0, "binary", {}), ["expected a non-empty mapping of operator to operand"]),
    ("field with a bare value", _where(0, "binary", "cmd.exe"), ["expected a non-empty mapping of operator to operand"]),
    ("text operator on a port", _where(2, "network.dst_port", {"prefix_any": ["80"]}), ["needs a free-text field"]),
    ("text operator on a closed-set field", _where(1, "file.operation", {"regex": "cr.*"}), ["closed value set"]),
    ("cidr operator on text", _where(0, "binary", {"in_cidr": ["10.0.0.0/8"]}), ["only applies to an IP address field"]),
    ("numeric operator on text", _where(0, "binary", {"gte": 1}), ["only applies to a numeric field"]),
    ("list operator given a string", _where(0, "binary", {"prefix_any": "C:\\"}), ["expected a non-empty list"]),
    ("list operator given nothing", _where(0, "binary", {"endswith_any": []}), ["expected a non-empty list"]),
    ("list operator with a number", _where(0, "binary", {"contains_any": [1]}), ["expected non-empty strings"]),
    ("list operator with an empty string", _where(0, "binary", {"contains_any": [""]}), ["expected non-empty strings"]),
    ("equals given a list", _where(0, "binary", {"equals": ["a"]}), ["expected a non-empty string"]),
    ("in given a string", _where(1, "file.operation", {"in": "create"}), ["expected a non-empty list"]),
    ("in given an empty list", _where(1, "file.operation", {"in": []}), ["expected a non-empty list"]),
    ("too many list items", _where(0, "binary", {"endswith_any": ["a"] * 1001}), ["the limit is 1000"]),
    ("gte given a string", _where(2, "network.dst_port", {"gte": "5"}), ["expected a finite number"]),
    ("gte given a bool", _where(2, "network.dst_port", {"gte": True}), ["expected a finite number"]),
    ("gte given infinity", _where(2, "network.dst_port", {"gte": float("inf")}), ["expected a finite number"]),
    ("regex given a list", _where(0, "binary", {"regex": ["a"]}), ["expected a non-empty regular expression string"]),
    ("regex given nothing", _where(0, "binary", {"regex": ""}), ["expected a non-empty regular expression string"]),
    ("regex that does not compile", _where(0, "binary", {"regex": "("}), ["invalid regular expression"]),
    ("regex that is too long", _where(0, "binary", {"regex": "a" * 501}), ["regular expression is 501 characters; the limit is 500"]),
    ("cidr with a bad prefix", _where(2, "network.dst_ip", {"not_in_cidr": ["10.0.0.0/33"]}), ["invalid CIDR '10.0.0.0/33'"]),
    ("cidr with host bits", _where(2, "network.dst_ip", {"not_in_cidr": ["10.0.0.1/8"]}), ["host bits set"]),
    ("cidr that is not an address", _where(2, "network.dst_ip", {"not_in_cidr": ["not-an-ip"]}), ["invalid CIDR"]),
    ("cidr given a number", _where(2, "network.dst_ip", {"not_in_cidr": [5]}), ["expected non-empty strings"]),
    ("file operation outside the contract", _where(1, "file.operation", {"equals": "readd"}), ["'readd' is not one of"]),
    ("file operation in a list", _where(1, "file.operation", {"in": ["create", "bogus"]}), ["'bogus' is not one of"]),
    ("direction outside the contract", _where(2, "network.direction", {"equals": "outgoing"}), ["'outgoing' is not one of ['outbound', 'inbound']"]),
    ("protocol in the wrong case", _where(2, "network.protocol", {"equals": "tcp"}), ["'tcp' is not one of ['TCP', 'UDP']"]),
    ("port above range", _where(2, "network.dst_port", {"equals": 70000}), ["outside 0..65535"]),
    ("port negative", _where(2, "network.dst_port", {"in": [80, -1]}), ["outside 0..65535"]),
    ("port as a string", _where(2, "network.dst_port", {"equals": "80"}), ["expected an integer"]),
    ("port as a bool", _where(2, "network.dst_port", {"equals": True}), ["expected an integer"]),
    ("address that is not one", _where(2, "network.dst_ip", {"equals": "999.1.1.1"}), ["is not an IP address"]),
    ("address as a number", _where(2, "network.dst_ip", {"equals": 5}), ["is not an IP address"]),
]


@pytest.mark.parametrize("label, mutate, needles", PREDICATES, ids=[c[0] for c in PREDICATES])
def test_predicate_validation(tmp_path, label, mutate, needles):
    err = rejected(tmp_path, "NX-WIN-001", mutate, *needles)
    assert err.source.name == "NX-WIN-001.yaml"


def test_attribute_predicates_reject_non_scalars(tmp_path):
    rejected(tmp_path, "NX-ANY-001", put("steps", 0, "where", "attributes.ti_hash_hit", value={"equals": ["a"]}),
             "expected a string, number or boolean")


def test_every_field_level_problem_in_a_rule_is_reported_together(tmp_path):
    def many(d):
        d["severity"] = "urgent"
        d["steps"][0]["where"]["binary"] = {"regex": "("}
        d["steps"][1]["lineage"]["max_depth"] = 0
        d["steps"][2]["where"]["network.dst_port"] = {"equals": 70000}
    err = rejected(tmp_path, "NX-WIN-001", many)
    text = "\n".join(err.problems)
    for needle in ("severity:", "invalid regular expression", "steps[1].lineage.max_depth", "outside 0..65535"):
        assert needle in text, text
    assert len(err.problems) == 4


def test_every_cross_field_problem_in_a_rule_is_reported_together(tmp_path):
    def many(d):
        d["steps"][1]["lineage"]["of"] = "nope"
        d["steps"][2]["step"] = "ps"
        d["technique_ids"] = ["T1105", "T1105"]
        d["os"] = ["linux"]
    err = rejected(tmp_path, "NX-WIN-001", many)
    text = "\n".join(err.problems)
    for needle in ("lineage.of: unknown step 'nope'", "step names must be unique", "technique_ids: duplicate", "os: a NX-WIN rule must declare"):
        assert needle in text, text


THRESHOLD = [
    ("unknown scope", put("threshold", "scope", value="global"), ["threshold.scope: must be the string 'process' or 'lineage(N)'"]),
    ("empty lineage scope", put("threshold", "scope", value="lineage()"), ["threshold.scope:"]),
    ("lineage depth zero", put("threshold", "scope", value="lineage(0)"), ["lineage depth must be 1..10, found 0"]),
    ("lineage depth eleven", put("threshold", "scope", value="lineage(11)"), ["lineage depth must be 1..10, found 11"]),
    ("lineage in the wrong case", put("threshold", "scope", value="Lineage(2)"), ["threshold.scope:"]),
    ("scope not a string", put("threshold", "scope", value=5), ["threshold.scope:"]),
    ("missing scope", drop("threshold", "scope"), ["threshold.scope: required key is missing"]),
    ("min_distinct zero", put("threshold", "min_distinct", value=0), ["threshold.min_distinct:"]),
    ("min_distinct string", put("threshold", "min_distinct", value="15"), ["threshold.min_distinct:"]),
    ("min_distinct bool", put("threshold", "min_distinct", value=True), ["threshold.min_distinct:"]),
    ("missing min_distinct", drop("threshold", "min_distinct"), ["threshold.min_distinct: required key is missing"]),
    ("window zero", put("threshold", "window_seconds", value=0), ["threshold.window_seconds:"]),
    ("missing window", drop("threshold", "window_seconds"), ["threshold.window_seconds: required key is missing"]),
    ("distinct field on the wrong event type", put("threshold", "distinct_field", value="file.path"), ["distinct_field: file.path is only present on"]),
    ("unknown distinct field", put("threshold", "distinct_field", value="network.nope"), ["distinct_field: unknown field path"]),
    ("unknown group_by", put("threshold", "group_by", value="nope"), ["group_by: unknown field path"]),
    ("missing distinct_field", drop("threshold", "distinct_field"), ["threshold.distinct_field: required key is missing"]),
    ("missing event_type", drop("threshold", "event_type"), ["threshold.event_type: required key is missing"]),
    ("bad event_type", put("threshold", "event_type", value="registry"), ["threshold.event_type:"]),
    ("extra key", put("threshold", "bogus", value=1), ["threshold.bogus: unknown key"]),
    ("bad predicate", put("threshold", "where", value={"network.direction": {"equals": "sideways"}}), ["'sideways' is not one of"]),
    ("predicate for another event type", put("threshold", "where", value={"file.path": {"equals": "x"}}), ["only present on ['file_access']"]),
]


@pytest.mark.parametrize("label, mutate, needles", THRESHOLD, ids=[c[0] for c in THRESHOLD])
def test_threshold_validation(tmp_path, label, mutate, needles):
    rejected(tmp_path, "NX-LIN-002", mutate, *needles)


def test_a_threshold_without_where_is_allowed(tmp_path):
    assert loaded(tmp_path, "NX-LIN-002", drop("threshold", "where")).threshold.where == ()


RESPONSE = [
    ("unknown action", "NX-WIN-002", put("response", "action", value="kill_host"), ["response.action:"]),
    ("missing action", "NX-WIN-002", drop("response", "action"), ["response.action: required key is missing"]),
    ("missing target", "NX-WIN-002", drop("response", "target_step"), ["response.target_step: required key is missing"]),
    ("unknown target", "NX-WIN-002", put("response", "target_step", value="nope"), ["response.target_step: unknown step 'nope'"]),
    ("bad target name", "NX-WIN-002", put("response", "target_step", value="bad name"), ["response.target_step:"]),
    ("extra key", "NX-WIN-002", put("response", "dry_run", value=False), ["response.dry_run: unknown key"]),
    ("response below high severity", "NX-WIN-002", put("severity", value="medium"), ["requires severity high or critical"]),
    ("response on a low rule", "NX-LIN-003", put("severity", value="low"), ["requires severity high or critical"]),
    ("response not a mapping", "NX-WIN-002", put("response", value="terminate_process"), ["response"]),
]


@pytest.mark.parametrize("label, base, mutate, needles", RESPONSE, ids=[c[0] for c in RESPONSE])
def test_response_validation(tmp_path, label, base, mutate, needles):
    rejected(tmp_path, base, mutate, *needles)


def test_a_critical_rule_may_respond(tmp_path):
    assert loaded(tmp_path, "NX-WIN-002", put("severity", value="critical")).response.action == "terminate_process"


# ------------------------------------------------------------------ YAML safety
SHIPPED_TEXT = (RULES / "NX-WIN-002.yaml").read_text(encoding="utf-8")


def yaml_rejected(tmp_path: Path, text: str | bytes, needle: str, name: str = "NX-WIN-002.yaml") -> RuleError:
    with pytest.raises(RuleError) as caught:
        load_rule(raw(tmp_path, text, name))
    assert needle in str(caught.value), str(caught.value)
    return caught.value


def test_yaml_syntax_error(tmp_path):
    yaml_rejected(tmp_path, "id: [unterminated\n", "invalid YAML")


def test_duplicate_keys_are_rejected_at_any_depth(tmp_path):
    yaml_rejected(tmp_path, SHIPPED_TEXT + "severity: low\n", "duplicate key 'severity'")
    yaml_rejected(tmp_path, SHIPPED_TEXT.replace("binary: {", "binary: { prefix_any: [\"a\"], prefix_any: [\"b\"],", 1), "duplicate key 'prefix_any'")


def test_more_than_one_document_is_rejected(tmp_path):
    yaml_rejected(tmp_path, SHIPPED_TEXT + "---\nid: NX-WIN-003\n", "more than one YAML document")


def test_anchors_and_aliases_are_rejected(tmp_path):
    yaml_rejected(tmp_path, SHIPPED_TEXT.replace("severity: high", "severity: &s high").replace("kind: single", "kind: *s"), "anchors and aliases")


def test_unsafe_tags_are_not_executed(tmp_path):
    marker = tmp_path / "pwned"
    text = SHIPPED_TEXT.replace("title:", f"x: !!python/object/apply:pathlib.Path.write_text [{json.dumps(str(marker))}, 'x']\ntitle:", 1)
    yaml_rejected(tmp_path, text, "invalid YAML")
    assert not marker.exists()


@pytest.mark.parametrize("text, needle", [
    ("", "file is empty"),
    ("# only a comment\n", "file is empty"),
    ("- a\n- b\n", "top level must be a mapping, found list"),
    ("just a string\n", "top level must be a mapping, found str"),
])
def test_empty_and_non_mapping_files(tmp_path, text, needle):
    yaml_rejected(tmp_path, text, needle)


def test_oversized_and_non_utf8_files(tmp_path):
    yaml_rejected(tmp_path, "# " + "x" * 70_000 + "\n" + SHIPPED_TEXT, "the limit is 65536")
    yaml_rejected(tmp_path, b"id: \xff\xfe\n", "not valid UTF-8")


def test_a_utf8_bom_is_tolerated(tmp_path):
    assert load_rule(raw(tmp_path, b"\xef\xbb\xbf" + SHIPPED_TEXT.encode("utf-8"), "NX-WIN-002.yaml")).id == "NX-WIN-002"


def test_unreadable_paths(tmp_path):
    with pytest.raises(RuleError, match="not a file"):
        load_rule(tmp_path / "NX-WIN-002.yaml")
    with pytest.raises(RuleError, match="not a file"):
        load_rule(tmp_path)


def test_a_rule_file_cannot_set_its_own_source(tmp_path):
    rejected(tmp_path, "NX-WIN-002", put("source", value="/etc/passwd"), "'source' is not a rule key")


# ------------------------------------------------------------------ directories: policy, duplicates, logging
def make_dir(tmp_path: Path, name: str = "rules", only: tuple[str, ...] = ()) -> Path:
    target = tmp_path / name
    target.mkdir(parents=True)
    for rule_id in only or SHIPPED:
        shutil.copy(RULES / f"{rule_id}.yaml", target / f"{rule_id}.yaml")
    return target


def test_a_bad_rule_is_skipped_logged_and_the_rest_still_load(tmp_path, caplog):
    directory = make_dir(tmp_path)
    data = shipped("NX-WIN-001")
    data["severity"] = "urgent"
    write(directory, data, "NX-WIN-001.yaml")
    with caplog.at_level(logging.INFO, logger="nexus_endpoint_core.rules"):
        result = load_rules(directory)
    assert [r.id for r in result] == [i for i in SHIPPED if i != "NX-WIN-001"]
    assert [e.source.name for e in result.errors] == ["NX-WIN-001.yaml"] and "severity:" in result.errors[0].problems[0]
    errors = [r for r in caplog.records if r.levelno == logging.ERROR]
    assert len(errors) == 1 and "NX-WIN-001.yaml" in errors[0].getMessage() and "severity" in errors[0].getMessage()
    assert any("loaded 6 rule(s)" in r.getMessage() and "rejected 1" in r.getMessage() for r in caplog.records)


def test_strict_loading_raises_one_error_listing_every_rejected_rule(tmp_path, caplog):
    directory = make_dir(tmp_path)
    for rid, mutate in (("NX-WIN-001", put("severity", value="urgent")), ("NX-LIN-002", put("threshold", "min_distinct", value=0))):
        data = shipped(rid)
        mutate(data)
        write(directory, data, f"{rid}.yaml")
    with caplog.at_level(logging.ERROR, logger="nexus_endpoint_core.rules"), pytest.raises(RuleLoadError) as caught:
        load_rules(directory, strict=True)
    assert [e.source.name for e in caught.value.errors] == ["NX-LIN-002.yaml", "NX-WIN-001.yaml"]
    assert "NX-LIN-002.yaml" in str(caught.value) and "NX-WIN-001.yaml" in str(caught.value)
    assert len([r for r in caplog.records if r.levelno == logging.ERROR]) == 2


def test_a_duplicate_id_can_never_load_twice(tmp_path, caplog):
    directory = make_dir(tmp_path, only=("NX-WIN-001", "NX-WIN-002"))
    shutil.copy(RULES / "NX-WIN-001.yaml", directory / "NX-WIN-001.copy.yaml")      # same id, different file name
    with caplog.at_level(logging.ERROR, logger="nexus_endpoint_core.rules"):
        result = load_rules(directory)
    assert [r.id for r in result] == ["NX-WIN-001", "NX-WIN-002"]                  # the properly named original stays authoritative
    assert result.get("NX-WIN-001").source.name == "NX-WIN-001.yaml"
    assert [e.source.name for e in result.errors] == ["NX-WIN-001.copy.yaml"]
    assert result.errors[0].problems == ("id: the file must be named NX-WIN-001.yaml, not NX-WIN-001.copy.yaml",)
    assert any("NX-WIN-001.copy.yaml" in r.getMessage() for r in caplog.records)
    with pytest.raises(RuleLoadError):
        load_rules(directory, strict=True)


def test_two_stray_copies_without_an_original_are_both_rejected(tmp_path):
    directory = make_dir(tmp_path, only=("NX-WIN-002",))
    for suffix in ("a", "b"):
        shutil.copy(RULES / "NX-WIN-001.yaml", directory / f"NX-WIN-001.{suffix}.yaml")
    result = load_rules(directory)
    assert [r.id for r in result] == ["NX-WIN-002"] and [e.source.name for e in result.errors] == ["NX-WIN-001.a.yaml", "NX-WIN-001.b.yaml"]


def test_only_exact_yaml_files_are_rules(tmp_path, caplog):
    directory = make_dir(tmp_path, only=("NX-WIN-002",))
    (directory / "RULE-FORMAT.md").write_text("# format", encoding="utf-8")
    (directory / "notes.txt").write_text("x", encoding="utf-8")
    shutil.copy(RULES / "NX-WIN-001.yaml", directory / "NX-WIN-001.yml")
    (directory / "sub").mkdir()
    shutil.copy(RULES / "NX-WIN-003.yaml", directory / "sub" / "NX-WIN-003.yaml")
    with caplog.at_level(logging.WARNING, logger="nexus_endpoint_core.rules"):
        result = load_rules(directory)
    assert [r.id for r in result] == ["NX-WIN-002"] and result.errors == ()
    assert any("NX-WIN-001.yml" in r.getMessage() and "exactly .yaml" in r.getMessage() for r in caplog.records)


def test_empty_directory_warns_and_strict_raises(tmp_path, caplog):
    empty = tmp_path / "empty"
    empty.mkdir()
    with caplog.at_level(logging.WARNING, logger="nexus_endpoint_core.rules"):
        result = load_rules(empty)
    assert len(result) == 0 and result.errors == () and any("no rule files" in r.getMessage() for r in caplog.records)
    with pytest.raises(RuleLoadError, match="no rules found"):
        load_rules(empty, strict=True)


def test_a_missing_directory_raises_in_both_modes(tmp_path):
    for strict in (False, True):
        with pytest.raises(FileNotFoundError):
            load_rules(tmp_path / "nope", strict=strict)
    (tmp_path / "file").write_text("x", encoding="utf-8")
    with pytest.raises(NotADirectoryError):
        load_rules(tmp_path / "file")


def test_loading_is_deterministic_and_idempotent(tmp_path):
    first, second = load_rules(RULES), load_rules(RULES)
    assert first == second and first.rules == second.rules and [r.id for r in first] == sorted(r.id for r in first)


# ------------------------------------------------------------------ immutability
def test_models_are_frozen_and_collections_are_tuples():
    result = load_rules(RULES)
    rule = result.get("NX-WIN-001")
    with pytest.raises(ValidationError):
        rule.severity = "low"
    with pytest.raises(ValidationError):
        rule.steps[0].where[0].op = "equals"
    with pytest.raises(ValidationError):
        rule.context.max_ancestors = 1
    for collection in (result.rules, result.errors, rule.os, rule.technique_ids, rule.references, rule.steps,
                       rule.steps[0].where, result.get("NX-LIN-001").steps[2].where):
        assert isinstance(collection, tuple)
    assert isinstance(rule.steps[0].where[0].operand, tuple)
    assert isinstance(rule.steps[2].where[1].compiled, tuple)
    with pytest.raises(AttributeError):
        rule.steps.append(None)
    with pytest.raises(Exception):
        result.rules = ()                                                   # RuleSet is a frozen dataclass
    assert hash(rule) == hash(load_rules(RULES).get("NX-WIN-001"))          # hashable: usable in sets and dicts


# ------------------------------------------------------------------ ATT&CK mapping
def canonical_layout(tmp_path: Path, name: str = "repo") -> tuple[Path, Path]:
    contracts = tmp_path / name / "contracts"
    rules_dir = contracts / "rules"
    rules_dir.mkdir(parents=True)
    for rid in SHIPPED:
        shutil.copy(RULES / f"{rid}.yaml", rules_dir / f"{rid}.yaml")
    shutil.copy(MAPPING, contracts / "attack-mapping.yaml")
    return rules_dir, contracts / "attack-mapping.yaml"


def edit_mapping(path: Path, mutate: Callable[[dict], None]) -> None:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    mutate(data)
    path.write_text(dump(data), encoding="utf-8")


def test_the_canonical_mapping_loads_and_matches_every_shipped_rule():
    mapping = load_attack_mapping(MAPPING)
    assert isinstance(mapping, AttackMapping) and mapping.source == MAPPING
    assert "T1059.001" in mapping.techniques and mapping.rules["NX-WIN-001"] == ("T1059.001", "T1074.001", "T1105")
    assert set(mapping.rules) == set(SHIPPED)
    with pytest.raises(TypeError):
        mapping.rules["NX-NEW-001"] = ()                                    # read-only mapping
    for rid in SHIPPED:
        assert load_rule(RULES / f"{rid}.yaml", attack_mapping=mapping).technique_ids == mapping.rules[rid]


def test_the_mapping_is_discovered_next_to_the_canonical_rules(tmp_path):
    rules_dir, mapping_path = canonical_layout(tmp_path)
    assert len(load_rules(rules_dir, strict=True)) == 7
    edit_mapping(mapping_path, lambda m: m["rules"].__setitem__("NX-WIN-001", ["T1059.001"]))
    result = load_rules(rules_dir)                                         # discovered, so the mismatch is caught without being asked
    assert [e.source.name for e in result.errors] == ["NX-WIN-001.yaml"]
    assert "differ from the ATT&CK mapping" in result.errors[0].problems[0]


def test_a_missing_mapping_in_the_canonical_layout_is_a_hard_failure(tmp_path):
    rules_dir, mapping_path = canonical_layout(tmp_path)
    mapping_path.unlink()
    for strict in (False, True):
        with pytest.raises(AttackMappingError, match="requires contracts/attack-mapping.yaml"):
            load_rules(rules_dir, strict=strict)


def test_an_independent_directory_may_run_without_a_mapping(tmp_path, caplog):
    directory = make_dir(tmp_path, "independent")
    with caplog.at_level(logging.INFO, logger="nexus_endpoint_core.rules"):
        result = load_rules(directory, strict=True)
    assert len(result) == 7 and any("no ATT&CK mapping found" in r.getMessage() for r in caplog.records)
    data = shipped("NX-WIN-001")
    data["technique_ids"] = ["T9999"]
    write(directory, data, "NX-WIN-001.yaml")
    assert len(load_rules(directory)) == 7                                  # nothing to check against, only the format is checked


def test_a_sibling_mapping_is_used_in_an_independent_layout(tmp_path):
    directory = make_dir(tmp_path / "pack", "rules")
    shutil.copy(MAPPING, directory.parent / "attack-mapping.yaml")
    data = shipped("NX-WIN-001")
    data["technique_ids"] = ["T1059.001"]
    write(directory, data, "NX-WIN-001.yaml")
    result = load_rules(directory)
    assert [e.source.name for e in result.errors] == ["NX-WIN-001.yaml"] and len(result) == 6


def test_an_explicit_mapping_is_required_and_wins(tmp_path):
    directory = make_dir(tmp_path, "independent")
    assert len(load_rules(directory, attack_mapping=MAPPING, strict=True)) == 7
    assert len(load_rules(directory, attack_mapping=load_attack_mapping(MAPPING), strict=True)) == 7
    with pytest.raises(AttackMappingError, match="file not found"):
        load_rules(directory, attack_mapping=tmp_path / "missing.yaml")
    other = tmp_path / "other.yaml"
    shutil.copy(MAPPING, other)
    edit_mapping(other, lambda m: m["rules"].__setitem__("NX-LIN-001", ["T1059.004"]))
    result = load_rules(directory, attack_mapping=other)
    assert [e.source.name for e in result.errors] == ["NX-LIN-001.yaml"]


def test_unknown_technique_and_mismatched_mapping_reject_the_rule(tmp_path):
    mapping = load_attack_mapping(MAPPING)
    rejected(tmp_path, "NX-WIN-001", put("technique_ids", value=["T1059.001", "T1074.001", "T9999"]),
             "technique_ids: T9999 is not defined in the ATT&CK mapping", "differ from the ATT&CK mapping", mapping=mapping)
    rejected(tmp_path, "NX-WIN-001", put("technique_ids", value=["T1105", "T1074.001", "T1059.001"]),
             "differ from the ATT&CK mapping", mapping=mapping)                              # same set, different order
    rejected(tmp_path, "NX-WIN-001", put("technique_ids", value=["T1059.001"]), "differ from the ATT&CK mapping", mapping=mapping)
    rejected(tmp_path, "NX-ANY-001", put("technique_ids", value=["T1005"]), "differ from the ATT&CK mapping", mapping=mapping)


def test_a_rule_missing_from_the_mapping_is_rejected(tmp_path):
    shrunk = tmp_path / "mapping.yaml"
    shutil.copy(MAPPING, shrunk)
    edit_mapping(shrunk, lambda m: m["rules"].__delitem__("NX-WIN-003"))
    directory = make_dir(tmp_path, "independent")
    result = load_rules(directory, attack_mapping=shrunk)
    assert [e.source.name for e in result.errors] == ["NX-WIN-003.yaml"]
    assert "not listed under 'rules' in the ATT&CK mapping" in result.errors[0].problems[0]


def test_a_mapping_entry_without_a_rule_file_is_a_warning(tmp_path, caplog):
    directory = make_dir(tmp_path, "independent", only=tuple(i for i in SHIPPED if i != "NX-WIN-003"))
    with caplog.at_level(logging.WARNING, logger="nexus_endpoint_core.rules"):
        result = load_rules(directory, attack_mapping=MAPPING, strict=True)
    assert len(result) == 6 and any("lists NX-WIN-003 but no rule file" in r.getMessage() for r in caplog.records)


MALFORMED_MAPPINGS = [
    ("not a mapping", lambda m: ["a", "b"], "top level must be a mapping"),
    ("unknown top-level key", lambda m: {**m, "extra": 1}, "extra: unknown key"),
    ("no techniques", lambda m: {"rules": m["rules"]}, "techniques: required"),
    ("empty techniques", lambda m: {**m, "techniques": {}}, "techniques: required"),
    ("no rules", lambda m: {"techniques": m["techniques"]}, "rules: required"),
    ("bad technique id", lambda m: {**m, "techniques": {**m["techniques"], "T12": {"tactic": "x", "name": "y"}}}, "not a technique id"),
    ("technique without a name", lambda m: {**m, "techniques": {**m["techniques"], "T1000": {"tactic": "x"}}}, "needs non-empty 'tactic' and 'name'"),
    ("bad rule id", lambda m: {**m, "rules": {**m["rules"], "NX-BAD": ["T1105"]}}, "not a rule id"),
    ("rule with a string", lambda m: {**m, "rules": {**m["rules"], "NX-WIN-009": "T1105"}}, "expected a non-empty list of technique ids"),
    ("rule with an empty list", lambda m: {**m, "rules": {**m["rules"], "NX-WIN-009": []}}, "expected a non-empty list of technique ids"),
    ("rule with an undefined technique", lambda m: {**m, "rules": {**m["rules"], "NX-WIN-009": ["T9999"]}}, "not defined under 'techniques'"),
    ("rule with duplicates", lambda m: {**m, "rules": {**m["rules"], "NX-WIN-009": ["T1105", "T1105"]}}, "duplicate technique ids"),
]


@pytest.mark.parametrize("label, mutate, needle", MALFORMED_MAPPINGS, ids=[c[0] for c in MALFORMED_MAPPINGS])
def test_a_malformed_mapping_is_a_clear_failure_never_a_silent_skip(tmp_path, label, mutate, needle):
    rules_dir, mapping_path = canonical_layout(tmp_path)
    mapping_path.write_text(dump(mutate(yaml.safe_load(MAPPING.read_text(encoding="utf-8")))), encoding="utf-8")
    for strict in (False, True):
        with pytest.raises(AttackMappingError) as caught:
            load_rules(rules_dir, strict=strict)
        assert needle in str(caught.value) and caught.value.path == mapping_path


@pytest.mark.parametrize("text, needle", [
    ("", "top level must be a mapping"),
    ("techniques: {\n", "invalid YAML"),
    ("techniques: {}\ntechniques: {}\n", "duplicate key 'techniques'"),
])
def test_unparseable_mappings_fail_clearly(tmp_path, text, needle):
    rules_dir, mapping_path = canonical_layout(tmp_path)
    mapping_path.write_text(text, encoding="utf-8")
    with pytest.raises(AttackMappingError, match=re.escape(needle)):
        load_rules(rules_dir)
    with pytest.raises(AttackMappingError, match=re.escape(needle)):
        load_attack_mapping(mapping_path)


def test_a_mapping_directory_instead_of_a_file_is_not_silently_skipped(tmp_path):
    rules_dir, mapping_path = canonical_layout(tmp_path)
    mapping_path.unlink()
    mapping_path.mkdir()
    with pytest.raises(AttackMappingError):
        load_rules(rules_dir)


def test_the_rule_set_type_is_exposed():
    assert isinstance(load_rules(RULES), RuleSet)
