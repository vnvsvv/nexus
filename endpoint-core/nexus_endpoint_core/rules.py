"""Rule loading, validation and pre-compilation (task A2; format: contracts/rules/RULE-FORMAT.md).

This module turns ``contracts/rules/*.yaml`` into immutable, validated ``Rule`` objects. It does not look at
events: evaluation (matching, lineage traversal, windows, suppression) is task A3 and will be added here.

Public API
    ``load_rules(dir, *, attack_mapping=None, strict=False) -> RuleSet``   a directory of rules
    ``load_rule(path, *, attack_mapping=None) -> Rule``                    one file (raises ``RuleError``)
    ``load_attack_mapping(path) -> AttackMapping``                         contracts/attack-mapping.yaml
    ``Rule`` and its parts (``Step``, ``Predicate``, ``Lineage``, ``Context``, ``ThresholdSpec``, ``Scope``,
    ``ResponseSpec``), ``RuleSet``, ``AttackMapping``, ``RuleError``, ``RuleLoadError``, ``AttackMappingError``.

Failure policy
    A rule that fails validation is *rejected*: it is logged at ERROR with its file name and the path of every
    problem, recorded in ``RuleSet.errors``, and the remaining rules still load. ``strict=True`` raises one
    ``RuleLoadError`` listing all rejected rules instead. Problems that make validation of *every* rule
    meaningless raise immediately, in both modes: a missing rules directory, and a missing or malformed ATT&CK
    mapping that is required (see below). A rule file must be named ``<id>.yaml``; that makes duplicate ids
    impossible to load: a stray copy under another name is rejected (naming the file it should be) and the
    correctly named original stays authoritative. Within one rule, field-level problems are reported first;
    cross-field problems (lineage targets, kind consistency, response) appear once those are fixed.

ATT&CK mapping (``contracts/attack-mapping.yaml``)
    * ``attack_mapping=<path>``: required; a missing or malformed file raises ``AttackMappingError``.
    * ``attack_mapping=None`` (default): discovered as ``<rules dir>/../attack-mapping.yaml``. If that file exists
      it is used (and must be well formed). If it does not exist, validation is skipped *unless* the directory
      is laid out like the repository's ``contracts/rules``, where the mapping is mandatory and its absence
      raises ``AttackMappingError``. An independent directory (tests, a packaged rules folder) may therefore
      run without a mapping, but the canonical rules can never silently lose the check.
    * With a mapping, each rule's technique ids must all exist in it and equal the mapping's list for that rule id.

Immutability
    Models are frozen pydantic v2 models; every nested collection is a tuple, ``RuleSet.rules`` and ``.errors``
    are tuples and ``AttackMapping.rules`` is a read-only mapping.

Decisions where the format documents are silent (recorded in endpoint-core/README.md as well)
    * Unknown keys are errors at every level; every step needs a non-empty ``where``; several operators on one
      field are ANDed; fields must suit the step's ``event_type`` and operators must suit the field.
    * ``scope: lineage(N)`` is parsed and its depth kept, but its traversal meaning (descendants only? ancestors
      and descendants?) is NOT defined by RULE-FORMAT.md and is deliberately not interpreted here. It must be
      confirmed before A3 evaluates threshold rules with that scope. No shipped rule uses it.
    * A3 notes: Windows string normalization is applied at match time (``NX-ANY-001`` covers both OSes), so
      operands are kept as authored; regexes are compiled without flags; attacker-controlled strings should be
      truncated before ``re.search`` (the loader only caps pattern length).
"""
from __future__ import annotations

import ipaddress
import logging
import math
import re
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Annotated, Any, Literal, Mapping, NamedTuple, get_args

import yaml
from nexus_contracts.models import OS, Direction, EventType, FileInfo, Proto, Severity
from pydantic import (BaseModel, BeforeValidator, ConfigDict, Field, StrictBool, StrictInt, StrictStr,
                      StringConstraints, ValidationError, field_validator, model_validator)
from yaml.constructor import ConstructorError

log = logging.getLogger(__name__)

MAX_FILE_BYTES = 64 * 1024        # per rule or mapping file
MAX_STEPS = 5                     # docs/02-CORRELATION.md section 3: backtracking depth <= 5
MAX_REGEX_LENGTH = 500
MAX_OPERAND_ITEMS = 1000
MAX_LINEAGE_DEPTH = 10
MAPPING_FILE_NAME = "attack-mapping.yaml"

_TECHNIQUE_RE = r"^T\d{4}(\.\d{3})?$"
_RULE_ID_RE = r"^NX-(LIN|WIN|ANY)-\d{3}$"
_ATTR_KEY = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
_LINEAGE_SCOPE = re.compile(r"^lineage\((\d+)\)$")
_ID_OS = {"LIN": ("linux",), "WIN": ("windows",), "ANY": ("linux", "windows")}

Op = Literal["equals", "in", "prefix_any", "endswith_any", "contains_any", "regex",
             "in_cidr", "not_in_cidr", "gte", "lte"]
OPERATORS: tuple[str, ...] = get_args(Op)
_STRING_OPS = {"prefix_any", "endswith_any", "contains_any", "regex"}
_LIST_OPS = {"in", "prefix_any", "endswith_any", "contains_any", "in_cidr", "not_in_cidr"}
_CIDR_OPS = {"in_cidr", "not_in_cidr"}
_NUMBER_OPS = {"gte", "lte"}

_FILE_OPERATIONS: tuple[str, ...] = get_args(FileInfo.model_fields["operation"].annotation)
_DIRECTIONS: tuple[str, ...] = get_args(Direction)
_PROTOCOLS: tuple[str, ...] = get_args(Proto)


class _Field(NamedTuple):
    kind: Literal["str", "int", "ip", "any"]
    events: frozenset[str] | None = None       # event types that carry the field; None = every event
    values: tuple[str, ...] | None = None      # closed value set, taken from the contract
    int_range: tuple[int, int] | None = None


_PORT = (0, 65535)
_FIELDS: Mapping[str, _Field] = MappingProxyType({
    "binary": _Field("str"),
    "command_line": _Field("str"),
    "user": _Field("str"),
    "sha256": _Field("str"),
    "file.path": _Field("str", frozenset({"file_access"})),
    "file.operation": _Field("str", frozenset({"file_access"}), _FILE_OPERATIONS),
    "network.protocol": _Field("str", frozenset({"network_connect"}), _PROTOCOLS),
    "network.src_port": _Field("int", frozenset({"network_connect"}), None, _PORT),
    "network.dst_ip": _Field("ip", frozenset({"network_connect"})),
    "network.dst_port": _Field("int", frozenset({"network_connect"}), None, _PORT),
    "network.direction": _Field("str", frozenset({"network_connect"}), _DIRECTIONS),
    "dns.query": _Field("str", frozenset({"dns_query"})),
})
_ATTRIBUTE_FIELD = _Field("any")
FIELD_PATHS: frozenset[str] = frozenset(_FIELDS)     # plus ``attributes.<key>``


# ---------------------------------------------------------------------------------------------- exceptions
class RuleError(ValueError):
    """One rule file was rejected. ``problems`` lists every problem found, each prefixed with its path."""

    def __init__(self, source: Path | None, problems: list[str] | tuple[str, ...]) -> None:
        self.source = source
        self.problems = tuple(problems)
        name = source.name if source is not None else "<rule>"
        super().__init__(f"{name}: " + "; ".join(self.problems))


class RuleLoadError(ValueError):
    """``strict=True`` loading found at least one rejected rule (or no rules at all)."""

    def __init__(self, errors: tuple[RuleError, ...], message: str = "") -> None:
        self.errors = errors
        super().__init__(message or f"{len(errors)} rule(s) rejected: " + " | ".join(str(e) for e in errors))


class AttackMappingError(ValueError):
    """The ATT&CK mapping is required but missing or malformed; no rule can be validated against it."""

    def __init__(self, path: Path | None, problems: list[str] | tuple[str, ...]) -> None:
        self.path = path
        self.problems = tuple(problems)
        super().__init__(f"ATT&CK mapping {path}: " + "; ".join(self.problems))


class _Problem(Exception):
    """Internal: one validation problem with a human-readable message."""


# ---------------------------------------------------------------------------------------------- YAML
class _UniqueKeyLoader(yaml.SafeLoader):
    """``safe_load`` that refuses duplicate mapping keys (PyYAML would silently keep the last one)."""

    def construct_mapping(self, node, deep=False):  # noqa: ANN001
        if isinstance(node, yaml.MappingNode):
            seen: set[Any] = set()
            for key_node, _ in node.value:
                key = self.construct_object(key_node, deep=True)
                try:
                    duplicate = key in seen
                except TypeError:
                    raise ConstructorError(None, None, "unhashable mapping key", key_node.start_mark) from None
                if duplicate:
                    raise ConstructorError(None, None, f"duplicate key {key!r}", key_node.start_mark)
                seen.add(key)
        return super().construct_mapping(node, deep=deep)


def _read_yaml(path: Path) -> Any:
    """Parse one small, single-document YAML file with safe tags only; raises ``_Problem``."""
    try:
        if not path.is_file():
            raise _Problem(f"cannot read {path}: not a file")
        size = path.stat().st_size
        if size > MAX_FILE_BYTES:
            raise _Problem(f"file is {size} bytes; the limit is {MAX_FILE_BYTES}")
        raw = path.read_bytes()
    except OSError as e:
        raise _Problem(f"cannot read file: {e.strerror or e}") from None
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise _Problem("file is not valid UTF-8") from None
    try:
        documents = 0
        for event in yaml.parse(text, Loader=yaml.SafeLoader):
            if isinstance(event, yaml.DocumentStartEvent):
                documents += 1
            if isinstance(event, yaml.AliasEvent) or getattr(event, "anchor", None) is not None:
                raise _Problem("YAML anchors and aliases are not allowed")
        if documents > 1:
            raise _Problem("file holds more than one YAML document")
        return yaml.load(text, Loader=_UniqueKeyLoader)  # noqa: S506 - SafeLoader subclass
    except yaml.YAMLError as e:
        raise _Problem("invalid YAML: " + " ".join(str(e).split())) from None


# ---------------------------------------------------------------------------------------------- predicates
def _field_spec(path: str) -> _Field | None:
    if path in _FIELDS:
        return _FIELDS[path]
    if path.startswith("attributes.") and _ATTR_KEY.match(path[len("attributes."):]):
        return _ATTRIBUTE_FIELD
    return None


def _scalar(spec: _Field, value: Any) -> Any:
    """Check one operand value against the field it is compared with; returns it unchanged."""
    if spec.kind == "str":
        if not isinstance(value, str) or not value:
            raise _Problem(f"expected a non-empty string, got {value!r}")
        if spec.values is not None and value not in spec.values:
            raise _Problem(f"{value!r} is not one of {list(spec.values)}")
    elif spec.kind == "int":
        if isinstance(value, bool) or not isinstance(value, int):
            raise _Problem(f"expected an integer, got {value!r}")
        if spec.int_range and not spec.int_range[0] <= value <= spec.int_range[1]:
            raise _Problem(f"{value} is outside {spec.int_range[0]}..{spec.int_range[1]}")
    elif spec.kind == "ip":
        try:
            if not isinstance(value, str):
                raise ValueError
            ipaddress.ip_address(value)
        except ValueError:
            raise _Problem(f"{value!r} is not an IP address") from None
    elif not isinstance(value, (str, int, float, bool)) or (isinstance(value, float) and not math.isfinite(value)):
        raise _Problem(f"expected a string, number or boolean, got {value!r}")
    return value


def _string_list(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise _Problem("expected a non-empty list")
    if len(value) > MAX_OPERAND_ITEMS:
        raise _Problem(f"list has {len(value)} items; the limit is {MAX_OPERAND_ITEMS}")
    for item in value:
        if not isinstance(item, str) or not item:
            raise _Problem(f"expected non-empty strings, found {item!r}")
    return tuple(value)


class Predicate(BaseModel):
    """One ``field op operand`` test, with its operand validated and (for regex/CIDR) compiled once."""

    model_config = ConfigDict(frozen=True, extra="forbid", arbitrary_types_allowed=True)

    field: str
    op: Op
    operand: Any                 # scalar | tuple of scalars | regex source | number (as authored)
    compiled: Any = None         # re.Pattern for regex; tuple of ip_network for in_cidr / not_in_cidr


def _predicate(field: str, spec: _Field, op: Any, operand: Any) -> Predicate:
    if op not in OPERATORS:
        raise _Problem(f"unknown operator {op!r} (allowed: {', '.join(OPERATORS)})")
    compiled: Any = None
    if op in _STRING_OPS and not (spec.kind == "any" or (spec.kind == "str" and spec.values is None)):
        raise _Problem(f"operator {op} needs a free-text field, but {field} is {spec.kind}"
                       + (" with a closed value set" if spec.values else ""))
    if op in _CIDR_OPS and spec.kind != "ip":
        raise _Problem(f"operator {op} only applies to an IP address field, not {field}")
    if op in _NUMBER_OPS and spec.kind not in ("int", "any"):
        raise _Problem(f"operator {op} only applies to a numeric field, not {field}")
    if op == "equals":
        _scalar(spec, operand)
        value: Any = operand
    elif op == "in":
        items = operand
        if not isinstance(items, list) or not items:
            raise _Problem("expected a non-empty list")
        if len(items) > MAX_OPERAND_ITEMS:
            raise _Problem(f"list has {len(items)} items; the limit is {MAX_OPERAND_ITEMS}")
        for item in items:
            _scalar(spec, item)
        value = tuple(items)
    elif op in ("prefix_any", "endswith_any", "contains_any"):
        value = _string_list(operand)
    elif op == "regex":
        if not isinstance(operand, str) or not operand:
            raise _Problem("expected a non-empty regular expression string")
        if len(operand) > MAX_REGEX_LENGTH:
            raise _Problem(f"regular expression is {len(operand)} characters; the limit is {MAX_REGEX_LENGTH}")
        try:
            compiled = re.compile(operand)
        except re.error as e:
            raise _Problem(f"invalid regular expression: {e}") from None
        value = operand
    elif op in _CIDR_OPS:
        networks = []
        for text in _string_list(operand):
            try:
                networks.append(ipaddress.ip_network(text, strict=True))
            except ValueError as e:
                raise _Problem(f"invalid CIDR {text!r}: {e}") from None
        value, compiled = tuple(operand), tuple(networks)
    else:  # gte / lte
        if isinstance(operand, bool) or not isinstance(operand, (int, float)) or not math.isfinite(operand):
            raise _Problem(f"expected a finite number, got {operand!r}")
        value = operand
    return Predicate(field=field, op=op, operand=value, compiled=compiled)


def _compile_where(where: Any, event_type: Any, *, allow_empty: bool = False) -> tuple[Predicate, ...]:
    """YAML ``where`` mapping -> tuple of predicates; raises ValueError listing every problem (one per line)."""
    if where is None and allow_empty:
        return ()
    if not isinstance(where, dict) or (not where and not allow_empty):
        raise ValueError("where must be a non-empty mapping of field path to {operator: operand}")
    problems: list[str] = []
    out: list[Predicate] = []
    for field, ops in where.items():
        label = f"where[{field!r}]"
        spec = _field_spec(field) if isinstance(field, str) else None
        if spec is None:
            problems.append(f"{label}: unknown field path (allowed: {', '.join(sorted(FIELD_PATHS))}, attributes.<key>)")
            continue
        if spec.events is not None and event_type in get_args(EventType) and event_type not in spec.events:
            problems.append(f"{label}: this field is only present on {sorted(spec.events)} events, not {event_type}")
            continue
        if not isinstance(ops, dict) or not ops:
            problems.append(f"{label}: expected a non-empty mapping of operator to operand")
            continue
        for op, operand in ops.items():
            try:
                out.append(_predicate(field, spec, op, operand))
            except _Problem as e:
                problems.append(f"{label}.{op}: {e}")
    if problems:
        raise ValueError("\n".join(problems))
    return tuple(out)


# ---------------------------------------------------------------------------------------------- rule models
def _number(value: Any) -> Any:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise ValueError("must be a finite number")
    return value


def _positive(value: Any) -> Any:
    if value <= 0:
        raise ValueError("must be greater than 0")
    return value


class _Model(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


Name = Annotated[str, StringConstraints(strict=True, pattern=r"^[A-Za-z_][A-Za-z0-9_]{0,31}$")]
Text = Annotated[str, StringConstraints(strict=True, min_length=1, max_length=200)]
Number = Annotated[float | int, BeforeValidator(_number)]


class Lineage(_Model):
    relation: Literal["same", "child_of", "descendant_of"]
    of: Name
    max_depth: Annotated[StrictInt, Field(ge=1, le=MAX_LINEAGE_DEPTH)] | None = None
    include_self: StrictBool = False

    @model_validator(mode="after")
    def _relation_rules(self) -> Lineage:
        if self.relation == "descendant_of":
            if self.max_depth is None:
                raise ValueError("max_depth is required for relation descendant_of")
        else:
            for key in ("max_depth", "include_self"):
                if key in self.model_fields_set:
                    raise ValueError(f"{key} is only allowed with relation descendant_of")
        return self


class Step(_Model):
    name: Name = Field(alias="step")
    event_type: EventType
    where: tuple[Predicate, ...] = Field(min_length=1)
    lineage: Lineage | None = None

    @model_validator(mode="before")
    @classmethod
    def _compile(cls, data: Any) -> Any:
        if isinstance(data, dict) and "where" in data:
            data = {**data, "where": _compile_where(data["where"], data.get("event_type"))}
        return data


class Context(_Model):
    max_ancestors: Annotated[StrictInt, Field(ge=0, le=MAX_LINEAGE_DEPTH)] = 3     # docs/02 section 4: default 3
    max_descendant_depth: Annotated[StrictInt, Field(ge=0, le=MAX_LINEAGE_DEPTH)]
    incident_window_seconds: Number

    check_window = field_validator("incident_window_seconds")(_positive)


class Scope(_Model):
    """Threshold scope. ``lineage`` keeps its depth; what it traverses is undefined until A3 (see module docstring)."""

    kind: Literal["process", "lineage"]
    depth: Annotated[StrictInt, Field(ge=1, le=MAX_LINEAGE_DEPTH)] | None = None

    @model_validator(mode="after")
    def _depth(self) -> Scope:
        if (self.kind == "lineage") != (self.depth is not None):
            raise ValueError("lineage scope needs a depth, process scope has none")
        return self


class ThresholdSpec(_Model):
    event_type: EventType
    where: tuple[Predicate, ...] = ()
    scope: Scope
    distinct_field: str
    group_by: str | None = None
    min_distinct: Annotated[StrictInt, Field(ge=1, le=100_000)]
    window_seconds: Number

    check_window = field_validator("window_seconds")(_positive)

    @model_validator(mode="before")
    @classmethod
    def _compile(cls, data: Any) -> Any:
        if isinstance(data, dict):
            data = dict(data)
            if "where" in data:
                data["where"] = _compile_where(data["where"], data.get("event_type"), allow_empty=True)
        return data

    @field_validator("scope", mode="before")
    @classmethod
    def _parse_scope(cls, value: Any) -> Any:
        if isinstance(value, Scope):
            return value
        if value == "process":
            return Scope(kind="process")
        match = _LINEAGE_SCOPE.match(value) if isinstance(value, str) else None
        if match is None:
            raise ValueError("must be the string 'process' or 'lineage(N)' with N a whole number")
        depth = int(match.group(1))
        if not 1 <= depth <= MAX_LINEAGE_DEPTH:
            raise ValueError(f"lineage depth must be 1..{MAX_LINEAGE_DEPTH}, found {depth}")
        return Scope(kind="lineage", depth=depth)

    @model_validator(mode="after")
    def _fields(self) -> ThresholdSpec:
        problems = []
        for key in ("distinct_field", "group_by"):
            path = getattr(self, key)
            if path is None:
                continue
            spec = _field_spec(path)
            if spec is None:
                problems.append(f"{key}: unknown field path {path!r}")
            elif spec.events is not None and self.event_type not in spec.events:
                problems.append(f"{key}: {path} is only present on {sorted(spec.events)} events, not {self.event_type}")
        if problems:
            raise ValueError("\n".join(problems))
        return self


class ResponseSpec(_Model):
    action: Literal["terminate_process"]
    target_step: Name


class Rule(_Model):
    id: Annotated[str, StringConstraints(strict=True, pattern=_RULE_ID_RE)]
    version: Annotated[str, StringConstraints(strict=True, min_length=1, max_length=20)]
    title: Text
    kind: Literal["single", "sequence", "threshold"]
    os: Annotated[tuple[OS, ...], Field(min_length=1)]
    severity: Severity
    technique_ids: Annotated[tuple[Annotated[str, StringConstraints(strict=True, pattern=_TECHNIQUE_RE)], ...],
                             Field(min_length=1)]
    references: tuple[Text, ...] = ()
    window_seconds: Number | None = None
    ordered: StrictBool | None = None
    context: Context
    steps: tuple[Step, ...] = ()
    threshold: ThresholdSpec | None = None
    response: ResponseSpec | None = None
    source: Path | None = None                     # set by the loader; never read from YAML

    @field_validator("window_seconds")
    @classmethod
    def _window(cls, value: Any) -> Any:
        return value if value is None else _positive(value)

    @model_validator(mode="before")
    @classmethod
    def _no_source(cls, data: Any) -> Any:
        if isinstance(data, dict) and "source" in data:
            raise ValueError("'source' is not a rule key")
        return data

    @model_validator(mode="after")
    def _consistency(self) -> Rule:
        given, problems = self.model_fields_set, []
        if len(set(self.os)) != len(self.os):
            problems.append("os: duplicate entries")
        if len(set(self.technique_ids)) != len(self.technique_ids):
            problems.append("technique_ids: duplicate entries")
        expected_os = _ID_OS[self.id.split("-")[1]]
        if set(self.os) != set(expected_os):
            problems.append(f"os: a {self.id.rsplit('-', 1)[0]} rule must declare os {list(expected_os)}, found {list(self.os)}")
        names = [s.name for s in self.steps]
        if len(set(names)) != len(names):
            problems.append("steps: step names must be unique")

        if self.kind == "threshold":
            for key in ("steps", "window_seconds", "ordered", "response"):
                if key in given and (key != "steps" or self.steps):
                    problems.append(f"{key}: not allowed on a threshold rule" + (" (it has its own window_seconds)" if key == "window_seconds" else ""))
            if self.threshold is None:
                problems.append("threshold: required for kind threshold")
        else:
            if self.threshold is not None:
                problems.append(f"threshold: not allowed on a {self.kind} rule")
            if self.window_seconds is None:
                problems.append("window_seconds: required for single and sequence rules")
            if self.kind == "single":
                if len(self.steps) != 1:
                    problems.append(f"steps: a single rule has exactly one step, found {len(self.steps)}")
                if "ordered" in given:
                    problems.append("ordered: only allowed on a sequence rule")
            elif not 2 <= len(self.steps) <= MAX_STEPS:
                problems.append(f"steps: a sequence rule has 2 to {MAX_STEPS} steps, found {len(self.steps)}")
            ordered = True if self.ordered is None else self.ordered
            index = {name: i for i, name in enumerate(names)}
            for i, step in enumerate(self.steps):
                if step.lineage is None:
                    continue
                target = step.lineage.of
                if target not in index:
                    problems.append(f"steps[{i}].lineage.of: unknown step {target!r}")
                elif target == step.name:
                    problems.append(f"steps[{i}].lineage.of: a step cannot refer to itself")
                elif self.kind == "sequence" and ordered and index[target] > i:
                    problems.append(f"steps[{i}].lineage.of: {target!r} must be an earlier step in an ordered rule")
            lineage_of = {s.name: s.lineage.of for s in self.steps if s.lineage is not None}
            for start in lineage_of:
                seen, cur = set(), start
                while cur in lineage_of and cur not in seen:
                    seen.add(cur)
                    cur = lineage_of[cur]
                if cur in seen and cur == start and lineage_of[start] != start:
                    problems.append(f"steps: lineage forms a cycle through {start!r}")
                    break
            if self.response is not None:
                if self.response.target_step not in index:
                    problems.append(f"response.target_step: unknown step {self.response.target_step!r}")
                if self.severity not in ("high", "critical"):
                    problems.append("response: automatic response requires severity high or critical (docs/04 section 3.1)")
        if problems:
            raise ValueError("\n".join(problems))
        return self


# ---------------------------------------------------------------------------------------------- ATT&CK mapping
@dataclass(frozen=True)
class AttackMapping:
    techniques: frozenset[str]
    rules: Mapping[str, tuple[str, ...]]
    source: Path | None = None


def load_attack_mapping(path: str | Path) -> AttackMapping:
    """Load and validate ``contracts/attack-mapping.yaml``; raises ``AttackMappingError`` on any problem."""
    path = Path(path)
    if not path.exists():
        raise AttackMappingError(path, ["file not found"])
    try:
        data = _read_yaml(path)
    except _Problem as e:
        raise AttackMappingError(path, [str(e)]) from None
    problems: list[str] = []
    if not isinstance(data, dict):
        raise AttackMappingError(path, ["top level must be a mapping with 'techniques' and 'rules'"])
    for key in data:
        if key not in ("techniques", "rules"):
            problems.append(f"{key}: unknown key")
    techniques, rules = data.get("techniques"), data.get("rules")
    ids: set[str] = set()
    if not isinstance(techniques, dict) or not techniques:
        problems.append("techniques: required, a non-empty mapping of technique id to {tactic, name}")
    else:
        for tid, info in techniques.items():
            if not isinstance(tid, str) or not re.match(_TECHNIQUE_RE, tid):
                problems.append(f"techniques[{tid!r}]: not a technique id such as T1059.001")
                continue
            ids.add(tid)
            if not isinstance(info, dict) or not all(isinstance(info.get(k), str) and info.get(k) for k in ("tactic", "name")):
                problems.append(f"techniques[{tid!r}]: needs non-empty 'tactic' and 'name'")
    by_rule: dict[str, tuple[str, ...]] = {}
    if not isinstance(rules, dict) or not rules:
        problems.append("rules: required, a non-empty mapping of rule id to a list of technique ids")
    else:
        for rid, listed in rules.items():
            if not isinstance(rid, str) or not re.match(_RULE_ID_RE, rid):
                problems.append(f"rules[{rid!r}]: not a rule id such as NX-WIN-001")
            elif not isinstance(listed, list) or not listed or not all(isinstance(t, str) for t in listed):
                problems.append(f"rules[{rid!r}]: expected a non-empty list of technique ids")
            else:
                unknown = [t for t in listed if t not in ids]
                if unknown:
                    problems.append(f"rules[{rid!r}]: technique(s) {unknown} are not defined under 'techniques'")
                if len(set(listed)) != len(listed):
                    problems.append(f"rules[{rid!r}]: duplicate technique ids")
                by_rule[rid] = tuple(listed)
    if problems:
        raise AttackMappingError(path, problems)
    return AttackMapping(frozenset(ids), MappingProxyType(by_rule), path)


def _mapping_problems(rule: Rule, mapping: AttackMapping) -> list[str]:
    out = [f"technique_ids: {t} is not defined in the ATT&CK mapping" for t in rule.technique_ids if t not in mapping.techniques]
    expected = mapping.rules.get(rule.id)
    if expected is None:
        out.append("id: this rule is not listed under 'rules' in the ATT&CK mapping")
    elif tuple(rule.technique_ids) != expected:
        out.append(f"technique_ids: {list(rule.technique_ids)} differ from the ATT&CK mapping {list(expected)}")
    return out


def _resolve_mapping(rules_dir: Path, explicit: str | Path | AttackMapping | None) -> AttackMapping | None:
    if isinstance(explicit, AttackMapping):
        return explicit
    if explicit is not None:
        return load_attack_mapping(explicit)
    sibling = rules_dir.parent / MAPPING_FILE_NAME
    if sibling.is_file():
        return load_attack_mapping(sibling)
    resolved = rules_dir.resolve()
    if resolved.name == "rules" and resolved.parent.name == "contracts":
        raise AttackMappingError(sibling, ["the repository layout contracts/rules requires contracts/attack-mapping.yaml, which is missing"])
    log.info("no ATT&CK mapping found next to %s; technique ids are checked for format only", rules_dir)
    return None


# ---------------------------------------------------------------------------------------------- loading
def _format_errors(error: ValidationError) -> list[str]:
    problems: list[str] = []
    for item in error.errors(include_url=False):
        path = ""
        for part in item["loc"]:
            path += f"[{part}]" if isinstance(part, int) else (f".{part}" if path else str(part))
        if item["type"] == "missing":
            lines = ["required key is missing"]
        elif item["type"] == "extra_forbidden":
            lines = ["unknown key"]
        else:
            lines = item["msg"].removeprefix("Value error, ").splitlines() or [item["msg"]]
        problems += [f"{path}: {line}" if path else line for line in lines]
    return list(dict.fromkeys(problems))


def load_rule(path: str | Path, *, attack_mapping: AttackMapping | None = None) -> Rule:
    """Load one rule file; raises ``RuleError`` listing every problem found."""
    path = Path(path)
    try:
        data = _read_yaml(path)
    except _Problem as e:
        raise RuleError(path, [str(e)]) from None
    if data is None:
        raise RuleError(path, ["file is empty"])
    if not isinstance(data, dict):
        raise RuleError(path, [f"top level must be a mapping, found {type(data).__name__}"])
    problems: list[str] = []
    rule: Rule | None = None
    try:
        rule = Rule.model_validate(data)
    except ValidationError as e:
        problems += _format_errors(e)
    rule_id = data.get("id")
    if isinstance(rule_id, str) and path.stem != rule_id:
        problems.append(f"id: the file must be named {rule_id}.yaml, not {path.name}")
    if rule is not None and attack_mapping is not None:
        problems += _mapping_problems(rule, attack_mapping)
    if problems or rule is None:
        raise RuleError(path, problems or ["rule failed validation"])
    return rule.model_copy(update={"source": path})


@dataclass(frozen=True)
class RuleSet:
    rules: tuple[Rule, ...]                 # valid rules, sorted by id
    errors: tuple[RuleError, ...] = ()      # rejected rules, in file order
    directory: Path | None = None

    def __len__(self) -> int:
        return len(self.rules)

    def __iter__(self):
        return iter(self.rules)

    def get(self, rule_id: str) -> Rule | None:
        return next((r for r in self.rules if r.id == rule_id), None)

    def for_os(self, os: str) -> tuple[Rule, ...]:
        return tuple(r for r in self.rules if os in r.os)


def load_rules(rules_dir: str | Path, *, attack_mapping: str | Path | AttackMapping | None = None,
               strict: bool = False) -> RuleSet:
    """Load every ``*.yaml`` rule in a directory (not recursive); see the module docstring for the policy."""
    rules_dir = Path(rules_dir)
    if not rules_dir.exists():
        raise FileNotFoundError(f"rules directory not found: {rules_dir}")
    if not rules_dir.is_dir():
        raise NotADirectoryError(f"not a directory: {rules_dir}")
    mapping = _resolve_mapping(rules_dir, attack_mapping)

    entries = sorted(p for p in rules_dir.iterdir() if p.is_file())
    for p in entries:
        if p.suffix.lower() in (".yml", ".yaml") and p.suffix != ".yaml":
            log.warning("ignoring %s: rule files must end in exactly .yaml", p.name)
    loaded: list[Rule] = []
    errors: list[RuleError] = []
    for path in (p for p in entries if p.suffix == ".yaml"):
        try:
            loaded.append(load_rule(path, attack_mapping=mapping))
        except RuleError as e:
            errors.append(e)

    # No duplicate-id pass is needed: ``load_rule`` requires the file to be named ``<id>.yaml``, so two files
    # in one directory can never both be accepted with the same id. A stray copy (``NX-WIN-001.copy.yaml``) is
    # rejected for its name and the correctly named original stays the one authoritative definition.
    accepted = sorted(loaded, key=lambda r: r.id)

    for error in errors:
        log.error("rule rejected: %s", error)
    if mapping is not None:
        for rule_id in sorted(set(mapping.rules) - {r.id for r in accepted} - {e.source.stem for e in errors if e.source}):
            log.warning("ATT&CK mapping lists %s but no rule file for it was found in %s", rule_id, rules_dir)
    if not any(p.suffix == ".yaml" for p in entries):
        log.warning("no rule files (*.yaml) found in %s", rules_dir)
    log.info("loaded %d rule(s) from %s; rejected %d", len(accepted), rules_dir, len(errors))

    result = RuleSet(tuple(accepted), tuple(errors), rules_dir)
    if strict and (errors or not accepted):
        raise RuleLoadError(result.errors, "" if errors else f"no rules found in {rules_dir}")
    return result
