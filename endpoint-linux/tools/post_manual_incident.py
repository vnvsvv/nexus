"""Build and submit the G1 incident for one recorded Linux L1 run."""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import ssl
import sys
from collections.abc import Iterable, Iterator
from datetime import datetime, timedelta
from http.client import HTTPConnection, HTTPException, HTTPSConnection
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import yaml

from nexus_contracts import (
    EvidenceItem,
    Gap,
    HostConnection,
    HostEvent,
    Incident,
    LocalResponse,
    ProcessNode,
    Relationship,
    RuleMatch,
    utc_now_iso,
    validate_against_schema,
)
from nexus_contracts.models import Basis

ROOT = Path(__file__).resolve().parents[2]
RULE_PATH = ROOT / "contracts/rules/NX-LIN-001.yaml"
ROLES = ("interp", "shell", "reader", "client")


class IncidentError(ValueError):
    """The captured run or its submission could not be verified."""


def read_events(path: Path) -> Iterator[HostEvent]:
    with path.open(encoding="utf-8") as source:
        for number, line in enumerate(source, 1):
            if not line.strip():
                continue
            try:
                payload = json.loads(line)
                if validate_against_schema("host_event", payload):
                    raise ValueError
                yield HostEvent.model_validate(payload)
            except ValueError as exc:
                raise IncidentError(
                    f"invalid HostEvent on JSONL line {number}"
                ) from exc


def utc(value: str) -> datetime:
    time = datetime.fromisoformat(value)
    if (
        time.utcoffset() != timedelta(0)
        or time.isoformat(timespec="milliseconds").replace("+00:00", "Z") != value
    ):
        raise IncidentError("timestamps must be UTC with milliseconds and Z")
    return time


def from_export(event: HostEvent, endpoint: str) -> bool:
    ref = event.attributes.get("raw_ref")
    if event.os != "linux" or event.attributes.get("sensor") != "tetragon":
        return False
    if not isinstance(ref, str):
        return False
    path_text, *coordinates = ref.rsplit(":", 4)
    path = Path(path_text)
    if (
        not path.is_absolute()
        or len(coordinates) != 4
        or not all(value.isdecimal() for value in coordinates)
    ):
        return False
    path = path.resolve()
    if path.is_relative_to(ROOT / "contracts/fixtures") or path.is_relative_to(
        ROOT / "endpoint-linux/tests/data"
    ):
        return False
    return event.process_instance_id.startswith(
        f"{endpoint}:"
    ) and event.event_id.startswith(f"{endpoint}:evt-")


def unique(events: list[HostEvent], role: str) -> HostEvent:
    if len(events) != 1:
        raise IncidentError(f"missing or ambiguous {role} observation")
    return events[0]


def build_incident(events: Iterable[HostEvent], manifest: dict[str, Any]) -> Incident:
    rule = yaml.safe_load(RULE_PATH.read_text(encoding="utf-8"))
    interp, shell, read, net = (step["where"] for step in rule["steps"])
    window = timedelta(seconds=rule["window_seconds"])
    if manifest["scenario"] != "L1":
        raise IncidentError("an L1 run manifest is required")
    endpoint = manifest["endpoint_id"]
    start, end = utc(manifest["start_utc"]), utc(manifest["end_utc"])
    if end < start:
        raise IncidentError("the manifest time bounds are reversed")
    steps = manifest["steps"]
    processes = [step for step in steps if step["kind"] == "process"]
    roles = {step["role"]: step for step in processes}
    pids = {step["pid"] for step in processes}
    if (
        set(roles) != set(ROLES)
        or len(processes) != len(pids)
        or len(pids) != len(ROLES)
        or manifest["root_pid"] != roles["interp"]["pid"]
        or any(type(pid) is not int or pid <= 0 for pid in pids)
    ):
        raise IncidentError("the manifest needs four distinct observed process PIDs")

    candidates = [
        event
        for event in events
        if event.endpoint_id == endpoint
        and event.pid in pids
        and from_export(event, endpoint)
        and start - window <= utc(event.timestamp_utc) <= end
    ]
    if len({event.event_id for event in candidates}) != len(candidates):
        raise IncidentError("the capture contains duplicate event IDs")

    starts: dict[str, HostEvent] = {}
    for role in ROLES:
        identity = roles[role]
        binaries = {identity["binary"], identity.get("invoked_binary")}
        starts[role] = unique(
            [
                event
                for event in candidates
                if event.event_type == "process_start"
                and event.attributes.get("identity_resolution") == "native"
                and event.pid == identity["pid"]
                and event.binary in binaries
                and (event.ppid is None or event.ppid == identity["parent_pid"])
                and (role == "interp" or utc(event.timestamp_utc) >= start)
            ],
            f"{role} process start",
        )
    root, parent, reader, client = (starts[role] for role in ROLES)
    if not root.binary.endswith(
        tuple(interp["binary"]["endswith_any"])
    ) or not parent.binary.endswith(tuple(shell["binary"]["endswith_any"])):
        raise IncidentError("the interpreter or shell does not satisfy NX-LIN-001")
    for role, observed_parent in (
        ("shell", root),
        ("reader", parent),
        ("client", parent),
    ):
        child = starts[role]
        if (
            roles[role]["parent_pid"] != observed_parent.pid
            or child.parent_process_instance_id != observed_parent.process_instance_id
            or utc(child.timestamp_utc) < utc(observed_parent.timestamp_utc)
        ):
            raise IncidentError(f"the {role} parent was not observed as required by L1")

    files = {
        step["path"]
        for step in steps
        if step["kind"] == "file"
        and step["pid"] == reader.pid
        and step["operation"] == read["file.operation"]["equals"]
    }
    reads = sorted(
        (
            event
            for event in candidates
            if event.event_type == "file_access"
            and belongs_to(event, reader)
            and event.attributes.get("sensor_event_id") == "security_file_permission"
            and event.file is not None
            and event.file.operation == read["file.operation"]["equals"]
            and event.file.path in files
            and event.file.path.startswith(tuple(read["file.path"]["prefix_any"]))
            and utc(event.timestamp_utc) <= utc(client.timestamp_utc)
        ),
        key=lambda event: event.timestamp_utc,
    )
    if not reads:
        raise IncidentError("no protected canary read was observed before curl started")
    read_event = reads[0]
    sockets = [
        step
        for step in steps
        if step["kind"] == "connection" and step["pid"] == client.pid
    ]
    if len(sockets) > 1:
        raise IncidentError("the manifest gives multiple curl connection observations")
    excluded = [
        ipaddress.ip_network(cidr) for cidr in net["network.dst_ip"]["not_in_cidr"]
    ]
    net_event = unique(
        [
            event
            for event in candidates
            if event.event_type == "network_connect"
            and belongs_to(event, client)
            and event.attributes.get("sensor_event_id") == "tcp_connect"
            and tcp_matches(
                event,
                manifest["target"],
                sockets,
                net["network.direction"]["equals"],
                excluded,
            )
            and utc(event.timestamp_utc) - utc(root.timestamp_utc) <= window
        ],
        "complete outbound TCP",
    )
    return assemble(rule, starts, read_event, net_event, candidates)


def belongs_to(event: HostEvent, process: HostEvent) -> bool:
    return (
        event.process_instance_id == process.process_instance_id
        and event.pid == process.pid
        and event.binary == process.binary
        and event.attributes.get("identity_resolution") in {"native", "pid_start_time"}
        and event.parent_process_instance_id
        in {None, process.parent_process_instance_id}
        and (event.ppid is None or process.ppid is None or event.ppid == process.ppid)
        and utc(event.timestamp_utc) >= utc(process.timestamp_utc)
    )


def tcp_matches(
    event: HostEvent,
    target: dict[str, Any],
    sockets: list[dict[str, Any]],
    direction: str,
    excluded: list[ipaddress.IPv4Network | ipaddress.IPv6Network],
) -> bool:
    tcp = event.network
    if tcp is None or tcp.protocol != "TCP" or tcp.direction != direction:
        return False
    source = ipaddress.ip_address(tcp.src_ip)
    destination = ipaddress.ip_address(tcp.dst_ip)
    return (
        source.version == destination.version
        and not (source.is_unspecified or destination.is_unspecified)
        and not any(destination in cidr for cidr in excluded)
        and 0 < tcp.src_port <= 65535
        and 0 < tcp.dst_port <= 65535
        and tcp.dst_ip == target["dst_ip"]
        and tcp.dst_port == target["dst_port"]
        and all(
            observed[key] == value
            for observed in sockets
            for key, value in tcp.model_dump().items()
            if key in observed
        )
    )


def assemble(
    rule: dict[str, Any],
    starts: dict[str, HostEvent],
    read: HostEvent,
    net: HostEvent,
    candidates: list[HostEvent],
) -> Incident:
    root = starts["interp"]
    assert read.file is not None and net.network is not None
    gaps: list[Gap] = []
    if root.parent_process_instance_id is None:
        gaps.append(
            Gap(
                code="PARENT_NOT_OBSERVED",
                message="Tetragon did not identify the interpreter's parent.",
                related=[root.event_id],
            )
        )
    links: list[Relationship] = []
    nodes: list[ProcessNode] = []
    evidence_events = [*starts.values(), read, net]
    bindings = dict(
        zip(
            ("interp", "shell", "read", "net"),
            (root.event_id, starts["shell"].event_id, read.event_id, net.event_id),
            strict=True,
        )
    )
    matched = set(bindings.values())
    for role, event in starts.items():
        exits = [
            item
            for item in candidates
            if item.event_type == "process_exit"
            and item.attributes.get("identity_resolution") == "native"
            and belongs_to(item, event)
        ]
        exit_event = exits[0] if len(exits) == 1 else None
        if exit_event is not None:
            evidence_events.append(exit_event)
        nodes.append(
            ProcessNode(
                process_instance_id=event.process_instance_id,
                parent_process_instance_id=event.parent_process_instance_id,
                pid=event.pid,
                binary=event.binary,
                command_line=event.command_line,
                user=event.user,
                sha256=event.sha256,
                start_time_utc=event.process_start_time_utc,
                end_time_utc=exit_event.timestamp_utc if exit_event else None,
                role="root" if role == "interp" else "matched",
            )
        )
        if role != "interp":
            assert event.parent_process_instance_id is not None
            links.append(
                Relationship(
                    type="PARENT_OF",
                    from_=event.parent_process_instance_id,
                    to=event.process_instance_id,
                    basis="observed",
                    evidence_event_ids=[event.event_id],
                )
            )

    net_info = net.network
    net_host = f"[{net_info.dst_ip}]" if ":" in net_info.dst_ip else net_info.dst_ip
    for kind, event, target in (
        ("ACCESSED_FILE", read, f"file:{read.file.path}"),
        (
            "CONNECTED_TO",
            net,
            f"net:{net_host}:{net_info.dst_port}/{net_info.protocol}",
        ),
    ):
        basis: Basis = "observed"
        if event.attributes["identity_resolution"] == "pid_start_time":
            basis = "inferred"
            gaps.append(
                Gap(
                    code="IDENTITY_INFERRED",
                    message="The adapter resolved this probe by PID and start time.",
                    related=[event.event_id, event.process_instance_id],
                )
            )
        links.append(
            Relationship(
                type=kind,
                from_=event.process_instance_id,
                to=target,
                basis=basis,
                evidence_event_ids=[event.event_id],
            )
        )

    token = net.event_id.rsplit(":evt-", 1)[1]
    stamp = net.timestamp_utc[:19].replace("-", "").replace(":", "")
    now = utc_now_iso()
    return Incident(
        incident_id=f"{root.endpoint_id}:INC-{stamp}-{token}",
        incident_version=1,
        endpoint_id=root.endpoint_id,
        os="linux",
        status="open",
        detected_at_utc=now,
        updated_at_utc=now,
        severity=rule["severity"],
        confidence="medium" if gaps else "high",
        title=f"{rule['id']} — manual Linux L1",
        rule_matches=[
            RuleMatch(
                rule_id=rule["id"],
                rule_version=rule["version"],
                matched_at_utc=now,
                bindings=bindings,
            )
        ],
        technique_ids=rule["technique_ids"],
        root_process_instance_id=root.process_instance_id,
        process_nodes=nodes,
        relationships=links,
        evidence=[
            EvidenceItem(
                event_id=event.event_id,
                role="matched" if event.event_id in matched else "context",
                event=event,
            )
            for event in sorted(evidence_events, key=lambda event: event.timestamp_utc)
        ],
        connections=[
            HostConnection(
                connection_id=f"conn-{token}",
                process_instance_id=net.process_instance_id,
                first_seen_utc=net.timestamp_utc,
                evidence_event_ids=[net.event_id],
                **net_info.model_dump(),
            )
        ],
        gaps=gaps,
        local_response=LocalResponse(),
    )


def incident_payload(incident: Incident) -> dict[str, Any]:
    """Serialize the incident for transmission with process command lines omitted."""
    payload = incident.model_dump(
        mode="json",
        by_alias=True,
        exclude_none=True,
        exclude={
            "process_nodes": {"__all__": {"command_line"}},
            "evidence": {"__all__": {"event": {"command_line"}}},
        },
    )
    if validate_against_schema("incident", payload):
        raise IncidentError("the incident does not pass the canonical JSON Schema")
    return payload


def submit_incident(
    incident: Incident, server_url: str, bearer: str, ca_file: Path | None = None
) -> dict[str, Any]:
    body = json.dumps(incident_payload(incident)).encode()
    if not bearer or any(not 32 < ord(ch) < 127 for ch in bearer):
        raise IncidentError("a valid NEXUS_TOKEN is required")
    url = urlsplit(server_url)
    host = url.hostname
    path = url.path.rstrip("/")
    if (
        not host
        or url.username is not None
        or url.password is not None
        or url.query
        or url.fragment
        or path not in {"", "/api/v1"}
    ):
        raise IncidentError("provide a server origin or an /api/v1 base URL")
    if url.scheme == "https":
        context = ssl.create_default_context(
            cafile=os.fspath(ca_file) if ca_file else None
        )
        connection = HTTPSConnection(host, url.port, timeout=10, context=context)
    elif url.scheme == "http" and host in {"127.0.0.1", "::1", "localhost"}:
        connection = HTTPConnection(
            "127.0.0.1" if host == "localhost" else host, url.port, timeout=10
        )
    else:
        raise IncidentError("HTTPS is required except for the loopback mock")
    try:
        connection.request(
            "POST",
            "/api/v1/incidents",
            body=body,
            headers={
                "Authorization": f"Bearer {bearer}",
                "Content-Type": "application/json",
            },
        )
        response = connection.getresponse()
        if response.status != 200:
            raise IncidentError(
                f"incident submission failed with HTTP {response.status}"
            )
        receipt = json.loads(response.read(65537))
        if (
            not isinstance(receipt, dict)
            or receipt.get("status") not in ("stored", "duplicate", "stale")
            or receipt.get("incident_id") != incident.incident_id
            or type(receipt.get("incident_version")) is not int
            or receipt["incident_version"] != incident.incident_version
        ):
            raise IncidentError("the server did not acknowledge this incident version")
        return {
            "status": receipt["status"],
            "incident_id": incident.incident_id,
            "incident_version": incident.incident_version,
        }
    finally:
        connection.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--events", type=Path, required=True, help="private HostEvent JSONL"
    )
    parser.add_argument(
        "--manifest", type=Path, required=True, help="the L1 manifest for this capture"
    )
    parser.add_argument("--server-url", default=os.getenv("NEXUS_SERVER_URL"))
    parser.add_argument(
        "--ca-file", type=Path, default=os.getenv("NEXUS_CA_FILE") or None
    )
    parser.add_argument(
        "--validate-only",
        action="store_true",
        help="build and validate without sending",
    )
    args = parser.parse_args(argv)
    try:
        if not args.validate_only and not args.server_url:
            raise IncidentError("set --server-url or NEXUS_SERVER_URL")
        manifest = json.loads(args.manifest.read_text(encoding="utf-8"))
        incident = build_incident(read_events(args.events), manifest)
        if args.validate_only:
            incident_payload(incident)
            result = {"status": "validated", "incident_id": incident.incident_id}
        else:
            result = submit_incident(
                incident, args.server_url, os.getenv("NEXUS_TOKEN", ""), args.ca_file
            )
    except IncidentError as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        return 1
    except (ValueError, KeyError, TypeError, OSError, HTTPException):
        print(
            json.dumps({"error": "invalid capture or failed server communication"}),
            file=sys.stderr,
        )
        return 1
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
