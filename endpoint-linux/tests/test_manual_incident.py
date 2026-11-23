import asyncio
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from anyio import to_thread
from httpx import ASGITransport, AsyncClient

from nexus_contracts import HostEvent, Incident, validate_against_schema
from tools import mock_server
from tools import post_manual_incident as manual

ROOT = Path(__file__).resolve().parents[2]
FIX = ROOT / "contracts/fixtures"


@pytest.fixture
def l1() -> tuple[list[HostEvent], dict]:
    """Canonical fixture data with test-only export provenance."""
    events = list(manual.read_events(FIX / "linux_l1_events.jsonl"))
    for offset, event in enumerate(events):
        event.attributes.update(
            raw_ref=f"/test/synthetic-tetragon-export:1:1:0:{offset}",
            identity_resolution="native",
        )
    starts = [event for event in events if event.event_type == "process_start"]
    file_event, net = events[3], events[6]
    assert file_event.file and net.network
    steps = [
        {
            "kind": "process",
            "role": role,
            "pid": event.pid,
            "binary": event.binary,
            "parent_pid": event.ppid,
        }
        for role, event in zip(
            ("interp", "shell", "reader", "client"), starts, strict=True
        )
    ]
    steps.append(
        {"kind": "file", "pid": file_event.pid, **file_event.file.model_dump()}
    )
    # Test an independently recorded connection tuple.
    steps.append({"kind": "connection", "pid": net.pid, **net.network.model_dump()})
    return events, {
        "scenario": "L1",
        "endpoint_id": net.endpoint_id,
        "root_pid": starts[0].pid,
        "start_utc": "2026-11-15T10:30:01.130Z",
        "end_utc": "2026-11-15T10:30:06.200Z",
        "target": {"dst_ip": net.network.dst_ip, "dst_port": net.network.dst_port},
        "steps": steps,
    }


def test_builds_canonical_l1_evidence_from_input(l1) -> None:
    events, manifest = l1
    internal_command_line = "/usr/bin/python3 --token test-secret"
    events[0].command_line = internal_command_line
    incident = manual.build_incident(events, manifest)
    expected = json.loads((FIX / "rules/NX-LIN-001.expect.json").read_text())
    template = Incident.model_validate_json(
        (FIX / "incident_linux_l1.json").read_text()
    )
    assert incident.rule_matches[0].bindings == expected["bindings"]
    assert incident.root_process_instance_id == expected["root_process_instance_id"]
    assert [node.process_instance_id for node in incident.process_nodes] == expected[
        "expected_process_instance_ids"
    ]
    assert incident.technique_ids == template.technique_ids
    assert incident.severity == template.severity
    assert incident.local_response.status == "not_requested"
    (connection,) = incident.connections
    network_event = events[-1]
    assert network_event.network is not None
    assert connection.first_seen_utc == network_event.timestamp_utc
    assert connection.process_instance_id == network_event.process_instance_id
    assert connection.evidence_event_ids == [network_event.event_id]
    assert {
        key: getattr(connection, key) for key in network_event.network.model_dump()
    } == (network_event.network.model_dump())
    evidence = {item.event_id: item.event for item in incident.evidence}
    assert evidence == {event.event_id: event for event in events}
    for edge in incident.relationships:
        (event_id,) = edge.evidence_event_ids
        event = evidence[event_id]
        if edge.type == "PARENT_OF":
            assert edge.from_ == event.parent_process_instance_id
            assert edge.to == event.process_instance_id
        elif edge.type == "ACCESSED_FILE":
            assert event.file is not None
            assert (edge.from_, edge.to) == (
                event.process_instance_id,
                f"file:{event.file.path}",
            )
        else:
            assert edge.type == "CONNECTED_TO"
            assert edge.from_ == network_event.process_instance_id
            assert event_id == network_event.event_id
            assert edge.to == (
                f"net:{network_event.network.dst_ip}:{network_event.network.dst_port}"
                f"/{network_event.network.protocol}"
            )
    assert all(edge.basis == "observed" for edge in incident.relationships)
    payload = manual.incident_payload(incident)
    assert validate_against_schema("incident", payload) == []
    assert "from" in payload["relationships"][0] and "server" not in payload
    assert "test-secret" not in json.dumps(payload)
    assert all("command_line" not in row for row in payload["process_nodes"])
    assert all("command_line" not in row["event"] for row in payload["evidence"])
    assert incident.process_nodes[0].command_line == internal_command_line
    assert evidence[events[0].event_id].command_line == internal_command_line
    assert manual.build_incident(events, manifest).incident_id == incident.incident_id


@pytest.mark.parametrize(
    "change",
    [
        "wrong_parent",
        "missing_parent",
        "loopback",
        "missing_read",
        "missing_connection",
        "missing_port",
        "manifest_mismatch",
        "late",
        "ambiguous",
    ],
)
def test_rejects_incomplete_or_inconsistent_l1_evidence(l1, change: str) -> None:
    events, manifest = l1
    net = events[-1]
    assert net.network
    if change == "wrong_parent":
        events[-2].parent_process_instance_id = events[0].process_instance_id
    elif change == "missing_parent":
        events[-2].parent_process_instance_id = None
    elif change == "loopback":
        net.network.dst_ip = manifest["target"]["dst_ip"] = "127.0.0.1"
        manifest["steps"][-1]["dst_ip"] = "127.0.0.1"
    elif change == "missing_read":
        events[:] = [event for event in events if event.event_type != "file_access"]
    elif change == "missing_connection":
        events.pop()
    elif change == "missing_port":
        net.network.src_port = 0
    elif change == "manifest_mismatch":
        manifest["steps"][-1]["src_port"] += 1
    elif change == "late":
        net.timestamp_utc = "2026-11-15T10:31:06.000Z"
        manifest["end_utc"] = "2026-11-15T10:31:07.000Z"
    else:
        events.append(
            net.model_copy(update={"event_id": "linux-vm-01:evt-00000000abcd"})
        )
    with pytest.raises(manual.IncidentError):
        manual.build_incident(events, manifest)


def test_fixture_without_export_provenance_is_rejected(l1) -> None:
    _, manifest = l1
    with pytest.raises(manual.IncidentError):
        manual.build_incident(
            manual.read_events(FIX / "linux_l1_events.jsonl"), manifest
        )


def test_adapter_identity_fallback_is_reported_as_inferred(l1) -> None:
    events, manifest = l1
    manifest["steps"].pop()  # curl did not supply a tuple
    events[-1].attributes["identity_resolution"] = "pid_start_time"
    incident = manual.build_incident(events, manifest)
    assert incident.relationships[-1].basis == "inferred"
    assert incident.confidence == "medium"
    assert {gap.code for gap in incident.gaps} == {"IDENTITY_INFERRED"}
    assert incident.connections[0].src_port == events[-1].network.src_port


def test_manifest_with_only_remote_tuple_does_not_fill_host_port(l1) -> None:
    events, manifest = l1
    manifest["steps"][-1].pop("src_port")
    incident = manual.build_incident(events, manifest)
    assert incident.connections[0].src_port == events[-1].network.src_port


def test_validate_only_cli_prints_receipt_without_credentials(
    l1,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events, manifest = l1
    source = tmp_path / "synthetic-events.jsonl"
    source.write_text(
        "".join(event.model_dump_json(exclude_none=True) + "\n" for event in events)
    )
    manifest_file = tmp_path / "synthetic-manifest.json"
    manifest_file.write_text(json.dumps(manifest))
    monkeypatch.delenv("NEXUS_TOKEN", raising=False)
    assert (
        manual.main(
            [
                "--events",
                str(source),
                "--manifest",
                str(manifest_file),
                "--validate-only",
            ]
        )
        == 0
    )
    assert set(json.loads(capsys.readouterr().out)) == {"incident_id", "status"}


def test_submission_against_existing_mock(l1, monkeypatch: pytest.MonkeyPatch) -> None:
    events, manifest = l1
    events[0].command_line = "/usr/bin/python3 --token synthetic-request-secret"
    incident = manual.build_incident(events, manifest)
    incident.title = "TEST ONLY — canonical L1 fixture"
    monkeypatch.setattr(
        mock_server, "STATE", {"incidents": {}, "events": asyncio.Queue()}
    )
    origin = "http://127.0.0.1:8000"

    async def call_mock_dependency_inline(function, *args, **kwargs):
        # The mock auth and lookup are in-memory. Avoid an event-loop wakeup
        # socket from a worker thread in restricted test environments.
        return function(*args)

    monkeypatch.setattr(to_thread, "run_sync", call_mock_dependency_inline)

    async def request(method, path, **kwargs):
        transport = ASGITransport(app=mock_server.app)
        async with AsyncClient(transport=transport, base_url=origin) as client:
            return await client.request(method, path, **kwargs)

    class InProcessConnection:
        def __init__(self, host, port, *, timeout):
            assert (host, port) == ("127.0.0.1", 8000)

        def request(self, method, path, *, body, headers):
            assert b"command_line" not in body
            assert b"synthetic-request-secret" not in body
            self.reply = asyncio.run(
                request(method, path, content=body, headers=headers)
            )

        def getresponse(self):
            return SimpleNamespace(
                status=self.reply.status_code,
                read=lambda size: self.reply.content[:size],
            )

        def close(self):
            pass

    monkeypatch.setattr(manual, "HTTPConnection", InProcessConnection)
    url = origin + "/api/v1"
    with pytest.raises(manual.IncidentError, match="HTTP 401"):
        manual.submit_incident(incident, url, "test-invalid-secret")
    assert manual.submit_incident(incident, url, "devtoken")["status"] == "stored"
    assert manual.submit_incident(incident, url, "devtoken")["status"] == "duplicate"
    view = asyncio.run(
        request(
            "GET",
            f"/api/v1/incidents/{incident.incident_id}",
            headers={"Authorization": "Bearer devtoken"},
        )
    ).json()
    assert view["incident"] == manual.incident_payload(incident)
    assert view["server"]["correlations"][0]["state"] == "pending"
    with pytest.raises(manual.IncidentError, match="HTTPS"):
        manual.submit_incident(incident, "http://nexus-server:8443", "devtoken")
