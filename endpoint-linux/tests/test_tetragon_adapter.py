import hashlib
import json
import os
import shlex
import signal
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest
from tetragon_adapter import TetragonAdapter

from nexus_contracts import HostEvent, validate_against_schema

DATA = Path(__file__).parent / "data"
ROOT = Path(__file__).resolve().parents[2]
TCP_CAPTURE = DATA / "sanitized_tetragon_v1_8_0_tcp_connect_loopback.jsonl"
LIFECYCLE_CAPTURE = DATA / "sanitized_tetragon_v1_8_0_lifecycle_file.jsonl"
LIFECYCLE_EXPECTED = DATA / "sanitized_tetragon_v1_8_0_lifecycle_file.expected.json"


def synthetic_records() -> list[dict[str, Any]]:
    return [
        json.loads(line)
        for line in (DATA / "synthetic_lifecycle_and_file.jsonl")
        .read_text()
        .splitlines()
    ]


def replay(tmp_path: Path, *records: dict[str, Any]) -> list[HostEvent]:
    path = tmp_path / "sensor.jsonl"
    path.write_text("".join(json.dumps(record) + "\n" for record in records))
    return list(TetragonAdapter(path, follow=False).events())


def assert_contract(events: list[HostEvent]) -> None:
    for event in events:
        payload = event.model_dump(mode="json", by_alias=True, exclude_none=True)
        assert validate_against_schema("host_event", payload) == []
        assert HostEvent.model_validate(payload) == event


def test_sanitized_tcp_capture_matches_rebased_peer_observations() -> None:
    assert hashlib.sha256(TCP_CAPTURE.read_bytes()).hexdigest() == (
        "96414f1c1357c4eae0db1ffe33889204b1cd93d6b1be7944807ee782ea20ef34"
    )
    lines = TCP_CAPTURE.read_bytes().splitlines(keepends=True)
    raw = [json.loads(line) for line in lines]
    events = list(TetragonAdapter(TCP_CAPTURE, follow=False).events())
    assert len(events) == 3
    assert [event.pid for event in events] == [4301, 4302, 4303]
    assert [event.timestamp_utc for event in events] == [
        "2000-01-01T00:00:20.100Z",
        "2000-01-01T00:00:20.125Z",
        "2000-01-01T00:00:20.153Z",
    ]
    assert raw[1]["process_kprobe"]["args"][0]["sock_arg"]["cookie"] == (
        raw[2]["process_kprobe"]["args"][0]["sock_arg"]["cookie"]
    )
    assert len({event.event_id for event in events}) == 3
    assert len({event.attributes["raw_ref"] for event in events}) == 3
    for index, (event, port) in enumerate(
        zip(events, (50001, 50002, 50003), strict=True)
    ):
        body = raw[index]["process_kprobe"]
        assert event.event_type == "network_connect"
        assert event.binary == "/usr/bin/curl"
        assert event.process_instance_id == (
            "linux-vm-01:" + body["process"]["exec_id"]
        )
        assert event.parent_process_instance_id == (
            "linux-vm-01:" + body["parent"]["exec_id"]
        )
        assert event.ppid == 4409
        assert event.network is not None
        assert event.network.model_dump() == {
            "src_ip": "127.0.0.1",
            "src_port": port,
            "dst_ip": "127.0.0.1",
            "dst_port": 18080,
            "protocol": "TCP",
            "direction": "outbound",
        }
        assert event.attributes["sensor"] == "tetragon"
        assert event.attributes["sensor_event_id"] == "tcp_connect"
        assert event.attributes["identity_resolution"] == "unknown"
        assert event.attributes["raw_ref"].endswith(f":{sum(map(len, lines[:index]))}")
    assert_contract(events)


@pytest.fixture
def sanitized_lifecycle() -> tuple[list[HostEvent], list[dict[str, Any]]]:
    data = LIFECYCLE_CAPTURE.read_bytes()
    assert hashlib.sha256(data).hexdigest() == (
        "e555ee0e930a2440a30b9c1ae880ac8bfba6dd1b37d727b2a728ccc97b198944"
    )
    raw = [json.loads(line) for line in data.splitlines()]
    events = list(TetragonAdapter(LIFECYCLE_CAPTURE, follow=False).events())
    assert len(events) == len(raw) == 11
    assert_contract(events)
    return events, raw


def test_sanitized_exec_and_exit_match_controlled_children(
    sanitized_lifecycle: tuple[list[HostEvent], list[dict[str, Any]]],
) -> None:
    events, raw = sanitized_lifecycle
    observed = json.loads(LIFECYCLE_EXPECTED.read_text())
    assert {event.pid for event in events} == {int(pid) for pid in observed}
    assert len({event.event_id for event in events}) == 11

    for pid, details in observed.items():
        group = [event for event in events if event.pid == int(pid)]
        start, end = group[0], group[-1]
        assert start.event_type == "process_start"
        assert end.event_type == "process_exit"
        assert start.command_line is not None
        assert shlex.split(start.command_line) == details["argv"]
        assert {event.binary for event in group} == {details["argv"][0]}
        assert {event.ppid for event in group} == {details["parent_pid"]}
        assert {event.process_instance_id for event in group} == {
            start.process_instance_id
        }
        assert {event.parent_process_instance_id for event in group} == {
            start.parent_process_instance_id
        }
        assert start.parent_process_instance_id is not None
        assert {event.attributes["identity_resolution"] for event in group} == {
            "native"
        }
        measured_exit = details["returncode"]
        if measured_exit == 0:
            # The capture has no status on successful exits. Leave it absent.
            assert end.exit is None
        elif measured_exit > 0:
            assert end.exit is not None and end.exit.exit_code == measured_exit
            assert end.exit.signal is None
        else:
            assert end.exit is not None and end.exit.signal == -measured_exit
            assert end.exit.exit_code is None

    for event, record in zip(events, raw, strict=True):
        details = observed[str(event.pid)]
        timestamp = datetime.fromisoformat(record["time"])
        assert (
            datetime.fromisoformat(details["start_utc"])
            <= timestamp
            <= datetime.fromisoformat(details["end_utc"])
        )
        assert event.timestamp_utc == record["time"][:23] + "Z"
        kind = next(key for key in record if key.startswith("process_"))
        actor = record[kind]["process"]
        assert event.process_start_time_utc == actor["start_time"][:23] + "Z"
        assert event.process_instance_id == "linux-vm-01:" + actor["exec_id"]
        assert event.parent_process_instance_id == (
            "linux-vm-01:" + record[kind]["parent"]["exec_id"]
        )


def test_sanitized_read_and_write_preserve_permission_checks(
    sanitized_lifecycle: tuple[list[HostEvent], list[dict[str, Any]]],
) -> None:
    events, raw = sanitized_lifecycle
    observed = json.loads(LIFECYCLE_EXPECTED.read_text())
    files = [event for event in events if event.event_type == "file_access"]
    assert len(files) == 3
    assert [event.attributes["permission_mask"] for event in files] == [4, 4, 2]
    assert len({event.attributes["raw_ref"] for event in files}) == 3
    for event in files:
        details = observed[str(event.pid)]
        assert event.file is not None
        assert event.file.operation == details["case"]
        assert event.file.path == details["argv"][-1]
        assert event.attributes["permission_check"] == "allowed"
        assert event.attributes["sensor_event_id"] == "security_file_permission"
    returns = [
        line["process_kprobe"]["return"]["int_arg"]
        for line in raw
        if "process_kprobe" in line
    ]
    assert returns == [0, 0, 0]


@pytest.mark.parametrize("port", [None, 0, -1, 65536, "50001", True])
def test_synthetic_invalid_or_missing_source_port_preserves_raw(
    tmp_path: Path, caplog: pytest.LogCaptureFixture, port: object
) -> None:
    record = json.loads(TCP_CAPTURE.read_bytes().splitlines()[0])
    sock = record["process_kprobe"]["args"][0]["sock_arg"]
    if port is None:
        sock.pop("sport")
    else:
        sock["sport"] = port
    path = tmp_path / "synthetic_tcp.jsonl"
    original = json.dumps(record, separators=(",", ":")) + "\n"
    path.write_text(original)
    assert list(TetragonAdapter(path, follow=False).events()) == []
    diagnostic = json.loads(caplog.records[-1].message)
    assert diagnostic["reason"] == "invalid_source_port"
    assert diagnostic["raw_jsonl"] == original
    assert diagnostic["raw_ref"].endswith(":0")
    assert path.read_text() == original


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("saddr", "0.0.0.0"),
        ("daddr", "host.example"),
        ("daddr", "::1"),
        ("dport", 0),
        ("protocol", "IPPROTO_UDP"),
    ],
)
def test_synthetic_incomplete_or_invalid_tuple_is_rejected(
    tmp_path: Path, caplog: pytest.LogCaptureFixture, field: str, value: object
) -> None:
    record = json.loads(TCP_CAPTURE.read_bytes().splitlines()[0])
    record["process_kprobe"]["args"][0]["sock_arg"][field] = value
    assert replay(tmp_path, record) == []
    assert "raw_jsonl" in json.loads(caplog.records[-1].message)


def test_synthetic_lifecycle_and_canonical_fixture_fields(tmp_path: Path) -> None:
    start, read, exit_record = synthetic_records()
    binary = tmp_path / "executable"
    binary.write_bytes(b"synthetic binary")
    start["process_exec"]["process"]["binary"] = str(binary)
    events = replay(tmp_path, start, read, exit_record)
    assert_contract(events)
    exec_event, read_event, exit_event = events
    assert exec_event.sha256 == hashlib.sha256(b"synthetic binary").hexdigest()
    assert exec_event.timestamp_utc == "2026-11-17T19:40:33.000Z"
    assert exec_event.process_start_time_utc == "2026-11-17T19:40:33.000Z"
    assert exec_event.command_line == f"{binary} --flag"
    assert exec_event.user == "root"
    assert exec_event.parent_process_instance_id == "linux-vm-01:synthetic-parent"
    assert exec_event.ppid == 8400
    assert exit_event.exit is not None
    assert exit_event.exit.exit_code == 17

    canonical = [
        HostEvent.model_validate_json(line)
        for line in (ROOT / "contracts/fixtures/linux_l1_events.jsonl")
        .read_text()
        .splitlines()
    ]
    canonical_read = next(
        event for event in canonical if event.event_type == "file_access"
    )
    assert read_event.file is not None and canonical_read.file is not None
    assert read_event.file.operation == canonical_read.file.operation
    assert (
        read_event.attributes["sensor_event_id"]
        == canonical_read.attributes["sensor_event_id"]
    )
    assert (
        read_event.process_instance_id
        == exec_event.process_instance_id
        == exit_event.process_instance_id
    )


def test_synthetic_exit_signal_and_missing_exit_details(tmp_path: Path) -> None:
    *_, exit_record = synthetic_records()
    body = exit_record["process_exit"]
    body.pop("status")
    body["signal"] = "SIGTERM"
    signaled = replay(tmp_path, exit_record)[0]
    assert signaled.exit is not None and signaled.exit.signal == signal.SIGTERM
    assert signaled.exit.exit_code is None
    body.pop("signal")
    assert replay(tmp_path, exit_record)[0].exit is None
    body["status"] = 0
    assert replay(tmp_path, exit_record)[0].exit.exit_code == 0


def test_synthetic_hash_cache_and_skip(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    start, *_ = synthetic_records()
    binary = tmp_path / "binary"
    start["process_exec"]["process"]["binary"] = str(binary)
    path = tmp_path / "sensor.jsonl"

    def write_starts() -> None:
        path.write_text((json.dumps(start) + "\n") * 2)

    binary.write_bytes(b"first")
    write_starts()
    adapter = TetragonAdapter(path, follow=False)
    original_read = os.read
    reads = []

    def count_read(fd: int, size: int) -> bytes:
        result = original_read(fd, size)
        if result:
            reads.append(result)
        return result

    monkeypatch.setattr(os, "read", count_read)
    first, again = list(adapter.events())
    assert first.sha256 == again.sha256 == hashlib.sha256(b"first").hexdigest()
    assert first.attributes["hash_basis"] == "path_at_collection"
    assert reads == [b"first"]
    binary.write_bytes(b"second")
    first, _ = list(adapter.events())
    assert first.sha256 == hashlib.sha256(b"second").hexdigest()
    with binary.open("wb") as handle:
        handle.truncate(64 * 1024 * 1024 + 1)
    oversized, _ = list(adapter.events())
    assert oversized.attributes["hash_skipped"] == "too_large"
    binary.unlink()
    event, _ = list(adapter.events())
    assert event.sha256 is None
    assert event.attributes["hash_skipped"] == "unreadable"


def test_synthetic_combined_and_denied_file_permissions(tmp_path: Path) -> None:
    _, record, _ = synthetic_records()
    kprobe = record["process_kprobe"]
    kprobe["args"][1]["int_arg"] = 6
    events = replay(tmp_path, record)
    assert_contract(events)
    assert [event.file.operation for event in events if event.file] == ["read", "write"]
    assert events[0].attributes["raw_ref"] == events[1].attributes["raw_ref"]
    assert {event.attributes["permission_mask"] for event in events} == {6}
    kprobe["return"]["int_arg"] = -13
    assert replay(tmp_path, record) == []
    kprobe["return"]["int_arg"] = 0
    kprobe["args"][1]["int_arg"] = 12
    assert replay(tmp_path, record) == []


@pytest.mark.parametrize(
    ("returned", "reason"),
    [
        ({}, "file_permission_result_missing"),
        ({"return": {}}, "file_permission_result_missing"),
        ({"return": None}, "file_permission_result_invalid"),
        ({"return": {"int_arg": "0"}}, "file_permission_result_invalid"),
        ({"return": {"int_arg": False}}, "file_permission_result_invalid"),
        ({"return": {"int_arg": 0.0}}, "file_permission_result_invalid"),
        ({"return": {"int_arg": None}}, "file_permission_result_invalid"),
        ({"return": {"int_arg": -13}}, "file_permission_check_failed"),
        ({"return": {"int_arg": 1}}, "file_permission_check_failed"),
        ({"return": {"int_arg": 0}}, None),
    ],
)
def test_synthetic_file_access_requires_explicit_success(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
    returned: dict[str, Any],
    reason: str | None,
) -> None:
    _, record, _ = synthetic_records()
    kprobe = record["process_kprobe"]
    kprobe.pop("return")
    kprobe.update(returned)
    events = replay(tmp_path, record)
    if reason is None:
        assert len(events) == 1
        assert events[0].attributes["permission_check"] == "allowed"
        assert_contract(events)
    else:
        assert events == []
        (entry,) = caplog.records
        diagnostic = json.loads(entry.message)
        assert diagnostic["reason"] == reason
        assert diagnostic["raw_ref"].endswith(":0")
        assert diagnostic["raw_jsonl"] == (tmp_path / "sensor.jsonl").read_text()


def test_synthetic_fallback_requires_matching_start_time_and_live_pid(
    tmp_path: Path,
) -> None:
    start, read, exit_record = synthetic_records()
    probe = read["process_kprobe"]["process"]
    probe["exec_id"] = "unseen"
    probe["start_time"] = "2026-11-17T19:40:33.010000001Z"  # Exactly 10 ms.
    _, inferred, _, late = replay(tmp_path, start, read, exit_record, read)
    assert inferred.attributes["identity_resolution"] == "pid_start_time"
    assert inferred.process_instance_id == "linux-vm-01:synthetic-child"
    assert late.attributes["identity_resolution"] == "unknown"
    assert late.process_instance_id == "linux-vm-01:unseen"

    probe["start_time"] = "2026-11-17T19:40:33.010000002Z"
    assert (
        replay(tmp_path, start, read)[1].attributes["identity_resolution"] == "unknown"
    )
    probe.pop("exec_id")
    assert len(replay(tmp_path, start, read)) == 1


def test_synthetic_late_exit_cannot_clear_reused_pid(tmp_path: Path) -> None:
    start, read, exit_record = synthetic_records()
    newer = json.loads(json.dumps(start))
    newer["time"] = "2026-11-17T19:40:33.022Z"
    newer["process_exec"]["process"].update(
        exec_id="newer", start_time="2026-11-17T19:40:33.020Z"
    )
    probe = read["process_kprobe"]["process"]
    probe.update(exec_id="unseen", start_time="2026-11-17T19:40:33.022Z")
    exit_record["time"] = "2026-11-17T19:40:33.030Z"
    events = replay(tmp_path, start, newer, exit_record, read)
    assert events[-1].process_instance_id == "linux-vm-01:newer"
    assert events[-1].attributes["identity_resolution"] == "pid_start_time"

    newer["process_exec"]["process"]["start_time"] = "2026-11-17T19:40:33.006Z"
    probe["start_time"] = "2026-11-17T19:40:33.007Z"
    assert (
        replay(tmp_path, start, newer, read)[-1].attributes["identity_resolution"]
        == "unknown"
    )


def test_synthetic_unemittable_exit_still_closes_known_identity(tmp_path: Path) -> None:
    start, read, exit_record = synthetic_records()
    exit_record["process_exit"]["process"].pop("binary")
    read["process_kprobe"]["process"]["exec_id"] = "unseen"
    events = replay(tmp_path, start, exit_record, read)
    assert [event.event_type for event in events] == ["process_start", "file_access"]
    assert events[-1].attributes["identity_resolution"] == "unknown"


@pytest.mark.parametrize(
    "field", ["binary", "parent_exec_id", "ppid", "auid", "node_name"]
)
def test_synthetic_fallback_rejects_conflicting_identity(
    tmp_path: Path, field: str
) -> None:
    start, read, _ = synthetic_records()
    parent_id = start["process_exec"]["parent"]["exec_id"]
    probe = read["process_kprobe"]
    actor = probe["process"]
    probe["parent"] = dict(start["process_exec"]["parent"])
    actor.update(exec_id="unseen", start_time="2026-11-17T19:40:33.005Z")
    start["process_exec"]["process"]["auid"] = actor["auid"] = 1000
    if field == "parent_exec_id":
        actor["parent_exec_id"] = probe["parent"]["exec_id"] = parent_id + "-other"
    elif field == "ppid":
        probe["parent"]["pid"] += 1
    elif field == "binary":
        actor["binary"] = "/usr/bin/tee"
    elif field == "auid":
        actor["auid"] = 1001
    else:
        start["node_name"] = "first-sensor"
        read["node_name"] = "other-sensor"

    known, unresolved = replay(tmp_path, start, read)
    assert unresolved.process_instance_id == "linux-vm-01:unseen"
    assert unresolved.attributes["identity_resolution"] == "unknown"
    actor.pop("exec_id")
    assert [event.event_type for event in replay(tmp_path, start, read)] == [
        "process_start"
    ]
    actor["exec_id"] = start["process_exec"]["process"]["exec_id"]
    actor["start_time"] = start["process_exec"]["process"]["start_time"]
    native = replay(tmp_path, start, read)[-1]
    assert native.process_instance_id == known.process_instance_id
    assert native.attributes["identity_resolution"] == "native"


def test_synthetic_exit_before_start_cannot_reopen_identity(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    start, read, exit_record = synthetic_records()
    read["time"] = "2026-11-17T19:40:33.300Z"
    read["process_kprobe"]["process"]["exec_id"] = "unseen"
    ended, unresolved = replay(tmp_path, exit_record, start, read)
    assert ended.event_type == "process_exit"
    assert ended.process_instance_id == "linux-vm-01:synthetic-child"
    assert unresolved.process_instance_id == "linux-vm-01:unseen"
    assert unresolved.attributes["identity_resolution"] == "unknown"
    (entry,) = caplog.records
    diagnostic = json.loads(entry.message)
    assert diagnostic["reason"] == "process_start_after_exit"
    assert json.loads(diagnostic["raw_jsonl"]) == start


def test_synthetic_late_start_does_not_replace_newer_execution(tmp_path: Path) -> None:
    start, read, exit_record = synthetic_records()
    newer, *_ = synthetic_records()
    newer["time"] = "2026-11-17T19:40:33.225Z"
    newer["process_exec"]["process"].update(
        exec_id="newer", start_time="2026-11-17T19:40:33.225Z"
    )
    read["time"] = "2026-11-17T19:40:33.300Z"
    read["process_kprobe"]["process"].update(
        exec_id="unseen", start_time="2026-11-17T19:40:33.226Z"
    )

    ended, started, inferred = replay(tmp_path, exit_record, newer, start, read)
    assert ended.event_type == "process_exit"
    assert started.event_type == "process_start"
    assert inferred.process_instance_id == started.process_instance_id
    assert inferred.attributes["identity_resolution"] == "pid_start_time"


def test_synthetic_evicted_exit_cannot_reopen_on_late_start(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    start, read, exit_record = synthetic_records()
    other_exit = json.loads(json.dumps(exit_record))
    other_exit["process_exit"]["process"].update(pid=8501, exec_id="other")
    read["process_kprobe"]["process"].pop("exec_id")
    newer, later_read, _ = synthetic_records()
    newer["time"] = "2026-11-17T19:40:33.225Z"
    newer["process_exec"]["process"].update(
        exec_id="newer", start_time="2026-11-17T19:40:33.225Z"
    )
    later_read["time"] = "2026-11-17T19:40:33.300Z"
    later_read["process_kprobe"]["process"].update(
        exec_id="unseen", start_time="2026-11-17T19:40:33.226Z"
    )
    path = tmp_path / "sensor.jsonl"
    path.write_text(
        "".join(
            json.dumps(row) + "\n"
            for row in (exit_record, other_exit, start, read, newer, later_read)
        )
    )

    events = list(TetragonAdapter(path, follow=False, identity_cache_size=1).events())
    assert [event.event_type for event in events] == [
        "process_exit",
        "process_exit",
        "process_start",
        "file_access",
    ]
    assert events[-1].process_instance_id == "linux-vm-01:newer"
    assert events[-1].attributes["identity_resolution"] == "pid_start_time"
    assert [json.loads(entry.message)["reason"] for entry in caplog.records] == [
        "process_start_before_retained_exits",
        "missing_process_identity",
    ]


@pytest.mark.parametrize("has_start_time", [True, False])
def test_synthetic_exit_only_execution_blocks_stale_pid_fallback(
    tmp_path: Path, has_start_time: bool
) -> None:
    start, read, exit_record = synthetic_records()
    departed = exit_record["process_exit"]["process"]
    departed["exec_id"] = "exited-before-exec"
    if has_start_time:
        departed["start_time"] = "2026-11-17T19:40:33.005Z"
    probe = read["process_kprobe"]["process"]
    probe.update(exec_id="unseen", start_time="2026-11-17T19:40:33.005Z")
    read["time"] = "2026-11-17T19:40:33.300Z"

    assert replay(tmp_path, start, exit_record, read)[-1].process_instance_id == (
        "linux-vm-01:unseen"
    )
    probe.pop("exec_id")
    assert [
        event.event_type for event in replay(tmp_path, start, exit_record, read)
    ] == [
        "process_start",
        "process_exit",
    ]
    probe["exec_id"] = departed["exec_id"]
    native = replay(tmp_path, start, exit_record, read)[-1]
    assert native.process_instance_id == "linux-vm-01:exited-before-exec"
    assert native.attributes["identity_resolution"] == "native"


@pytest.mark.parametrize(
    "field,value", [("flags", "taskWalk"), ("binary", "<unknown>")]
)
def test_synthetic_incomplete_observation_does_not_supply_fallback_identity(
    tmp_path: Path, caplog: pytest.LogCaptureFixture, field: str, value: str
) -> None:
    start, read, _ = synthetic_records()
    actor = read["process_kprobe"]["process"]
    actor.update(exec_id="unseen")
    actor[field] = value
    unmatched = replay(tmp_path, start, read)[-1]
    assert unmatched.process_instance_id == "linux-vm-01:unseen"
    assert unmatched.attributes["identity_resolution"] == "unknown"
    actor["exec_id"] = "unusable\nID"
    assert [event.event_type for event in replay(tmp_path, start, read)] == [
        "process_start"
    ]
    diagnostic = json.loads(caplog.records[-1].message)
    assert diagnostic["reason"] == "missing_process_identity"
    assert json.loads(diagnostic["raw_jsonl"]) == read


def test_synthetic_procfs_placeholder_and_missing_required_fields(
    tmp_path: Path,
) -> None:
    record, *_ = synthetic_records()
    body = record["process_exec"]
    proc = body["process"]
    proc["flags"] = "procFS rootCWD"
    event = replay(tmp_path, record)[0]
    assert event.attributes["identity_resolution"] == "native"
    body.pop("parent")
    proc.pop("parent_exec_id")
    event = replay(tmp_path, record)[0]
    assert event.attributes["identity_resolution"] == "placeholder"
    assert event.attributes["placeholder"] is True
    assert event.parent_process_instance_id is None
    proc.pop("binary")
    assert replay(tmp_path, record) == []
    proc["binary"] = "/lab/bin/test"
    record["time"] = "2026-11-17T19:40:33"
    assert replay(tmp_path, record) == []


def test_synthetic_tail_recovers_and_ignores_incomplete_record(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    path = tmp_path / "synthetic_tail.jsonl"
    record = json.dumps(synthetic_records()[0]).encode()
    path.write_bytes(b"broken\n" + b"x" * 707 + b"\n{}\n" + record + b"\n" + record)
    events = list(TetragonAdapter(path, follow=False, max_line_bytes=600).events())
    assert len(events) == 1
    reports = [json.loads(row.message)["reason"] for row in caplog.records]
    assert reports == ["invalid_json", "line_too_large", "incomplete_line"]
    assert_contract(events)


def test_synthetic_rotation_drains_line_completed_during_inode_lookup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "tetragon.log"
    first, read, end = synthetic_records()
    first_line, read_line, end_line = [
        json.dumps(record).encode() + b"\n" for record in (first, read, end)
    ]
    path.write_bytes(first_line + read_line[:40])
    original_stat = Path.stat
    rotated = False

    def rotate_then_stat(target: Path, *args: Any, **kwargs: Any) -> os.stat_result:
        nonlocal rotated
        if target == path and not rotated:
            rotated = True
            with path.open("ab") as handle:
                handle.write(read_line[40:])
            path.rename(tmp_path / "tetragon.log.1")
            path.write_bytes(end_line)
        return original_stat(target, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", rotate_then_stat)
    events = TetragonAdapter(path).events()
    try:
        assert next(events).event_type == "process_start"
        recovered = next(events)
        assert recovered.event_type == "file_access"
        assert recovered.attributes["raw_ref"].endswith(f":0:{len(first_line)}")
        assert next(events).event_type == "process_exit"
    finally:
        events.close()


def test_synthetic_rotation_drains_old_line_completed_during_replacement_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "tetragon.log"
    old_path = tmp_path / "tetragon.log.1"
    start, read, end = [
        json.dumps(record).encode() + b"\n" for record in synthetic_records()
    ]
    path.write_bytes(start + read[:40])
    events = TetragonAdapter(path).events()
    try:
        assert next(events).event_type == "process_start"
        path.rename(old_path)
        path.write_bytes(end)
        original_open = os.open

        def finish_old_line(target: Path, flags: int) -> int:
            if target == path:
                with old_path.open("ab") as handle:
                    handle.write(read[40:])
            return original_open(target, flags)

        monkeypatch.setattr(os, "open", finish_old_line)
        recovered = next(events)
        assert recovered.event_type == "file_access"
        assert recovered.attributes["raw_ref"].endswith(f":0:{len(start)}")
        replacement = next(events)
        assert replacement.event_type == "process_exit"
        assert replacement.attributes["raw_ref"].endswith(":1:0")
    finally:
        events.close()


@pytest.mark.parametrize(
    ("offset", "expected"),
    [
        ("Z", "2026-11-17T19:40:33.123Z"),
        ("+00:00", "2026-11-17T19:40:33.123Z"),
        ("-00:00", "2026-11-17T19:40:33.123Z"),
        ("+23:59", "2026-11-16T19:41:33.123Z"),
        ("-23:59", "2026-11-18T19:39:33.123Z"),
        ("+00:59", "2026-11-17T18:41:33.123Z"),
        ("+00:60", None),
        ("+00:99", None),
        ("+24:00", None),
        ("-24:00", None),
        ("-01:60", None),
        ("-00:99", None),
    ],
)
@pytest.mark.parametrize("field", ["time", "start_time"])
def test_synthetic_timestamp_offset_bounds(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
    offset: str,
    expected: str | None,
    field: str,
) -> None:
    start, *_ = synthetic_records()
    source = start if field == "time" else start["process_exec"]["process"]
    source[field] = "2026-11-17T19:40:33.123987654" + offset
    events = replay(tmp_path, start)
    if expected is None:
        assert events == []
        assert json.loads(caplog.records[-1].message)["reason"] == "invalid_timestamp"
    else:
        (event,) = events
        stamp = event.timestamp_utc if field == "time" else event.process_start_time_utc
        assert stamp == expected
        assert_contract(events)


def test_synthetic_follow_handles_partial_rotation_and_copytruncate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "synthetic_live.jsonl"
    record = synthetic_records()[0]

    def line(pid: int, padding: str = "") -> bytes:
        proc = record["process_exec"]["process"]
        proc.update(pid=pid, exec_id=f"test-{pid}", arguments=padding)
        return json.dumps(record).encode() + b"\n"

    initial = line(8501)
    initially_partial = line(8502)
    path.write_bytes(initial + initially_partial[:40])

    def add_remainder() -> None:
        with path.open("ab") as handle:
            handle.write(initially_partial[40:])

    def prepare_rotation() -> None:
        with path.open("ab") as handle:
            handle.write(line(8503) + b'{"discard')
        path.rename(tmp_path / "synthetic_live.jsonl.1")
        path.write_bytes(line(8504))

    def copytruncate() -> None:
        path.write_bytes(line(8505, "larger than previous contents" * 100))

    actions = iter((add_remainder, prepare_rotation, copytruncate))
    monkeypatch.setattr("tetragon_adapter.time.sleep", lambda _: next(actions)())
    events = TetragonAdapter(path).events()
    try:
        result = [next(events) for _ in range(5)]
    finally:
        events.close()
    assert [event.pid for event in result] == [8501, 8502, 8503, 8504, 8505]
    assert len({event.attributes["raw_ref"] for event in result}) == 5
