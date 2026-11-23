import json
import stat
from pathlib import Path

import pytest
from main import main

from nexus_contracts import HostEvent, validate_against_schema

DATA = Path(__file__).parent / "data"


@pytest.mark.parametrize("trusted", [False, True])
def test_replay_gates_command_line_export(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    trusted: bool,
) -> None:
    records = [
        json.loads(line)
        for line in (DATA / "synthetic_lifecycle_and_file.jsonl")
        .read_text()
        .splitlines()
    ]
    records[0]["process_exec"]["process"]["arguments"] = "--token test-secret"
    invalid = json.loads(
        (DATA / "sanitized_tetragon_v1_8_0_tcp_connect_loopback.jsonl")
        .read_text()
        .splitlines()[0]
    )
    probe = invalid["process_kprobe"]
    probe["process"]["arguments"] = "--token test-secret"
    probe["args"][0]["sock_arg"]["sport"] = 0
    source = tmp_path / "tetragon.jsonl"
    source.write_text("".join(json.dumps(row) + "\n" for row in [*records, invalid]))
    output = tmp_path / "events.jsonl"
    monkeypatch.setenv("NEXUS_TETRAGON_LOG", str(source))
    monkeypatch.setenv("NEXUS_ENDPOINT_ID", "test-linux")
    args = ["--replay", "--jsonl-out", str(output)]
    if trusted:
        args.append("--include-command-line")
    assert main(args) == 0
    text = output.read_text()
    assert "test-secret" not in caplog.text
    (diagnostic,) = caplog.records
    assert json.loads(diagnostic.getMessage()) == {
        "sensor": "tetragon",
        "reason": "invalid_source_port",
    }
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    rows = [json.loads(line) for line in text.splitlines()]
    assert [row["event_type"] for row in rows] == [
        "process_start",
        "file_access",
        "process_exit",
    ]
    assert all(row["endpoint_id"] == "test-linux" for row in rows)
    if trusted:
        event = HostEvent.model_validate(rows[0])
        assert event.command_line == f"{event.binary} --token test-secret"
    else:
        assert "test-secret" not in text
        assert all("command_line" not in row for row in rows)
    for row in rows:
        HostEvent.model_validate(row)
        assert validate_against_schema("host_event", row) == []
    assert main(args) != 0
    assert output.read_text() == text


def test_missing_export_does_not_create_output(tmp_path: Path) -> None:
    output = tmp_path / "events.jsonl"
    assert (
        main(
            [
                "--replay",
                "--tetragon-log",
                str(tmp_path / "missing"),
                "--jsonl-out",
                str(output),
            ]
        )
        != 0
    )
    assert not output.exists()
