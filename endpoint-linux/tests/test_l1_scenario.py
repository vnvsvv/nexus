import importlib.util
import json
import shlex
import stat
import subprocess
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def scenario() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "l1_scenario", ROOT / "lab/scenarios/l1_stage_and_send.py"
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_shell_structure_preserves_l1_lineage(scenario: ModuleType) -> None:
    rule = yaml.safe_load((ROOT / "contracts/rules/NX-LIN-001.yaml").read_text())
    interp, shell, read, net = rule["steps"]
    assert interp["event_type"] == "process_start"
    assert scenario.BASH.endswith(tuple(shell["where"]["binary"]["endswith_any"]))
    assert str(scenario.CANARY).startswith(
        tuple(read["where"]["file.path"]["prefix_any"])
    )
    assert net["lineage"]["of"] == read["lineage"]["of"] == shell["step"]
    script = scenario.SHELL_SCRIPT
    subprocess.run(["bash", "-n"], input=script, text=True, check=True)
    assert '"$1" -- "$2" >/dev/null &' in script
    assert script.index("reader_pid=$!") < script.index('wait "$reader_pid"')
    assert script.index('wait "$reader_pid"') < script.index("client_start=")
    assert script.index("client_start=") < script.index("client_pid=$!")
    assert script.index("client_pid=$!") < script.index('wait "$client_pid"')
    curl_command = script.split("client_start=$EPOCHREALTIME\n")[1].split(
        "\nclient_pid=$!"
    )[0]
    args = shlex.split(curl_command.replace("\\\n", " "))
    assert args[:2] == ["$3", "--disable"]
    assert "--fail" in args
    assert args[args.index("--request") + 1] == "POST"
    assert args[args.index("--max-time") + 1] == "10"
    assert rule["window_seconds"] == 60
    assert args[args.index("--data-raw") + 1] == "NEXUS-L1-SYNTHETIC"
    assert [arg for arg in args if arg.startswith("--data")] == ["--data-raw"]
    assert "$2" not in args and "--upload-file" not in args
    assert args[-2:] == ["$4", "&"]


def test_partial_socket_observation_keeps_only_reported_fields(scenario: ModuleType):
    assert scenario.socket_observation(["", "0", "192.168.20.10", "8443", "200"]) == {
        "dst_ip": "192.168.20.10",
        "dst_port": 8443,
        "http_status": 200,
    }


@pytest.mark.parametrize("tuple_observed", [True, False])
def test_manifest_records_spawned_children_and_optional_socket_tuple(
    scenario: ModuleType,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    tuple_observed: bool,
) -> None:
    canary = tmp_path / "canary.txt"
    canary.write_text("test canary\n")
    monkeypatch.setattr(scenario, "CANARY", canary)
    monkeypatch.setattr(scenario, "MAN_DIR", tmp_path)
    socket_line = (
        "socket\t192.168.10.10\t51107\t192.168.20.10\t8443\t200\n"
        if tuple_observed
        else "socket\t\t0\t\t0\t000\n"
    )
    trace = (
        "reader\t702\t1760000000.010000\t1760000000.020000\t0\n"
        + socket_line
        + "client\t703\t1760000000.030000\t1760000000.050000\t0\n"
    )
    calls = []

    def popen(args, **kwargs):
        calls.append(args)
        assert "NEXUS_TOKEN" not in kwargs["env"]
        return SimpleNamespace(pid=701, communicate=lambda: (trace, None), returncode=0)

    monkeypatch.setattr(scenario.subprocess, "Popen", popen)
    assert scenario.main(["--isolated-lab"]) == 0
    assert len(calls) == 1 and calls[0][:3] == [
        scenario.BASH,
        "-c",
        scenario.SHELL_SCRIPT,
    ]
    assert calls[0][-1] == "http://192.168.20.10:8443/upload"
    (path,) = tmp_path.glob("L1-*.json")
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    manifest = json.loads(path.read_text())
    root, shell, reader, client = (
        step for step in manifest["steps"] if step["kind"] == "process"
    )
    assert shell["parent_pid"] == root["pid"] == manifest["root_pid"]
    assert reader["parent_pid"] == client["parent_pid"] == shell["pid"] == 701
    assert (reader["pid"], client["pid"]) == (702, 703)
    assert reader["end_utc"] < client["start_utc"]
    (file,) = [row for row in manifest["steps"] if row["kind"] == "file"]
    assert file["pid"] == reader["pid"]
    sockets = [row for row in manifest["steps"] if row["kind"] == "connection"]
    assert manifest["connection_observed"] is tuple_observed
    if tuple_observed:
        (connection,) = sockets
        assert (connection["pid"], connection["src_port"]) == (703, 51107)
        assert connection["dst_ip"] == "192.168.20.10"
    else:
        assert not sockets
        assert "src_port" not in path.read_text()
