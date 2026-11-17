#!/usr/bin/env python3
"""Scenario L3 (harmless): one process opens TCP connections to 30 sequential ports on the other lab VM.
Most will be refused (RST) — that is fine: Tetragon sees tcp_connect, conntrack sees NEW, NFStream sees short flows.
"""
import json, os, socket, time
from datetime import datetime, timezone

TARGET = os.environ.get("NEXUS_TARGET", "192.168.20.10")
START = int(os.environ.get("NEXUS_PORT_START", "9100"))
now = lambda: datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
os.makedirs("/lab/manifests", exist_ok=True)
man = {"scenario": "L3", "endpoint_id": os.environ.get("NEXUS_ENDPOINT_ID", "linux-vm-01"), "start_utc": now(),
       "root_pid": os.getpid(), "root_binary": "/usr/bin/python3", "steps": []}
for port in range(START, START + 30):
    s = socket.socket(); s.settimeout(0.5)
    try:
        s.connect((TARGET, port))
    except OSError:
        pass
    man["steps"].append({"kind": "connection", "protocol": "TCP", "dst_ip": TARGET, "dst_port": port, "direction": "outbound", "t": now()})
    s.close(); time.sleep(0.2)
man["end_utc"] = now()
path = f"/lab/manifests/L3-{man['start_utc'].replace(':', '')}.json"
json.dump(man, open(path, "w"), indent=2)
print("manifest:", path)
