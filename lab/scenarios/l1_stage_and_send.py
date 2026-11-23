#!/usr/bin/env python3
"""Exercise the L1 telemetry sequence on the approved isolated lab VMs."""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import re
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any

CANARY = Path("/lab/protected/nexus-l1-canary.txt")
MAN_DIR = Path("/lab/manifests")
BASH = "/usr/bin/bash"
CAT = "/usr/bin/cat"
CURL = "/usr/bin/curl"
TARGET = "192.168.20.10"
PORT = 8443
SHELL_SCRIPT = r"""
reader_start=$EPOCHREALTIME
"$1" -- "$2" >/dev/null &
reader_pid=$!
wait "$reader_pid"
reader_status=$?
printf 'reader\t%s\t%s\t%s\t%s\n' "$reader_pid" "$reader_start" "$EPOCHREALTIME" "$reader_status"
(( reader_status == 0 )) || exit "$reader_status"

client_start=$EPOCHREALTIME
"$3" --disable --ipv4 --noproxy '*' --fail --silent --output /dev/null \
    --connect-timeout 4 --max-time 10 \
    --write-out 'socket\t%{local_ip}\t%{local_port}\t%{remote_ip}\t%{remote_port}\t%{http_code}\n' \
    --request POST --header 'Content-Type: text/plain' \
    --data-raw 'NEXUS-L1-SYNTHETIC' "$4" &
client_pid=$!
wait "$client_pid"
client_status=$?
printf 'client\t%s\t%s\t%s\t%s\n' "$client_pid" "$client_start" "$EPOCHREALTIME" "$client_status"
exit "$client_status"
"""


def now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def shell_time(value: str) -> str:
    seconds, micros = value.split(".")
    return (
        datetime.fromtimestamp(int(seconds), UTC)
        .replace(microsecond=int(micros.ljust(6, "0")))
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def start_ticks(pid: int) -> dict[str, int]:
    try:
        tail = Path(f"/proc/{pid}/stat").read_text().rpartition(") ")[2]
        return {"start_ticks": int(tail.split()[19])}
    except (OSError, IndexError, ValueError):
        return {}


def socket_observation(fields: list[str]) -> dict[str, Any]:
    src, sport, dst, dport, http = fields
    observation: dict[str, Any] = {}
    for key, value in (("src_ip", src), ("dst_ip", dst)):
        try:
            address = ipaddress.ip_address(value)
        except ValueError:
            continue
        if not address.is_unspecified:
            observation[key] = str(address)
    for key, value in (("src_port", sport), ("dst_port", dport)):
        if value.isdecimal() and 0 < int(value) <= 65535:
            observation[key] = int(value)
    if http.isdecimal() and int(http):
        observation["http_status"] = int(http)
    return observation


def child_steps(trace: str, shell_pid: int) -> list[dict[str, Any]]:
    steps: list[dict[str, Any]] = []
    socket_fields: list[str] = []
    for line in trace.splitlines():
        kind, *fields = line.split("\t")
        if kind == "socket":
            socket_fields = fields
            continue
        pid, start, end, status = fields
        step = {
            "kind": "process",
            "role": kind,
            "pid": int(pid),
            "parent_pid": shell_pid,
            "binary": {"reader": CAT, "client": CURL}[kind],
            "start_utc": shell_time(start),
            "end_utc": shell_time(end),
            "wait_status": int(status),
        }
        steps.append(step)
        observed = {key: step[key] for key in ("pid", "start_utc", "end_utc")}
        if kind == "reader" and step["wait_status"] == 0:
            steps.append(
                observed | {"kind": "file", "path": str(CANARY), "operation": "read"}
            )
        if kind == "client" and socket_fields:
            details = socket_observation(socket_fields)
            if details:
                steps.append(
                    observed
                    | details
                    | {
                        "kind": "connection",
                        "observed_by": "curl",
                        "protocol": "TCP",
                        "direction": "outbound",
                    }
                )
    return steps


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--isolated-lab", action="store_true", help="run on the isolated Linux lab VM"
    )
    args = parser.parse_args(argv)
    if not args.isolated_lab:
        parser.error("--isolated-lab is required")
    endpoint = os.environ.get("NEXUS_ENDPOINT_ID", "linux-vm-01")
    if not re.fullmatch(r"[a-z0-9-]+", endpoint):
        parser.error("invalid NEXUS_ENDPOINT_ID")
    if not CANARY.is_file() or CANARY.resolve() != CANARY:
        parser.error("the regular L1 canary file is required")
    MAN_DIR.mkdir(mode=0o700, parents=True, exist_ok=True)

    root_pid = os.getpid()
    start = now()
    root = {
        "kind": "process",
        "role": "interp",
        "pid": root_pid,
        "parent_pid": os.getppid(),
        "binary": os.readlink("/proc/self/exe"),
        "invoked_binary": sys.executable,
        "observed_at_utc": start,
        **start_ticks(root_pid),
    }
    shell_start = now()
    proc = subprocess.Popen(
        [
            BASH,
            "-c",
            SHELL_SCRIPT,
            "nexus-l1",
            CAT,
            str(CANARY),
            CURL,
            f"http://{TARGET}:{PORT}/upload",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
    )
    shell_ticks = start_ticks(proc.pid)
    trace, _ = proc.communicate()
    end = now()
    steps = [
        root,
        {
            "kind": "process",
            "role": "shell",
            "pid": proc.pid,
            "parent_pid": root_pid,
            "binary": BASH,
            "start_utc": shell_start,
            "end_utc": end,
            "returncode": proc.returncode,
            **shell_ticks,
        },
        *child_steps(trace, proc.pid),
    ]
    manifest = {
        "scenario": "L1",
        "endpoint_id": endpoint,
        "start_utc": start,
        "end_utc": end,
        "root_pid": root_pid,
        "root_binary": root["binary"],
        "target": {"dst_ip": TARGET, "dst_port": PORT},
        "steps": steps,
        "connection_observed": any(step["kind"] == "connection" for step in steps),
    }
    with NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=MAN_DIR,
        prefix=f"L1-{start.replace(':', '')}-",
        suffix=".json",
        delete=False,
    ) as output:
        json.dump(manifest, output, indent=2)
        output.write("\n")
    print(json.dumps({"manifest": output.name, "exit_code": proc.returncode}))
    return 0 if proc.returncode == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
