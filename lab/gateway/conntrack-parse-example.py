#!/usr/bin/env python3
"""Reference parser for `conntrack -E -e NEW,DESTROY -o timestamp,extended` output.
Rakan's connection_registry wraps this; it is here so the format is agreed and testable.

Example lines (ipv4, with -o timestamp,extended):
[1731666606.012345]     [NEW] ipv4     2 tcp      6 120 SYN_SENT src=192.168.10.10 dst=192.168.20.10 sport=51542 dport=8443 [UNREPLIED] src=192.168.20.10 dst=192.168.10.10 sport=8443 dport=51542
[1731666608.100001] [DESTROY] ipv4     2 tcp      6 src=192.168.10.10 dst=192.168.20.10 sport=51542 dport=8443 packets=9 bytes=1812 src=192.168.20.10 dst=192.168.10.10 sport=8443 dport=51542 packets=7 bytes=614
"""
from __future__ import annotations

import re
from datetime import datetime, timezone

LINE = re.compile(r"^\[(?P<ts>[0-9.]+)\]\s+\[(?P<ev>NEW|DESTROY|UPDATE)\]\s+ipv4\s+\d+\s+(?P<proto>tcp|udp|icmp)\s+\d+\s+(?P<rest>.*)$")
KV = re.compile(r"(\w+)=(\S+)")


def parse(line: str) -> dict | None:
    m = LINE.match(line.strip())
    if not m:
        return None
    kvs = KV.findall(m.group("rest"))
    # first src/dst/sport/dport block = original direction; second = reply direction
    orig, reply = {}, {}
    seen_src = 0
    for k, v in kvs:
        if k == "src":
            seen_src += 1
        (orig if seen_src <= 1 else reply)[k] = v
    ts = datetime.fromtimestamp(float(m.group("ts")), tz=timezone.utc)
    return {
        "event": m.group("ev"),
        "protocol": m.group("proto").upper(),
        "orig_src_ip": orig.get("src"), "orig_src_port": int(orig.get("sport", 0)),
        "orig_dst_ip": orig.get("dst"), "orig_dst_port": int(orig.get("dport", 0)),
        "timestamp_utc": ts.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
        "packets_orig": int(orig.get("packets", 0)) or None, "bytes_orig": int(orig.get("bytes", 0)) or None,
        "packets_reply": int(reply.get("packets", 0)) or None, "bytes_reply": int(reply.get("bytes", 0)) or None,
    }


if __name__ == "__main__":
    import sys
    for ln in sys.stdin:
        p = parse(ln)
        if p:
            print(p)
