"""Scrub raw Sysmon XML events (exported from your own machine) into commit-safe sample files.

It is a helper, not a guarantee. The guarantees come from (1) collecting only scripted lab activity
and (2) tools/check_samples.py, which fails closed. Always read the scrubbed files yourself.

What it replaces, consistently across all files so parent/child links survive:
  * your computer name  -> dev-laptop (or windows-vm-01 with --computer-as)
  * your user name      -> dev        (or labuser with --user-as)
  * every real SID (S-1-5-21-a-b-c-rid) -> S-1-5-21-1000-1000-1000-1001
  * ProcessGuid, ParentProcessGuid, LogonGuid -> {5eed0000-0000-0000-0000-0000000000NN}
  * any extra literal you pass with --map OLD=NEW (e.g. your LAN IP -> 192.168.20.10)
Output files are renamed eid<N>-<index>.xml so original names (which can contain dates or names) are dropped.

Usage:
  python tools/scrub_samples.py RAW_DIR OUT_DIR --computer LAPTOP-XXXX --user MYNAME \\
         --map 192.168.1.23=192.168.20.10 --map "OneDrive - Some University=Documents"
RAW_DIR must be outside the repository.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SID = re.compile(r"S-1-5-21-\d+-\d+-\d+-\d+")
GUID_DATA = re.compile(r'(<Data Name="(?:ProcessGuid|ParentProcessGuid|LogonGuid)">)(\{[0-9A-Fa-f-]{36}\})(</Data>)')
EVENT_ID = re.compile(r"<EventID[^>]*>(\d+)</EventID>")


def _word_sub(text: str, old: str, new: str) -> str:
    return re.sub(r"(?<![A-Za-z0-9])" + re.escape(old) + r"(?![A-Za-z0-9])", new, text, flags=re.I)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("raw_dir", type=Path)
    ap.add_argument("out_dir", type=Path)
    ap.add_argument("--computer", required=True, help="your real computer name")
    ap.add_argument("--computer-as", default="dev-laptop", choices=["dev-laptop", "windows-vm-01"])
    ap.add_argument("--user", required=True, help="your real Windows user name")
    ap.add_argument("--user-as", default="dev", choices=["dev", "labuser"])
    ap.add_argument("--map", action="append", default=[], metavar="OLD=NEW", help="extra literal replacement (repeatable)")
    args = ap.parse_args(argv)

    raw = args.raw_dir.resolve()
    if ROOT in raw.parents or raw == ROOT:
        print("refusing: RAW_DIR is inside the repository. Keep raw captures outside it.")
        return 2
    extra = [m.split("=", 1) for m in args.map]
    if any(len(x) != 2 or not x[0] for x in extra):
        print("--map needs OLD=NEW")
        return 2
    args.out_dir.mkdir(parents=True, exist_ok=True)
    guids: dict[str, str] = {}
    counters: dict[str, int] = {}

    def fake_guid(m: re.Match) -> str:
        real = m.group(2).lower()
        guids.setdefault(real, "{5eed0000-0000-0000-0000-%012x}" % (len(guids) + 1))
        return m.group(1) + guids[real] + m.group(3)

    files = sorted(p for p in raw.glob("*.xml"))
    if not files:
        print(f"no .xml files in {raw}")
        return 1
    for p in files:
        text = p.read_text(encoding="utf-8-sig", errors="replace")
        for old, new in extra:  # literal maps first so longer, more specific strings win
            text = re.sub(re.escape(old), new, text, flags=re.I)
        text = _word_sub(text, args.computer, args.computer_as)
        text = _word_sub(text, args.user, args.user_as)
        text = SID.sub("S-1-5-21-1000-1000-1000-1001", text)
        text = GUID_DATA.sub(fake_guid, text)
        m = EVENT_ID.search(text)
        eid = m.group(1) if m else "x"
        counters[eid] = counters.get(eid, 0) + 1
        (args.out_dir / f"eid{eid}-{counters[eid]:03d}.xml").write_text(text, encoding="utf-8")
    print(f"scrubbed {len(files)} file(s) into {args.out_dir}; {len(guids)} GUID(s) replaced")
    print("NEXT: read every output file, then run: python tools/check_samples.py [--deny-file <private file>]")
    return 0


if __name__ == "__main__":
    sys.exit(main())
