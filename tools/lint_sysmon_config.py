"""Static checks for the NEXUS Sysmon configs.

THIS IS NOT A SYSMON VALIDATION. It cannot know whether Sysmon accepts a file. It only checks:
  * the file is well-formed XML, ASCII-only, with the expected schema version and global settings;
  * every event type is explicitly configured (nothing is left to Sysmon's defaults);
  * the profile-specific invariants that protect privacy (dev) or lab behaviour (lab).
The authoritative checks are `Sysmon64.exe -? config`, `Sysmon64.exe -s` and installing the config.

Usage:
  python tools/lint_sysmon_config.py [--schema-dump sysmon-schema.txt] [FILE ...]
With no FILE it checks both configs under lab/sysmon/. The profile is taken from the file name
(*-dev.xml -> dev, otherwise lab).

--schema-dump takes the saved output of `Sysmon64.exe -s` and does a WEAK check: each event element
name and field name used in the config must occur somewhere in that text. It cannot prove a field
belongs to the right event, but it catches typos and fields your Sysmon version does not know.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from xml.etree import ElementTree as ET

ROOT = Path(__file__).resolve().parent.parent
SCHEMA_VERSION = "4.91"

# Event element names the configs may use (from general Sysmon knowledge; unverified against 15.22).
ALL_EVENTS = [
    "ProcessCreate", "FileCreateTime", "NetworkConnect", "ProcessTerminate", "DriverLoad", "ImageLoad",
    "CreateRemoteThread", "RawAccessRead", "ProcessAccess", "FileCreate", "RegistryEvent",
    "FileCreateStreamHash", "PipeEvent", "WmiEvent", "DnsQuery", "FileDelete", "ClipboardChange",
    "ProcessTampering", "FileDeleteDetected", "FileExecutableDetected",
]
# Fields the configs may filter on, per event (from general knowledge; confirm with `Sysmon64.exe -s`).
KNOWN_FIELDS = {
    "ProcessCreate": {"Image", "CommandLine", "ParentImage", "ParentCommandLine"},
    "NetworkConnect": {"Image", "DestinationIp", "DestinationPort"},
    "ProcessTerminate": {"Image"},
    "FileCreate": {"TargetFilename"},
    "DnsQuery": {"QueryName"},
    "FileDelete": {"TargetFilename"},
    "FileDeleteDetected": {"TargetFilename"},
}
GLOBAL_TAGS = {"HashAlgorithms", "CheckRevocation", "DnsLookup", "EventFiltering"}

DEV_ENABLED = {"ProcessCreate", "NetworkConnect", "ProcessTerminate", "FileCreate", "DnsQuery", "FileDeleteDetected"}
LAB_ENABLED = DEV_ENABLED
TOOL_IMAGES = {r"\cmd.exe", r"\powershell.exe", r"\pwsh.exe", r"\python.exe", r"\curl.exe"}


def _rules(ev: ET.Element):
    """Yield (field, condition, value) for each rule of an event filter element."""
    for r in ev:
        yield r.tag, r.get("condition", "is"), (r.text or "").strip()


def _collect(root: ET.Element):
    """Return {event: {"include": [ (field,cond,val) ...] | None, "exclude": [...] | None}}."""
    out: dict[str, dict[str, list | None]] = {}
    problems: list[str] = []
    ef = root.find("EventFiltering")
    if ef is None:
        return out, ["missing <EventFiltering>"]
    for g in ef:
        if g.tag != "RuleGroup":
            problems.append(f"<{g.tag}> directly under EventFiltering; expected RuleGroup")
            continue
        if g.get("groupRelation") not in ("or", "and"):
            problems.append(f"RuleGroup '{g.get('name')}' has no explicit groupRelation")
        for ev in g:
            if ev.tag not in ALL_EVENTS:
                problems.append(f"unknown event element <{ev.tag}>")
                continue
            mode = ev.get("onmatch")
            if mode not in ("include", "exclude"):
                problems.append(f"<{ev.tag}> has onmatch={mode!r}")
                continue
            slot = out.setdefault(ev.tag, {"include": None, "exclude": None})
            if slot[mode] is not None:
                problems.append(f"<{ev.tag}> has two {mode} filters")
            slot[mode] = list(_rules(ev))
    return out, problems


def lint(path: Path, profile: str, schema_dump: str | None = None) -> list[str]:
    errs: list[str] = []
    raw = path.read_bytes()
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as e:
        return [f"non-ASCII byte at offset {e.start}; keep Sysmon configs ASCII-only"]
    header = text.split("-->", 1)[0]
    unvalidated = re.search(r"\bUNVALIDATED\b", header) is not None
    validated = re.search(r"(?<![A-Za-z])VALIDATED \d{4}-\d{2}-\d{2}\b", header) is not None
    if unvalidated == validated:
        errs.append("header comment must say exactly one of UNVALIDATED or 'VALIDATED YYYY-MM-DD' "
                    "(the date a real Sysmon loaded and verified the file)")
    try:
        root = ET.fromstring(text)
    except ET.ParseError as e:
        return [f"not well-formed XML: {e}"]
    if root.tag != "Sysmon":
        return [f"root element is <{root.tag}>, expected <Sysmon>"]
    if root.get("schemaversion") != SCHEMA_VERSION:
        errs.append(f"schemaversion={root.get('schemaversion')!r}, expected {SCHEMA_VERSION!r}")
    for tag in root:
        if tag.tag not in GLOBAL_TAGS:
            errs.append(f"unexpected top-level element <{tag.tag}>")
    if (root.findtext("HashAlgorithms") or "").strip() != "SHA256":
        errs.append("HashAlgorithms must be exactly SHA256")
    if (root.findtext("CheckRevocation") or "").strip() != "False":
        errs.append("CheckRevocation must be False (no certificate-revocation lookups)")
    if (root.findtext("DnsLookup") or "").strip() != "False":
        errs.append("DnsLookup must be False (no reverse DNS lookups of destinations)")

    events, problems = _collect(root)
    errs += problems
    for name in ALL_EVENTS:
        if name not in events:
            errs.append(f"event <{name}> is not configured explicitly")
    for name, slots in events.items():
        for mode, rules in slots.items():
            for field, cond, val in rules or []:
                if name in KNOWN_FIELDS and field not in KNOWN_FIELDS[name]:
                    errs.append(f"<{name}> {mode}: field <{field}> is not in the known-field table")
                if not val:
                    errs.append(f"<{name}> {mode}: empty value for <{field}>")

    # An empty include filter means "log nothing"; an exclude filter with no include means "log everything".
    def enabled(ev: str) -> bool:
        s = events.get(ev, {})
        return bool(s.get("include")) or (s.get("include") is None and s.get("exclude") is not None)

    on = {e for e in ALL_EVENTS if enabled(e)}
    want = DEV_ENABLED if profile == "dev" else LAB_ENABLED
    if on != want:
        errs.append(f"enabled events are {sorted(on)}, expected {sorted(want)}")
    if events.get("FileDelete", {}).get("include") or events.get("FileDelete", {}).get("exclude") is not None:
        errs.append("EID 23 (FileDelete) must stay off: it archives deleted files into C:\\Sysmon")
    fdd = events.get("FileDeleteDetected", {}).get("include") or []
    if [(f, c, v.lower()) for f, c, v in fdd] != [("TargetFilename", "begin with", "c:\\lab\\")]:
        errs.append("FileDeleteDetected (EID 26) must include exactly: TargetFilename begin with C:\\Lab\\")

    if profile == "dev":
        errs += _dev_invariants(events)
    else:
        errs += _lab_invariants(events)
    if schema_dump is not None:
        errs += _schema_dump_check(root, schema_dump)
    return errs


def _dev_invariants(ev: dict) -> list[str]:
    e: list[str] = []
    # No enabled event may be exclude-only (that would log everything).
    for name in DEV_ENABLED:
        if not ev.get(name, {}).get("include"):
            e.append(f"dev: <{name}> must have an include filter with rules (exclude-only logs everything)")
    allowed_image_suffix = TOOL_IMAGES
    for name in ("NetworkConnect", "ProcessTerminate"):
        for f, c, v in ev.get(name, {}).get("include") or []:
            ok = f == "Image" and ((c == "end with" and v.lower() in allowed_image_suffix)
                                   or (c == "begin with" and v.lower() == "c:\\lab\\"))
            if not ok:
                e.append(f"dev: <{name}> include {f} {c} {v!r} is outside the allowed tool/lab set")
    for f, c, v in ev.get("ProcessCreate", {}).get("include") or []:
        ok = (f in ("CommandLine", "ParentCommandLine", "Image", "ParentImage") and v.lower() == "c:\\lab\\"
              and c in ("contains", "begin with")) or (f == "CommandLine" and c == "contains" and v == "NEXUS_TEST")
        if not ok:
            e.append(f"dev: <ProcessCreate> include {f} {c} {v!r} is broader than the lab folder or marker")
    for f, c, v in ev.get("FileCreate", {}).get("include") or []:
        if not (f == "TargetFilename" and c == "begin with" and v.lower() == "c:\\lab\\"):
            e.append(f"dev: <FileCreate> include {f} {c} {v!r} must be exactly C:\\Lab\\")
    for f, c, v in ev.get("DnsQuery", {}).get("include") or []:
        if not (f == "QueryName" and c == "end with" and v == ".nexus.test"):
            e.append(f"dev: <DnsQuery> include {f} {c} {v!r} must be exactly the .nexus.test suffix")
    excl = {(f, c, v) for f, c, v in ev.get("NetworkConnect", {}).get("exclude") or []}
    for port in ("80", "443"):
        if ("DestinationPort", "is", port) not in excl:
            e.append(f"dev: <NetworkConnect> must exclude DestinationPort {port}")
    for ip in ("127.", "fe80:"):
        if ("DestinationIp", "begin with", ip) not in excl:
            e.append(f"dev: <NetworkConnect> must exclude DestinationIp begin with {ip}")
    return e


def _lab_invariants(ev: dict) -> list[str]:
    e: list[str] = []
    nc = {(f, c, v) for f, c, v in ev.get("NetworkConnect", {}).get("exclude") or []}
    for ip in ("192.168.20.1", "192.168.10.1"):
        if ("DestinationIp", "is", ip) not in nc:
            e.append(f"lab: <NetworkConnect> must exclude agent traffic to {ip}")
    dns = {(f, c, v) for f, c, v in ev.get("DnsQuery", {}).get("exclude") or []}
    if ("QueryName", "begin with", "nexus-server") not in dns:
        e.append("lab: <DnsQuery> must exclude nexus-server")
    fc = {(f, c, v.lower()) for f, c, v in ev.get("FileCreate", {}).get("exclude") or []}
    if ("TargetFilename", "begin with", "c:\\lab\\manifests\\") not in fc:
        e.append("lab: <FileCreate> must exclude C:\\Lab\\manifests\\")
    if ev.get("ProcessCreate", {}).get("include"):
        e.append("lab: <ProcessCreate> is exclude-based; an include filter would silently narrow it")
    return e


def _schema_dump_check(root: ET.Element, dump: str) -> list[str]:
    errs: list[str] = []
    seen_events: set[str] = set()
    seen_fields: set[str] = set()
    for g in root.iter("RuleGroup"):
        for ev in g:
            seen_events.add(ev.tag)
            for r in ev:
                seen_fields.add(r.tag)
    for name in sorted(seen_events | seen_fields):
        if not re.search(r"\b" + re.escape(name) + r"\b", dump):
            errs.append(f"'{name}' does not occur in the supplied `Sysmon64.exe -s` output")
    return errs


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("files", nargs="*", type=Path)
    ap.add_argument("--schema-dump", type=Path, help="saved output of `Sysmon64.exe -s` (weak name check)")
    args = ap.parse_args(argv)
    files = args.files or [ROOT / "lab/sysmon/nexus-sysmon-dev.xml", ROOT / "lab/sysmon/nexus-sysmon.xml"]
    dump = args.schema_dump.read_text(encoding="utf-8", errors="replace") if args.schema_dump else None
    bad = 0
    for f in files:
        profile = "dev" if f.name.endswith("-dev.xml") else "lab"
        errs = lint(f, profile, dump)
        print(f"{'FAIL' if errs else 'ok  '} {f} (profile={profile})")
        for m in errs:
            print(f"     - {m}")
        bad += bool(errs)
    print("static lint only; this does NOT prove Sysmon accepts the file" if not bad else "lint failed")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
