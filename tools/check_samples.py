"""Fail-closed check for Sysmon sample files that are about to be committed to the PUBLIC repository.

The rule is allowlist-based: anything that is not explicitly known to be harmless is an error.
It runs in CI (no secrets needed) and locally before every commit that touches sample files.

What it enforces (see lab/sysmon/SAMPLE-COLLECTION.md for the human process around it):
  * only .xml / .json / .md files; never .evtx, .csv, screenshots or archives;
  * Sysmon events only (EID 1, 3, 5, 11, 22, 23, 26), with placeholder Computer, user, SID and GUIDs;
  * IPv4 addresses only from loopback and the lab subnets 192.168.10.0/24 and 192.168.20.0/24;
  * user-profile paths only for the placeholder users; no OneDrive paths;
  * command lines only if they reference C:\\Lab\\, carry the NEXUS_TEST marker, or are a bare system exe;
  * DNS names only under .nexus.test (or the lab hostnames);
  * optionally, a PRIVATE deny-list of strings (your real user name, computer name, e-mail, university
    path) supplied through --deny-file or the NEXUS_SAMPLE_DENY environment variable. The deny-list
    file must live outside the repository because it contains exactly the secrets being kept out.

Usage:
  python tools/check_samples.py [DIR ...] [--deny-file PATH]
Default DIR is endpoint-windows/tests/samples (missing is fine). It also fails if any *.evtx file
exists anywhere in the working tree outside .git, .venv and node_modules.
"""
from __future__ import annotations

import argparse
import ipaddress
import os
import re
import sys
from pathlib import Path
from xml.etree import ElementTree as ET

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DIR = ROOT / "endpoint-windows" / "tests" / "samples"

ALLOWED_EXT = {".xml", ".json", ".md"}
ALLOWED_EIDS = {"1", "3", "5", "11", "22", "23", "26"}
ALLOWED_COMPUTERS = {"dev-laptop", "windows-vm-01"}
ALLOWED_SIDS = {"S-1-5-18", "S-1-5-21-1000-1000-1000-1001"}
ALLOWED_USERS = {
    r"dev-laptop\dev", r"windows-vm-01\labuser",
    r"nt authority\system", r"nt authority\network service", r"nt authority\local service",
}
ALLOWED_PROFILES = {"dev", "public", "labuser", "default", "default user", "all users", "administrator"}
ALLOWED_HOSTNAMES = {"", "-", "dev-laptop", "windows-vm-01", "linux-vm-01", "nexus-server"}
ALLOWED_LAB_SUBNETS = [ipaddress.ip_network("192.168.10.0/24"), ipaddress.ip_network("192.168.20.0/24"),
                       ipaddress.ip_network("127.0.0.0/8")]
GUID_FIELDS = {"ProcessGuid", "ParentProcessGuid", "LogonGuid"}
FAKE_GUID = re.compile(r"^\{5eed0000-0000-0000-0000-[0-9a-f]{12}\}$", re.I)
ANY_GUID = re.compile(r"\{?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}?", re.I)
IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
IPV6_TOKEN = re.compile(r"^[0-9a-f:]+$", re.I)
PROFILE = re.compile(r"[A-Za-z]:\\Users\\([^\\\"'<>;\s]+)", re.I)
SYSTEM_EXE_ONLY = re.compile(r'^"?[A-Za-z]:\\(?:windows|program files(?: \(x86\))?)\\[^"]*\.exe"?$', re.I)
SKIP_IPV4_FIELDS = {"FileVersion"}  # four-part version numbers look like IPv4 addresses


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _ip_ok(text: str) -> bool:
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return False
    return ip.is_unspecified or any(ip in n for n in ALLOWED_LAB_SUBNETS if ip.version == n.version) or ip.is_loopback


def check_text(name: str, text: str, deny: list[str]) -> list[str]:
    """Checks that apply to any text file (xml, json, md)."""
    errs: list[str] = []
    low = text.lower()
    for d in deny:
        if d and d.lower() in low:
            errs.append(f"{name}: contains a string from your private deny-list")
    for m in PROFILE.finditer(text):
        if m.group(1).lower() not in ALLOWED_PROFILES:
            errs.append(f"{name}: user profile path for a real-looking user ({m.group(0)!r})")
    if "onedrive" in low:
        errs.append(f"{name}: mentions OneDrive (personal cloud path)")
    return errs


def check_xml(name: str, text: str, deny: list[str]) -> list[str]:
    errs = check_text(name, text, deny)
    if re.search(r"<!(DOCTYPE|ENTITY)", text, re.I):
        return errs + [f"{name}: DOCTYPE/ENTITY declarations are not allowed"]
    try:
        root = ET.fromstring(text)
    except ET.ParseError as e:
        return errs + [f"{name}: not well-formed XML ({e})"]
    if _local(root.tag) != "Event":
        return errs + [f"{name}: root element is not <Event>"]
    system = next((c for c in root if _local(c.tag) == "System"), None)
    edata = next((c for c in root if _local(c.tag) == "EventData"), None)
    if system is None or edata is None:
        return errs + [f"{name}: missing System or EventData"]
    sysd = {_local(c.tag): c for c in system}
    prov = sysd.get("Provider")
    if prov is None or prov.get("Name") != "Microsoft-Windows-Sysmon":
        errs.append(f"{name}: Provider is not Microsoft-Windows-Sysmon")
    eid = (sysd["EventID"].text or "").strip() if "EventID" in sysd else ""
    if eid not in ALLOWED_EIDS:
        errs.append(f"{name}: EventID {eid!r} is not one of {sorted(ALLOWED_EIDS, key=int)}")
    comp = (sysd["Computer"].text or "").strip() if "Computer" in sysd else ""
    if comp.lower() not in ALLOWED_COMPUTERS:
        errs.append(f"{name}: Computer {comp!r} is not a placeholder {sorted(ALLOWED_COMPUTERS)}")
    sec = sysd.get("Security")
    if sec is not None and sec.get("UserID") not in ALLOWED_SIDS:
        errs.append(f"{name}: SID {sec.get('UserID')!r} is not a placeholder")

    data = {d.get("Name", ""): (d.text or "").strip() for d in edata if _local(d.tag) == "Data"}
    for k, v in data.items():
        if k == "User" and v.lower() not in ALLOWED_USERS:
            errs.append(f"{name}: User {v!r} is not a placeholder user")
        if k in GUID_FIELDS and v and not FAKE_GUID.match(v):
            errs.append(f"{name}: {k} {v!r} is not a scrubbed GUID")
        if k not in SKIP_IPV4_FIELDS:
            for ip in IPV4.findall(v):
                if not _ip_ok(ip):
                    errs.append(f"{name}: {k} contains IPv4 {ip} outside loopback and the lab subnets")
        if k in ("SourceIp", "DestinationIp") and ":" in v:
            if not (IPV6_TOKEN.match(v) and v.lower() in ("::1", "0:0:0:0:0:0:0:1") or v.lower().startswith("fe80:")):
                errs.append(f"{name}: {k} contains IPv6 {v!r}; only loopback/link-local is allowed")
        if k in ("SourceHostname", "DestinationHostname"):
            h = v.lower().rstrip(".")
            if h not in ALLOWED_HOSTNAMES and not h.endswith(".nexus.test"):
                errs.append(f"{name}: {k} {v!r} is not a lab hostname")
        if k == "QueryName":
            q = v.lower().rstrip(".")
            if not (q.endswith(".nexus.test") or q in ALLOWED_HOSTNAMES):
                errs.append(f"{name}: QueryName {v!r} is not under .nexus.test")
        if k in ("CommandLine", "ParentCommandLine") and v not in ("", "-", "?"):
            ok = (r"c:\lab" + "\\") in v.lower() or "NEXUS_TEST" in v or SYSTEM_EXE_ONLY.match(v)
            if not ok:
                errs.append(f"{name}: {k} is not lab-related and may contain personal data: {v[:60]!r}")
        if k == "CurrentDirectory" and v:
            lv = v.lower()
            if not lv.startswith(("c:\\lab\\", "c:\\windows\\", "c:\\users\\dev\\", "c:\\program files")):
                errs.append(f"{name}: CurrentDirectory {v!r} is outside the allowed prefixes")
    for g in ANY_GUID.findall(text):
        if not FAKE_GUID.match(g if g.startswith("{") else "{" + g.strip("{}") + "}") and \
                g.strip("{}").lower() != "5770385f-c22a-43e0-bf4c-06f5698ffbd9":  # Sysmon provider GUID (public)
            errs.append(f"{name}: unscrubbed GUID {g}")
    return sorted(set(errs))


def check_dir(d: Path, deny: list[str]) -> list[str]:
    errs: list[str] = []
    for p in sorted(d.rglob("*")):
        if p.is_dir():
            continue
        name = str(p.relative_to(d))
        ext = p.suffix.lower()
        if ext not in ALLOWED_EXT:
            errs.append(f"{name}: extension {ext or '(none)'} is not allowed in samples (allowed: {sorted(ALLOWED_EXT)})")
            continue
        text = p.read_text(encoding="utf-8-sig", errors="replace")
        if ext == ".xml":
            errs += check_xml(name, text, deny)
        else:
            errs += check_text(name, text, deny)
            for ip in IPV4.findall(text):
                if not _ip_ok(ip):
                    errs.append(f"{name}: IPv4 {ip} outside loopback and the lab subnets")
            for g in ANY_GUID.findall(text):
                if not FAKE_GUID.match("{" + g.strip("{}") + "}"):
                    errs.append(f"{name}: unscrubbed GUID {g}")
    return errs


def stray_raw_captures(root: Path) -> list[str]:
    bad: list[str] = []
    for dirpath, dirnames, files in os.walk(root):
        dirnames[:] = [x for x in dirnames if x not in {".git", ".venv", "node_modules", "__pycache__"}]
        bad += [str(Path(dirpath, f).relative_to(root)) for f in files if f.lower().endswith(".evtx")]
    return [f"{p}: raw .evtx captures must never be inside the repository folder" for p in bad]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("dirs", nargs="*", type=Path)
    ap.add_argument("--deny-file", type=Path, default=os.environ.get("NEXUS_SAMPLE_DENY"),
                    help="private file, one forbidden string per line (keep it OUTSIDE the repository)")
    args = ap.parse_args(argv)
    deny: list[str] = []
    if args.deny_file:
        deny = [ln.strip() for ln in Path(args.deny_file).read_text(encoding="utf-8").splitlines() if ln.strip()]
        if ROOT in Path(args.deny_file).resolve().parents:
            print("WARNING: the deny-file is inside the repository; move it out so it is never committed")
    errs = stray_raw_captures(ROOT)
    dirs = args.dirs or [DEFAULT_DIR]
    checked = 0
    for d in dirs:
        if not d.exists():
            print(f"note: {d} does not exist yet; nothing to check")
            continue
        checked += sum(1 for p in d.rglob("*") if p.is_file())
        errs += check_dir(d, deny)
    for e in errs:
        print("ERROR", e)
    print(f"{checked} sample file(s) checked, {len(errs)} problem(s)" + ("" if deny else " (no private deny-list supplied)"))
    return 1 if errs else 0


if __name__ == "__main__":
    sys.exit(main())
