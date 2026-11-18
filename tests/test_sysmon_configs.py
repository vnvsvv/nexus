"""Static tests for the Sysmon configs and the sample checker.

These do NOT validate the configs against a real Sysmon. They keep the privacy invariants of the
dev profile and the lab-profile decisions from regressing, and they exercise tools/check_samples.py
with synthetic data only (no real Windows capture exists in this repository yet).
"""
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))

import check_samples  # noqa: E402
import lint_sysmon_config as lint  # noqa: E402

DEV = ROOT / "lab/sysmon/nexus-sysmon-dev.xml"
LAB = ROOT / "lab/sysmon/nexus-sysmon.xml"


def _mutate(tmp_path: Path, src: Path, old: str, new: str) -> Path:
    text = src.read_text()
    assert old in text, old
    out = tmp_path / src.name
    out.write_text(text.replace(old, new, 1))
    return out


def test_shipped_configs_lint_clean():
    assert lint.lint(DEV, "dev") == []
    assert lint.lint(LAB, "lab") == []


def test_lint_cli_exit_code():
    r = subprocess.run([sys.executable, "-I", str(ROOT / "tools/lint_sysmon_config.py")], capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr


@pytest.mark.parametrize("old,new,needle", [
    ('<TargetFilename condition="begin with">C:\\Lab\\</TargetFilename>\n      </FileCreate>\n      <FileCreate onmatch="exclude">',
     '<TargetFilename condition="begin with">C:\\Users\\</TargetFilename>\n      </FileCreate>\n      <FileCreate onmatch="exclude">',
     "FileCreate"),
    ('<QueryName condition="end with">.nexus.test</QueryName>', '<QueryName condition="end with">.com</QueryName>', "DnsQuery"),
    ('<DestinationPort condition="is">443</DestinationPort>', '', "DestinationPort 443"),
    ('<FileDelete onmatch="include" />', '<FileDelete onmatch="include"><TargetFilename condition="begin with">C:\\Lab\\</TargetFilename></FileDelete>', "EID 23"),
    ('<ImageLoad onmatch="include" />', '<ImageLoad onmatch="exclude" />', "ImageLoad"),
    ('<Image condition="end with">\\curl.exe</Image>\n        <Image condition="begin with">C:\\Lab\\</Image>\n      </NetworkConnect>',
     '<Image condition="end with">\\chrome.exe</Image>\n        <Image condition="begin with">C:\\Lab\\</Image>\n      </NetworkConnect>', "NetworkConnect"),
    ('<CommandLine condition="contains">NEXUS_TEST</CommandLine>', '<CommandLine condition="contains">powershell</CommandLine>', "ProcessCreate"),
])
def test_dev_privacy_regressions_are_caught(tmp_path, old, new, needle):
    bad = _mutate(tmp_path, DEV, old, new)
    errs = lint.lint(bad, "dev")
    assert errs and any(needle in e for e in errs), errs


def test_non_ascii_and_missing_marker_and_schema_are_caught(tmp_path):
    assert any("non-ASCII" in e for e in lint.lint(_mutate(tmp_path, DEV, "EID 1   process", "EID 1 \u2014 process"), "dev"))
    no_marker = tmp_path / "nomarker-dev.xml"
    no_marker.write_text(DEV.read_text().replace("UNVALIDATED", "checked"))
    assert any("UNVALIDATED" in e for e in lint.lint(no_marker, "dev"))
    both = tmp_path / "both-dev.xml"
    both.write_text(DEV.read_text().replace("UNVALIDATED.", "UNVALIDATED. VALIDATED 2026-12-01.", 1))
    assert any("exactly one" in e for e in lint.lint(both, "dev"))
    # after real validation the marker is replaced by a dated one, and lint must still pass
    done = tmp_path / "done-dev.xml"
    done.write_text(DEV.read_text().replace("UNVALIDATED", "VALIDATED 2026-12-01"))
    assert lint.lint(done, "dev") == []
    assert any("schemaversion" in e for e in lint.lint(_mutate(tmp_path, DEV, 'schemaversion="4.91"', 'schemaversion="4.90"'), "dev"))
    assert any("groupRelation" in e for e in lint.lint(_mutate(tmp_path, DEV, '<RuleGroup name="DnsQuery" groupRelation="or">', '<RuleGroup name="DnsQuery">'), "dev"))


def test_lab_decisions_are_caught(tmp_path):
    assert any("192.168.20.1" in e for e in lint.lint(_mutate(tmp_path, LAB, '<DestinationIp condition="is">192.168.20.1</DestinationIp>', ""), "lab"))
    assert any("manifests" in e for e in lint.lint(_mutate(tmp_path, LAB, r'C:\Lab\manifests\</TargetFilename>', r'C:\Lab\other\</TargetFilename>'), "lab"))
    assert any("EID 23" in e for e in lint.lint(_mutate(tmp_path, LAB, '<FileDelete onmatch="include" />', '<FileDelete onmatch="exclude" />'), "lab"))


def test_schema_dump_weak_check(tmp_path):
    names = set(re.findall(r"<(\w+) (?:onmatch|condition)|<(\w+) condition", DEV.read_text()))
    ok_dump = " ".join(lint.ALL_EVENTS) + " Image CommandLine ParentImage ParentCommandLine DestinationIp DestinationPort TargetFilename QueryName"
    assert lint.lint(DEV, "dev", ok_dump) == []
    assert any("ParentCommandLine" in e for e in lint.lint(DEV, "dev", ok_dump.replace("ParentCommandLine", "")))
    assert names  # sanity: the regex found something


# ---------------------------------------------------------------- sample checker (synthetic data)

NS = "http://schemas.microsoft.com/win/2004/08/events/event"


def _event(eid=1, computer="dev-laptop", sid="S-1-5-21-1000-1000-1000-1001", data=None):
    data = {"ProcessGuid": "{5eed0000-0000-0000-0000-000000000001}", "Image": r"C:\Windows\System32\cmd.exe",
            "CommandLine": r'cmd /c "C:\Lab\scenarios\x.cmd"', "User": r"dev-laptop\dev", **(data or {})}
    items = "".join(f'<Data Name="{k}">{v}</Data>' for k, v in data.items())
    return (f'<Event xmlns="{NS}"><System><Provider Name="Microsoft-Windows-Sysmon"/><EventID>{eid}</EventID>'
            f'<Computer>{computer}</Computer><Security UserID="{sid}"/></System><EventData>{items}</EventData></Event>')


def _check(tmp_path, xml, name="eid1-001.xml", deny=()):
    d = tmp_path / "samples"
    d.mkdir(exist_ok=True)
    (d / name).write_text(xml)
    return check_samples.check_dir(d, deny=list(deny))


def test_sample_checker_accepts_scrubbed_sample(tmp_path):
    assert _check(tmp_path, _event()) == []


@pytest.mark.parametrize("xml,needle", [
    (_event(computer="LAPTOP-8F2K1"), "Computer"),
    (_event(sid="S-1-5-21-123456789-987654321-111222333-1001"), "SID"),
    (_event(data={"CommandLine": r"C:\Users\someone\AppData\x.exe C:\Lab\a"}), "user profile"),
    (_event(data={"ProcessGuid": "{3c1a7d2e-5f10-6511-1a02-00000000a100}"}), "GUID"),
    (_event(eid=3, data={"DestinationIp": "93.184.216.34", "SourceIp": "192.168.20.10"}), "IPv4"),
    (_event(data={"CommandLine": r'powershell -c "Invoke-X -Token abc"'}), "CommandLine"),
    (_event(eid=9), "EventID"),
    ("<notxml", "XML"),
])
def test_sample_checker_rejects(tmp_path, xml, needle):
    errs = _check(tmp_path, xml)
    assert errs and any(needle in e for e in errs), errs


def test_sample_checker_denylist_and_extensions(tmp_path):
    xml = _event(data={"CommandLine": r"cmd /c C:\Lab\a.cmd secretword"})
    assert any("deny" in e for e in _check(tmp_path, xml, deny=["SecretWord"]))
    (tmp_path / "samples" / "raw.evtx").write_bytes(b"x")
    assert any("extension" in e for e in check_samples.check_dir(tmp_path / "samples", deny=[]))
