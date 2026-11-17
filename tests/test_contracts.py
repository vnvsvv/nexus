"""Contract tests: fixtures validate; models and schemas agree; mock server behaves."""
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from nexus_contracts import HostEvent, Incident, NfLite1, validate_against_schema  # noqa: E402

FIX = ROOT / "contracts" / "fixtures"


def test_validate_fixtures_script():
    r = subprocess.run([sys.executable, "-I", str(ROOT / "tools" / "validate_fixtures.py")], capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr


def test_host_event_requires_subobject():
    ev = json.loads((FIX / "linux_l1_events.jsonl").read_text().splitlines()[-1])
    assert ev["event_type"] == "network_connect"
    bad = dict(ev)
    bad.pop("network")
    with pytest.raises(Exception):
        HostEvent.model_validate(bad)
    assert validate_against_schema("host_event", bad)


def test_incident_roundtrip_exclude_none():
    inc = Incident.model_validate(json.loads((FIX / "incident_linux_l1.json").read_text()))
    out = inc.model_dump(mode="json", by_alias=True, exclude_none=True)
    assert not validate_against_schema("incident", out)
    assert out["relationships"][0]["from"].startswith("linux-vm-01:")


def test_feature_order_matches_fixture():
    fx = json.loads((FIX / "flow_feature_fixture.json").read_text())
    assert list(NfLite1.model_fields["ORDER"].default) == fx["expected_names"]
    assert len(fx["expected_vector"]) == 24
