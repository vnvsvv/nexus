import json
import re
from pathlib import Path

import pytest

from nexus_contracts import MLPrediction, NfLite1
from nexus_ml.classifier import DummyClassifier


@pytest.mark.parametrize("as_model", [False, True])
def test_gateway_dummy_prediction(as_model):
    fixture = Path(__file__).resolve().parents[2] / "contracts/fixtures/flow_feature_fixture.json"
    flow = json.loads(fixture.read_text(encoding="utf-8"))
    features = dict(zip(flow["expected_names"], flow["expected_vector"], strict=True))
    prediction = DummyClassifier().predict(NfLite1(**features) if as_model else features)
    assert isinstance(prediction, MLPrediction)
    assert prediction.label == "benign"
    assert prediction.score == 0.0
    assert prediction.threshold == 0.5
    assert prediction.model_version == "ids-dummy-000"
    assert prediction.feature_version == "nf-lite-1"
    assert re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z", prediction.predicted_at_utc)


@pytest.mark.parametrize("invalid", [{}, None, [], {"unexpected": 1}])
def test_dummy_rejects_incomplete_inputs(invalid):
    with pytest.raises(ValueError):
        DummyClassifier().predict(invalid)


@pytest.mark.parametrize("patch", [
    {"in_pkts": -1}, {"in_pkts": 1.5}, {"in_pkts": True},
    {"mean_pkt_size": float("nan")}, {"mean_pkt_size": float("inf")},
    {"ORDER": ()}, {"unexpected": 1},
])
def test_dummy_rejects_malformed_flow(patch):
    from nexus_ml.features import FEATURE_ORDER

    features = dict.fromkeys(FEATURE_ORDER, 0)
    with pytest.raises(ValueError):
        DummyClassifier().predict({**features, **patch})


def test_dummy_revalidates_model_values():
    from nexus_ml.features import FEATURE_ORDER

    flow = NfLite1(**dict.fromkeys(FEATURE_ORDER, 0))
    with pytest.raises(ValueError):
        DummyClassifier().predict(flow.model_copy(update={"mean_pkt_size": -1}))
