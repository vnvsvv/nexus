"""Baseline predictor used by the gateway before a trained bundle is available."""

from typing import Any

from nexus_contracts import MLPrediction, NfLite1, utc_now_iso

from .features import FEATURE_ORDER, validated_vector


class DummyClassifier:
    """Return the fixed Week 1 baseline prediction for a flow."""

    model_version = "ids-dummy-000"

    def predict(self, features: dict[str, Any] | NfLite1) -> MLPrediction:
        if isinstance(features, NfLite1):
            if features.ORDER != FEATURE_ORDER:
                raise ValueError("unexpected nf-lite-1 feature order")
            features = features.model_dump()
        if not isinstance(features, dict):
            raise ValueError("expected an nf-lite-1 feature dictionary or model")
        validated_vector(features)
        return MLPrediction(
            label="benign",
            score=0.0,
            threshold=0.5,
            model_version=self.model_version,
            predicted_at_utc=utc_now_iso(),
        )
