"""Load and save the served model artifact."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import joblib

from phishing.config import ARTIFACTS_DIR
from phishing.schema import ModelArtifact


def persist_model(
    estimator,
    feature_names: list[str],
    threshold: float,
    metrics: dict[str, float],
    model_name: str,
    notes: str = "",
    extra: dict[str, Any] | None = None,
    extra_estimators: dict[str, Any] | None = None,
    path: Path | None = None,
) -> Path:
    ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    path = path or (ARTIFACTS_DIR / "model.joblib")
    artifact = ModelArtifact(
        model_name=model_name,
        feature_names=list(feature_names),
        threshold=float(threshold),
        metrics={k: float(v) for k, v in metrics.items()},
        trained_at=datetime.now(UTC).isoformat(),
        notes=notes,
        extra=extra or {},
    )
    payload: dict[str, Any] = {"estimator": estimator, "artifact": artifact}
    if extra_estimators:
        payload.update(extra_estimators)
    joblib.dump(payload, path)
    return path


def load_payload(path: Path | None = None) -> dict[str, Any]:
    path = path or (ARTIFACTS_DIR / "model.joblib")
    return joblib.load(path)


def load_model(path: Path | None = None) -> tuple[Any, ModelArtifact]:
    payload = load_payload(path)
    return payload["estimator"], payload["artifact"]
