"""Load and save the served model artifact.

The served model is stored in XGBoost's native format, not a pickle:

* ``artifacts/model_meta.json``: the :class:`ModelArtifact` fields plus the
  file name of each booster;
* ``artifacts/page.ubj`` and ``artifacts/url.ubj``: the 48-feature page model
  and the URL-only fallback, written by ``Booster.save_model``.

Loading needs only xgboost and numpy. Unpickling the old ``model.joblib``
needed scikit-learn (``XGBClassifier`` is an sklearn estimator), and that
dragged scikit-learn and pandas into the serverless bundle. The native files
also do not have to be written by the exact xgboost build that reads them.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from phishing.config import ARTIFACTS_DIR
from phishing.io import load_json, save_json
from phishing.schema import ModelArtifact

META_NAME = "model_meta.json"
FORMAT_VERSION = 1
# Payload key -> booster file. "estimator" is the page model.
BOOSTER_FILES = {"estimator": "page.ubj", "url_estimator": "url.ubj"}


class BoosterScorer:
    """The slice of ``XGBClassifier`` the scanner and explainer use.

    ``predict_proba`` takes a DataFrame (columns are matched by name) or a 2-D
    array already in ``feature_names`` order, and returns ``[1 - p, p]`` rows
    like the sklearn wrapper. ``get_booster`` is what ``phishing.explain``
    uses for TreeSHAP.
    """

    def __init__(self, booster: Any, feature_names: list[str]) -> None:
        self._booster = booster
        self.feature_names = list(feature_names)
        best = booster.attr("best_iteration")
        # Mirror XGBClassifier: an early-stopped model predicts with the best
        # round, not every tree it grew.
        self._iteration_range = (0, int(best) + 1) if best is not None else (0, 0)

    def get_booster(self) -> Any:
        return self._booster

    def _matrix(self, X: Any) -> Any:
        import numpy as np

        if hasattr(X, "columns"):
            missing = [name for name in self.feature_names if name not in X.columns]
            if missing:
                raise ValueError(f"frame is missing model features: {missing}")
            X = X.loc[:, self.feature_names].to_numpy(dtype=np.float64)
        array = np.asarray(X, dtype=np.float64)
        if array.ndim == 1:
            array = array.reshape(1, -1)
        if array.shape[1] != len(self.feature_names):
            raise ValueError(
                f"expected {len(self.feature_names)} features, got {array.shape[1]}"
            )
        return np.ascontiguousarray(array)

    def predict_proba(self, X: Any) -> Any:
        import numpy as np
        import xgboost as xgb

        matrix = xgb.DMatrix(self._matrix(X), feature_names=self.feature_names)
        p = np.asarray(
            self._booster.predict(matrix, iteration_range=self._iteration_range),
            dtype=np.float64,
        ).reshape(-1)
        return np.column_stack([1.0 - p, p])


def _booster_of(estimator: Any) -> Any:
    get_booster = getattr(estimator, "get_booster", None)
    if get_booster is None:
        raise TypeError(
            f"{type(estimator).__name__} has no XGBoost booster; the served "
            "model must be XGBoost to be saved in native format"
        )
    return get_booster()


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
    """Write the boosters and their metadata. Returns the metadata path.

    ``path`` names the metadata file; the boosters go next to it.
    """
    path = Path(path or (ARTIFACTS_DIR / META_NAME))
    path.parent.mkdir(parents=True, exist_ok=True)
    artifact = ModelArtifact(
        model_name=model_name,
        feature_names=list(feature_names),
        threshold=float(threshold),
        metrics={k: float(v) for k, v in metrics.items()},
        trained_at=datetime.now(UTC).isoformat(),
        notes=notes,
        extra=extra or {},
    )
    estimators = {"estimator": estimator, **(extra_estimators or {})}
    unknown = set(estimators) - set(BOOSTER_FILES)
    if unknown:
        raise ValueError(f"no booster file name for {sorted(unknown)}")
    files: dict[str, str] = {}
    for key, est in estimators.items():
        filename = BOOSTER_FILES[key]
        _booster_of(est).save_model(str(path.parent / filename))
        files[key] = filename
    import xgboost as xgb

    save_json(
        {
            "format": FORMAT_VERSION,
            "xgboost": xgb.__version__,
            "estimators": files,
            "artifact": artifact.to_dict(),
        },
        path,
    )
    return path


def load_artifact(path: Path | None = None) -> tuple[ModelArtifact, dict[str, str]]:
    """Metadata only: no xgboost import, a few KB of JSON."""
    path = Path(path or (ARTIFACTS_DIR / META_NAME))
    if not path.is_file():
        raise FileNotFoundError(
            f"No trained model at {path}. From the repo root run: phishing train"
        )
    meta = load_json(path)
    if meta.get("format") != FORMAT_VERSION:
        raise ValueError(f"{path} has format {meta.get('format')!r}, expected {FORMAT_VERSION}")
    return ModelArtifact(**meta["artifact"]), dict(meta["estimators"])


def load_payload(path: Path | None = None) -> dict[str, Any]:
    """``{"estimator", "artifact", "url_estimator"}``, as the scanner expects."""
    import xgboost as xgb

    path = Path(path or (ARTIFACTS_DIR / META_NAME))
    artifact, files = load_artifact(path)
    url_features = list(artifact.extra.get("url_features") or [])
    payload: dict[str, Any] = {"artifact": artifact}
    for key, filename in files.items():
        booster = xgb.Booster()
        booster.load_model(str(path.parent / filename))
        names = artifact.feature_names if key == "estimator" else url_features
        payload[key] = BoosterScorer(booster, names or list(booster.feature_names or []))
    return payload


def load_model(path: Path | None = None) -> tuple[Any, ModelArtifact]:
    payload = load_payload(path)
    return payload["estimator"], payload["artifact"]


def check_native_parity(
    payload: dict[str, Any],
    references: dict[str, tuple[Any, Any]],
    tolerance: float = 1e-6,
) -> dict[str, float]:
    """Max |p_native - p_sklearn| per estimator; raise above ``tolerance``.

    ``references`` maps a payload key to ``(fitted XGBClassifier, rows)``.
    Training calls this so a format change can never ship a model that
    scores differently from the one that was evaluated.
    """
    import numpy as np

    gaps: dict[str, float] = {}
    for key, (reference, rows) in references.items():
        expected = np.asarray(reference.predict_proba(rows))[:, 1]
        actual = np.asarray(payload[key].predict_proba(rows))[:, 1]
        gap = float(np.max(np.abs(expected - actual))) if len(expected) else 0.0
        gaps[key] = gap
        if gap > tolerance:
            raise AssertionError(
                f"native {key} differs from the trained model by {gap:.2e} "
                f"(tolerance {tolerance:.0e})"
            )
    return gaps
