"""SHAP explanations for tree models, reused by notebooks and the scan CLI."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd

from phishing.config import FIGURES_DIR


def _unwrap(estimator):
    """Peel CalibratedClassifierCV so TreeExplainer sees the boosting model."""
    if hasattr(estimator, "calibrated_classifiers_"):
        inner = estimator.calibrated_classifiers_[0]
        return getattr(inner, "estimator", getattr(inner, "base_estimator", estimator))
    return estimator


def _tree_explainer(estimator, X_background: pd.DataFrame):
    import shap

    model = _unwrap(estimator)
    # Path-dependent TreeExplainer (no background) is the reliable option for
    # LightGBM/XGBoost/sklearn forests. Interventional mode with a tiny
    # background (e.g. a single scanned row) collapses SHAP values to 0.
    try:
        return shap.TreeExplainer(model)
    except Exception:
        return shap.TreeExplainer(model, data=X_background, model_output="raw")


def _xgboost_contributions(estimator, X: pd.DataFrame) -> np.ndarray | None:
    """Path-dependent TreeSHAP from the booster, in frame column order.

    This is the algorithm ``shap.TreeExplainer`` runs for XGBoost. Calling it
    directly keeps shap, numba, and llvmlite out of the served bundle.
    """
    model = _unwrap(estimator)
    get_booster = getattr(model, "get_booster", None)
    if get_booster is None:
        return None
    import xgboost as xgb

    booster = get_booster()
    frame = X
    caller_columns = [str(column) for column in X.columns]
    if booster.feature_names:
        expected = [str(name) for name in booster.feature_names]
        missing = [name for name in expected if name not in frame.columns]
        if missing:
            raise ValueError(f"frame is missing booster features: {missing}")
        frame = frame.loc[:, expected]
    array = np.ascontiguousarray(frame.to_numpy(dtype=np.float64), dtype=np.float64)
    if booster.feature_names:
        matrix = xgb.DMatrix(
            array, feature_names=[str(column) for column in frame.columns]
        )
    else:
        matrix = xgb.DMatrix(array)
    contribs = np.asarray(booster.predict(matrix, pred_contribs=True), dtype=np.float64)
    if contribs.ndim == 3:
        contribs = contribs[:, -1, :]
    if contribs.ndim != 2 or contribs.shape[1] != frame.shape[1] + 1:
        raise ValueError(
            f"expected contributions ({frame.shape[0]}, {frame.shape[1] + 1}), "
            f"got {contribs.shape}"
        )
    values = contribs[:, :-1]
    if [str(column) for column in frame.columns] != caller_columns:
        order = [list(frame.columns).index(name) for name in caller_columns]
        values = values[:, order]
    return values


def shap_values(estimator, X: pd.DataFrame, background: pd.DataFrame | None = None):
    values = _xgboost_contributions(estimator, X)
    if values is not None:
        return None, values

    bg = background if background is not None else X.sample(
        n=min(200, len(X)), random_state=42
    )
    explainer = _tree_explainer(estimator, bg)
    values = explainer.shap_values(X)
    # Binary classifiers may return a list [class0, class1]
    if isinstance(values, list):
        values = values[1]
    return explainer, np.asarray(values)


def top_contributors(
    feature_names: list[str],
    shap_row: np.ndarray,
    feature_row: pd.Series,
    k: int = 5,
) -> list[dict[str, Any]]:
    """Largest-magnitude SHAP values for a single instance, with signs."""
    order = np.argsort(-np.abs(shap_row))[:k]
    out = []
    for i in order:
        name = feature_names[i]
        value = float(shap_row[i])
        out.append(
            {
                "feature": name,
                "shap": value,
                "encoded_value": float(feature_row[name]),
                "direction": "phishing" if value > 0 else "legitimate",
            }
        )
    return out


def global_importance(feature_names: list[str], values: np.ndarray) -> pd.Series:
    mean_abs = np.abs(values).mean(axis=0)
    return pd.Series(mean_abs, index=feature_names).sort_values(ascending=False)


def save_beeswarm(explainer, values, X: pd.DataFrame, path: Path | None = None) -> Path:
    import matplotlib.pyplot as plt
    import shap

    FIGURES_DIR.mkdir(parents=True, exist_ok=True)
    path = path or (FIGURES_DIR / "shap_beeswarm.png")
    plt.figure()
    shap.summary_plot(values, X, show=False)
    plt.tight_layout()
    plt.savefig(path, dpi=120, bbox_inches="tight")
    plt.close()
    return path
