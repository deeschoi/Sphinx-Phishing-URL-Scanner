"""SHAP explanations for tree models, reused by notebooks and the scanner."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import numpy as np

if TYPE_CHECKING:
    import pandas as pd


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


def _xgboost_contributions(
    estimator, X: Any, feature_names: list[str] | None = None
) -> np.ndarray | None:
    """Path-dependent TreeSHAP from the booster, in the caller's column order.

    This is the algorithm ``shap.TreeExplainer`` runs for XGBoost. Calling it
    directly keeps shap, numba, and llvmlite out of the served bundle.

    ``X`` is a DataFrame, or a 2-D array whose columns are ``feature_names``
    (the scan path, which does not import pandas).
    """
    model = _unwrap(estimator)
    get_booster = getattr(model, "get_booster", None)
    if get_booster is None:
        return None
    import xgboost as xgb

    booster = get_booster()
    if hasattr(X, "columns"):
        caller_columns = [str(column) for column in X.columns]
        array = X.to_numpy(dtype=np.float64)
    else:
        if feature_names is None:
            raise ValueError("feature_names is required when X is an array")
        caller_columns = [str(name) for name in feature_names]
        array = np.asarray(X, dtype=np.float64)
        if array.ndim == 1:
            array = array.reshape(1, -1)
    if array.shape[1] != len(caller_columns):
        raise ValueError(f"{array.shape[1]} columns for {len(caller_columns)} feature names")

    columns = caller_columns
    if booster.feature_names:
        expected = [str(name) for name in booster.feature_names]
        missing = [name for name in expected if name not in caller_columns]
        if missing:
            raise ValueError(f"frame is missing booster features: {missing}")
        array = array[:, [caller_columns.index(name) for name in expected]]
        columns = expected
    array = np.ascontiguousarray(array, dtype=np.float64)
    if booster.feature_names:
        matrix = xgb.DMatrix(array, feature_names=columns)
    else:
        matrix = xgb.DMatrix(array)
    contribs = np.asarray(booster.predict(matrix, pred_contribs=True), dtype=np.float64)
    if contribs.ndim == 3:
        contribs = contribs[:, -1, :]
    if contribs.ndim != 2 or contribs.shape[1] != array.shape[1] + 1:
        raise ValueError(
            f"expected contributions ({array.shape[0]}, {array.shape[1] + 1}), "
            f"got {contribs.shape}"
        )
    values = contribs[:, :-1]
    if columns != caller_columns:
        values = values[:, [columns.index(name) for name in caller_columns]]
    return values


def shap_values(
    estimator,
    X: Any,
    background: pd.DataFrame | None = None,
    feature_names: list[str] | None = None,
):
    values = _xgboost_contributions(estimator, X, feature_names)
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


def global_importance(feature_names: list[str], values: np.ndarray) -> pd.Series:
    import pandas as pd

    mean_abs = np.abs(values).mean(axis=0)
    return pd.Series(mean_abs, index=feature_names).sort_values(ascending=False)
