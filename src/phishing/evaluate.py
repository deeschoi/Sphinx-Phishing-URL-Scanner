"""Cross-validation, threshold search, and calibration."""

from __future__ import annotations

from collections.abc import Iterable

import numpy as np
import pandas as pd
from sklearn.base import BaseEstimator, clone
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    brier_score_loss,
    confusion_matrix,
    f1_score,
    log_loss,
    precision_score,
    recall_score,
    roc_auc_score,
    roc_curve,
)
from sklearn.model_selection import StratifiedGroupKFold, StratifiedKFold, cross_validate

from phishing.config import N_SPLITS, RANDOM_STATE
from phishing.models import build_models

SCORING = {
    "accuracy": "accuracy",
    "roc_auc": "roc_auc",
    "precision": "precision",
    "recall": "recall",
    "f1": "f1",
    "neg_log_loss": "neg_log_loss",
    "neg_brier_score": "neg_brier_score",
}


def metric_dict(y_true, y_pred, y_proba) -> dict[str, float]:
    return {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "auroc": float(roc_auc_score(y_true, y_proba)),
        "aupr": float(average_precision_score(y_true, y_proba)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "log_loss": float(log_loss(y_true, y_proba)),
        "brier": float(brier_score_loss(y_true, y_proba)),
    }


def confusion_counts(y_true, y_pred) -> dict[str, int]:
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    return {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)}


def cv_splitter(grouped: bool, n_splits: int = N_SPLITS, random_state: int = RANDOM_STATE):
    """Grouped or plain stratified k-fold, seeded so folds are reproducible."""
    if grouped:
        return StratifiedGroupKFold(n_splits=n_splits, shuffle=True, random_state=random_state)
    return StratifiedKFold(n_splits=n_splits, shuffle=True, random_state=random_state)


def cross_validate_model(
    estimator: BaseEstimator,
    X: pd.DataFrame,
    y: pd.Series,
    groups: np.ndarray | None = None,
    grouped: bool = False,
    n_splits: int = N_SPLITS,
    random_state: int = RANDOM_STATE,
) -> dict[str, np.ndarray]:
    cv = cv_splitter(grouped, n_splits, random_state)
    if grouped and groups is None:
        raise ValueError("grouped=True requires pattern-group ids")
    return cross_validate(
        estimator,
        X,
        y,
        cv=cv,
        scoring=SCORING,
        groups=groups if grouped else None,
        n_jobs=-1,
    )


def summarize_cv(cv_results: dict[str, np.ndarray]) -> dict[str, str]:
    out = {}
    for key, values in cv_results.items():
        if not key.startswith("test_"):
            continue
        metric = key.replace("test_", "")
        # sklearn reports neg_log_loss / neg_brier_score (higher is better)
        vals = np.asarray(values, dtype=float)
        if metric.startswith("neg_"):
            vals = -vals
            metric = metric[4:]
        out[metric] = f"{vals.mean():.4f} ± {vals.std():.4f}"
        out[f"{metric}_mean"] = float(vals.mean())
        out[f"{metric}_std"] = float(vals.std())
    return out


def leakage_delta_table(
    X: pd.DataFrame,
    y: pd.Series,
    groups: np.ndarray,
    model_names: Iterable[str] | None = None,
    n_splits: int = N_SPLITS,
) -> pd.DataFrame:
    """Headline Stage 1 experiment: random CV vs grouped CV per model."""
    models = build_models(list(model_names) if model_names else None)
    rows = []
    for name, est in models.items():
        random_cv = cross_validate_model(est, X, y, grouped=False, n_splits=n_splits)
        grouped_cv = cross_validate_model(
            est, X, y, groups=groups, grouped=True, n_splits=n_splits
        )
        random_s = summarize_cv(random_cv)
        grouped_s = summarize_cv(grouped_cv)
        rows.append(
            {
                "model": name,
                "random_accuracy": random_s["accuracy_mean"],
                "grouped_accuracy": grouped_s["accuracy_mean"],
                "accuracy_optimism": random_s["accuracy_mean"] - grouped_s["accuracy_mean"],
                "random_auroc": random_s["roc_auc_mean"],
                "grouped_auroc": grouped_s["roc_auc_mean"],
                "auroc_optimism": random_s["roc_auc_mean"] - grouped_s["roc_auc_mean"],
                "random_f1": random_s["f1_mean"],
                "grouped_f1": grouped_s["f1_mean"],
                "random_brier": random_s["brier_score_mean"],
                "grouped_brier": grouped_s["brier_score_mean"],
            }
        )
    return pd.DataFrame(rows).set_index("model")


def best_f1_threshold(y_true, y_proba, grid: np.ndarray | None = None) -> tuple[float, float]:
    if grid is None:
        grid = np.linspace(0.05, 0.95, 181)
    y_true = np.asarray(y_true)
    y_proba = np.asarray(y_proba)
    scores = [f1_score(y_true, (y_proba >= t).astype(int), zero_division=0) for t in grid]
    i = int(np.argmax(scores))
    return float(grid[i]), float(scores[i])


def fpr_target_threshold(
    y_true, y_proba, max_fpr: float = 0.01
) -> tuple[float, float]:
    """Highest-recall threshold whose false-positive rate is at most ``max_fpr``.

    Falls back to the ROC point with FPR closest to the target if none is at or
    below it (can happen on tiny test sets).
    """
    fpr, tpr, thresholds = roc_curve(y_true, y_proba)
    # roc_curve thresholds[0] is inf; skip it
    fpr, tpr, thresholds = fpr[1:], tpr[1:], thresholds[1:]
    ok = np.where(fpr <= max_fpr)[0]
    if len(ok):
        # among points with FPR <= target, pick the one with highest TPR
        i = ok[int(np.argmax(tpr[ok]))]
    else:
        i = int(np.argmin(np.abs(fpr - max_fpr)))
    return float(thresholds[i]), float(fpr[i])


def threshold_report(y_true, y_proba, threshold: float) -> dict[str, float]:
    pred = (np.asarray(y_proba) >= threshold).astype(int)
    counts = confusion_counts(y_true, pred)
    tn, fp, fn, tp = counts["tn"], counts["fp"], counts["fn"], counts["tp"]
    metrics = metric_dict(y_true, pred, y_proba)
    metrics.update(counts)
    metrics["threshold"] = float(threshold)
    metrics["fpr"] = float(fp / (fp + tn)) if (fp + tn) else 0.0
    metrics["fnr"] = float(fn / (fn + tp)) if (fn + tp) else 0.0
    return metrics


def expected_cost(
    y_true, y_proba, threshold: float, fp_cost: float = 1.0, fn_cost: float = 1.0
) -> float:
    """Mean misclassification cost per URL at ``threshold``.

    Accuracy weights both error types equally, which is the wrong objective for a
    security tool: blocking a legitimate bank and missing a credential-harvesting
    page have very different consequences.
    """
    pred = (np.asarray(y_proba) >= threshold).astype(int)
    counts = confusion_counts(y_true, pred)
    total = len(np.asarray(y_true))
    if not total:
        return 0.0
    return float((counts["fp"] * fp_cost + counts["fn"] * fn_cost) / total)


def best_cost_threshold(
    y_true,
    y_proba,
    fp_cost: float = 1.0,
    fn_cost: float = 1.0,
    grid: np.ndarray | None = None,
) -> tuple[float, float]:
    """Threshold minimising :func:`expected_cost`, and the cost it achieves."""
    if grid is None:
        grid = np.linspace(0.01, 0.99, 197)
    costs = [expected_cost(y_true, y_proba, t, fp_cost, fn_cost) for t in grid]
    i = int(np.argmin(costs))
    return float(grid[i]), float(costs[i])


def calibrate(
    estimator: BaseEstimator,
    X_train: pd.DataFrame,
    y_train: pd.Series,
    method: str = "isotonic",
    cv: int = 5,
) -> CalibratedClassifierCV:
    calibrated = CalibratedClassifierCV(
        clone(estimator), method=method, cv=cv, n_jobs=-1
    )
    calibrated.fit(X_train, y_train)
    return calibrated


def reliability_curve(y_true, y_proba, n_bins: int = 10):
    edges = np.linspace(0, 1, n_bins + 1)
    idx = np.clip(np.digitize(y_proba, edges) - 1, 0, n_bins - 1)
    centres, observed, counts = [], [], []
    for b in range(n_bins):
        mask = idx == b
        if mask.sum() == 0:
            continue
        centres.append(float(np.asarray(y_proba)[mask].mean()))
        observed.append(float(np.asarray(y_true)[mask].mean()))
        counts.append(int(mask.sum()))
    return np.array(centres), np.array(observed), np.array(counts)
