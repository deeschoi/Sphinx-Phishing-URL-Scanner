"""Fit the served PhiUSIIL model and write artifacts/model.joblib."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sklearn.base import clone

from phishing.config import (
    ARTIFACTS_DIR,
    PHIUSIIL_HTML_FEATURES,
    PHIUSIIL_MODEL_FEATURES,
    PHIUSIIL_URL_FEATURES,
    REPORTS_DIR,
    ensure_dirs,
)
from phishing.data import grouped_split, load_phiusiil_xy
from phishing.evaluate import best_cost_threshold, metric_dict, threshold_report
from phishing.io import save_json
from phishing.models import build_models
from phishing.tuning import persist_model

MODEL_NAME = "XGBoost"
OPERATING_POINTS = {"warn": (1.0, 1.0), "block": (10.0, 1.0)}


def _fit_eval(template, X_tr, y_tr, X_te, y_te) -> tuple[Any, dict[str, Any], dict[str, dict]]:
    evaluated = clone(template).fit(X_tr, y_tr)
    proba = evaluated.predict_proba(X_te)[:, 1]
    metrics = metric_dict(y_te, evaluated.predict(X_te), proba)
    thresholds: dict[str, dict[str, float]] = {}
    for name, (fp_cost, fn_cost) in OPERATING_POINTS.items():
        t, _ = best_cost_threshold(y_te, proba, fp_cost, fn_cost)
        thresholds[name] = threshold_report(y_te, proba, t)
    return evaluated, metrics, thresholds


def train_phiusiil_model(*, model_name: str = MODEL_NAME) -> dict[str, Any]:
    """Train on PhiUSIIL, evaluate on a host-grouped holdout, persist the served model.

    Persists two estimators: the 48-feature page model and a URL-only fallback
    used when HTML was not measured. Missing HTML is never scored as zeros.
    """
    ensure_dirs()
    X, y, groups, tld_prob = load_phiusiil_xy()
    features = list(PHIUSIIL_MODEL_FEATURES)
    X = X[features]
    X_tr, X_te, y_tr, y_te, _, _ = grouped_split(X, y, groups)

    html_fill = {
        name: float(X_tr.loc[y_tr == 0, name].median()) if (y_tr == 0).any() else 0.0
        for name in PHIUSIIL_HTML_FEATURES
    }

    template = build_models()[model_name]
    _, metrics, thresholds = _fit_eval(template, X_tr, y_tr, X_te, y_te)
    warn = thresholds["warn"]["threshold"]
    block = max(thresholds["block"]["threshold"], warn)

    url_cols = list(PHIUSIIL_URL_FEATURES)
    _, url_metrics, url_thresholds = _fit_eval(
        template, X_tr[url_cols], y_tr, X_te[url_cols], y_te
    )
    url_warn = url_thresholds["warn"]["threshold"]
    url_block = max(url_thresholds["block"]["threshold"], url_warn)

    served_metrics = dict(metrics)
    served_metrics["recall"] = thresholds["warn"]["recall"]
    served_metrics["fpr"] = thresholds["warn"]["fpr"]

    served = clone(template).fit(X, y)
    url_served = clone(template).fit(X[url_cols], y)

    importances = {}
    raw_imp = getattr(served, "feature_importances_", None)
    if raw_imp is not None:
        importances = {
            name: float(score)
            for name, score in sorted(
                zip(features, raw_imp, strict=True),
                key=lambda row: -row[1],
            )
        }
    url_importances = {}
    raw_url_imp = getattr(url_served, "feature_importances_", None)
    if raw_url_imp is not None:
        url_importances = {
            name: float(score)
            for name, score in sorted(
                zip(url_cols, raw_url_imp, strict=True),
                key=lambda row: -row[1],
            )
        }
    extra = {
        "fpr_threshold": block,
        "operating_points": thresholds,
        "dataset": "PhiUSIIL Phishing URL (Prasad & Chandra, 2023)",
        "tld_legit_prob": tld_prob,
        "html_fill": html_fill,
        "url_features": url_cols,
        "url_threshold": url_warn,
        "url_fpr_threshold": url_block,
        "url_metrics": url_metrics,
        "url_operating_points": url_thresholds,
        "grouping": "hostname",
        "feature_importances": importances,
        "url_feature_importances": url_importances,
        "dropped": [
            "FILENAME",
            "URL",
            "Domain",
            "TLD",
            "Title",
            "URLSimilarityIndex",
            "URLCharProb",
        ],
        "https_encoding": "IsHTTPS scheme bit; not 2012 SSLfinal_State",
        "limitation": (
            "PhiUSIIL phishing rows are thin HTML shells, so page-richness "
            "features nearly separate the classes on the frozen table. The "
            "scanner uses a URL-only fallback when HTML is missing, ignores "
            "www as a subdomain, extra special character, or path/slash leak, "
            "and never scores placeholder zeros as a kit. The held-out numbers "
            "here are measured on the frozen 2023 columns and do not transfer "
            "to live 2026 scans: on a 240-host live sample (scripts/07, seed "
            "7) the scanner reads 90.6% accuracy, 75.0% recall, 0.9% FPR, with "
            "59 of 240 hosts no longer resolving. Two known leaks survive in "
            "the table: TLDLegitimateProb is near zero for .app / .io, so real "
            "sites on those TLDs score high on the URL string alone, and free "
            "hosting suffixes carry 22,478 phishing rows against 1 legitimate "
            "row (kept out of the feature set for that reason)."
        ),
        "live_sample": {
            "script": "scripts/07_live_sample_eval.py",
            "seed": 7,
            "n_per_class": 120,
            "accuracy": 0.906,
            "recall": 0.750,
            "false_positive_rate": 0.009,
            "precision": 0.980,
            "unrated_hosts": 59,
            "note": (
                "Live re-extraction over the network, not the frozen CSV. "
                "Rated hosts only; unreachable hosts get a URL-pattern chip."
            ),
        },
    }
    path = persist_model(
        served,
        feature_names=features,
        threshold=warn,
        metrics=served_metrics,
        model_name=model_name,
        notes=(
            "PhiUSIIL 48-feature model plus URL-only fallback. Host-grouped "
            "holdout; refitted on the full table. URL features recomputed so "
            "www is not a class leak (subdomain, special-char count, or path). "
            "Missing HTML is not filled with zeros. At scan time the two "
            "estimators are reconciled: when the page model says kit but the "
            "URL string looks clean, the URL score wins, because the page "
            "model's top weights are the columns that shifted since 2023."
        ),
        extra=extra,
        extra_estimators={"url_estimator": url_served},
        path=ARTIFACTS_DIR / "model.joblib",
    )
    save_json(tld_prob, ARTIFACTS_DIR / "tld_legit_prob.json")
    save_json(html_fill, ARTIFACTS_DIR / "html_fill.json")

    card = {
        "trained_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "dataset": extra["dataset"],
        "n_rows": int(len(X)),
        "evaluation": "grouped holdout by hostname; no host shared between train and test",
        "n_train": int(len(X_tr)),
        "n_test": int(len(X_te)),
        "phishing_rate": float(y.mean()),
        "algorithm": "XGBoost (300 trees, depth 5, lr 0.08)",
        "features": features,
        "n_features": len(features),
        "metrics": metrics,
        "thresholds": thresholds,
        "url_only": {
            "features": url_cols,
            "metrics": url_metrics,
            "thresholds": url_thresholds,
            "feature_importances": url_importances,
        },
        "dropped_leaks": extra["dropped"],
        "https_encoding": extra["https_encoding"],
        "limitation": extra["limitation"],
        "live_sample": extra["live_sample"],
        "top_importances": dict(list(importances.items())[:12]),
        "artifact": str(path),
    }
    save_json(card, REPORTS_DIR / "06_model_card.json")
    return card
