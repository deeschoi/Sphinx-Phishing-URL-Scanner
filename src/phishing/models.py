"""Model factory covering the original three estimators plus two modern GBMs."""

from __future__ import annotations

from typing import Any

from sklearn.base import BaseEstimator
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression

from phishing.config import RANDOM_STATE


def make_logistic_regression(**kwargs: Any) -> LogisticRegression:
    params = dict(
        C=1e10,
        solver="liblinear",
        max_iter=1000,
        random_state=RANDOM_STATE,
    )
    params.update(kwargs)
    return LogisticRegression(**params)


def make_random_forest(**kwargs: Any) -> RandomForestClassifier:
    params = dict(
        n_estimators=300,
        random_state=RANDOM_STATE,
        n_jobs=-1,
    )
    params.update(kwargs)
    return RandomForestClassifier(**params)


def make_gradient_boosting(**kwargs: Any) -> GradientBoostingClassifier:
    params = dict(
        n_estimators=150,
        learning_rate=0.1,
        max_depth=3,
        random_state=RANDOM_STATE,
    )
    params.update(kwargs)
    return GradientBoostingClassifier(**params)


def make_xgboost(**kwargs: Any):
    from xgboost import XGBClassifier

    params = dict(
        n_estimators=300,
        learning_rate=0.08,
        max_depth=5,
        subsample=0.9,
        colsample_bytree=0.9,
        eval_metric="logloss",
        random_state=RANDOM_STATE,
        n_jobs=-1,
        verbosity=0,
    )
    params.update(kwargs)
    return XGBClassifier(**params)


def make_lightgbm(**kwargs: Any):
    import lightgbm as lgb

    params = dict(
        n_estimators=300,
        learning_rate=0.08,
        num_leaves=31,
        subsample=0.9,
        colsample_bytree=0.9,
        random_state=RANDOM_STATE,
        n_jobs=-1,
        verbose=-1,
    )
    params.update(kwargs)
    return lgb.LGBMClassifier(**params)


MODEL_BUILDERS = {
    "Logistic Regression": make_logistic_regression,
    "Random Forest": make_random_forest,
    "Gradient Boosting": make_gradient_boosting,
    "XGBoost": make_xgboost,
    "LightGBM": make_lightgbm,
}

# Original notebook trio, used for the leakage-delta comparison.
NOTEBOOK_MODELS = ["Logistic Regression", "Random Forest", "Gradient Boosting"]
ALL_MODELS = list(MODEL_BUILDERS.keys())


def build_model(name: str, **kwargs: Any) -> BaseEstimator:
    if name not in MODEL_BUILDERS:
        raise KeyError(f"Unknown model {name!r}. Choose from {list(MODEL_BUILDERS)}")
    return MODEL_BUILDERS[name](**kwargs)


def build_models(names: list[str] | None = None) -> dict[str, BaseEstimator]:
    names = names or ALL_MODELS
    return {name: build_model(name) for name in names}
