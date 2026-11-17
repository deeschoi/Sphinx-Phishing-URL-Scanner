"""Served explanations match shap.TreeExplainer without importing shap at runtime."""

from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.datasets import make_classification
from xgboost import XGBClassifier

from phishing.explain import shap_values


def _frame(rows: int = 40, features: int = 6, seed: int = 0) -> tuple[pd.DataFrame, np.ndarray]:
    values, labels = make_classification(
        n_samples=rows,
        n_features=features,
        n_informative=4,
        n_redundant=0,
        random_state=seed,
    )
    frame = pd.DataFrame(values, columns=[f"f{i}" for i in range(features)])
    return frame, labels


def test_xgboost_contributions_match_shap_tree_explainer():
    import shap

    frame, labels = _frame()
    model = XGBClassifier(
        n_estimators=20,
        max_depth=3,
        random_state=0,
        verbosity=0,
    )
    model.fit(frame, labels)
    held_out = frame.iloc[-8:]
    _, values = shap_values(model, held_out)
    expected = shap.TreeExplainer(model).shap_values(held_out)
    if isinstance(expected, list):
        expected = expected[1]
    np.testing.assert_allclose(values, np.asarray(expected), atol=1e-5, rtol=0)


def test_contributions_follow_the_frame_column_order():
    frame, labels = _frame()
    model = XGBClassifier(n_estimators=15, max_depth=2, random_state=1, verbosity=0)
    model.fit(frame, labels)
    held_out = frame.iloc[:4]
    _, original = shap_values(model, held_out)
    reordered = held_out[list(reversed(held_out.columns))]
    _, values = shap_values(model, reordered)
    assert values.shape == (len(reordered), reordered.shape[1])
    positions = [list(reordered.columns).index(name) for name in held_out.columns]
    np.testing.assert_allclose(values[:, positions], original)


def test_contribution_width_matches_the_frame():
    frame, labels = _frame(rows=30, features=4)
    model = XGBClassifier(n_estimators=10, max_depth=2, random_state=2, verbosity=0)
    model.fit(frame, labels)
    _, values = shap_values(model, frame.iloc[:3])
    assert values.shape == (3, 4)


def test_array_with_feature_names_matches_the_frame():
    """The scan path passes a numpy row plus names, not a DataFrame."""
    frame, labels = _frame()
    model = XGBClassifier(n_estimators=15, max_depth=3, random_state=3, verbosity=0)
    model.fit(frame, labels)
    held_out = frame.iloc[:5]
    _, from_frame = shap_values(model, held_out)
    _, from_array = shap_values(model, held_out.to_numpy(), feature_names=list(held_out.columns))
    np.testing.assert_allclose(from_array, from_frame)


def test_native_booster_scorer_explains_like_the_classifier(tmp_path):
    from phishing.tuning import load_payload, persist_model

    frame, labels = _frame()
    model = XGBClassifier(n_estimators=15, max_depth=3, random_state=4, verbosity=0)
    model.fit(frame, labels)
    path = persist_model(
        model,
        feature_names=list(frame.columns),
        threshold=0.5,
        metrics={},
        model_name="XGBoost",
        path=tmp_path / "model_meta.json",
    )
    scorer = load_payload(path)["estimator"]
    held_out = frame.iloc[:5]
    _, expected = shap_values(model, held_out)
    _, values = shap_values(scorer, held_out.to_numpy(), feature_names=list(frame.columns))
    np.testing.assert_allclose(values, expected, atol=1e-6)
