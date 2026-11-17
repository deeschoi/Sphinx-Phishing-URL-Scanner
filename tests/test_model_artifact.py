"""The served model round-trips through native XGBoost files, not a pickle."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import pytest
from sklearn.datasets import make_classification
from xgboost import XGBClassifier

from phishing.tuning import (
    META_NAME,
    BoosterScorer,
    check_native_parity,
    load_artifact,
    load_payload,
    persist_model,
)

ROOT = Path(__file__).resolve().parent.parent


def _fitted(features: int = 5, seed: int = 0):
    values, labels = make_classification(
        n_samples=120, n_features=features, n_informative=3, n_redundant=0, random_state=seed
    )
    frame = pd.DataFrame(values, columns=[f"f{i}" for i in range(features)])
    model = XGBClassifier(n_estimators=25, max_depth=3, random_state=seed, verbosity=0)
    return model.fit(frame, labels), frame


def _persist(tmp_path, page, url_model, url_cols):
    return persist_model(
        page,
        feature_names=[f"f{i}" for i in range(5)],
        threshold=0.4,
        metrics={"accuracy": 0.9},
        model_name="XGBoost",
        extra={"url_features": url_cols, "tld_legit_prob": {"com": 0.7}},
        extra_estimators={"url_estimator": url_model},
        path=tmp_path / META_NAME,
    )


def test_round_trip_matches_the_classifier(tmp_path):
    page, frame = _fitted()
    url_cols = ["f0", "f1"]
    url_model = XGBClassifier(n_estimators=10, max_depth=2, verbosity=0).fit(
        frame[url_cols], (frame["f0"] > 0).astype(int)
    )
    path = _persist(tmp_path, page, url_model, url_cols)

    assert sorted(p.name for p in tmp_path.iterdir()) == [META_NAME, "page.ubj", "url.ubj"]
    meta = json.loads(path.read_text())
    assert meta["estimators"] == {"estimator": "page.ubj", "url_estimator": "url.ubj"}

    payload = load_payload(path)
    assert isinstance(payload["estimator"], BoosterScorer)
    assert payload["artifact"].threshold == 0.4
    assert payload["artifact"].extra["tld_legit_prob"] == {"com": 0.7}
    gaps = check_native_parity(
        payload,
        {"estimator": (page, frame), "url_estimator": (url_model, frame[url_cols])},
    )
    assert max(gaps.values()) <= 1e-6


def test_scorer_takes_arrays_and_matches_frames_by_name(tmp_path):
    page, frame = _fitted()
    url_model = XGBClassifier(n_estimators=5, verbosity=0).fit(frame[["f0"]], frame["f0"] > 0)
    scorer = load_payload(_persist(tmp_path, page, url_model, ["f0"]))["estimator"]
    expected = page.predict_proba(frame.iloc[:4])
    np.testing.assert_allclose(scorer.predict_proba(frame.iloc[:4].to_numpy()), expected, atol=1e-6)
    shuffled = frame.iloc[:4][list(reversed(frame.columns))]
    np.testing.assert_allclose(scorer.predict_proba(shuffled), expected, atol=1e-6)
    np.testing.assert_allclose(
        scorer.predict_proba(frame.iloc[0].to_numpy()), expected[:1], atol=1e-6
    )
    with pytest.raises(ValueError):
        scorer.predict_proba(frame[["f0", "f1"]])


def test_parity_check_refuses_a_different_model(tmp_path):
    page, frame = _fitted(seed=0)
    other, _ = _fitted(seed=1)
    url_model = XGBClassifier(n_estimators=5, verbosity=0).fit(frame[["f0"]], frame["f0"] > 0)
    payload = load_payload(_persist(tmp_path, page, url_model, ["f0"]))
    with pytest.raises(AssertionError, match="differs from the trained model"):
        check_native_parity(payload, {"estimator": (other, frame)})


def test_missing_model_is_file_not_found(tmp_path):
    with pytest.raises(FileNotFoundError):
        load_artifact(tmp_path / META_NAME)
    with pytest.raises(FileNotFoundError):
        load_payload(tmp_path / META_NAME)


def test_non_xgboost_estimator_is_refused(tmp_path):
    from sklearn.linear_model import LogisticRegression

    model = LogisticRegression().fit([[0.0], [1.0]], [0, 1])
    with pytest.raises(TypeError, match="no XGBoost booster"):
        persist_model(model, ["x"], 0.5, {}, "LR", path=tmp_path / META_NAME)


def test_a_scan_works_without_pandas_or_sklearn_installed():
    """The serverless bundle ships without them.

    xgboost imports both opportunistically when they are installed, so
    checking sys.modules would only test xgboost. Instead make them
    unimportable, as in the function, and require a full scan to succeed.
    """
    if not (ROOT / "artifacts" / META_NAME).is_file():
        pytest.skip("no trained model")
    code = (
        "import sys\n"
        "class Block:\n"
        "    def find_spec(self, name, path=None, target=None):\n"
        "        if name.split('.')[0] in {'pandas', 'sklearn', 'joblib'}:\n"
        "            raise ImportError(f'{name} is not in the serve bundle')\n"
        "sys.meta_path.insert(0, Block())\n"
        "from phishing.scanner import scan\n"
        "result = scan('https://www.example.com/login', tier='A')\n"
        "assert result['probability'] is not None\n"
        "assert result['signals'], result['notes']\n"
        "print('ok')\n"
    )
    out = subprocess.run(
        [sys.executable, "-c", code],
        cwd=ROOT,
        env={"PYTHONPATH": str(ROOT / "src"), "PATH": "/usr/bin:/bin"},
        capture_output=True,
        text=True,
        check=False,
    )
    assert out.returncode == 0, out.stderr[-2000:]
    assert out.stdout.strip().endswith("ok")


def test_cold_scan_fetches_while_the_model_loads(monkeypatch):
    """On a cold instance the page fetch runs in a worker during model load."""
    if not (ROOT / "artifacts" / META_NAME).is_file():
        pytest.skip("no trained model")
    import threading

    from phishing import scanner
    from phishing.features.fetch import FetchResult

    seen: dict[str, object] = {}

    def fake_fetch(url, timeout=8):
        seen["thread"] = threading.current_thread().name
        seen["timeout"] = timeout
        return FetchResult(
            url=url,
            final_url=url,
            ok=False,
            status_code=None,
            html=None,
            soup=None,
            n_redirects=0,
            error="offline",
            error_kind="dns",
        )

    monkeypatch.setattr(scanner, "assert_public_url", lambda url: None)
    monkeypatch.setattr(scanner, "fetch_page", fake_fetch)
    scanner._loaded_payload.cache_clear()
    try:
        result = scanner.scan("https://www.example.com/", timeout=5)
    finally:
        scanner._loaded_payload.cache_clear()
    assert str(seen["thread"]).startswith("scan-fetch")
    assert seen["timeout"] == 5
    assert result["verdict"] == "unreachable"

    # Warm: no worker, the extractor fetches as before.
    seen.clear()
    scanner._loaded_payload()
    monkeypatch.setattr(scanner, "phiusiil_feature_values", _recording_extractor(seen))
    try:
        scanner.scan("https://www.example.com/", timeout=5)
    except Exception:  # noqa: BLE001 - only the fetch argument matters here
        pass
    finally:
        scanner._loaded_payload.cache_clear()
    assert seen["fetch"] is None


def _recording_extractor(seen):
    def extractor(url, **kwargs):
        seen["fetch"] = kwargs.get("fetch")
        raise RuntimeError("stop after recording")

    return extractor
