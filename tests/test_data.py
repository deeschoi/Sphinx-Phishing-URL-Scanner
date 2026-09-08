"""Lock the EDA numbers reported in research/Choi_Final.ipynb / Choi_Final_Write_Up.pdf."""

from __future__ import annotations

import numpy as np
import pandas as pd

from phishing.config import FEATURE_COLUMNS, TARGET_COLUMN
from phishing.data import (
    grouped_split,
    load_raw,
    load_xy,
    to_model_frame,
    unique_pattern_stats,
)


def test_load_raw_shape_and_columns():
    df = load_raw()
    assert df.shape == (11055, 31)
    assert list(df.columns) == FEATURE_COLUMNS + [TARGET_COLUMN]
    assert df.isnull().sum().sum() == 0
    assert (df.dtypes == np.int64).all() or (df.dtypes == "int64").all()


def test_unique_pattern_stats_match_notebook():
    stats = unique_pattern_stats(load_raw())
    assert stats["n_rows"] == 11055
    assert stats["n_columns"] == 31
    assert stats["n_unique_patterns"] == 5785
    assert stats["n_conflicting_patterns"] == 64
    assert stats["n_duplicate_rows"] == 5206
    assert abs(stats["phishing_rate_original"] - 0.44305744) < 1e-6


def test_recode_makes_phishing_the_positive_class():
    raw = load_raw()
    model = to_model_frame(raw)
    # Original -1 (phishing) becomes 1; original 1 (legitimate) becomes 0.
    assert (model[TARGET_COLUMN] == (raw[TARGET_COLUMN] == -1).astype(int)).all()
    assert abs(model[TARGET_COLUMN].mean() - 0.44305744) < 1e-6
    assert set(model[TARGET_COLUMN].unique()) == {0, 1}


def test_pattern_group_ids_are_stable_and_cover_uniques():
    X, _, groups = load_xy()
    assert len(groups) == len(X)
    assert pd.Series(groups).nunique() == 5785
    # Identical feature rows share a group id.
    dup_mask = X.duplicated(keep=False)
    if dup_mask.any():
        first_dup = X[dup_mask].iloc[0]
        same = (X == first_dup).all(axis=1)
        assert pd.Series(groups[same]).nunique() == 1


def test_grouped_split_does_not_leak_patterns():
    X, y, groups = load_xy()
    X_tr, X_te, y_tr, y_te, g_tr, g_te = grouped_split(X, y, groups)
    assert set(g_tr).isdisjoint(set(g_te))
    assert len(X_tr) + len(X_te) == len(X)
    assert abs(y_tr.mean() - y.mean()) < 0.03
    assert abs(y_te.mean() - y.mean()) < 0.03


def test_fit_tld_legit_prob_is_a_shrunk_legitimacy_rate():
    """Not P(TLD|legit): a rare-but-clean TLD must score above a common-but-mixed one."""
    from phishing.data import fit_tld_legit_prob

    tlds = ["uk"] * 20 + ["com"] * 100 + ["xyz"] * 20
    # y=1 phishing, y=0 legitimate. uk is 95% legit; xyz is 5% legit; com is 60%.
    y = [0] * 19 + [1] + [0] * 60 + [1] * 40 + [0] + [1] * 19
    prior = fit_tld_legit_prob(tlds, y, k=10)
    assert prior["uk"] > prior["com"] > prior["xyz"]
    # Shrinkage pulls xyz up from 0.05 and uk down from 0.95.
    assert 0.05 < prior["xyz"] < 0.3
    assert 0.7 < prior["uk"] < 0.95
