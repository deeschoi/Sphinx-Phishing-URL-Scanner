"""Load, recode, and split the UCI Phishing Websites dataset."""

from __future__ import annotations

from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split

from phishing.config import (
    DATA_PATH,
    FEATURE_COLUMNS,
    RANDOM_STATE,
    TARGET_COLUMN,
    TEST_SIZE,
)


def load_raw(path: Path | None = None) -> pd.DataFrame:
    """Load the CSV and drop the non-informative ``id`` column.

    Returns a frame of shape (11055, 31): 30 predictors + ``Result``.
    ``Result`` is still in the original encoding: -1 phishing, 1 legitimate.
    """
    csv_path = Path(path) if path is not None else DATA_PATH
    df = pd.read_csv(csv_path)
    if "id" in df.columns:
        df = df.drop(columns=["id"])
    missing = [c for c in FEATURE_COLUMNS + [TARGET_COLUMN] if c not in df.columns]
    if missing:
        raise ValueError(f"Dataset is missing expected columns: {missing}")
    return df[FEATURE_COLUMNS + [TARGET_COLUMN]].copy()


def to_model_frame(df: pd.DataFrame) -> pd.DataFrame:
    """Recode ``Result`` so that 1 = phishing and 0 = legitimate.

    The original UCI encoding uses -1 for phishing. scikit-learn metrics treat
    1 as the positive class, which is the convention we want for a security
    detector (catching phishing is the event of interest).
    """
    out = df.copy()
    out[TARGET_COLUMN] = (out[TARGET_COLUMN] == -1).astype(int)
    return out


def pattern_group_ids(X: pd.DataFrame) -> np.ndarray:
    """Stable integer id per unique 30-feature vector.

    Duplicate rows that share a feature pattern must stay in the same CV fold
    and the same train/test partition, otherwise random splits leak identical
    vectors across the boundary and inflate accuracy.
    """
    cols = [c for c in FEATURE_COLUMNS if c in X.columns]
    hashed = pd.util.hash_pandas_object(X[cols], index=False)
    # factorize so ids are dense 0..n_unique-1 (easier to inspect)
    codes, _ = pd.factorize(hashed, sort=True)
    return codes.astype(np.int64)


def unique_pattern_stats(df: pd.DataFrame) -> dict[str, int | float]:
    """Reproduce the EDA numbers reported in research/Choi_Final.ipynb."""
    X = df[FEATURE_COLUMNS]
    groups = pattern_group_ids(X)
    n_unique = int(pd.Series(groups).nunique())
    label_nunique = (
        df.assign(_g=groups).groupby("_g")[TARGET_COLUMN].nunique()
    )
    n_conflicting = int((label_nunique > 1).sum())
    n_duplicates = int(df.duplicated().sum())
    return {
        "n_rows": int(len(df)),
        "n_columns": int(df.shape[1]),
        "n_unique_patterns": n_unique,
        "n_conflicting_patterns": n_conflicting,
        "n_duplicate_rows": n_duplicates,
        "phishing_rate_original": float((df[TARGET_COLUMN] == -1).mean()),
    }


def stratified_split(
    X: pd.DataFrame,
    y: pd.Series,
    test_size: float = TEST_SIZE,
    random_state: int = RANDOM_STATE,
) -> tuple[pd.DataFrame, pd.DataFrame, pd.Series, pd.Series]:
    """80/20 stratified split (the original notebook's protocol)."""
    return train_test_split(
        X, y, test_size=test_size, stratify=y, random_state=random_state
    )


def grouped_split(
    X: pd.DataFrame,
    y: pd.Series,
    groups: np.ndarray,
    test_size: float = TEST_SIZE,
    random_state: int = RANDOM_STATE,
) -> tuple[pd.DataFrame, pd.DataFrame, pd.Series, pd.Series, np.ndarray, np.ndarray]:
    """Train/test split that never puts the same feature pattern on both sides.

    Groups are stratified by their majority label so the phishing rate stays
    close to the global rate. This is the honest holdout used from Stage 1 on.
    """
    gdf = pd.DataFrame({"group": groups, "y": y.to_numpy()})
    group_label = gdf.groupby("group")["y"].agg(lambda s: int(s.mode().iloc[0]))
    g_train, g_test = train_test_split(
        group_label.index.to_numpy(),
        test_size=test_size,
        stratify=group_label.to_numpy(),
        random_state=random_state,
    )
    train_mask = np.isin(groups, g_train)
    test_mask = np.isin(groups, g_test)
    return (
        X.loc[train_mask],
        X.loc[test_mask],
        y.loc[train_mask],
        y.loc[test_mask],
        groups[train_mask],
        groups[test_mask],
    )


def leakage_report(
    X: pd.DataFrame,
    y: pd.Series,
    test_size: float = TEST_SIZE,
    random_state: int = RANDOM_STATE,
) -> dict[str, float | int]:
    """Quantify how much a naive random split leaks.

    Measures the fraction of test rows whose exact feature pattern also appears
    in the training partition, which is the mechanism that inflates the accuracy
    reported in the original notebook.
    """
    groups = pattern_group_ids(X)
    idx = np.arange(len(X))
    train_idx, test_idx = train_test_split(
        idx, test_size=test_size, stratify=y.to_numpy(), random_state=random_state
    )
    train_patterns = set(groups[train_idx].tolist())
    seen = np.isin(groups[test_idx], list(train_patterns))

    label_nunique = pd.DataFrame({"g": groups, "y": y.to_numpy()}).groupby("g")["y"].nunique()
    n_conflicting = int((label_nunique > 1).sum())
    n_unique = int(pd.Series(groups).nunique())

    return {
        "n_rows": int(len(X)),
        "n_unique_patterns": n_unique,
        "duplicate_row_fraction": float(1 - n_unique / len(X)),
        "random_split_test_rows_seen_in_train": float(seen.mean()),
        "conflicting_label_patterns": n_conflicting,
        "conflicting_label_fraction": float(n_conflicting / n_unique) if n_unique else 0.0,
    }


def load_xy(path: Path | None = None) -> tuple[pd.DataFrame, pd.Series, np.ndarray]:
    """Convenience: recoded X, y, and pattern-group ids."""
    raw = load_raw(path)
    model = to_model_frame(raw)
    X = model[FEATURE_COLUMNS]
    y = model[TARGET_COLUMN]
    groups = pattern_group_ids(X)
    return X, y, groups


def _phiusiil_host(url: str) -> str:
    from urllib.parse import urlparse

    host = urlparse(str(url)).hostname or ""
    return host.lower().rstrip(".")


def load_phiusiil_raw(path: Path | None = None) -> pd.DataFrame:
    """Load the PhiUSIIL CSV. Label is still 1 = legitimate, 0 = phishing."""
    from phishing.config import PHIUSIIL_PATH

    csv_path = Path(path) if path is not None else PHIUSIIL_PATH
    if not csv_path.is_file():
        raise FileNotFoundError(
            f"PhiUSIIL dataset not found at {csv_path}. "
            "Place PhiUSIIL_Phishing_URL_Dataset.csv under datasets/."
        )
    df = pd.read_csv(csv_path, low_memory=False)
    if "label" not in df.columns or "URL" not in df.columns:
        raise ValueError("PhiUSIIL CSV must contain URL and label columns")
    return df


def load_phiusiil_xy(
    path: Path | None = None,
) -> tuple[pd.DataFrame, pd.Series, np.ndarray, dict[str, float]]:
    """PhiUSIIL features for the served model.

    HTML columns come from the CSV (frozen page snapshots). URL columns are
    recomputed with the live extractor so training and scanning share one
    definition — in particular, a leading ``www.`` is not treated as a
    phishing-like extra subdomain or an extra special character (every
    legitimate PhiUSIIL row has www and none has a path). URL length, letters,
    and other-special counts are taken from the www-stripped origin so a
    trailing slash or ``/en-us`` cannot impersonate the phishing class.

    Recodes the target so 1 = phishing. Groups by hostname.
    """
    from phishing.config import (
        PHIUSIIL_HTML_FEATURES,
        PHIUSIIL_MODEL_FEATURES,
        PHIUSIIL_URL_FEATURES,
    )
    from phishing.features.phiusiil_url import extract_phiusiil_url_features

    raw = load_phiusiil_raw(path)
    missing_html = [c for c in PHIUSIIL_HTML_FEATURES if c not in raw.columns]
    if missing_html:
        raise ValueError(f"PhiUSIIL dataset is missing expected columns: {missing_html}")

    tld_prob = (
        raw.groupby("TLD")["TLDLegitimateProb"].first().astype(float).to_dict()
        if "TLD" in raw.columns
        else {}
    )
    tld_prob = {str(k): float(v) for k, v in tld_prob.items()}

    y = (raw["label"] == 0).astype(int)
    y.name = TARGET_COLUMN

    url_rows = [
        extract_phiusiil_url_features(url, tld_prob=tld_prob) for url in raw["URL"].tolist()
    ]
    url_df = pd.DataFrame(url_rows, index=raw.index)[PHIUSIIL_URL_FEATURES]
    html_df = raw[PHIUSIIL_HTML_FEATURES].apply(pd.to_numeric, errors="coerce").fillna(0.0)
    X = pd.concat([url_df, html_df], axis=1)[PHIUSIIL_MODEL_FEATURES]
    groups = raw["URL"].map(_phiusiil_host).fillna("").to_numpy()
    codes, _ = pd.factorize(pd.Series(groups), sort=True)
    return X, y, codes.astype(np.int64), tld_prob
