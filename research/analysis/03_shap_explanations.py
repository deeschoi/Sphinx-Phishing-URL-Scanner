"""SHAP attributions, permutation importance, and interaction effects.

Gini importance says which features a tree split on; it says nothing about
direction and is biased toward high-cardinality features. SHAP gives signed,
per-prediction attributions that add up to the model output, which is both a
better global ranking and the mechanism the scanner uses to explain individual
verdicts.
"""

from __future__ import annotations

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import shap
from sklearn.inspection import permutation_importance

from phishing.config import FEATURE_INFO, FIGURES_DIR, RANDOM_STATE, REPORTS_DIR, ensure_dirs
from phishing.data import grouped_split, load_xy
from phishing.io import save_json
from phishing.models import build_models


def main() -> None:
    ensure_dirs()
    X, y, groups = load_xy()
    X_tr, X_te, y_tr, y_te, _, _ = grouped_split(X, y, groups)

    model = build_models()["XGBoost"].fit(X_tr, y_tr)

    explainer = shap.TreeExplainer(model)
    sv = explainer.shap_values(X_te)
    mean_abs = np.abs(sv).mean(axis=0)

    perm = permutation_importance(
        model, X_te, y_te, n_repeats=10, random_state=RANDOM_STATE,
        scoring="accuracy", n_jobs=-1,
    )

    gini = model.feature_importances_

    imp = pd.DataFrame({
        "feature": X.columns,
        "shap_mean_abs": mean_abs,
        "permutation_drop": perm.importances_mean,
        "gini": gini,
    })
    imp["shap_share"] = imp["shap_mean_abs"] / imp["shap_mean_abs"].sum()
    imp["gini_rank"] = imp["gini"].rank(ascending=False).astype(int)
    imp["shap_rank"] = imp["shap_mean_abs"].rank(ascending=False).astype(int)
    imp["rank_shift"] = imp["gini_rank"] - imp["shap_rank"]
    imp = imp.sort_values("shap_mean_abs", ascending=False).reset_index(drop=True)

    print("=== Top 12 features by mean |SHAP| (XGBoost, grouped test set) ===")
    print(imp.head(12)[["feature", "shap_share", "permutation_drop",
                        "gini_rank", "shap_rank"]].round(4).to_string(index=False))

    concentration = imp["shap_share"].head(2).sum()
    print(f"\nTop 2 features carry {concentration:.1%} of total attribution.")
    print(f"Features contributing under 1% each: "
          f"{int((imp['shap_share'] < 0.01).sum())} of 30")

    disagree = imp.reindex(imp["rank_shift"].abs().sort_values(ascending=False).index)
    print("\n=== Largest disagreements between Gini rank and SHAP rank ===")
    print(disagree.head(6)[["feature", "gini_rank", "shap_rank", "rank_shift"]]
          .to_string(index=False))

    # Directional check: does each feature push the way the source paper intends?
    print("\n=== Direction of effect (mean SHAP by encoded value) ===")
    direction_rows = []
    for i, feat in enumerate(X.columns):
        for val in sorted(X_te[feat].unique()):
            mask = X_te[feat] == val
            direction_rows.append({
                "feature": feat, "value": int(val), "n": int(mask.sum()),
                "mean_shap": float(sv[mask.to_numpy(), i].mean()),
            })
    direction = pd.DataFrame(direction_rows)

    for feat in imp["feature"].head(5):
        sub = direction[direction["feature"] == feat]
        parts = [f"{int(r.value):+d} -> {r.mean_shap:+.3f}" for r in sub.itertuples()]
        print(f"  {feat:28s} {'  '.join(parts)}")

    rates = _conditional_rates(X, y)
    reversed_feats = rates.loc[rates["verdict"] == "reversed", "feature"].tolist()
    null_feats = rates.loc[rates["verdict"] == "no marginal signal", "feature"].tolist()

    print("\n=== Encoding audit: does each feature mean what the paper says? ===")
    print("The paper defines -1 as a phishing indicator, so P(phishing) should fall "
          "as the encoded\nvalue rises. Computed directly from the data, no model "
          "involved.")
    print(rates[rates["verdict"] != "as documented"].to_string(index=False))
    print(f"\n{len(reversed_feats)} features are encoded backwards relative to their "
          f"documented meaning.")
    print(f"{len(null_feats)} features carry no marginal signal at all "
          f"(identical phishing rate at every value).")

    interactions = _top_interactions(explainer, X_te)
    print("\n=== Strongest pairwise interactions (mean |SHAP interaction|) ===")
    for a, b, v in interactions[:8]:
        print(f"  {a} x {b}: {v:.4f}")

    imp.to_csv(REPORTS_DIR / "03_feature_importance.csv", index=False)
    direction.to_csv(REPORTS_DIR / "03_shap_direction.csv", index=False)
    save_json(
        {
            "top_two_share": float(concentration),
            "importance": imp.to_dict("records"),
            "interactions": [{"a": a, "b": b, "strength": v} for a, b, v in interactions],
            "reversed_features": reversed_feats,
            "no_signal_features": null_feats,
            "encoding_audit": rates.to_dict("records"),
        },
        REPORTS_DIR / "03_shap.json",
    )

    _plot(sv, X_te, imp)
    print(f"\nWrote results to {REPORTS_DIR}")


def _conditional_rates(X: pd.DataFrame, y: pd.Series, tol: float = 0.01) -> pd.DataFrame:
    """Raw P(phishing | feature = value) and whether it matches the documented encoding."""
    rows = []
    for feat in X.columns:
        present = sorted(X[feat].unique())
        entry = {"feature": feat}
        for val in (-1, 0, 1):
            mask = X[feat] == val
            entry[f"P(phish|{val:+d})"] = (
                round(float(y[mask].mean()), 3) if mask.any() else None
            )
        lo = float(y[X[feat] == present[0]].mean())
        hi = float(y[X[feat] == present[-1]].mean())
        drop = lo - hi  # should be positive: risk falls as encoding moves to +1

        if abs(drop) < tol:
            verdict = "no marginal signal"
        elif drop < 0:
            verdict = "reversed"
        else:
            verdict = "as documented"

        entry["risk_drop"] = round(drop, 3)
        entry["verdict"] = verdict
        entry["documented -1 means"] = FEATURE_INFO[feat]["values"].get(-1, "n/a")
        rows.append(entry)
    return pd.DataFrame(rows)


def _top_interactions(explainer, X_te: pd.DataFrame, sample: int = 800):
    rng = np.random.default_rng(RANDOM_STATE)
    idx = rng.choice(len(X_te), size=min(sample, len(X_te)), replace=False)
    inter = explainer.shap_interaction_values(X_te.iloc[idx])
    strength = np.abs(inter).mean(axis=0)
    np.fill_diagonal(strength, 0)

    cols = list(X_te.columns)
    pairs = []
    for i in range(len(cols)):
        for j in range(i + 1, len(cols)):
            pairs.append((cols[i], cols[j], float(strength[i, j])))
    return sorted(pairs, key=lambda p: p[2], reverse=True)


def _plot(sv, X_te, imp) -> None:
    fig = plt.figure(figsize=(9, 8))
    shap.summary_plot(sv, X_te, max_display=20, show=False, plot_size=None)
    plt.title("SHAP attributions per feature (red = legitimate encoding, "
              "blue = phishing encoding)", fontsize=10)
    plt.tight_layout()
    fig.savefig(FIGURES_DIR / "03_shap_beeswarm.png", dpi=150, bbox_inches="tight")
    plt.close(fig)

    top = imp.head(15).iloc[::-1]
    fig, axes = plt.subplots(1, 2, figsize=(13, 7), sharey=True)
    axes[0].barh(top["feature"], top["shap_share"], color="#2b7a78", edgecolor="black")
    axes[0].set_xlabel("Share of total |SHAP|")
    axes[0].set_title("SHAP importance")
    axes[1].barh(top["feature"], top["permutation_drop"], color="#c9773c",
                 edgecolor="black")
    axes[1].set_xlabel("Accuracy lost when shuffled")
    axes[1].set_title("Permutation importance")
    for ax in axes:
        ax.grid(axis="x", alpha=0.3)
    fig.suptitle("Two views of feature importance on the grouped test set")
    fig.tight_layout()
    fig.savefig(FIGURES_DIR / "03_importance_comparison.png", dpi=150)
    plt.close(fig)


if __name__ == "__main__":
    main()
