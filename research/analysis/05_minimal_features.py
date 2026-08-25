"""Smallest feature set that stays within a point of the full model.

Every feature costs something at scan time: a TLS handshake, a WHOIS query, an
HTML parse. Greedy forward selection scored by grouped cross-validation finds how
few we can get away with. Restricting the candidate pool to features that are
still obtainable in 2026 makes the answer directly usable by the scanner.
"""

from __future__ import annotations

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd
from sklearn.base import clone
from sklearn.model_selection import cross_val_score
from sklearn.tree import DecisionTreeClassifier, export_text

from phishing.config import (
    DEPLOYABLE_FEATURES,
    FIGURES_DIR,
    RANDOM_STATE,
    REPORTS_DIR,
    ensure_dirs,
)
from phishing.data import grouped_split, load_xy
from phishing.evaluate import cv_splitter, metric_dict
from phishing.io import save_json
from phishing.models import build_models

MAX_FEATURES = 12


def forward_select(X, y, groups, candidates, model, max_features=MAX_FEATURES):
    chosen, history, remaining = [], [], list(candidates)
    cv = cv_splitter(grouped=True)

    while remaining and len(chosen) < max_features:
        scored = []
        for feat in remaining:
            trial = chosen + [feat]
            score = cross_val_score(
                clone(model), X[trial], y, groups=groups, cv=cv,
                scoring="accuracy", n_jobs=-1,
            ).mean()
            scored.append((score, feat))
        score, feat = max(scored)
        chosen.append(feat)
        remaining.remove(feat)
        history.append({"k": len(chosen), "added": feat, "cv_accuracy": float(score)})
        print(f"  {len(chosen):2d}. +{feat:28s} CV accuracy {score:.4f}")

    return chosen, history


def main() -> None:
    ensure_dirs()
    X, y, groups = load_xy()
    X_tr, X_te, y_tr, y_te, _, _ = grouped_split(X, y, groups)

    # A shallow tree is fast enough to make forward selection tractable and is
    # itself a candidate deliverable, since the result is human-readable.
    selector_model = DecisionTreeClassifier(max_depth=8, random_state=RANDOM_STATE)
    deployable = list(DEPLOYABLE_FEATURES)

    print("=== Greedy forward selection over features available in 2026 ===")
    chosen, history = forward_select(X, y, groups, deployable, selector_model)

    xgb_template = build_models()["XGBoost"]

    full = clone(xgb_template).fit(X_tr[deployable], y_tr)
    full_acc = metric_dict(
        y_te, full.predict(X_te[deployable]),
        full.predict_proba(X_te[deployable])[:, 1],
    )["accuracy"]
    print(f"\nReference: XGBoost on all {len(deployable)} deployable features "
          f"= {full_acc:.4f}")

    print("\n=== Test accuracy of the top-k selected features (XGBoost) ===")
    curve = []
    for k in range(1, len(chosen) + 1):
        feats = chosen[:k]
        m = clone(xgb_template).fit(X_tr[feats], y_tr)
        s = metric_dict(y_te, m.predict(X_te[feats]), m.predict_proba(X_te[feats])[:, 1])
        curve.append({"k": k, "features": feats, **s})
        print(f"  k={k:2d}  acc={s['accuracy']:.4f}  auroc={s['auroc']:.4f}  "
              f"(+{feats[-1]})")

    curve_df = pd.DataFrame(curve)
    within_1pt = curve_df[curve_df["accuracy"] >= full_acc - 0.01]
    k_star = int(within_1pt["k"].min()) if len(within_1pt) else len(chosen)
    print(f"\nSmallest set within 1 point of the full deployable model: "
          f"k = {k_star}")
    print(f"  {chosen[:k_star]}")

    print("\n=== Same features as a readable decision tree (depth 4) ===")
    tree = DecisionTreeClassifier(max_depth=4, random_state=RANDOM_STATE)
    tree.fit(X_tr[chosen[:k_star]], y_tr)
    tree_acc = metric_dict(
        y_te, tree.predict(X_te[chosen[:k_star]]),
        tree.predict_proba(X_te[chosen[:k_star]])[:, 1],
    )
    print(f"Depth-4 tree on {k_star} features: accuracy {tree_acc['accuracy']:.4f}")
    rules = export_text(tree, feature_names=chosen[:k_star], max_depth=4)
    print(rules[:1500])

    (REPORTS_DIR / "05_decision_rules.txt").write_text(rules)
    curve_df.drop(columns=["features"]).to_csv(
        REPORTS_DIR / "05_minimal_features.csv", index=False
    )
    save_json({
        "selection_history": history,
        "accuracy_curve": [{k: v for k, v in row.items() if k != "features"}
                           for row in curve],
        "selected_order": chosen,
        "k_within_1pt": k_star,
        "minimal_feature_set": chosen[:k_star],
        "full_deployable_accuracy": full_acc,
        "shallow_tree_accuracy": tree_acc["accuracy"],
    }, REPORTS_DIR / "05_minimal_features.json")

    _plot(curve_df, full_acc, k_star, chosen)
    print(f"\nWrote results to {REPORTS_DIR}")


def _plot(curve_df, full_acc, k_star, chosen) -> None:
    fig, ax = plt.subplots(figsize=(10, 5.5))
    ax.plot(curve_df["k"], curve_df["accuracy"], "o-", color="#2b7a78", lw=2,
            label="XGBoost on top-k selected features")
    ax.axhline(full_acc, color="black", ls="--", lw=1.2,
               label=f"All 25 deployable features ({full_acc:.3f})")
    ax.axhline(full_acc - 0.01, color="gray", ls=":", lw=1,
               label="Within 1 accuracy point")
    ax.axvline(k_star, color="#c9773c", ls="-.", lw=1.5, label=f"k = {k_star}")

    for row in curve_df.itertuples():
        ax.annotate(chosen[row.k - 1], (row.k, row.accuracy),
                    textcoords="offset points", xytext=(0, -14),
                    ha="center", fontsize=7, rotation=30)

    ax.set_xlabel("Number of features")
    ax.set_ylabel("Test accuracy (grouped split)")
    ax.set_title("Greedy forward selection: accuracy against feature budget")
    ax.set_ylim(0.65, 1.0)
    ax.legend(loc="lower right", fontsize=9)
    ax.grid(alpha=0.3)
    fig.tight_layout()
    fig.savefig(FIGURES_DIR / "05_minimal_features.png", dpi=150)
    plt.close(fig)


if __name__ == "__main__":
    main()
