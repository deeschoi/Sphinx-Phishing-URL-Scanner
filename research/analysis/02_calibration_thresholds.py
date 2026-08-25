"""Calibration quality and cost-sensitive operating points.

Accuracy at a 0.5 cutoff is the wrong target for a security tool. Wrongly
blocking a legitimate bank costs something very different from letting a
credential-harvesting page through, and the right threshold depends on that
ratio. This script checks whether predicted probabilities are trustworthy in the
first place, then derives operating points for two deployment modes: a tolerant
"warn the user" setting and a strict "block outright" setting.
"""

from __future__ import annotations

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.base import clone
from sklearn.calibration import CalibratedClassifierCV
from sklearn.metrics import brier_score_loss

from phishing.config import FIGURES_DIR, REPORTS_DIR, ensure_dirs
from phishing.data import grouped_split, load_xy
from phishing.evaluate import (
    best_cost_threshold,
    expected_cost,
    reliability_curve,
    threshold_report,
)
from phishing.io import save_json
from phishing.models import build_models

# Cost ratios expressed as (false positive cost, false negative cost).
# A ratio of 1:1 treats both errors alike; 10:1 says blocking a legitimate site
# is ten times worse than missing a phish (a browser warning that users learn to
# ignore); 1:10 says the opposite (an enterprise mail gateway).
COST_SCENARIOS = {
    "balanced (1:1)": (1.0, 1.0),
    "avoid false alarms (10:1)": (10.0, 1.0),
    "avoid missed phish (1:10)": (1.0, 10.0),
}


def main() -> None:
    ensure_dirs()
    X, y, groups = load_xy()
    X_tr, X_te, y_tr, y_te, _, _ = grouped_split(X, y, groups)

    models = build_models()
    proba, calibrated_proba = {}, {}

    print("=== Calibration (Brier score, lower is better) ===")
    calib_rows = []
    for name, model in models.items():
        fitted = clone(model).fit(X_tr, y_tr)
        p = fitted.predict_proba(X_te)[:, 1]
        proba[name] = p

        # Platt scaling fitted with internal CV on the training set only.
        calib = CalibratedClassifierCV(clone(model), method="sigmoid", cv=5)
        calib.fit(X_tr, y_tr)
        pc = calib.predict_proba(X_te)[:, 1]
        calibrated_proba[name] = pc

        raw_b, cal_b = brier_score_loss(y_te, p), brier_score_loss(y_te, pc)
        print(f"  {name:22s} raw {raw_b:.4f} -> Platt-scaled {cal_b:.4f} "
              f"({'improved' if cal_b < raw_b else 'no gain'})")
        calib_rows.append({"model": name, "brier_raw": raw_b, "brier_calibrated": cal_b})

    print("\n=== Cost-optimal thresholds (grouped test set) ===")
    thr_rows = []
    for name in models:
        p = proba[name]
        for label, (fp_cost, fn_cost) in COST_SCENARIOS.items():
            t, cost = best_cost_threshold(y_te, p, fp_cost, fn_cost)
            m = threshold_report(y_te, p, t)
            default = expected_cost(y_te, p, 0.5, fp_cost, fn_cost)
            thr_rows.append({
                "model": name, "scenario": label, **m,
                "cost_at_tuned": cost, "cost_at_0.5": default,
                "cost_reduction": (default - cost) / default if default else 0.0,
            })

    thr = pd.DataFrame(thr_rows)
    best = thr.loc[thr["model"] == "XGBoost"]
    print(best[["scenario", "threshold", "accuracy", "precision", "recall",
                "fpr", "cost_reduction"]].round(4).to_string(index=False))

    print("\n=== Recall achievable at strict false-positive budgets (XGBoost) ===")
    budget_rows = []
    p = proba["XGBoost"]
    for budget in (0.001, 0.005, 0.01, 0.02, 0.05):
        grid = np.linspace(0.001, 0.999, 999)
        feasible = [(t, threshold_report(y_te, p, t)) for t in grid]
        feasible = [(t, m) for t, m in feasible if m["fpr"] <= budget]
        if not feasible:
            continue
        t, m = max(feasible, key=lambda tm: tm[1]["recall"])
        budget_rows.append({"fpr_budget": budget, **m})
        print(f"  FPR <= {budget:.1%}: threshold {t:.3f} catches "
              f"{m['recall']:.1%} of phishing sites "
              f"(misses {m['fn']} of {m['fn'] + m['tp']})")

    thr.to_csv(REPORTS_DIR / "02_thresholds.csv", index=False)
    save_json(
        {"calibration": calib_rows, "thresholds": thr.to_dict("records"),
         "fpr_budgets": budget_rows},
        REPORTS_DIR / "02_calibration_thresholds.json",
    )

    _plot_reliability(y_te, proba, calibrated_proba)
    _plot_cost_curves(y_te, proba)
    print(f"\nWrote results to {REPORTS_DIR}")


def _plot_reliability(y_te, proba, calibrated_proba) -> None:
    fig, axes = plt.subplots(1, 2, figsize=(12, 5.5), sharey=True)
    for ax, source, title in (
        (axes[0], proba, "Raw model probabilities"),
        (axes[1], calibrated_proba, "After Platt scaling"),
    ):
        ax.plot([0, 1], [0, 1], "k--", lw=1, label="Perfectly calibrated")
        for name, p in source.items():
            centres, observed, _ = reliability_curve(y_te, p, n_bins=12)
            ax.plot(centres, observed, "o-", ms=4, lw=1.5, label=name)
        ax.set_xlabel("Predicted probability of phishing")
        ax.set_title(title)
        ax.grid(alpha=0.3)
    axes[0].set_ylabel("Observed phishing rate")
    axes[1].legend(fontsize=8, loc="upper left")
    fig.suptitle("Reliability diagrams on the grouped test set")
    fig.tight_layout()
    fig.savefig(FIGURES_DIR / "02_reliability.png", dpi=150)
    plt.close(fig)


def _plot_cost_curves(y_te, proba) -> None:
    grid = np.linspace(0.01, 0.99, 197)
    fig, axes = plt.subplots(1, 3, figsize=(15, 4.6), sharey=False)
    for ax, (label, (fp_cost, fn_cost)) in zip(axes, COST_SCENARIOS.items(), strict=True):
        for name, p in proba.items():
            costs = [expected_cost(y_te, p, t, fp_cost, fn_cost) for t in grid]
            ax.plot(grid, costs, lw=1.6, label=name)
            i = int(np.argmin(costs))
            ax.plot(grid[i], costs[i], "o", ms=6)
        ax.axvline(0.5, color="gray", ls=":", lw=1, label="Default 0.5 cutoff")
        ax.set_title(label)
        ax.set_xlabel("Decision threshold")
        ax.set_ylabel("Expected cost per URL")
        ax.grid(alpha=0.3)
    axes[-1].legend(fontsize=8)
    fig.suptitle("Expected misclassification cost by threshold; dots mark the optimum")
    fig.tight_layout()
    fig.savefig(FIGURES_DIR / "02_cost_curves.png", dpi=150)
    plt.close(fig)


if __name__ == "__main__":
    main()
