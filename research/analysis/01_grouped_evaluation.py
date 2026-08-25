"""Re-evaluate every model under a leakage-free split.

The original notebook uses a random 80/20 split. Because 47% of rows are exact
duplicate feature vectors, that split lets most test patterns appear in training
too, so reported accuracy is optimistic. This script measures the size of that
bias by scoring the same models two ways: the naive random split and a grouped
split where each distinct feature pattern belongs to exactly one side.
"""

from __future__ import annotations

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.base import clone
from sklearn.model_selection import cross_val_score

from phishing.config import FIGURES_DIR, REPORTS_DIR, ensure_dirs
from phishing.data import grouped_split, leakage_report, load_xy, stratified_split
from phishing.evaluate import cv_splitter, metric_dict
from phishing.io import save_json
from phishing.models import build_models


def main() -> None:
    ensure_dirs()
    X, y, groups = load_xy()

    leak = leakage_report(X, y)
    print("=== Leakage in the naive random split ===")
    print(f"rows                                  {leak['n_rows']:,}")
    print(f"unique feature patterns               {leak['n_unique_patterns']:,}")
    print(f"duplicate rows                        {leak['duplicate_row_fraction']:.1%}")
    print(f"test rows whose pattern is in train   "
          f"{leak['random_split_test_rows_seen_in_train']:.1%}")
    print(f"patterns with contradictory labels    {leak['conflicting_label_patterns']} "
          f"({leak['conflicting_label_fraction']:.1%})")

    Xr_tr, Xr_te, yr_tr, yr_te = stratified_split(X, y)
    Xg_tr, Xg_te, yg_tr, yg_te, _, _ = grouped_split(X, y, groups)
    print(f"\ngrouped split sizes: train={len(Xg_tr):,} test={len(Xg_te):,} "
          f"(phishing rate {yg_te.mean():.3f})")

    rows = []
    for name, model in build_models().items():
        print(f"\n--- {name} ---")

        cv_random = cross_val_score(
            clone(model), Xr_tr, yr_tr, cv=cv_splitter(grouped=False),
            scoring="accuracy", n_jobs=1,
        )
        cv_grouped = cross_val_score(
            clone(model), X, y, groups=groups, cv=cv_splitter(grouped=True),
            scoring="accuracy", n_jobs=1,
        )

        m_random = clone(model).fit(Xr_tr, yr_tr)
        s_random = metric_dict(
            yr_te, m_random.predict(Xr_te), m_random.predict_proba(Xr_te)[:, 1]
        )

        m_grouped = clone(model).fit(Xg_tr, yg_tr)
        s_grouped = metric_dict(
            yg_te, m_grouped.predict(Xg_te), m_grouped.predict_proba(Xg_te)[:, 1]
        )

        gap = s_random["accuracy"] - s_grouped["accuracy"]
        print(f"  random  CV {cv_random.mean():.4f} +/- {cv_random.std():.4f} | "
              f"test acc {s_random['accuracy']:.4f} auroc {s_random['auroc']:.4f}")
        print(f"  grouped CV {cv_grouped.mean():.4f} +/- {cv_grouped.std():.4f} | "
              f"test acc {s_grouped['accuracy']:.4f} auroc {s_grouped['auroc']:.4f}")
        print(f"  optimism from leakage: {gap:+.4f} accuracy")

        rows.append({
            "model": name,
            "cv_random_mean": cv_random.mean(), "cv_random_std": cv_random.std(),
            "cv_grouped_mean": cv_grouped.mean(), "cv_grouped_std": cv_grouped.std(),
            **{f"random_{k}": v for k, v in s_random.items()},
            **{f"grouped_{k}": v for k, v in s_grouped.items()},
            "accuracy_optimism": gap,
        })

    results = pd.DataFrame(rows).set_index("model")
    results.to_csv(REPORTS_DIR / "01_grouped_evaluation.csv")
    save_json(
        {"leakage": leak, "results": results.reset_index().to_dict("records")},
        REPORTS_DIR / "01_grouped_evaluation.json",
    )

    print("\n=== Honest (grouped) test performance ===")
    print(results[["grouped_accuracy", "grouped_auroc", "grouped_precision",
                   "grouped_recall", "grouped_f1"]].round(4).to_string())
    print("\n=== Optimism introduced by the random split ===")
    print(results[["random_accuracy", "grouped_accuracy", "accuracy_optimism"]]
          .round(4).to_string())

    _plot(results)
    print(f"\nWrote results to {REPORTS_DIR}")


def _plot(results: pd.DataFrame) -> None:
    order = results["grouped_accuracy"].sort_values().index
    r = results.loc[order]
    pos = np.arange(len(r))
    height = 0.38

    fig, ax = plt.subplots(figsize=(9, 5))
    ax.barh(pos + height / 2, r["random_accuracy"], height,
            label="Random split (leaky)", color="#c94c4c", edgecolor="black")
    ax.barh(pos - height / 2, r["grouped_accuracy"], height,
            label="Grouped split (honest)", color="#2b7a78", edgecolor="black")

    for i, (rand, grp) in enumerate(
        zip(r["random_accuracy"], r["grouped_accuracy"], strict=True)
    ):
        ax.text(rand + 0.002, i + height / 2, f"{rand:.3f}", va="center", fontsize=9)
        ax.text(grp + 0.002, i - height / 2, f"{grp:.3f}", va="center", fontsize=9)

    ax.set_yticks(pos)
    ax.set_yticklabels(r.index)
    ax.set_xlim(0.85, 1.0)
    ax.set_xlabel("Test accuracy")
    ax.set_title("Duplicate feature vectors inflate accuracy on this dataset\n"
                 "Same models, same data, different partitioning rule")
    ax.legend(loc="lower right")
    ax.grid(axis="x", alpha=0.3)
    fig.tight_layout()
    fig.savefig(FIGURES_DIR / "01_leakage_effect.png", dpi=150)
    plt.close(fig)


if __name__ == "__main__":
    main()
