"""What survives when 2012-era features are no longer available?

Five of the thirty features depend on services that no longer exist: Alexa rank
was retired in 2022, Toolbar PageRank in 2016, and the rest need paid APIs or a
blocklist frozen in November 2012. A separate worry is SSLfinal_State, the single
strongest predictor: in 2012 HTTPS was a genuine discriminator, but it is now
near-universal, so a model leaning on it may be measuring nothing.

This script scores nested feature sets that correspond to real deployment
constraints, which also tells the scanner how much accuracy each tier of network
access is worth.
"""

from __future__ import annotations

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.base import clone

from phishing.config import (
    DEPLOYABLE_FEATURES,
    FEATURE_COLUMNS,
    FIGURES_DIR,
    REPORTS_DIR,
    SOURCE,
    ensure_dirs,
)
from phishing.config import (
    NO_SIGNAL_FEATURES as NO_SIGNAL,
)
from phishing.config import (
    REVERSED_FEATURES as REVERSED,
)
from phishing.data import grouped_split, load_xy
from phishing.evaluate import metric_dict
from phishing.io import save_json
from phishing.models import build_models


def by_source(*kinds: str) -> list[str]:
    return [f for f in FEATURE_COLUMNS if SOURCE[f] in kinds]


def scenarios() -> dict[str, list[str]]:
    available = list(DEPLOYABLE_FEATURES)
    return {
        "All 30 features": FEATURE_COLUMNS,
        "Without SSLfinal_State": [f for f in FEATURE_COLUMNS if f != "SSLfinal_State"],
        "Without the 5 dead-service features": available,
        "Without dead services or SSL": [f for f in available if f != "SSLfinal_State"],
        "Without the 7 reversed features": [f for f in FEATURE_COLUMNS if f not in REVERSED],
        "Without reversed or no-signal features": [
            f for f in FEATURE_COLUMNS if f not in REVERSED + NO_SIGNAL
        ],
        "URL string only (no network)": by_source("url_only"),
        "URL string + TLS certificate": by_source("url_only", "tls"),
        "URL + TLS + page fetch": by_source("url_only", "tls", "http"),
        "Everything computable in 2026": by_source(
            "url_only", "tls", "http", "dns_whois", "portscan"
        ),
    }


def main() -> None:
    ensure_dirs()
    X, y, groups = load_xy()
    X_tr, X_te, y_tr, y_te, _, _ = grouped_split(X, y, groups)

    print("=== Feature availability in 2026 ===")
    counts = pd.Series({f: SOURCE[f] for f in FEATURE_COLUMNS}).value_counts()
    for kind, n in counts.items():
        print(f"  {kind:10s} {n:2d} features")

    template = build_models()["XGBoost"]
    rows = []
    baseline = None

    print("\n=== Accuracy by feature scenario (XGBoost, grouped test set) ===")
    for label, feats in scenarios().items():
        model = clone(template).fit(X_tr[feats], y_tr)
        p = model.predict_proba(X_te[feats])[:, 1]
        s = metric_dict(y_te, model.predict(X_te[feats]), p)
        if baseline is None:
            baseline = s["accuracy"]
        delta = s["accuracy"] - baseline
        rows.append({"scenario": label, "n_features": len(feats),
                     "delta_vs_full": delta, **s})
        print(f"  {label:42s} p={len(feats):2d}  acc={s['accuracy']:.4f}  "
              f"auroc={s['auroc']:.4f}  ({delta:+.4f})")

    results = pd.DataFrame(rows)
    results.to_csv(REPORTS_DIR / "04_obsolescence.csv", index=False)

    # How much does each individual feature actually matter on its own?
    print("\n=== Leave-one-out impact of the top features ===")
    loo = []
    for feat in ["SSLfinal_State", "URL_of_Anchor", "web_traffic", "Prefix_Suffix",
                 "having_Sub_Domain", "Links_in_tags"]:
        feats = [f for f in FEATURE_COLUMNS if f != feat]
        model = clone(template).fit(X_tr[feats], y_tr)
        acc = metric_dict(y_te, model.predict(X_te[feats]),
                          model.predict_proba(X_te[feats])[:, 1])["accuracy"]
        loo.append({"feature": feat, "accuracy_without": acc,
                    "accuracy_lost": baseline - acc})
        print(f"  drop {feat:26s} -> {acc:.4f}  (loses {baseline - acc:+.4f})")

    save_json({"baseline_accuracy": baseline,
               "scenarios": results.to_dict("records"),
               "leave_one_out": loo},
              REPORTS_DIR / "04_obsolescence.json")

    _plot(results, baseline)
    print(f"\nWrote results to {REPORTS_DIR}")


def _plot(results: pd.DataFrame, baseline: float) -> None:
    r = results.iloc[::-1]
    pos = np.arange(len(r))
    colors = ["#2b7a78" if d >= -0.01 else "#c94c4c" for d in r["delta_vs_full"]]

    fig, ax = plt.subplots(figsize=(10, 6))
    ax.barh(pos, r["accuracy"], color=colors, edgecolor="black")
    ax.axvline(baseline, color="black", ls="--", lw=1.2,
               label=f"All 30 features ({baseline:.3f})")
    for i, (acc, n) in enumerate(zip(r["accuracy"], r["n_features"], strict=True)):
        ax.text(acc + 0.003, i, f"{acc:.3f}  (p={n})", va="center", fontsize=9)

    ax.set_yticks(pos)
    ax.set_yticklabels(r["scenario"], fontsize=9)
    ax.set_xlim(0.75, 1.02)
    ax.set_xlabel("Test accuracy (grouped split)")
    ax.set_title("How much accuracy survives when features become unavailable")
    ax.legend(loc="lower right")
    ax.grid(axis="x", alpha=0.3)
    fig.tight_layout()
    fig.savefig(FIGURES_DIR / "04_obsolescence.png", dpi=150)
    plt.close(fig)


if __name__ == "__main__":
    main()
