"""Measure live-scan accuracy on a random sample of PhiUSIIL hosts.

The model card's grouped-holdout number is measured on the frozen 2023 CSV
columns. This script re-extracts every feature over the network in 2026, so it
reports what the deployed scanner actually does: false positives on modern
legitimate pages, misses on phishing kits, and hosts that no longer resolve.

Tune on one seed, report on another. Network variance means the set of dead
hosts differs between runs, so reachability counts are part of the result.

    python scripts/07_live_sample_eval.py --seed 42 --n-per-class 80
"""

from __future__ import annotations

import argparse
import random
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import urlparse

import pandas as pd

from phishing.config import PROJECT_ROOT, REPORTS_DIR, ensure_dirs
from phishing.io import save_json

DATASETS = PROJECT_ROOT / "datasets"
LEGIT_CSV = DATASETS / "PhiUSIIL_Legitimate_Only.csv"
PHISH_CSV = DATASETS / "PhiUSIIL_Phishing_Only.csv"

# Verdicts that are a live-site risk judgment. Anything else (unreachable,
# not_probed) means the scanner withheld a rating.
RATED = {"phishing", "suspicious", "probably safe", "legitimate"}
FLAGGED = {"phishing", "suspicious"}

# Fields kept for each misclassified host, so a regression can be attributed
# to the page model or the URL model without re-running the scan.
_DETAIL = ("url", "verdict", "probability", "url_probability", "page_probability")


def _disable_shap() -> None:
    """SHAP is 90% of the wall time and does not change the probability."""
    import phishing.explain

    def _no_shap(estimator, X, background=None):  # noqa: ANN001, ARG001
        raise RuntimeError("SHAP disabled for the live sample harness")

    phishing.explain.shap_values = _no_shap


def _host(url: str) -> str:
    return (urlparse(str(url)).hostname or "").lower().rstrip(".")


def _sample_unique_hosts(csv_path: Path, n: int, seed: int) -> list[str]:
    """One URL per hostname, so a kit with 400 paths cannot dominate the sample."""
    if not csv_path.is_file():
        raise FileNotFoundError(
            f"{csv_path} not found. Split the PhiUSIIL CSV by label first."
        )
    urls = pd.read_csv(csv_path, usecols=["URL"], low_memory=False)["URL"].tolist()
    by_host: dict[str, str] = {}
    for url in urls:
        host = _host(url)
        if host and host not in by_host:
            by_host[host] = url
    hosts = sorted(by_host)
    rng = random.Random(seed)
    picked = rng.sample(hosts, min(n, len(hosts)))
    return [by_host[h] for h in picked]


def _scan_one(url: str, label: int, timeout: int) -> dict:
    from phishing.scanner import scan

    row = {"url": url, "label": label, "host": _host(url)}
    try:
        result = scan(url, tier="full", timeout=timeout)
    except Exception as exc:  # noqa: BLE001
        row.update(verdict="error", error=str(exc), probability=None)
        return row
    row.update(
        verdict=result["verdict"],
        risk=result.get("risk"),
        probability=result.get("probability"),
        page_probability=result.get("page_probability"),
        url_probability=result.get("url_probability"),
        url_pattern_risk=result.get("url_pattern_risk"),
        url_only=result.get("url_only"),
        reachability=(result.get("coverage") or {}).get("reachability"),
        model=result.get("model"),
        error=None,
    )
    return row


def _confusion(rows: list[dict]) -> dict:
    """Accuracy over rated hosts only; unrated hosts are counted separately."""
    rated = [r for r in rows if r["verdict"] in RATED]
    tp = sum(1 for r in rated if r["label"] == 1 and r["verdict"] in FLAGGED)
    fn = sum(1 for r in rated if r["label"] == 1 and r["verdict"] not in FLAGGED)
    fp = sum(1 for r in rated if r["label"] == 0 and r["verdict"] in FLAGGED)
    tn = sum(1 for r in rated if r["label"] == 0 and r["verdict"] not in FLAGGED)
    total = tp + fn + fp + tn
    return {
        "n_rated": total,
        "true_positive": tp,
        "false_negative": fn,
        "false_positive": fp,
        "true_negative": tn,
        "accuracy": (tp + tn) / total if total else 0.0,
        "recall": tp / (tp + fn) if (tp + fn) else 0.0,
        "false_positive_rate": fp / (fp + tn) if (fp + tn) else 0.0,
        "precision": tp / (tp + fp) if (tp + fp) else 0.0,
    }


def _reachability(rows: list[dict]) -> dict:
    out: dict[str, dict[str, int]] = {}
    for row in rows:
        klass = "phishing" if row["label"] == 1 else "legitimate"
        bucket = out.setdefault(klass, {})
        status = row.get("reachability") or row.get("verdict") or "unknown"
        bucket[status] = bucket.get(status, 0) + 1
    return out


def _unrated_url_risk(rows: list[dict]) -> dict:
    """Of the hosts that got no rating, what did the URL string alone say?"""
    unrated = [r for r in rows if r["verdict"] not in RATED and r["verdict"] != "error"]
    counts: dict[str, int] = {}
    for row in unrated:
        key = str(row.get("url_pattern_risk"))
        counts[key] = counts.get(key, 0) + 1
    phishing_unrated = [r for r in unrated if r["label"] == 1]
    return {
        "n_unrated": len(unrated),
        "n_unrated_phishing": len(phishing_unrated),
        "url_pattern_risk": counts,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--n-per-class", type=int, default=80)
    parser.add_argument("--timeout", type=int, default=8)
    parser.add_argument("--workers", type=int, default=16)
    parser.add_argument("--out", type=Path, default=REPORTS_DIR / "phiusiil_live_sample_eval.json")
    args = parser.parse_args()

    ensure_dirs()
    _disable_shap()

    legit = _sample_unique_hosts(LEGIT_CSV, args.n_per_class, args.seed)
    phish = _sample_unique_hosts(PHISH_CSV, args.n_per_class, args.seed)
    jobs = [(url, 0) for url in legit] + [(url, 1) for url in phish]
    print(f"scanning {len(jobs)} hosts (seed {args.seed}, {args.n_per_class}/class)…")

    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        rows = list(
            pool.map(lambda job: _scan_one(job[0], job[1], args.timeout), jobs)
        )

    confusion = _confusion(rows)
    payload = {
        "seed": args.seed,
        "n_per_class": args.n_per_class,
        "timeout": args.timeout,
        "confusion": confusion,
        "reachability": _reachability(rows),
        "unrated": _unrated_url_risk(rows),
        "false_positives": [
            {k: r[k] for k in _DETAIL}
            for r in rows
            if r["label"] == 0 and r["verdict"] in FLAGGED
        ],
        "false_negatives": [
            {k: r[k] for k in _DETAIL}
            for r in rows
            if r["label"] == 1 and r["verdict"] in RATED and r["verdict"] not in FLAGGED
        ],
        "rows": rows,
    }
    save_json(payload, args.out)

    print(
        f"\n=== live sample (seed {args.seed}) ===\n"
        f"  rated {confusion['n_rated']} of {len(rows)} hosts\n"
        f"  accuracy {confusion['accuracy']:.3f}  recall {confusion['recall']:.3f}  "
        f"FPR {confusion['false_positive_rate']:.3f}\n"
        f"  TP {confusion['true_positive']}  FN {confusion['false_negative']}  "
        f"FP {confusion['false_positive']}  TN {confusion['true_negative']}"
    )
    unrated = payload["unrated"]
    print(
        f"  unrated {unrated['n_unrated']} "
        f"({unrated['n_unrated_phishing']} phishing): {unrated['url_pattern_risk']}"
    )
    print(f"\nWrote {args.out}")


if __name__ == "__main__":
    main()
