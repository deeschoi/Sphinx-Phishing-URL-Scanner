"""CLI: train, evaluate, and scan a live URL.

Usage (from the repo root)::

    PYTHONPATH=src python -m phishing.cli evaluate
    PYTHONPATH=src python -m phishing.cli train
    PYTHONPATH=src python -m phishing.cli scan https://example.com
"""

from __future__ import annotations

import argparse
import json
import sys

import pandas as pd

from phishing.config import REPORTS_DIR, ensure_dirs
from phishing.data import load_xy
from phishing.evaluate import leakage_delta_table
from phishing.models import ALL_MODELS, NOTEBOOK_MODELS


def cmd_evaluate(args: argparse.Namespace) -> int:
    ensure_dirs()
    X, y, groups = load_xy()
    names = NOTEBOOK_MODELS if args.quick else ALL_MODELS
    print(f"Computing leakage-delta table for: {', '.join(names)}")
    table = leakage_delta_table(X, y, groups, model_names=names)
    out = REPORTS_DIR / "leakage_delta.csv"
    table.to_csv(out)
    print(table.round(4).to_string())
    print(f"\nWrote {out}")
    return 0


def cmd_train(_args: argparse.Namespace) -> int:
    """Train the PhiUSIIL scanner model and persist it."""
    from phishing.fit import train_phiusiil_model

    print("Training PhiUSIIL model (host-grouped holdout)...")
    card = train_phiusiil_model()
    metrics = card["metrics"]
    print(
        f"held-out acc={metrics['accuracy']:.4f}  "
        f"auroc={metrics['auroc']:.4f}  f1={metrics['f1']:.4f}  "
        f"brier={metrics['brier']:.4f}"
    )
    for name, report in card["thresholds"].items():
        print(
            f"  {name:5s} threshold {report['threshold']:.3f}  "
            f"recall={report['recall']:.3f}  fpr={report['fpr']:.3f}"
        )
    print(f"Saved {card['artifact']}")
    return 0


def _shap_bar(contribution: float, width: int = 10) -> str:
    filled = int(round(min(abs(contribution), 3.0) / 3.0 * width))
    return ("█" * filled).ljust(width, "░")


def render_scan(payload: dict) -> str:
    """One-screen human summary of a scan payload."""
    verdict = str(payload.get("verdict") or "unknown")
    probability = float(payload.get("probability") or 0.0)
    lines = [
        f"{verdict}  p={probability:.3f}",
        str(payload.get("model") or ""),
    ]
    rationale = str(payload.get("rationale") or "").strip()
    if rationale:
        lines.append("")
        lines.append(rationale)
    signals = list(payload.get("signals") or [])[:5]
    if signals:
        lines.append("")
        lines.append("Top signals")
        for signal in signals:
            label = str(signal.get("label") or signal.get("feature") or "")
            contrib = float(signal.get("contribution") or 0.0)
            sign = "+" if contrib >= 0 else ""
            lines.append(f"  {_shap_bar(contrib)}  {sign}{contrib:.2f}  {label}")
    notes = [str(note) for note in (payload.get("notes") or []) if note]
    if notes:
        lines.append("")
        lines.append("Notes")
        for note in notes:
            lines.append(f"  • {note}")
    coverage = payload.get("coverage") or {}
    lines.append("")
    lines.append("Coverage")
    lines.append(f"  reachability: {coverage.get('reachability') or '—'}")
    lines.append(f"  page fetched: {'yes' if coverage.get('page_fetched') else 'no'}")
    hops = coverage.get("redirect_hops") or []
    n_hops = coverage.get("redirects") or len(hops)
    lines.append(f"  redirects: {n_hops}")
    for hop in hops:
        mark = " (shortener)" if hop.get("shortener") else ""
        lines.append(f"    {hop.get('url')}{mark}")
    host_unicode = payload.get("host_unicode")
    if host_unicode:
        lines.append(f"  unicode host: {host_unicode}")
    return "\n".join(lines).rstrip() + "\n"


def cmd_scan(args: argparse.Namespace) -> int:
    from phishing.scanner import UnsafeTargetError, scan

    try:
        payload = scan(args.url, tier=args.tier)
    except UnsafeTargetError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    except (ValueError, FileNotFoundError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    if args.json:
        print(json.dumps(payload, indent=2, default=str))
    else:
        print(render_scan(payload), end="")
    return 0


def cmd_validate(_args: argparse.Namespace) -> int:
    """Compare live Tier-A features on known URLs against the 2012 legitimate class."""
    from phishing.config import TARGET_COLUMN, TIER_A
    from phishing.data import load_raw, to_model_frame
    from phishing.features.url_features import extract_url_features

    legit_urls = [
        "https://www.google.com/",
        "https://www.wikipedia.org/",
        "https://github.com/",
        "https://www.apple.com/",
        "https://www.microsoft.com/",
        "https://www.amazon.com/",
        "https://www.nytimes.com/",
        "https://www.bbc.com/",
        "https://www.mozilla.org/",
        "https://www.cloudflare.com/",
        "https://stackoverflow.com/",
        "https://www.reddit.com/",
        "https://www.linkedin.com/",
        "https://www.youtube.com/",
        "https://www.instagram.com/",
        "https://www.netflix.com/",
        "https://www.adobe.com/",
        "https://www.ibm.com/",
        "https://www.oracle.com/",
        "https://www.salesforce.com/",
    ]
    phishy_urls = [
        "http://192.168.1.10/login",
        "http://bit.ly/abc123",
        "http://paypal-secure-login.com/confirm",
        "http://www.bank.com@evil.example/steal",
        "http://https-www-paypal-it.soft-hair.com/",
        "http://login.secure.update.paypal.example.com/session",
        "http://example.com//http://phishing.example/drop",
        "http://tinyurl.com/r4nd0m",
        "http://confirm-account-appleid.com/webapps/mpp/home?dispatch=" + "a" * 80,
        "http://0x58.0xCC.0xCA.0x62/2/paypal.ca/index.html",
    ]

    rows = []
    for url, label in [(u, "legit_2026") for u in legit_urls] + [
        (u, "synthetic_phish") for u in phishy_urls
    ]:
        feats = extract_url_features(url)
        feats["source"] = label
        feats["url"] = url
        rows.append(feats)
    live = pd.DataFrame(rows)

    raw = to_model_frame(load_raw())
    legit_2012 = raw.loc[raw[TARGET_COLUMN] == 0, TIER_A]
    live_legit = live.loc[live["source"] == "legit_2026", TIER_A]

    comparison = pd.DataFrame(
        {
            "mean_2012_legit": legit_2012.mean(),
            "mean_2026_legit_tierA": live_legit.mean(),
            "mean_synthetic_phish_tierA": live.loc[
                live["source"] == "synthetic_phish", TIER_A
            ].mean(),
        }
    )
    ensure_dirs()
    comparison.to_csv(REPORTS_DIR / "extractor_drift.csv")
    live.to_csv(REPORTS_DIR / "extractor_live_sample.csv", index=False)
    print(comparison.round(3).to_string())
    print(f"\nWrote {REPORTS_DIR / 'extractor_drift.csv'}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="phishing")
    sub = p.add_subparsers(dest="cmd", required=True)

    ev = sub.add_parser("evaluate", help="random vs grouped CV leakage table")
    ev.add_argument("--quick", action="store_true", help="notebook's three models only")
    ev.set_defaults(func=cmd_evaluate)

    # --tune and --quick used to be accepted here and then printed that they
    # were ignored; --model on `scan` was parsed and never read. Flags that do
    # nothing are worse than absent ones, so they are gone.
    tr = sub.add_parser("train", help="train and persist the PhiUSIIL scanner model")
    tr.set_defaults(func=cmd_train)

    sc = sub.add_parser("scan", help="extract features and score a URL")
    sc.add_argument("url")
    sc.add_argument("--tier", choices=["A", "B", "full"], default="full")
    sc.add_argument("--json", action="store_true", help="print the full payload")
    sc.set_defaults(func=cmd_scan)

    va = sub.add_parser("validate", help="Tier-A drift vs 2012 legitimate class")
    va.set_defaults(func=cmd_validate)
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
