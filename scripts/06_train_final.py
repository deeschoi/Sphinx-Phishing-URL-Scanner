"""Train and persist the model the scanner serves.

The served estimator is trained on PhiUSIIL (2023 URLs), not the 2012 UCI table.
Host-grouped holdout numbers are the honest estimate; the artifact is refitted
on the full table so the scanner sees every labelled host.
"""

from __future__ import annotations

from phishing.fit import train_phiusiil_model


def main() -> None:
    card = train_phiusiil_model()
    print(f"=== PhiUSIIL model ({card['n_features']} features) ===")
    print(f"  rows {card['n_rows']}  train {card['n_train']}  test {card['n_test']}")
    metrics = card["metrics"]
    print(
        f"  held-out accuracy {metrics['accuracy']:.4f}  "
        f"auroc {metrics['auroc']:.4f}  brier {metrics['brier']:.4f}"
    )
    url_only = card.get("url_only") or {}
    url_metrics = url_only.get("metrics") or {}
    if url_metrics:
        print(
            f"  URL-only accuracy {url_metrics['accuracy']:.4f}  "
            f"auroc {url_metrics['auroc']:.4f}  brier {url_metrics['brier']:.4f}"
        )
    for name, report in card["thresholds"].items():
        print(
            f"  {name:5s} threshold {report['threshold']:.3f} -> "
            f"recall {report['recall']:.3f}, false-positive rate {report['fpr']:.3f}"
        )
    print(f"\n  saved to {card['artifact']}")
    print(f"  note: {card.get('limitation', '')}")
    print("Model card written to reports/06_model_card.json")


if __name__ == "__main__":
    main()
