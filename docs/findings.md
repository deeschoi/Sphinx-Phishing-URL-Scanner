# How well Sphinx actually scores

This is the evaluation write-up: live vs holdout numbers, what was tried and rejected, and why the served model is PhiUSIIL rather than the 2012 UCI table. How a scan is extracted: [methodology.md](methodology.md). Verdicts, features, and payload: [parameters.md](parameters.md). Install and config: [README](../README.md).

## Live vs holdout

The served estimator is **XGBoost** trained on [PhiUSIIL](https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset) (Prasad & Chandra, 2023): 235,795 rows, 48 features, 42.8% phishing. Evaluation is a **host-grouped holdout** — no hostname is shared between train and test.

The model card reports **99.95% accuracy** on that holdout. That number is measured on the **frozen 2023 CSV columns**. It is an upper bound, not a deployment estimate. The UI reports both this figure and the live-sample figure on every scan.

`scripts/07_live_sample_eval.py` re-extracts every feature over the network, which is what Sphinx actually does:

```bash
PYTHONPATH=src python scripts/07_live_sample_eval.py --seed 7 --n-per-class 120
```

Held-out sample, seed 7, 120 unique hosts per class (tuning was done on seed 42):

| | Baseline | After disagreement + URL-pattern chip |
|---|---|---|
| Accuracy | 0.878 | **0.906** |
| Recall | 0.781 | 0.750 |
| False-positive rate | 0.068 | **0.009** |
| Precision | 0.862 | **0.980** |

Of 240 hosts, 59 no longer resolve (56 of them phishing). That churn, not the model, is the main limit on live recall. Of those 59 unrated hosts, the eval dump still records 54 as phishing-shaped on the URL string. The remaining handful used to receive a `legitimate` string chip; current Sphinx withholds that chip, because a clean-looking origin is not evidence that a dead host is safe.

## What was measured and rejected

Three plausible changes made things worse and were backed out; the reasoning is in the code comments so they are not retried:

- *A free-hosting-platform feature.* These suffixes cover 22,478 phishing rows and **1** legitimate row in PhiUSIIL. Trained as an input it became the #2 feature and scored real docs sites (`docs.github.io`, `nextjs.vercel.app`) at *p* ≈ 0.999. Kept only as the routing hint in [methodology.md](methodology.md).
- *Counting subdomain depth against the platform suffix.* Cost 4.7 points of recall: it also lowers every kit parked on those same suffixes, which is the larger population.
- *Widening the JS-shell heuristic and imputing all HTML features.* Cost 5.1 and 10.3 points of recall respectively. A phishing kit is also a thin page behind a few scripts, and `HasPasswordField` / `Bank` / `Pay` are genuinely measured on a kit's login page.

A separate leak survives: `TLDLegitimateProb` is 0.013 for `.io` and 0.0015 for `.app`, so real sites on those TLDs score 0.83–0.95 on the URL string alone. `tests/test_phiusiil.py` pins that behaviour so a future fix has a failing test to flip.

## Why this project exists (2012 → 2023)

The original notebook ([`research/Choi_Final.ipynb`](../research/Choi_Final.ipynb)) trained Random Forest on a random 80/20 split of the [UCI Phishing Websites](https://archive.ics.uci.edu/dataset/327/phishing+websites) set (Mohammad, Thabtah & McCluskey, 2012): 11,055 rows, 30 integer features, **97.69% test accuracy**. That number is real and also inflated. 47% of rows are exact duplicate feature patterns; a random split scores memorisation. Under `StratifiedGroupKFold` on those pattern ids, LightGBM is the honest winner at 0.956 accuracy, and the leak is 1–2 points for tree ensembles.

Five of those 30 features cannot be reproduced in 2026 (Alexa, toolbar PageRank, Google Index, inbound-link counts, 2012 blocklists). `SSLfinal_State` was the dominant signal in 2012; Let's Encrypt made it cheap to fake. A model trained under 2012 HTTPS prevalence drops recall from 0.95 to **0.78** if every site is forced to “have SSL”.

That is why Sphinx is not a 25-feature 2012 Random Forest with placeholders. The served model is PhiUSIIL (2023 URLs, living HTML features, host-grouped split), with a URL-only fallback so missing page content is not scored as a kit.

The **Research findings** tab still surfaces the 2012 leakage, encoding-audit, and obsolescence tables. They are the argument for replacing that model, not the score Sphinx shows you.

## Limitations

- Training pages are **2023 crawls**. Live 2026 HTML (minified homepages, JS shells) is a shifted distribution. Treat the 99.95% grouped-holdout figure as an upper bound; live re-extraction reads **90.6% accuracy / 75.0% recall / 0.9% FPR**.
- Roughly a quarter of PhiUSIIL phishing hosts no longer resolve, so live recall is measured on a shrinking and non-random subset of the phishing class.
- Page fetches do not execute JavaScript. SPA shells are imputed for a handful of link-count features; password / bank / pay markers are left as measured.
- `TLDLegitimateProb` near zero for `.app` / `.io` inflates URL-only scores on real sites that use those TLDs.
- Free-hosting suffixes are a routing hint, not a feature, because they almost perfectly separate the PhiUSIIL classes.
- Grouped holdout is still i.i.d. across hosts, not across time. There is no temporal holdout.
- The served model is **not calibrated**. Holdout Brier is 0.0004 on frozen columns, but live false positives pin at *p* ≈ 1.0 and platform-hosted kits at *p* ≈ 0. Read the gauge as a score, not as a frequency.
- Rate limits and the concurrency cap are process-local. Replicating the API needs a shared store (Redis) to hold across instances.
- Unreachable hosts with a clean origin get no `url_pattern_risk` chip. Absence of a chip is not a legitimate verdict.
- The analyst explains a scan; it does not add detection. It can only be as right as the scan it is reading, and it is a language model — the tool trail under each answer is there to be checked. A visitor Groq key transits HTTPS to this API for that request; treat the operator as trusted for the duration of the chat.

## References

Prasad, A., & Chandra, S. (2023). PhiUSIIL Phishing URL Dataset. UCI Machine Learning Repository. https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset

Mohammad, R. M., Thabtah, F., & McCluskey, L. (2012). An Assessment of Features Related to Phishing Websites Using an Automated Technique. *ICITST*, 492–497.

UCI Machine Learning Repository: Phishing Websites Dataset. https://archive.ics.uci.edu/dataset/327/phishing+websites
