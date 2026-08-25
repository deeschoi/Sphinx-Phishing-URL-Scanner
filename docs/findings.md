# How Sphinx scores a URL

This is the project write-up: what a live scan actually measures, how well that holds up off the 2023 CSV, and how the optional analyst chat is grounded. For install, CLI, and config, see the [README](../README.md).

## What a scan does

Sphinx only fetches public `http`/`https` URLs. Because the target is chosen by whoever is typing, `src/phishing/netguard.py` closes three separate holes:

- **The literal target.** Anything that is not a globally routable address is refused — loopback, RFC1918, link-local, CGNAT (`100.64.0.0/10`, which is neither `is_private` nor `is_global`), multicast, reserved, IPv4-mapped IPv6, and the cloud metadata IPs by name and by address.
- **Redirects.** Auto-redirects are off. Each hop is re-validated before it is followed, because an open redirect lets the *target* choose hop *n+1*.
- **DNS rebinding.** The connection is made through an adapter that checks the address the socket actually reached, so a short-TTL name that answers public for the check and loopback for the connection is dropped mid-handshake.

`user:password@host` is stripped before the request is made, so credentials never reach the target or the scan history. A response has to be 2xx to count as a page: a 404, a parking page, or a WAF interstitial falls back to URL-only scoring instead of being scored as the site's own markup.

The served estimator is **XGBoost** trained on [PhiUSIIL](https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset) (Prasad & Chandra, 2023): 235,795 rows, 48 features, 42.8% phishing. Evaluation is a **host-grouped holdout** — no hostname is shared between train and test. The label is recoded so **1 = phishing**.

Features split into two extractors that share one definition with training:

- **20 URL-string features** — length, IP host, HTTPS scheme bit, TLD prior, obfuscation, special-character ratios. `www` is not counted as a subdomain, extra special character, or path leak (every legitimate PhiUSIIL row has `www` and none has a path).
- **28 HTML features** — line count, title↔domain match, favicon, forms, password fields, social/copyright markers, image/CSS/JS/self/external ref counts. These replace the 2012 reputation columns (Alexa, PageRank, inbound links) that no longer exist.

Identifiers and label leaks (`URL`, `Domain`, `Title`, `URLSimilarityIndex`, `URLCharProb`, …) are dropped.

Two estimators are persisted:

1. The **48-feature page model**, used when HTML was actually measured.
2. A **URL-only fallback**, used when HTML was not measured. Missing HTML is never scored as zeros. A failed fetch still gets a live risk band from this estimator. DNS failure (`unreachable`) and an offline `--tier A` scan (`not_probed`) do not: those verdicts withhold `risk`.

A third path is a **disagreement rule**, not a third model. The page model's top weights (`NoOfExternalRef` 57%, `LineOfCode` 10%, `NoOfSelfRef` 9%) are the columns that moved between the 2023 crawl and 2026 markup, so a rich modern homepage can pin at *p* ≈ 1.0. When the page model says kit and the URL string looks clean, the URL score wins. That rule is gated: kits on shared-hosting suffixes (`github.io`, `vercel.app`, `firebaseapp.com`, …) keep the page score, because those URLs look clean by construction. When the two scores disagree, or differ by 0.2 or more, the Scanner shows both rather than hiding the unused estimator.

Unreachable hosts do not get a live risk band. The UI may show a `url_pattern_risk` chip (`URL pattern: phishing` / `suspicious`) only when the origin string, or a kit-shaped path (`*.html`, `*.php`, …), actually looks like phishing. A clean origin is left unchipped: that is not a safety clearance, and the chip never reuses the live-verdict colours. Kit-shaped paths are a routing hint like the free-hosting suffixes, not a model feature — counting any path in the URL-only model made `/en-us` look like a kit. The origin-only model ignores the path, so a dead host with `/wetj/famt.html` is flagged from that suffix rather than from the host alone.

The response reports the page that was actually scored. A URL that 302s somewhere else shows the landing page and the hop count, because that redirect is often the whole attack.

Every scan is logged so History and Stats work. A logging failure never fails a scan.

## How well it actually scores live URLs

The model card reports **99.95% accuracy** on the host-grouped holdout. That number is measured on the **frozen 2023 CSV columns**. It is an upper bound, not a deployment estimate.

`analysis/07_live_sample_eval.py` re-extracts every feature over the network, which is what Sphinx actually does:

```bash
PYTHONPATH=src python analysis/07_live_sample_eval.py --seed 7 --n-per-class 120
```

Held-out sample, seed 7, 120 unique hosts per class (tuning was done on seed 42):

| | Baseline | After disagreement + URL-pattern chip |
|---|---|---|
| Accuracy | 0.878 | **0.906** |
| Recall | 0.781 | 0.750 |
| False-positive rate | 0.068 | **0.009** |
| Precision | 0.862 | **0.980** |

Of 240 hosts, 59 no longer resolve (56 of them phishing). That churn, not the model, is the main limit on live recall. Of those 59 unrated hosts, the eval dump still records 54 as phishing-shaped on the URL string. The remaining handful used to receive a `legitimate` string chip; current Sphinx withholds that chip, because a clean-looking origin is not evidence that a dead host is safe.

**What was measured and rejected.** Three plausible changes made things worse and were backed out; the reasoning is in the code comments so they are not retried:

- *A free-hosting-platform feature.* These suffixes cover 22,478 phishing rows and **1** legitimate row in PhiUSIIL. Trained as an input it became the #2 feature and scored real docs sites (`docs.github.io`, `nextjs.vercel.app`) at *p* ≈ 0.999. Kept only as the routing hint above.
- *Counting subdomain depth against the platform suffix.* Cost 4.7 points of recall: it also lowers every kit parked on those same suffixes, which is the larger population.
- *Widening the JS-shell heuristic and imputing all HTML features.* Cost 5.1 and 10.3 points of recall respectively. A phishing kit is also a thin page behind a few scripts, and `HasPasswordField` / `Bank` / `Pay` are genuinely measured on a kit's login page.

A separate leak survives: `TLDLegitimateProb` is 0.013 for `.io` and 0.0015 for `.app`, so real sites on those TLDs score 0.83–0.95 on the URL string alone. `tests/test_phiusiil.py` pins that behaviour so a future fix has a failing test to flip.

## Ask about this scan

Every result carries a chat panel. It is an explanation layer over a scan that already happened — the verdict, the probability, and the SHAP attributions are computed by the classifier before a single token is generated, and the model is told in as many words that its own impression of a URL string is not evidence. Changing the URL starts a new conversation, so evidence from one scan cannot leak into the next.

Chat is opt-in. Scans never need Groq. If the server has no `GROQ_API_KEY`, the panel stays visible and asks for a visitor key from [console.groq.com/keys](https://console.groq.com/keys). Save stores it in `sessionStorage` (gone when the tab closes). `POST /api/chat` sends it as `X-Groq-Api-Key`; `/api/scan` never accepts that header. Locally you can keep `GROQ_API_KEY` in `.env` instead: `/api/agent` then reports `requires_user_key: false` and the chips work without pasting. A request header wins over the env key. Without either, chat returns 503.

Starter chips on the panel: *Why this verdict?*, *What would change your mind?*, *What could this scan have missed?*, *How much should I trust this score?*

Answers are required to use two headings, in that order:

| Section | What belongs there |
|---|---|
| **Findings** | Measured evidence only, as bullets. Optional bold groups such as **Toward phishing** / **Toward legitimate**. Each bullet names the feature, its measured value, and the SHAP direction (log-odds, not a percentage of the verdict). |
| **Commentary** | One or two short paragraphs that synthesize those findings for this verdict, including limits and what would change the read. No new facts that are not in Findings or a tool result. |

The UI (`web/src/analystReply.ts`) parses those headings into two panels. If the model skips the headings, the parser still splits evidence bullets from surrounding prose so the layout does not collapse into a wall of markdown.

Grounding is enforced by the tool surface rather than by asking nicely. `src/phishing/agent.py` exposes six tools over the real payload:

| Tool | Returns |
|---|---|
| `get_signals` | The full ranked SHAP list, with whether each feature was measured |
| `get_features` | Raw extracted values for any of the 48 columns |
| `get_extraction_warnings` | What could not be measured, and what was substituted |
| `get_model_card` | Dataset, holdout vs live metrics, thresholds, documented leaks |
| `get_host_history` | Prior verdicts for the same hostname, from scan telemetry |
| `rescan_url` | A fresh scan, through the same SSRF guard, capped per conversation |

The UI lists which of these an answer actually consulted, so a claim can be traced to evidence rather than taken on faith.

The system prompt is server-side and non-negotiable. Client messages are filtered to `user` and `assistant` turns before they are sent upstream, so a caller cannot smuggle in a system message or a fabricated tool result. The briefing the analyst sees also refuses to treat a missing `url_pattern_risk` as a clearance. Four things the prompt insists on:

1. **Never clear a site.** A `legitimate` verdict means the model found no phishing signals — not that it is safe to type a password into. On the live sample this model misses about a quarter of the phishing pages it can reach.
2. **Say which accuracy number applies.** ~99.9% is the frozen-column holdout; ~90.6% accuracy / 75% recall is live re-extraction, which is what a real scan gets.
3. **Lead with withheld / URL-only scans.** A URL-string score is not a judgment of a live site.
4. **Volunteer the known blind spots** — the plain-HTTP prior, the `.io`/`.app` TLD prior, and phishing kits on trusted platforms — when they bear on the answer.

Asked about `http://neverssl.com`, which the scanner flags at *p* ≈ 1.0, it names `IsHTTPS` and its +10.9 log-odds contribution under Findings, then says in Commentary that the flag is more likely a false positive than evidence, because the training table has essentially no legitimate HTTP rows. That is the intended behaviour: the interesting answer is usually why a score should not be trusted.

Transport is the OpenAI-compatible Groq endpoint over `requests` — no new dependency. Chat is opt-in BYOK: the browser sends `X-Groq-Api-Key` from `sessionStorage`, or the server uses `GROQ_API_KEY` if the operator set one. With neither, `/api/chat` returns 503. Scans never need a Groq key. Chat uses its own limiter (`SPHINX_CHAT_RATE_PER_MINUTE` / `SPHINX_CHAT_MAX_CONCURRENT`), not the scan budget.

## Why this project exists (2012 → 2023)

The original notebook trained Random Forest on a random 80/20 split of the [UCI Phishing Websites](https://archive.ics.uci.edu/dataset/327/phishing+websites) set (Mohammad, Thabtah & McCluskey, 2012): 11,055 rows, 30 integer features, **97.69% test accuracy**. That number is real and also inflated. 47% of rows are exact duplicate feature patterns; a random split scores memorisation. Under `StratifiedGroupKFold` on those pattern ids, LightGBM is the honest winner at 0.956 accuracy, and the leak is 1–2 points for tree ensembles.

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
