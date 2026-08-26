# Parameters

Numbers and names the scanner actually uses. How they are extracted: [methodology.md](methodology.md). How well they hold up live: [findings.md](findings.md). Environment variables for running Sphinx: [README](../README.md#configuration).

## Fetch limits

| Limit | Value |
|---|---|
| Timeout | 8s default; API accepts 2–20s |
| Body cap | 2 MB (truncated HTML is noted, not scored as a full page) |
| Redirects | 8, followed by hand; each hop re-validated |
| Schemes | `http` / `https` only |

`--tier A` is URL-string only (no network). `B` fetches HTML. `full` (default) is what the website uses.

## Verdicts

Bands are derived from the warn/block cuts the model ships with. `probably safe` is `warn / 2`, so all four live bands stay reachable.

| Verdict | Meaning |
|---|---|
| **phishing** | Score at or above the block threshold. Treat the link as hostile. |
| **suspicious** | Score at or above the warn threshold, below block. |
| **probably safe** | Live page, score below warn but not in the lowest band. |
| **legitimate** | Live page, lowest band. The model found no phishing signals — not a clearance to type a password. |
| **unreachable** | The hostname did not resolve. No live-site rating. |
| **not_probed** | Offline scan (`--tier A`). No live-site rating. Shown in the UI as **not rated**. |

A failed fetch is still one of the four live bands, from the URL-only model, with a note that the page was not measured.

Served cuts (from `reports/06_model_card.json`):

| Cut | Threshold |
|---|---|
| warn | 0.205 |
| block | 0.9 |

The score is not calibrated. Read the gauge as a score, not as a frequency.

## Features

XGBoost on 235,795 PhiUSIIL rows (42.8% phishing), 48 columns. Evaluation is a **host-grouped holdout** — no hostname is shared between train and test. The label is recoded so **1 = phishing**.

**URL string (20)** — no network:

`URLLength`, `DomainLength`, `IsDomainIP`, `TLDLength`, `NoOfSubDomain`, `HasObfuscation`, `NoOfObfuscatedChar`, `ObfuscationRatio`, `NoOfLettersInURL`, `LetterRatioInURL`, `NoOfDegitsInURL`, `DegitRatioInURL`, `NoOfEqualsInURL`, `NoOfQMarkInURL`, `NoOfAmpersandInURL`, `NoOfOtherSpecialCharsInURL`, `SpacialCharRatioInURL`, `IsHTTPS`, `CharContinuationRate`, `TLDLegitimateProb`

`IsHTTPS` is the scheme bit, not a certificate check.

**HTML (28)** — measured only when a 2xx page was fetched:

`LineOfCode`, `LargestLineLength`, `HasTitle`, `DomainTitleMatchScore`, `URLTitleMatchScore`, `HasFavicon`, `Robots`, `IsResponsive`, `NoOfURLRedirect`, `NoOfSelfRedirect`, `HasDescription`, `NoOfPopup`, `NoOfiFrame`, `HasExternalFormSubmit`, `HasSocialNet`, `HasSubmitButton`, `HasHiddenFields`, `HasPasswordField`, `Bank`, `Pay`, `Crypto`, `HasCopyrightInfo`, `NoOfImage`, `NoOfCSS`, `NoOfJS`, `NoOfSelfRef`, `NoOfEmptyRef`, `NoOfExternalRef`

Dropped as identifiers or label leaks: `FILENAME`, `URL`, `Domain`, `TLD`, `Title`, `URLSimilarityIndex`, `URLCharProb`.

Scan-time substitutions (not training columns):

- SPA shells impute `NoOfExternalRef`, `NoOfSelfRef`, `NoOfEmptyRef`, `LineOfCode`.
- Minified lines above 20,000 characters are treated as unmeasured and filled with the legitimate-class median.

Free-hosting suffixes and kit-shaped paths are routing hints, not features. See [methodology.md](methodology.md).

## What a result contains

- Verdict, probability, and a one-line rationale.
- Top SHAP contributors (log-odds, not percentages), flagged when a feature was not actually measured.
- Scan coverage: reachability, DNS, page download, HTTP status, redirects followed, whether the landing page was HTTPS (scheme only — no certificate is parsed), and how many of the 48 features were used.
- Model reliability: grouped-holdout accuracy / AUROC vs the live-sample figures in [findings.md](findings.md).
- Notes (redirects, truncated HTML, JavaScript shells, URL-only fallback, disagreement).
- Optional dual scores when the two estimators disagree.

## Analyst tools

| Tool | Returns |
|---|---|
| `get_signals` | Ranked SHAP list, with whether each feature was measured |
| `get_features` | Raw values for any of the 48 columns |
| `get_extraction_warnings` | What could not be measured, and what was substituted |
| `get_model_card` | Dataset, holdout vs live metrics, thresholds, documented leaks |
| `get_host_history` | Prior verdicts for the same hostname, from scan telemetry |
| `rescan_url` | A fresh scan, through the same SSRF guard, capped per conversation |

## HTTP API

Guarded routes require `X-API-Key` when `SPHINX_API_KEY` is set. When it is unset, they accept anonymous callers only according to `SPHINX_ALLOW_ANONYMOUS` (default: loopback).

| Method | Path | Auth | Body / query |
|---|---|---|---|
| `POST` | `/api/scan` | guarded | `{ "url", "timeout"? }` |
| `POST` | `/api/chat` | guarded | Scan already returned. Optional `X-Groq-Api-Key`. |
| `GET` | `/api/scans` | guarded | `limit` (1–200, default 50), `offset` |
| `GET` | `/api/stats` | guarded | `days` (7 / 30 / 90) |
| `GET` | `/api/agent` | public | Whether chat needs a visitor Groq key |
| `GET` | `/api/model` | public | Feature lists, holdout + live metrics, thresholds |
| `GET` | `/api/findings` | public | 2012 research tables for the Findings tab |
| `GET` | `/api/health` | public | Liveness only. Never touches the model or DB |
| `GET` | `/api/ready` | public | Readiness: model artifact loaded, DB answers, UI built |

`/` and client-side routes (`/history`, `/stats`, `/findings`) serve the built React app. OpenAPI is at `/docs`.
