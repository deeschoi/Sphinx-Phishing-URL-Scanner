# Sphinx

Sphinx is a live phishing scanner you run as a website: FastAPI serves the trained model and the React UI from one process. It is not the Python documentation generator of the same name. Paste a URL and it fetches the page (JavaScript is never executed), scores the risk with a trained classifier, and shows which signals decided the verdict.

There is no login on localhost. Scanner, History, Stats, and Research findings work without any API key from the same machine; callers from off-loopback addresses need `SPHINX_API_KEY` or an explicit `SPHINX_ALLOW_ANONYMOUS=1`. The analyst chat is optional: paste your own [Groq](https://console.groq.com/keys) key (`gsk_…`) in the panel when you want an explanation. That key lives in the browser’s `sessionStorage`, is sent only on `POST /api/chat` as `X-Groq-Api-Key`, and is not stored on the server.

This repo began as a DATS 2103 coursework project on the 2012 UCI Phishing Websites table. The original notebook and write-up are unchanged under [`research/`](research/README.md). The scanner Sphinx serves today is trained on a different dataset: [PhiUSIIL](https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset) (Prasad & Chandra, 2023).

How a scan is extracted and guarded, live vs holdout numbers, and how the analyst chat is grounded: **[docs/findings.md](docs/findings.md)**.

## What Sphinx does

A scan is not a blocklist lookup. Sphinx measures the URL string and, when it can, the HTML of the landing page, then scores those 48 features with XGBoost.

1. **Refuse anything that is not a public `http`/`https` page.** Loopback, RFC1918, link-local, CGNAT, multicast, reserved, IPv4-mapped IPv6, and cloud-metadata addresses are dropped before a socket is opened. `user:password@host` is stripped so credentials never reach the target or history. Auto-redirects are off: each hop is re-validated, and the connection is bound to the address that was actually reached (DNS rebinding cannot sneak a private hop through).
2. **Fetch without executing JavaScript.** Timeout defaults to 8s (API max 20s). Bodies are capped at 2 MB. Only a 2xx response counts as a page: a 404, parking page, or WAF interstitial falls back to URL-only scoring instead of being scored as the site's markup. Up to 8 redirects are followed by hand.
3. **Extract the same 48 columns the model was trained on.** 20 from the URL string (length, IP host, HTTPS scheme bit, TLD prior, obfuscation, character ratios) and 28 from HTML (line count, title↔domain match, favicon, forms, password fields, social/copyright markers, image/CSS/JS/self/external refs). Missing HTML is never scored as zeros.
4. **Score with two persisted estimators, then explain.** The 48-feature page model is used when HTML was measured. A URL-only fallback is used when it was not. SHAP bars explain whichever number is on screen.

Two extra rules sit on top of those estimators:

- **Disagreement.** The page model's heaviest weights (`NoOfExternalRef`, `LineOfCode`, `NoOfSelfRef`) drifted between the 2023 crawl and 2026 markup, so a rich modern homepage can pin at *p* ≈ 1.0. When the page model says phishing and the URL string looks clean, the URL score wins — except on free-hosting suffixes (`github.io`, `vercel.app`, `firebaseapp.com`, …), where kits look clean by construction. When the two scores disagree, or differ by 0.2 or more, the Scanner shows both.
- **Withheld live ratings.** DNS failure (`unreachable`) and an offline `--tier A` scan (`not_probed`) do not get a live `risk` band. A failed fetch still does: the URL-only model scores the string. Unreachable hosts may show a `URL pattern:` chip only when the origin, or a kit-shaped path (`*.html`, `*.php`, …), actually looks like phishing. A clean origin is left unchipped — that is not a safety clearance.

The served model is XGBoost on 235,795 PhiUSIIL rows (42.8% phishing), evaluated on a **host-grouped holdout**. Held-out accuracy on the frozen 2023 CSV columns is **99.95%**; that is an upper bound. Live re-extraction on a held-out sample reads **90.6% accuracy / 75% recall / 0.9% FPR**. The UI reports both numbers on every scan. The score is not calibrated: read the gauge as a score, not as a frequency.

### Verdicts

| Verdict | Meaning |
|---|---|
| **phishing** | Score at or above the block threshold. Treat the link as hostile. |
| **suspicious** | Score at or above the warn threshold, below block. |
| **probably safe** | Live page, score below warn but not in the lowest band. |
| **legitimate** | Live page, lowest band. The model found no phishing signals — not a clearance to type a password. |
| **unreachable** | The hostname did not resolve. No live-site rating. |
| **not_probed** | Offline scan (`--tier A`). No live-site rating. Shown in the UI as **not rated**. |

A failed fetch is still one of the four live bands, from the URL-only model, with a note that the page was not measured. The response always names the page that was actually scored: a URL that 302s somewhere else shows the landing page and the hop count.

### What a result contains

- Verdict, probability, and a one-line rationale.
- Top SHAP contributors (log-odds, not percentages), flagged when a feature was not actually measured.
- Scan coverage: reachability, DNS, page download, HTTP status, redirects followed, whether the landing page was HTTPS (scheme only — no certificate is parsed), and how many of the 48 features were used.
- Model reliability: grouped-holdout accuracy / AUROC vs the live-sample figures above.
- Notes (redirects, truncated HTML, JavaScript shells, URL-only fallback, disagreement).
- Optional dual scores when the two estimators disagree.

Every scan is logged so History and Stats work. A logging failure never fails a scan.

## The website

The web app brands itself **Sphinx**. Four sections:

| Section | What it is for |
|---|---|
| **Scanner** | Paste a URL (or use the example chips). Returns the payload above. History's **Scan again** lands here with `?url=` and actually runs. Optional analyst chat splits **Findings** (measured evidence) from **Commentary**. |
| **History** | Recent scans logged by the API, paginated 50 at a time. Credentials, query strings, fragments, and path segments that look like secrets (OTPs, JWTs, hex tokens, a segment after `/reset` / `/token` / …) are stripped before storage. Best-effort: a readable slug that is itself a secret is kept. |
| **Stats** | Verdict mix and daily mean score over 7 / 30 / 90 days, for spotting drift. Unreachable hosts are excluded from the mean. Counts are filtered to the selected window. |
| **Research findings** | Headline tables from the 2012 UCI analysis that started this project (leakage, encoding, decay). Nothing on that page is used to score a URL. |

### Analyst chat

Chat is an explanation layer over a scan that already happened. The verdict and SHAP values are computed by the classifier before a token is generated. Scans never need Groq.

If the server has no `GROQ_API_KEY`, the panel stays visible and asks for a visitor key. A request header wins over the env key. Without either, chat returns 503.

Starter chips: *Why this verdict?*, *What would change your mind?*, *What could this scan have missed?*, *How much should I trust this score?* Answers must use **Findings** then **Commentary**. The UI lists which of six tools an answer actually consulted:

| Tool | Returns |
|---|---|
| `get_signals` | Ranked SHAP list, with whether each feature was measured |
| `get_features` | Raw values for any of the 48 columns |
| `get_extraction_warnings` | What could not be measured, and what was substituted |
| `get_model_card` | Dataset, holdout vs live metrics, thresholds, documented leaks |
| `get_host_history` | Prior verdicts for the same hostname, from scan telemetry |
| `rescan_url` | A fresh scan, through the same SSRF guard, capped per conversation |

The system prompt is server-side. Client messages are filtered to `user` / `assistant` turns. The `scan` object on `/api/chat` is schema-validated (unknown keys dropped); when a `scan_id` resolves in telemetry, stored `url` / `verdict` / `probability` / `model` override the client. Changing the URL starts a new conversation.

## HTTP API

Guarded routes require `X-API-Key` when `SPHINX_API_KEY` is set. When it is unset, they accept anonymous callers only according to `SPHINX_ALLOW_ANONYMOUS` (default: loopback).

| Method | Path | Auth | What it does |
|---|---|---|---|
| `POST` | `/api/scan` | guarded | Fetch, extract, score. Body: `{ "url", "timeout"? }`. |
| `POST` | `/api/chat` | guarded | Ask about a scan already returned. Optional `X-Groq-Api-Key`. |
| `GET` | `/api/scans` | guarded | Paginated history (`limit`, `offset`). |
| `GET` | `/api/stats` | guarded | Verdict mix and daily mean (`days`). |
| `GET` | `/api/agent` | public | Whether chat needs a visitor Groq key. |
| `GET` | `/api/model` | public | Feature lists, holdout + live metrics, thresholds. |
| `GET` | `/api/findings` | public | 2012 research tables for the Findings tab. |
| `GET` | `/api/health` | public | Liveness only. Never touches the model or DB. |
| `GET` | `/api/ready` | public | Readiness: model artifact loaded, DB answers, UI built. |

`/` and client-side routes (`/history`, `/stats`, `/findings`) serve the built React app. OpenAPI is at `/docs`.

## Run Sphinx

Python 3.11+ (3.12 matches the Docker image).

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -e .

# train the served model if artifacts/model.joblib is missing
phishing train

cd web && npm install && npm run build && cd ..

# optional: local Groq fallback so chat works without pasting a key in the UI
cp .env.example .env && $EDITOR .env    # GROQ_API_KEY is optional

uvicorn api.main:app --reload --port 8000
```

Open [http://127.0.0.1:8000](http://127.0.0.1:8000). Opening `web/index.html` as a file will not work: the page talks to `/api/scan` on this server.

While iterating on the UI, run Vite against a live API:

```bash
uvicorn api.main:app --reload --port 8000   # terminal 1
cd web && npm run dev                       # terminal 2, http://127.0.0.1:5173
```

Vite proxies `/api` to port 8000. History and stats stay empty until you scan at least one URL.

Or in a container. The image trains the model and builds the UI during the build, so it is reproducible from source alone and needs no pre-built artifact. It listens on `$PORT` (default 8000) so the same image can run locally or on a host that injects the port:

```bash
docker compose up --build                     # SQLite, data in a named volume
docker compose --profile postgres up --build  # with Postgres alongside
```

Compose publishes `127.0.0.1:8000` on the host, but inside the container the peer is the Docker bridge (not loopback), so compose sets `SPHINX_ALLOW_ANONYMOUS=1`. That is declaring an already-restricted bind, not opening the service to the internet. A raw `docker run -p 8000:8000` without that env var will 401 every scan.

### Public demo (Render)

Sphinx is a long-running app, not a static site: GitHub Pages and Read the Docs cannot run `/api/scan`. A README “try it” link needs the Docker image on a host that keeps `uvicorn` up (Render, Fly, Cloud Run, a VPS). The intended public setup is a **Render Docker web service**, **Free** instance, **ephemeral SQLite**, **no `GROQ_API_KEY`**.

Visitors scan anonymously. Chat is bring-your-own-key so Groq bills them, not the operator. Health check **`/api/ready`** (not `/api/health`). First image build trains the model and can take 30–60+ minutes. Free instances sleep after idle; the next click pays a cold start. History and Stats reset when the instance is replaced unless you attach a disk or Postgres later. One instance, no autoscaling: rate limits are process-local.

Dashboard env (never commit secrets):

| Variable | Public demo |
| --- | --- |
| `GROQ_API_KEY` | omit |
| `SPHINX_API_KEY` | omit (a key baked into the UI is not auth) |
| `SPHINX_ALLOW_ANONYMOUS` | `1` (the demo is intentionally public; rate limits are the control) |
| `SPHINX_SCAN_RATE_PER_MINUTE` | `8` |
| `SPHINX_SCAN_MAX_CONCURRENT` | `2` |
| `SPHINX_CHAT_RATE_PER_MINUTE` | `5` |
| `SPHINX_CHAT_MAX_CONCURRENT` | `1` |
| `SPHINX_TRUST_PROXY_HEADERS` | `1` only because Render is the only ingress |

Once the service has an HTTPS URL, put it here:

**Live demo:** _(add the Render URL when the service is up)_

[`render.yaml`](render.yaml) is the Blueprint for that service. Apply it from the Render dashboard (or create a Docker web service from this repo and copy the table above). Get a Groq key at [console.groq.com/keys](https://console.groq.com/keys).

### CLI

```bash
phishing scan https://example.com
phishing scan --tier A https://example.com   # URL string only, no network fetch
# equivalent: python run.py scan https://example.com
```

`--tier A` is offline. `B` fetches HTML. `full` (default) is what the website uses.

### Configuration

`.env` at the repo root is loaded at startup and never overrides a real environment variable. Copy from `.env.example`.

| Variable | Default | Notes |
| --- | --- | --- |
| `PHISHING_ROOT` | repo root | Base for data, artifacts, reports |
| `PHISHING_PHIUSIIL` | `$PHISHING_ROOT/datasets/PhiUSIIL_Phishing_URL_Dataset.csv` | Served-model training table |
| `PHISHING_DATA` | `$PHISHING_ROOT/research/datasets/Training_Dataset.csv` | 2012 UCI table (research) |
| `PHISHING_ARTIFACTS_DIR` | `$PHISHING_ROOT/artifacts` | Served model |
| `PHISHING_REPORTS_DIR` | `$PHISHING_ROOT/reports` | Analysis output |
| `PHISHING_DATABASE_URL` | `sqlite:///$PHISHING_ROOT/data/scans.db` | Scan telemetry |
| `SPHINX_API_KEY` | unset | Optional `X-API-Key` on scan/chat/history/stats. Not Groq; a key baked into the UI is not auth |
| `SPHINX_ALLOW_ANONYMOUS` | `loopback` | Who may call those routes with no key: `loopback`, `private` (LAN), `1`/`all` (public), `0`/`never` |
| `SPHINX_SCAN_RATE_PER_MINUTE` | `20` | Per-caller scan budget |
| `SPHINX_SCAN_MAX_CONCURRENT` | `4` | Extra scans return 503 |
| `SPHINX_CHAT_RATE_PER_MINUTE` | `30` | Per-caller chat budget |
| `SPHINX_CHAT_MAX_CONCURRENT` | `1` | Extra chat returns 503 |
| `SPHINX_READ_RATE_PER_MINUTE` | `60` | Per-caller budget for `/api/scans` and `/api/stats` |
| `SPHINX_TRUST_PROXY_HEADERS` | `0` | Honour `X-Forwarded-For` only behind a proxy you control; the right-most trusted hop is used |
| `SPHINX_TRUSTED_PROXY_HOPS` | `1` | How many right-most XFF hops belong to proxies you control (clamped 1–8) |
| `GROQ_API_KEY` | unset | Optional operator fallback. Omit on a public host; visitors can still send `X-Groq-Api-Key` |
| `GROQ_MODEL` | `openai/gpt-oss-120b` | Any Groq tool-calling model |
| `GROQ_TIMEOUT` | `45` | Seconds for one Groq round-trip |
| `GROQ_MAX_TOOL_STEPS` | `5` | Tool-loop cap per chat turn |

`POST /api/scan` fetches a caller-chosen URL. Keep the rate limits, bind behind a reverse proxy (compose already binds `127.0.0.1:8000`), leave `SPHINX_ALLOW_ANONYMOUS` at its `loopback` default unless the service is intentionally public, and omit `GROQ_API_KEY` on public hosts.

## Train, test, and research scripts

```bash
pytest -m "not network"     # lock extractors, loaders, ML helpers, API guards
cd web && npm test          # React / Vite unit tests
phishing train              # PhiUSIIL XGBoost → artifacts/model.joblib
phishing evaluate           # 2012 leakage-delta table (research, not the served model)
phishing validate           # 2012 Tier-A drift vs 2026 legitimate URLs
alembic upgrade head        # apply migrations (the API also creates tables on boot)
```

CI also typechecks and builds the UI, lints with Ruff, imports every entry point, and smoke-tests the Docker image (including that private targets return 403). Numbered scripts under `analysis/` train the served model (`06`) and run the live re-extraction eval (`07`; see [docs/findings.md](docs/findings.md)). The 2012 UCI scripts and notebooks live under [`research/`](research/README.md).

## Repo map

```text
src/phishing/                         library: scan, train, extract, analyst
  scanner.py                          live scan → verdict, SHAP, coverage
  netguard.py                         SSRF guards
  agent.py                            Groq analyst (Findings / Commentary)
  fit.py                              train the PhiUSIIL model
  db.py                               scan telemetry, redaction
  features/                           PhiUSIIL extractors (plus 2012 extractors for research)
api/                                  FastAPI: scan, chat, history, stats, UI
  security.py                         API key, anonymous-access, rate limits
web/                                  React + Vite UI
migrations/                           alembic revisions for the scans table
datasets/                             PhiUSIIL training CSVs (2023)
analysis/
  06_train_final.py                   served-model train (Docker build)
  07_live_sample_eval.py              live re-extraction eval
docs/findings.md                      how a scan works, live numbers, analyst chat
tests/                                pytest; network tests marked skippable
research/                             2012 coursework — not used at scan time
  Choi_Final.ipynb                    original submission (untouched)
  Choi_Final_Write_Up.pdf             original write-up
  Phishing Websites Features.docx     UCI feature dictionary
  notebooks/                          stages 1–3 narrative
  analysis/                           01–05: leakage, calibration, SHAP, decay
  datasets/Training_Dataset.csv       UCI 2012 table
artifacts/model.joblib                fitted model (gitignored; run train)
reports/                              CSV / JSON / figures, including the model card
Dockerfile                            trains at build, serves uvicorn on $PORT
render.yaml                           public demo Blueprint
```
