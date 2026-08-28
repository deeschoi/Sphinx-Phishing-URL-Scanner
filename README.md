# Sphinx

Sphinx is a live phishing scanner you run as a website: FastAPI serves the trained model and the React UI from one process. It is not the Python documentation generator of the same name. Paste a URL and it fetches the page (JavaScript is never executed), scores the risk with a trained classifier, and shows which signals decided the verdict.

There is no login on localhost. Scanner, History, Stats, and Research findings work without any API key from the same machine; callers from off-loopback addresses need `SPHINX_API_KEY` or an explicit `SPHINX_ALLOW_ANONYMOUS=1`. The analyst chat is optional: paste your own [Groq](https://console.groq.com/keys) key (`gsk_…`) in the panel when you want an explanation. That key lives in the browser’s `sessionStorage`, is sent only on `POST /api/chat` as `X-Groq-Api-Key`, and is not stored on the server.

This repo began as a DATS 2103 coursework project on the 2012 UCI Phishing Websites table. The original notebook and write-up are unchanged under [`research/`](research/README.md). The scanner Sphinx serves today is trained on [PhiUSIIL](https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset) (Prasad & Chandra, 2023).

How a scan is extracted, what the numbers mean, and live vs holdout results: **[docs/](docs/README.md)**.

## What Sphinx can do

A scan is not a blocklist lookup. Sphinx measures the URL string and, when it can, the HTML of the landing page, then scores those 48 features with XGBoost. Private and metadata addresses are refused before a socket is opened. The page model is used when HTML was measured; a URL-only fallback is used when it was not. SHAP bars explain whichever number is on screen.

The web app has four sections:

| Section | What it is for |
|---|---|
| **Scanner** | Paste a URL (or use the example chips). Returns a verdict, probability, SHAP contributors, and scan coverage. History's **Scan again** lands here with `?url=` and actually runs. Optional analyst chat splits **Findings** (measured evidence) from **Commentary**. |
| **History** | Recent scans logged by the API, paginated 50 at a time. Credentials and token-shaped path segments are stripped before storage. |
| **Stats** | Verdict mix and daily mean score over 7 / 30 / 90 days, for spotting drift. Unreachable hosts are excluded from the mean. |
| **Research findings** | Headline tables from the 2012 UCI analysis that started this project (leakage, encoding, decay). Nothing on that page is used to score a URL. |

Chat is an explanation layer over a scan that already happened. Scans never need Groq. If the server has no `GROQ_API_KEY`, the panel asks for a visitor key.

There is also a CLI (`phishing scan`) and an HTTP API (`POST /api/scan`, OpenAPI at `/docs`). Route table and payload fields: [docs/parameters.md](docs/parameters.md).

## Public demo (Render)

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

### **Live demo:** https://sphinx-tnna.onrender.com

If scans 401 with “reachable from outside localhost”, the service is missing `SPHINX_ALLOW_ANONYMOUS=1` in the Render dashboard (Environment). Adding it restarts the running instance; you do not need a rebuild. Render also injects `RENDER=true`, which the API treats as the same public-demo opt-in when that variable is unset.

[`render.yaml`](render.yaml) is the Blueprint for that service. Apply it from the Render dashboard (or create a Docker web service from this repo and copy the table above). Get a Groq key at [console.groq.com/keys](https://console.groq.com/keys).

## Run locally

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

### CLI

```bash
phishing scan https://example.com
phishing scan --tier A https://example.com   # URL string only, no network fetch
# equivalent: python run.py scan https://example.com
```

`--tier A` is offline. `B` fetches HTML. `full` (default) is what the website uses.

### Configuration

`.env` at the repo root is loaded at startup and never overrides a real environment variable. Copy from [`.env.example`](.env.example) for the full list (paths, rate limits, Groq knobs).

| Variable | Default | Notes |
| --- | --- | --- |
| `SPHINX_API_KEY` | unset | Optional `X-API-Key` on scan/chat/history/stats. A key baked into the UI is not auth |
| `SPHINX_ALLOW_ANONYMOUS` | `loopback` (Render: `1` if unset) | Who may call those routes with no key: `loopback`, `private`, `1`/`all`, `0`/`never` |
| `GROQ_API_KEY` | unset | Optional operator fallback. Omit on a public host; visitors can still send `X-Groq-Api-Key` |
| `PHISHING_DATABASE_URL` | SQLite under `data/` | Scan telemetry. Point at Postgres for compose `--profile postgres` |
| `SPHINX_TRUST_PROXY_HEADERS` | `0` | Honour `X-Forwarded-For` only behind a proxy you control |

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

CI also typechecks and builds the UI, lints with Ruff, imports every entry point, and smoke-tests the Docker image (including that private targets return 403). Numbered scripts under `scripts/` train the served model (`06`) and run the live re-extraction eval (`07`; see [docs/](docs/README.md)). The 2012 UCI scripts and notebooks live under [`research/`](research/README.md).

## Repo map

Docker, Render, Alembic, and Python packaging all look at the repo root, which is why those files sit next to the README. Coursework, notebooks, and the 2012 table live under `research/`. Local editor and scan artifacts (`.claude/`, `CLAUDE-SECURITY-*`) are gitignored.

```text
src/phishing/                         library: scan, train, extract, analyst
api/                                  FastAPI: scan, chat, history, stats, UI
web/                                  React + Vite UI
migrations/                           alembic revisions for the scans table
datasets/                             PhiUSIIL training CSVs (2023)
scripts/                              served-model train (06) and live eval (07)
docs/                                 methodology, parameters, findings
tests/                                pytest; network tests marked skippable
research/                             2012 coursework — not used at scan time
artifacts/model.joblib                fitted model (gitignored; run train)
reports/                              CSV / JSON / figures, including the model card
Dockerfile                            trains at build, serves uvicorn on $PORT
render.yaml                           public demo Blueprint
```
