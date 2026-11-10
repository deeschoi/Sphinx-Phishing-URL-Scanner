# Sphinx

<p align="center">
  <img src="docs/images/sphinx.jpeg" alt="Sphinx" width="600">
</p>

<p align="center">
  <a href="https://sphinx-tnna.onrender.com">Try Sphinx!</a>
</p>

Sphinx is a live phishing scanner you run as a website: FastAPI serves the trained model and the React UI from one process. It is not the Python documentation generator of the same name. Paste a URL and it fetches the page (JavaScript is never executed), scores the risk with a trained classifier, and shows which signals decided the verdict.

No login on localhost. Scanner, History, Stats, and Research work without any API key from the same machine; callers from off-loopback addresses need `SPHINX_API_KEY` or an explicit `SPHINX_ALLOW_ANONYMOUS=1`. Paste your own [Groq](https://console.groq.com/keys) key (`gsk_…`) in the panel when you want an explanation. That key lives in the browser’s `sessionStorage`, is sent only on `POST /api/chat` as `X-Groq-Api-Key`, and is not stored on the server.

This repo began as a DATS 2103 coursework project on the 2012 UCI Phishing Websites table. The original notebook and write-up are unchanged under [`research/`](research/README.md). The scanner Sphinx serves today is trained on [PhiUSIIL](https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset) (Prasad & Chandra, 2023).

How a scan is extracted, what the numbers mean, and live vs holdout results: **[docs/](docs/README.md)**.

## What Sphinx can do

A scan is not a blocklist lookup. Sphinx measures the URL string and, when it can, the HTML of the landing page, then scores those 48 features with XGBoost. Private and metadata addresses are refused before a socket is opened. The page model is used when HTML was measured; a URL-only fallback is used when it was not. SHAP bars explain whichever number is on screen.

The web app has five sections:

| Section | What it is for |
|---|---|
| **Scanner** | Paste a URL (or use the example chips). Returns a verdict, probability, SHAP contributors, and scan coverage. History's **Open** hydrates the stored payload via `?scan=`; **Scan again** lands here with `?url=` and actually runs. Optional analyst chat splits **Findings** (measured evidence) from **Commentary**. |
| **Batch** | Paste a list of URLs. Each is queued as its own job; export the finished rows as CSV or JSON. |
| **History** | Recent scans logged by the API, paginated 50 at a time. Credentials and token-shaped path segments are stripped before storage. |
| **Stats** | Verdict mix, URL-only vs page share, disagreement-rule rate, and daily mean score over 7 / 30 / 90 days. Unreachable hosts are excluded from the mean. |
| **Research findings** | Headline tables from the 2012 UCI analysis that started this project (leakage, encoding, decay). Nothing on that page is used to score a URL. |

Chat is an explanation layer over a scan that already happened. Scans never need Groq. If the server has no `GROQ_API_KEY`, the panel asks for a visitor key.

There is also a CLI (`phishing scan`) and an HTTP API (`POST /api/scan`, `POST /api/scan/jobs`, `POST /api/scan/batch`; OpenAPI at `/docs` when `SPHINX_ENABLE_DOCS=1`). Route table and payload fields: [docs/parameters.md](docs/parameters.md).

## Public demo (Vercel)

The hosted demo can also run as one Python function on Vercel. The UI is on the CDN. Neon Postgres holds scan history, Upstash Redis holds the shared rate limit, and Upstash QStash runs scan jobs. Render stays up as the rollback host. The “Try Sphinx” link above stays on Render until `python scripts/parity_check.py https://sphinx-tnna.onrender.com <vercel-url>` exits 0.

Git deploys are off. [`.github/workflows/deploy-vercel.yml`](.github/workflows/deploy-vercel.yml) trains the model, migrates the production Neon branch, builds, smoke-tests a URL that is not on the production domain, and promotes only when those checks pass. `vercel rollback` returns to the previous deploy. The live link can point back at Render at any time.

Preview and Production use different Neon branches, so a preview never writes production telemetry. Preview deployments have Deployment Protection turned on (`scripts/ensure_preview_protection.sh`) so they are not an anonymous open proxy. Production deployment URLs stay reachable: QStash and the smoke test call the staged URL before promote.

`vercel.json` schedules maintenance once a day at 08:00 UTC (`0 8 * * *`). A Hobby account rejects a cron that runs more often, which is what stopped `vercel deploy`. The daily run is the idle backstop: it times out jobs whose worker disappeared and deletes job rows older than 24 hours. The same timeout also runs when a scan is queued and when a stale job's status is read, so the queue cap and the UI do not wait for that call. `/api/internal/maintenance` still requires `CRON_SECRET`.

Dashboard env for Production (never commit secrets, and never set `GROQ_API_KEY` or `SPHINX_API_KEY`):

| Variable | Production |
| --- | --- |
| `SPHINX_ALLOW_ANONYMOUS` | `1` (explicit; `VERCEL=1` does not open the API) |
| `SPHINX_SCAN_RATE_PER_MINUTE` | `8` |
| `SPHINX_SCAN_MAX_CONCURRENT` | `2` |
| `SPHINX_JOB_WORKERS` | `2` |
| `SPHINX_CHAT_RATE_PER_MINUTE` | `5` |
| `SPHINX_CHAT_MAX_CONCURRENT` | `1` |
| `SPHINX_TRUST_PROXY_HEADERS` | `1` |
| `SPHINX_TRUSTED_PROXY_HOPS` | `1` |
| `SPHINX_RATE_LIMIT_BACKEND` | `redis` |
| `REDIS_URL` | Upstash `rediss://` URL |
| `SPHINX_JOB_BACKEND` | `qstash` |
| `QSTASH_TOKEN` | Upstash token |
| `QSTASH_CURRENT_SIGNING_KEY` | current signing key |
| `QSTASH_NEXT_SIGNING_KEY` | next signing key |
| `CRON_SECRET` | bearer token Vercel Cron sends |
| `PHISHING_DATABASE_URL` | Neon pooled string for this environment’s branch |
| `SPHINX_LEASE_TTL_SECONDS` | `60` (same as the function `maxDuration`) |
| `OMP_NUM_THREADS` | `1` (`app.py` sets this when it is unset) |

The function is trained and installed from [`requirements-serve.txt`](requirements-serve.txt) (`xgboost-cpu`, no shap). Docker and Render keep using [`requirements.txt`](requirements.txt).

## Public demo (Render)

Sphinx also runs as a long-running process. The rollback host is a **Render Docker web service**, **Free** instance, **ephemeral SQLite**, **no `GROQ_API_KEY`**. A VPS, Fly, or Cloud Run can run the same image.

Visitors scan anonymously. Chat is bring-your-own-key so Groq bills them, not the operator. Health check **`/api/ready`** (not `/api/health`). First image build trains the model and can take 30+ minutes. Free instances sleep after idle; the next click pays a cold start. One instance, no autoscaling: rate limits are process-local.

History, Stats, and the analyst's host-history tool read from the database. On Render Free the default SQLite file lives on the instance disk, so **every replace or spin-down wipes telemetry**. Attach a [Render disk](https://render.com/docs/disks) mounted at `/app/data` (the image writes `data/scans.db` there) or set `PHISHING_DATABASE_URL` to Postgres — compose already supports that via `docker compose --profile postgres up`. Without one of those, the History tab on a public demo is empty after the next deploy.

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
pip install -e ".[dev]"

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
phishing scan --json https://example.com     # full payload
phishing scan --tier A https://example.com   # URL string only, no network fetch
# equivalent: python run.py scan https://example.com
```

`--tier A` is offline. `B` fetches HTML. `full` (default) is what the website uses. The default CLI output is a one-screen summary; `--json` is the previous dump.

### Configuration

`.env` at the repo root is loaded at startup and never overrides a real environment variable. Copy from [`.env.example`](.env.example) for the full list (paths, rate limits, Groq knobs).

| Variable | Default | Notes |
| --- | --- | --- |
| `SPHINX_API_KEY` | unset | Optional `X-API-Key` on scan/chat/history/stats. A key baked into the UI is not auth |
| `SPHINX_ALLOW_ANONYMOUS` | `loopback` (Render: `1` if unset) | Who may call those routes with no key: `loopback`, `private`, `1`/`all`, `0`/`never` |
| `GROQ_API_KEY` | unset | Optional operator fallback. Omit on a public host; visitors can still send `X-Groq-Api-Key` |
| `PHISHING_DATABASE_URL` | SQLite under `data/` | Scan telemetry. Point at Postgres for compose `--profile postgres`, or attach a Render disk at `/app/data` so History survives replaces |
| `SPHINX_JOB_WORKERS` | same as `SPHINX_SCAN_MAX_CONCURRENT` | In-flight async scan jobs. With QStash this is the flow-control parallelism |
| `SPHINX_JOB_QUEUE_MAX` | `32` | Jobs waiting behind those workers. Past this, enqueue returns 503 |
| `SPHINX_JOB_BACKEND` | `thread` | `qstash` publishes durable jobs. Local, Docker, and Render stay on `thread` |
| `SPHINX_RATE_LIMIT_BACKEND` | `memory` | `redis` shares the budget across function instances |
| `REDIS_URL` | unset | Required when the rate-limit backend is `redis` |
| `SPHINX_LEASE_TTL_SECONDS` | `60` | How long a crashed instance may hold a Redis scan slot |
| `SPHINX_BATCH_MAX_URLS` | `25` | Cap on `POST /api/scan/batch`, clamped to `SPHINX_SCAN_RATE_PER_MINUTE` (a batch of N spends N) |
| `SPHINX_ENABLE_DOCS` | unset | Set to `1` to publish `/docs`. Off by default |
| `SPHINX_TRUST_PROXY_HEADERS` | `0` | Honour `X-Forwarded-For` only behind a proxy you control |
| `QSTASH_TOKEN` | unset | Publish token for `SPHINX_JOB_BACKEND=qstash` |
| `QSTASH_CURRENT_SIGNING_KEY` | unset | Verifies `POST /api/internal/scan-jobs/run` |
| `QSTASH_NEXT_SIGNING_KEY` | unset | Accepted during a signing-key rotation |
| `CRON_SECRET` | unset | Bearer token for `GET` or `POST /api/internal/maintenance` |

When `SPHINX_ALLOW_ANONYMOUS` is the public opt-in (`1` / `all`) and no API key is set, history and stats are limited to the calling client. A configured API key is one tenant and sees every row. Scan ids in the API are random, not the database counter.

`POST /api/scan` fetches a caller-chosen URL. Keep the rate limits, bind behind a reverse proxy (compose already binds `127.0.0.1:8000`), leave `SPHINX_ALLOW_ANONYMOUS` at its `loopback` default unless the service is intentionally public, and omit `GROQ_API_KEY` on public hosts.

## Train, test, and research scripts

```bash
pytest -m "not network"     # lock extractors, loaders, ML helpers, API guards
cd web && npm test          # React / Vite unit tests
phishing train              # PhiUSIIL XGBoost → artifacts/model.joblib
phishing evaluate           # 2012 leakage-delta table (research, not the served model)
phishing validate           # 2012 Tier-A drift vs 2026 legitimate URLs
alembic upgrade head        # apply migrations (local and Docker still create tables on boot; Vercel does not)
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
render.yaml                           rollback demo Blueprint
requirements-serve.txt                Vercel function deps (xgboost-cpu, no shap)
app.py                                Vercel entrypoint; re-exports api.main:app
vercel.json                           CDN, headers, cron, function limits
```
