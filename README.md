# Sphinx

Sphinx is a live phishing scanner you run as a website: FastAPI serves the trained model and the React UI from one process. It is not the Python documentation generator of the same name. Paste a URL and it fetches the page (JavaScript is never executed), scores the risk with a trained classifier, and shows which signals decided the verdict.

There is no login. Scanner, History, Stats, and Research findings work without any API key. The analyst chat is optional: paste your own [Groq](https://console.groq.com/keys) key (`gsk_…`) in the panel when you want an explanation. That key lives in the browser’s `sessionStorage`, is sent only on `POST /api/chat` as `X-Groq-Api-Key`, and is not stored on the server.

The web app brands itself **Sphinx**. Four sections:

| Section | What it is for |
|---|---|
| **Scanner** | Paste a URL. Sphinx returns a verdict, probability, SHAP contributors, and scan coverage. When the two estimators disagree, both scores are shown. Unreachable hosts get no live rating. Optional analyst chat splits **Findings** (measured evidence) from **Commentary**. |
| **History** | Recent scans logged by the API. Credentials, query strings, and token-shaped path segments are stripped before storage. |
| **Stats** | Verdict mix and daily mean score, for spotting drift. Unreachable hosts are excluded from the mean. |
| **Research findings** | Headline tables from the 2012 UCI analysis that started this project (leakage, encoding, decay). Nothing on that page is used to score a URL. |

This repo began as a DATS 2103 coursework project on the 2012 UCI Phishing Websites table. The original submission is unchanged: [`research/Choi_Final.ipynb`](research/Choi_Final.ipynb). The scanner Sphinx serves today is trained on a different dataset.

How a scan is extracted and guarded, live vs holdout numbers, and how the analyst chat is grounded: **[docs/findings.md](docs/findings.md)**.

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

### Public demo (Render)

Sphinx is a long-running app, not a static site: GitHub Pages and Read the Docs cannot run `/api/scan`. A README “try it” link needs the Docker image on a host that keeps `uvicorn` up (Render, Fly, Cloud Run, a VPS). The intended public setup is a **Render Docker web service**, **Free** instance, **ephemeral SQLite**, **no `GROQ_API_KEY`**.

Visitors scan anonymously. Chat is bring-your-own-key so Groq bills them, not the operator. Health check **`/api/ready`** (not `/api/health`). First image build trains the model and can take 30–60+ minutes. Free instances sleep after idle; the next click pays a cold start. History and Stats reset when the instance is replaced unless you attach a disk or Postgres later. One instance, no autoscaling: rate limits are process-local.

Dashboard env (never commit secrets):

| Variable | Public demo |
| --- | --- |
| `GROQ_API_KEY` | omit |
| `SPHINX_API_KEY` | omit (a key baked into the UI is not auth) |
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
| `SPHINX_SCAN_RATE_PER_MINUTE` | `20` | Per-caller scan budget |
| `SPHINX_SCAN_MAX_CONCURRENT` | `4` | Extra scans return 503 |
| `SPHINX_CHAT_RATE_PER_MINUTE` | `30` | Per-caller chat budget |
| `SPHINX_CHAT_MAX_CONCURRENT` | `1` | Extra chat returns 503 |
| `SPHINX_TRUST_PROXY_HEADERS` | `0` | Honour `X-Forwarded-For` only behind a proxy you control |
| `GROQ_API_KEY` | unset | Optional operator fallback. Omit on a public host; visitors can still send `X-Groq-Api-Key` |
| `GROQ_MODEL` | `openai/gpt-oss-120b` | Any Groq tool-calling model |

`POST /api/scan` fetches a caller-chosen URL. Keep the rate limits, bind behind a reverse proxy (compose already binds `127.0.0.1:8000`), and omit `GROQ_API_KEY` on public hosts.

## Train, test, and research scripts

```bash
pytest -m "not network"     # lock extractors, loaders, and ML helpers
phishing train              # PhiUSIIL XGBoost → artifacts/model.joblib
phishing evaluate           # 2012 leakage-delta table (research, not the served model)
phishing validate           # 2012 Tier-A drift vs 2026 legitimate URLs
alembic upgrade head        # apply migrations (the API also creates tables on boot)
```

Numbered scripts under `analysis/` train the served model (`06`) and run the live re-extraction eval (`07`; see [docs/findings.md](docs/findings.md)). The 2012 UCI scripts and notebooks live under [`research/`](research/README.md).

## Repo map

```text
src/phishing/                         library: scan, train, extract, analyst
  scanner.py                          live scan → verdict, SHAP, coverage
  netguard.py                         SSRF guards
  agent.py                            Groq analyst (Findings / Commentary)
  fit.py                              train the PhiUSIIL model
  features/                           PhiUSIIL extractors (plus 2012 extractors for research)
api/                                  FastAPI: scan, chat, history, stats, UI
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
  notebooks/                          stages 1–3 narrative
  analysis/                           01–05: leakage, calibration, SHAP, decay
  datasets/Training_Dataset.csv       UCI 2012 table
artifacts/model.joblib                fitted model (gitignored; run train)
reports/                              CSV / JSON / figures, including the model card
Dockerfile                            trains at build, serves uvicorn on $PORT
render.yaml                           public demo Blueprint
```
