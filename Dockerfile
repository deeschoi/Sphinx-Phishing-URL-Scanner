# The served model is gitignored, so the image trains it during the build. That
# keeps the image self-contained and reproducible from source alone: the model
# always matches the code and dataset in the same commit. The React UI is built
# in a separate Node stage and copied into the runtime image as static files.
FROM python:3.12-slim AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    VIRTUAL_ENV=/opt/venv \
    PATH=/opt/venv/bin:$PATH \
    PHISHING_ROOT=/build

WORKDIR /build

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential libgomp1 \
    && rm -rf /var/lib/apt/lists/*

RUN python -m venv "$VIRTUAL_ENV"

COPY requirements.txt ./
RUN pip install --upgrade pip && pip install -r requirements.txt

COPY pyproject.toml README.md ./
COPY datasets/ ./datasets/
COPY src/ ./src/
COPY analysis/ ./analysis/
RUN pip install . --no-deps

# Produces artifacts/model.joblib and reports/06_model_card.json.
RUN python analysis/06_train_final.py


FROM node:22-alpine AS frontend

WORKDIR /web

COPY web/package.json web/package-lock.json ./
RUN npm ci

COPY web/ ./
RUN npm run build


FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH=/opt/venv/bin:$PATH \
    PHISHING_ROOT=/app

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends libgomp1 curl gosu \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 scanner

COPY --from=builder /opt/venv /opt/venv

# The CSVs are only needed to train, and training already happened in the
# builder stage. Copying them into the runtime image added ~100 MB of data
# nothing at runtime reads.
COPY api/ ./api/
COPY reports/ ./reports/
COPY --from=builder /build/artifacts/ ./artifacts/
COPY --from=builder /build/reports/06_model_card.json ./reports/06_model_card.json
COPY --from=frontend /web/dist ./web/dist
COPY docker-entrypoint.sh /docker-entrypoint.sh

# Stay root in the image metadata so the entrypoint can chown a Compose
# named volume at /app/data (those mounts are root:root). It then execs
# uvicorn as scanner. docker run --user 10001 still works: the entrypoint
# skips chown and execs as the given user.
RUN mkdir -p /app/data \
    && chown -R scanner:scanner /app \
    && chmod 755 /docker-entrypoint.sh

ENTRYPOINT ["/docker-entrypoint.sh"]

# Local/compose default. Render injects PORT at runtime (often 10000).
ENV PORT=8000
EXPOSE 8000

# Readiness, not liveness: /api/health answers ok even with no model artifact
# and no database, so an unhealthy instance kept receiving traffic and 503ing
# every scan. /api/ready loads the artifact and pings the database.
# Shell form so $PORT expands; JSON exec form would keep 8000 forever.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS http://127.0.0.1:${PORT:-8000}/api/ready || exit 1

CMD ["sh", "-c", "exec uvicorn api.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
