# The served model is gitignored, so the image trains it during the build. That
# keeps the image self-contained and reproducible from source alone: the model
# always matches the code and dataset in the same commit. The React UI is built
# in a separate Node stage and copied into the runtime image as static files.
FROM python:3.12-slim@sha256:a0f57064cbdcd6285fa45f51237ab0b35ea8ebaed06a1f5973e89e19dfb86704 AS builder

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
COPY scripts/ ./scripts/
RUN pip install . --no-deps

# Produces artifacts/model.joblib and reports/06_model_card.json.
RUN python scripts/06_train_final.py

# pip is only needed to build the venv. A current pip vendors msgpack 1.1.2,
# urllib3 2.7.0, and setuptools 70.3.0, which the image scan rejects. The
# runtime process never installs packages.
RUN rm -rf /opt/venv/lib/python3.12/site-packages/pip \
           /opt/venv/lib/python3.12/site-packages/pip-*.dist-info \
    && rm -f /opt/venv/bin/pip /opt/venv/bin/pip3 /opt/venv/bin/pip3.12


FROM node:22-alpine@sha256:fe4f6d74e20370acb04ad889077d14d0f64a9c8ea6a42bc60cddf1e844699914 AS frontend

WORKDIR /web

COPY web/package.json web/package-lock.json ./
RUN npm ci

COPY web/ ./
RUN npm run build


FROM python:3.12-slim@sha256:a0f57064cbdcd6285fa45f51237ab0b35ea8ebaed06a1f5973e89e19dfb86704 AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH=/opt/venv/bin:$PATH \
    PHISHING_ROOT=/app

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends libgomp1 gosu \
    && rm -rf /var/lib/apt/lists/* \
    && rm -rf /usr/local/lib/python3.12/site-packages/pip \
              /usr/local/lib/python3.12/site-packages/pip-*.dist-info \
              /usr/local/lib/python3.12/ensurepip \
    && rm -f /usr/local/bin/pip /usr/local/bin/pip3 /usr/local/bin/pip3.12 \
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
# Python, not curl: the runtime image does not ship a second HTTP client.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python -c "import os,urllib.request; urllib.request.urlopen('http://127.0.0.1:'+os.environ.get('PORT','8000')+'/api/ready', timeout=4)"

CMD ["sh", "-c", "exec uvicorn api.main:app --host 0.0.0.0 --port ${PORT:-8000}"]
