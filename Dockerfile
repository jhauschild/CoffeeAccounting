# Coffee ledger: single-process FastAPI app (SQLite). Build: docker build -t coffee-ledger .
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    DATABASE_URL=sqlite:////data/coffee.db

WORKDIR /app

# Dependencies first (cached layer); runtime requirements only, no dev/test packages.
COPY requirements.txt ./
RUN pip install -r requirements.txt \
 && useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin app \
 && mkdir /data /backups \
 && chown app:app /data /backups

COPY alembic.ini ./
COPY app ./app
COPY migrations ./migrations
COPY static ./static
COPY templates ./templates
COPY scripts ./scripts

USER app
VOLUME ["/data"]
EXPOSE 8000

# /healthz only proves the process is up; /readyz additionally checks database + migrations.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=4).status == 200 else 1)"]

# Exactly one worker: rate limits, the SQLite write lock and the access-gate cookie assume a single process.
CMD ["sh", "scripts/run.sh"]
