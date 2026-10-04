# Coffee ledger: single-process FastAPI app (SQLite). Build: docker build -t coffee-ledger .
# Same interpreter minor as the one the test suite runs on (3.13). For a reproducible build pin the base image by
# digest at build time (README, "Reproducible build"): FROM python:3.13-slim@sha256:<digest>
FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    DATABASE_URL=sqlite:////data/coffee.db \
    SECRETS_DIR=/secrets

WORKDIR /app

# Dependencies first (cached layer): the fully pinned, hashed runtime lock file (direct and transitive packages,
# every artifact checked by SHA-256; pip refuses anything not in the file). No dev/test packages.
# requirements.txt lists the direct dependencies for development; regenerate the lock with the command at the top
# of requirements.lock whenever it changes (README, "Reproducible build").
COPY requirements.lock ./
RUN pip install --require-hashes --no-deps -r requirements.lock \
 && useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin app \
 && mkdir /data /backups \
 && chown app:app /data /backups \
 && mkdir -m 0700 /secrets \
 && chown app:app /secrets

COPY alembic.ini ./
COPY app ./app
COPY migrations ./migrations
COPY static ./static
COPY templates ./templates
COPY scripts ./scripts

# /secrets holds the encrypted mail login (python -m app.cli setup-mail). It is created here, mode 0700 and
# owned by the app user, so that a named volume mounted on it inherits both on first use. The image itself
# contains no mail login; the compose file mounts the `secrets` volume here and nowhere else.
USER app
VOLUME ["/data"]
EXPOSE 8000

# /healthz only proves the process is up; /readyz additionally checks database + migrations.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=4).status == 200 else 1)"]

# Exactly one worker: rate limits, the SQLite write lock and the in-process mail status assume a single process.
CMD ["sh", "scripts/run.sh"]
