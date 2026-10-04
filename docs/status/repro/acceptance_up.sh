#!/bin/bash
# Acceptance run (task 7.3), step 1: build two clean instances from `git archive HEAD` in a work directory and start them.
#
#   bash docs/status/repro/acceptance_up.sh WORKDIR        (run from the repository root; WORKDIR must not exist)
#
# Creates WORKDIR/{dev,prod}  (git archive copies, so nothing from the working tree leaks in),
#         WORKDIR/tls         (self-signed certificate valid for localhost and 127.0.0.1),
#         WORKDIR/relay       (fake TLS SMTP relay: messages, login log),
# builds each .env from .env.example exactly like the README, runs `alembic upgrade head` and the guided
# `python -m app.cli setup` through a pseudo-terminal (hidden password prompts), then starts
#   dev   : ENVIRONMENT=development, http://127.0.0.1:18100, MAIL_BACKEND=file, BALANCE_TOTP_REQUIRED=true,
#           started as in the README (`uvicorn app.main:app --port 18100`)
#   prod  : ENVIRONMENT=production, https://localhost:18443 with real TLS (uvicorn --ssl-keyfile, flags of scripts/run.sh),
#           MAIL_BACKEND=smtp to the fake relay on 127.0.0.1:18587 (STARTTLS, AUTH); the relay's certificate is
#           trusted through SSL_CERT_FILE (OpenSSL trust-store variable): no application code is bypassed.
# Writes WORKDIR/acceptance.env (ports, test passwords) for acceptance_v2.py and the other scripts.
set -eu
W="$(mkdir -p "$1" && cd "$1" && pwd)"
ROOT="$(pwd)"
PY="${PY:-/home/claude/venv/bin/python}"
export PATH="$(dirname "$PY"):$PATH"
REPRO="$ROOT/docs/status/repro"
HEAD_PW='Acc-Head-Password-2026!'
MAIL_USER='svc-coffee@lrz.de'
MAIL_PW='ACC-MAIL-PASSWORD-9xQ4mLz7'
SECRET_KEY="$($PY -c 'import secrets; print(secrets.token_urlsafe(48))')"

mkdir -p "$W/dev" "$W/prod" "$W/tls" "$W/relay"
git archive HEAD | tar -x -C "$W/dev"
git archive HEAD | tar -x -C "$W/prod"
git rev-parse --short HEAD > "$W/commit.txt"

# --- certificate and relay ------------------------------------------------------------------------------------
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$W/tls/key.pem" -out "$W/tls/cert.pem" -days 3 -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,digitalSignature,keyEncipherment" -addext "extendedKeyUsage=serverAuth" 2>/dev/null
nohup "$PY" "$REPRO/fake_relay.py" --port 18587 --cert "$W/tls/cert.pem" --key "$W/tls/key.pem" --dir "$W/relay" \
  --user "$MAIL_USER" --password "$MAIL_PW" > "$W/relay.log" 2>&1 &
echo $! > "$W/relay.pid"
for _ in $(seq 1 50); do [ -e "$W/relay/ready" ] && break; sleep 0.2; done
[ -e "$W/relay/ready" ] || { echo "relay did not start"; cat "$W/relay.log"; exit 1; }

# --- dev instance -----------------------------------------------------------------------------------------------
cd "$W/dev"
"$PY" "$REPRO/mkenv.py" ENVIRONMENT=development PUBLIC_BASE_URL=http://127.0.0.1:18100 DATABASE_URL=sqlite:///./data/coffee.db \
  MAIL_BACKEND=file MAIL_FILE_DIR=./mails "MAIL_FROM=Coffee Ledger <coffee@tum.de>" SECRETS_DIR=./secrets \
  SECRET_KEY="dev-acceptance-key-$($PY -c 'import secrets; print(secrets.token_hex(24))')" BALANCE_TOTP_REQUIRED=true
chmod 600 .env
mkdir -p data mails secrets && chmod 700 secrets
alembic upgrade head > "$W/dev_alembic.txt" 2>&1
"$PY" "$REPRO/pty_run.py" --secret "$HEAD_PW" --secret "$MAIL_PW" --script "[[\"head administrator now\\\\? \\\\[Y/n\\\\] \",\"y\"],[\"Username: \",\"head\"],[\"Password: \",\"$HEAD_PW\"],[\"Repeat password: \",\"$HEAD_PW\"],[\"Store the mail login now\\\\? \\\\[Y/n\\\\] \",\"y\"],[\"SMTP username \\\\(input hidden\\\\): \",\"$MAIL_USER\"],[\"SMTP password \\\\(input hidden\\\\): \",\"$MAIL_PW\"],[\"Repeat the SMTP password: \",\"$MAIL_PW\"],[\"Set the price per shot now\\\\? \\\\[Y/n\\\\] \",\"y\"],[\"e.g. 0.50: \",\"0.50\"],[\"Send a test mail now\\\\? \\\\[y/N\\\\] \",\"y\"],[\"Send to \\\\(address\\\\): \",\"setup@tum.de\"]]" \
  -- "$PY" -m app.cli setup > "$W/dev_setup.txt" 2>&1 || { cat "$W/dev_setup.txt"; exit 1; }
nohup "$PY" -m uvicorn app.main:app --port 18100 > "$W/dev_server.log" 2>&1 &
echo $! > "$W/dev.pid"

# --- production instance ---------------------------------------------------------------------------------------
cd "$W/prod"
"$PY" "$REPRO/mkenv.py" ENVIRONMENT=production PUBLIC_BASE_URL=https://localhost:18443 DATABASE_URL="sqlite:///$W/prod/data/coffee.db" \
  SECRET_KEY="$SECRET_KEY" SMTP_HOST=127.0.0.1 SMTP_PORT=18587 SMTP_SECURITY=starttls MAIL_BACKEND=smtp \
  "MAIL_FROM=Coffee Ledger <coffee@tum.de>" SECRETS_DIR="$W/prod/secrets" OPERATOR_CONTACT="Operator, op@tum.de"
chmod 600 .env
mkdir -p data backups && mkdir -p secrets && chmod 700 secrets
export SSL_CERT_FILE="$W/tls/cert.pem" BACKUP_DIR="$W/prod/backups"
alembic upgrade head > "$W/prod_alembic.txt" 2>&1
"$PY" "$REPRO/pty_run.py" --secret "$HEAD_PW" --secret "$MAIL_PW" --script "[[\"head administrator now\\\\? \\\\[Y/n\\\\] \",\"y\"],[\"Username: \",\"head\"],[\"Password: \",\"$HEAD_PW\"],[\"Repeat password: \",\"$HEAD_PW\"],[\"Store the mail login now\\\\? \\\\[Y/n\\\\] \",\"y\"],[\"SMTP username \\\\(input hidden\\\\): \",\"$MAIL_USER\"],[\"SMTP password \\\\(input hidden\\\\): \",\"$MAIL_PW\"],[\"Repeat the SMTP password: \",\"$MAIL_PW\"],[\"Set the price per shot now\\\\? \\\\[Y/n\\\\] \",\"y\"],[\"e.g. 0.50: \",\"0.40\"],[\"Send a test mail now\\\\? \\\\[y/N\\\\] \",\"y\"],[\"Send to \\\\(address\\\\): \",\"setup@tum.de\"]]" \
  -- "$PY" -m app.cli setup > "$W/prod_setup.txt" 2>&1 || { cat "$W/prod_setup.txt"; exit 1; }
nohup "$PY" -m uvicorn app.main:app --host 127.0.0.1 --port 18443 --workers 1 --proxy-headers --forwarded-allow-ips 127.0.0.1 \
  --no-server-header --no-access-log --log-level info --ssl-keyfile "$W/tls/key.pem" --ssl-certfile "$W/tls/cert.pem" \
  > "$W/prod_server.log" 2>&1 &
echo $! > "$W/prod.pid"

for _ in $(seq 1 60); do
  curl -fsS "http://127.0.0.1:18100/readyz" > /dev/null 2>&1 && curl -fsS --cacert "$W/tls/cert.pem" "https://localhost:18443/readyz" > /dev/null 2>&1 && break
  sleep 0.3
done
cat > "$W/acceptance.env" <<EOF
W=$W
DEV_BASE=http://127.0.0.1:18100
PROD_BASE=https://localhost:18443
CERT=$W/tls/cert.pem
HEAD_PW=$HEAD_PW
MAIL_USER=$MAIL_USER
MAIL_PW=$MAIL_PW
SECRET_KEY=$SECRET_KEY
EOF
echo "dev  : $(curl -sS http://127.0.0.1:18100/readyz)"
echo "prod : $(curl -sS --cacert "$W/tls/cert.pem" https://localhost:18443/readyz)"
echo "up: $W (commit $(cat "$W/commit.txt"))"
