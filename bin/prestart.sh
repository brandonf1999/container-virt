#!/usr/bin/env bash
set -euo pipefail

APP_ROOT="/opt/virt-app"
cd "$APP_ROOT"

ALEMBIC_INI="${APP_ROOT}/alembic.ini"
PYTHON_BIN="${PYTHON_BIN:-python}"

if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
  if command -v python3 >/dev/null 2>&1; then
    PYTHON_BIN="python3"
  else
    echo "[prestart] No python interpreter found" >&2
    exit 1
  fi
fi

if [ -z "${DATABASE_URL:-}" ]; then
  echo "[prestart] DATABASE_URL not set; skipping migrations" >&2
else
  echo "[prestart] Applying database migrations..."
  if PYTHONPATH="${APP_ROOT}/app${PYTHONPATH:+:${PYTHONPATH}}" \
    "$PYTHON_BIN" -m alembic -c "${ALEMBIC_INI}" upgrade head; then
    echo "[prestart] Migration step complete"

    echo "[prestart] Running bootstrap seed..."
    if PYTHONPATH="${APP_ROOT}/app${PYTHONPATH:+:${PYTHONPATH}}" \
      "$PYTHON_BIN" -m app.db.bootstrap; then
      echo "[prestart] Bootstrap step complete"
    else
      echo "[prestart] Bootstrap failed; continuing startup without seed" >&2
    fi
  else
    echo "[prestart] Database migrations failed; continuing startup without DB updates" >&2
  fi
fi

exec "$@"
