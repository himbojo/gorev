#!/usr/bin/env sh
# start.sh — Bootstrap gorev with a randomly generated Redis password.
#
# Redis is used as an ephemeral OCSP response cache only (no persistent data).
# A fresh strong password is generated each time the stack starts, so there is
# nothing to rotate or store long-term. If you need a fixed password (e.g. for
# external monitoring), set REDIS_PASSWORD in your shell before running.
#
# Usage:
#   ./scripts/start.sh                  # production compose
#   ./scripts/start.sh --test           # test compose (docker-compose.test.yml)

set -eu

COMPOSE_FILE="docker-compose.yml"
if [ "${1:-}" = "--test" ]; then
  COMPOSE_FILE="docker-compose.test.yml"
  shift
fi

# Generate a 32-byte (256-bit) random password if not already set.
if [ -z "${REDIS_PASSWORD:-}" ]; then
  # openssl is available in virtually every environment; fall back to /dev/urandom.
  if command -v openssl >/dev/null 2>&1; then
    REDIS_PASSWORD="$(openssl rand -base64 32 | tr -d '/+=' | head -c 44)"
  else
    REDIS_PASSWORD="$(head -c 33 /dev/urandom | base64 | tr -d '/+=' | head -c 44)"
  fi
  echo "Generated ephemeral Redis password (not stored, valid for this session only)."
fi

export REDIS_PASSWORD

exec docker compose -f "${COMPOSE_FILE}" up "$@"
