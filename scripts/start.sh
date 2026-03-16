#!/usr/bin/env sh
# start.sh — Bootstrap gorev with a randomly generated Redis password.
#
# Redis is used as an ephemeral OCSP response cache only (no persistent data).
# A fresh strong password is generated each time the stack starts, so there is
# nothing to rotate or store long-term. If you need a fixed password (e.g. for
# external monitoring), set REDIS_PASSWORD in your shell before running.
#
# Usage:
#   ./scripts/start.sh [up|down|ps|...]   # production compose
#   ./scripts/start.sh --test [up|...]     # test compose

set -eu

COMPOSE_FILE="docker-compose.yml"
if [ "${1:-}" = "--test" ]; then
  COMPOSE_FILE="docker-compose.test.yml"
  shift
fi

# The first remaining argument is the docker-compose command (default: up)
CMD="${1:-up}"

# Only generate/export a password if we are starting services or running a command.
# For 'down', 'ps', 'logs', etc., we still export it to silence warnings in the .yml,
# but 'start.sh' is the preferred entrypoint for all compose actions now.
if [ -z "${REDIS_PASSWORD:-}" ]; then
  if command -v openssl >/dev/null 2>&1; then
    REDIS_PASSWORD="$(openssl rand -base64 32 | tr -d '/+=' | head -c 44)"
  else
    REDIS_PASSWORD="$(head -c 33 /dev/urandom | base64 | tr -d '/+=' | head -c 44)"
  fi
  # Only announce generation for commands that actually use it.
  case "$CMD" in
    up|run|start|recreate)
      echo "Generated ephemeral Redis password (not stored, valid for this session only)."
      ;;
  esac
fi

export REDIS_PASSWORD

echo "Running docker compose -f ${COMPOSE_FILE} $@..."
exec docker compose -f "${COMPOSE_FILE}" "$@"
