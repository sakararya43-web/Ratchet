#!/bin/sh
# Real Linux process smoke; credentials come from the locally generated file.
set -eu
cd "$(dirname "$0")/.."
set -a
. ./.local/core.env
set +a
export RATCHET_DATABASE_DSN="postgres://ratchet_runtime:${RATCHET_RUNTIME_PASSWORD}@${RATCHET_DATABASE_HOST:-127.0.0.1}:${RATCHET_DATABASE_PORT:-${RATCHET_POSTGRES_PORT:-55434}}/ratchet?sslmode=disable"
export RATCHET_MIGRATION_DSN="postgres://ratchet_migrator:${RATCHET_MIGRATOR_PASSWORD}@${RATCHET_DATABASE_HOST:-127.0.0.1}:${RATCHET_DATABASE_PORT:-${RATCHET_POSTGRES_PORT:-55434}}/ratchet?sslmode=disable"
binary=./.local/ratchetd-core-smoke
go build -o "$binary" ./cmd/ratchetd
"$binary" migrate
tenant="smoke_$(cat /proc/sys/kernel/random/uuid)"
command=$(cat /proc/sys/kernel/random/uuid)
actor=$(cat /proc/sys/kernel/random/uuid)
digest=$(sha256sum PRD.md | cut -d ' ' -f 1)
record() {
  "$binary" record-core-evidence --tenant "$tenant" --stream core:smoke \
    --command-id "$command" --actor-reference "$actor" --evidence-sha256 "$digest"
}
first=$(record)
retry=$(record)
case "$first" in *'"duplicate":false'*) ;; *) exit 1 ;; esac
case "$retry" in *'"duplicate":true'*) ;; *) exit 1 ;; esac
loaded=$("$binary" load-stream --tenant "$tenant" --stream core:smoke)
case "$loaded" in *"$digest"*) ;; *) exit 1 ;; esac
verified=$("$binary" verify-chain --tenant "$tenant")
case "$verified" in *'"events_verified":1,'*) ;; *) exit 1 ;; esac
"$binary" serve --listen 127.0.0.1:58080 > .local/linux-health.log 2>&1 &
core_pid=$!
trap 'kill "$core_pid" 2>/dev/null || true; wait "$core_pid" 2>/dev/null || true' EXIT INT TERM
attempt=0
while :; do
  kill -0 "$core_pid"
  status=$(curl --silent --output .local/storage-readiness.json --write-out '%{http_code}' http://127.0.0.1:58080/readyz/storage || true)
  test "$status" = 200 && break
  attempt=$((attempt + 1))
  test "$attempt" -lt 30
  sleep 0.5
done
test "$(curl --silent --output /dev/null --write-out '%{http_code}' http://127.0.0.1:58080/livez)" = 200
test "$(curl --silent --output .local/decision-readiness.json --write-out '%{http_code}' http://127.0.0.1:58080/readyz)" = 503
printf '%s\n' 'PASS: real append, idempotent retry, new-process read, chain verification, liveness and honest readiness.'
