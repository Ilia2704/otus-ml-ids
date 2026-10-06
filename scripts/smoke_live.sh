#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
smoke_project="ids-ml-lab-smoke-$$"
deadline_seconds="${SMOKE_TIMEOUT_SECONDS:-120}"

cd "$repo_root"
export COMPOSE_PROFILES=live

cleanup() {
  docker compose -p "$smoke_project" down -v --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

docker compose -p "$smoke_project" build generator
docker compose -p "$smoke_project" up --no-build -d

deadline=$((SECONDS + deadline_seconds))
while ((SECONDS < deadline)); do
  matched="$(curl -fsS http://127.0.0.1:9103/metrics 2>/dev/null | awk '/^ids_evaluator_matched_events_total / {print $2}')" || true
  targets="$(curl -fsS http://127.0.0.1:9090/api/v1/targets 2>/dev/null | grep -o '"health":"up"' | wc -l | tr -d ' ')" || true
  generator_id="$(docker compose -p "$smoke_project" ps -q generator)"
  restart_count=""
  if [[ -n "$generator_id" ]]; then
    restart_count="$(docker inspect --format '{{.RestartCount}}' "$generator_id")"
  fi

  if [[ -n "$matched" && "$targets" -ge 3 && "$restart_count" == "0" ]] \
    && docker compose -p "$smoke_project" exec -T generator test -s /runtime/truth/events.jsonl \
    && docker compose -p "$smoke_project" exec -T zeek sh -c 'test -s /logs/dns.log || test -s /logs/http.log' \
    && docker compose -p "$smoke_project" exec -T detector test -s /runtime/predictions/events.jsonl \
    && awk -v value="$matched" 'BEGIN {exit !(value > 0)}'; then
    printf 'Smoke test passed: matched=%s prometheus_targets_up=%s generator_restarts=%s\n' \
      "$matched" "$targets" "$restart_count"
    exit 0
  fi
  sleep 2
done

docker compose -p "$smoke_project" ps
docker compose -p "$smoke_project" logs --no-color --tail=120
printf 'Smoke test failed after %s seconds\n' "$deadline_seconds" >&2
exit 1
