#!/usr/bin/env bash
# topic-bootstrap.sh — create the 8 Thinking Engine topics for one user.
#
# SPEC-0167 §Kafka Topology. Refuses to run without --ctx-hash; all
# topics are prefixed m3c.<ctx_hash>.  RF=1 in Phase 1 (dev only).

set -euo pipefail

CTX_HASH=""
BROKER="${BROKER:-localhost:9092}"
PARTITIONS="${PARTITIONS:-3}"
REPLICATION="${REPLICATION:-1}"

usage() {
  cat <<EOF
Usage: $0 --ctx-hash <16-hex-chars> [--broker host:port] [--partitions N] [--replication N]

Creates the 8 Thinking Engine topics (SPEC-0167 §Kafka Topology)
prefixed m3c.<ctx_hash>.*. RF=1 is the Phase 1 default.
EOF
  exit 2
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --ctx-hash)    CTX_HASH="${2:-}"; shift 2 ;;
    --broker)      BROKER="${2:-}"; shift 2 ;;
    --partitions)  PARTITIONS="${2:-}"; shift 2 ;;
    --replication) REPLICATION="${2:-}"; shift 2 ;;
    -h|--help)     usage ;;
    *) echo "unknown flag: $1" >&2; usage ;;
  esac
done

if [[ -z "${CTX_HASH}" ]]; then
  echo "ERROR: --ctx-hash is REQUIRED (SPEC-0167 §Isolation Model)" >&2
  usage
fi

if ! [[ "${CTX_HASH}" =~ ^[0-9a-f]{16}$ ]]; then
  echo "ERROR: --ctx-hash must be exactly 16 hex chars, got: ${CTX_HASH}" >&2
  exit 2
fi

TOPICS=(
  "m3c.${CTX_HASH}.thoughts.raw"
  "m3c.${CTX_HASH}.reflections.generated"
  "m3c.${CTX_HASH}.insights.generated"
  "m3c.${CTX_HASH}.artifacts.created"
  "m3c.${CTX_HASH}.process.commands"
  "m3c.${CTX_HASH}.process.events"
  "m3c.${CTX_HASH}.compilation.requests"
  "m3c.${CTX_HASH}.context.snapshots"
)

if ! command -v kafka-topics >/dev/null 2>&1; then
  echo "kafka-topics not in PATH — invoke via docker:" >&2
  echo "  docker compose -f docker-compose.yml exec broker kafka-topics --help" >&2
  echo "Or set PATH to your Confluent CLI install." >&2
  exit 1
fi

for t in "${TOPICS[@]}"; do
  echo "creating ${t} (p=${PARTITIONS} rf=${REPLICATION})"
  kafka-topics --bootstrap-server "${BROKER}" \
    --create --if-not-exists \
    --topic "${t}" \
    --partitions "${PARTITIONS}" \
    --replication-factor "${REPLICATION}"
done

echo "done: ${#TOPICS[@]} topics ensured for ctx=${CTX_HASH}"
