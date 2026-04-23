#!/usr/bin/env bash
# Start the m3c Thinking Engine against the ER1-DUMP2DATALAKE cluster.
# SPEC-0167 Phase 1 dogfood — Kamir's ctx, single-user, local dev only.
#
# Prereqs (must be true before running):
#   - er1-thought-bridge running (ADR-0002), topic populated
#   - ./build/thinking-engine exists and was built with -tags thinking_kafka
#     (build via:  CGO_ENABLED=0 go build -tags thinking_kafka \
#                     -o ./build/thinking-engine ./cmd/thinking-engine)
#   - OPENAI_API_KEY (or OLLAMA_URL) exported in this shell
#   - GOOGLE_APPLICATION_CREDENTIALS_FIRESTORE set so aims-core's
#     register_engine.py can reach Firestore

set -euo pipefail

CTX="${CTX:-107677460544181387647___mft}"
CTX_HASH="${CTX_HASH:-c241d2aad2268287}"
CTX_HASH_UPPER=$(echo "$CTX_HASH" | tr 'a-z' 'A-Z')
ENGINE_PORT="${ENGINE_PORT:-7140}"
KAFKA_URL="${KAFKA_URL:-localhost:9094}"
AIMS_CORE_DIR="${AIMS_CORE_DIR:-/Users/kamir/GITHUB.active/my-ai-X/aims-core}"
ENGINE_BIN="${ENGINE_BIN:-./build/thinking-engine}"

# ---------------------------------------------------------------- pre-flight
[[ -x "$ENGINE_BIN" ]] || { echo "FATAL: $ENGINE_BIN not found or not executable"; exit 1; }
[[ -n "${OPENAI_API_KEY:-}" || -n "${OLLAMA_URL:-}" ]] || {
    echo "FATAL: export OPENAI_API_KEY or OLLAMA_URL before running"; exit 1;
}

# --------------------------------------------------------------- HMAC secret
HMAC_VAR="THINKING_ENGINE_HMAC_KEY_${CTX_HASH_UPPER}"
if [[ -z "${!HMAC_VAR:-}" ]]; then
    echo "Generating HMAC secret for ${HMAC_VAR}..."
    export "${HMAC_VAR}=$(openssl rand -hex 32)"
    echo "  -> set in this shell only. Persist via:"
    echo "     export ${HMAC_VAR}='${!HMAC_VAR}'"
fi
export THINKING_ENGINE_SECRET="${!HMAC_VAR}"

# -------------------------------------------------------- register in Firestore
if [[ "${SKIP_REGISTER:-0}" != "1" ]]; then
    echo "Registering engine in Firestore (_thinking_engines/${CTX_HASH})..."
    ( cd "$AIMS_CORE_DIR/flask" && \
      python -m modules.thinking_bridge.register_engine \
          --ctx "$CTX" \
          --engine-url "http://localhost:${ENGINE_PORT}/v1" \
          --secret-ref "env:${HMAC_VAR}" \
          --cluster-id "er1-dump-cluster" \
          --ctx-hash "$CTX_HASH" \
          ${FORCE_REGISTER:+--force} ) || {
        echo "  register_engine failed (already registered? pass FORCE_REGISTER=1 to overwrite)"
    }
fi

# ----------------------------------------------------- verify topic reachable
echo "Probing dump Kafka at $KAFKA_URL..."
docker exec er1-kafka kafka-topics --bootstrap-server localhost:9092 \
    --describe --topic "m3c.${CTX_HASH}.thoughts.raw" | head -3 || {
    echo "FATAL: topic m3c.${CTX_HASH}.thoughts.raw not reachable on dump cluster"; exit 2;
}

# ----------------------------------------------------------------- run engine
echo ""
echo "Starting thinking-engine:"
echo "  ctx_hash  = $CTX_HASH"
echo "  kafka     = $KAFKA_URL"
echo "  listen    = :$ENGINE_PORT"
echo "  er1_sink  = ${ENABLE_ER1_SINK:-0} (keep 0 until maindrec POST /memory/<ctx>/artifacts ships)"
echo ""

export ENABLE_ER1_SINK="${ENABLE_ER1_SINK:-0}"

exec "$ENGINE_BIN" \
    --user-context-id="$CTX" \
    --kafka="$KAFKA_URL" \
    --listen=":${ENGINE_PORT}" \
    --secret-env="${HMAC_VAR}"
