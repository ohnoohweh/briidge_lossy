#!/bin/sh
set -eu

PY_BIN="${1:?python binary required}"
CFG_PATH="${2:?config path required}"
LOG_PATH="${3:?runtime log path required}"
SERVICE_LOG="${4:?service log path required}"
RESTART_DELAY_SECONDS="${5:-30}"

RESTART_EXIT_CODE_IMMEDIATE=75
RESTART_EXIT_CODE_DELAYED=77

while :; do
    "${PY_BIN}" -c "from obstacle_bridge.bridge import main; main()" \
        --config "${CFG_PATH}" \
        --log-file "${LOG_PATH}"
    rc=$?
    if [ "${rc}" -eq "${RESTART_EXIT_CODE_IMMEDIATE}" ]; then
        echo "[synology-service] bridge requested immediate restart (rc=${rc})" >>"${SERVICE_LOG}"
        continue
    fi
    if [ "${rc}" -eq "${RESTART_EXIT_CODE_DELAYED}" ]; then
        echo "[synology-service] bridge requested delayed restart (rc=${rc}); sleeping ${RESTART_DELAY_SECONDS}s" >>"${SERVICE_LOG}"
        sleep "${RESTART_DELAY_SECONDS}"
        continue
    fi
    echo "[synology-service] bridge exited rc=${rc}" >>"${SERVICE_LOG}"
    exit "${rc}"
done
