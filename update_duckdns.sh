#!/usr/bin/env bash

TOKEN="${DUCKDNS_TOKEN:-}"
DOMAIN="${DUCKDNS_DOMAIN:-}"
LOG_DIR="${DDNS_LOG_DIR:-}"

if [[ -z "$TOKEN" || -z "$DOMAIN" || -z "$LOG_DIR" ]]; then
    echo "Error: DUCKDNS_TOKEN and DUCKDNS_DOMAIN must be set." &>> ddns_log
    exit 1
fi

RESPONSE=$(curl -s "https://www.duckdns.org/update?domains=${DOMAIN}&token=${TOKEN}&ip=")

if [[ "$RESPONSE" == "OK" ]]; then
    echo "$(date +"%Y-%m-%dT%H:%M:%SZ") [OK] Updated ${DOMAIN}.duckdns.org" &>> ${LOG_DIR}/ddns_log
else
    echo "$(date +"%Y-%m-%dT%H:%M:%SZ") [ERROR] Update failed" &>> ${LOG_DIR}/ddns_log
    exit 1
fi
