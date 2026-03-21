#!/bin/sh
set -eu

bind_ip="${FILE_YEET_BIND_IP:-0.0.0.0}"
bind_port="${FILE_YEET_BIND_PORT:-7828}"
tls_cert="${FILE_YEET_TLS_CERT:-}"
tls_key="${FILE_YEET_TLS_KEY:-}"

set -- file_yeet_server "--bind-ip=${bind_ip}" "--bind-port=${bind_port}" "$@"

if [ -n "${tls_cert}" ] || [ -n "${tls_key}" ]; then
    if [ -z "${tls_cert}" ] || [ -z "${tls_key}" ]; then
        echo "Both FILE_YEET_TLS_CERT and FILE_YEET_TLS_KEY must be set together." >&2
        exit 1
    fi

    set -- "$@" "--tls-cert=${tls_cert}" "--tls-key=${tls_key}"
else
    set -- "$@" "--self-sign-certificate"
fi

exec "$@"
