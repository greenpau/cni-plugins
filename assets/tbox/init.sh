#!/usr/bin/env bash

set -e
set -x

/usr/bin/iperf3 -s -D -I /var/run/iperf3.pid
nohup /usr/bin/caddy run -config /etc/caddy/config.json > /var/log/caddy.log 2>&1 &

echo "Running $@"
exec "$@"
