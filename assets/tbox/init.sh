#!/usr/bin/env bash

set -e
set -x

/usr/bin/iperf3 -s -D -I /var/run/iperf3.pid

mkdir -p /etc/caddy
cat <<'EOF' > /etc/caddy/config.json
{
  "admin": {
    "disabled": true
  },
  "apps": {
    "http": {
      "servers": {
        "static": {
          "idle_timeout": 30000000000,
          "listen": [
            ":80"
          ],
          "max_header_bytes": 10240,
          "read_header_timeout": 10000000000,
          "routes": [
            {
              "handle": [
                {
                  "handler": "file_server",
                  "browse": {}
                }
              ]
            }
          ]
        }
      }
    }
  }
}
EOF

mkdir -p /var/lib/caddy/
cat <<EOF > /var/lib/caddy/index.html
<!doctype html>
<html>
  <head>
    <title>Caddy</title>
  </head>
  <body>
    <h1>Caddy</h1>

    <p>Hostname: <code>`hostname`</code></p>

    <p>IP addressing</p>
<pre>
`ip addr show`
</pre>

    <p>IP routing</p>
<pre>
`ip route`
</pre>

    <p>DNS Resolution</p>
<pre>
`cat /etc/resolv.conf`
</pre>

  </body>
</html>
EOF

nohup /usr/bin/caddy run -config /etc/caddy/config.json > /var/log/caddy.log 2>&1 &

echo "Running $@"
exec "$@"
