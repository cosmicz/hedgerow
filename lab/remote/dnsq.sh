#!/bin/sh
# Remote shim with the same interface as lab/test/dnsq.sh (NAME SERVER [SERVICE]) for a
# host that does not run the lab (the Pi). It asks the Mac's loopback probe helper
# through the SSH reverse tunnel at 127.0.0.1:8777 and prints the first A address.
name=$1; server=${2:-10.77.0.53}; svc=${3:-client}
[ "$server" = "10.77.0.53" ] || exit 2
# No jq on the Pi: extract the address field with sed from the single-line JSON reply.
curl -sS --max-time 8 -G "http://127.0.0.1:${RG_PROBE_PORT:-8777}/resolve" --data-urlencode "name=$name" --data-urlencode "client=$svc" 2>/dev/null | sed -n 's/.*"address":"\([^"]*\)".*/\1/p'
