#!/bin/sh
# Isolation evidence from inside each lab container and from the Docker network.
# Expected: no default route, external and host-resolver connects unreachable,
# external names unresolvable, network Internal=true, host ports only on 127.0.0.1.
. "$(dirname "$0")/lib.sh"

NET_NAME=$($COMPOSE config --format json 2>/dev/null | jq -r '.networks.lab.name // empty')
[ -n "$NET_NAME" ] || { fail "compose network 'lab' not defined"; report; exit 1; }
internal=$(docker network inspect "$NET_NAME" --format '{{.Internal}}' 2>/dev/null || echo missing)
assert_eq true "$internal" "network $NET_NAME is internal"

for svc in pihole gateway client; do
  # /proc/net/route: a default route has Destination (field 2) 00000000.
  # Match that field only; link routes carry 00000000 in the Gateway field.
  defroutes=$(in_svc "$svc" sh -c 'awk '"'"'NR>1 && $2=="00000000"'"'"' /proc/net/route | wc -l | tr -d " "' 2>/dev/null || echo "svc-missing")
  assert_eq 0 "$defroutes" "$svc: no default route"
  out=$(in_svc "$svc" sh -c 'nc -z -w 2 1.1.1.1 53 2>&1 && echo CONNECTED || echo BLOCKED' 2>/dev/null || echo "svc-missing")
  assert_contains BLOCKED "$out" "$svc: 1.1.1.1:53 unreachable"
  out=$(in_svc "$svc" sh -c 'nc -z -w 2 192.168.65.7 53 2>&1 && echo CONNECTED || echo BLOCKED' 2>/dev/null || echo "svc-missing")
  assert_contains BLOCKED "$out" "$svc: docker host resolver unreachable"
done

# External name must not resolve through the appliance (no upstream leak).
out=$(sh "$LAB_DIR/test/dnsq.sh" example.com 10.77.0.53)
assert_eq "" "$out" "client: example.com does not resolve via pihole"

# Host port bindings: only the console publishes, and only on 127.0.0.1.
pubs=$($COMPOSE ps --format json 2>/dev/null | jq -r 'select(.Publishers != null) | .Publishers[] | select(.PublishedPort > 0) | "\(.URL):\(.PublishedPort)"' | sort -u | tr '\n' ' ')
assert_eq "127.0.0.1:${RG_PIHOLE_HOST_PORT:-8053} " "$pubs" "published ports: console on 127.0.0.1 only"
for svc in pihole gateway client; do
  n=$($COMPOSE ps --format json "$svc" 2>/dev/null | jq -r '[.Publishers[]? | select(.PublishedPort > 0)] | length')
  assert_eq 0 "$n" "$svc: publishes no host port"
done
# Console must not route between mgmt and lab.
fwd=$(in_svc console cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo svc-missing)
assert_eq 0 "$fwd" "console: ip_forward disabled"
report
