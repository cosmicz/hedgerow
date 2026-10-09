#!/bin/sh
# Functional smoke: lab names resolve through the appliance, negative controls do
# not, endpoint serves the banner, API auth works, deny list empty at baseline.
. "$(dirname "$0")/lib.sh"
load_env

q() { sh "$LAB_DIR/test/dnsq.sh" "$1" 10.77.0.53; }
assert_eq 10.77.0.80 "$(q benign.lab.test)"  "benign.lab.test -> 10.77.0.80"
assert_eq 10.77.0.80 "$(q flagged.lab.test)" "flagged.lab.test -> 10.77.0.80 (no rule yet)"
assert_eq 10.77.0.80 "$(q endpoint.lab.test)" "endpoint.lab.test -> 10.77.0.80"
assert_eq "" "$(q never.invalid)" "never.invalid does not resolve"
banner=$(in_svc client sh -c 'wget -q -T 5 -O - http://endpoint.lab.test/' 2>/dev/null || true)
assert_contains "router-guard lab endpoint" "$banner" "endpoint HTTP banner served"

api_login || { report; exit 1; }
ver=$(api GET /info/version | jq -r '.version.core.local.version // .version.ftl.local.version // empty')
[ -n "$ver" ] && pass "api: version readable ($ver)" || fail "api: version unreadable"
count=$(api GET /domains/deny/exact | jq -r '.domains | length')
assert_eq 0 "$count" "baseline: deny/exact list empty"
gid=$(api GET /groups/rg-lab | jq -r '.groups[0].id // empty')
[ -n "$gid" ] && [ "$gid" -ge 1 ] && pass "provision: group rg-lab id=$gid (>=1)" || fail "provision: group rg-lab missing"
cg=$(api GET /clients/10.77.0.100 | jq -c '.clients[0].groups // empty')
assert_eq "[$gid]" "$cg" "provision: client 10.77.0.100 in group [$gid] only"
assert_eq "" "$(api GET /clients/10.77.0.101 | jq -r '.clients[0].client // empty')" "provision: control client 10.77.0.101 not registered"
api_logout
report
