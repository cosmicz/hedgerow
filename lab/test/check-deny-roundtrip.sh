#!/bin/sh
# Transformation check of the adapter target: deny rule absent -> added via API
# scoped to the dedicated group -> owned client gets 0.0.0.0 while the control
# client and benign names are unaffected -> rule deleted -> restored. Leaves the
# lab at baseline. Not the application's tests.
. "$(dirname "$0")/lib.sh"
load_env
D=update-check.cloudsyncapi.net
q() { sh "$LAB_DIR/test/dnsq.sh" "$1" 10.77.0.53; }
q2() { sh "$LAB_DIR/test/dnsq.sh" "$1" 10.77.0.53 client2; }

api_login || { report; exit 1; }
trap 'api DELETE "/domains/deny/exact/$D" >/dev/null 2>&1; api_logout' EXIT
gid=$(api GET /groups/rg-lab | jq -r '.groups[0].id // empty')
[ -n "$gid" ] || { fail "group rg-lab not provisioned"; report; exit 1; }
before=$(q "$D")
assert_eq 10.77.0.80 "$before" "before: $D resolves (wrong state for a block)"
resp=$(api POST /domains/deny/exact "{\"domain\":\"$D\",\"comment\":\"rg-lab roundtrip\",\"groups\":[$gid],\"enabled\":true}")
assert_eq "$D" "$(printf '%s' "$resp" | jq -r '.processed.success[0].item // empty')" "api: deny/exact added"
# Pi-hole applies list changes asynchronously; poll briefly.
i=0; after=""
while [ $i -lt 10 ]; do after=$(q "$D"); [ "$after" = "0.0.0.0" ] && break; i=$((i+1)); sleep 1; done
assert_eq 0.0.0.0 "$after" "after add: $D answers 0.0.0.0 for owned client (group $gid)"
assert_eq 10.77.0.80 "$(q wikipedia.org)" "after add: wikipedia.org unaffected"
assert_eq 10.77.0.80 "$(q2 "$D")" "after add: control client2 still resolves $D (scope holds)"
del=$(curl -sS --max-time 15 -o /dev/null -w '%{http_code}' -X DELETE "$RG_PIHOLE_API_BASE/domains/deny/exact/$D" -H "X-FTL-SID: $SID")
assert_eq 204 "$del" "api: deny/exact deleted (204)"
i=0; restored=""
while [ $i -lt 10 ]; do restored=$(q "$D"); [ "$restored" = "10.77.0.80" ] && break; i=$((i+1)); sleep 1; done
assert_eq 10.77.0.80 "$restored" "after delete: $D resolves again"
assert_eq 10.77.0.80 "$(q2 "$D")" "after delete: control client2 unchanged"
assert_eq 0 "$(api GET /domains/deny/exact | jq -r '.domains | length')" "deny list back to empty"
report
