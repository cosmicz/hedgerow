#!/bin/sh
# Image identity: every compose image is locked and every loaded image ID equals
# its lock entry. Fails if an image is missing, mismatched, or unlocked.
. "$(dirname "$0")/lib.sh"
out=$(sh "$LAB_DIR/bin/lab" verify-images 2>&1); rc=$?
printf '%s\n' "$out" | grep -E '^(ok|FAIL)' | while read -r line; do printf '%s\n' "$line"; done
[ "$rc" -eq 0 ] && pass "all compose images match lab/images.lock" || fail "image identity enforcement failed"
report
