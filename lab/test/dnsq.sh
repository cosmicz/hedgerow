#!/bin/sh
# Resolve NAME via SERVER from inside a lab client container using busybox
# nslookup. Prints the first A address, or nothing when the name does not
# resolve. Usage: dnsq.sh NAME SERVER [SERVICE=client]
name=$1; server=$2; svc=${3:-client}
docker compose --project-directory "$(cd "$(dirname "$0")/.." && pwd)" exec -T "$svc" \
  sh -c "nslookup -type=a '$name' '$server' 2>/dev/null" \
  | awk '/^Name:/{f=1} f && /^Address:/{print $2; exit}'
