#!/bin/sh
# Start/stop loopback-only ClickHouse and MongoDB for the sponsor adapters.
# No credentials are created: both bind 127.0.0.1 and hold synthetic data only.
set -eu
TOOLS="${RG_SPONSOR_TOOLS:?set RG_SPONSOR_TOOLS to the directory used by fetch.sh}"
STATE="${RG_SPONSOR_STATE:-$(pwd)/private/sponsor-state}"
CH_VERSION=26.8.22.13
MONGO_VERSION=8.0.4
CH_HTTP_PORT="${RG_CLICKHOUSE_PORT:-18123}"
MONGO_PORT="${RG_MONGO_PORT:-27717}"

start() {
  for pidfile in "$STATE/clickhouse/pid" "$STATE/mongodb/pid"; do
    if owned "$pidfile"; then
      echo "already running: $pidfile" >&2
      exit 1
    fi
  done
  mkdir -p "$STATE/clickhouse" "$STATE/mongodb"
  cat > "$STATE/clickhouse/config.xml" <<XML
<clickhouse>
  <logger><level>warning</level><log>$STATE/clickhouse/server.log</log><errorlog>$STATE/clickhouse/error.log</errorlog></logger>
  <listen_host>127.0.0.1</listen_host>
  <http_port>$CH_HTTP_PORT</http_port>
  <path>$STATE/clickhouse/data-$CH_VERSION/</path>
  <tmp_path>$STATE/clickhouse/tmp/</tmp_path>
  <user_files_path>$STATE/clickhouse/user_files/</user_files_path>
  <users>
    <default>
      <password></password>
      <networks><ip>127.0.0.1</ip></networks>
      <profile>default</profile>
      <quota>default</quota>
      <access_management>0</access_management>
    </default>
  </users>
  <profiles><default/></profiles>
  <quotas><default/></quotas>
</clickhouse>
XML
  # Without the watchdog the recorded PID is the server itself, so owned()
  # can match its command line (the watchdog rewrites its process title).
  CLICKHOUSE_WATCHDOG_ENABLE=0 nohup "$TOOLS/clickhouse-$CH_VERSION" server --config-file="$STATE/clickhouse/config.xml" \
    > "$STATE/clickhouse/stdout.log" 2>&1 &
  echo $! > "$STATE/clickhouse/pid"
  "$TOOLS/mongodb-macos-aarch64-$MONGO_VERSION/bin/mongod" --bind_ip 127.0.0.1 \
    --port "$MONGO_PORT" --dbpath "$STATE/mongodb" \
    --logpath "$STATE/mongodb/mongod.log" --fork --pidfilepath "$STATE/mongodb/pid" >/dev/null
  echo "clickhouse http://127.0.0.1:$CH_HTTP_PORT  mongodb mongodb://127.0.0.1:$MONGO_PORT"
}

# True only when the pidfile names a live process that is still our service;
# a stale pidfile whose PID was reused by another program is never signalled.
owned() {
  [ -f "$1" ] || return 1
  pid="$(cat "$1")"
  case "$pid" in ''|*[!0-9]*) return 1 ;; esac
  command="$(ps -p "$pid" -o command= 2>/dev/null)" || return 1
  case "$command" in
    *"$TOOLS/clickhouse-$CH_VERSION server --config-file=$STATE/clickhouse/config.xml"*) return 0 ;;
    *"mongod --bind_ip 127.0.0.1"*"--dbpath $STATE/mongodb"*) return 0 ;;
  esac
  return 1
}

stop() {
  for pidfile in "$STATE/clickhouse/pid" "$STATE/mongodb/pid"; do
    if owned "$pidfile"; then
      kill "$(cat "$pidfile")"
    elif [ -f "$pidfile" ]; then
      echo "stale pidfile ignored: $pidfile" >&2
    fi
    rm -f "$pidfile"
  done
}

listening() {
  # lsof truncates command names to nine characters ("clickhous").
  lsof -nP -iTCP -sTCP:LISTEN | grep -E "clickhous|mongod" || true
}

case "${1:-start}" in
  start) start ;;
  stop) stop ;;
  status) listening ;;
  *) echo "usage: services.sh start|stop|status" >&2; exit 2 ;;
esac
