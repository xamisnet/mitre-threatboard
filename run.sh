#!/usr/bin/env bash
# THREATBOARD launcher — start / stop / restart the MITRE ATT&CK cyber-news dashboard.
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PORT="${PORT:-8899}"
PIDFILE="/tmp/threatboard.pid"
LOG="/tmp/threatboard.log"

case "${1:-start}" in
  start)
    if [[ -f "$PIDFILE" ]] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
      echo "THREATBOARD already running (pid $(cat "$PIDFILE")) on http://127.0.0.1:$PORT"; exit 0
    fi
    cd "$DIR"
    nohup python3 -m http.server "$PORT" --bind 127.0.0.1 >"$LOG" 2>&1 &
    echo $! > "$PIDFILE"
    sleep 1
    code=$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$PORT/index.html")
    echo "THREATBOARD started (pid $(cat "$PIDFILE")) -> http://127.0.0.1:$PORT/index.html  [HTTP $code]"
    ;;
  stop)
    [[ -f "$PIDFILE" ]] && kill "$(cat "$PIDFILE")" 2>/dev/null && rm -f "$PIDFILE" && echo "stopped" || echo "not running"
    ;;
  restart)
    "$0" stop || true; sleep 0.5; "$0" start
    ;;
  status)
    if [[ -f "$PIDFILE" ]] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
      echo "running (pid $(cat "$PIDFILE")) -> http://127.0.0.1:$PORT/index.html"
    else echo "not running"; fi
    ;;
  *) echo "usage: $0 {start|stop|restart|status}"; exit 1 ;;
esac
