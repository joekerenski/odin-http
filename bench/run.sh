#!/usr/bin/env bash
# Runs the benchmark scenarios with oha against a running bench server.
# Usage: bench/run.sh <port> [duration]
set -euo pipefail
PORT=${1:-8081}
DUR=${2:-10s}
URL=http://127.0.0.1:$PORT

run() {
	local name=$1; shift
	local out
	out=$(oha --no-tui -z "$DUR" --output-format json "$@" 2>/dev/null)
	python3 - "$name" "$out" <<'PY'
import json, sys
name, d = sys.argv[1], json.loads(sys.argv[2])
s, p = d["summary"], d["latencyPercentiles"]
codes = d.get("statusCodeDistribution", {})
print(f"{name:<28} {s['requestsPerSec']:>11.0f} req/s  p50 {p['p50']*1000:7.3f}ms  p99 {p['p99']*1000:7.3f}ms  ok {s['successRate']*100:5.1f}%  codes {codes}")
PY
}

mkdir -p bench/static
[ -f bench/static/1m.bin ] || head -c 1048576 /dev/urandom > bench/static/1m.bin

run "plaintext c=64"          -c 64  "$URL/plain"
run "plaintext c=512"         -c 512 "$URL/plain"
run "json c=64"               -c 64  "$URL/json"
run "64KiB response c=64"     -c 64  "$URL/big"
run "POST 1KiB echo c=64"     -c 64  -m POST -d "$(head -c 1024 /dev/zero | tr '\0' 'a')" "$URL/echo"
run "static 1MiB c=32"        -c 32  "$URL/static/1m.bin"
run "plaintext no-keepalive"  -c 32  --disable-keepalive "$URL/plain"
