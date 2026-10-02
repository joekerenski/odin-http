#!/usr/bin/env bash
# A shorter subset for A/B experiments: bench/quick.sh <port> [duration]
set -euo pipefail
PORT=${1:-8081}; DUR=${2:-5s}; URL=http://127.0.0.1:$PORT
q() { local name=$1; shift; oha --no-tui -z "$DUR" --output-format json "$@" 2>/dev/null | python3 -c "
import json,sys; d=json.load(sys.stdin); s=d['summary']; p=d['latencyPercentiles']
print(f\"$name\".ljust(26), f\"{s['requestsPerSec']:>10.0f} req/s  p50 {(p['p50'] or 0)*1000:7.3f}ms  p99 {(p['p99'] or 0)*1000:7.3f}ms\")"; }
q "plaintext c=64" -c 64 "$URL/plain"
q "json c=64" -c 64 "$URL/json"
q "static 1MiB c=32" -c 32 "$URL/static/1m.bin"
q "no-keepalive c=32" -c 32 --disable-keepalive "$URL/plain"
