#!/usr/bin/env bash
# Runs the Autobahn TestSuite (fuzzingclient) against the echo server in tests/autobahn/server.
# Needs docker. Runs every case, 12/13 with permessage-deflate.
# Usage: tests/autobahn/run.sh [case-glob ...]   e.g. tests/autobahn/run.sh '9.*'
# Report: tests/autobahn/reports/index.html, summary printed at the end.
set -euo pipefail
cd "$(dirname "$0")/../.."

PORT=9001
mkdir -p tests/autobahn/reports
odin build tests/autobahn/server -o:speed -out:tests/autobahn/echo-server
./tests/autobahn/echo-server $PORT &
SERVER=$!
trap 'kill $SERVER 2>/dev/null || true' EXIT
sleep 0.5

config=tests/autobahn/fuzzingclient.json
if [ $# -gt 0 ]; then
	cases=$(printf '"%s",' "$@")
	config=tests/autobahn/reports/fuzzingclient.json
	sed "s/\"cases\": \[\"\*\"\]/\"cases\": [${cases%,}]/" tests/autobahn/fuzzingclient.json > "$config"
fi

docker run --rm \
	--platform linux/amd64 \
	--add-host=host.docker.internal:host-gateway \
	-v "$PWD/$config:/config/fuzzingclient.json:ro" \
	-v "$PWD/tests/autobahn/reports:/reports" \
	crossbario/autobahn-testsuite \
	wstest -m fuzzingclient -s /config/fuzzingclient.json

python3 - <<'PY'
import json, collections
r = json.load(open("tests/autobahn/reports/index.json"))["odin-http"]
by = collections.Counter(v["behavior"] for v in r.values())
print("\nresults:", dict(by))
bad = sorted((k for k, v in r.items() if v["behavior"] not in ("OK", "INFORMATIONAL", "NON-STRICT")),
             key=lambda k: [int(x) for x in k.split(".")])
if bad:
	print("not OK:", " ".join(f"{k}({r[k]['behavior']})" for k in bad))
PY
