#!/usr/bin/env bash
# Runs the Autobahn TestSuite in fuzzingserver mode against the WebSocket client (autobahn/client).
# Needs docker. Report: autobahn/reports/clients/index.html, summary printed at the end.
set -euo pipefail
cd "$(dirname "$0")/.."

PORT=9001
mkdir -p autobahn/reports/clients
odin build autobahn/client -o:speed -out:autobahn/echo-client

NAME=odin-http-fuzzingserver
docker rm -f $NAME > /dev/null 2>&1 || true
docker run -d --rm --name $NAME \
	--platform linux/amd64 \
	-p 127.0.0.1:$PORT:9001 \
	-v "$PWD/autobahn/fuzzingserver.json:/config/fuzzingserver.json:ro" \
	-v "$PWD/autobahn/reports/clients:/reports/clients" \
	crossbario/autobahn-testsuite \
	wstest -m fuzzingserver -s /config/fuzzingserver.json > /dev/null
trap 'docker rm -f $NAME > /dev/null 2>&1 || true' EXIT

# Wait for it to listen.
for _ in $(seq 1 60); do
	if docker logs $NAME 2>&1 | grep -q "Listening\|listening\|Ok, will run"; then break; fi
	sleep 0.5
done
sleep 1

./autobahn/echo-client ws://127.0.0.1:$PORT

python3 - <<'PY'
import json, collections
r = json.load(open("autobahn/reports/clients/index.json"))["odin-http"]
by = collections.Counter(v["behavior"] for v in r.values())
print("\nresults:", dict(by), "of", len(r))
bad = sorted((k for k, v in r.items() if v["behavior"] not in ("OK", "INFORMATIONAL", "NON-STRICT")),
             key=lambda k: [int(x) for x in k.split(".")])
if bad:
	print("not OK:", " ".join(f"{k}({r[k]['behavior']})" for k in bad))
PY
