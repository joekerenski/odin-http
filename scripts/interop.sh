#!/usr/bin/env bash
# Interop tests (tests/interop): curl, Python's http.client and websockets, directly and through
# Caddy (TLS, HTTP/2), against tests/interop/server, in the Linux test container.
# Usage: scripts/interop.sh [unittest args...]   e.g. scripts/interop.sh Proxy.test_http2_parallel
#
# Runaway protection: the container is capped (CPUS, default 2, 2 GiB), `timeout` is its first
# process so everything in it is killed after a fixed budget, and output is cut off at 1 MiB.
set -euo pipefail
cd "$(dirname "$0")/.."

ODIN_COMMIT=8412dc37a
BASE=odin-http-test:$ODIN_COMMIT
IMAGE=odin-http-interop:$ODIN_COMMIT

docker build -q --build-arg ODIN_COMMIT=$ODIN_COMMIT -t "$BASE" -f scripts/linux.Dockerfile scripts > /dev/null
docker build -q --build-arg BASE="$BASE" -t "$IMAGE" -f scripts/interop.Dockerfile scripts > /dev/null

TESTS=""
if [ $# -gt 0 ]; then TESTS=$(printf '%q ' "$@"); fi

docker run --rm --cpus="${CPUS:-2}" --memory=2g --pids-limit=512 -e PYTHONDONTWRITEBYTECODE=1 \
	--security-opt seccomp=unconfined --ulimit nofile=65536:65536 \
	-v "$PWD:/src" "$IMAGE" timeout -s KILL 600 bash -c "
	set -u
	odin build tests/interop/server -o:speed -out:/tmp/interop || exit 1
	odin build tests/interop/client -o:speed -out:/tmp/interop-client || exit 1
	# For the client's host name check, see tests/interop/client.
	echo '127.0.0.1 alias.test' >> /etc/hosts
	head -c 3000000 /dev/urandom > /tmp/file.bin

	/tmp/interop 8080 /tmp/file.bin > /tmp/server.log 2>&1 & srv=\$!
	caddy run --config tests/interop/Caddyfile --adapter caddyfile > /tmp/caddy.log 2>&1 & caddy=\$!

	# Wait for both (Caddy also issues its certificate).
	for _ in \$(seq 100); do
		curl -sf -o /dev/null http://127.0.0.1:8080/hello && [ -f /tmp/caddy/pki/authorities/local/root.crt ] \
			&& curl -sf -o /dev/null --cacert /tmp/caddy/pki/authorities/local/root.crt https://localhost:8443/hello \
			&& curl -sf -o /dev/null --cacert /tmp/caddy/pki/authorities/local/root.crt https://127.0.0.1:8446/hello && break
		sleep 0.1
	done

	DIRECT=http://127.0.0.1:8080 PROXY=https://localhost:8443 CA=/tmp/caddy/pki/authorities/local/root.crt FILE=/tmp/file.bin ODIN_CLIENT=/tmp/interop-client \
		timeout -s KILL 400 python3 tests/interop/test_interop.py $TESTS 2>&1
	rc=\$?

	# The server must still be up, and shut down cleanly.
	if ! kill -0 \$srv 2>/dev/null; then echo 'server died'; rc=1; fi
	kill -INT \$srv 2>/dev/null
	for _ in \$(seq 50); do kill -0 \$srv 2>/dev/null || break; sleep 0.1; done
	if kill -0 \$srv 2>/dev/null; then echo 'server did not shut down within 5s'; kill -KILL \$srv; rc=1; fi
	wait \$srv 2>/dev/null; code=\$?
	if [ \$code -ne 0 ]; then echo \"server exited with \$code\"; rc=1; fi
	kill -KILL \$caddy 2>/dev/null

	if grep -qv 'uring interrupted' /tmp/server.log 2>/dev/null; then echo '--- server log'; head -c 4000 /tmp/server.log; fi
	if [ \$rc -ne 0 ] && [ -s /tmp/caddy.log ]; then echo '--- caddy log'; tail -c 4000 /tmp/caddy.log; fi
	exit \$rc" 2>&1 | head -c 1048576
exit "${PIPESTATUS[0]}"
