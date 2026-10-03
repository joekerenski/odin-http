#!/usr/bin/env bash
# WebSocket benchmark (bench/ws): every scenario against a single-threaded server, with a
# single-threaded load generator, in the Linux test container (io_uring).
# Usage: bench/ws.sh [SECONDS] [SCENARIO ...]
# Env: WS_PING=1 (default keepalive pings), WS_LEVEL=n (zlib level), CPUS (container cap, default 2).
#
# Runaway protection: the container is capped (CPUS, 2 GiB), `timeout` is its first process so the
# whole run (and every process in it) is killed after a fixed budget, each load run has its own
# limit, servers are killed with SIGKILL, and output is cut off at 1 MiB.
set -euo pipefail
cd "$(dirname "$0")/.."

SECS=${1:-5}
shift || true
SCENARIOS=${*:-echo-32 echo-4k echo-64k echo-1m echoz-4k bcast-1000 bcast-4k}
N=$(echo $SCENARIOS | wc -w)
BUDGET=$(( 60 + N * (SECS + 20) ))

docker run --rm -e WS_PING -e WS_LEVEL --cpus="${CPUS:-2}" --memory=2g --pids-limit=256 \
	--security-opt seccomp=unconfined --ulimit nofile=65536:65536 \
	-v "$PWD:/src" odin-http-test:8412dc37a timeout -s KILL $BUDGET bash -c "
	odin build bench/ws -o:speed -out:/tmp/ws || exit 1
	port=9100
	for sc in $SCENARIOS; do
		port=\$((port + 1))
		/tmp/ws server \$port > /tmp/server.log 2>&1 & srv=\$!
		sleep 0.3
		out=\$(timeout -s KILL $((SECS + 15)) /tmp/ws load \$port \$sc $SECS) || out=\"\$sc: failed\"
		# Server CPU (user + system) over the whole run, from /proc, in seconds.
		cpu=\$(awk '{print (\$14 + \$15) / 100}' /proc/\$srv/stat 2>/dev/null)
		echo \"\$out   server cpu \${cpu}s\"
		kill -KILL \$srv 2>/dev/null; wait \$srv 2>/dev/null
		if [ -s /tmp/server.log ]; then echo \"\$sc server: \$(head -c 300 /tmp/server.log)\"; fi
	done" 2>&1 | head -c 1048576
