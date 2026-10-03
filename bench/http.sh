#!/usr/bin/env bash
# HTTP benchmark: bench/server built from one or more revisions, loaded with wrk, in the Linux
# container (io_uring). Server and wrk are pinned to separate cores.
# Usage: bench/http.sh [SECONDS] [REV ...]     REV: a commit, or "." for the working tree (default)
#        e.g. bench/http.sh 5 2fe913b .        upstream's last commit against the working tree
# Env: THREADS (server threads, default 2), SCENARIOS (names below, default all), DEFINES (extra
# -define flags for the server build, e.g. -define:NO_TIMEOUTS=true).
#
# Runaway protection: the container is capped (2 GiB, 4 CPUs), `timeout` is its first process so
# everything in it is killed after a fixed budget, and output is cut off at 1 MiB.
set -euo pipefail
cd "$(dirname "$0")/.."

SECS=${1:-5}
shift || true
REVS=${*:-.}
SCENARIOS=${SCENARIOS:-plain json big echo static close}
N=$(( $(echo $REVS | wc -w) * $(echo $SCENARIOS | wc -w) ))
BUDGET=$(( 120 + N * (SECS + 15) ))

ODIN_COMMIT=8412dc37a
docker build -q --build-arg ODIN_COMMIT=$ODIN_COMMIT -t odin-http-test:$ODIN_COMMIT -f scripts/linux.Dockerfile scripts > /dev/null
docker build -q --build-arg BASE=odin-http-test:$ODIN_COMMIT -t odin-http-interop:$ODIN_COMMIT -f scripts/interop.Dockerfile scripts > /dev/null

docker run --rm -e THREADS -e DEFINES --cpuset-cpus=0-3 --memory=2g --pids-limit=256 \
	--security-opt seccomp=unconfined --ulimit nofile=65536:65536 \
	-v "$PWD:/src" odin-http-interop:$ODIN_COMMIT timeout -s KILL $BUDGET bash -c "
	git config --global --add safe.directory /src
	mkdir -p /tmp/bench/static && head -c 1048576 /dev/urandom > /tmp/bench/static/1m.bin
	printf 'wrk.method = \"POST\"\nwrk.body = string.rep(\"a\", 1024)\n' > /tmp/post.lua

	port=9200
	for rev in $REVS; do
		rm -rf /tmp/rev && mkdir -p /tmp/rev/http
		if [ \"\$rev\" = . ]; then cp -r /src/*.odin /tmp/rev/http/; else git -C /src archive \"\$rev\" | tar -x -C /tmp/rev/http; fi
		# The bench server is always the current one (it only uses APIs every version has).
		odin build bench/server -o:speed -collection:lib=/tmp/rev -define:THREADS=\${THREADS:-2} \${DEFINES:-} -out:/tmp/benchsrv 2>&1 | head -20
		[ -x /tmp/benchsrv ] || { echo \"\$rev: build failed\"; continue; }
		echo \"== \$rev\"

		for sc in $SCENARIOS; do
			port=\$((port + 1))
			(cd /tmp && exec taskset -c 0-1 /tmp/benchsrv \$port) > /tmp/server.log 2>&1 & srv=\$!
			sleep 0.3
			url=http://127.0.0.1:\$port
			case \$sc in
				plain)  args=\"-c 64 \$url/plain\" ;;
				json)   args=\"-c 64 \$url/json\" ;;
				big)    args=\"-c 64 \$url/big\" ;;
				echo)   args=\"-c 64 -s /tmp/post.lua \$url/echo\" ;;
				static) args=\"-c 32 \$url/static/1m.bin\" ;;
				close)  args=\"-c 32 -H Connection:close \$url/plain\" ;;
			esac
			out=\$(timeout -s KILL $((SECS + 10)) taskset -c 2-3 wrk -t 2 -d ${SECS}s --latency \$args 2>&1) || true
			rps=\$(echo \"\$out\" | awk '/Requests\/sec/ {print int(\$2)}')
			p50=\$(echo \"\$out\" | awk '\$1 == \"50%\" {print \$2}')
			p99=\$(echo \"\$out\" | awk '\$1 == \"99%\" {print \$2}')
			errs=\$(echo \"\$out\" | grep -E 'Socket errors|Non-2xx' | tr -s ' ' | tr '\n' ' ')
			printf '%-8s %9s req/s  p50 %9s  p99 %9s  %s\n' \$sc \"\${rps:-?}\" \"\${p50:-?}\" \"\${p99:-?}\" \"\$errs\"
			kill -KILL \$srv 2>/dev/null; wait \$srv 2>/dev/null
			if [ -s /tmp/server.log ]; then echo \"  server: \$(head -c 300 /tmp/server.log)\"; fi
		done
		rm -f /tmp/benchsrv
	done" 2>&1 | head -c 1048576
