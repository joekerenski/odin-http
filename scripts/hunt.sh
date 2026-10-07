#!/usr/bin/env bash
# Repeats the stress tests (all three at once, heavy load, info logging) until a run fails or hangs.
# On a hang it saves a thread dump (gdb) to .hunt-bt.txt. Meant to run in the Linux test container:
#   scripts/test-linux.sh --hunt [RUNS]      (DEBUG= for a build without -debug)
odin build tests/server -build-mode:test ${DEBUG--debug} $BUILD_EXTRA -define:TRACE_ASSERTIONS=true -define:STRESS_SECONDS=3 -define:STRESS_SERVER_THREADS=4 -define:STRESS_WORKERS=12 -define:ODIN_TEST_LOG_LEVEL=info -define:ODIN_TEST_FAIL_ON_BAD_MEMORY=true -define:ODIN_TEST_FANCY=false -define:ODIN_TEST_NAMES=${HUNT_NAMES:-tests_server.stress_http,tests_server.stress_websocket,tests_server.stress_shutdown_under_load,tests_server.stress_tls,tests_server.stress_tls_shutdown_under_load} -out:/tmp/s || exit 1
for i in $(seq 1 ${RUNS:-40}); do
	if [ -n "${HUNT_GDB:-}" ]; then
		# Under gdb, which stops at a crash before any signal handler: the faulting thread's stack.
		timeout -s KILL 60 gdb -q -batch -ex "set pagination off" -ex "handle SIGPIPE nostop noprint pass" \
			-ex run -ex "bt 40" -ex "info threads" /tmp/s > /tmp/log 2>&1
		if grep -q "SIGSEGV\|SIGABRT\|SIGBUS" /tmp/log; then
			echo "run $i: crashed"
			grep -A45 "received signal" /tmp/log | cut -c1-220
			exit 0
		fi
		continue
	fi
	/tmp/s > /tmp/log 2>&1 &
	pid=$!
	for _ in $(seq 1 25); do sleep 1; kill -0 $pid 2>/dev/null || break; done
	if kill -0 $pid 2>/dev/null; then
		echo "run $i: HUNG"
		gdb -p $pid -batch -ex "thread apply all bt 25" 2>/dev/null | grep -E "^Thread|^#" > /tmp/bt
		kill -KILL $pid
		cp /tmp/bt .hunt-bt.txt
		grep -E "ERROR|FATAL|filled up" /tmp/log | grep -v "scanning error" | sed -E "s/\[20[0-9: -]+\]//" | sort | uniq -c | sort -rn | head -10 | cut -c1-200
		exit 0
	fi
	wait $pid; rc=$?
	if [ $rc != 0 ] || grep -q "back trace" /tmp/log; then
		echo "run $i: exit=$rc"
		grep -E "ERROR|FATAL|back trace|^\s+#|^ - " /tmp/log | grep -v "scanning error\|filled up\|+++ leak" | sed -E "s/\[20[0-9: -]+\]//" | head -30 | cut -c1-200
		# Leak sites, counted.
		grep "+++ leak" /tmp/log | sed -E "s/@ 0x[0-9A-Fa-f]+ //" | sort | uniq -c | sort -rn | head -20 | cut -c1-200
		exit 0
	fi
	truncate -s 0 /tmp/log
done
echo "no failure in $i runs"
