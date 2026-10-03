#!/usr/bin/env bash
# Runs every test suite. Works on macOS and Linux (see scripts/test-linux.sh for Linux in docker).
# Usage: scripts/test.sh [--asan] [--stress SECONDS] [--fuzz-iterations N]
#   --asan            also runs the live server + websocket suites under the address sanitizer.
#   --stress SECONDS  also runs the stress tests for SECONDS each. Prefer scripts/test-linux.sh
#                     for this, the container caps CPU and memory. Heavier load:
#                     STRESS_EXTRA="-define:STRESS_SERVER_THREADS=4 -define:STRESS_WORKERS=12"
#
# Runaway protection: every step runs at low priority in its own process group, and the whole
# group is killed when the step exceeds STEP_TIMEOUT seconds (default 180) or its output exceeds
# MAX_LOG_MB (default 20).
set -uo pipefail
set -m # Background jobs get their own process group, so a step can be killed with its children.
cd "$(dirname "$0")/.."

ASAN=0
STRESS=0
FUZZ_ITERATIONS=200000
STEP_TIMEOUT=${STEP_TIMEOUT:-180}
MAX_LOG_BYTES=$(( ${MAX_LOG_MB:-20} * 1024 * 1024 ))
while [ $# -gt 0 ]; do
	case $1 in
		--asan) ASAN=1 ;;
		--stress) STRESS=$2; shift ;;
		--fuzz-iterations) FUZZ_ITERATIONS=$2; shift ;;
		*) echo "unknown argument: $1"; exit 2 ;;
	esac
	shift
done

OUT=$(mktemp -d)
CURRENT=
cleanup() {
	[ -n "$CURRENT" ] && kill -KILL -- -"$CURRENT" 2>/dev/null
	rm -rf "$OUT"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

# Leaks and bad frees fail the test that caused them.
DEFS="-define:ODIN_TEST_LOG_LEVEL=warning -define:ODIN_TEST_FAIL_ON_BAD_MEMORY=true -define:ODIN_TEST_FANCY=false"
failed=()

step() {
	local name=$1; shift
	local log="$OUT/step.log"
	printf '%-28s ' "$name"
	local start=$SECONDS reason=

	"$@" > "$log" 2>&1 &
	CURRENT=$!
	renice -n 10 -p "$CURRENT" > /dev/null 2>&1 # Low priority, inherited by what it starts.
	if [ "$(uname)" = Darwin ]; then
		# Background QoS: efficiency cores and throttled I/O, so a runaway can't heat the machine.
		taskpolicy -b -p "$CURRENT" > /dev/null 2>&1
	fi
	while kill -0 "$CURRENT" 2>/dev/null; do
		sleep 1
		if (( SECONDS - start > STEP_TIMEOUT )); then
			reason="killed: still running after ${STEP_TIMEOUT}s"
		elif [ "$(wc -c < "$log")" -gt "$MAX_LOG_BYTES" ]; then
			reason="killed: output passed $((MAX_LOG_BYTES / 1024 / 1024))MB"
		fi
		if [ -n "$reason" ]; then
			kill -TERM -- -"$CURRENT" 2>/dev/null
			sleep 1
			kill -KILL -- -"$CURRENT" 2>/dev/null
			break
		fi
	done
	{ wait "$CURRENT"; } 2>/dev/null
	local rc=$?
	CURRENT=

	if [ $rc = 0 ] && [ -z "$reason" ]; then
		echo "ok   ($((SECONDS - start))s)"
	else
		echo "FAIL ($((SECONDS - start))s) ${reason}"
		# Only the tail, and only lines that say something.
		tail -c 200000 "$log" | grep -vE "request scanning error|^\s*$" | tail -40 | cut -c1-300 | sed 's/^/    /'
		failed+=("$name")
	fi
}

check_examples() {
	# bench/server imports the library as `lib:http`.
	mkdir -p "$OUT/lib" && ln -sfn "$PWD" "$OUT/lib/http"
	for e in examples/*/ autobahn/server/ bench/server/; do
		odin check "$e" -vet --strict-style -collection:lib="$OUT/lib" || return 1
	done
}

STRESS_NAMES=${STRESS_NAMES:-tests_server.stress_http,tests_server.stress_websocket,tests_server.stress_shutdown_under_load}

echo "odin $(odin version | awk '{print $NF}') on $(uname -sm)"
step "examples typecheck"     check_examples
step "unit"                   odin test tests/unit      -vet --strict-style $DEFS -out:"$OUT/unit"
step "websocket codec"        odin test tests/websocket -vet --strict-style $DEFS -out:"$OUT/ws"
step "client"                 odin test tests/client    -vet --strict-style $DEFS -out:"$OUT/client"
step "server (live)"          odin test tests/server    -vet --strict-style $DEFS -out:"$OUT/server"
step "parser fuzz"            odin test tests/fuzz -o:speed -define:FUZZ_ITERATIONS="$FUZZ_ITERATIONS" $DEFS -out:"$OUT/fuzz"
if [ $ASAN = 1 ]; then
	step "server (live, asan)"    odin test tests/server    -sanitize:address -debug $DEFS -out:"$OUT/server-asan"
	step "websocket codec (asan)" odin test tests/websocket -sanitize:address -debug $DEFS -out:"$OUT/ws-asan"
	step "client (asan)"          odin test tests/client    -sanitize:address -debug $DEFS -out:"$OUT/client-asan"
fi
if [ "$STRESS" != 0 ]; then
	# One stress test at a time.
	for name in ${STRESS_NAMES//,/ }; do
		step "${name#tests_server.} (${STRESS}s)" odin test tests/server -define:STRESS_SECONDS="$STRESS" ${STRESS_EXTRA:-} -define:ODIN_TEST_THREADS=1 -define:ODIN_TEST_NAMES="$name" $DEFS -out:"$OUT/stress"
		if [ $ASAN = 1 ]; then
			step "${name#tests_server.} (asan)" odin test tests/server -sanitize:address -debug -define:STRESS_SECONDS="$STRESS" ${STRESS_EXTRA:-} -define:ODIN_TEST_THREADS=1 -define:ODIN_TEST_NAMES="$name" $DEFS -out:"$OUT/stress-asan"
		fi
	done
fi

if [ ${#failed[@]} -gt 0 ]; then
	echo "failed: ${failed[*]}"
	exit 1
fi
echo "all passed"
