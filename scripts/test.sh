#!/usr/bin/env bash
# Runs every test suite. Works on macOS and Linux (see scripts/test-linux.sh for Linux in docker).
# Usage: scripts/test.sh [--asan] [--fuzz-iterations N]
#   --asan  also runs the live server + websocket suites under the address sanitizer.
set -uo pipefail
cd "$(dirname "$0")/.."

ASAN=0
FUZZ_ITERATIONS=200000
while [ $# -gt 0 ]; do
	case $1 in
		--asan) ASAN=1 ;;
		--fuzz-iterations) FUZZ_ITERATIONS=$2; shift ;;
		*) echo "unknown argument: $1"; exit 2 ;;
	esac
	shift
done

OUT=$(mktemp -d)
trap 'rm -rf "$OUT"' EXIT
LOG=-define:ODIN_TEST_LOG_LEVEL=warning
failed=()

step() {
	local name=$1; shift
	printf '%-28s ' "$name"
	local start=$SECONDS
	if output=$("$@" 2>&1); then
		echo "ok   ($((SECONDS - start))s)"
	else
		echo "FAIL ($((SECONDS - start))s)"
		echo "$output" | grep -vE "request scanning error|^\s*$" | tail -40 | sed 's/^/    /'
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

echo "odin $(odin version | awk '{print $NF}') on $(uname -sm)"
step "examples typecheck"    check_examples
step "unit"                  odin test tests/unit      -vet --strict-style $LOG -out:"$OUT/unit"
step "websocket codec"       odin test tests/websocket -vet --strict-style $LOG -out:"$OUT/ws"
step "server (live)"         odin test tests/server    -vet --strict-style $LOG -out:"$OUT/server"
step "parser fuzz"           odin test tests/fuzz -o:speed -define:FUZZ_ITERATIONS="$FUZZ_ITERATIONS" $LOG -out:"$OUT/fuzz"
if [ $ASAN = 1 ]; then
	step "server (live, asan)"   odin test tests/server    -sanitize:address -debug $LOG -out:"$OUT/server-asan"
	step "websocket codec (asan)" odin test tests/websocket -sanitize:address -debug $LOG -out:"$OUT/ws-asan"
fi

if [ ${#failed[@]} -gt 0 ]; then
	echo "failed: ${failed[*]}"
	exit 1
fi
echo "all passed"
