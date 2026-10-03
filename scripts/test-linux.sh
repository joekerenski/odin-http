#!/usr/bin/env bash
# Runs scripts/test.sh inside a Linux container (io_uring backend), e.g. on OrbStack.
# Usage: scripts/test-linux.sh [test.sh args...]   e.g. scripts/test-linux.sh --asan --stress 5
#        scripts/test-linux.sh --hunt [RUNS]        repeat the stress tests until one fails/hangs
#
# The container is capped (CPUS, default 2, MEMORY, default 2g), so nothing in it can load the
# host fully; test.sh adds per-step time and output limits on top.
#
# Runs on the native architecture (arm64 on Apple silicon). x86-64 under Rosetta is not an option:
# Rosetta does not implement io_uring (ENOSYS), so nothing would start.
set -euo pipefail
cd "$(dirname "$0")/.."

ODIN_COMMIT=8412dc37a
IMAGE=odin-http-test:$ODIN_COMMIT

docker build -q --build-arg ODIN_COMMIT=$ODIN_COMMIT -t "$IMAGE" -f scripts/linux.Dockerfile scripts > /dev/null

# Docker's default seccomp profile blocks io_uring, which is what core:nbio uses on Linux.
# The address sanitizer needs ptrace-like personality changes, hence SYS_PTRACE.
CMD=(scripts/test.sh "$@")
if [ "${1:-}" = --hunt ]; then
	CMD=(env RUNS="${2:-40}" scripts/hunt.sh)
fi

docker run --rm \
	--cpus="${CPUS:-2}" \
	--memory="${MEMORY:-2g}" \
	--pids-limit=1024 \
	--security-opt seccomp=unconfined \
	--cap-add SYS_PTRACE \
	-e DEBUG \
	--ulimit nofile=65536:65536 \
	-e STRESS_NAMES -e STRESS_EXTRA -e STEP_TIMEOUT -e MAX_LOG_MB \
	-v "$PWD:/src" \
	"$IMAGE" \
	"${CMD[@]}"
