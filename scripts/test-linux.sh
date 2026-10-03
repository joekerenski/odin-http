#!/usr/bin/env bash
# Runs scripts/test.sh inside a Linux container (io_uring backend), e.g. on OrbStack.
# Usage: scripts/test-linux.sh [test.sh args...]   e.g. scripts/test-linux.sh --asan
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
docker run --rm \
	--security-opt seccomp=unconfined \
	--cap-add SYS_PTRACE \
	--ulimit nofile=65536:65536 \
	-v "$PWD:/src" \
	"$IMAGE" \
	scripts/test.sh "$@"
