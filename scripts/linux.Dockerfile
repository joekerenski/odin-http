# Linux test image: Odin built from source at a pinned commit, with LLVM 22 from apt.llvm.org.
# Built and used by scripts/test-linux.sh.
FROM ubuntu:24.04

ARG LLVM_VERSION=22
ARG ODIN_COMMIT=8412dc37a

RUN apt-get update \
	&& apt-get install -y --no-install-recommends ca-certificates wget gnupg lsb-release software-properties-common git make libssl-dev \
	&& wget -qO /tmp/llvm.sh https://apt.llvm.org/llvm.sh \
	&& bash /tmp/llvm.sh ${LLVM_VERSION} \
	&& rm -rf /var/lib/apt/lists/* /tmp/llvm.sh

ENV PATH="/usr/lib/llvm-${LLVM_VERSION}/bin:/opt/odin:${PATH}"

RUN git clone --filter=blob:none https://github.com/odin-lang/Odin /opt/odin \
	&& cd /opt/odin \
	&& git checkout ${ODIN_COMMIT} \
	&& LLVM_CONFIG=llvm-config-${LLVM_VERSION} ./build_odin.sh release \
	&& ./odin version

WORKDIR /src

# gdb for thread dumps of hung tests (gdb -p PID -batch -ex "thread apply all bt"), zlib for permessage-deflate.
RUN apt-get update && apt-get install -y --no-install-recommends gdb zlib1g-dev && rm -rf /var/lib/apt/lists/*
