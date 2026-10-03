# Interop and benchmark image: the Linux test image plus real clients (curl, Python websockets), Caddy
# and wrk.
# Built and used by scripts/interop.sh and bench/http.sh.
#
# Caddy comes from its official image, pinned: Ubuntu's package (2.6.2, 2022) has a reverse proxy
# race that aborts responses to POSTs on reused upstream connections (Go's server closing the
# request body once the response starts), which current versions don't.
ARG BASE
ARG CADDY=caddy:2.11.6
FROM ${CADDY} AS caddy

FROM ${BASE}
COPY --from=caddy /usr/bin/caddy /usr/bin/caddy
RUN apt-get update \
	&& apt-get install -y --no-install-recommends curl python3-websockets wrk \
	&& rm -rf /var/lib/apt/lists/*
