# Hardening work list

This file is the working checklist. Finding IDs (S/F/C) refer to [REPORT.md](REPORT.md); new work items have their own IDs (T = tests, P = performance, W = WebSocket, A = API).

**Definition of done for every item:**
- A regression test exists that failed before the fix and passes after.
- The full suite is green under the default build and under `-sanitize:address`.
- The item is ticked here with the commit that fixed it.

## Phase 0: Test infrastructure

- [x] **T1** `tests/server`: black-box harness that starts a real server on an ephemeral port and talks raw bytes. (5e1e7e4)
- [x] **T2** Unit tests for every parser: request line, version, header line, Content-Length, chunk size, Transfer-Encoding list, Connection list, cookies, dates, URL / percent-decoding, MIME lookup. (b10286d)
- [x] **T3** Fuzz drivers for the parsers (random + mutational from a seed corpus) with invariants: no panic, bounded allocation, round-trip where applicable. Run in CI for a fixed time budget. (cf81da8)
- [x] **T4** Pipelining / keep-alive tests: N requests on one connection with mixed bodies, verify exact response framing. (8625991)
- [x] **T5** Concurrency tests: many connections across threads, shutdown under load, no leaks (tracking allocator) and clean ASan.
  - `tests/server/stress_test.odin`: mixed HTTP (keep-alive, pipelining, chunked uploads, aborts mid-head/body, RSTs, unread responses, half-closes, garbage), WebSockets with cross-thread broadcasts and closes, shutdown under load. Off by default; `scripts/test-linux.sh --stress N [--asan]` (container capped at 2 CPUs / 2 GiB, per-step time and log limits).
  - All suites run with `ODIN_TEST_FAIL_ON_BAD_MEMORY`: leaks fail the test.
  - `Quarantine` allocator in the harness (zeroes freed memory, never reuses it) turns use-after-free into immediate failures; ASan can't see Odin heap frees.
  - `scripts/test-linux.sh --hunt [RUNS]`: repeat the stress tests until one fails or hangs, with a gdb thread dump on hangs.
- [ ] **T6** Client test harness: crafted-response server (status, framing, TLS with a local CA, truncation, slow responses).
- [ ] **T7** Interop: real curl / Python clients against the server; real servers against the client; Caddy in front of the server (docker) for the pooled-connection cases.
- [x] **T8** CI: run all of the above on Linux, macOS and Windows; drop the non-compiling examples or fix them (S23). (4336bc3)
  - The GitHub Actions workflow was removed on 2026-10-03 (this copy is macOS/Linux only). Replaced by `scripts/test.sh [--asan]` (macOS/Linux) and `scripts/test-linux.sh [--asan]` (Linux arm64 in docker, io_uring). x86-64 Linux can't be tested on Apple silicon: Rosetta has no io_uring. Running the server in docker needs a seccomp profile that allows io_uring.

## Phase 1: Server crashes and framing (critical / high)

- [x] **S1** Trailers: parse into a separate `req.trailers` map with its own size limit (S13); never touch read-only headers. (5e1e7e4)
- [x] **S2** Chunk terminator: a missing CRLF after chunk data is a framing error → 400 + close, never an assert. (5e1e7e4)
- [x] **S3, S10** Strict `1*DIGIT` Content-Length parser with overflow check, validated at header time (not lazily in `body`). Same strictness for hex chunk sizes (no sign, prefix, `_`, overflow). (5e1e7e4)
- [x] **S4** HEAD: send heading only, keep Content-Length of the would-be body; don't read files for HEAD. (5e1e7e4)
- [x] **S6, S22** `Expect: 100-continue`: send `100 Continue` as an interim response *only when the handler starts reading the body*, then continue with the same request. Case-insensitive; ignore for HTTP/1.0. (5e1e7e4)
- [x] **S8** Transfer-Encoding: parse as a case-insensitive coding list; last coding must be exactly `chunked`; `chunked` only once; unknown codings → 501 + close. (5e1e7e4)
- [x] **S9** TE + CL present → process as chunked, drop CL, force `Connection: close` after the response. (5e1e7e4)
- [x] **S11** Header names must be RFC 9110 `token`; values must be `field-content` (no NUL, CR, LF, other CTLs except HTAB). Trim only SP/HTAB. (5e1e7e4)
- [x] **S12** Request line: exact `method SP request-target SP HTTP/DIGIT.DIGIT`; target must be non-empty, without CTL/SP/DEL; method a valid token (unknown → 501). (5e1e7e4)
- [x] **S16** `Connection` parsed as a case-insensitive token list. (5e1e7e4)
- [x] **S21** Header limit counts raw bytes incl. CRLF; cap header count; duplicate header combining in linear time. (5e1e7e4 / 8625991)

## Phase 2: Timeouts, limits, robustness

- [x] **S5** Timeouts in `Server_Opts`, all enforced with nbio per-op timeouts: (4336bc3)
  - `header_timeout`: whole request head.
  - `body_read_timeout`: per read.
  - `idle_timeout`: keep-alive wait for the next request.
  - `write_timeout`.

  Sensible non-zero defaults.
- [x] **S7** `max_body_size` in `Server_Opts` with a finite default (e.g. 8 MiB); per-call `max_length` can lower it, not raise it beyond the server cap unless explicitly allowed. (5e1e7e4)
- [x] **S14** Accept errors: retry transient ones (`Aborted`, `Interrupted`, `Would_Block`), back off on resource exhaustion, log and keep running otherwise. Never panic on network input. (4336bc3)
- [x] **S15** Response headers and cookies: reject (assert in debug, drop + log in release) names that aren't tokens and values containing CR/LF/NUL/CTLs. No silent "escaping". (4336bc3)
- [x] **S17** Signal handling: async-signal-safe (set an atomic flag + wake the loops), no thread-local access. (4336bc3)
- [x] **S18** Per-thread cached Date (each loop updates its own once per second). (4336bc3)
- [x] **S19** Shutdown: no busy loop; optional deadline after which active connections are force-closed. (4336bc3)
- [x] **S20** `max_connections` per server; accept pauses at the cap and resumes on close. (4336bc3)
- [x] **A1** Replace remaining `assert`s on input-dependent paths with errors. Audit every `#no_bounds_check`. (4336bc3)

## Phase 3: Static files, routing, cookies

- [x] **F1** Zero-length / non-regular files: Content-Length 0 without reading; 404 for non-regular files (dirs, FIFOs, devices). (c44734d)
- [x] **F2, F9, F12** `respond_dir`: (c44734d)
  - Component-wise prefix match.
  - Decode → clean → verify the result stays under the root.
  - Reject NUL/CTL.
  - Handle absolute targets.
  - Optional symlink policy.
- [x] **F3** Errors after the heading is written force `Connection: close`; short reads are errors. (c44734d)
- [x] **F5** Stream files (`nbio.sendfile` where available, bounded chunked reads otherwise); support `Range`/`If-Modified-Since`/`ETag` (P-phase). (c44734d)
- [x] **F4** Router: add a segment-based router (`/users/:id/edit`, `*rest`) as the default; keep Lua patterns opt-in with a max routed-path length and a documented `[^/]*` idiom. (b10286d)
- [x] **F8** Reject position captures `()` in `route_add`; bounds-check captures. (b10286d)
- [x] **F10** Proper origin-form / absolute-form target parsing, percent-decoding of path segments after routing, fragment stripping. (b10286d)
- [x] **F6, F14** Cookies: validate name (token) / value (cookie-octet) / domain / path on write; first-wins + tolerant parsing on read; ignore unknown attributes. (b10286d)
- [x] **F7, F13** Rate limiter: bounded table, IPv6 keyed by /64, exact limit, atomic sweep, Retry-After ≥ 1. (b10286d)
- [x] **F11** Invalid UTF-8 path → 400 once, not an error log per route. (b10286d)
- [x] **F15** MIME: case-insensitive, add common types, `charset=utf-8` for text, optional `X-Content-Type-Options: nosniff`. (c44734d)

## Phase 4: WebSockets (RFC 6455)

- [x] **W1** Upgrade API: inside a handler, `websocket.upgrade(req, res, opts, callbacks)` validates the handshake, sends 101, and takes the connection out of the HTTP loop. (2ca5a6f)
  - Validation: GET, `Upgrade: websocket`, `Connection: upgrade` token, `Sec-WebSocket-Version: 13`, 16-byte base64 key.
  - Origin check hook and subprotocol negotiation.
- [x] **W2** Frame codec (sans-I/O): (2ca5a6f)
  - FIN/RSV/opcode/length/mask parsing.
  - Reject unmasked client frames, non-zero RSV without extension, reserved opcodes, fragmented or >125-byte control frames, non-minimal lengths and 64-bit lengths with the MSB set.
- [x] **W3** Message assembly: fragmentation, interleaved control frames, incremental UTF-8 validation for text (fail fast), `max_message_size` and `max_frame_size`. (2ca5a6f)
- [x] **W4** Close handshake: status code validation, close-reason UTF-8, timeouts for the peer's close, TCP close ordering. (2ca5a6f)
- [x] **W5** Ping/pong: auto-pong, optional keepalive pings with a dead-peer timeout; idle timeout. (2ca5a6f)
- [ ] **W6** Send path: bounded per-connection send queue with backpressure signal (`send` returns a full/queued status), zero-copy writes where possible, broadcast helper across threads (`nbio.exec` onto the owning loop).
- [x] **W7** Client side (`websocket.dial`) over the hardened client, with masking from a CSPRNG.
  - Built on nbio directly (the HTTP client is blocking and not hardened yet), sharing the connection code with the server (`conn.odin`). `ws://` only: TLS on the event loop is out of scope. Masks from `crypto.rand_bytes` in batches; the client waits for the server to close TCP after the close handshake (RFC 6455 7.1.1). Tests: `ws_client_echo` (quarantine allocator), `ws_client_handshake_failures`, compressed client sessions in `stress_websocket`.
- [x] **W8** Autobahn TestSuite (fuzzingclient against our server, fuzzingserver against our client) in docker: 100% pass on cases 1-11 (non-compression), informational cases reviewed.
  - Server side done: `autobahn/run.sh`. 296 OK, 0 failed; 6.4.3/6.4.4 NON-STRICT (invalid UTF-8 is detected once the whole frame has arrived, not mid-frame); 7.1.6/7.13.x informational. Case 9 (performance) shows nothing slow. Fixed 2.10 (pongs were sent in reverse order). Client side: `autobahn/run-client.sh`.
  - 2026-10-03, with compression: server 517/517 and client 517/517 (512 OK, 2 NON-STRICT, 3 informational, 0 failed on both sides).
- [x] **W9** `permessage-deflate` (RFC 7692) via `vendor:zlib`, with decompression-bomb limits; Autobahn 12-13.
  - Opt-in (`Opts.compression`, ~300KiB zlib state per connection). Offers asking for an 8-bit window are declined (zlib can't compress with 256 bytes). Decompression is capped at `max_message_size` (1009) and text is validated while it's decompressed. Messages under 32 bytes go uncompressed. Tests: negotiation unit tests, `ws_compression_bomb`.

## Found by the stress tests (2026-10-03)

- [x] **W10** Use-after-free: a WebSocket connection could be finalized (freed) inside frame processing, e.g. when the peer's close frame completed a close we started, or on a protocol error after our close was queued, and then used again by `process`/`on_recv`. Symptoms, depending on what reused the memory: an endless loop on the event loop thread (its connections starve), an `nbio` assertion (recv with an empty buffer) or nothing. Fix: connections are marked busy while an I/O completion runs and only finalized when it returns. Test: `ws_close_handshakes_dont_use_freed_conn` (quarantine allocator).
- [x] **W11** Cross-thread `send`/`close`/`broadcast` queued one `nbio` operation per message on the target loop: a busy or stalled loop filled its queue and the sending thread spun forever (logging every iteration, 11 GB in 5 minutes); after a server shutdown it targeted event loops that no longer exist. Fix: one mailbox per loop, at most one queued wake-up, closed with the loop's last connection (sends are dropped after that), capped at `MAILBOX_LIMIT`.
- [x] **S24** Shutdown abandoned connections (handler never responded) without closing their sockets: one leaked file descriptor each.
- [x] **S25** `listen` logged event loop errors as `%!(BAD ENUM VALUE=1)`; it logs the OS error number now, with an io_uring hint on Linux.
- [x] **T9** The server test suite hung forever when the server could not start (e.g. io_uring blocked in docker).
- Note: `core:net`'s `set_option(.Linger)` passes a `timeval` where the OS expects a `struct linger`; the stress client sets `SO_LINGER` through `core:sys/posix`.

## Phase 5: Client

- [ ] **C1, C7** TLS:
  - Verify peer (`SSL_VERIFY_PEER`), default CA paths, hostname/IP check, SNI without the port.
  - TLS ≥ 1.2, shared `SSL_CTX`.
  - Explicit `insecure_skip_verify` opt-out.
- [ ] **C2, C3, C4, C9** Parsing hardening:
  - Share the strict parsers from Phase 1.
  - Trailers in a separate map.
  - Default response size limit with overflow-safe checks.
  - Header limits.
  - Fix urlencoded ownership or drop auto-decoding.
- [ ] **C5, C13, C14, C17** Request construction:
  - Validate/percent-encode the target.
  - Validate header names and values and cookies.
  - Case-insensitive scheme; reject unknown schemes.
  - IP-literal default ports; strip the fragment.
- [ ] **C6** Connect / read / write / total deadlines in a `Client_Opts`.
- [ ] **C8, C16** Correct EOF/error mapping for TLS (`SSL_get_error`) and TCP; reject truncated bodies.
- [ ] **C10, C11** Skip 1xx, no body for HEAD/204/304, accept any 3-digit status, tolerate unknown cookie attributes.
- [ ] **C12, C15** Resource cleanup on every error path; correct `SSL_write`/`SSL_connect` handling; `SSL_shutdown`.
- [ ] **A2** Non-blocking client on nbio (connection pooling, keep-alive), to be used by the WebSocket client and to stop blocking event-loop threads.

## Phase 6: Performance

- [x] **P1** Benchmark harness (bench/: server + oha scripts; baseline recorded) (`wrk`/`oha` or a small Odin load generator): plaintext, JSON, 1 KB / 64 KB / 1 MB bodies, pipelined, many idle connections. Record a baseline against upstream `fac113f` before changing hot paths.
- [ ] **P2** Connection pooling (scanner buffer + arena reuse, the existing TODO), avoid per-header allocations in `sanitize_key`, write responses directly from a fixed buffer (existing TODO).
- [ ] **P3** Zero-copy bodies where possible (Content-Length bodies sliced from the scanner buffer), vectored sends (heading + body).
- [ ] **P4** Static files via `sendfile`, `Range` support, conditional requests.
- [ ] **P5** Track p50/p99 latency and RSS in CI-adjacent benchmark runs; no hardening change may regress throughput by more than 5% without a note here.
- [ ] **P6** Regression on new connections: no-keepalive throughput is ~33k req/s vs upstream's ~52k. Not caused by timeouts or TCP_NODELAY (A/B tested). Bisect: 5e1e7e4 is still ~53k, so it came in a later commit (8625991..f24233c).
- [ ] **P7** Per-op timeouts cost ~3-13% on small keep-alive requests (io_uring linked timeouts). Plan: a per-thread sweeper with coarse (1s) deadlines instead of per-op timeouts.
