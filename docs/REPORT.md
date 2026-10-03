# odin-http security & correctness audit

- **Baseline:** upstream `laytan/odin-http` @ `fac113f` (2026-08-26), Odin `dev-2026-09-nightly:a2fb372`, Linux x86-64 (io_uring backend).
- **Scope:** server (`server.odin`, `scanner.odin`, `http.odin`, `headers.odin`, `request.odin`, `body.odin`, `response.odin`), static files & routing (`responses.odin`, `routing.odin`, `handlers.odin`, `cookie.odin`, `mimes.odin`), client (`client/`, `openssl/`).
- **Method:** line-by-line review, then reproduction against a live build with raw-socket probes. A crafted Python server was used for the client. Findings marked **[repro]** were triggered for real. The rest were verified by reading the code and the stdlib it calls.

The work items derived from this report are tracked in [ISSUES.md](ISSUES.md). IDs are shared between the two files.

## Summary

The library is small (~3.5k lines excluding the dead `old_nbio/`), readable, and built on a solid foundation (`core:nbio`: io_uring / kqueue / IOCP). It is **not** production-grade:

- **One request can crash the server process** in at least four ways (failed assertions or bounds checks abort the whole process).
- **No timeouts exist anywhere**, client or server, and request bodies are unbounded by default.
- **HEAD responses carry a body**, which desynchronises pooled keep-alive connections (e.g. behind Caddy).
- **The client does no TLS certificate or hostname verification at all.**
- **There is no test suite** beyond one small unit test.

The upstream branch `v2-slash-core` (2024, stale, built on the old nbio) contains a WebSocket implementation and some fixes that never reached `main`; it is reference material only.

### Reachability behind Caddy

Our deployment terminates TLS/HTTP2/HTTP3 in Caddy and proxies HTTP/1.1 to the Odin server over pooled keep-alive connections. Go's HTTP stack normalises a lot (negative Content-Length, malformed chunking, invalid header names, unknown transfer codings), so some findings are not reachable from the internet in that setup. Every finding is still fixed: the server must be safe without relying on the proxy. Severity below is for direct exposure. The "via Caddy" column is our best expectation, not a tested fact.

---

## Server core

| ID | Sev | Finding | Location | Via Caddy |
|---|---|---|---|---|
| S1 | Critical | Chunked request with any trailer field crashes the process [repro] | body.odin:278 → http.odin:190 | Likely (Go forwards trailers) |
| S2 | Critical | Chunk data not followed by CRLF crashes the process [repro] | body.odin:251 | Unlikely |
| S3 | Critical | Negative `Content-Length` crashes the process, on every route [repro] | body.odin:128,148 → scanner.odin:21 | Unlikely |
| S4 | High | HEAD responses include the body; keep-alive response desync [repro] | responses.odin:169, response.odin:325 | **Yes** |
| S5 | High | No timeouts: header read, body read, idle keep-alive, write. Slowloris; ~N idle sockets exhaust N fds [repro] | scanner.odin:661, everywhere | Partly |
| S6 | High | `Expect: 100-continue` hangs forever; handler never runs [repro, curl] | server.odin:579 | Likely |
| S7 | High | Request body size unlimited unless each handler passes `max_length`; whole body buffered | body.odin:29 | Yes |
| S8 | Medium | `Transfer-Encoding` check is `has_suffix("chunked")`, case-sensitive: `xchunked` accepted, `Chunked` rejected; unknown codings not answered 501 [repro] | request.odin:480, body.odin:33 | Normalised |
| S9 | Medium | TE + CL: CL silently dropped, connection kept open (RFC 9112 §6.1 says close) [repro] | request.odin:489 | Normalised |
| S10 | Medium | Content-Length / chunk-size parsing via `strconv` accepts `+`, `_`, and wraps on overflow [repro] | body.odin:128,201 | Normalised |
| S11 | Medium | Header names not validated as `token` (spaces, CTLs accepted); values accept NUL / bare CR [repro] | http.odin:151 | Normalised |
| S12 | Medium | Request-line not validated: `HTTP/1` accepted, non-digit versions, empty target, CTLs in target [repro] | http.odin:34,81 | Normalised |
| S13 | Medium | Trailers merged into request headers; bypass the header size limit and can clobber existing headers | body.odin:259 | Yes |
| S14 | Medium | Accept errors other than `Insufficient_Resources` → `panic` (e.g. `Aborted`, `Interrupted`, `Unknown`) | server.odin:428 | n/a |
| S15 | Medium | Response header values only escape `\n`: bare `\r` and CTLs pass through; names likewise | http.odin:380, headers.odin:422 | App-dependent |
| S16 | Medium | `Connection` header compared with `== "close"`: lists / case-insensitivity ignored | response.odin:400 | Normalised |
| S17 | Low | Signal handler dereferences thread-local `td` (nil on non-server threads) and calls non-async-signal-safe code | server.odin:311 | n/a |
| S18 | Low | Cached `Date` buffer written by thread 0 while read by all threads (torn reads) | server.odin:633 | n/a |
| S19 | Low | `_server_thread_init` busy-spins while state is `.Cleaning`; shutdown has no deadline; `fmt.assertf` missing its arg | server.odin:207,284 | n/a |
| S20 | Low | No connection cap per server; accept back-off is a fixed 1s timer | server.odin:420 | n/a |
| S21 | Low | Header-limit accounting excludes CRLF; header count unbounded within the byte budget; duplicate headers re-concatenated (quadratic) | server.odin:553, http.odin:194 | Yes |
| S22 | Low | `Expect` value compared case-sensitively; 100-continue also sent to HTTP/1.0 | server.odin:579 | — |
| S23 | Info | `old_nbio/` and `allocator.odin` (`#+build ignore`) are dead code; `examples/tcp_echo` and `examples/routing` don't compile | — | — |

## Static files, routing, cookies

| ID | Sev | Finding | Location |
|---|---|---|---|
| F1 | Critical | Serving a 0-byte file (or FIFO) crashes the process via `nbio` `assert(len(buf) > 0)` [repro] | responses.odin:72 |
| F2 | High | `respond_dir` escapes the base dir by one level: `/static../secret.txt` → `www/secret.txt` [repro] | responses.odin:119-132 |
| F3 | Medium | Read error after heading written → wrong Content-Length, connection kept open; directories → 500 with `content-length: N` and no body [repro] | responses.odin:72-86 |
| F4 | Medium | Route patterns open to ReDoS (`core:text/match` has no step budget); `^/(.*)/(.*)/edit$` takes 3.7 s on an 8 KB path [repro, measured] | routing.odin:278 |
| F5 | Medium | Whole file buffered in memory; on POSIX non-Linux, open/stat/read run synchronously on the loop thread | responses.odin:72 |
| F6 | Medium | Set-Cookie attribute injection via `;`, `\r`, CTLs in name/value/domain/path [repro] | cookie.odin:33-54 |
| F7 | Medium | Rate limiter map unbounded (IPv6 rotation); `clear()` keeps capacity | handlers.odin:91 |
| F8 | Low | Position capture `()` in a route → slice out of range panic [repro] | routing.odin:287 |
| F9 | Low | Absolute `target` in `respond_dir` made relative by `"./"` join [repro] | responses.odin:132 |
| F10 | Low | Paths never percent-decoded or normalised; `url_parse` treats `foo/admin` as host+path, keeps `#frag` | routing.odin:19 |
| F11 | Low | Invalid UTF-8 path logs at error level once per route per request | routing.odin:280 |
| F12 | Low | NUL in path → filename truncated by cstring conversion while MIME taken from full string | responses.odin:38 |
| F13 | Low | Rate limiter allows max+1, racy read of `next_sweep`, Retry-After rounds to 0 | handlers.odin:103 |
| F14 | Low | Cookie parsing: last-wins (cookie tossing), only splits on exact `"; "`, rejects empty values and unknown attributes | cookie.odin:110,371 |
| F15 | Low | MIME: case-sensitive extensions, missing jpg/mjs/webp/woff2/pdf, no charset, no `nosniff` | mimes.odin |

## Client

| ID | Sev | Finding | Location |
|---|---|---|---|
| C1 | Critical | No TLS certificate or hostname verification; self-signed cert for another host accepted [repro] | client/client.odin:97-114 |
| C2 | High | Malicious server crashes the client: status line without space, negative CL, negative chunk size, chunk without CRLF, trailers (readonly assert) [all repro] | communication.odin:151, client.odin:332,413,443,465 |
| C3 | High | Memory corruption on `x-www-form-urlencoded` response bodies (invalid free / UAF) [repro] | client.odin:269-300 |
| C4 | High | Response size unlimited by default; limit bypass via overflow; headers unbounded [repro, 205 MB RSS] | client.odin:337-348,420 |
| C5 | High | CRLF injection via URL path/query, cookies, header values (bare `\r`) [repro] | http.odin:352, communication.odin:87-108 |
| C6 | High | No connect/read/write timeouts [repro] | client.odin:93, communication.odin:238,273 |
| C7 | Medium | SNI includes the port (`host:8443`, `[::1]:443`) | client.odin:102 |
| C8 | Medium | All TLS read errors treated as EOF → truncated bodies accepted as complete [repro] | communication.odin:238 |
| C9 | Medium | Bodies without a length capped at 64 KiB by default [repro] | client.odin:305 |
| C10 | Medium | 1xx returned as the final response; HEAD/204/304 bodies not skipped [repro] | communication.odin:145 |
| C11 | Medium | Valid responses rejected: unknown cookie attributes, unregistered status codes (520); `2:0` parses as 300 [repro] | cookie.odin:170, status.odin:123 |
| C12 | Medium | Sockets, SSL objects and memory leak on every error path | client.odin:93-133, communication.odin:128-214 |
| C13 | Medium | Scheme compared case-sensitively (`HTTPS://` goes out in plaintext); unknown schemes treated as http | client.odin:96 |
| C14 | Medium | IP-literal URLs without a port fail (`Port_Required`) [repro] | communication.odin:20 |
| C15 | Low | `SSL_write` loop never advances the buffer; `SSL_connect` result mishandled; no NULL checks; no `SSL_shutdown`; new `SSL_CTX` per request; error queue never cleared | client.odin:97-126 |
| C16 | Low | Plain-TCP EOF returns `(0, nil)` → scanner spins 128 times then `No_Progress`; stray `case nil:` in stream switch | communication.odin:273-290 |
| C17 | Low | URL fragment sent on the wire; `with_json` silently switches GET to POST; destroy-ownership footguns | — |

## What is done well

- Clean callback-driven design on `core:nbio`; one event loop per thread, `SO_REUSEPORT`-style accept on every thread.
- A per-connection growing arena gives cheap request-scoped allocation.
- Already handled correctly:
  - **Headers:** duplicate Host is rejected, conflicting duplicate Content-Length is rejected, and space before the colon / obs-fold are refused.
  - **Bodies and file I/O:**
    - Unread request bodies are drained (up to 256 KiB) or the connection is closed.
    - Chunk sizes reject negatives.
    - `respond_dir` defeats classic `../` and literal `%2e%2e`.
    - File handles are closed on every error path (Linux).
  - **Fuzzing:** the cookie iterator and cookie date parser survived 3M fuzz inputs.
- Response status can be patched after the body is written (fixed-width status, no reason phrase).

## Upstream (Odin core) issues found along the way

| ID | Finding | Workaround |
|---|---|---|
| U1 | `core:nbio` `sendfile` on Linux (dev-2026-09) never closes the read end of its splice pipe on success (`sendfile_callback`, impl_linux.odin): one fd leaked per call. After ~8k static file responses the process held 8k pipes, and a server thread spun at 100% after SIGINT. | Files are streamed with bounded `read` + `send` instead (response.odin). Faster than upstream's whole-file buffering anyway. |
