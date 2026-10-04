# odin-http

An HTTP/1.1 server, an HTTP(S) client and WebSockets for [Odin](https://odin-lang.org), on `core:nbio`
(io_uring on Linux, kqueue on macOS). macOS and Linux only.

> A personal, hardened copy of [laytan/odin-http](https://github.com/laytan/odin-http) by Laytan Laats,
> with its full history. Not affiliated with or endorsed by the original project; all credit for the
> original library goes to its author.

| Import | Package | What it is |
|---|---|---|
| `odin-http` | `http` | The server: routing, middleware, request bodies, cookies, static files, streaming responses, rate limiting |
| `odin-http/client` | `client` | HTTP/1.1 client for `http://` and `https://`, blocking or async, with connection reuse |
| `odin-http/websocket` | `websocket` | WebSockets (RFC 6455 + permessage-deflate): server upgrade and `ws://`/`wss://` client |
| `odin-http/openssl` | `openssl` | OpenSSL 3 bindings used by the client and WebSocket TLS (you don't need to import it) |

The server speaks plain HTTP; for HTTPS put [Caddy](#running-behind-caddy) in front of it. The clients
speak TLS themselves and always verify certificates.

## State

- **Server**: strict HTTP/1.1 parsing and framing, limits and timeouts on everything a client controls,
  graceful shutdown. Fuzzed, stress-tested (also under the address sanitizer), and tested against curl,
  Python and Caddy. The audit it went through and what was fixed: [docs/REPORT.md](docs/REPORT.md),
  [docs/ISSUES.md](docs/ISSUES.md).
- **WebSockets**: server and client pass the full [Autobahn TestSuite](https://github.com/crossbario/autobahn-testsuite)
  (517/517 cases each, compression included).
- **Client**: verified TLS, strict response parsing with size limits, deadlines, keep-alive.
- **Performance**: plaintext ~600k req/s with keep-alive on 2 threads (Linux arm64), WebSocket echo
  ~1.9M small messages/s on one thread. See [Performance](#performance).
- Not here: HTTP/2 (Caddy does it for you), TLS in the server (same), Windows.

## Installation

Needs a recent Odin (developed against `dev-2026-08`), OpenSSL 3 and zlib:

```sh
brew install openssl@3                  # macOS (zlib comes with the OS)
sudo apt install libssl-dev zlib1g-dev  # Debian/Ubuntu
```

Odin has no package manager: put the repository somewhere and import it, either through a collection or
by path.

**As a collection** (one checkout for all your projects):

```sh
git clone https://github.com/joekerenski/odin-http ~/odin-libs/odin-http
odin run . -collection:libs=$HOME/odin-libs
```

```odin
import http "libs:odin-http"
import "libs:odin-http/client"
import ws "libs:odin-http/websocket"
```

**Inside your project** (e.g. as a git submodule):

```sh
git submodule add https://github.com/joekerenski/odin-http deps/odin-http
```

```odin
import http "deps/odin-http"   // relative to the importing file
import "deps/odin-http/client"
```

For the language server, add the collection to your project's `ols.json`:
`"collections": [{"name": "libs", "path": "/Users/you/odin-libs"}]`.

Only the packages you import are compiled; the tests, benchmarks and tools in this repository are never
part of your build.

## Server

```odin
package main

import "core:encoding/json"
import "core:log"
import "core:net"
import "core:time"

import http "libs:odin-http"

Greeting :: struct {
	name: string,
}

main :: proc() {
	context.logger = log.create_console_logger(.Info)

	router: http.Router
	http.router_init(&router)
	defer http.router_destroy(&router)

	// ":name" matches one path segment, "*rest" the remainder of the path.
	http.route_get(&router, "/hello/:name", http.handler(proc(req: ^http.Request, res: ^http.Response) {
		name, _ := http.url_param(req, "name")
		http.respond_json(res, Greeting{name})
	}))

	// Request bodies arrive in a callback (the handler must not block, see below).
	http.route_post(&router, "/greet", http.handler(proc(req: ^http.Request, res: ^http.Response) {
		http.body(req, 64 * 1024, res, proc(res: rawptr, body: http.Body, err: http.Body_Error) {
			res := (^http.Response)(res)
			if err != nil {
				http.respond(res, http.body_error_status(err))
				return
			}
			g: Greeting
			if json.unmarshal_string(body, &g) != nil {
				http.respond(res, http.Status.Bad_Request)
				return
			}
			http.respond_plain(res, g.name)
		})
	}))

	// Files under ./public, with ranges and the right Content-Type; paths can't escape the directory.
	http.route_get(&router, "/static/*path", http.handler(proc(req: ^http.Request, res: ^http.Response) {
		http.respond_dir(res, "/static", "public", req.url.path)
	}))

	// Middleware: 100 requests per minute per client.
	routes := http.router_handler(&router)
	limit: http.Rate_Limit_Data
	limited := http.rate_limit(&limit, &routes, &http.Rate_Limit_Opts{window = time.Minute, max = 100, trusted_proxies = 1})

	s: http.Server
	http.server_shutdown_on_interrupt(&s) // Ctrl-C: finish what's in flight, then stop.

	opts := http.Default_Server_Opts
	opts.max_body_size = 16 * 1024 * 1024
	err := http.listen_and_serve(&s, limited, net.Endpoint{net.IP4_Loopback, 8080}, opts)
	if err != nil { log.error(err) }
}
```

**How handlers run.** The server runs one event loop per thread (`Server_Opts.thread_count`, defaults to
the core count). Handlers run on those threads and must not block: anything slow (reading the body, calling
another service with `client.request_async`, timers) continues in a callback, and the handler (or a
callback) calls `respond` exactly once. `context.temp_allocator` belongs to the request and is freed after
the response. Responses can also be streamed with `response_writer_init` (chunked).

**Limits and timeouts** (`Server_Opts`, defaults in `Default_Server_Opts`): request line and header section
8000 bytes, 100 header fields, bodies 8 MiB, `max_connections`, 30s to send the request head, 30s per body
read, 30s per write, 3 minutes idle between keep-alive requests, 30s for in-flight requests at shutdown.

More: [examples/](examples/) (`minimal`, `routing`, `complete` with cookies and static files, `client`,
`websocket` chat).

## Client

```odin
import "core:fmt"
import "core:time"

import http "libs:odin-http"
import "libs:odin-http/client"

fetch :: proc() {
	// Blocking (for programs and tools).
	res, err := client.get("https://example.com/")
	if err != nil {
		fmt.println("request failed:", err) // e.g. .Timeout, .TLS_Verification_Failed, .Truncated
		return
	}
	defer client.response_destroy(&res)
	fmt.println(res.status, res.headers, res.body)

	// With a method, headers, cookies and a JSON body.
	req: client.Request
	client.request_init(&req, .Post)
	defer client.request_destroy(&req)
	http.headers_set(&req.headers, "authorization", "Bearer ...")
	client.with_json(&req, struct{name: string}{"odin"})
	res2, err2 := client.request(&req, "https://example.com/api", {timeout = 10 * time.Second})
	if err2 == nil { client.response_destroy(&res2) }
}

// In a handler: async, on the handler's event loop; the callback runs on the same thread.
proxy :: proc(req: ^http.Request, res: ^http.Response) {
	r: client.Request
	client.request_init(&r, .Get, context.temp_allocator)
	err := client.request_async(&r, "https://example.com/", client.Default_Opts, res, proc(upstream: client.Response, err: client.Error, user_data: rawptr) {
		res := (^http.Response)(user_data)
		if err != nil {
			http.respond(res, http.Status.Bad_Gateway)
			return
		}
		upstream := upstream
		defer client.response_destroy(&upstream)
		http.respond_plain(res, upstream.body) // copies the body
	})
	if err != nil { http.respond(res, http.Status.Bad_Gateway) }
}
```

- TLS: certificate chain, host name (or IP address) and TLS ≥ 1.2 are always checked; there is no switch to
  turn that off. `Opts.tls_ca_file` trusts a private CA instead of the system store.
- Responses are read completely, within `Opts.max_body_size` (16 MiB), `max_header_size` (64 KiB) and
  `max_headers` (100), unless streamed (below). Chunked and Content-Length bodies, trailers in
  `res.trailers`, cookies in `res.cookies`. A body that's cut short is an error, not a short body.
- Deadlines: `connect_timeout` (10s) and `timeout` for the whole request (60s); `stall_timeout` (off,
  60s when streaming) bounds each wait for more of the response.
- Connections are kept alive and reused per origin, across threads (`idle_timeout` 30s,
  `max_idle_per_host` 4, `disable_keep_alive`). A dead pooled connection is replaced transparently;
  idempotent requests (GET, HEAD, PUT, DELETE) are retried once if the server closed it as the request went out.
- Requests are validated, not escaped: a header value with a line break or an invalid cookie is refused
  with `.Invalid_Request`.
- Names are resolved with a blocking DNS lookup.

### Streaming

`request_stream` (blocking) and `request_stream_async` hand the body over as it arrives, for large
downloads and streaming APIs. `on_head` sees the status and headers first; `on_body` gets each piece,
its framing removed; either returning false cancels with `.Cancelled`. The body isn't kept, so
`max_body_size` only limits a single chunk. `timeout` covers the request until its head arrives, then
only `stall_timeout` applies: a reply may stream for minutes, a server that goes quiet still fails.

`client.SSE` parses Server-Sent Events (`text/event-stream`) incrementally:

```odin
import "core:bytes"
import "core:fmt"

import http "libs:odin-http"
import "libs:odin-http/client"

complete :: proc(body: string) -> client.Error {
	req: client.Request
	client.request_init(&req, .Post)
	defer client.request_destroy(&req)
	http.headers_set(&req.headers, "authorization", "Bearer ...")
	http.headers_set(&req.headers, "content-type", "application/json")
	bytes.buffer_write_string(&req.body, body) // or client.with_json

	sse: client.SSE
	client.sse_init(&sse, proc(ev: client.SSE_Event, user_data: rawptr) -> bool {
		if ev.data != "[DONE]" { fmt.println(ev.type, ev.data) } // one JSON delta per event
		return true // false would stop reading (the request then ends with .Cancelled)
	})
	defer client.sse_destroy(&sse)

	stream := client.Stream{
		// Anything but 200: cancel, the request ends with .Cancelled.
		on_head = proc(status: http.Status, headers: http.Headers, user_data: rawptr) -> bool {
			return status == .OK
		},
		on_body = proc(data: []byte, user_data: rawptr) -> bool {
			return client.sse_feed((^client.SSE)(user_data), data)
		},
	}
	res, err := client.request_stream(&req, "https://api.example.com/v1/chat/completions", stream, &sse)
	client.response_destroy(&res)
	return err
}
```

The callbacks run on the request's thread (`request_stream` runs it on a thread of its own and blocks
the caller), so share their results with other threads through a mutex or a queue.

## WebSockets

```odin
import http "libs:odin-http"
import ws "libs:odin-http/websocket"

// Server: upgrade inside any handler.
chat :: proc(req: ^http.Request, res: ^http.Response) {
	ws.upgrade(req, res, {compression = true}, {
		on_open    = proc(c: ^ws.Conn) { ws.send_text(c, "welcome") },
		on_message = proc(c: ^ws.Conn, kind: ws.Message_Kind, data: []byte) {
			ws.send(c, kind, data) // echo
		},
		on_close   = proc(c: ^ws.Conn, code: u16, reason: string) {},
	})
}

// Client: on a thread with an nbio event loop (a server thread, or your own nbio.tick loop).
connect :: proc() {
	ws.dial("wss://example.com/socket", {opts = {compression = true}}, {
		on_open    = proc(c: ^ws.Conn) { ws.send_text(c, "hello") },
		on_message = proc(c: ^ws.Conn, kind: ws.Message_Kind, data: []byte) {},
		on_close   = proc(c: ^ws.Conn, code: u16, reason: string) {},
	})
}
```

- A connection lives on one event loop thread. From other threads use `ws.handle(c)` with
  `send_from_any_thread`, `close_from_any_thread` and `broadcast` (one copy per event loop, safe after the
  connection or the server is gone). See [examples/websocket](examples/websocket/main.odin).
- `Opts`: `max_message_size` (1 MiB; compressed messages are limited after decompression),
  `send_queue_limit` (4 MiB, `send` returns `.Queue_Full` beyond it, `on_drain` when it's empty again),
  keepalive pings every 30s, `subprotocols`, `compression` (permessage-deflate).
- The server accepts browser connections only from the same origin by default (`check_origin`, against
  cross-site WebSocket hijacking); `ws.allow_any_origin` turns that off.
- `wss://` verifies the server like the HTTP client does (`Dial_Opts.tls_ca_file` for a private CA).

## Running behind Caddy

The server speaks plain HTTP/1.1; [Caddy](https://caddyserver.com) in front gives you TLS (with automatic
certificates), HTTP/2 and HTTP/3. WebSockets go through as is. Tested with Caddy 2.11 (`scripts/interop.sh`).

```caddyfile
example.com {
	reverse_proxy 127.0.0.1:8080 {
		request_buffers 64KB
	}
}
```

- Listen on `127.0.0.1` (`net.IP4_Loopback`), so clients can't bypass Caddy.
- Keep `request_buffers` (any size): it works around a race in Go's HTTP/1 server that, with a fast
  upstream, aborts about 1 in 50 concurrent POST responses (Caddy logs "aborting with incomplete response
  ... use of closed network connection").
- Set `Rate_Limit_Opts.trusted_proxies = 1`, otherwise every client shares Caddy's address. Caddy replaces
  the `X-Forwarded-For` a client sends, so it can't be spoofed.
- Keep `Server_Opts.idle_timeout` (3 minutes) above Caddy's upstream keep-alive (2 minutes).
- The WebSocket origin check works unchanged: Caddy forwards the `Host` header.

In Docker, io_uring needs a seccomp profile that allows it (e.g. `--security-opt seccomp=unconfined`);
x86-64 emulation (Rosetta) doesn't implement io_uring.

## Performance

Linux arm64 (OrbStack), server on 2 threads, wrk on 2 other cores (`bench/http.sh`):

| HTTP, keep-alive | req/s | p99 |
|---|---|---|
| plaintext, 64 connections | ~600k | 0.2-1.2ms |
| JSON | ~620k | 0.2-2.3ms |
| 64 KiB responses | ~220k | 0.8-2.4ms |
| 1 KiB POST echo | ~540-580k | 0.5-1.5ms |
| 1 MiB static file | ~14k (~14 GiB/s) | 5ms |

WebSockets, one server thread (`bench/ws.sh`): ~1.9M echoes/s of 32 bytes (p50 0.56ms), ~650k of 4 KiB,
~110k compressed 4 KiB text, broadcasts to 1000 clients ~390k deliveries/s.

## Development

```
odin-http/
├── *.odin          package http (the server)
├── client/         package client
├── websocket/      package websocket
├── openssl/        package openssl
├── examples/       runnable examples
├── tests/          unit, live-server, fuzz, client, interop and Autobahn suites
├── bench/          HTTP and WebSocket benchmarks
├── scripts/        test runners and the Linux test image
└── docs/           the audit report and work list
```

```sh
scripts/test.sh [--asan]                     # all suites, macOS or Linux
scripts/test-linux.sh [--asan] [--stress 5]  # Linux (io_uring) in docker, CPU and memory capped
scripts/test-linux.sh --hunt 40              # repeat the stress tests until one fails, with thread dumps
scripts/interop.sh                           # curl, Python and Caddy (TLS, HTTP/2) against the server and clients
tests/autobahn/run.sh                        # Autobahn TestSuite against the server (docker)
tests/autobahn/run-client.sh                 # ... against the WebSocket client
bench/http.sh 5 2fe913b .                    # HTTP benchmark, any revisions side by side
bench/ws.sh                                  # WebSocket benchmark
```

Every runner is capped (time, output, CPU, memory) so a hung test can't run away.

## License

MIT, see [LICENSE](LICENSE). Original work by Laytan Laats.
