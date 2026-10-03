# Odin HTTP

> **Personal copy of [laytan/odin-http](https://github.com/laytan/odin-http)** by Laytan Laats, with the full original history.
> It adds a hardened HTTP/1.1 server (see [audit/](audit/)) and a WebSocket server ([websocket/](websocket/)).
> Not affiliated with or endorsed by the original project. All credit for the original library goes to its author.

A HTTP/1.1 implementation for Odin purely written in Odin (besides SSL).

See generated package documentation at [odin-http.laytan.dev](https://odin-http.laytan.dev).

See below examples or the examples directory.

## Disclaimer

This is not intended for production use and serves as a proof of concept for the implementation that will be going into Odin's core collection.

## Compatibility

This is beta software, confirmed to work in my own use cases but can certainly contain edge cases and bugs that I did not catch.
Please file issues for any bug or suggestion you encounter/have.

I am usually on a recent master version of Odin and commits will be made with new features if applicable, backwards compatibility or even
stable version compatibility is not currently a thing.

Because this is still heavily in development, I do not hesitate to push API changes at the moment, so beware.

This copy targets macOS and Linux only (the upstream project also supports Windows).
Any other distributions or versions have not been tested and might not work.

## Dependencies

The *client* package depends on OpenSSL for making HTTPS requests.

For Linux, most distros come with OpenSSL, if not you can install it with a package manager, usually under `libssl3`.

The *websocket* package links the system zlib for compression (`permessage-deflate`), on Linux usually `zlib1g-dev` / `zlib-devel`.

## Performance

`bench/http.sh` (HTTP, wrk) and `bench/ws.sh` (WebSocket) run in the Linux container; `bench/http.sh 5 2fe913b .`
compares upstream's last commit with the working tree. Linux arm64 (OrbStack), 2 server threads, wrk on 2 other cores:

| | req/s | p99 |
|---|---|---|
| plaintext, 64 connections | ~600k | 0.2-1.2ms |
| JSON | ~620k | 0.2-2.3ms |
| 64 KiB responses | ~220k | 0.8-2.4ms |
| 1 KiB POST echo | ~540-580k | 0.5-1.5ms |
| 1 MiB static file | ~14k (~14 GiB/s) | 5ms |

Keep-alive throughput matches upstream; static files are about twice as fast. Throughput without keep-alive is
too noisy on this VM to compare (100k-600k for either version).

## IO implementations

Although these implementation details are not exposed when using the package, these are the underlying kernel API's that are used.

- Linux:   [io_uring](https://en.wikipedia.org/wiki/Io_uring)
- Darwin:  [KQueue](https://en.wikipedia.org/wiki/Kqueue)

The IO part of this package can be used on its own for other types of applications, see the nbio directory for the documentation on that.
It has APIs for reading, writing, opening, closing, seeking files and accepting, connecting, sending, receiving and closing sockets, both UDP and TCP, fully cross-platform.

## Server example

```odin
package main

import "core:fmt"
import "core:log"
import "core:net"
import "core:time"

import http "../.." // Change to path of package.

main :: proc() {
	context.logger = log.create_console_logger(.Info)

	s: http.Server
	// Register a graceful shutdown when the program receives a SIGINT signal.
	http.server_shutdown_on_interrupt(&s)

	// Set up routing
	router: http.Router
	http.router_init(&router)
	defer http.router_destroy(&router)

	// Routes are tried in order.
	// Route matching is implemented using an implementation of Lua patterns, see the docs on them here:
	// https://www.lua.org/pil/20.2.html
	// They are very similar to regex patterns but a bit more limited, which makes them much easier to implement since Odin does not have a regex implementation.

	// Matches /users followed by any word (alphanumeric) followed by /comments and then / with any number.
	// The captures are available as req.url_params[0] and req.url_params[1], or by name with http.url_param(req, "user").
	http.route_get(&router, "/users/:user/comments/:comment", http.handler(proc(req: ^http.Request, res: ^http.Response) {
		http.respond_plain(res, fmt.tprintf("user %s, comment: %s", req.url_params[0], req.url_params[1]))
	}))
	http.route_get(&router, "/cookies", http.handler(cookies))
	http.route_get(&router, "/api", http.handler(api))
	http.route_get(&router, "/ping", http.handler(ping))
	http.route_get(&router, "/index", http.handler(index))

	// Matches every get request that did not match another route.
	http.route_get(&router, "/*path", http.handler(static))

	http.route_post(&router, "/ping", http.handler(post_ping))

	routed := http.router_handler(&router)

	log.info("Listening on http://localhost:6969")

	err := http.listen_and_serve(&s, routed, net.Endpoint{address = net.IP4_Loopback, port = 6969})
	fmt.assertf(err == nil, "server stopped with error: %v", err)
}

cookies :: proc(req: ^http.Request, res: ^http.Response) {
	append(
		&res.cookies,
		http.Cookie{
			name         = "Session",
			value        = "123",
			expires_gmt  = time.now(),
			max_age_secs = 10,
			http_only    = true,
			same_site    = .Lax,
		},
	)
	http.respond_plain(res, "Yo!")
}

api :: proc(req: ^http.Request, res: ^http.Response) {
	if err := http.respond_json(res, req.line); err != nil {
		log.errorf("could not respond with JSON: %s", err)
	}
}

ping :: proc(req: ^http.Request, res: ^http.Response) {
	http.respond_plain(res, "pong")
}

index :: proc(req: ^http.Request, res: ^http.Response) {
	http.respond_file(res, "examples/complete/static/index.html")
}

static :: proc(req: ^http.Request, res: ^http.Response) {
	http.respond_dir(res, "/", "examples/complete/static", req.url.path)
}

post_ping :: proc(req: ^http.Request, res: ^http.Response) {
	http.body(req, len("ping"), res, proc(res: rawptr, body: http.Body, err: http.Body_Error) {
		res := cast(^http.Response)res

		if err != nil {
			http.respond(res, http.body_error_status(err))
			return
		}

		if body != "ping" {
			http.respond(res, http.Status.Unprocessable_Content)
			return
		}

		http.respond_plain(res, "pong")
	})
}
```

## Client example

```odin
package main

import "core:fmt"

import "../../client"

main :: proc() {
	get()
	post()
}

// basic get request.
get :: proc() {
	res, err := client.get("https://www.google.com/")
	if err != nil {
		fmt.printf("Request failed: %s", err)
		return
	}
	defer client.response_destroy(&res)

	fmt.printf("Status: %s\n", res.status)
	fmt.printf("Headers: %v\n", res.headers)
	fmt.printf("Cookies: %v\n", res.cookies)
	body, allocation, berr := client.response_body(&res)
	if berr != nil {
		fmt.printf("Error retrieving response body: %s", berr)
		return
	}
	defer client.body_destroy(body, allocation)

	fmt.println(body)
}

Post_Body :: struct {
	name:    string,
	message: string,
}

// POST request with JSON.
post :: proc() {
	req: client.Request
	client.request_init(&req, .Post)
	defer client.request_destroy(&req)

	pbody := Post_Body{"Laytan", "Hello, World!"}
	if err := client.with_json(&req, pbody); err != nil {
		fmt.printf("JSON error: %s", err)
		return
	}

	res, err := client.request(&req, "https://webhook.site/YOUR-ID-HERE")
	if err != nil {
		fmt.printf("Request failed: %s", err)
		return
	}
	defer client.response_destroy(&res)

	fmt.printf("Status: %s\n", res.status)
	fmt.printf("Headers: %v\n", res.headers)
	fmt.printf("Cookies: %v\n", res.cookies)

	body, allocation, berr := client.response_body(&res)
	if berr != nil {
		fmt.printf("Error retrieving response body: %s", berr)
		return
	}
	defer client.body_destroy(body, allocation)

	fmt.println(body)
}
```

## WebSockets

The `websocket` package (RFC 6455, with `permessage-deflate` from RFC 7692) has a server side, upgrading
a request inside any handler, and a client (`ws://` only). Both pass the full
[Autobahn TestSuite](https://github.com/crossbario/autobahn-testsuite) (`autobahn/run.sh`, `autobahn/run-client.sh`).

```odin
import ws "odin-http/websocket"

// Server: inside an HTTP handler.
ws.upgrade(req, res, {compression = true}, {
	on_message = proc(c: ^ws.Conn, kind: ws.Message_Kind, data: []byte) {
		ws.send(c, kind, data) // echo
	},
})

// Client: on a thread with an nbio event loop (e.g. a server thread).
ws.dial("ws://localhost:8080/chat", {opts = {compression = true}}, {
	on_open    = proc(c: ^ws.Conn) { ws.send_text(c, "hello") },
	on_message = proc(c: ^ws.Conn, kind: ws.Message_Kind, data: []byte) {},
	on_close   = proc(c: ^ws.Conn, code: u16, reason: string) {},
})
```

Connections live on one event loop thread; use `ws.handle(c)` with `ws.send_from_any_thread` / `ws.broadcast`
from other threads.

## Running behind Caddy

The server speaks plain HTTP/1.1; put [Caddy](https://caddyserver.com) in front for TLS, HTTP/2 and
HTTP/3. WebSockets go through as is. Tested with Caddy 2.11 (`scripts/interop.sh`).

```caddyfile
example.com {
	reverse_proxy 127.0.0.1:8080 {
		request_buffers 64KB
	}
}
```

- Listen on `127.0.0.1` (`net.IP4_Loopback`), so clients can't bypass Caddy.
- `request_buffers` (any size) works around a race in Go's HTTP/1 server: with a fast upstream, about 1
  in 50 concurrent POSTs gets an aborted response without it (Caddy logs "aborting with incomplete
  response ... use of closed network connection"). Caddy's experimental `enable_full_duplex` server
  option fixes it too.
- Set `Rate_Limit_Opts.trusted_proxies = 1`, otherwise every client shares Caddy's address. Caddy
  replaces the `X-Forwarded-For` a client sends, so it can't be spoofed.
- Keep `Server_Opts.idle_timeout` (default 3 minutes) above Caddy's upstream keep-alive (2 minutes).
- The WebSocket origin check works unchanged: Caddy forwards the `Host` header.

## Tests

```sh
scripts/test.sh [--asan]                     # all suites (macOS / Linux)
scripts/test-linux.sh [--asan] [--stress 5]  # Linux (io_uring) in docker, capped at 2 CPUs
scripts/test-linux.sh --hunt 40              # repeat the stress tests until one fails, with thread dumps
scripts/interop.sh                           # curl, Python and Caddy (TLS, HTTP/2) against a real server
```
