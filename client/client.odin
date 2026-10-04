/*
An HTTP/1.1 client for http:// and https:// (TLS through the system's OpenSSL, the server's
certificate and host name are always verified).

	res, err := client.get("https://example.com/")
	if err != nil { ... }
	defer client.response_destroy(&res)
	fmt.println(res.status, res.body)

`request`/`get` block the calling thread (the request runs on a thread of its own). Inside an HTTP
handler, or anywhere else an nbio event loop runs, use `request_async`, which runs on the calling
thread's event loop.

Responses are read completely, within `Opts` limits. To process a body as it arrives (a large
download, Server-Sent Events from a streaming API), use `request_stream` / `request_stream_async`
with a `Stream`; `SSE` (sse.odin) parses an event stream. Connections are reused (keep-alive)
unless `Opts.disable_keep_alive` is set.
*/
package client

import "core:bytes"
import "core:encoding/json"
import "core:io"
import "core:mem"
import "core:mem/virtual"
import "core:strings"
import "core:thread"
import "core:time"

import http ".."

Opts :: struct {
	// Establishing the TCP connection, defaults to 10s.
	connect_timeout: time.Duration,
	// The whole request: connecting, TLS, sending the request and receiving the complete
	// response. Defaults to 60s. When streaming, only until the response head has arrived: a
	// body that keeps coming can take as long as it takes (see `stall_timeout`).
	timeout:         time.Duration,
	// The longest wait for any single read, so a server that goes quiet fails even while the
	// total `timeout` has time left. Off by default; 60s when streaming.
	stall_timeout:   time.Duration,
	// Limits on the response: status line and header section (and, separately, trailers) in
	// bytes, defaults to 64 KiB; header count, defaults to 100; body, defaults to 16 MiB (when
	// streaming: any one chunk of a chunked body, the body itself isn't kept).
	max_header_size: int,
	max_headers:     int,
	max_body_size:   int,
	// https://: a PEM file with the CA certificates to trust instead of the system's (e.g. a
	// private CA). Verification can't be turned off.
	tls_ca_file:     string,

	// Connections are kept open after a request and reused for the next one to the same origin
	// (see pool.odin), unless this is set.
	disable_keep_alive: bool,
	// How long an idle connection is kept, defaults to 30s (servers often close theirs after a
	// minute or more). How many are kept per origin, defaults to 4.
	idle_timeout:       time.Duration,
	max_idle_per_host:  int,
}

Default_Opts :: Opts{
	connect_timeout = 10 * time.Second,
	timeout         = 60 * time.Second,
	max_header_size = 64 * mem.Kilobyte,
	max_headers     = 100,
	max_body_size   = 16 * mem.Megabyte,
	idle_timeout    = 30 * time.Second,
	max_idle_per_host = 4,
}

Error :: enum u8 {
	None,
	// Not an http:// or https:// URL with a host, or it contains user info.
	Invalid_URL,
	Unsupported_Scheme,
	// A request header or cookie that isn't valid (or a header the client sets itself:
	// Content-Length, Transfer-Encoding, Connection, TE, Trailer, Upgrade).
	Invalid_Request,
	// The host name could not be resolved (resolution is blocking).
	Resolve_Failed,
	Connect_Failed,
	// `connect_timeout` or `timeout` passed.
	Timeout,
	// OpenSSL could not be set up, e.g. `tls_ca_file` couldn't be loaded.
	TLS_Setup_Failed,
	// The server's certificate isn't trusted or isn't for the host (the reason is logged at info level).
	TLS_Verification_Failed,
	TLS_Failed,
	Network_Error,
	// The connection ended before a complete response head arrived.
	Connection_Closed,
	// The connection ended in the middle of the body.
	Truncated,
	Invalid_Response,
	// Over one of the `Opts` limits.
	Response_Too_Large,
	// A Transfer-Encoding other than chunked (the client never asks for one).
	Unsupported_Encoding,
	// A `Stream` callback returned false.
	Cancelled,
}

Request :: struct {
	method:  http.Method,
	headers: http.Headers,
	cookies: [dynamic]http.Cookie,
	body:    bytes.Buffer,
}

// Initializes the request with sane defaults using the given allocator.
request_init :: proc(r: ^Request, method := http.Method.Get, allocator := context.allocator) {
	r.method = method
	http.headers_init(&r.headers, allocator)
	r.cookies = make([dynamic]http.Cookie, allocator)
	bytes.buffer_init_allocator(&r.body, 0, 0, allocator)
}

// Destroys the request.
// Header keys and values that the user added will have to be deleted by the user.
// Same with any strings inside the cookies.
request_destroy :: proc(r: ^Request) {
	delete(r.headers._kv)
	delete(r.cookies)
	bytes.buffer_destroy(&r.body)
}

// Sets the body to `v` as JSON (and the method to POST if it was GET).
with_json :: proc(r: ^Request, v: any, opt: json.Marshal_Options = {}) -> json.Marshal_Error {
	if r.method == .Get { r.method = .Post }
	http.headers_set_content_type(&r.headers, http.mime_to_content_type(.Json))

	stream := bytes.buffer_to_stream(&r.body)
	opt := opt
	json.marshal_to_writer(io.to_writer(stream), v, &opt) or_return
	return nil
}

Response :: struct {
	status:   http.Status,
	// Lower-case names, repeated headers joined with ", ". Read-only.
	headers:  http.Headers,
	// Trailer fields of a chunked body. Read-only.
	trailers: http.Headers,
	// From the Set-Cookie headers (unparseable ones are skipped).
	cookies:  []http.Cookie,
	body:     string,

	_arena:     ^virtual.Arena,
	_body:      [dynamic]byte,
	_allocator: mem.Allocator,
}

// Frees everything the response holds (its headers, cookies and body included).
response_destroy :: proc(res: ^Response) {
	if res._arena != nil {
		virtual.arena_destroy(res._arena)
		free(res._arena, res._allocator)
	}
	delete(res._body)
	res^ = {}
}

/*
Called with the response, which then belongs to the callee (`response_destroy`), or with an error
(and nothing to free).
*/
Callback :: #type proc(res: Response, err: Error, user_data: rawptr)

/*
Sends `req` to `url` on the calling thread's nbio event loop. Returns right away; `cb` is called on
this thread once the response is complete or the request failed.

An error is returned (and `cb` isn't called) when the URL or request is invalid, the host can't be
resolved (resolution is blocking) or TLS can't be set up. `req` is serialized before this returns,
it can be destroyed right away.

`allocator` must be usable from the event loop's thread, it holds the response.
*/
request_async :: proc(req: ^Request, url: string, opts: Opts, user_data: rawptr, cb: Callback, allocator := context.allocator) -> Error {
	return start(req, url, with_defaults(opts), user_data, cb, allocator)
}

/*
Sends `req` to `url` and waits for the complete response. Free it with `response_destroy`.

The request runs on a thread of its own (with its own event loop), so this can be called from any
thread, but it blocks the caller: in an HTTP handler use `request_async` instead.
*/
request :: proc(req: ^Request, url: string, opts := Default_Opts, allocator := context.allocator) -> (res: Response, err: Error) {
	Blocking :: struct {
		req:       ^Request,
		url:       string,
		opts:      Opts,
		allocator: mem.Allocator,
		res:       Response,
		err:       Error,
		done:      bool,
	}
	b := Blocking{req = req, url = url, opts = opts, allocator = allocator}

	t := thread.create_and_start_with_poly_data(&b, proc(b: ^Blocking) {
		if err := acquire_loop(); err != nil {
			b.err = .Network_Error
			return
		}
		defer release_loop()

		b.err = request_async(b.req, b.url, b.opts, b, proc(res: Response, err: Error, user_data: rawptr) {
			b := (^Blocking)(user_data)
			b.res, b.err, b.done = res, err, true
		}, b.allocator)
		if b.err != nil { return }
		for !b.done {
			if tick_loop() != nil {
				// Not expected; the request's own timeouts bound this otherwise.
				break
			}
		}
	}, init_context = context)
	thread.join(t)
	thread.destroy(t)
	return b.res, b.err
}

/*
Callbacks for a streamed response. Both run on the thread doing the request (the event loop's for
`request_stream_async`, the request's own thread for `request_stream`) and get the request's
`user_data`. Returning false cancels the request: it ends with `.Cancelled` and the connection is
closed. Callbacks never run after the request's `Callback`, or after `request_stream` returned.
*/
Stream :: struct {
	// The final response's status and headers (read-only, valid until the request ends), before
	// any of its body. Optional.
	on_head: proc(status: http.Status, headers: http.Headers, user_data: rawptr) -> bool,
	// The body as it arrives, its framing removed, in order. `data` is only valid during the call.
	on_body: proc(data: []byte, user_data: rawptr) -> bool,
}

/*
`request_async`, with the body handed to `stream` as it arrives instead of collected: the response
given to `cb` has the status, headers and trailers, and an empty body. `timeout` covers the request
until its response head; after that `stall_timeout` (60s unless set) bounds each wait for more.
*/
request_stream_async :: proc(req: ^Request, url: string, opts: Opts, stream: Stream, user_data: rawptr, cb: Callback, allocator := context.allocator) -> Error {
	assert(stream.on_body != nil, "client: a Stream needs on_body")
	return start(req, url, stream_defaults(opts), user_data, cb, allocator, stream, user_data)
}

/*
`request`, with the body handed to `stream` as it arrives (see `request_stream_async`). Blocks
until the response is complete, cancelled or failed; the callbacks run on the request's own thread
meanwhile, so data they share with other threads needs synchronizing. The returned response has
an empty body.
*/
request_stream :: proc(req: ^Request, url: string, stream: Stream, user_data: rawptr, opts := Default_Opts, allocator := context.allocator) -> (res: Response, err: Error) {
	assert(stream.on_body != nil, "client: a Stream needs on_body")
	Blocking :: struct {
		req:       ^Request,
		url:       string,
		opts:      Opts,
		stream:    Stream,
		user_data: rawptr,
		allocator: mem.Allocator,
		res:       Response,
		err:       Error,
		done:      bool,
	}
	b := Blocking{req = req, url = url, opts = opts, stream = stream, user_data = user_data, allocator = allocator}

	t := thread.create_and_start_with_poly_data(&b, proc(b: ^Blocking) {
		if err := acquire_loop(); err != nil {
			b.err = .Network_Error
			return
		}
		defer release_loop()

		b.err = start(b.req, b.url, stream_defaults(b.opts), b, proc(res: Response, err: Error, user_data: rawptr) {
			b := (^Blocking)(user_data)
			b.res, b.err, b.done = res, err, true
		}, b.allocator, b.stream, b.user_data)
		if b.err != nil { return }
		for !b.done {
			if tick_loop() != nil { break }
		}
	}, init_context = context)
	thread.join(t)
	thread.destroy(t)
	return b.res, b.err
}

@(private)
stream_defaults :: proc(opts: Opts) -> Opts {
	o := with_defaults(opts)
	if o.stall_timeout <= 0 { o.stall_timeout = 60 * time.Second }
	return o
}

// A GET request, see `request`.
get :: proc(url: string, opts := Default_Opts, allocator := context.allocator) -> (Response, Error) {
	r: Request
	request_init(&r, .Get, allocator)
	defer request_destroy(&r)
	return request(&r, url, opts, allocator)
}

@(private)
with_defaults :: proc(opts: Opts) -> Opts {
	o := opts
	if o.connect_timeout <= 0 { o.connect_timeout = Default_Opts.connect_timeout }
	if o.timeout <= 0         { o.timeout         = Default_Opts.timeout }
	if o.max_header_size <= 0 { o.max_header_size = Default_Opts.max_header_size }
	if o.max_headers <= 0     { o.max_headers     = Default_Opts.max_headers }
	if o.max_body_size <= 0   { o.max_body_size   = Default_Opts.max_body_size }
	if o.idle_timeout <= 0    { o.idle_timeout    = Default_Opts.idle_timeout }
	if o.max_idle_per_host <= 0 { o.max_idle_per_host = Default_Opts.max_idle_per_host }
	return o
}

// Headers the client sets itself (framing, connection management); a request can't set them.
@(private)
RESERVED_HEADERS :: [?]string{"content-length", "transfer-encoding", "connection", "te", "trailer", "upgrade"}

/*
The request as sent: request line, headers (Host, User-Agent and Accept unless set, Connection:
close unless `keep_alive`, Content-Length when there is a body or the method expects one), cookies,
body. Header names must be tokens and values field-content, cookies must be valid: nothing is
escaped, an invalid request is refused.
*/
format_request :: proc(req: ^Request, t: Target, keep_alive := false, allocator := context.allocator) -> (out: []byte, err: Error) {
	sb := strings.builder_make(0, bytes.buffer_length(&req.body) + 256, allocator)
	defer if err != nil { strings.builder_destroy(&sb) }

	strings.write_string(&sb, http.method_string(req.method))
	strings.write_byte(&sb, ' ')
	strings.write_string(&sb, t.target)
	strings.write_string(&sb, " HTTP/1.1\r\n")

	for name, value in req.headers._kv {
		if !http.is_token(name) || !http.is_field_value(value) { return nil, .Invalid_Request }
		for reserved in RESERVED_HEADERS {
			if http.ascii_equal_fold(name, reserved) { return nil, .Invalid_Request }
		}
	}

	if _, has := http.headers_get(req.headers, "host"); !has {
		strings.write_string(&sb, "host: ")
		strings.write_string(&sb, t.host_header)
		strings.write_string(&sb, "\r\n")
	}
	if _, has := http.headers_get(req.headers, "user-agent"); !has {
		strings.write_string(&sb, "user-agent: odin-http\r\n")
	}
	if _, has := http.headers_get(req.headers, "accept"); !has {
		strings.write_string(&sb, "accept: */*\r\n")
	}
	if !keep_alive { strings.write_string(&sb, "connection: close\r\n") }

	body_len := bytes.buffer_length(&req.body)
	if body_len > 0 || req.method == .Post || req.method == .Put || req.method == .Patch {
		strings.write_string(&sb, "content-length: ")
		strings.write_int(&sb, body_len)
		strings.write_string(&sb, "\r\n")
	}

	for name, value in req.headers._kv {
		strings.write_string(&sb, name)
		strings.write_string(&sb, ": ")
		strings.write_string(&sb, value)
		strings.write_string(&sb, "\r\n")
	}

	if len(req.cookies) > 0 {
		strings.write_string(&sb, "cookie: ")
		for cookie, i in req.cookies {
			if !http.cookie_valid(cookie) { return nil, .Invalid_Request }
			if i > 0 { strings.write_string(&sb, "; ") }
			strings.write_string(&sb, cookie.name)
			strings.write_byte(&sb, '=')
			strings.write_string(&sb, cookie.value)
		}
		strings.write_string(&sb, "\r\n")
	}

	strings.write_string(&sb, "\r\n")
	strings.write_bytes(&sb, bytes.buffer_to_bytes(&req.body))
	return sb.buf[:], .None
}
