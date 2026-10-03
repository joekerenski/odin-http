package tests_server

// The HTTP client (package client) against our own server and against canned (malformed,
// truncated, slow) responses.

import "core:bytes"
import "core:fmt"
import "core:io"
import "core:nbio"
import "core:net"
import "core:strconv"
import "core:strings"
import "core:sync"
import "core:testing"
import "core:thread"
import "core:time"

import http "../.."
import "../../client"

@(private="file")
pattern :: proc(n: int, allocator := context.temp_allocator) -> []byte {
	b := make([]byte, n, allocator)
	for &c, i in b { c = byte(i % 251) }
	return b
}

// The port of the server the /proxy route calls (itself).
@(private="file")
proxy_port: int

@(private="file")
client_handler :: proc() -> http.Handler {
	return http.handler(proc(req: ^http.Request, res: ^http.Response) {
		switch req.url.path {
		case "/pattern":
			n, _ := strconv.parse_int(http.query_get(req.url, "size"))
			res.status = .OK
			http.body_set(res, pattern(n))
			http.respond(res)
		case "/echo":
			http.body(req, -1, res, proc(res: rawptr, body: http.Body, err: http.Body_Error) {
				res := (^http.Response)(res)
				if err != nil {
					http.respond(res, http.body_error_status(err))
					return
				}
				http.respond_plain(res, body)
			})
		case "/inspect":
			// What the client sent, and two cookies back.
			trace, _ := http.headers_get(req.headers, "x-trace")
			cookie, _ := http.headers_get(req.headers, "cookie")
			append(&res.cookies, http.Cookie{name = "a", value = "1", http_only = true}, http.Cookie{name = "b", value = "2"})
			http.respond_plain(res, fmt.tprintf("%s %s %s", http.method_string(req.line.(http.Requestline).method), trace, cookie))
		case "/stream":
			res.status = .OK
			rw: http.Response_Writer
			w := http.response_writer_init(&rw, res, nil)
			for i in 0 ..< 1000 { fmt.wprintf(w, "line %i\n", i) }
			io.close(w)
		case "/empty":
			http.respond(res, http.Status.No_Content)
		case "/proxy":
			// A handler calling another server (here: this one) without blocking its thread.
			r: client.Request
			client.request_init(&r, .Get, context.temp_allocator)
			err := client.request_async(&r, fmt.tprintf("http://127.0.0.1:%i/pattern?size=100000", proxy_port), client.Default_Opts, res, proc(up: client.Response, err: client.Error, user_data: rawptr) {
				res := (^http.Response)(user_data)
				if err != nil {
					http.respond_plain(res, fmt.tprint("upstream failed:", err), .Bad_Gateway)
					return
				}
				up := up
				defer client.response_destroy(&up)
				ok := bytes.equal(transmute([]byte)up.body, pattern(100000))
				http.respond_plain(res, fmt.tprintf("upstream %v %i %v", int(up.status), len(up.body), ok))
			})
			if err != nil { http.respond_plain(res, fmt.tprint("request_async:", err), .Bad_Gateway) }
		case:
			http.respond(res, http.Status.Not_Found)
		}
	})
}

@(test)
client_against_server :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	q: Quarantine
	context.allocator = quarantine_allocator(&q)
	ts := server_start(t, client_handler(), threads = 2)
	defer server_stop(ts)
	proxy_port = ts.port
	base := fmt.tprintf("http://127.0.0.1:%i", ts.port)

	{
		res, err := client.get(fmt.tprintf("%s/pattern?size=%i", base, 3_000_000))
		testing.expect_value(t, err, client.Error.None)
		testing.expect_value(t, res.status, http.Status.OK)
		testing.expectf(t, bytes.equal(transmute([]byte)res.body, pattern(3_000_000)), "body of %i bytes", len(res.body))
		client.response_destroy(&res)
	}
	{
		req: client.Request
		client.request_init(&req, .Post, context.temp_allocator)
		data := pattern(500_000)
		bytes.buffer_write(&req.body, data)
		res, err := client.request(&req, fmt.tprintf("%s/echo", base))
		testing.expect(t, err == nil && bytes.equal(transmute([]byte)res.body, data))
		client.response_destroy(&res)
	}
	{
		req: client.Request
		client.request_init(&req, .Put, context.temp_allocator)
		http.headers_set(&req.headers, "X-Trace", "t-1")
		append(&req.cookies, http.Cookie{name = "session", value = "s1"})
		res, err := client.request(&req, fmt.tprintf("%s/inspect", base))
		testing.expectf(t, err == nil && res.body == "PUT t-1 session=s1", "%v %q", err, res.body)
		testing.expectf(t, len(res.cookies) == 2 && res.cookies[0].name == "a" && res.cookies[0].http_only && res.cookies[1].value == "2", "%v", res.cookies)
		client.response_destroy(&res)
	}
	{
		res, err := client.get(fmt.tprintf("%s/stream", base))
		want := strings.builder_make(context.temp_allocator)
		for i in 0 ..< 1000 { fmt.sbprintf(&want, "line %i\n", i) }
		testing.expectf(t, err == nil && res.body == strings.to_string(want), "%v %i", err, len(res.body))
		testing.expect_value(t, http.headers_get_unsafe(res.headers, "transfer-encoding"), "chunked")
		client.response_destroy(&res)
	}
	{
		req: client.Request
		client.request_init(&req, .Head, context.temp_allocator)
		res, err := client.request(&req, fmt.tprintf("%s/pattern?size=%i", base, 1000))
		testing.expectf(t, err == nil && res.status == .OK && res.body == "" && http.headers_get_unsafe(res.headers, "content-length") == "1000", "%v %v", err, res.headers)
		client.response_destroy(&res)
	}
	{
		res, err := client.get(fmt.tprintf("%s/empty", base))
		testing.expect(t, err == nil && res.status == .No_Content && res.body == "")
		client.response_destroy(&res)
	}
	{
		// Over the body limit.
		res, err := client.get(fmt.tprintf("%s/pattern?size=%i", base, 2000), {max_body_size = 1000})
		testing.expect_value(t, err, client.Error.Response_Too_Large)
		client.response_destroy(&res)
	}
	{
		// request_async inside a handler.
		res, err := client.get(fmt.tprintf("%s/proxy", base))
		testing.expectf(t, err == nil && res.body == "upstream 200 100000 true", "%v %q", err, res.body)
		client.response_destroy(&res)
	}
}

// Many requests at once on the calling thread's event loop.
@(test)
client_async_concurrent :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	q: Quarantine
	context.allocator = quarantine_allocator(&q)
	ts := server_start(t, client_handler(), threads = 2)
	defer server_stop(ts)

	nbio.acquire_thread_event_loop()
	defer nbio.release_thread_event_loop()

	State :: struct { t: ^testing.T, done, ok: int }
	s := State{t = t}
	N :: 50
	for i in 0 ..< N {
		r: client.Request
		client.request_init(&r, .Post, context.temp_allocator)
		bytes.buffer_write(&r.body, pattern(i * 1000))
		err := client.request_async(&r, fmt.tprintf("http://127.0.0.1:%i/echo", ts.port), client.Default_Opts, &s, proc(res: client.Response, err: client.Error, user_data: rawptr) {
			s := (^State)(user_data)
			s.done += 1
			res := res
			defer client.response_destroy(&res)
			if err == nil && res.status == .OK && bytes.equal(transmute([]byte)res.body, pattern(len(res.body))) { s.ok += 1 }
		})
		testing.expect_value(t, err, client.Error.None)
	}
	start := time.tick_now()
	for s.done < N && time.tick_since(start) < 30 * time.Second { nbio.tick(10 * time.Millisecond) }
	testing.expectf(t, s.done == N && s.ok == N, "%i done, %i ok", s.done, s.ok)
}

// --- Canned responses ---

@(private="file")
Canned :: struct {
	sock:      net.TCP_Socket,
	port:      int,
	// One response per connection, in order; written after the request head arrived.
	responses: []string,
	// Keep each connection open this long after writing, then close it.
	hold:      time.Duration,
	thread:    ^thread.Thread,
	served:    int,
	mu:        sync.Mutex,
}

@(private="file")
canned_start :: proc(responses: []string, hold: time.Duration = 0) -> ^Canned {
	c := new(Canned)
	c.responses, c.hold = responses, hold
	err: net.Network_Error
	c.sock, err = net.listen_tcp({net.IP4_Loopback, 0})
	assert(err == nil)
	ep, _ := net.bound_endpoint(c.sock)
	c.port = ep.port
	// accept gives up after a while, so a test that never connects can't hang the thread.
	net.set_option(c.sock, .Receive_Timeout, 5 * time.Second)

	c.thread = thread.create_and_start_with_poly_data(c, proc(c: ^Canned) {
		for resp in c.responses {
			conn, _, err := net.accept_tcp(c.sock)
			if err != nil { return }
			net.set_option(conn, .Receive_Timeout, 2 * time.Second)
			// Read the request head.
			head: [dynamic]byte
			buf: [4096]byte
			for !strings.contains(string(head[:]), "\r\n\r\n") {
				n, rerr := net.recv_tcp(conn, buf[:])
				if rerr != nil || n == 0 { break }
				append(&head, ..buf[:n])
			}
			delete(head)
			if resp != "" { net.send_tcp(conn, transmute([]byte)resp) }
			if c.hold > 0 { time.sleep(c.hold) }
			net.close(conn)
			sync.atomic_add(&c.served, 1)
		}
	}, context)
	return c
}

@(private="file")
canned_stop :: proc(c: ^Canned) {
	net.close(c.sock)
	thread.join(c.thread)
	thread.destroy(c.thread)
	free(c)
}

@(test)
client_canned_responses :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	q: Quarantine
	context.allocator = quarantine_allocator(&q)

	Case :: struct { response: string, err: client.Error, status: int, body: string }
	cases := []Case{
		{"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nshort", .Truncated, 0, ""},
		{"", .Connection_Closed, 0, ""},
		{"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhel", .Truncated, 0, ""},
		{"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\nX-Sum: 9\r\n\r\n", .None, 200, "abc"},
		{"HTTP/1.0 200 OK\r\n\r\nuntil close", .None, 200, "until close"},
		{"HTTP/1.1 599 Weird\r\nContent-Length: 2\r\n\r\nok", .None, 599, "ok"},
		{strings.concatenate({"HTTP/1.1 200 OK\r\nX: ", strings.repeat("a", 100_000, context.temp_allocator), "\r\n\r\n"}, context.temp_allocator), .Response_Too_Large, 0, ""},
		{"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 3\r\n\r\nabc", .Invalid_Response, 0, ""},
		{"SSH-2.0-OpenSSH_9.6\r\n", .Invalid_Response, 0, ""},
	}
	responses := make([]string, len(cases), context.temp_allocator)
	for c, i in cases { responses[i] = c.response }
	srv := canned_start(responses)

	for c in cases {
		res, err := client.get(fmt.tprintf("http://127.0.0.1:%i/", srv.port))
		testing.expectf(t, err == c.err, "%.40q: %v, want %v", c.response, err, c.err)
		if err == nil {
			testing.expectf(t, int(res.status) == c.status && res.body == c.body, "%.40q: %v %q", c.response, res.status, res.body)
		}
		if c.err == nil && c.status == 200 && strings.contains(c.response, "X-Sum") {
			testing.expect_value(t, http.headers_get_unsafe(res.trailers, "x-sum"), "9")
		}
		client.response_destroy(&res)
	}
	canned_stop(srv)
}

@(test)
client_timeouts_and_failures :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	q: Quarantine
	context.allocator = quarantine_allocator(&q)

	// A server that never answers: the total timeout.
	{
		srv := canned_start({""}, hold = 3 * time.Second)
		start := time.tick_now()
		res, err := client.get(fmt.tprintf("http://127.0.0.1:%i/", srv.port), {timeout = 300 * time.Millisecond})
		elapsed := time.tick_since(start)
		testing.expectf(t, err == .Timeout && elapsed < 2 * time.Second, "%v after %v", err, elapsed)
		client.response_destroy(&res)
		canned_stop(srv)
	}
	// TLS to a server that doesn't speak it.
	{
		srv := canned_start({"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"})
		res, err := client.get(fmt.tprintf("https://127.0.0.1:%i/", srv.port))
		testing.expect_value(t, err, client.Error.TLS_Failed)
		client.response_destroy(&res)
		canned_stop(srv)
	}
	// Nothing listening.
	{
		srv := canned_start({})
		port := srv.port
		canned_stop(srv)
		res, err := client.get(fmt.tprintf("http://127.0.0.1:%i/", port))
		testing.expect_value(t, err, client.Error.Connect_Failed)
		client.response_destroy(&res)
	}
	// Refused before anything is sent.
	Sync :: struct { url: string, err: client.Error, ca: string }
	for c in ([]Sync{
		{"ftp://x/", .Unsupported_Scheme, ""},
		{"http://user@x/", .Invalid_URL, ""},
		{"http://does-not-exist.invalid/", .Resolve_Failed, ""},
		{"https://127.0.0.1:1/", .TLS_Setup_Failed, "/does/not/exist.pem"},
	}) {
		res, err := client.get(c.url, {tls_ca_file = c.ca})
		testing.expectf(t, err == c.err, "%q: %v, want %v", c.url, err, c.err)
		client.response_destroy(&res)
	}
}
