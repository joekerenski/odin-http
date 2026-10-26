package tests_server

// Streamed request bodies (`body_stream`): large uploads, chunked framing in any split, early
// responses, limits, and the minimum transfer rate.

import "core:bytes"
import "core:fmt"
import "core:hash"
import "core:nbio"
import "core:net"
import "core:os"
import "core:strconv"
import "core:strings"
import "core:testing"
import "core:time"

import http "../.."
import "../../client"

@(private="file")
Up_Mode :: enum {
	// Asks for the next piece from the callback.
	Next,
	// Asks for the next piece from a timer (the handler doing something asynchronous).
	Async,
	// Holds each piece for 400ms.
	Hold,
	// max_length 1000.
	Limit,
	// Responds 413 on the first piece, from the callback.
	Reject,
	// Responds 413 after the first piece, from a timer.
	Reject_Timer,
	// Responds right after starting the stream, while the first read is in flight.
	Ignore,
}

@(private="file")
Up :: struct {
	req:       ^http.Request,
	res:       ^http.Response,
	mode:      Up_Mode,
	n:         int,
	pieces:    int,
	max_piece: int,
	sum:       u64,
	done:      bool,
	out:       [256]byte,
}

/*
Streams the body and responds with what it got: "n=<bytes> sum=<fnv64a> max=<largest piece>
trailer=<X-T trailer>". Paths: /up, /up-async, /up-hold, /up-limit, /up-reject, /up-reject-timer,
/up-ignore (see Up_Mode), anything else responds "hello".
*/
upload_handler :: proc() -> http.Handler {
	return http.handler(proc(req: ^http.Request, res: ^http.Response) {
		mode: Up_Mode
		switch req.url.path {
		case "/up":              mode = .Next
		case "/up-async":        mode = .Async
		case "/up-hold":         mode = .Hold
		case "/up-limit":        mode = .Limit
		case "/up-reject":       mode = .Reject
		case "/up-reject-timer": mode = .Reject_Timer
		case "/up-ignore":       mode = .Ignore
		case:
			http.respond_plain(res, "hello")
			return
		}

		up := new(Up, context.temp_allocator)
		up^ = {req = req, res = res, mode = mode, sum = 0xcbf29ce484222325}
		http.body_stream(req, 1000 if mode == .Limit else -1, up, on_piece)
		if mode == .Ignore {
			http.respond(res, http.Status.Accepted)
		}

		on_piece :: proc(up: rawptr, data: []byte, done: bool, err: http.Body_Error) {
			up := (^Up)(up)
			if err != nil {
				http.respond(up.res, http.body_error_status(err))
				return
			}
			up.n        += len(data)
			up.pieces   += 1
			up.max_piece = max(up.max_piece, len(data))
			up.sum       = hash.fnv64a(data, up.sum)
			up.done      = done

			switch up.mode {
			case .Reject:
				http.respond(up.res, http.Status.Payload_Too_Large)
				return
			case .Reject_Timer:
				nbio.timeout_poly(20 * time.Millisecond, up, proc(_: ^nbio.Operation, up: ^Up) {
					http.respond(up.res, http.Status.Payload_Too_Large)
				})
				return
			case .Next, .Limit, .Ignore:
			case .Async, .Hold:
				nbio.timeout_poly(400 * time.Millisecond if up.mode == .Hold else time.Millisecond, up, proc(_: ^nbio.Operation, up: ^Up) {
					if up.done { up_respond(up); return }
					http.body_stream_next(up.req)
				})
				return
			}
			if done { up_respond(up); return }
			http.body_stream_next(up.req)
		}

		up_respond :: proc(up: ^Up) {
			trailer, _ := http.headers_get(up.req.trailers, "x-t")
			http.respond_plain(up.res, fmt.bprintf(up.out[:], "n=%i sum=%x max=%i trailer=%s", up.n, up.sum, up.max_piece, trailer))
		}
	})
}

// The test body: a byte pattern that doesn't repeat every power of two.
@(private="file")
pattern_fill :: proc(buf: []byte, offset: int) {
	for &b, i in buf {
		p := offset + i
		b = byte(p * 7 + p >> 9)
	}
}

@(private="file")
pattern :: proc(n: int) -> []byte {
	b := make([]byte, n, context.temp_allocator)
	pattern_fill(b, 0)
	return b
}

@(private="file")
want_body :: proc(data: []byte, trailer := "") -> string {
	return fmt.tprintf("n=%i sum=%x", len(data), hash.fnv64a(data))
}

// The body as chunked transfer coding, in chunks of the given sizes (cycled).
@(private="file")
chunked :: proc(data: []byte, sizes: []int, trailers := "") -> string {
	b := strings.builder_make(context.temp_allocator)
	for i, k := 0, 0; i < len(data); k += 1 {
		n := min(sizes[k % len(sizes)], len(data) - i)
		fmt.sbprintf(&b, "%x\r\n", n)
		strings.write_bytes(&b, data[i:i + n])
		strings.write_string(&b, "\r\n")
		i += n
	}
	fmt.sbprintf(&b, "0\r\n%s\r\n", trailers)
	return strings.to_string(b)
}

@(private="file")
post :: proc(path: string, body: []byte, extra := "") -> string {
	return fmt.tprintf("POST %s HTTP/1.1\r\nHost: x\r\nContent-Length: %i\r\n%s\r\n%s", path, len(body), extra, string(body))
}

@(private="file")
post_chunked :: proc(path: string, body: string, extra := "") -> string {
	return fmt.tprintf("POST %s HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n%s\r\n%s", path, extra, body)
}

@(test)
upload_content_length :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	ts := server_start(t, upload_handler())
	defer server_stop(ts)

	data := pattern(32 << 20)
	for path in ([]string{"/up", "/up-async"}) {
		resp := roundtrip(ts, post(path, data, "Connection: close\r\n"), wait = 5 * time.Second)
		testing.expectf(t, strings.contains(resp, want_body(data)), "%s: %q", path, resp)
		// The body went through the connection's read buffer, it never grew.
		testing.expectf(t, strings.contains(resp, fmt.tprintf("max=%i", http.STREAM_BUF_SIZE)), "%s: %q", path, resp)
	}
}

// 256 MiB (4096 times the buffer) through a 64 KiB buffer, generated as it's sent.
@(test)
upload_huge :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 120 * time.Second)
	ts := server_start(t, upload_handler())
	defer server_stop(ts)

	SIZE :: 256 << 20
	c, ok := raw_dial(ts)
	testing.expect(t, ok)
	defer raw_close(c)
	raw_send(c, fmt.tprintf("POST /up HTTP/1.1\r\nHost: x\r\nContent-Length: %i\r\nConnection: close\r\n\r\n", SIZE))
	buf := make([]byte, 1 << 20, context.temp_allocator)
	sum := u64(0xcbf29ce484222325)
	for off := 0; off < SIZE; off += len(buf) {
		pattern_fill(buf, off)
		sum = hash.fnv64a(buf, sum)
		if !raw_send(c, string(buf)) { break }
	}
	resp, _ := raw_recv(c, 5 * time.Second)
	testing.expectf(t, strings.contains(resp, fmt.tprintf("n=%i sum=%x max=%i", SIZE, sum, http.STREAM_BUF_SIZE)), "%q", resp)
}

@(test)
upload_chunked :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	ts := server_start(t, upload_handler())
	defer server_stop(ts)

	// Tiny chunks (thousands buffered at once, delivered without nesting a call per chunk), a chunk
	// larger than the buffer, odd sizes, and a trailer.
	data := pattern(3 << 20)
	body := chunked(data, {1, 1, 1, 7, 200_000, 3, 1 << 20, 65_537}, "X-T: yes\r\n")
	resp := roundtrip(ts, post_chunked("/up", body, "Connection: close\r\n"), wait = 5 * time.Second)
	testing.expectf(t, strings.contains(resp, want_body(data)) && strings.contains(resp, "trailer=yes"), "%q", resp)

	resp = roundtrip(ts, post_chunked("/up-async", chunked(data[:100_000], {1, 5000}), "Connection: close\r\n"), wait = 5 * time.Second)
	testing.expectf(t, strings.contains(resp, want_body(data[:100_000])), "async: %q", resp)

	// Framing split at every byte.
	small := pattern(300)
	req := post_chunked("/up", chunked(small, {1, 7, 100}, "X-T: split\r\n"))
	c, ok := raw_dial(ts)
	testing.expect(t, ok)
	defer raw_close(c)
	net.set_option(c.sock, .TCP_Nodelay, true)
	for i in 0 ..< len(req) {
		raw_send(c, req[i:i + 1])
		if i % 4 == 0 { time.sleep(200 * time.Microsecond) }
	}
	resp, _ = raw_recv(c, 500 * time.Millisecond)
	testing.expectf(t, strings.contains(resp, want_body(small)) && strings.contains(resp, "trailer=split"), "split: %q", resp)
}

@(test)
upload_keep_alive :: proc(t: ^testing.T) {
	ts := server_start(t, upload_handler())
	defer server_stop(ts)

	data := pattern(300_000)
	reqs := strings.concatenate({
		post("/up", data),
		post_chunked("/up-async", chunked(data, {20_000})),
		"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
	}, context.temp_allocator)
	c, _ := raw_dial(ts)
	defer raw_close(c)
	raw_send(c, reqs)
	// Generous: the second body comes in pieces with a timer each, and timers are slow on a loaded machine.
	resp, _ := raw_recv(c, 5 * time.Second)
	testing.expectf(t, count_responses(resp) == 3 && strings.count(resp, want_body(data)) == 2 && strings.has_suffix(resp, "hello"), "%q", resp)
}

// The handler responds before the body ended: the (small) rest is discarded, the connection reused.
@(test)
upload_early_response_keeps_connection :: proc(t: ^testing.T) {
	ts := server_start(t, upload_handler())
	defer server_stop(ts)

	data := pattern(200_000)
	cases := []struct { req: string, status: int } {
		{post("/up-reject", data), 413},
		{post("/up-reject-timer", data), 413},
		{post_chunked("/up-reject", chunked(data, {1000})), 413},
		{post_chunked("/up-reject-timer", chunked(data, {70_000})), 413},
		{post("/up-ignore", data), 202},
	}
	for tc in cases {
		// The GET after it on the same connection, which then closes.
		resp := roundtrip(ts, strings.concatenate({tc.req, "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"}, context.temp_allocator), wait = time.Second)
		testing.expectf(t, status_of(resp) == tc.status && count_responses(resp) == 2 && strings.has_suffix(resp, "hello"), "%.60q: %q", tc.req, resp)
	}

	// The read in flight when the handler responded is waited for.
	c, _ := raw_dial(ts)
	defer raw_close(c)
	raw_send(c, "POST /up-ignore HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\n\r\n")
	time.sleep(50 * time.Millisecond)
	raw_send(c, "0123456789GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
	resp, _ := raw_recv(c, time.Second)
	testing.expectf(t, status_of(resp) == 202 && count_responses(resp) == 2 && strings.has_suffix(resp, "hello"), "in flight: %q", resp)
}

// Too much left to discard: respond, then close.
@(test)
upload_early_response_closes :: proc(t: ^testing.T) {
	ts := server_start(t, upload_handler())
	defer server_stop(ts)

	for path in ([]string{"/up-reject", "/up-reject-timer"}) {
		c, _ := raw_dial(ts)
		raw_send(c, fmt.tprintf("POST %s HTTP/1.1\r\nHost: x\r\nContent-Length: %i\r\n\r\n", path, 100 << 20))
		raw_send(c, string(pattern(100_000)))
		resp, closed := raw_recv(c, 2 * time.Second)
		testing.expectf(t, status_of(resp) == 413 && strings.contains(resp, "connection: close") && closed, "%s: %q closed=%v", path, resp, closed)
		raw_close(c)
	}

	// Chunked: it discards up to the limit, then gives up.
	c, _ := raw_dial(ts)
	defer raw_close(c)
	raw_send(c, "POST /up-reject HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n")
	raw_send(c, chunked(pattern(400_000), {10_000})[:390_000])
	resp, closed := raw_recv(c, 2 * time.Second)
	testing.expectf(t, status_of(resp) == 413 && closed, "chunked: %q closed=%v", resp, closed)
}

@(test)
upload_limits :: proc(t: ^testing.T) {
	ts := server_start(t, upload_handler())
	defer server_stop(ts)

	ok_data := pattern(1000)
	resp := roundtrip(ts, post("/up-limit", ok_data))
	testing.expectf(t, strings.contains(resp, want_body(ok_data)), "at the limit: %q", resp)

	// Content-Length over the limit: rejected before anything is read (the client didn't send it).
	resp = roundtrip(ts, "POST /up-limit HTTP/1.1\r\nHost: x\r\nContent-Length: 1001\r\n\r\n")
	testing.expectf(t, status_of(resp) == 413, "content-length: %q", resp)

	// Chunked over the limit, found at the chunk that goes over.
	resp = roundtrip(ts, post_chunked("/up-limit", chunked(pattern(1500), {600})))
	testing.expectf(t, status_of(resp) == 413, "chunked: %q", resp)

	// Not limited by max_body_size.
	opts := http.Default_Server_Opts
	opts.max_body_size = 1000
	ts2 := server_start(t, upload_handler(), opts)
	defer server_stop(ts2)
	data := pattern(100_000)
	resp = roundtrip(ts2, post("/up", data))
	testing.expectf(t, strings.contains(resp, want_body(data)), "max_body_size: %q", resp)
}

@(test)
upload_bad_framing :: proc(t: ^testing.T) {
	ts := server_start(t, upload_handler())
	defer server_stop(ts)

	bad := []string{
		"zz\r\nabc\r\n0\r\n\r\n",               // invalid size
		"3\r\nabcX\r\n0\r\n\r\n",               // data not followed by CRLF
		"3\r\nabc\r\n0\r\nnot a trailer\r\n\r\n", // bad trailer
	}
	for body in bad {
		resp := roundtrip(ts, post_chunked("/up", body))
		testing.expectf(t, status_of(resp) == 400 && count_responses(resp) == 1, "%q: %q", body, resp)
	}
}

@(test)
upload_expect_continue :: proc(t: ^testing.T) {
	ts := server_start(t, upload_handler())
	defer server_stop(ts)

	c, _ := raw_dial(ts)
	defer raw_close(c)
	data := pattern(5000)
	raw_send(c, "POST /up HTTP/1.1\r\nHost: x\r\nContent-Length: 5000\r\nExpect: 100-continue\r\n\r\n")
	resp, _ := raw_recv(c, 300 * time.Millisecond)
	testing.expectf(t, resp == "HTTP/1.1 100 Continue\r\n\r\n", "interim: %q", resp)
	raw_send(c, string(data))
	resp, _ = raw_recv(c, 300 * time.Millisecond)
	testing.expectf(t, strings.contains(resp, want_body(data)), "final: %q", resp)
}

@(test)
upload_client_disconnects :: proc(t: ^testing.T) {
	ts := server_start(t, upload_handler())
	defer server_stop(ts)

	c, _ := raw_dial(ts)
	defer raw_close(c)
	raw_send(c, "POST /up HTTP/1.1\r\nHost: x\r\nContent-Length: 100000\r\n\r\n")
	raw_send(c, string(pattern(70_000)))
	net.shutdown(c.sock, .Send)
	resp, closed := raw_recv(c, time.Second)
	testing.expectf(t, status_of(resp) == 400 && closed, "%q closed=%v", resp, closed)
}

// A client trickling the body is cut off, also when every single read is within the timeout.
@(test)
upload_min_rate :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 30 * time.Second)
	opts := http.Default_Server_Opts
	opts.body_read_timeout = 300 * time.Millisecond
	opts.body_min_rate     = 1000
	h := upload_handler()
	ts := server_start(t, h, opts)
	defer server_stop(ts)
	ts_echo := server_start(t, echo_handler(), opts)
	defer server_stop(ts_echo)

	for target in ([]struct { ts: ^Test_Server, path: string }{{ts, "/up"}, {ts_echo, "/echo"}}) {
		c, _ := raw_dial(target.ts)
		raw_send(c, fmt.tprintf("POST %s HTTP/1.1\r\nHost: x\r\nContent-Length: 1000\r\n\r\n", target.path))
		start := time.now()
		closed := false
		resp: string
		for _ in 0 ..< 60 {
			raw_send(c, "x")
			resp, closed = raw_recv(c, 100 * time.Millisecond)
			if closed || resp != "" { break }
		}
		testing.expectf(t, closed && status_of(resp) == 400, "%s: %q closed=%v", target.path, resp, closed)
		testing.expectf(t, time.since(start) < 3 * time.Second, "%s: took %v", target.path, time.since(start))
		raw_close(c)
	}

	// The time the handler holds a piece doesn't count: 400ms per piece, more than the timeout.
	c, _ := raw_dial(ts)
	defer raw_close(c)
	raw_send(c, "POST /up-hold HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\n\r\n01234")
	time.sleep(600 * time.Millisecond)
	raw_send(c, "56789")
	resp, _ := raw_recv(c, 1500 * time.Millisecond)
	testing.expectf(t, strings.contains(resp, "n=10 "), "hold: %q", resp)
}

// --- The client's side: request bodies from a `Body_Source` ---

// A source of `size` pattern bytes, handed out at most `step` at a time; `fail_at` >= 0 fails there.
@(private="file")
Gen :: struct {
	size, step, offset: int,
	fail_at:            int,
	// Claims this length (Content-Length), -1 for chunked.
	length:             int,
}

@(private="file")
gen_source :: proc(g: ^Gen) -> client.Body_Source {
	return {
		user_data = g,
		length    = g.length,
		read = proc(buf: []byte, user_data: rawptr) -> (n: int, done: bool, ok: bool) {
			g := (^Gen)(user_data)
			if g.fail_at >= 0 && g.offset >= g.fail_at { return 0, false, false }
			n = min(len(buf), g.size - g.offset, g.step)
			pattern_fill(buf[:n], g.offset)
			g.offset += n
			return n, g.offset == g.size, true
		},
	}
}

@(private="file")
gen_sum :: proc(size: int) -> u64 {
	buf := make([]byte, 1 << 20, context.temp_allocator)
	sum := u64(0xcbf29ce484222325)
	for off := 0; off < size; off += len(buf) {
		n := min(len(buf), size - off)
		pattern_fill(buf[:n], off)
		sum = hash.fnv64a(buf[:n], sum)
	}
	return sum
}

@(test)
client_upload_file :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	ts := server_start(t, upload_handler())
	defer server_stop(ts)
	defer client.close_idle_connections()

	dir, derr := os.make_directory_temp("", "odin-http-upload-*", context.temp_allocator)
	if !testing.expect(t, derr == nil) { return }
	defer os.remove_all(dir)
	path := strings.concatenate({dir, "/body.bin"}, context.temp_allocator)
	data := pattern(40 << 20)
	testing.expect(t, os.write_entire_file(path, data) == nil)

	req: client.Request
	client.request_init(&req, .Put, context.temp_allocator)
	defer client.request_destroy(&req)
	testing.expect(t, client.body_from_file(&req, path) == nil)

	url := fmt.tprintf("http://127.0.0.1:%i/up", ts.port)
	res, err := client.request(&req, url)
	testing.expectf(t, err == nil && strings.has_prefix(res.body, want_body(data)), "blocking: %v %q", err, res.body)
	client.response_destroy(&res)

	// Sent twice more: from the start again, on the same (kept-alive) connection. On this thread's
	// event loop: its pool is its own, other tests closing idle connections don't touch it.
	testing.expect(t, nbio.acquire_thread_event_loop() == nil)
	defer nbio.release_thread_event_loop()
	defer client.close_idle_connections()
	before := client.stats()
	for i in 0 ..< 2 {
		Done :: struct { res: client.Response, err: client.Error, done: bool }
		d: Done
		testing.expect(t, client.request_async(&req, url, client.Default_Opts, &d, proc(res: client.Response, err: client.Error, d: rawptr) {
			d := (^Done)(d)
			d.res, d.err, d.done = res, err, true
		}) == nil)
		for !d.done { nbio.tick(10 * time.Millisecond) }
		testing.expectf(t, d.err == nil && strings.has_prefix(d.res.body, want_body(data)), "async %i: %v %q", i, d.err, d.res.body)
		client.response_destroy(&d.res)
	}
	after := client.stats()
	testing.expectf(t, after.reused - before.reused >= 1, "the second upload didn't reuse the connection: %v -> %v", before, after)

	testing.expect(t, client.body_from_file(&req, strings.concatenate({dir, "/missing"}, context.temp_allocator)) != nil)
}

@(test)
client_upload_source :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	ts := server_start(t, upload_handler())
	defer server_stop(ts)
	defer client.close_idle_connections()
	url := fmt.tprintf("http://127.0.0.1:%i/up", ts.port)

	cases := []struct { g: Gen, err: client.Error } {
		{{size = 30 << 20, step = max(int), length = 30 << 20, fail_at = -1}, nil},
		// Chunked, in parts of every size.
		{{size = 30 << 20, step = max(int), length = -1, fail_at = -1}, nil},
		{{size = 20_000, step = 1, length = -1, fail_at = -1}, nil},
		{{size = 300_000, step = 7_777, length = -1, fail_at = -1}, nil},
		{{size = 0, step = 1, length = -1, fail_at = -1}, nil},
		{{size = 0, step = 1, length = 0, fail_at = -1}, nil},
		// Failing, and not keeping to its length.
		{{size = 1 << 20, step = 1000, length = 1 << 20, fail_at = 500_000}, .Body_Source_Failed},
		{{size = 1 << 20, step = 1000, length = -1, fail_at = 0}, .Body_Source_Failed},
		{{size = 1000, step = 100, length = 2000, fail_at = -1}, .Body_Source_Failed},
		{{size = 2000, step = 100, length = 1000, fail_at = -1}, .Body_Source_Failed},
	}
	for &tc in cases {
		req: client.Request
		client.request_init(&req, .Post, context.temp_allocator)
		req.source = gen_source(&tc.g)
		res, err := client.request(&req, url)
		if tc.err == nil {
			want := fmt.tprintf("n=%i sum=%x", tc.g.size, gen_sum(tc.g.size))
			testing.expectf(t, err == nil && strings.has_prefix(res.body, want), "%v: %v %q", tc.g, err, res.body)
		} else {
			testing.expectf(t, err == tc.err, "%v: %v, want %v", tc.g, err, tc.err)
		}
		client.response_destroy(&res)
		client.request_destroy(&req)
	}

	// A body in memory and a source at once isn't a request.
	g := Gen{size = 10, step = 10, length = 10, fail_at = -1}
	req: client.Request
	client.request_init(&req, .Post, context.temp_allocator)
	defer client.request_destroy(&req)
	req.source = gen_source(&g)
	bytes.buffer_write_string(&req.body, "x")
	_, err := client.request(&req, url)
	testing.expect_value(t, err, client.Error.Invalid_Request)
}

// The server rejects the upload early: the client stops sending and gets the response (thanks to
// the server's lingering close, also when it closes while the client is still sending).
@(test)
client_upload_rejected :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	ts := server_start(t, upload_handler())
	defer server_stop(ts)
	defer client.close_idle_connections()

	for path in ([]string{"/up-reject", "/up-reject-timer", "/up-limit"}) {
		for length in ([]int{200 << 20, -1}) {
			g := Gen{size = 200 << 20, step = max(int), length = length, fail_at = -1}
			req: client.Request
			client.request_init(&req, .Post, context.temp_allocator)
			req.source = gen_source(&g)
			start := time.tick_now()
			res, err := client.request(&req, fmt.tprintf("http://127.0.0.1:%i%s", ts.port, path))
			testing.expectf(t, err == nil && res.status == .Payload_Too_Large, "%s %i: %v %v", path, length, err, res.status)
			// It stopped sending, the server never read most of it.
			testing.expectf(t, g.offset < 20 << 20, "%s %i: %i bytes produced", path, length, g.offset)
			testing.expectf(t, time.tick_since(start) < 5 * time.Second, "%s %i: took %v", path, length, time.tick_since(start))
			client.response_destroy(&res)
			client.request_destroy(&req)
		}
	}
}

// Over TLS: the server's pieces come out of its TLS layer, the client's parts go into its own, and
// an early response is told apart from the session tickets a TLS 1.3 server sends after the
// handshake.
@(test)
tls_upload :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	opts := http.Default_Server_Opts
	opts.tls = http.TLS_Opts{cert_file = TLS_DIR + "server_a.pem", key_file = TLS_DIR + "server_a.key"}
	ts := server_start(t, upload_handler(), opts, threads = 2)
	defer server_stop(ts)
	defer client.close_idle_connections()
	copts := client.Default_Opts
	copts.tls_ca_file = TLS_DIR + "ca_a.pem"
	base := fmt.tprintf("https://localhost:%i", ts.port)

	// From memory.
	{
		data := pattern(24 << 20)
		req: client.Request
		client.request_init(&req, .Post, context.temp_allocator)
		defer client.request_destroy(&req)
		bytes.buffer_write(&req.body, data)
		res, err := client.request(&req, fmt.tprintf("%s/up", base), copts)
		testing.expectf(t, err == nil && strings.has_prefix(res.body, want_body(data)), "memory: %v %q", err, res.body)
		// Pieces are what one read of the TLS layer gives, never more than the buffer.
		max_piece, _ := strconv.parse_int(strings.split(res.body[strings.index(res.body, "max=") + 4:], " ", context.temp_allocator)[0])
		testing.expectf(t, max_piece > 0 && max_piece <= http.STREAM_BUF_SIZE, "largest piece %i", max_piece)
		client.response_destroy(&res)
	}

	// The async path (a timer per piece) with less, timers are slow on a loaded machine.
	for tc in ([]struct { size, length: int, path: string }{{30 << 20, 30 << 20, "/up"}, {30 << 20, -1, "/up"}, {1 << 20, -1, "/up-async"}}) {
		g := Gen{size = tc.size, step = max(int), length = tc.length, fail_at = -1}
		req: client.Request
		client.request_init(&req, .Post, context.temp_allocator)
		req.source = gen_source(&g)
		res, err := client.request(&req, fmt.tprintf("%s%s", base, tc.path), copts)
		want := fmt.tprintf("n=%i sum=%x", g.size, gen_sum(g.size))
		testing.expectf(t, err == nil && strings.has_prefix(res.body, want), "source %v: %v %q", tc, err, res.body)
		client.response_destroy(&res)
		client.request_destroy(&req)
	}

	for path in ([]string{"/up-reject", "/up-reject-timer"}) {
		g := Gen{size = 200 << 20, step = max(int), length = 200 << 20, fail_at = -1}
		req: client.Request
		client.request_init(&req, .Post, context.temp_allocator)
		req.source = gen_source(&g)
		res, err := client.request(&req, fmt.tprintf("%s%s", base, path), copts)
		testing.expectf(t, err == nil && res.status == .Payload_Too_Large && g.offset < 20 << 20, "%s: %v %v, %i bytes produced", path, err, res.status, g.offset)
		client.response_destroy(&res)
		client.request_destroy(&req)
	}
}
