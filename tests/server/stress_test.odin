package tests_server

// Stress tests: a multi-threaded server under concurrent, messy traffic for a fixed time.
//
// Every test checks that valid exchanges get exactly the right response, that the server gets back
// to zero connections once the clients are gone, that it still serves afterwards, and (with
// -define:ODIN_TEST_FAIL_ON_BAD_MEMORY=true, as scripts/test.sh runs it) that nothing leaks.
//
// Off by default (STRESS_SECONDS=0), run them with scripts/test-linux.sh --stress SECONDS, which caps
// the container's CPU and memory and kills steps that run too long or log too much.
// Heavier runs: -define:STRESS_SERVER_THREADS=4 -define:STRESS_WORKERS=12.

import "core:io"
import "core:log"
import "core:math/rand"
import "core:nbio"
import "core:net"
import "core:strconv"
import "core:strings"
import "core:sync"
import "core:sys/posix"
import "core:testing"
import "core:thread"
import "core:time"

import http "../.."
import ws "../../websocket"

STRESS_SECONDS :: #config(STRESS_SECONDS, 0)

@(private="file") SERVER_THREADS :: #config(STRESS_SERVER_THREADS, 2)
@(private="file") HTTP_WORKERS   :: #config(STRESS_WORKERS, 4)
@(private="file") WS_WORKERS     :: #config(STRESS_WORKERS, 4)

// Skips the test when stress tests are off, otherwise fails it if it runs well past its budget
// (the runner then stops the test; scripts/test.sh kills the process if server threads hang on).
@(private="file")
stress_begin :: proc(t: ^testing.T) -> bool {
	if STRESS_SECONDS <= 0 { return false }
	testing.set_fail_timeout(t, STRESS_SECONDS * time.Second + 30 * time.Second)
	return true
}

@(private="file")
big_body: [64 * 1024]byte

// Timeouts relaxed enough for loaded/sanitized runs, short enough to matter.
@(private="file")
stress_opts :: proc() -> http.Server_Opts {
	opts := http.Default_Server_Opts
	opts.idle_timeout      = 2 * time.Second
	opts.header_timeout    = 2 * time.Second
	opts.body_read_timeout = 2 * time.Second
	opts.write_timeout     = 2 * time.Second
	opts.shutdown_timeout  = 1 * time.Second
	return opts
}

// --- Shared bookkeeping ---

@(private="file")
Stress :: struct {
	t:         ^testing.T,
	port:      int,
	mu:        sync.Mutex,
	failures:  int,
	exchanges: int, // atomic
	stop:      bool, // atomic: workers finish their session and exit
	lenient:   bool, // atomic: the server is going away, errors are expected
	// WebSocket connections that are open on the server, for the broadcaster.
	ws_handles: [dynamic]ws.Handle,
}

@(private="file")
fail :: proc(s: ^Stress, format: string, args: ..any) {
	if sync.atomic_load(&s.lenient) { return }
	sync.guard(&s.mu)
	s.failures += 1
	if s.failures <= 5 {
		testing.expectf(s.t, false, format, ..args)
	}
}

@(private="file")
run_workers :: proc(s: ^Stress, n: int, work: proc(s: ^Stress), threads: ^[dynamic]^thread.Thread) {
	for _ in 0 ..< n {
		th := thread.create_and_start_with_poly_data2(s, work, proc(s: ^Stress, work: proc(s: ^Stress)) {
			state := rand.create(rand.uint64())
			context.random_generator = rand.default_random_generator(&state)
			for !sync.atomic_load(&s.stop) {
				work(s)
				free_all(context.temp_allocator)
			}
		}, context)
		append(threads, th)
	}
}

@(private="file")
join_all :: proc(threads: ^[dynamic]^thread.Thread) {
	for th in threads {
		thread.join(th)
		thread.destroy(th)
	}
	clear(threads)
}

// Waits until the server has no connections left, they were all closed by the clients.
@(private="file")
expect_drained :: proc(t: ^testing.T, ts: ^Test_Server, loc := #caller_location) {
	start := time.tick_now()
	for sync.atomic_load(&ts.server.conn_count.raw) > 0 && time.tick_since(start) < 5 * time.Second {
		time.sleep(10 * time.Millisecond)
	}
	n := sync.atomic_load(&ts.server.conn_count.raw)
	testing.expectf(t, n == 0, "%i connections still open 5s after all clients left", n, loc = loc)
}

@(private="file")
expect_healthy :: proc(t: ^testing.T, ts: ^Test_Server, loc := #caller_location) {
	resp := roundtrip(ts, "GET /plain HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n", 2 * time.Second)
	testing.expectf(t, status_of(resp) == 200 && strings.has_suffix(resp, "hello"), "server unhealthy after load: %q", resp, loc = loc)
}

// --- Server side ---

//   /echo    echoes the body (chunked or not)
//   /big     64 KiB
//   /slow    responds 1-30ms later from a timer (the client may be gone by then)
//   /stream  chunked response
//   /ws      WebSocket echo, registered for broadcasts
//   other    "hello"
@(private="file")
stress_handler :: proc(s: ^Stress) -> http.Handler {
	return {
		user_data = s,
		handle = proc(h: ^http.Handler, req: ^http.Request, res: ^http.Response) {
			switch req.url.path {
			case "/echo":
				http.body(req, 1 << 20, res, proc(res: rawptr, body: http.Body, err: http.Body_Error) {
					res := (^http.Response)(res)
					if err != nil {
						http.respond(res, http.body_error_status(err))
						return
					}
					http.respond_plain(res, body)
				})
			case "/big":
				http.respond_plain(res, string(big_body[:]))
			case "/slow":
				delay := time.Duration(1 + (uintptr(res) >> 4) % 30) * time.Millisecond
				nbio.timeout_poly(delay, res, proc(_: ^nbio.Operation, res: ^http.Response) {
					http.respond_plain(res, "slow")
				})
			case "/stream":
				res.status = .OK
				rw: http.Response_Writer
				w := http.response_writer_init(&rw, res, nil)
				io.write_string(w, "streamed ")
				io.write_string(w, "body")
				io.close(w)
			case "/ws":
				ws.upgrade(req, res, {max_message_size = 1 << 20, ping_interval = -1}, {
					user_data = h.user_data,
					on_open = proc(c: ^ws.Conn) {
						s := (^Stress)(c.user_data)
						sync.guard(&s.mu)
						append(&s.ws_handles, ws.handle(c))
					},
					on_message = proc(c: ^ws.Conn, kind: ws.Message_Kind, data: []byte) {
						ws.send(c, kind, data)
					},
					on_close = proc(c: ^ws.Conn, _: u16, _: string) {
						s := (^Stress)(c.user_data)
						h := ws.handle(c)
						sync.guard(&s.mu)
						for other, i in s.ws_handles {
							if other.id == h.id {
								unordered_remove(&s.ws_handles, i)
								break
							}
						}
					},
				})
			case:
				http.respond_plain(res, "hello")
			}
		},
	}
}

// --- HTTP client side ---

@(private="file")
Client :: struct {
	sock: net.TCP_Socket,
	buf:  [dynamic]byte,
}

@(private="file")
client_dial :: proc(port: int) -> (c: Client, ok: bool) {
	sock, err := net.dial_tcp(net.Endpoint{address = net.IP4_Loopback, port = port})
	if err != nil { return }
	net.set_option(sock, .Receive_Timeout, 5 * time.Second)
	c.sock = sock
	c.buf.allocator = context.temp_allocator
	return c, true
}

@(private="file")
client_fill :: proc(c: ^Client) -> bool {
	tmp: [16384]byte
	n, err := net.recv_tcp(c.sock, tmp[:])
	if err != nil || n == 0 { return false }
	append(&c.buf, ..tmp[:n])
	return true
}

@(private="file")
send_all :: proc(sock: net.TCP_Socket, data: string) -> bool {
	sent := 0
	for sent < len(data) {
		n, err := net.send_tcp(sock, transmute([]byte)data[sent:])
		if err != nil { return false }
		sent += n
	}
	return true
}

// Closes with an RST instead of a FIN (SO_LINGER with a zero timeout). net.set_option(.Linger)
// can't do this, it passes a timeval where the OS expects a `struct linger`.
@(private="file")
close_rst :: proc(sock: net.TCP_Socket) {
	l := posix.linger{l_onoff = 1, l_linger = 0}
	posix.setsockopt(posix.FD(sock), posix.SOL_SOCKET, .LINGER, &l, size_of(l))
	net.close(sock)
}

// Reads one complete response (skipping 1xx), handling Content-Length and chunked bodies.
@(private="file")
read_response :: proc(c: ^Client) -> (status: int, body: string, ok: bool) {
	for {
		head_end: int
		for {
			if i := strings.index(string(c.buf[:]), "\r\n\r\n"); i >= 0 {
				head_end = i + 4
				break
			}
			if !client_fill(c) { return }
		}
		status = status_of(string(c.buf[:head_end]))
		if status == 0 { return }
		if status < 200 {
			remove_range(&c.buf, 0, head_end)
			continue
		}
		head := strings.to_lower(string(c.buf[:head_end]), context.temp_allocator)

		if strings.contains(head, "\r\ntransfer-encoding: chunked") {
			out := make([dynamic]byte, context.temp_allocator)
			pos := head_end
			for {
				line_end: int
				for {
					if i := strings.index(string(c.buf[pos:]), "\r\n"); i >= 0 {
						line_end = pos + i
						break
					}
					if !client_fill(c) { return }
				}
				size, size_ok := strconv.parse_int(string(c.buf[pos:line_end]), 16)
				if !size_ok || size < 0 { return }
				pos = line_end + 2
				for len(c.buf) < pos + size + 2 {
					if !client_fill(c) { return }
				}
				if size == 0 {
					pos += 2 // No trailers: the last chunk is followed by the final CRLF.
					break
				}
				append(&out, ..c.buf[pos:pos + size])
				pos += size + 2
			}
			remove_range(&c.buf, 0, pos)
			return status, string(out[:]), true
		}

		n := 0
		if i := strings.index(head, "\r\ncontent-length: "); i >= 0 {
			rest := head[i + len("\r\ncontent-length: "):]
			n, _ = strconv.parse_int(rest[:strings.index(rest, "\r\n")])
		}
		for len(c.buf) < head_end + n {
			if !client_fill(c) { return }
		}
		body = strings.clone(string(c.buf[head_end:head_end + n]), context.temp_allocator)
		remove_range(&c.buf, 0, head_end + n)
		return status, body, true
	}
}

@(private="file")
random_text :: proc(n: int) -> string {
	b := make([]byte, n, context.temp_allocator)
	for &c in b { c = 'a' + byte(rand.int_max(26)) }
	return string(b)
}

// A random valid request and the body its response must have.
@(private="file")
random_request :: proc() -> (req: string, want: string) {
	switch rand.int_max(6) {
	case 0:
		return "GET /plain HTTP/1.1\r\nHost: x\r\n\r\n", "hello"
	case 1:
		return "GET /big HTTP/1.1\r\nHost: x\r\n\r\n", string(big_body[:])
	case 2:
		return "GET /slow HTTP/1.1\r\nHost: x\r\n\r\n", "slow"
	case 3:
		return "GET /stream HTTP/1.1\r\nHost: x\r\n\r\n", "streamed body"
	case 4:
		body := random_text(rand.int_max(8192))
		buf: [20]byte
		return strings.concatenate({
			"POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: ", strconv.write_int(buf[:], i64(len(body)), 10), "\r\n\r\n", body,
		}, context.temp_allocator), body
	case:
		// Chunked upload, in random pieces.
		body := random_text(rand.int_max(8192))
		sb := strings.builder_make(context.temp_allocator)
		strings.write_string(&sb, "POST /echo HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n")
		rest := body
		for len(rest) > 0 {
			n := 1 + rand.int_max(len(rest))
			strings.write_int(&sb, n, 16)
			strings.write_string(&sb, "\r\n")
			strings.write_string(&sb, rest[:n])
			strings.write_string(&sb, "\r\n")
			rest = rest[n:]
		}
		strings.write_string(&sb, "0\r\n\r\n")
		return strings.to_string(sb), body
	}
}

@(private="file")
check_response :: proc(s: ^Stress, what: string, status: int, body, want: string, ok: bool) -> bool {
	if !ok || status != 200 || body != want {
		fail(s, "%s: status %i ok=%v, body %i bytes (want %i): %.60q", what, status, ok, len(body), len(want), body)
		return false
	}
	sync.atomic_add(&s.exchanges, 1)
	return true
}

// One client connection doing one random thing.
@(private="file")
http_session :: proc(s: ^Stress) {
	c, ok := client_dial(s.port)
	if !ok {
		fail(s, "dial failed")
		time.sleep(time.Millisecond)
		return
	}
	closed := false
	defer if !closed { net.close(c.sock) }

	switch rand.int_max(100) {
	case 0 ..< 40: // Keep-alive: several requests, one after another.
		for _ in 0 ..< 1 + rand.int_max(5) {
			req, want := random_request()
			if !send_all(c.sock, req) { fail(s, "keep-alive: send failed"); return }
			status, body, rok := read_response(&c)
			if !check_response(s, "keep-alive", status, body, want, rok) { return }
		}

	case 40 ..< 55: // Pipelined: all requests at once, then all responses in order.
		n := 2 + rand.int_max(5)
		wants := make([]string, n, context.temp_allocator)
		sb := strings.builder_make(context.temp_allocator)
		for &want in wants {
			req: string
			req, want = random_request()
			strings.write_string(&sb, req)
		}
		if !send_all(c.sock, strings.to_string(sb)) { fail(s, "pipelined: send failed"); return }
		for want in wants {
			status, body, rok := read_response(&c)
			if !check_response(s, "pipelined", status, body, want, rok) { return }
		}

	case 55 ..< 63: // Gone in the middle of the request head.
		req, _ := random_request()
		send_all(c.sock, req[:1 + rand.int_max(len(req) - 4)])

	case 63 ..< 71: // Gone in the middle of the body.
		send_all(c.sock, "POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 5000\r\n\r\n")
		send_all(c.sock, random_text(rand.int_max(4000)))

	case 71 ..< 79: // Reset right after a request (the response may be in flight).
		send_all(c.sock, "GET /slow HTTP/1.1\r\nHost: x\r\n\r\n" if rand.int_max(2) == 0 else "GET /big HTTP/1.1\r\nHost: x\r\n\r\n")
		if rand.int_max(2) == 0 { time.sleep(time.Duration(rand.int_max(20)) * time.Millisecond) }
		close_rst(c.sock)
		closed = true

	case 79 ..< 87: // Never reads the response.
		send_all(c.sock, "GET /big HTTP/1.1\r\nHost: x\r\n\r\nGET /big HTTP/1.1\r\nHost: x\r\n\r\n")

	case 87 ..< 95: // Half-close after the request, then read the response.
		req, want := random_request()
		if !send_all(c.sock, req) { fail(s, "half-close: send failed"); return }
		net.shutdown(c.sock, .Send)
		status, body, rok := read_response(&c)
		check_response(s, "half-close", status, body, want, rok)

	case: // Garbage: the server must answer (4xx/5xx) or close, not hang.
		junk := make([]byte, 1 + rand.int_max(200), context.temp_allocator)
		for &b in junk { b = byte(rand.int_max(256)) }
		send_all(c.sock, string(junk))
		send_all(c.sock, "\r\n\r\n")
		for client_fill(&c) {}
		if len(c.buf) > 0 && status_of(string(c.buf[:])) < 400 {
			fail(s, "garbage got a non-error response: %.60q", string(c.buf[:]))
		}
	}
}

// --- WebSocket client side ---

@(private="file")
ws_session :: proc(s: ^Stress) {
	c, head, ok := ws_dial_port(s.port)
	if !ok || status_of(head) != 101 {
		if ok { net.close(c.sock) }
		fail(s, "ws: handshake failed: %q", head)
		time.sleep(time.Millisecond)
		return
	}
	closed := false
	defer if !closed { net.close(c.sock) }

	for _ in 0 ..< 1 + rand.int_max(8) {
		kind := ws.Opcode.Text if rand.int_max(2) == 0 else .Binary
		size := rand.int_max(200) if rand.int_max(10) > 0 else rand.int_max(70000)
		payload := transmute([]byte)strings.concatenate({"m", random_text(size)}, context.temp_allocator)
		if kind == .Binary && len(payload) > 1 { payload[1] = 0xff }

		if rand.int_max(4) == 0 && len(payload) > 2 {
			// Fragmented, with a ping in between.
			cut := 1 + rand.int_max(len(payload) - 1)
			ws_send(&c, kind, payload[:cut], fin = false)
			ws_send(&c, .Ping, transmute([]byte)string("p"))
			ws_send(&c, .Continuation, payload[cut:])
		} else {
			ws_send(&c, kind, payload)
		}

		// Read until our echo, skipping broadcasts and pongs.
		for {
			f, fok := ws_recv(&c, 5 * time.Second)
			if !fok {
				fail(s, "ws: no echo for a %i byte message", len(payload))
				return
			}
			#partial switch f.opcode {
			case .Pong:
				continue
			case .Close:
				// The server (broadcaster) closed it: complete the handshake.
				ws_send(&c, .Close, f.payload[:min(2, len(f.payload))])
				return
			case .Text:
				if string(f.payload) == "bcast" { continue }
			}
			if f.opcode != kind || string(f.payload) != string(payload) {
				fail(s, "ws: echo mismatch: %v %i bytes, want %v %i bytes", f.opcode, len(f.payload), kind, len(payload))
				return
			}
			sync.atomic_add(&s.exchanges, 1)
			break
		}
	}

	switch rand.int_max(4) {
	case 0: // Close handshake.
		ws_send(&c, .Close, close_payload(1000))
		for {
			f, fok := ws_recv(&c, 5 * time.Second)
			if !fok { fail(s, "ws: no close frame back"); return }
			if f.opcode == .Close { break }
		}
	case 1: // Just gone.
	case 2: // Reset.
		close_rst(c.sock)
		closed = true
	case 3: // Gone in the middle of a frame.
		hdr: [ws.MAX_HEADER_SIZE]byte
		h := ws.write_header(hdr[:], true, .Binary, 1000, [4]byte{1, 2, 3, 4})
		send_all(c.sock, string(h))
		send_all(c.sock, random_text(rand.int_max(999)))
	}
}

// Broadcasts to every open WebSocket connection from another thread and sometimes closes one.
@(private="file")
broadcaster :: proc(s: ^Stress) {
	handles: []ws.Handle
	{
		sync.guard(&s.mu)
		handles = make([]ws.Handle, len(s.ws_handles), context.temp_allocator)
		copy(handles, s.ws_handles[:])
	}
	ws.broadcast(handles, .Text, transmute([]byte)string("bcast"))
	if len(handles) > 0 && rand.int_max(10) == 0 {
		ws.close_from_any_thread(rand.choice(handles), .Going_Away)
	}
	time.sleep(2 * time.Millisecond)
}

// --- Tests ---

@(test)
stress_http :: proc(t: ^testing.T) {
	if !stress_begin(t) { return }
	s := Stress{t = t}
	defer delete(s.ws_handles)
	ts := server_start(t, stress_handler(&s), stress_opts(), SERVER_THREADS)
	defer server_stop(ts)
	s.port = ts.port

	threads := make([dynamic]^thread.Thread)
	defer delete(threads)
	run_workers(&s, HTTP_WORKERS, http_session, &threads)
	time.sleep(STRESS_SECONDS * time.Second)
	sync.atomic_store(&s.stop, true)
	join_all(&threads)

	log.infof("stress_http: %i good exchanges, %i failures", s.exchanges, s.failures)
	testing.expect(t, s.exchanges > 0, "no exchange succeeded")
	expect_drained(t, ts)
	expect_healthy(t, ts)
}

@(test)
stress_websocket :: proc(t: ^testing.T) {
	if !stress_begin(t) { return }
	s := Stress{t = t}
	defer delete(s.ws_handles)
	ts := server_start(t, stress_handler(&s), stress_opts(), SERVER_THREADS)
	defer server_stop(ts)
	s.port = ts.port

	threads := make([dynamic]^thread.Thread)
	defer delete(threads)
	run_workers(&s, WS_WORKERS, ws_session, &threads)
	run_workers(&s, 1, broadcaster, &threads)
	time.sleep(STRESS_SECONDS * time.Second)
	sync.atomic_store(&s.stop, true)
	join_all(&threads)

	log.infof("stress_websocket: %i good echoes, %i failures", s.exchanges, s.failures)
	testing.expect(t, s.exchanges > 0, "no echo succeeded")
	expect_drained(t, ts)
	{
		sync.guard(&s.mu)
		testing.expectf(t, len(s.ws_handles) == 0, "%i websockets never reported on_close", len(s.ws_handles))
	}
	expect_healthy(t, ts)
}

// Shuts the server down in the middle of HTTP + WebSocket traffic, while another thread keeps
// broadcasting (to connections that are being closed, and then to event loops that are gone).
@(test)
stress_shutdown_under_load :: proc(t: ^testing.T) {
	if !stress_begin(t) { return }
	s := Stress{t = t}
	defer delete(s.ws_handles)
	opts := stress_opts()
	opts.shutdown_timeout = 500 * time.Millisecond
	ts := server_start(t, stress_handler(&s), opts, SERVER_THREADS)
	s.port = ts.port

	threads := make([dynamic]^thread.Thread)
	defer delete(threads)
	run_workers(&s, max(HTTP_WORKERS / 2, 1), http_session, &threads)
	run_workers(&s, max(WS_WORKERS / 2, 1), ws_session, &threads)
	run_workers(&s, 1, broadcaster, &threads)
	time.sleep(min(STRESS_SECONDS, 1) * time.Second)

	sync.atomic_store(&s.lenient, true)
	start := time.tick_now()
	server_stop(ts)
	took := time.tick_since(start)
	testing.expectf(t, took < 5 * time.Second, "shutdown under load took %v", took)

	// Keep the clients and the broadcaster going against the stopped server for a moment.
	time.sleep(200 * time.Millisecond)
	sync.atomic_store(&s.stop, true)
	join_all(&threads)
	log.infof("stress_shutdown_under_load: %i good exchanges before shutdown, shutdown took %v", s.exchanges, took)
}
