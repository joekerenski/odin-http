package tests_server

// The WebSocket client (websocket.dial) against our own server, on the test thread's event loop.

import "core:bytes"
import "core:fmt"
import "core:mem"
import "core:nbio"
import "core:strings"
import "core:testing"
import "core:time"

import http "../.."
import "../../client"
import ws "../../websocket"

@(private="file")
Client_Run :: struct {
	t:          ^testing.T,
	// Messages to send once open; the echoes must come back in order.
	send:       [][]byte,
	got:        int,
	compressed: bool,
	opened:     bool,
	closed:     bool,
	close_code: u16,
	reason_buf: [256]byte,
	reason:     string,
}

@(private="file")
client_callbacks :: proc(r: ^Client_Run) -> ws.Callbacks {
	return {
		user_data = r,
		on_open = proc(c: ^ws.Conn) {
			r := (^Client_Run)(c.user_data)
			r.opened = true
			r.compressed = c.compressed
			for m, i in r.send {
				kind := ws.Message_Kind.Text if i % 2 == 0 else .Binary
				testing.expect(r.t, ws.send(c, kind, m) == .Ok)
			}
			if len(r.send) == 0 { ws.close(c) }
		},
		on_message = proc(c: ^ws.Conn, kind: ws.Message_Kind, data: []byte) {
			r := (^Client_Run)(c.user_data)
			if r.got < len(r.send) {
				want := r.send[r.got]
				testing.expectf(r.t, bytes.equal(data, want), "echo %i: %i bytes, want %i", r.got, len(data), len(want))
			}
			r.got += 1
			if r.got == len(r.send) { ws.close(c) }
		},
		on_close = proc(c: ^ws.Conn, code: u16, reason: string) {
			r := (^Client_Run)(c.user_data)
			r.closed = true
			r.close_code = code
			n := copy(r.reason_buf[:], reason)
			r.reason = string(r.reason_buf[:n])
		},
	}
}

// Runs the calling thread's event loop until `r` is closed (or 10s passed).
@(private="file")
run_until_closed :: proc(t: ^testing.T, r: ^Client_Run, loc := #caller_location) {
	start := time.tick_now()
	for !r.closed && time.tick_since(start) < 10 * time.Second {
		nbio.tick(10 * time.Millisecond)
	}
	testing.expect(t, r.closed, "client never closed", loc = loc)
}

@(private="file")
ws_compressing_echo_handler :: proc() -> http.Handler {
	return http.handler(proc(req: ^http.Request, res: ^http.Response) {
		ws.upgrade(req, res, {compression = true, max_message_size = 2 * mem.Megabyte, send_queue_limit = 16 * mem.Megabyte}, {
			on_message = proc(c: ^ws.Conn, kind: ws.Message_Kind, data: []byte) {
				ws.send(c, kind, data)
			},
		})
	})
}

@(private="file")
test_messages :: proc() -> [][]byte {
	msgs := make([dynamic][]byte, context.temp_allocator)
	for size in ([]int{0, 1, 31, 32, 125, 126, 1000, 65535, 65536, 300_000}) {
		m := make([]byte, size, context.temp_allocator)
		// Compressible but not trivial text (valid UTF-8 for the text messages).
		for &b, i in m { b = 'a' + byte((i * 7 + i / 13) % 26) }
		append(&msgs, m)
	}
	return msgs[:]
}

@(test)
ws_client_echo :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 30 * time.Second)
	q: Quarantine
	context.allocator = quarantine_allocator(&q)
	ts := server_start(t, ws_compressing_echo_handler())
	defer server_stop(ts)

	if !testing.expect_value(t, nbio.acquire_thread_event_loop(), nil) { return }
	defer nbio.release_thread_event_loop()

	url := fmt.tprintf("ws://127.0.0.1:%i/echo?x=1", ts.port)
	for compression in ([]bool{true, false}) {
		r := Client_Run{t = t, send = test_messages()}
		_, err := ws.dial(url, {opts = {compression = compression, max_message_size = 2 * mem.Megabyte}}, client_callbacks(&r))
		if !testing.expect(t, err == nil) { return }
		run_until_closed(t, &r)
		testing.expectf(t, r.opened && r.got == len(r.send), "compression=%v: opened=%v, %i/%i echoes", compression, r.opened, r.got, len(r.send))
		testing.expectf(t, r.compressed == compression, "compression=%v negotiated=%v", compression, r.compressed)
		testing.expectf(t, r.close_code == 1000, "close code %v (%s)", r.close_code, r.reason)
	}
}

@(test)
ws_client_handshake_failures :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 30 * time.Second)
	if !testing.expect_value(t, nbio.acquire_thread_event_loop(), nil) { return }
	defer nbio.release_thread_event_loop()

	// Rejected synchronously.
	Bad :: struct { url: string, err: ws.Dial_Error, ca_file: string }
	for b in ([]Bad{
		{"http://x/", .Invalid_URL, ""},
		{"ws://", .Invalid_URL, ""},
		{"wss://", .Invalid_URL, ""},
		{"ws://user@x/", .Invalid_URL, ""},
		{"ws://x:/", .Invalid_URL, ""},
		{"wss://[]:443/", .Invalid_URL, ""},
		{"ws://x/a b", .Invalid_URL, ""},
		{"ws://does-not-exist.invalid/", .Resolve_Failed, ""},
		{"wss://does-not-exist.invalid/", .Resolve_Failed, ""},
		{"wss://127.0.0.1:1/", .TLS_Setup_Failed, "/does/not/exist.pem"},
	}) {
		_, err := ws.dial(b.url, {tls_ca_file = b.ca_file}, {})
		testing.expectf(t, err == b.err, "%q: %v, want %v", b.url, err, b.err)
	}

	// Plain HTTP server: not a 101.
	ts := server_start(t, echo_handler())
	{
		r := Client_Run{t = t}
		_, err := ws.dial(fmt.tprintf("ws://127.0.0.1:%i/", ts.port), {}, client_callbacks(&r))
		testing.expect(t, err == nil)
		run_until_closed(t, &r)
		testing.expectf(t, !r.opened && r.close_code == 1006 && strings.contains(r.reason, "expected 101"), "plain HTTP: opened=%v %v %q", r.opened, r.close_code, r.reason)
	}
	// wss:// to a server that doesn't speak TLS.
	{
		r := Client_Run{t = t}
		_, err := ws.dial(fmt.tprintf("wss://127.0.0.1:%i/", ts.port), {timeout = 3 * time.Second}, client_callbacks(&r))
		testing.expect(t, err == nil)
		run_until_closed(t, &r)
		testing.expectf(t, !r.opened && r.close_code == 1006 && strings.contains(r.reason, "TLS"), "TLS to plain HTTP: opened=%v %v %q", r.opened, r.close_code, r.reason)
	}
	port := ts.port
	server_stop(ts)

	// Nothing listening anymore: connect fails.
	{
		r := Client_Run{t = t}
		_, err := ws.dial(fmt.tprintf("ws://127.0.0.1:%i/", port), {}, client_callbacks(&r))
		testing.expect(t, err == nil)
		run_until_closed(t, &r)
		testing.expectf(t, !r.opened && r.close_code == 1006 && strings.contains(r.reason, "connect failed"), "refused: opened=%v %v %q", r.opened, r.close_code, r.reason)
	}
}

// A small compressed message that inflates past the server's limit is refused with 1009,
// without decompressing all of it.
@(test)
ws_compression_bomb :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 30 * time.Second)
	h := http.handler(proc(req: ^http.Request, res: ^http.Response) {
		ws.upgrade(req, res, {compression = true, max_message_size = 64 * 1024}, {
			on_message = proc(c: ^ws.Conn, kind: ws.Message_Kind, data: []byte) { ws.send(c, kind, data) },
		})
	})
	ts := server_start(t, h)
	defer server_stop(ts)

	if !testing.expect_value(t, nbio.acquire_thread_event_loop(), nil) { return }
	defer nbio.release_thread_event_loop()

	// 8 MiB of zeros compresses to ~8 KiB: under the frame limit, far over the message limit.
	bomb := make([]byte, 8 * mem.Megabyte, context.temp_allocator)
	r := Client_Run{t = t, send = {bomb}}
	_, err := ws.dial(fmt.tprintf("ws://127.0.0.1:%i/", ts.port), {opts = {compression = true, send_queue_limit = 16 * mem.Megabyte}}, client_callbacks(&r))
	if !testing.expect(t, err == nil) { return }
	run_until_closed(t, &r)
	testing.expectf(t, r.opened && r.compressed && r.close_code == 1009, "opened=%v compressed=%v close %v (%s)", r.opened, r.compressed, r.close_code, r.reason)
	expect_server_ok(t, ts)
}

// The server still answers (any response: the handler only speaks WebSocket).
@(private="file")
expect_server_ok :: proc(t: ^testing.T, ts: ^Test_Server, loc := #caller_location) {
	resp := roundtrip(ts, "GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n", 2 * time.Second)
	testing.expectf(t, status_of(resp) != 0, "server unresponsive: %q", resp, loc = loc)
}

// Dialing (or an async request) from a thread without an event loop is an error, not a crash.
@(test)
client_without_event_loop :: proc(t: ^testing.T) {
	if !testing.expect(t, nbio.current_thread_event_loop() == nil, "test thread already has an event loop") { return }

	c, err := ws.dial("ws://127.0.0.1:1/", {}, {})
	testing.expect_value(t, err, ws.Dial_Error.No_Event_Loop)
	testing.expect(t, c == nil)

	req: client.Request
	client.request_init(&req, .Get, context.temp_allocator)
	aerr := client.request_async(&req, "http://127.0.0.1:1/", client.Default_Opts, nil, proc(_: client.Response, _: client.Error, _: rawptr) {})
	testing.expect_value(t, aerr, client.Error.No_Event_Loop)
}
