package tests_server

import "core:bytes"
import "core:encoding/endian"
import "core:fmt"
import "core:math/rand"
import "core:net"
import "core:strings"
import "core:sync"
import "core:testing"
import "core:time"

import http "../.."
import ws "../../websocket"

// --- A minimal raw WebSocket client for tests ---

WS_KEY :: "dGhlIHNhbXBsZSBub25jZQ=="

Ws_Client :: struct {
	sock: net.TCP_Socket,
	buf:  [dynamic]byte, // Received, unparsed bytes.
}

ws_dial :: proc(t: ^testing.T, ts: ^Test_Server, extra_headers := "", first_frames: []byte = nil) -> (c: Ws_Client, head: string, ok: bool) {
	sock, err := net.dial_tcp(net.Endpoint{address = net.IP4_Loopback, port = ts.port})
	if err != nil { return }
	c.sock = sock
	c.buf.allocator = context.temp_allocator
	req := fmt.tprintf("GET /ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n%s\r\n", WS_KEY, extra_headers)
	data := strings.concatenate({req, string(first_frames)}, context.temp_allocator)
	raw_send({sock}, data)

	// Read until the end of the response head.
	for {
		if i := strings.index(string(c.buf[:]), "\r\n\r\n"); i >= 0 {
			head = strings.clone(string(c.buf[:i + 4]), context.temp_allocator)
			remove_range(&c.buf, 0, i + 4)
			return c, head, true
		}
		if !ws_fill(&c, 2 * time.Second) { return c, string(c.buf[:]), false }
	}
}

ws_fill :: proc(c: ^Ws_Client, wait: time.Duration) -> bool {
	net.set_option(c.sock, .Receive_Timeout, wait)
	tmp: [65536]byte
	n, err := net.recv_tcp(c.sock, tmp[:])
	if err != nil || n == 0 { return false }
	append(&c.buf, ..tmp[:n])
	return true
}

ws_send :: proc(c: ^Ws_Client, opcode: ws.Opcode, payload: []byte, fin := true, masked := true, rsv: u8 = 0) {
	hdr: [ws.MAX_HEADER_SIZE]byte
	mask := [4]byte{0x12, 0x34, 0x56, 0x78}
	h := ws.write_header(hdr[:], fin, opcode, len(payload), mask if masked else nil)
	h[0] |= rsv << 4
	body := make([]byte, len(payload), context.temp_allocator)
	copy(body, payload)
	if masked { ws.apply_mask(body, mask) }
	raw_send({c.sock}, strings.concatenate({string(h), string(body)}, context.temp_allocator))
}

Ws_Frame :: struct {
	opcode:  ws.Opcode,
	fin:     bool,
	payload: []byte,
}

// Reads the next frame from the server; ok is false on timeout/close.
ws_recv :: proc(c: ^Ws_Client, wait := 2 * time.Second) -> (f: Ws_Frame, ok: bool) {
	for {
		h, hl, res := ws.parse_header(c.buf[:], require_mask = false)
		if res == .Ok && len(c.buf) >= hl + h.payload_len {
			f = {h.opcode, h.fin, make([]byte, h.payload_len, context.temp_allocator)}
			copy(f.payload, c.buf[hl:hl + h.payload_len])
			remove_range(&c.buf, 0, hl + h.payload_len)
			return f, true
		}
		if res == .Protocol_Error { return }
		if !ws_fill(c, wait) { return }
	}
}

// Expects the server to send a close frame with `code` and then close the TCP connection.
ws_expect_close :: proc(t: ^testing.T, c: ^Ws_Client, code: u16, loc := #caller_location) {
	f, ok := ws_recv(c)
	testing.expectf(t, ok && f.opcode == .Close, "want close frame, got %v ok=%v", f, ok, loc = loc)
	if ok && f.opcode == .Close && len(f.payload) >= 2 {
		got, _ := endian.get_u16(f.payload, .Big)
		testing.expectf(t, got == code, "close code %v, want %v", got, code, loc = loc)
	} else if ok && f.opcode == .Close {
		testing.expectf(t, code == 1005, "close frame without code, want %v", code, loc = loc)
	}
	// And then the TCP connection closes.
	start := time.tick_now()
	for ws_fill(c, 2 * time.Second) {
		if time.tick_since(start) > 3 * time.Second { break }
	}
	_, closed := raw_recv({c.sock}, 100 * time.Millisecond)
	testing.expect(t, closed, "TCP connection not closed after close frame", loc = loc)
}

close_payload :: proc(code: u16, reason := "") -> []byte {
	b := make([]byte, 2 + len(reason), context.temp_allocator)
	endian.put_u16(b, .Big, code)
	copy(b[2:], reason)
	return b
}

// --- The server side: an echo endpoint ---

ws_echo_opts := ws.Opts{max_message_size = 64 * 1024}

ws_echo_handler :: proc() -> http.Handler {
	return http.handler(proc(req: ^http.Request, res: ^http.Response) {
		ws.upgrade(req, res, ws_echo_opts, {
			on_message = proc(c: ^ws.Conn, kind: ws.Message_Kind, data: []byte) {
				if kind == .Text && string(data) == "close-me" {
					ws.close(c, .Normal, "bye")
					return
				}
				ws.send(c, kind, data)
			},
		})
	})
}

// --- Tests ---

@(test)
ws_handshake_and_echo :: proc(t: ^testing.T) {
	testing.expect(t, ws.accept_key(WS_KEY, context.temp_allocator) == "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=")

	ts := server_start(t, ws_echo_handler())
	defer server_stop(ts)

	c, head, ok := ws_dial(t, ts)
	defer net.close(c.sock)
	testing.expectf(t, ok && status_of(head) == 101, "got %q", head)
	testing.expectf(t, strings.contains(head, "sec-websocket-accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo="), "got %q", head)

	ws_send(&c, .Text, transmute([]byte)string("hello"))
	f, fok := ws_recv(&c)
	testing.expectf(t, fok && f.opcode == .Text && string(f.payload) == "hello", "got %v", f)

	big := make([]byte, 70000 - 6000, context.temp_allocator)
	for &b, i in big { b = byte(i) }
	ws_send(&c, .Binary, big)
	f, fok = ws_recv(&c)
	testing.expectf(t, fok && f.opcode == .Binary && bytes.equal(f.payload, big), "binary echo: %v bytes", len(f.payload))

	// Fragmented text with a ping in the middle.
	ws_send(&c, .Text, transmute([]byte)string("frag"), fin = false)
	ws_send(&c, .Ping, transmute([]byte)string("p"))
	ws_send(&c, .Continuation, transmute([]byte)string("ment"), fin = false)
	ws_send(&c, .Continuation, transmute([]byte)string("ed"))
	f, fok = ws_recv(&c)
	testing.expectf(t, fok && f.opcode == .Pong && string(f.payload) == "p", "want pong, got %v", f)
	f, fok = ws_recv(&c)
	testing.expectf(t, fok && f.opcode == .Text && string(f.payload) == "fragmented", "got %v", f)

	// Client-initiated close: the code is echoed and the server closes TCP.
	ws_send(&c, .Close, close_payload(1000, "done"))
	ws_expect_close(t, &c, 1000)
}

@(test)
ws_frames_with_handshake :: proc(t: ^testing.T) {
	ts := server_start(t, ws_echo_handler())
	defer server_stop(ts)

	// A client that pipelines its first frame right after the handshake request.
	mask := [4]byte{1, 2, 3, 4}
	hdr: [ws.MAX_HEADER_SIZE]byte
	h := ws.write_header(hdr[:], true, .Text, 2, mask)
	payload := []byte{'h', 'i'}
	ws.apply_mask(payload, mask)
	frame := strings.concatenate({string(h), string(payload)}, context.temp_allocator)

	c, head, ok := ws_dial(t, ts, first_frames = transmute([]byte)frame)
	defer net.close(c.sock)
	testing.expect(t, ok && status_of(head) == 101)
	f, fok := ws_recv(&c)
	testing.expectf(t, fok && string(f.payload) == "hi", "got %v", f)
}

@(test)
ws_server_initiated_close :: proc(t: ^testing.T) {
	ts := server_start(t, ws_echo_handler())
	defer server_stop(ts)

	c, _, _ := ws_dial(t, ts)
	defer net.close(c.sock)
	ws_send(&c, .Text, transmute([]byte)string("close-me"))
	f, ok := ws_recv(&c)
	testing.expectf(t, ok && f.opcode == .Close && string(f.payload[2:]) == "bye", "got %v", f)
	// Complete the handshake: the server then closes TCP.
	ws_send(&c, .Close, close_payload(1000))
	_, closed := raw_recv({c.sock}, 2 * time.Second)
	testing.expect(t, closed)
}

@(test)
ws_protocol_violations :: proc(t: ^testing.T) {
	ts := server_start(t, ws_echo_handler())
	defer server_stop(ts)

	Case :: struct { name: string, send: proc(c: ^Ws_Client), code: u16 }
	cases := []Case{
		{"unmasked frame", proc(c: ^Ws_Client) { ws_send(c, .Text, transmute([]byte)string("x"), masked = false) }, 1002},
		{"rsv bit", proc(c: ^Ws_Client) { ws_send(c, .Text, transmute([]byte)string("x"), rsv = 4) }, 1002},
		{"invalid utf8", proc(c: ^Ws_Client) { ws_send(c, .Text, []byte{0xC0, 0x80}) }, 1007},
		{"invalid utf8 fragment", proc(c: ^Ws_Client) { ws_send(c, .Text, []byte{'a', 0xED, 0xA0}, fin = false) }, 1007},
		{"truncated utf8 at end", proc(c: ^Ws_Client) { ws_send(c, .Text, []byte{'a', 0xE2, 0x82}) }, 1007},
		{"continuation without start", proc(c: ^Ws_Client) { ws_send(c, .Continuation, transmute([]byte)string("x")) }, 1002},
		{"new message during fragmented", proc(c: ^Ws_Client) {
			ws_send(c, .Text, transmute([]byte)string("a"), fin = false)
			ws_send(c, .Text, transmute([]byte)string("b"))
		}, 1002},
		{"too big", proc(c: ^Ws_Client) { ws_send(c, .Binary, make([]byte, 64 * 1024 + 1, context.temp_allocator)) }, 1009},
		{"too big fragmented", proc(c: ^Ws_Client) {
			ws_send(c, .Binary, make([]byte, 40000, context.temp_allocator), fin = false)
			ws_send(c, .Continuation, make([]byte, 40000, context.temp_allocator))
		}, 1009},
		{"close code 1005", proc(c: ^Ws_Client) { ws_send(c, .Close, close_payload(1005)) }, 1002},
		{"close 1 byte", proc(c: ^Ws_Client) { ws_send(c, .Close, []byte{3}) }, 1002},
		{"close bad reason", proc(c: ^Ws_Client) { ws_send(c, .Close, []byte{0x03, 0xE8, 0xFF}) }, 1007},
		{"ping too long", proc(c: ^Ws_Client) {
			// Hand-crafted: a ping with a 126-byte payload (16-bit length).
			hdr := []byte{0x89, 0x80 | 126, 0, 126, 0, 0, 0, 0}
			raw_send({c.sock}, strings.concatenate({string(hdr), strings.repeat("p", 126, context.temp_allocator)}, context.temp_allocator))
		}, 1002},
	}
	for tc in cases {
		c, head, ok := ws_dial(t, ts)
		testing.expectf(t, ok && status_of(head) == 101, "%s: handshake %q", tc.name, head)
		tc.send(&c)
		f, fok := ws_recv(&c)
		got: u16
		if fok && f.opcode == .Close && len(f.payload) >= 2 { got, _ = endian.get_u16(f.payload, .Big) }
		testing.expectf(t, got == tc.code, "%s: want close %v, got %v (%v)", tc.name, tc.code, got, f)
		_, closed := raw_recv({c.sock}, 2 * time.Second)
		testing.expectf(t, closed, "%s: TCP not closed", tc.name)
		net.close(c.sock)
	}
}

@(test)
ws_handshake_rejections :: proc(t: ^testing.T) {
	ts := server_start(t, ws_echo_handler())
	defer server_stop(ts)

	resp := roundtrip(ts, "GET /ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 8\r\n\r\n")
	testing.expectf(t, status_of(resp) == 426 && strings.contains(resp, "sec-websocket-version: 13"), "got %q", resp)

	resp = roundtrip(ts, "GET /ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: short\r\nSec-WebSocket-Version: 13\r\n\r\n")
	testing.expectf(t, status_of(resp) == 400, "got %q", resp)

	resp = roundtrip(ts, "GET /ws HTTP/1.1\r\nHost: x\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")
	testing.expectf(t, status_of(resp) == 400, "got %q", resp)

	resp = roundtrip(ts, "POST /ws HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")
	testing.expectf(t, status_of(resp) == 405, "got %q", resp)

	// Cross-site: Origin doesn't match Host.
	resp = roundtrip(ts, "GET /ws HTTP/1.1\r\nHost: x\r\nOrigin: https://evil.example\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n")
	testing.expectf(t, status_of(resp) == 403, "got %q", resp)

	// Same origin is fine, and header tokens are case-insensitive.
	c, head, ok := ws_dial(t, ts, "Origin: https://x\r\n")
	net.close(c.sock)
	testing.expectf(t, ok && status_of(head) == 101, "got %q", head)
}

@(test)
ws_shutdown_sends_going_away :: proc(t: ^testing.T) {
	ts := server_start(t, ws_echo_handler())
	c, _, ok := ws_dial(t, ts)
	testing.expect(t, ok)
	defer net.close(c.sock)

	Stopper :: struct { ts: ^Test_Server }
	stop_thread := thread_start_stop(ts)

	f, fok := ws_recv(&c)
	code: u16
	if fok && len(f.payload) >= 2 { code, _ = endian.get_u16(f.payload, .Big) }
	testing.expectf(t, fok && f.opcode == .Close && code == 1001, "got %v", f)
	ws_send(&c, .Close, close_payload(1001))
	thread_join_stop(stop_thread)
}

@(test)
ws_keepalive_ping :: proc(t: ^testing.T) {
	ws_echo_opts.ping_interval = 200 * time.Millisecond
	ws_echo_opts.pong_timeout  = 200 * time.Millisecond
	defer { ws_echo_opts.ping_interval = 0; ws_echo_opts.pong_timeout = 0 }

	ts := server_start(t, ws_echo_handler())
	defer server_stop(ts)
	c, _, _ := ws_dial(t, ts)
	defer net.close(c.sock)

	f, ok := ws_recv(&c)
	testing.expectf(t, ok && f.opcode == .Ping, "want ping, got %v", f)
	// Don't answer: the server gives up on us.
	_, closed := raw_recv({c.sock}, 2 * time.Second)
	testing.expect(t, closed, "dead peer not dropped")
}

@(private="file")
cross_handle: ws.Handle
@(private="file")
cross_ready: sync.Sema

@(test)
ws_send_from_other_thread :: proc(t: ^testing.T) {
	h := http.handler(proc(req: ^http.Request, res: ^http.Response) {
		ws.upgrade(req, res, {}, {
			on_open = proc(c: ^ws.Conn) {
				cross_handle = ws.handle(c)
				sync.sema_post(&cross_ready)
			},
		})
	})
	ts := server_start(t, h)
	defer server_stop(ts)

	c, _, ok := ws_dial(t, ts)
	testing.expect(t, ok)
	defer net.close(c.sock)
	sync.sema_wait(&cross_ready)

	// From the test thread (not the server's event loop).
	ws.broadcast({cross_handle, cross_handle}, .Text, transmute([]byte)string("from afar"))
	for _ in 0 ..< 2 {
		f, fok := ws_recv(&c)
		testing.expectf(t, fok && string(f.payload) == "from afar", "got %v", f)
	}

	ws.close_from_any_thread(cross_handle, .Going_Away)
	f, fok := ws_recv(&c)
	testing.expectf(t, fok && f.opcode == .Close, "got %v", f)
	ws_send(&c, .Close, close_payload(1001))
	_, closed := raw_recv({c.sock}, 2 * time.Second)
	testing.expect(t, closed)

	// The connection is gone: sending to its handle is a no-op.
	ws.send_from_any_thread(cross_handle, .Text, transmute([]byte)string("nobody home"))
}

WS_FUZZ_ITERATIONS :: #config(WS_FUZZ_ITERATIONS, 600)

// Random/mutated frame sequences against the echo server: every exchange must end with the server
// closing the connection (no hangs, no crashes) after the client stops, and the server must stay healthy.
@(test)
ws_fuzz_frames :: proc(t: ^testing.T) {
	ts := server_start(t, ws_echo_handler(), fast_opts())
	defer server_stop(ts)

	r := rand.create(rand.uint64())
	context.random_generator = rand.default_random_generator(&r)

	opcodes := []u8{0x0, 0x1, 0x2, 0x3, 0x8, 0x9, 0xA, 0xB, 0xF}
	for _ in 0 ..< WS_FUZZ_ITERATIONS {
		c, head, ok := ws_dial(t, ts)
		if !ok || status_of(head) != 101 {
			testing.expectf(t, false, "handshake failed: %q", head)
			net.close(c.sock)
			continue
		}

		stream := make([dynamic]byte, context.temp_allocator)
		for _ in 0 ..< 1 + rand.int_max(6) {
			payload := make([]byte, rand.choice([]int{0, 1, 2, 5, 125, 126, 200, 3000}), context.temp_allocator)
			for &b in payload { b = byte(rand.int_max(256)) if rand.int_max(2) == 0 else 'a' }
			op := rand.choice(opcodes)
			fin := rand.int_max(4) != 0
			masked := rand.int_max(10) != 0
			hdr: [ws.MAX_HEADER_SIZE]byte
			mask := [4]byte{byte(rand.int_max(256)), 1, 2, 3}
			h := ws.write_header(hdr[:], fin, ws.Opcode(op & 0xF) if op <= 2 || (op >= 8 && op <= 0xA) else .Text, len(payload), mask if masked else nil)
			h[0] = (h[0] & 0xF0) | (op & 0x0F)
			if rand.int_max(10) == 0 { h[0] |= byte(rand.int_max(8)) << 4 }
			if masked { ws.apply_mask(payload, mask) }
			append(&stream, ..h)
			append(&stream, ..payload)
		}
		// Byte-level mutations on top.
		for _ in 0 ..< rand.int_max(3) {
			if len(stream) > 0 { stream[rand.int_max(len(stream))] = byte(rand.int_max(256)) }
		}
		if rand.int_max(4) == 0 { resize(&stream, rand.int_max(len(stream) + 1)) }

		raw_send({c.sock}, string(stream[:]))
		// Then a clean close from our side; the server must close TCP within the close timeout.
		ws_send(&c, .Close, close_payload(1000))
		net.shutdown(c.sock, .Send)
		deadline := time.tick_now()
		closed := false
		for time.tick_since(deadline) < 8 * time.Second {
			if !ws_fill(&c, 2 * time.Second) {
				_, closed = raw_recv({c.sock}, 10 * time.Millisecond)
				break
			}
		}
		testing.expectf(t, closed, "server did not close after stream % x", stream[:min(len(stream), 64)])
		net.close(c.sock)
		free_all(context.temp_allocator)
	}

	c, head, ok := ws_dial(t, ts)
	defer net.close(c.sock)
	testing.expectf(t, ok && status_of(head) == 101, "unhealthy after fuzzing: %q", head)
	ws_send(&c, .Text, transmute([]byte)string("still alive"))
	f, fok := ws_recv(&c)
	testing.expectf(t, fok && string(f.payload) == "still alive", "got %v", f)
}
