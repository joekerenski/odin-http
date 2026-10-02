// WebSocket server connections (RFC 6455) on top of the HTTP server.
//
// Usage, inside an HTTP handler:
//
//	websocket.upgrade(req, res, {}, {
//		on_message = proc(c: ^websocket.Conn, kind: websocket.Message_Kind, data: []byte) {
//			websocket.send(c, kind, data) // echo
//		},
//	})
//
// A connection lives on the event loop thread that accepted it, all procedures in this package
// must be called from that thread (inside the callbacks, or from timers/operations on that loop).
package websocket

import "base:runtime"

import "core:crypto/legacy/sha1"
import "core:encoding/base64"
import "core:log"
import "core:mem"
import "core:nbio"
import "core:net"
import "core:strings"
import "core:time"

import http ".."

Opts :: struct {
	// Largest message (after reassembling fragments) accepted, bigger ones close the connection
	// with 1009. Defaults to 1MiB.
	max_message_size: int,
	// Largest single frame accepted, defaults to `max_message_size`.
	max_frame_size:   int,
	// Most bytes of data frames queued for sending; `send` returns `.Queue_Full` beyond it.
	// Control frames are not limited. Defaults to 4MiB.
	send_queue_limit: int,
	// Send a ping after this long without receiving anything, defaults to 30s. Negative disables.
	ping_interval:    time.Duration,
	// Close the connection when nothing is received this long after a ping, defaults to 30s.
	pong_timeout:     time.Duration,
	// How long to wait for the peer's close frame after sending ours, defaults to 5s.
	close_timeout:    time.Duration,
	// Subprotocols the server speaks, the first one the client offers (in the client's order) is picked.
	subprotocols:     []string,
	// Decides whether a handshake with the given Origin header is accepted. When nil, requests with
	// an Origin are only accepted if it names the same host as the Host header (browsers always send
	// Origin, so this blocks cross-site WebSocket hijacking); requests without one are accepted.
	// Use `allow_any_origin` to accept everything.
	check_origin:     proc(req: ^http.Request, origin: string) -> bool,
}

Message_Kind :: enum u8 {
	Text   = u8(Opcode.Text),
	Binary = u8(Opcode.Binary),
}

Callbacks :: struct {
	// Available as `c.user_data`.
	user_data:  rawptr,
	// The handshake completed, the connection is open.
	on_open:    proc(c: ^Conn),
	// A complete message. `data` is only valid during the call (text is already validated as UTF-8).
	// The temp allocator is reset after every message.
	on_message: proc(c: ^Conn, kind: Message_Kind, data: []byte),
	// The send queue has fully drained (useful for backpressure after `.Queue_Full`).
	on_drain:   proc(c: ^Conn),
	// The connection is closed, called exactly once (also if the handshake never completed);
	// `c` is freed after this returns. `code` is 1006 (Abnormal) if no close frame was exchanged.
	on_close:   proc(c: ^Conn, code: u16, reason: string),
}

Send_Result :: enum u8 {
	Ok,
	// The connection is closing or closed.
	Closed,
	// `send_queue_limit` would be exceeded, nothing was queued.
	Queue_Full,
}

State :: enum u8 {
	Connecting,
	Open,
	// A close frame was queued/sent (by us or in reply); no more data is sent.
	Closing,
	Closed,
}

Conn :: struct {
	user_data:     rawptr,
	// The negotiated subprotocol, "" if none.
	subprotocol:   string,
	state:         State,

	_id:           u64,
	_loop:         ^nbio.Event_Loop,
	_cb:           Callbacks,
	_opts:         Opts,
	_h:            http.Hijacked,
	_allocator:    mem.Allocator,
	_write_timeout: time.Duration,

	// Read side.
	_rbuf:          [dynamic]byte,
	_rstart:        int,
	_msg:           [dynamic]byte,
	_msg_active:    bool,
	_msg_kind:      Message_Kind,
	_utf8:          Utf8_Validator,
	_recv_pending:  bool,
	_awaiting_pong: bool,

	// Write side.
	_queue:         [dynamic]Out_Frame,
	_queued_bytes:  int,
	_send_pending:  bool,

	// Close handshake.
	_close_queued:     bool,
	_close_after_send: bool,
	_close_received:   bool,
	_close_timer:      ^nbio.Operation,
	_peer_code:        u16,
	_peer_reason:      string,
	_fail_code:        u16,
	_aborting:         bool,
	_finalized:        bool,
}

@(private)
Out_Frame :: struct {
	buf:         []byte,
	sent:        int,
	payload_len: int,
	close:       bool,
	data:        bool,
}

@(private)
GUID :: "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// Accepts every Origin, for `Opts.check_origin` (only for APIs that don't rely on cookies/ambient auth).
allow_any_origin :: proc(_: ^http.Request, _: string) -> bool { return true }

// The default origin check: the Origin's host[:port] must equal the Host header.
same_origin :: proc(req: ^http.Request, origin: string) -> bool {
	host := http.headers_get(req.headers, "host") or_return
	i := strings.index(origin, "://")
	if i < 0 { return false }
	return http.ascii_equal_fold(origin[i + 3:], host)
}

/*
Validates the WebSocket handshake of `req` and, when valid, answers with 101 Switching Protocols and
takes over the connection. Otherwise an error response (400, 403 or 426) is sent.

Returns whether the upgrade was started. `on_close` is called in every case where `true` is returned.
*/
upgrade :: proc(req: ^http.Request, res: ^http.Response, opts: Opts, callbacks: Callbacks, allocator := context.allocator) -> bool {
	fail :: proc(res: ^http.Response, status: http.Status, why: string) -> bool {
		log.infof("websocket handshake rejected: %s", why)
		http.headers_set_close(&res.headers)
		http.respond(res, status)
		return false
	}

	rline := req.line.(http.Requestline)
	if rline.method != .Get || req.is_head { return fail(res, .Method_Not_Allowed, "not a GET") }
	if rline.version != {1, 1} { return fail(res, .Bad_Request, "not HTTP/1.1") }

	upgrade_hdr, _ := http.headers_get(req.headers, "upgrade")
	connection, _  := http.headers_get(req.headers, "connection")
	if !http.header_list_has_token(upgrade_hdr, "websocket") || !http.header_list_has_token(connection, "upgrade") {
		return fail(res, .Bad_Request, "missing Upgrade: websocket / Connection: upgrade")
	}

	if version, _ := http.headers_get(req.headers, "sec-websocket-version"); version != "13" {
		http.headers_set(&res.headers, "sec-websocket-version", "13")
		return fail(res, .Upgrade_Required, "unsupported Sec-WebSocket-Version")
	}

	key, _ := http.headers_get(req.headers, "sec-websocket-key")
	key = http.trim_ows(key)
	if decoded, err := base64.decode(key, allocator = context.temp_allocator); err != nil || len(decoded) != 16 {
		return fail(res, .Bad_Request, "invalid Sec-WebSocket-Key")
	}

	if origin, has_origin := http.headers_get(req.headers, "origin"); has_origin {
		check := opts.check_origin if opts.check_origin != nil else same_origin
		if !check(req, origin) { return fail(res, .Forbidden, "origin not allowed") }
	}

	c := new(Conn, allocator)
	c._allocator = allocator
	c._cb = callbacks
	c.user_data = callbacks.user_data
	c._opts = opts
	if c._opts.max_message_size <= 0 { c._opts.max_message_size = 1 * mem.Megabyte }
	if c._opts.max_frame_size   <= 0 { c._opts.max_frame_size   = c._opts.max_message_size }
	if c._opts.send_queue_limit <= 0 { c._opts.send_queue_limit = 4 * mem.Megabyte }
	if c._opts.ping_interval    == 0 { c._opts.ping_interval    = 30 * time.Second }
	if c._opts.pong_timeout     <= 0 { c._opts.pong_timeout     = 30 * time.Second }
	if c._opts.close_timeout    <= 0 { c._opts.close_timeout    = 5 * time.Second }
	c._rbuf.allocator  = allocator
	c._msg.allocator   = allocator
	c._queue.allocator = allocator

	// Subprotocol: the first one the client offers that we support.
	if offered, has := http.headers_get(req.headers, "sec-websocket-protocol"); has && len(c._opts.subprotocols) > 0 {
		rest := offered
		pick: for raw_offer in strings.split_iterator(&rest, ",") {
			offer := http.trim_ows(raw_offer)
			for ours in c._opts.subprotocols {
				if offer == ours {
					c.subprotocol = ours
					break pick
				}
			}
		}
	}

	accept := accept_key(key, context.temp_allocator)

	res.status = .Switching_Protocols
	http.headers_set(&res.headers, "upgrade", "websocket")
	http.headers_set(&res.headers, "connection", "Upgrade")
	http.headers_set(&res.headers, "sec-websocket-accept", accept)
	if c.subprotocol != "" {
		http.headers_set(&res.headers, "sec-websocket-protocol", c.subprotocol)
	}

	http.response_hijack(res, c, on_hijacked, on_server_shutdown)
	return true
}

// Sec-WebSocket-Accept for a Sec-WebSocket-Key: base64(sha1(key + GUID)).
accept_key :: proc(key: string, allocator := context.allocator) -> string {
	ctx: sha1.Context
	sha1.init(&ctx)
	sha1.update(&ctx, transmute([]byte)key)
	sha1.update(&ctx, transmute([]byte)string(GUID))
	digest: [sha1.DIGEST_SIZE]byte
	sha1.final(&ctx, digest[:])
	accept, _ := base64.encode(digest[:], allocator = allocator)
	return accept
}

// Sends a message. Data is copied, it can be reused right away.
send :: proc(c: ^Conn, kind: Message_Kind, data: []byte) -> Send_Result {
	return queue_frame(c, Opcode(kind), data)
}

send_text :: proc(c: ^Conn, text: string) -> Send_Result {
	return queue_frame(c, .Text, transmute([]byte)text)
}

send_binary :: proc(c: ^Conn, data: []byte) -> Send_Result {
	return queue_frame(c, .Binary, data)
}

// Sends a ping (at most 125 bytes of payload).
ping :: proc(c: ^Conn, payload: []byte = nil, loc := #caller_location) -> Send_Result {
	assert(len(payload) <= 125, "ping payloads are limited to 125 bytes", loc)
	return queue_frame(c, .Ping, payload)
}

// Starts the closing handshake. Queued messages are sent first.
close :: proc(c: ^Conn, code: Close_Code = .Normal, reason := "") {
	start_close(c, u16(code), reason, after_send = false)
}

// Bytes of data frames waiting to be sent.
queued_bytes :: proc(c: ^Conn) -> int {
	return c._queued_bytes
}

@(private)
on_hijacked :: proc(user: rawptr, h: http.Hijacked, buffered: []byte, ok: bool) {
	c := (^Conn)(user)
	if !ok {
		c.state = .Closed
		c._finalized = true
		if c._cb.on_close != nil { c._cb.on_close(c, u16(Close_Code.Abnormal), "") }
		free(c, c._allocator)
		return
	}

	c._h = h
	c.state = .Open
	register(c)
	c._write_timeout = http.hijacked_server_opts(h).write_timeout
	append(&c._rbuf, ..buffered)

	context.temp_allocator = http.hijacked_temp_allocator(h)
	if c._cb.on_open != nil { c._cb.on_open(c) }

	process(c)
	if !c._aborting {
		start_recv(c)
	}
}

@(private)
on_server_shutdown :: proc(user: rawptr) {
	c := (^Conn)(user)
	close(c, .Going_Away, "server shutting down")
}

@(private)
start_recv :: proc(c: ^Conn) {
	if c._recv_pending || c._aborting { return }

	// Room for at least one header + a decent chunk.
	if cap(c._rbuf) - len(c._rbuf) < 4096 {
		reserve(&c._rbuf, len(c._rbuf) + 16384)
	}

	timeout: time.Duration
	switch {
	case c.state == .Closing:   timeout = c._opts.close_timeout
	case c._awaiting_pong:      timeout = c._opts.pong_timeout
	case c._opts.ping_interval > 0: timeout = c._opts.ping_interval
	case:                       timeout = nbio.NO_TIMEOUT
	}

	c._recv_pending = true
	// The unused capacity of the buffer (slicing the dynamic array itself is bounded by its length).
	spare := ([^]byte)(raw_data(c._rbuf))[len(c._rbuf):cap(c._rbuf)]
	nbio.recv_poly(c._h.socket, {spare}, c, on_recv, timeout = timeout)
}

@(private)
on_recv :: proc(op: ^nbio.Operation, c: ^Conn) {
	c._recv_pending = false
	if c._aborting {
		maybe_finalize(c)
		return
	}

	if op.recv.err != nil {
		if op.recv.err == net.TCP_Recv_Error.Timeout {
			on_read_timeout(c)
			return
		}
		abort(c)
		return
	}
	if op.recv.received == 0 {
		// The peer closed the TCP connection (without a close handshake if we didn't get one).
		abort(c)
		return
	}

	(^runtime.Raw_Dynamic_Array)(&c._rbuf).len += op.recv.received
	c._awaiting_pong = false

	context.temp_allocator = http.hijacked_temp_allocator(c._h)
	process(c)

	if !c._aborting {
		start_recv(c)
	}
}

@(private)
on_read_timeout :: proc(c: ^Conn) {
	switch {
	case c.state == .Closing:
		log.debug("websocket: peer did not complete the close handshake in time")
		abort(c)
	case c._awaiting_pong:
		log.debug("websocket: peer did not respond to ping")
		abort(c)
	case:
		c._awaiting_pong = true
		queue_frame(c, .Ping, nil)
		start_recv(c)
	}
}

// Parses and handles all complete frames in the read buffer.
@(private)
process :: proc(c: ^Conn) {
	defer compact(c)

	for !c._aborting && !c._close_received {
		avail := c._rbuf[c._rstart:]
		h, hl, res := parse_header(avail, require_mask = true)
		switch res {
		case .Need_More:      return
		case .Protocol_Error: fail(c, .Protocol_Error); return
		case .Ok:
		}

		if !is_control(h.opcode) {
			if h.payload_len > c._opts.max_frame_size || len(c._msg) + h.payload_len > c._opts.max_message_size {
				fail(c, .Message_Too_Big)
				return
			}
		}

		total := hl + h.payload_len
		if len(avail) < total {
			// Make sure the whole frame fits once it arrives.
			compact(c)
			reserve(&c._rbuf, c._rstart + total)
			return
		}

		payload := avail[hl:total]
		apply_mask(payload, h.mask)
		c._rstart += total

		handle_frame(c, h, payload)
		free_all(context.temp_allocator)
	}
}

@(private)
compact :: proc(c: ^Conn) {
	if c._rstart == 0 { return }
	remaining := len(c._rbuf) - c._rstart
	copy(c._rbuf[:remaining], c._rbuf[c._rstart:])
	resize(&c._rbuf, remaining)
	c._rstart = 0
}

@(private)
handle_frame :: proc(c: ^Conn, h: Frame_Header, payload: []byte) {
	switch h.opcode {
	case .Text, .Binary:
		if c._msg_active { fail(c, .Protocol_Error); return }
		kind := Message_Kind(h.opcode)
		if h.fin {
			if kind == .Text {
				v: Utf8_Validator
				if !utf8_feed(&v, payload) || !utf8_complete(&v) { fail(c, .Invalid_Payload); return }
			}
			deliver(c, kind, payload)
			return
		}
		c._msg_active = true
		c._msg_kind = kind
		c._utf8 = {}
		append_fragment(c, payload)

	case .Continuation:
		if !c._msg_active { fail(c, .Protocol_Error); return }
		if !append_fragment(c, payload) { return }
		if h.fin {
			if c._msg_kind == .Text && !utf8_complete(&c._utf8) { fail(c, .Invalid_Payload); return }
			c._msg_active = false
			deliver(c, c._msg_kind, c._msg[:])
			clear(&c._msg)
		}

	case .Ping:
		queue_frame(c, .Pong, payload)

	case .Pong:
		c._awaiting_pong = false

	case .Close:
		code, reason, ok := parse_close_payload(payload)
		if !ok {
			// A bad code is a protocol error, a bad reason (only) invalid UTF-8.
			bad_utf8 := len(payload) >= 2 && close_code_valid(u16(payload[0]) << 8 | u16(payload[1]))
			fail(c, .Invalid_Payload if bad_utf8 else .Protocol_Error)
			return
		}
		c._close_received = true
		c._peer_code      = code
		c._peer_reason    = strings.clone(reason, c._allocator)
		if !c._close_queued {
			// Echo the code back, then close the TCP connection (the server closes first).
			start_close(c, code, "", after_send = true)
		} else if has_queued_close(c) {
			// Our close frame is still on its way, close once it's out.
			c._close_after_send = true
		} else {
			// This is the reply to our close: done.
			abort(c)
		}
	}
}

// Appends a fragment to the message being assembled, false if the connection was failed.
@(private)
append_fragment :: proc(c: ^Conn, payload: []byte) -> bool {
	if c._msg_kind == .Text && !utf8_feed(&c._utf8, payload) {
		fail(c, .Invalid_Payload)
		return false
	}
	append(&c._msg, ..payload)
	return true
}

@(private)
deliver :: proc(c: ^Conn, kind: Message_Kind, data: []byte) {
	// After we sent a close, incoming data is discarded.
	if c.state != .Open { return }
	if c._cb.on_message != nil {
		c._cb.on_message(c, kind, data)
	}
}

// Fails the connection (RFC 6455 7.1.7): send a close frame with `code` and close the TCP
// connection right after, without waiting for the peer.
@(private)
fail :: proc(c: ^Conn, code: Close_Code) {
	log.debugf("websocket: failing connection with %v", code)
	if c._fail_code == 0 { c._fail_code = u16(code) }
	c._msg_active = false
	clear(&c._msg)
	if c._close_queued {
		abort(c)
		return
	}
	start_close(c, u16(code), "", after_send = true)
}

@(private)
start_close :: proc(c: ^Conn, code: u16, reason: string, after_send: bool) {
	if c._close_queued || c._aborting { return }
	c._close_queued = true
	c._close_after_send = after_send
	c.state = .Closing

	payload: [125]byte
	n := 0
	if code != u16(Close_Code.No_Status) && code != 0 {
		payload[0], payload[1] = byte(code >> 8), byte(code)
		n = 2
		// Truncate the reason to fit (on a code point boundary).
		r := reason
		if len(r) > 123 {
			cut := 123
			for cut > 0 && (r[cut] & 0xC0) == 0x80 { cut -= 1 }
			r = r[:cut]
		}
		n += copy(payload[2:], r)
	}
	push_frame(c, .Close, payload[:n], is_close = true)

	// Wait (a limited time) for the peer's close frame; unless we close right after sending.
	if !after_send {
		c._close_timer = nbio.timeout_poly(c._opts.close_timeout, c, proc(_: ^nbio.Operation, c: ^Conn) {
			c._close_timer = nil
			log.debug("websocket: peer did not complete the close handshake in time")
			abort(c)
		})
	}
}

@(private)
has_queued_close :: proc(c: ^Conn) -> bool {
	for f in c._queue { if f.close { return true } }
	return false
}

@(private)
queue_frame :: proc(c: ^Conn, opcode: Opcode, payload: []byte) -> Send_Result {
	if c.state != .Open || c._aborting { return .Closed }
	if !is_control(opcode) && c._queued_bytes + len(payload) > c._opts.send_queue_limit {
		return .Queue_Full
	}
	push_frame(c, opcode, payload)
	return .Ok
}

@(private)
push_frame :: proc(c: ^Conn, opcode: Opcode, payload: []byte, is_close := false) {
	hdr: [MAX_HEADER_SIZE]byte
	h := write_header(hdr[:], true, opcode, len(payload))
	buf := make([]byte, len(h) + len(payload), c._allocator)
	copy(buf, h)
	copy(buf[len(h):], payload)

	f := Out_Frame{buf = buf, payload_len = len(payload), close = is_close, data = !is_control(opcode)}
	if f.data { c._queued_bytes += len(payload) }

	// Pings/pongs jump ahead of queued data (but not of a frame already being written);
	// everything else, including close, keeps its order.
	if opcode == .Ping || opcode == .Pong {
		at := 1 if c._send_pending else 0
		at = min(at, len(c._queue))
		inject_at(&c._queue, at, f)
	} else {
		append(&c._queue, f)
	}
	send_next(c)
}

@(private)
send_next :: proc(c: ^Conn) {
	if c._send_pending || c._aborting || len(c._queue) == 0 { return }
	f := &c._queue[0]
	c._send_pending = true
	timeout := c._write_timeout if c._write_timeout > 0 else nbio.NO_TIMEOUT
	nbio.send_poly(c._h.socket, {f.buf[f.sent:]}, c, on_sent, all = false, timeout = timeout)
}

@(private)
on_sent :: proc(op: ^nbio.Operation, c: ^Conn) {
	c._send_pending = false
	if c._aborting {
		maybe_finalize(c)
		return
	}
	if op.send.err != nil {
		log.debugf("websocket: send failed: %v", op.send.err)
		abort(c)
		return
	}

	f := &c._queue[0]
	f.sent += op.send.sent
	if f.sent < len(f.buf) {
		send_next(c)
		return
	}

	done := f^
	ordered_remove(&c._queue, 0)
	if done.data { c._queued_bytes -= done.payload_len }
	delete(done.buf, c._allocator)

	if done.close {
		if c._close_after_send || c._close_received {
			abort(c)
			return
		}
	}

	if len(c._queue) == 0 {
		if c._cb.on_drain != nil && c.state == .Open {
			context.temp_allocator = http.hijacked_temp_allocator(c._h)
			c._cb.on_drain(c)
		}
	}
	send_next(c)
}

// Closes the TCP connection; the connection is finalized once pending operations complete.
@(private)
abort :: proc(c: ^Conn) {
	if c._aborting { return }
	c._aborting = true
	c.state = .Closing
	net.shutdown(c._h.socket, .Both)
	maybe_finalize(c)
}

@(private)
maybe_finalize :: proc(c: ^Conn) {
	if !c._aborting || c._recv_pending || c._send_pending || c._finalized { return }
	c._finalized = true
	c.state = .Closed
	unregister(c)

	if c._close_timer != nil {
		nbio.remove(c._close_timer)
		c._close_timer = nil
	}

	// The peer's code if the handshake happened, else the code we failed with, else 1006.
	code, reason := u16(Close_Code.Abnormal), ""
	switch {
	case c._close_received: code, reason = c._peer_code, c._peer_reason
	case c._fail_code != 0: code = c._fail_code
	}
	if c._cb.on_close != nil {
		context.temp_allocator = http.hijacked_temp_allocator(c._h)
		c._cb.on_close(c, code, reason)
	}

	for f in c._queue { delete(f.buf, c._allocator) }
	delete(c._queue)
	delete(c._rbuf)
	delete(c._msg)
	delete(c._peer_reason, c._allocator)

	h := c._h
	free(c, c._allocator)
	http.hijacked_close(h)
}
