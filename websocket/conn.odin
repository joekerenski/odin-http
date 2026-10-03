// WebSocket connections (RFC 6455, RFC 7692), shared by the server (`upgrade`) and the client (`dial`).
//
// A connection lives on one event loop thread (the one that accepted or dialed it); all
// procedures in this package must be called from that thread (inside the callbacks, or from
// timers/operations on that loop), except the `*_from_any_thread` ones and `broadcast`.
package websocket

import "base:runtime"

import "core:crypto"
import "core:log"
import "core:mem"
import "core:nbio"
import "core:net"
import "core:strings"
import "core:time"

import http ".."

Opts :: struct {
	// Largest message (after reassembling fragments and decompressing) accepted, bigger ones close
	// the connection with 1009. Defaults to 1MiB.
	max_message_size:  int,
	// Largest single frame accepted, defaults to `max_message_size`.
	max_frame_size:    int,
	// Most bytes of data frames queued for sending; `send` returns `.Queue_Full` beyond it.
	// Control frames are not limited. Defaults to 4MiB.
	send_queue_limit:  int,
	// Send a ping after this long without receiving anything, defaults to 30s. Negative disables.
	ping_interval:     time.Duration,
	// Close the connection when nothing is received this long after a ping, defaults to 30s.
	pong_timeout:      time.Duration,
	// How long to wait for the peer's close frame after sending ours, defaults to 5s.
	close_timeout:     time.Duration,
	// Per write, defaults to the HTTP server's `write_timeout` (server) or 30s (client).
	write_timeout:     time.Duration,
	// Server: the subprotocols we speak, the first one the client offers (in the client's order) is
	// picked. Client: the subprotocols offered, the server picks one (see `Conn.subprotocol`).
	subprotocols:      []string,
	// permessage-deflate (RFC 7692): offered by the client, accepted by the server when the
	// client offers it. Costs ~300KiB of zlib state per connection.
	compression:       bool,
	// zlib level 1 (fastest) .. 9 (smallest), defaults to 1: for live messages speed matters more
	// than the last few percent of size (level 6 was ~35% slower in bench/ws, echoz-4k).
	compression_level: int,
	// Server only. Decides whether a handshake with the given Origin header is accepted. When nil,
	// requests with an Origin are only accepted if it names the same host as the Host header
	// (browsers always send Origin, so this blocks cross-site WebSocket hijacking); requests without
	// one are accepted. Use `allow_any_origin` to accept everything.
	check_origin:      proc(req: ^http.Request, origin: string) -> bool,
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
	// `c` is freed after this returns. `code` is 1006 (Abnormal) if no close frame was exchanged;
	// for a client whose handshake failed, `reason` says why.
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

Role :: enum u8 {
	Server,
	Client,
}

Conn :: struct {
	user_data:     rawptr,
	// The negotiated subprotocol, "" if none.
	subprotocol:   string,
	state:         State,
	role:          Role,
	// Whether permessage-deflate was negotiated.
	compressed:    bool,

	_id:           u64,
	_loop:         ^nbio.Event_Loop,
	_cb:           Callbacks,
	_opts:         Opts,
	_allocator:    mem.Allocator,
	_write_timeout: time.Duration,

	// Transport: set by the server (hijacked HTTP connection) or the client.
	_socket:       net.TCP_Socket,
	// Temp allocator for the callbacks, reset after every message.
	_temp:         mem.Allocator,
	// Closes the socket and frees what the role owns, right before `c` is freed.
	_release:      proc(c: ^Conn),
	_h:            http.Hijacked,
	_client:       ^Client_State,
	// Client wss:// connections, see tls.odin.
	_tls:               ^Tls,
	_tls_handshake_done: proc(c: ^Conn, why: string),
	_tls_write_timeout:  time.Duration,
	_plain_recv_done:    Recv_Done,
	_plain_send_done:    Send_Done,

	// Compression (when negotiated).
	_deflate:      Deflater,
	_inflate:      Inflater,

	// Client: masks from the CSPRNG, 64 at a time.
	_masks:        [256]byte,
	_mask_pos:     int,

	// Read side.
	_rbuf:           [dynamic]byte,
	_rstart:         int,
	_msg:            [dynamic]byte,
	_msg_active:     bool,
	_msg_kind:       Message_Kind,
	_msg_compressed: bool,
	_utf8:           Utf8_Validator,
	_recv_pending:   bool,

	// Keepalive: one timer per connection instead of a timeout on every read.
	_keepalive:      ^nbio.Operation,
	_last_rx:        time.Time,
	_ping_sent:      time.Time,
	_awaiting_pong:  bool,

	// Write side.
	_queue:         [dynamic]Out_Frame,
	_queued_bytes:  int,
	_send_pending:  bool,
	// Frames at the front of the queue that the pending send covers.
	_inflight:      int,

	// Close handshake.
	_close_queued:     bool,
	_close_after_send: bool,
	_close_received:   bool,
	// Client: the close handshake is done, waiting for the server to close TCP.
	_awaiting_eof:     bool,
	// Entry points (I/O completions) running for this connection, see `enter`.
	_busy:             int,
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
	// Set when `buf` is shared with other connections (a broadcast), see `Shared_Frame`.
	shared:      ^Shared_Frame,
	sent:        int,
	payload_len: int,
	close:       bool,
	data:        bool,
}

/*
An encoded frame queued on several connections of one event loop (a broadcast to uncompressed
server connections: no mask, so the bytes are the same for all). Freed when the last one sent it.
Only used on its loop's thread, so the count isn't atomic.
*/
@(private)
Shared_Frame :: struct {
	refs:      int,
	buf:       []byte,
	allocator: mem.Allocator,
}

@(private)
shared_frame_make :: proc(kind: Message_Kind, payload: []byte, allocator: mem.Allocator) -> ^Shared_Frame {
	hdr: [MAX_HEADER_SIZE]byte
	h := write_header(hdr[:], true, Opcode(kind), len(payload))
	sf := new(Shared_Frame, allocator)
	sf.allocator = allocator
	sf.buf = make([]byte, len(h) + len(payload), allocator)
	copy(sf.buf, h)
	copy(sf.buf[len(h):], payload)
	sf.refs = 1 // The creator's reference, see `shared_frame_release`.
	return sf
}

@(private)
shared_frame_release :: proc(sf: ^Shared_Frame) {
	sf.refs -= 1
	if sf.refs == 0 {
		delete(sf.buf, sf.allocator)
		free(sf, sf.allocator)
	}
}

// Whether a shared frame (see `Shared_Frame`) can be queued on `c` instead of encoding its own.
@(private)
can_share_frames :: proc(c: ^Conn) -> bool {
	return c.role == .Server && !c.compressed
}

// Queues a shared frame; same rules as `send`.
@(private)
queue_shared_frame :: proc(c: ^Conn, sf: ^Shared_Frame, payload_len: int) -> Send_Result {
	if c.state != .Open || c._aborting { return .Closed }
	if c._queued_bytes + payload_len > c._opts.send_queue_limit { return .Queue_Full }
	sf.refs += 1
	append(&c._queue, Out_Frame{buf = sf.buf, shared = sf, payload_len = payload_len, data = true})
	c._queued_bytes += payload_len
	send_next(c)
	return .Ok
}

@(private)
frame_free :: proc(c: ^Conn, f: Out_Frame) {
	if f.shared != nil {
		shared_frame_release(f.shared)
	} else {
		delete(f.buf, c._allocator)
	}
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

// --- Setup ---

@(private)
conn_init :: proc(c: ^Conn, role: Role, opts: Opts, callbacks: Callbacks, allocator: mem.Allocator) {
	c.role = role
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
	c._write_timeout = c._opts.write_timeout
	c._rbuf.allocator  = allocator
	c._msg.allocator   = allocator
	c._queue.allocator = allocator
}

// Sets up compression with the negotiated parameters, false when zlib failed.
@(private)
conn_init_compression :: proc(c: ^Conn, p: Deflate_Params) -> bool {
	ours_window: int
	ours_reset, theirs_reset: bool
	switch c.role {
	case .Server:
		ours_window, ours_reset, theirs_reset = p.server_max_window_bits, p.server_no_context_takeover, p.client_no_context_takeover
	case .Client:
		ours_window, ours_reset, theirs_reset = max(p.client_max_window_bits, 0), p.client_no_context_takeover, p.server_no_context_takeover
	}
	if !deflater_init(&c._deflate, ours_window, c._opts.compression_level, ours_reset) || !inflater_init(&c._inflate, theirs_reset) {
		conn_destroy_compression(c)
		return false
	}
	c.compressed = true
	return true
}

@(private)
conn_destroy_compression :: proc(c: ^Conn) {
	deflater_destroy(&c._deflate)
	inflater_destroy(&c._inflate)
}

// The handshake is done: the connection is open. `buffered` are bytes already read after it.
@(private)
conn_open :: proc(c: ^Conn, buffered: []byte) {
	c.state = .Open
	register(c)
	enter(c)
	defer leave(c)
	append(&c._rbuf, ..buffered)

	c._last_rx = nbio.now()
	if c._opts.ping_interval > 0 {
		arm_keepalive(c, c._opts.ping_interval)
	}

	context.temp_allocator = c._temp
	if c._cb.on_open != nil { c._cb.on_open(c) }

	process(c)
	if !c._aborting {
		start_recv(c)
	}
}

// --- Read side ---

@(private)
start_recv :: proc(c: ^Conn) {
	if c._recv_pending || c._aborting { return }

	// Room for at least one header + a decent chunk.
	if cap(c._rbuf) - len(c._rbuf) < 4096 {
		reserve(&c._rbuf, len(c._rbuf) + 16384)
	}

	// Idle connections are handled by the keepalive timer, not per read.
	timeout := c._opts.close_timeout if c.state == .Closing else nbio.NO_TIMEOUT

	c._recv_pending = true
	// The unused capacity of the buffer (slicing the dynamic array itself is bounded by its length).
	spare := ([^]byte)(raw_data(c._rbuf))[len(c._rbuf):cap(c._rbuf)]
	transport_recv(c, spare, timeout, on_recv)
}

@(private)
on_recv :: proc(c: ^Conn, received: int, err: IO_Error) {
	c._recv_pending = false
	enter(c)
	defer leave(c)
	if c._aborting { return }

	if err != .None {
		// .Closed: the peer closed the connection (without a close handshake if we didn't get one).
		if err == .Timeout {
			log.debug("websocket: peer did not finish closing in time")
		}
		abort(c)
		return
	}

	(^runtime.Raw_Dynamic_Array)(&c._rbuf).len += received
	c._last_rx = nbio.now()
	c._awaiting_pong = false

	context.temp_allocator = c._temp
	process(c)

	if !c._aborting {
		start_recv(c)
	}
}

@(private)
arm_keepalive :: proc(c: ^Conn, after: time.Duration) {
	c._keepalive = nbio.timeout_poly(max(after, time.Millisecond), c, on_keepalive)
}

/*
Runs every `ping_interval` (or `pong_timeout` while waiting for a pong): pings a connection that
has been quiet for `ping_interval`, closes it when nothing came back within `pong_timeout`.
*/
@(private)
on_keepalive :: proc(_: ^nbio.Operation, c: ^Conn) {
	c._keepalive = nil
	enter(c)
	defer leave(c)
	if c._aborting || c.state != .Open { return }

	now := nbio.now()
	if c._awaiting_pong {
		waited := time.diff(c._ping_sent, now)
		if waited >= c._opts.pong_timeout {
			log.debug("websocket: peer did not respond to ping")
			abort(c)
			return
		}
		arm_keepalive(c, c._opts.pong_timeout - waited)
		return
	}

	idle := time.diff(c._last_rx, now)
	if idle >= c._opts.ping_interval {
		c._awaiting_pong = true
		c._ping_sent = now
		queue_frame(c, .Ping, nil)
		arm_keepalive(c, c._opts.pong_timeout)
		return
	}
	arm_keepalive(c, c._opts.ping_interval - idle)
}

// Parses and handles all complete frames in the read buffer.
@(private)
process :: proc(c: ^Conn) {
	defer compact(c)

	// After the peer's close frame nothing else is processed.
	if c._close_received {
		clear(&c._rbuf)
		c._rstart = 0
		return
	}

	allowed_rsv: u8 = RSV1 if c.compressed else 0
	for !c._aborting && !c._close_received {
		avail := c._rbuf[c._rstart:]
		h, hl, res := parse_header(avail, require_mask = c.role == .Server, allowed_rsv = allowed_rsv)
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
		if h.masked { apply_mask(payload, h.mask) }
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
	// RSV1 (compression) is only allowed on the first frame of a data message.
	if h.rsv != 0 && (is_control(h.opcode) || h.opcode == .Continuation) {
		fail(c, .Protocol_Error)
		return
	}

	switch h.opcode {
	case .Text, .Binary:
		if c._msg_active { fail(c, .Protocol_Error); return }
		kind := Message_Kind(h.opcode)

		if h.rsv & RSV1 != 0 {
			c._msg_active = true
			c._msg_kind = kind
			c._msg_compressed = true
			c._utf8 = {}
			clear(&c._msg)
			if !inflate_fragment(c, payload) { return }
			if h.fin { finish_message(c) }
			return
		}

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
		c._msg_compressed = false
		c._utf8 = {}
		append_fragment(c, payload)

	case .Continuation:
		if !c._msg_active { fail(c, .Protocol_Error); return }
		if c._msg_compressed {
			if !inflate_fragment(c, payload) { return }
		} else {
			if !append_fragment(c, payload) { return }
		}
		if h.fin { finish_message(c) }

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
			// Echo the code back, then the TCP connection is closed (see `finish_close`).
			start_close(c, code, "", after_send = true)
		} else if has_queued_close(c) {
			// Our close frame is still on its way, finish once it's out.
			c._close_after_send = true
		} else {
			// This is the reply to our close: done.
			finish_close(c)
		}
	}
}

// Appends an uncompressed fragment, false if the connection was failed.
@(private)
append_fragment :: proc(c: ^Conn, payload: []byte) -> bool {
	if c._msg_kind == .Text && !utf8_feed(&c._utf8, payload) {
		fail(c, .Invalid_Payload)
		return false
	}
	append(&c._msg, ..payload)
	return true
}

// Decompresses a fragment into the message, false if the connection was failed.
@(private)
inflate_fragment :: proc(c: ^Conn, payload: []byte) -> bool {
	before := len(c._msg)
	return inflated(c, inflate_append(&c._inflate, payload, &c._msg, c._opts.max_message_size), before)
}

@(private)
inflated :: proc(c: ^Conn, res: Inflate_Result, before: int) -> bool {
	switch res {
	case .Ok:
	case .Too_Big:
		fail(c, .Message_Too_Big)
		return false
	case .Error:
		log.debug("websocket: invalid compressed data")
		fail(c, .Invalid_Payload)
		return false
	}
	// Text is validated as it is decompressed, failing fast.
	if c._msg_kind == .Text && !utf8_feed(&c._utf8, c._msg[before:]) {
		fail(c, .Invalid_Payload)
		return false
	}
	return true
}

// The last fragment of a fragmented or compressed message arrived.
@(private)
finish_message :: proc(c: ^Conn) {
	if c._msg_compressed {
		before := len(c._msg)
		if !inflated(c, inflate_finish(&c._inflate, &c._msg, c._opts.max_message_size), before) { return }
	}
	if c._msg_kind == .Text && !utf8_complete(&c._utf8) { fail(c, .Invalid_Payload); return }
	c._msg_active = false
	deliver(c, c._msg_kind, c._msg[:])
	clear(&c._msg)
}

@(private)
deliver :: proc(c: ^Conn, kind: Message_Kind, data: []byte) {
	// After we sent a close, incoming data is discarded.
	if c.state != .Open { return }
	if c._cb.on_message != nil {
		c._cb.on_message(c, kind, data)
	}
}

// --- Closing ---

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
		set_close_timer(c)
	}
}

@(private)
set_close_timer :: proc(c: ^Conn) {
	if c._close_timer != nil { nbio.remove(c._close_timer) }
	c._close_timer = nbio.timeout_poly(c._opts.close_timeout, c, proc(_: ^nbio.Operation, c: ^Conn) {
		c._close_timer = nil
		log.debug("websocket: peer did not finish closing in time")
		abort(c)
	})
}

/*
Both close frames have been exchanged (or we failed the connection and our close frame is out).
The server closes the TCP connection right away; a client waits (`close_timeout`) for the server
to do it, so the server is the one in TIME_WAIT (RFC 6455 7.1.1).
*/
@(private)
finish_close :: proc(c: ^Conn) {
	if c.role == .Server {
		abort(c)
		return
	}
	if c._awaiting_eof { return }
	c._awaiting_eof = true
	set_close_timer(c)
	// Reading goes on: the server closing TCP ends it (`on_recv` gets 0 bytes).
}

@(private)
has_queued_close :: proc(c: ^Conn) -> bool {
	for f in c._queue { if f.close { return true } }
	return false
}

// --- Write side ---

@(private)
queue_frame :: proc(c: ^Conn, opcode: Opcode, payload: []byte) -> Send_Result {
	if c.state != .Open || c._aborting { return .Closed }
	if is_control(opcode) {
		push_frame(c, opcode, payload)
		return .Ok
	}
	// Checked before compressing: a compressed message that isn't sent would desync the peer's
	// decompressor (the compression context carries over between messages).
	if c._queued_bytes + len(payload) > c._opts.send_queue_limit {
		return .Queue_Full
	}
	if c.compressed && len(payload) >= COMPRESS_MIN_SIZE {
		if compressed, ok := deflate_message(&c._deflate, payload, c._allocator); ok {
			defer delete(compressed)
			push_frame(c, opcode, compressed[:], rsv = RSV1)
			return .Ok
		}
		log.error("websocket: compression failed, failing the connection")
		fail(c, .Internal_Error)
		return .Closed
	}
	push_frame(c, opcode, payload)
	return .Ok
}

@(private)
push_frame :: proc(c: ^Conn, opcode: Opcode, payload: []byte, is_close := false, rsv: u8 = 0) {
	mask: Maybe([4]byte)
	if c.role == .Client { mask = next_mask(c) }

	hdr: [MAX_HEADER_SIZE]byte
	h := write_header(hdr[:], true, opcode, len(payload), mask, rsv)
	buf := make([]byte, len(h) + len(payload), c._allocator)
	copy(buf, h)
	copy(buf[len(h):], payload)
	if m, ok := mask.?; ok { apply_mask(buf[len(h):], m) }

	f := Out_Frame{buf = buf, payload_len = len(payload), close = is_close, data = !is_control(opcode)}
	if f.data { c._queued_bytes += len(payload) }

	// Pings/pongs jump ahead of queued data (but not of frames already being written, nor of
	// earlier pings/pongs, so pongs go out in the order their pings came in);
	// everything else, including close, keeps its order.
	if opcode == .Ping || opcode == .Pong {
		at := c._inflight if c._send_pending else 0
		at = min(at, len(c._queue))
		for at < len(c._queue) && !c._queue[at].data && !c._queue[at].close {
			at += 1
		}
		inject_at(&c._queue, at, f)
	} else {
		append(&c._queue, f)
	}
	send_next(c)
}

// Client frames are masked with unpredictable keys (RFC 6455 10.3), from the CSPRNG in batches.
@(private)
next_mask :: proc(c: ^Conn) -> (m: [4]byte) {
	if c._mask_pos == 0 { crypto.rand_bytes(c._masks[:]) }
	copy(m[:], c._masks[c._mask_pos:])
	c._mask_pos = (c._mask_pos + 4) % len(c._masks)
	return
}

// Most frames written with one (vectored) send.
@(private)
MAX_SEND_BATCH :: 64

@(private)
send_next :: proc(c: ^Conn) {
	if c._send_pending || c._aborting || len(c._queue) == 0 { return }
	// Everything queued (up to a limit) in one go: one operation for many small messages.
	n := min(len(c._queue), MAX_SEND_BATCH)
	bufs: [MAX_SEND_BATCH][]byte
	for i in 0 ..< n {
		f := &c._queue[i]
		bufs[i] = f.buf[f.sent:]
	}
	c._inflight = n
	c._send_pending = true
	timeout := c._write_timeout if c._write_timeout > 0 else nbio.NO_TIMEOUT
	transport_send(c, bufs[:n], timeout, on_sent)
}

@(private)
on_sent :: proc(c: ^Conn, sent: int, err: IO_Error) {
	c._send_pending = false
	enter(c)
	defer leave(c)
	if c._aborting { return }
	if err != .None {
		log.debugf("websocket: send failed: %v", err)
		abort(c)
		return
	}

	// Account the written bytes to the frames in flight, in order.
	sent := sent
	done := 0
	for i in 0 ..< c._inflight {
		f := &c._queue[i]
		left := len(f.buf) - f.sent
		if sent < left {
			f.sent += sent
			break
		}
		sent -= left
		f.sent = len(f.buf)
		done += 1
	}
	c._inflight = 0

	close_sent := false
	for f in c._queue[:done] {
		if f.data { c._queued_bytes -= f.payload_len }
		if f.close { close_sent = true }
		frame_free(c, f)
	}
	remove_range(&c._queue, 0, done)

	if close_sent && (c._close_after_send || c._close_received) {
		finish_close(c)
		return
	}

	if len(c._queue) == 0 {
		if c._cb.on_drain != nil && c.state == .Open {
			context.temp_allocator = c._temp
			c._cb.on_drain(c)
		}
	}
	send_next(c)
}

// --- Teardown ---

// Closes the TCP connection; the connection is finalized once pending operations complete.
@(private)
abort :: proc(c: ^Conn) {
	if c._aborting { return }
	c._aborting = true
	c.state = .Closing
	net.shutdown(c._socket, .Both)
	maybe_finalize(c)
}

/*
I/O completions run code that can abort the connection (protocol errors, the close handshake,
user callbacks calling `close`) and then keep using it. While one runs the connection is busy and
can't be freed, it's finalized when the last entry point returns.
*/
@(private)
enter :: proc(c: ^Conn) {
	c._busy += 1
}

@(private)
leave :: proc(c: ^Conn) {
	c._busy -= 1
	if c._busy == 0 {
		maybe_finalize(c)
	}
}

@(private)
maybe_finalize :: proc(c: ^Conn) {
	if !c._aborting || c._busy > 0 || c._recv_pending || c._send_pending || transport_busy(c) || c._finalized { return }
	c._finalized = true
	c.state = .Closed
	unregister(c)

	if c._close_timer != nil {
		nbio.remove(c._close_timer)
		c._close_timer = nil
	}
	if c._keepalive != nil {
		nbio.remove(c._keepalive)
		c._keepalive = nil
	}

	// The peer's code if the handshake happened, else the code we failed with, else 1006.
	code, reason := u16(Close_Code.Abnormal), ""
	switch {
	case c._close_received: code, reason = c._peer_code, c._peer_reason
	case c._fail_code != 0: code = c._fail_code
	}
	if c._cb.on_close != nil {
		context.temp_allocator = c._temp
		c._cb.on_close(c, code, reason)
	}

	for f in c._queue { frame_free(c, f) }
	delete(c._queue)
	delete(c._rbuf)
	delete(c._msg)
	delete(c._peer_reason, c._allocator)
	conn_destroy_compression(c)

	c._release(c)
	free(c, c._allocator)
}
