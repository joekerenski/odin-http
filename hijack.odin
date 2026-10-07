package http

import "core:log"
import "core:mem"
import "core:mem/virtual"
import "core:net"

import "openssl"

/*
A connection taken over from the HTTP server with `response_hijack`, e.g. for WebSockets.

The connection stays on the event loop (thread) that served the request; all operations on it must
happen on that thread. It keeps counting towards `Server_Opts.max_connections`, and graceful
shutdown notifies the new owner (`on_shutdown`) and eventually shuts the socket down.

The owner must call `hijacked_close` exactly once, after all its operations on the socket have
completed (shutting the socket down with `net.shutdown(.Both)` makes pending operations complete).
*/
Hijacked :: struct {
	socket: net.TCP_Socket,
	client: net.Endpoint,
	// Set when the connection is TLS: the owner reads and writes through `ssl` from now on (its
	// memory BIOs hold the ciphertext, `rbio` possibly some already received) and frees it.
	tls:    Hijacked_TLS,
	_conn:  ^Connection,
}

Hijacked_TLS :: struct {
	ssl:        ^openssl.SSL,
	rbio, wbio: ^openssl.BIO,
}

// Called once the response has been sent (ok) or failed to send (not ok, the connection is closed).
// `buffered` holds bytes the client already sent after the request, it is only valid during the call.
Hijack_Callback :: #type proc(user_data: rawptr, h: Hijacked, buffered: []byte, ok: bool)

// Called (once) on the connection's thread when the server starts a graceful shutdown.
Hijack_Shutdown_Callback :: #type proc(user_data: rawptr)

@(private)
Hijack_State :: struct {
	user_data:   rawptr,
	cb:          Hijack_Callback,
	on_shutdown: Hijack_Shutdown_Callback,
	notified:    bool,
}

/*
Sends the response (typically `101 Switching Protocols`, with headers set by the caller, no body)
and then hands the connection over instead of reading the next request.

Requests with a body that hasn't been read can't be hijacked: a 400 is sent and the callback gets `ok = false`.

After the callback the request and response must no longer be used.
*/
response_hijack :: proc(r: ^Response, user_data: rawptr, cb: Hijack_Callback, on_shutdown: Hijack_Shutdown_Callback = nil, loc := #caller_location) {
	assert_has_td(loc)
	assert(!r.sent, "response has already been sent", loc)

	conn := r._conn
	req  := &conn.loop.req

	if req._framing != .None && req._body_ok == nil {
		log.info("refusing to hijack a connection with an unread request body")
		headers_set_close(&r.headers)
		r.status = .Bad_Request
		respond(r)
		cb(user_data, {}, nil, false)
		return
	}

	r.sent = true
	conn.hijack = new(Hijack_State, conn.server.conn_allocator)
	conn.hijack^ = {user_data = user_data, cb = cb, on_shutdown = on_shutdown}

	if !r._heading_written {
		_response_write_heading(r, -1)
	}
	connection_send(conn, r._buf.buf[:], proc(c: ^Connection, ok: bool) {
		hs := c.hijack
		if !ok || !connection_set_state(c, .Hijacked) {
			hs.cb(hs.user_data, {}, nil, false)
			free(hs, c.server.conn_allocator)
			c.hijack = nil
			c.state = .Will_Close
			connection_close(c)
			return
		}

		// The request/response memory is not needed anymore.
		free_all(virtual.arena_allocator(&c.temp_allocator))

		buffered := c.scanner.buf[c.scanner.start:c.scanner.end]
		h := Hijacked{socket = c.socket, client = c.loop.req.client, _conn = c}
		if t := c.tls; t != nil {
			// The TLS session goes to the new owner, the rest of our TLS state is freed.
			h.tls = {t.ssl, t.rbio, t.wbio}
			t.ssl = nil
			tls_conn_destroy(c)
		}
		c.loop = {}
		hs.cb(hs.user_data, h, buffered, true)

		// The scanner buffer isn't used anymore after the owner had the chance to copy what was buffered.
		scanner_destroy(&c.scanner)
		c.scanner = {}
	})
}

// A temporary allocator that lives as long as the hijacked connection; free_all it as you see fit.
hijacked_temp_allocator :: proc(h: Hijacked) -> mem.Allocator {
	return virtual.arena_allocator(&h._conn.temp_allocator)
}

// The write timeout configured on the server, for use by the new owner. <= 0 means none.
hijacked_server_opts :: proc(h: Hijacked) -> Server_Opts {
	return h._conn.server.opts
}

// Closes and frees a hijacked connection, see `Hijacked`.
hijacked_close :: proc(h: Hijacked) {
	c := h._conn
	assert(c.state == .Hijacked, "hijacked_close on a connection that isn't hijacked (or closed twice)")
	if c.hijack != nil {
		free(c.hijack, c.server.conn_allocator)
		c.hijack = nil
	}
	c.state = .Will_Close
	connection_close(c)
}

// Shutdown handling for hijacked connections, see `_server_thread_shutdown`.
@(private)
hijacked_on_server_shutdown :: proc(c: ^Connection, force: bool) {
	if c.hijack != nil && !c.hijack.notified {
		c.hijack.notified = true
		if c.hijack.on_shutdown != nil {
			c.hijack.on_shutdown(c.hijack.user_data)
		}
	}
	if force {
		net.shutdown(c.socket, .Both)
	}
}
