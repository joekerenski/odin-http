#+private
package client

import "core:log"
import "core:mem"
import "core:mem/virtual"
import "core:nbio"
import "core:net"
import "core:time"

import http ".."
import "../openssl"

// Ciphertext / plaintext read at once.
READ_SIZE :: 32 * 1024

/*
One request in flight. Strictly sequential: connect (or take an idle connection from the pool),
TLS handshake, write the request, read until the response is complete. So at most one nbio
operation is pending, and `finish` (which frees the request's state) is only ever called from a
completion with nothing else in flight.
*/
Conn :: struct {
	opts:        Opts,
	deadline:    time.Time,
	request:     []byte,
	method:      http.Method,
	socket:      net.TCP_Socket,
	tls:         bool,
	tls_host:    string,
	tls_is_ip:   bool,
	tls_ca_file: string,
	tls_ctx:     ^openssl.SSL_CTX,
	port:        int,
	// The pool's key for the origin, "" without keep-alive.
	key:         string,
	// The connection came from the pool (and may turn out to be closed already).
	reused:      bool,
	// Some of the response arrived.
	got_bytes:   bool,
	// The request couldn't be (fully) written: the server may still have answered (e.g. 413).
	send_failed: bool,

	// TLS: ciphertext comes in through `cin` into `rbio`, goes out of `wbio` through `out`.
	ssl:         ^openssl.SSL,
	rbio, wbio:  ^openssl.BIO,
	cin:         []byte,
	out:         [dynamic]byte,
	// What to do once `out` is written.
	after_flush: proc(c: ^Conn),

	// Received plaintext not yet consumed by the parser.
	buf:         [dynamic]byte,
	parser:      Parser,
	res_arena:   ^virtual.Arena,

	cb:          Callback,
	user_data:   rawptr,
	allocator:   mem.Allocator,

	// A streamed response: the parser hands the head and body to these.
	stream:      Stream,
	stream_user: rawptr,
}

acquire_loop :: proc() -> nbio.General_Error { return nbio.acquire_thread_event_loop() }
release_loop :: proc() { nbio.release_thread_event_loop() }
tick_loop    :: proc() -> nbio.General_Error { return nbio.tick() }

start :: proc(req: ^Request, url: string, opts: Opts, user_data: rawptr, cb: Callback, allocator: mem.Allocator, stream := Stream{}, stream_user: rawptr = nil) -> Error {
	t := parse_url(url, context.temp_allocator) or_return
	request := format_request(req, t, !opts.disable_keep_alive, allocator) or_return

	c := new(Conn, allocator)
	c.opts      = opts
	c.deadline  = time.time_add(nbio.now(), opts.timeout)
	c.request   = request
	c.method    = req.method
	c.tls       = t.tls
	c.tls_is_ip = t.is_ip
	c.port      = t.port
	c.cb        = cb
	c.user_data = user_data
	c.allocator = allocator
	c.stream      = stream
	c.stream_user = stream_user
	c.buf.allocator = allocator
	c.out.allocator = allocator

	c.res_arena = new(virtual.Arena, allocator)
	if virtual.arena_init_growing(c.res_arena) != nil {
		free(c.res_arena, allocator)
		delete(c.request, allocator)
		free(c, allocator)
		return .Network_Error
	}
	arena := virtual.arena_allocator(c.res_arena)
	c.tls_host    = clone_string(t.host, arena)
	c.tls_ca_file = clone_string(opts.tls_ca_file, arena)
	if !opts.disable_keep_alive { c.key = origin_key(t, opts.tls_ca_file, arena) }
	parser_init(&c.parser, opts, req.method == .Head, arena, allocator)
	if stream.on_body != nil {
		c.parser.on_head = on_stream_head
		c.parser.on_body = on_stream_body
		c.parser.user_data = c
	}

	if c.key != "" {
		if ic, ok := pool_get(c.key); ok {
			adopt(c, ic)
			send_request(c)
			return .None
		}
	}

	if err := connect(c); err != nil {
		virtual.arena_destroy(c.res_arena)
		free(c.res_arena, allocator)
		delete(c.parser.body)
		conn_free(c)
		return err
	}
	return .None
}

// Resolves the host (blocking), sets up TLS and starts connecting.
connect :: proc(c: ^Conn) -> Error {
	endpoint: net.Endpoint
	if c.tls_is_ip {
		addr := net.parse_address(c.tls_host)
		if addr == nil { return .Invalid_URL }
		endpoint = {addr, c.port}
	} else {
		ep4, ep6, err := net.resolve(c.tls_host)
		if err != nil { return .Resolve_Failed }
		endpoint = ep4 if ep4 != {} else ep6
		if endpoint == {} { return .Resolve_Failed }
		endpoint.port = c.port
	}

	if c.tls && c.tls_ctx == nil {
		c.tls_ctx = openssl.client_ctx(c.tls_ca_file)
		if c.tls_ctx == nil {
			log.warnf("client: TLS setup failed: %s", openssl.error_string())
			return .TLS_Setup_Failed
		}
	}

	pool_record_dial()
	nbio.dial_poly(endpoint, c, on_dialed, timeout = min(c.opts.connect_timeout, time_left(c)))
	return .None
}

// Takes over an idle connection from the pool.
adopt :: proc(c: ^Conn, ic: Idle_Conn) {
	c.reused = true
	c.socket = ic.socket
	c.ssl, c.rbio, c.wbio = ic.ssl, ic.rbio, ic.wbio
	if c.ssl != nil { c.cin = make([]byte, READ_SIZE, c.allocator) }
}

// Frees the request's state (not the connection's socket and TLS state, see `finish`).
conn_free :: proc(c: ^Conn) {
	if c.tls_ctx != nil { openssl.SSL_CTX_free(c.tls_ctx) }
	delete(c.cin, c.allocator)
	delete(c.out)
	delete(c.buf)
	delete(c.request, c.allocator)
	free(c, c.allocator)
}

@(private="file")
clone_string :: proc(s: string, allocator: mem.Allocator) -> string {
	b := make([]byte, len(s), allocator)
	copy(b, s)
	return string(b)
}

time_left :: proc(c: ^Conn) -> time.Duration {
	return max(time.diff(nbio.now(), c.deadline), time.Millisecond)
}

// How long one read may wait: what's left of the deadline, at most `stall_timeout`.
read_timeout :: proc(c: ^Conn) -> time.Duration {
	t := time_left(c)
	if c.opts.stall_timeout > 0 { t = min(t, c.opts.stall_timeout) }
	return t
}

// The head of a streamed response is in. From here only `stall_timeout` bounds the wait: the body
// may keep coming for as long as it does.
on_stream_head :: proc(p: ^Parser) -> bool {
	c := (^Conn)(p.user_data)
	c.deadline = time.time_add(nbio.now(), 365 * 24 * time.Hour)
	if c.stream.on_head == nil { return true }
	p.headers.readonly = true
	return c.stream.on_head(http.Status(p.status), p.headers, c.stream_user)
}

on_stream_body :: proc(p: ^Parser, data: []byte) -> bool {
	c := (^Conn)(p.user_data)
	return c.stream.on_body(data, c.stream_user)
}

expired :: proc(c: ^Conn) -> bool {
	return time.diff(nbio.now(), c.deadline) <= 0
}

on_dialed :: proc(op: ^nbio.Operation, c: ^Conn) {
	if op.dial.err != nil {
		log.debugf("client: connect failed: %v", op.dial.err)
		finish(c, .Timeout if op.dial.err == net.Dial_Error.Timeout || expired(c) else .Connect_Failed)
		return
	}
	c.socket = op.dial.socket

	if !c.tls {
		send_request(c)
		return
	}

	ok: bool
	c.ssl, c.rbio, c.wbio, ok = openssl.client_ssl(c.tls_ctx, c.tls_host, c.tls_is_ip)
	if !ok {
		finish(c, .TLS_Setup_Failed)
		return
	}
	c.cin = make([]byte, READ_SIZE, c.allocator)
	handshake(c)
}

// --- TLS ---

handshake :: proc(c: ^Conn) {
	openssl.ERR_clear_error()
	r := openssl.SSL_do_handshake(c.ssl)
	openssl.drain_bio(c.wbio, &c.out)

	// Write what the handshake produced first, then carry on.
	if len(c.out) > 0 {
		flush(c, handshake)
		return
	}
	if r == 1 {
		send_request(c)
		return
	}

	switch openssl.SSL_get_error(c.ssl, r) {
	case openssl.SSL_ERROR_WANT_READ:
		read_cipher(c, handshake)
	case:
		if why := openssl.verify_error(c.ssl); why != "" {
			log.infof("client: certificate of %s rejected: %s", c.tls_host, why)
			finish(c, .TLS_Verification_Failed)
		} else {
			log.infof("client: TLS handshake with %s failed: %s", c.tls_host, openssl.error_string())
			finish(c, .TLS_Failed)
		}
	}
}

// Writes `out`, then calls `next`.
flush :: proc(c: ^Conn, next: proc(c: ^Conn)) {
	if expired(c) { finish(c, .Timeout); return }
	c.after_flush = next
	nbio.send_poly(c.socket, {c.out[:]}, c, proc(op: ^nbio.Operation, c: ^Conn) {
		clear(&c.out)
		if op.send.err != nil {
			on_send_error(c, op.send.err)
			return
		}
		c.after_flush(c)
	}, all = true, timeout = time_left(c))
}

// Reads ciphertext into `rbio`, then calls `next`.
read_cipher :: proc(c: ^Conn, next: proc(c: ^Conn)) {
	if expired(c) { finish(c, .Timeout); return }
	c.after_flush = next
	nbio.recv_poly(c.socket, {c.cin}, c, proc(op: ^nbio.Operation, c: ^Conn) {
		if op.recv.err != nil {
			on_recv_error(c, op.recv.err)
			return
		}
		if op.recv.received == 0 {
			on_eof(c)
			return
		}
		openssl.BIO_write(c.rbio, raw_data(c.cin), i32(op.recv.received))
		c.after_flush(c)
	}, timeout = read_timeout(c))
}

// --- Request ---

send_request :: proc(c: ^Conn) {
	if c.ssl == nil {
		if expired(c) { finish(c, .Timeout); return }
		nbio.send_poly(c.socket, {c.request}, c, proc(op: ^nbio.Operation, c: ^Conn) {
			if op.send.err != nil {
				on_send_error(c, op.send.err)
				return
			}
			read_response(c)
		}, all = true, timeout = time_left(c))
		return
	}

	openssl.ERR_clear_error()
	if len(c.request) > 0 {
		// Memory BIOs take everything at once.
		if r := openssl.SSL_write(c.ssl, raw_data(c.request), i32(len(c.request))); int(r) != len(c.request) {
			log.infof("client: TLS write failed: %s", openssl.error_string())
			finish(c, .TLS_Failed)
			return
		}
	}
	openssl.drain_bio(c.wbio, &c.out)
	flush(c, read_response)
}

/*
Sending failed. A server can answer and close before reading the whole request (e.g. 413), so
unless the connection is unusable we still read what it sent.
*/
on_send_error :: proc(c: ^Conn, err: net.Send_Error) {
	if err == net.TCP_Send_Error.Timeout || expired(c) {
		finish(c, .Timeout)
		return
	}
	log.debugf("client: send failed: %v", err)
	if c.send_failed {
		finish(c, .Network_Error)
		return
	}
	c.send_failed = true
	read_response(c)
}

// --- Response ---

read_response :: proc(c: ^Conn) {
	if c.ssl != nil {
		read_tls(c)
		return
	}
	if expired(c) { finish(c, .Timeout); return }
	if cap(c.buf) - len(c.buf) < READ_SIZE / 2 { reserve(&c.buf, len(c.buf) + READ_SIZE) }
	spare := ([^]byte)(raw_data(c.buf))[len(c.buf):cap(c.buf)]
	nbio.recv_poly(c.socket, {spare}, c, proc(op: ^nbio.Operation, c: ^Conn) {
		if op.recv.err != nil {
			on_recv_error(c, op.recv.err)
			return
		}
		if op.recv.received == 0 {
			on_eof(c)
			return
		}
		non_zero_resize(&c.buf, len(c.buf) + op.recv.received)
		c.got_bytes = true
		feed(c)
	}, timeout = read_timeout(c))
}

read_tls :: proc(c: ^Conn) {
	if cap(c.buf) - len(c.buf) < READ_SIZE / 2 { reserve(&c.buf, len(c.buf) + READ_SIZE) }
	spare := ([^]byte)(raw_data(c.buf))[len(c.buf):cap(c.buf)]
	room := cap(c.buf) - len(c.buf)

	openssl.ERR_clear_error()
	n := 0
	ssl_err: i32
	for n < room {
		r := openssl.SSL_read(c.ssl, &spare[n], i32(min(room - n, int(max(i32)))))
		if r <= 0 {
			ssl_err = openssl.SSL_get_error(c.ssl, r)
			break
		}
		n += int(r)
	}
	if n > 0 { c.got_bytes = true }
	// Reading can make OpenSSL answer (e.g. a key update): write that first.
	if openssl.drain_bio(c.wbio, &c.out) > 0 && !c.send_failed {
		if n > 0 { non_zero_resize(&c.buf, len(c.buf) + n) }
		flush(c, proc(c: ^Conn) { feed(c) })
		return
	}
	if n > 0 {
		non_zero_resize(&c.buf, len(c.buf) + n)
		feed(c)
		return
	}

	switch ssl_err {
	case openssl.SSL_ERROR_WANT_READ:
		read_cipher(c, read_tls)
	case openssl.SSL_ERROR_ZERO_RETURN:
		// The server's close_notify: the end of the stream.
		on_eof(c)
	case:
		log.infof("client: TLS read failed: %s", openssl.error_string())
		finish(c, .TLS_Failed)
	}
}

// Parses what was received, then reads more or finishes.
feed :: proc(c: ^Conn) {
	consumed, err := parser_feed(&c.parser, c.buf[:])
	remove_range(&c.buf, 0, consumed)
	if err != nil {
		finish(c, err)
		return
	}
	if c.parser.state == .Done {
		finish(c, .None)
		return
	}
	read_response(c)
}

on_recv_error :: proc(c: ^Conn, err: net.Recv_Error) {
	if err == net.TCP_Recv_Error.Timeout || expired(c) {
		finish(c, .Timeout)
		return
	}
	log.debugf("client: receive failed: %v", err)
	finish(c, .Network_Error)
}

on_eof :: proc(c: ^Conn) {
	err := parser_eof(&c.parser)
	if err == .Connection_Closed && c.send_failed { err = .Network_Error }
	finish(c, err)
}

// Delivers the response or the error. The connection goes back to the pool when it can be reused.
finish :: proc(c: ^Conn, err: Error) {
	if err != nil && should_retry(c, err) {
		retry(c)
		return
	}

	res: Response
	p := &c.parser
	if err == nil {
		p.headers.readonly = true
		p.trailers.readonly = true
		res = Response{
			status     = http.Status(p.status),
			headers    = p.headers,
			trailers   = p.trailers,
			cookies    = p.cookies[:],
			body       = string(p.body[:]),
			_arena     = c.res_arena,
			_body      = p.body,
			_allocator = c.allocator,
		}
	}

	if err == nil && reusable(c) {
		pool_put(c.key, {
			socket  = c.socket,
			ssl     = c.ssl,
			rbio    = c.rbio,
			wbio    = c.wbio,
			expires = time.tick_add(time.tick_now(), c.opts.idle_timeout),
		}, c.opts.max_idle_per_host)
	} else {
		close_connection(c)
	}

	if err != nil {
		virtual.arena_destroy(c.res_arena)
		free(c.res_arena, c.allocator)
		delete(c.parser.body)
	}

	cb, user_data := c.cb, c.user_data
	conn_free(c)
	cb(res, err, user_data)
}

close_connection :: proc(c: ^Conn) {
	if c.ssl != nil { openssl.SSL_free(c.ssl) }
	if c.socket != 0 { net.close(c.socket) }
	c.ssl, c.rbio, c.wbio, c.socket = nil, nil, nil, 0
}

/*
After a complete response, the connection can carry the next request unless: the server said
`Connection: close`, it's HTTP/1.0, the body ended with the connection, the request wasn't fully
sent, or anything (plaintext or TLS records) arrived beyond the response.
*/
reusable :: proc(c: ^Conn) -> bool {
	p := &c.parser
	if c.key == "" || c.send_failed || p.http10 || p.close_delimited || len(c.buf) > 0 { return false }
	if conn, has := http.headers_get_unsafe(p.headers, "connection"); has && http.header_list_has_token(conn, "close") { return false }
	if c.ssl != nil && (openssl.SSL_pending(c.ssl) > 0 || openssl.BIO_ctrl_pending(c.rbio) > 0) { return false }
	return true
}

/*
A connection from the pool that turns out to be closed (the server closed it between the
liveness check and our request) fails before any of the response arrives. Then the request is
sent again on a new connection, once, if repeating it is safe (an idempotent method, RFC 9110 9.2.2).
*/
should_retry :: proc(c: ^Conn, err: Error) -> bool {
	if !c.reused || c.got_bytes || expired(c) { return false }
	#partial switch err {
	case .Connection_Closed, .Network_Error, .TLS_Failed:
	case:
		return false
	}
	#partial switch c.method {
	case .Get, .Head, .Put, .Delete, .Options, .Trace:
		return true
	}
	return false
}

retry :: proc(c: ^Conn) {
	log.debug("client: reused connection was closed, retrying on a new one")
	close_connection(c)
	delete(c.cin, c.allocator)
	c.cin = nil
	clear(&c.out)
	clear(&c.buf)
	c.reused = false
	c.send_failed = false
	if err := connect(c); err != nil {
		finish(c, err)
	}
}
