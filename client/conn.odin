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
One request in flight. Strictly sequential: connect, TLS handshake, write the request, read until
the response is complete. So at most one nbio operation is pending, and `finish` (which frees the
connection) is only ever called from a completion with nothing else in flight.
*/
Conn :: struct {
	opts:        Opts,
	deadline:    time.Time,
	request:     []byte,
	socket:      net.TCP_Socket,
	tls_host:    string,
	tls_is_ip:   bool,
	tls_ctx:     ^openssl.SSL_CTX,
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
}

acquire_loop :: proc() -> nbio.General_Error { return nbio.acquire_thread_event_loop() }
release_loop :: proc() { nbio.release_thread_event_loop() }
tick_loop    :: proc() -> nbio.General_Error { return nbio.tick() }

start :: proc(req: ^Request, url: string, opts: Opts, user_data: rawptr, cb: Callback, allocator: mem.Allocator) -> Error {
	t := parse_url(url, context.temp_allocator) or_return

	endpoint: net.Endpoint
	if t.is_ip {
		addr := net.parse_address(t.host)
		if addr == nil { return .Invalid_URL }
		endpoint = {addr, t.port}
	} else {
		ep4, ep6, err := net.resolve(t.host)
		if err != nil { return .Resolve_Failed }
		endpoint = ep4 if ep4 != {} else ep6
		if endpoint == {} { return .Resolve_Failed }
		endpoint.port = t.port
	}

	ctx: ^openssl.SSL_CTX
	if t.tls {
		ctx = openssl.client_ctx(opts.tls_ca_file)
		if ctx == nil {
			log.warnf("client: TLS setup failed: %s", openssl.error_string())
			return .TLS_Setup_Failed
		}
	}

	request, ferr := format_request(req, t, allocator)
	if ferr != nil {
		if ctx != nil { openssl.SSL_CTX_free(ctx) }
		return ferr
	}

	c := new(Conn, allocator)
	c.opts      = opts
	c.deadline  = time.time_add(nbio.now(), opts.timeout)
	c.request   = request
	c.tls_ctx   = ctx
	c.tls_is_ip = t.is_ip
	c.cb        = cb
	c.user_data = user_data
	c.allocator = allocator
	c.buf.allocator = allocator
	c.out.allocator = allocator

	c.res_arena = new(virtual.Arena, allocator)
	if virtual.arena_init_growing(c.res_arena) != nil {
		free(c.res_arena, allocator)
		delete(c.request, allocator)
		if ctx != nil { openssl.SSL_CTX_free(ctx) }
		free(c, allocator)
		return .Network_Error
	}
	arena := virtual.arena_allocator(c.res_arena)
	c.tls_host = clone_string(t.host, arena)
	parser_init(&c.parser, opts, req.method == .Head, arena, allocator)

	nbio.dial_poly(endpoint, c, on_dialed, timeout = min(opts.connect_timeout, time_left(c)))
	return .None
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

	if c.tls_ctx == nil {
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
	}, timeout = time_left(c))
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
		feed(c)
	}, timeout = time_left(c))
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

// Delivers the response or the error, and frees the connection.
finish :: proc(c: ^Conn, err: Error) {
	res: Response
	if err == nil {
		p := &c.parser
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
	} else {
		virtual.arena_destroy(c.res_arena)
		free(c.res_arena, c.allocator)
		delete(c.parser.body)
	}

	if c.ssl != nil { openssl.SSL_free(c.ssl) }
	if c.tls_ctx != nil { openssl.SSL_CTX_free(c.tls_ctx) }
	if c.socket != 0 { net.close(c.socket) }
	delete(c.cin, c.allocator)
	delete(c.out)
	delete(c.buf)
	delete(c.request, c.allocator)

	cb, user_data := c.cb, c.user_data
	free(c, c.allocator)
	cb(res, err, user_data)
}
