// The connection's transport: plain TCP, or TLS (wss://, client side) through OpenSSL over memory
// BIOs, with nbio moving the ciphertext.
package websocket

import "core:log"
import "core:nbio"
import "core:net"
import "core:strings"
import "core:sync"
import "core:time"

import "../openssl"

@(private)
IO_Error :: enum u8 {
	None,
	// The peer closed the connection (or sent a TLS close_notify).
	Closed,
	Timeout,
	Failed,
}

@(private)
Recv_Done :: #type proc(c: ^Conn, received: int, err: IO_Error)
@(private)
Send_Done :: #type proc(c: ^Conn, sent: int, err: IO_Error)

// Ciphertext read at once.
@(private)
TLS_READ_SIZE :: 32 * 1024

@(private)
Tls :: struct {
	ssl:      ^openssl.SSL,
	// Owned by `ssl`. Ciphertext from the peer goes into `rbio`, ciphertext for the peer comes out of `wbio`.
	rbio:     ^openssl.BIO,
	wbio:     ^openssl.BIO,
	cin:      []byte,
	// Ciphertext waiting to be written, and the part being written.
	out:      [dynamic]byte,
	sending:  [dynamic]byte,
	// An nbio operation is in flight; the connection can't be freed until it completes.
	reading:  bool,
	writing:  bool,
	// Sticky: once the transport failed, everything fails.
	failed:   IO_Error,

	// The pending receive of the connection.
	recv_buf:     []byte,
	recv_done:    Recv_Done,
	recv_timeout: time.Duration,

	// The pending send of the connection: done once the ciphertext up to `send_mark` is written.
	send_done:    Send_Done,
	send_plain:   int,
	send_mark:    int,
	queued_total: int,
	written_total: int,
}

// --- Transport, used by the connection ---

// Reads into `buf`; `done` gets the byte count, 0 with `.Closed` at the end of the stream.
// With TLS, `done` may be called before this returns (data that was already decrypted).
@(private)
transport_recv :: proc(c: ^Conn, buf: []byte, timeout: time.Duration, done: Recv_Done) {
	if c._tls != nil {
		t := c._tls
		t.recv_buf, t.recv_done, t.recv_timeout = buf, done, timeout
		tls_pump_recv(c)
		return
	}
	c._plain_recv_done = done
	nbio.recv_poly(c._socket, {buf}, c, proc(op: ^nbio.Operation, c: ^Conn) {
		err := io_error(op.recv.err)
		if err == .None && op.recv.received == 0 { err = .Closed }
		c._plain_recv_done(c, op.recv.received, err)
	}, timeout = timeout)
}

// Writes `bufs` (in order); `done` gets how much was written, which is everything unless it failed.
// With TLS, `done` may be called before this returns (when encrypting fails).
@(private)
transport_send :: proc(c: ^Conn, bufs: [][]byte, timeout: time.Duration, done: Send_Done, all := false) {
	if c._tls != nil {
		tls_send(c, bufs, timeout, done)
		return
	}
	c._plain_send_done = done
	nbio.send_poly(c._socket, bufs, c, proc(op: ^nbio.Operation, c: ^Conn) {
		c._plain_send_done(c, op.send.sent, io_error(op.send.err))
	}, all = all, timeout = timeout)
}

// Operations of the transport that are still in flight (besides the connection's own recv/send).
@(private)
transport_busy :: proc(c: ^Conn) -> bool {
	return c._tls != nil && (c._tls.reading || c._tls.writing)
}

@(private)
io_error :: proc {
	io_error_recv,
	io_error_send,
}

@(private)
io_error_recv :: proc(err: net.Recv_Error) -> IO_Error {
	if err == nil { return .None }
	#partial switch err.(net.TCP_Recv_Error) {
	case .Timeout:           return .Timeout
	case .Connection_Closed: return .Closed
	}
	return .Failed
}

@(private)
io_error_send :: proc(err: net.Send_Error) -> IO_Error {
	if err == nil { return .None }
	#partial switch err.(net.TCP_Send_Error) {
	case .Timeout:           return .Timeout
	case .Connection_Closed: return .Closed
	}
	return .Failed
}

// --- TLS ---

@(private)
default_ctx: ^openssl.SSL_CTX
@(private)
default_ctx_once: sync.Once

/*
A client context that verifies the server: its certificate chain against the system's trust store,
or the CAs in `ca_file` (PEM) when given, and TLS 1.2 at least. The host name is checked per
connection (`tls_init`).
*/
@(private)
tls_client_ctx :: proc(ca_file: string) -> ^openssl.SSL_CTX {
	make_ctx :: proc(ca_file: string) -> ^openssl.SSL_CTX {
		ctx := openssl.SSL_CTX_new(openssl.TLS_client_method())
		if ctx == nil { return nil }
		ok: i32
		if ca_file == "" {
			ok = openssl.SSL_CTX_set_default_verify_paths(ctx)
		} else {
			ok = openssl.SSL_CTX_load_verify_locations(ctx, strings.clone_to_cstring(ca_file, context.temp_allocator), nil)
		}
		if ok != 1 || openssl.SSL_CTX_set_min_proto_version(ctx, openssl.TLS1_2_VERSION) != 1 {
			log.warnf("websocket: TLS setup failed: %s", tls_error_string())
			openssl.SSL_CTX_free(ctx)
			return nil
		}
		openssl.SSL_CTX_set_verify(ctx, openssl.SSL_VERIFY_PEER, nil)
		return ctx
	}

	if ca_file != "" { return make_ctx(ca_file) }
	sync.once_do(&default_ctx_once, proc() { default_ctx = make_ctx("") })
	return default_ctx
}

// Sets up TLS for a client connection to `host` (a name or an IP address, without brackets).
@(private)
tls_init :: proc(c: ^Conn, ctx: ^openssl.SSL_CTX, host: string, is_ip: bool) -> bool {
	ssl := openssl.SSL_new(ctx)
	if ssl == nil { return false }
	rbio := openssl.BIO_new(openssl.BIO_s_mem())
	wbio := openssl.BIO_new(openssl.BIO_s_mem())
	if rbio == nil || wbio == nil {
		if rbio != nil { openssl.BIO_free(rbio) }
		if wbio != nil { openssl.BIO_free(wbio) }
		openssl.SSL_free(ssl)
		return false
	}
	openssl.SSL_set_bio(ssl, rbio, wbio)
	openssl.SSL_set_connect_state(ssl)

	chost := strings.clone_to_cstring(host, context.temp_allocator)
	ok: bool
	if is_ip {
		// No SNI for addresses (RFC 6066 3), and the certificate must name the address.
		ok = openssl.X509_VERIFY_PARAM_set1_ip_asc(openssl.SSL_get0_param(ssl), chost) == 1
	} else {
		ok = openssl.SSL_set_tlsext_host_name(ssl, chost) == 1 && openssl.SSL_set1_host(ssl, chost) == 1
	}
	if !ok {
		openssl.SSL_free(ssl)
		return false
	}

	t := new(Tls, c._allocator)
	t.ssl, t.rbio, t.wbio = ssl, rbio, wbio
	t.cin = make([]byte, TLS_READ_SIZE, c._allocator)
	t.out.allocator = c._allocator
	t.sending.allocator = c._allocator
	c._tls = t
	return true
}

@(private)
tls_destroy :: proc(c: ^Conn) {
	t := c._tls
	if t == nil { return }
	assert(!t.reading && !t.writing)
	openssl.SSL_free(t.ssl)
	delete(t.cin, c._allocator)
	delete(t.out)
	delete(t.sending)
	free(t, c._allocator)
	c._tls = nil
}

/*
The TLS handshake, then `done(c, "")`, or `done(c, why)` when it failed. Runs strictly one
operation at a time (write what OpenSSL produced, then read), so nothing is in flight when `done`
is called.
*/
@(private)
tls_handshake :: proc(c: ^Conn, done: proc(c: ^Conn, why: string)) {
	c._tls_handshake_done = done
	tls_handshake_step(c)
}

@(private)
tls_handshake_step :: proc(c: ^Conn) {
	t := c._tls
	openssl.ERR_clear_error()
	r := openssl.SSL_do_handshake(t.ssl)
	tls_drain(t)

	// First write whatever the handshake produced.
	if len(t.out) > 0 {
		t.sending, t.out = t.out, t.sending
		t.writing = true
		nbio.send_poly(c._socket, {t.sending[:]}, c, proc(op: ^nbio.Operation, c: ^Conn) {
			t := c._tls
			t.writing = false
			t.written_total += len(t.sending)
			clear(&t.sending)
			if op.send.err != nil {
				c._tls_handshake_done(c, "TLS handshake: sending failed")
				return
			}
			tls_handshake_step(c)
		}, all = true, timeout = handshake_time_left(c))
		return
	}

	if r == 1 {
		c._tls_handshake_done(c, "")
		return
	}

	switch openssl.SSL_get_error(t.ssl, r) {
	case openssl.SSL_ERROR_WANT_READ:
		t.reading = true
		nbio.recv_poly(c._socket, {t.cin}, c, proc(op: ^nbio.Operation, c: ^Conn) {
			t := c._tls
			t.reading = false
			switch {
			case op.recv.err == net.TCP_Recv_Error.Timeout:
				c._tls_handshake_done(c, "TLS handshake timed out")
			case op.recv.err != nil, op.recv.received == 0:
				c._tls_handshake_done(c, "TLS handshake: the server closed the connection")
			case:
				openssl.BIO_write(t.rbio, raw_data(t.cin), i32(op.recv.received))
				tls_handshake_step(c)
			}
		}, timeout = handshake_time_left(c))
	case:
		if v := openssl.SSL_get_verify_result(t.ssl); v != openssl.X509_V_OK {
			c._tls_handshake_done(c, strings.concatenate({"TLS: certificate verification failed: ", string(openssl.X509_verify_cert_error_string(v))}, context.temp_allocator))
		} else {
			c._tls_handshake_done(c, strings.concatenate({"TLS handshake failed: ", tls_error_string()}, context.temp_allocator))
		}
	}
}

// Moves the ciphertext OpenSSL produced to `out`.
@(private)
tls_drain :: proc(t: ^Tls) {
	for {
		pending := int(openssl.BIO_ctrl_pending(t.wbio))
		if pending <= 0 { return }
		at := len(t.out)
		non_zero_resize(&t.out, at + pending)
		n := openssl.BIO_read(t.wbio, raw_data(t.out[at:]), i32(pending))
		non_zero_resize(&t.out, at + max(int(n), 0))
		t.queued_total += max(int(n), 0)
		if n <= 0 { return }
	}
}

// Decrypts what's available into the pending receive, reading more ciphertext when needed.
@(private)
tls_pump_recv :: proc(c: ^Conn) {
	t := c._tls
	for {
		if t.recv_done == nil { return }

		n := 0
		ssl_err: i32 = openssl.SSL_ERROR_NONE
		openssl.ERR_clear_error()
		for n < len(t.recv_buf) {
			r := openssl.SSL_read(t.ssl, raw_data(t.recv_buf[n:]), i32(min(len(t.recv_buf) - n, int(max(i32)))))
			if r <= 0 {
				ssl_err = openssl.SSL_get_error(t.ssl, r)
				break
			}
			n += int(r)
		}
		// Reading can make OpenSSL answer (e.g. a key update).
		tls_flush(c)

		done := t.recv_done
		if n > 0 {
			t.recv_done, t.recv_buf = nil, nil
			done(c, n, .None)
			return
		}

		switch ssl_err {
		case openssl.SSL_ERROR_WANT_READ:
			if t.failed != .None {
				t.recv_done, t.recv_buf = nil, nil
				done(c, 0, t.failed)
				return
			}
			if t.reading { return }
			t.reading = true
			nbio.recv_poly(c._socket, {t.cin}, c, tls_on_cipher_recv, timeout = t.recv_timeout)
			return
		case openssl.SSL_ERROR_ZERO_RETURN:
			t.recv_done, t.recv_buf = nil, nil
			done(c, 0, .Closed)
			return
		case:
			log.debugf("websocket: TLS read failed: %s", tls_error_string())
			t.failed = .Failed
			t.recv_done, t.recv_buf = nil, nil
			done(c, 0, .Failed)
			return
		}
	}
}

/*
While the connection is still `.Connecting` (the HTTP handshake), the callbacks are the client's
handshake steps, which free the connection when it fails (`handshake_failed`): the completions
must not touch it after calling them. Afterwards the connection's `enter`/`leave` protect it.
*/
@(private)
tls_on_cipher_recv :: proc(op: ^nbio.Operation, c: ^Conn) {
	t := c._tls
	t.reading = false
	connecting := c.state == .Connecting
	if connecting {
		if c._client.failing != "" {
			if !transport_busy(c) { handshake_failed(c, c._client.failing) }
			return
		}
	} else {
		enter(c)
	}
	defer if !connecting { leave(c) }

	err := io_error(op.recv.err)
	if err == .None && op.recv.received == 0 { err = .Closed }
	if err != .None {
		if t.failed == .None { t.failed = err }
		if done := t.recv_done; done != nil {
			t.recv_done, t.recv_buf = nil, nil
			done(c, 0, err)
		}
		return
	}

	openssl.BIO_write(t.rbio, raw_data(t.cin), i32(op.recv.received))
	tls_pump_recv(c)
}

@(private)
tls_send :: proc(c: ^Conn, bufs: [][]byte, timeout: time.Duration, done: Send_Done) {
	t := c._tls
	assert(t.send_done == nil)
	if t.failed != .None {
		done(c, 0, t.failed)
		return
	}

	total := 0
	openssl.ERR_clear_error()
	for b in bufs {
		if len(b) == 0 { continue }
		// Memory BIOs grow as needed, so the whole buffer is taken.
		if r := openssl.SSL_write(t.ssl, raw_data(b), i32(len(b))); int(r) != len(b) {
			log.debugf("websocket: TLS write failed: %s", tls_error_string())
			t.failed = .Failed
			done(c, 0, .Failed)
			return
		}
		total += len(b)
	}

	tls_drain(t)
	t.send_done, t.send_plain, t.send_mark = done, total, t.queued_total
	c._tls_write_timeout = timeout
	tls_flush(c)
}

// Writes the queued ciphertext, one send at a time, in order.
@(private)
tls_flush :: proc(c: ^Conn) {
	t := c._tls
	tls_drain(t)
	if t.writing || len(t.out) == 0 || t.failed != .None || c._aborting { return }

	t.sending, t.out = t.out, t.sending
	t.writing = true
	nbio.send_poly(c._socket, {t.sending[:]}, c, tls_on_cipher_sent, all = true, timeout = c._tls_write_timeout)
}

@(private)
tls_on_cipher_sent :: proc(op: ^nbio.Operation, c: ^Conn) {
	t := c._tls
	t.writing = false
	connecting := c.state == .Connecting
	if connecting {
		if c._client.failing != "" {
			if !transport_busy(c) { handshake_failed(c, c._client.failing) }
			return
		}
	} else {
		enter(c)
	}
	defer if !connecting { leave(c) }

	if err := io_error(op.send.err); err != .None {
		if t.failed == .None { t.failed = err }
		clear(&t.sending)
		if done := t.send_done; done != nil {
			t.send_done = nil
			done(c, 0, err)
		}
		return
	}

	t.written_total += len(t.sending)
	clear(&t.sending)
	if done := t.send_done; done != nil && t.written_total >= t.send_mark {
		t.send_done = nil
		done(c, t.send_plain, .None)
		if connecting { return } // See above.
	}
	tls_flush(c)
}

// OpenSSL's queued errors, as text (temp allocated).
@(private)
tls_error_string :: proc() -> string {
	sb := strings.builder_make(context.temp_allocator)
	for {
		e := openssl.ERR_get_error()
		if e == 0 { break }
		buf: [256]byte
		openssl.ERR_error_string_n(e, raw_data(buf[:]), len(buf))
		if strings.builder_len(sb) > 0 { strings.write_string(&sb, "; ") }
		strings.write_string(&sb, string(cstring(raw_data(buf[:]))))
	}
	if strings.builder_len(sb) == 0 { return "unknown error" }
	return strings.to_string(sb)
}
