package http

import "core:log"
import "core:nbio"
import "core:net"
import "core:os"
import "core:strconv"
import "core:strings"
import "core:sync"
import "core:time"

import "openssl"

/*
TLS for the server (HTTPS), through the system's OpenSSL over memory BIOs: nbio moves the
ciphertext, everything above `connection_recv`/`connection_send` is the same as for plain HTTP.

The certificate comes from files (e.g. what certbot or lego write); they are checked for changes
every `reload_interval`, so a renewed certificate is used for new connections without a restart.
*/
TLS_Opts :: struct {
	// PEM files: the certificate followed by its chain (e.g. fullchain.pem), and its private key.
	cert_file:       string,
	key_file:        string,
	// How often the files are checked for changes, defaults to a minute. Negative disables it.
	reload_interval: time.Duration,
	// Sends `Strict-Transport-Security: max-age=...` on every response when > 0 (browsers then
	// only use HTTPS for the site for that long). Off by default.
	hsts_max_age:    time.Duration,
}

TLS_Error :: enum u8 {
	None,
	// The certificate or key couldn't be loaded or don't match (the reason is logged).
	Setup_Failed,
}

// What `listen` and `listen_and_serve` can fail with.
Listen_Error :: union #shared_nil {
	net.Network_Error,
	TLS_Error,
}

@(private)
Server_TLS :: struct {
	enabled:    bool,
	mu:         sync.Mutex,
	// New connections are created from this; existing ones keep a reference to the context they
	// started with, so a reload doesn't affect them.
	ctx:        ^openssl.SSL_CTX,
	cert_mtime: time.Time,
	key_mtime:  time.Time,
	// The Strict-Transport-Security value, "" for none.
	hsts:       string,
}

// Ciphertext read at once.
@(private)
TLS_READ_SIZE :: 32 * 1024

@(private)
TLS_Conn :: struct {
	ssl:            ^openssl.SSL,
	rbio, wbio:     ^openssl.BIO,
	cin:            []byte,
	// Ciphertext waiting to be written, and the part being written.
	out:            [dynamic]byte,
	sending:        [dynamic]byte,
	// An nbio operation is in flight: the connection can't be freed until it completes.
	reading:        bool,
	writing:        bool,
	failed:         bool,
	// Shut the socket's write side down once everything (the close_notify) is written.
	shutdown_after: bool,

	// The connection's pending read.
	recv_buf:       []byte,
	recv_done:      Recv_Done,
	// The connection's pending write: done once the ciphertext up to `send_mark` is written.
	send_done:      proc(c: ^Connection, ok: bool),
	send_mark:      int,
	queued:         int,
	written:        int,
}

@(private)
Recv_Status :: enum u8 {
	Ok,
	// The peer closed the connection (or sent a TLS close_notify).
	Closed,
	Failed,
}

@(private)
Recv_Done :: #type proc(c: ^Connection, received: int, status: Recv_Status)

// --- Setup ---

@(private)
server_tls_init :: proc(s: ^Server, opts: TLS_Opts) -> TLS_Error {
	ctx, why := openssl.server_ctx(opts.cert_file, opts.key_file)
	if ctx == nil {
		log.errorf("TLS: %s", why)
		return .Setup_Failed
	}
	s.tls.enabled = true
	s.tls.ctx = ctx
	s.tls.cert_mtime = file_mtime(opts.cert_file)
	s.tls.key_mtime = file_mtime(opts.key_file)
	if opts.hsts_max_age > 0 {
		buf: [32]byte
		secs := strconv.write_int(buf[:], i64(opts.hsts_max_age / time.Second), 10)
		s.tls.hsts = strings.concatenate({"max-age=", secs}, s.conn_allocator)
	}
	return .None
}

@(private)
server_tls_destroy :: proc(s: ^Server) {
	if !s.tls.enabled { return }
	openssl.SSL_CTX_free(s.tls.ctx)
	delete(s.tls.hsts, s.conn_allocator)
	s.tls = {}
}

@(private)
file_mtime :: proc(path: string) -> time.Time {
	fi, err := os.stat(path, context.temp_allocator)
	if err != nil { return {} }
	return fi.modification_time
}

// Checks the certificate files and loads them again when they changed. Runs on the first server
// thread every `reload_interval`.
@(private)
server_tls_reload :: proc(s: ^Server) {
	opts := s.opts.tls.(TLS_Opts)
	cert, key := file_mtime(opts.cert_file), file_mtime(opts.key_file)
	if cert == s.tls.cert_mtime && key == s.tls.key_mtime { return }
	// Changed (or a file is missing, mid-rename): keep the old certificate until a load works.
	ctx, why := openssl.server_ctx(opts.cert_file, opts.key_file)
	if ctx == nil {
		log.warnf("TLS: the certificate files changed but can't be loaded, keeping the current certificate: %s", why)
		return
	}
	old: ^openssl.SSL_CTX
	{
		sync.guard(&s.tls.mu)
		old, s.tls.ctx = s.tls.ctx, ctx
		s.tls.cert_mtime, s.tls.key_mtime = cert, key
	}
	// Connections still using the old context hold their own reference.
	openssl.SSL_CTX_free(old)
	log.info("TLS: certificate reloaded")
}

@(private)
server_tls_reload_start :: proc(td: ^Server_Thread) {
	interval := td.server.opts.tls.(TLS_Opts).reload_interval
	if interval < 0 { return }
	if interval == 0 { interval = time.Minute }
	td.tls_timer = nbio.timeout_poly(interval, td, proc(_: ^nbio.Operation, td: ^Server_Thread) {
		td.tls_timer = nil
		if td.state != .Serving { return }
		server_tls_reload(td.server)
		server_tls_reload_start(td)
	})
}

// TLS state for a new connection, nil when it couldn't be set up.
@(private)
tls_conn_new :: proc(c: ^Connection) -> ^TLS_Conn {
	s := c.server
	ssl: ^openssl.SSL
	rbio, wbio: ^openssl.BIO
	ok: bool
	{
		sync.guard(&s.tls.mu)
		ssl, rbio, wbio, ok = openssl.server_ssl(s.tls.ctx)
	}
	if !ok { return nil }
	t := new(TLS_Conn, s.conn_allocator)
	t^ = {ssl = ssl, rbio = rbio, wbio = wbio}
	t.cin = make([]byte, TLS_READ_SIZE, s.conn_allocator)
	t.out.allocator = s.conn_allocator
	t.sending.allocator = s.conn_allocator
	return t
}

// Frees the connection's TLS state. Nothing may be in flight.
@(private)
tls_conn_destroy :: proc(c: ^Connection) {
	t := c.tls
	if t == nil { return }
	assert(!t.reading && !t.writing)
	if t.ssl != nil { openssl.SSL_free(t.ssl) }
	delete(t.cin, c.server.conn_allocator)
	delete(t.out)
	delete(t.sending)
	free(t, c.server.conn_allocator)
	c.tls = nil
}

// Operations of the TLS layer still in flight.
@(private)
tls_busy :: proc(c: ^Connection) -> bool {
	return c.tls != nil && (c.tls.reading || c.tls.writing)
}

// --- Reading ---

/*
Reads into `buf`. With TLS this decrypts what's already there first (OpenSSL may hold plaintext
from an earlier read), so `done` can be called before this returns.
*/
@(private)
connection_recv :: proc(c: ^Connection, buf: []byte, done: Recv_Done) {
	if c.tls != nil {
		c.tls.recv_buf, c.tls.recv_done = buf, done
		tls_pump_recv(c)
		return
	}
	c.recv_done = done
	nbio.recv_poly(c.socket, {buf}, c, proc(op: ^nbio.Operation, c: ^Connection) {
		status := Recv_Status.Ok
		if op.recv.err != nil {
			#partial switch op.recv.err.(net.TCP_Recv_Error) {
			// EBADF (bad file descriptor) happens when the OS closed the socket.
			case .Connection_Closed, .Invalid_Argument: status = .Closed
			case:                                       status = .Failed
			}
		} else if op.recv.received == 0 {
			status = .Closed
		}
		done := c.recv_done
		c.recv_done = nil
		done(c, op.recv.received, status)
	})
}

@(private)
tls_pump_recv :: proc(c: ^Connection) {
	t := c.tls
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
	// The handshake, session tickets and key updates make OpenSSL write while reading.
	tls_flush(c)

	if n > 0 {
		tls_deliver(c, n, .Ok)
		return
	}
	switch ssl_err {
	case openssl.SSL_ERROR_WANT_READ:
		if t.failed {
			tls_deliver(c, 0, .Failed)
			return
		}
		if t.reading { return }
		t.reading = true
		// No timeout: the connection's read deadline is enforced by the sweeper (`server_sweep_conns`).
		nbio.recv_poly(c.socket, {t.cin}, c, tls_on_cipher_recv)
	case openssl.SSL_ERROR_ZERO_RETURN:
		tls_deliver(c, 0, .Closed)
	case:
		// Usually a client that isn't speaking TLS (plain HTTP on the HTTPS port) or doesn't trust us.
		log.debugf("TLS: connection %i failed: %s", c.socket, openssl.error_string())
		t.failed = true
		tls_deliver(c, 0, .Failed)
	}
}

@(private)
tls_deliver :: proc(c: ^Connection, n: int, status: Recv_Status) {
	t := c.tls
	done := t.recv_done
	t.recv_done, t.recv_buf = nil, nil
	done(c, n, status)
}

@(private)
tls_on_cipher_recv :: proc(op: ^nbio.Operation, c: ^Connection) {
	t := c.tls
	t.reading = false
	if op.recv.err != nil || op.recv.received == 0 {
		status := Recv_Status.Closed
		if op.recv.err != nil {
			#partial switch op.recv.err.(net.TCP_Recv_Error) {
			case .Connection_Closed, .Invalid_Argument:
			case: status = .Failed
			}
		}
		t.failed = true
		if t.recv_done != nil { tls_deliver(c, 0, status) }
		return
	}
	openssl.BIO_write(t.rbio, raw_data(t.cin), i32(op.recv.received))
	tls_pump_recv(c)
}

// --- Writing ---

@(private)
tls_send :: proc(c: ^Connection, buf: []byte, done: proc(c: ^Connection, ok: bool)) {
	t := c.tls
	assert(t.send_done == nil, "a write is already in flight on this connection")
	if t.failed {
		done(c, false)
		return
	}
	openssl.ERR_clear_error()
	// Memory BIOs grow as needed, so the whole buffer is taken at once.
	for rest := buf; len(rest) > 0; {
		r := openssl.SSL_write(t.ssl, raw_data(rest), i32(min(len(rest), int(max(i32)))))
		if r <= 0 {
			log.debugf("TLS: write on connection %i failed: %s", c.socket, openssl.error_string())
			t.failed = true
			done(c, false)
			return
		}
		rest = rest[r:]
	}
	t.queued += openssl.drain_bio(t.wbio, &t.out)
	t.send_done, t.send_mark = done, t.queued
	tls_flush(c)
}

// Writes the queued ciphertext, one send at a time, in order.
@(private)
tls_flush :: proc(c: ^Connection) {
	t := c.tls
	t.queued += openssl.drain_bio(t.wbio, &t.out)
	if t.writing || t.failed { return }
	if len(t.out) == 0 {
		if t.shutdown_after {
			t.shutdown_after = false
			net.shutdown(c.socket, .Send)
		}
		return
	}

	t.sending, t.out = t.out, t.sending
	t.writing = true
	wt := c.server.opts.write_timeout
	c.write_deadline = time.time_add(nbio.now(), wt) if wt > 0 else {}
	nbio.send_poly(c.socket, {t.sending[:]}, c, tls_on_cipher_sent, all = true)
}

@(private)
tls_on_cipher_sent :: proc(op: ^nbio.Operation, c: ^Connection) {
	t := c.tls
	t.writing = false
	c.write_deadline = {}

	if op.send.err != nil || c.write_expired {
		if c.write_expired {
			log.infof("write timed out on connection %i", c.socket)
		} else {
			log.debugf("could not send on connection %i: %v", c.socket, op.send.err)
		}
		t.failed = true
		clear(&t.sending)
		if done := t.send_done; done != nil {
			t.send_done = nil
			done(c, false)
		}
		return
	}

	t.written += len(t.sending)
	clear(&t.sending)
	if done := t.send_done; done != nil && t.written >= t.send_mark {
		t.send_done = nil
		done(c, true)
		// The callback may have handed the connection over (hijack) or closed it.
		if c.tls != t { return }
	}
	tls_flush(c)
}

/*
Starts closing a TLS connection: the close_notify alert goes out after anything still queued, then
the write side is shut down (like `net.shutdown(.Send)` for a plain connection).
*/
@(private)
tls_close :: proc(c: ^Connection) {
	t := c.tls
	if t.failed {
		net.shutdown(c.socket, .Send)
		return
	}
	openssl.SSL_shutdown(t.ssl)
	t.shutdown_after = true
	tls_flush(c)
}

// --- Helpers ---

/*
A handler for the plain HTTP port that sends every request to the same URL over HTTPS, with a 308
(the method and body are kept). `https_port` is the port the HTTPS server listens on as seen by
clients (left out of the URL when it's 443).
*/
redirect_to_https :: proc(https_port := 443) -> Handler {
	return Handler{
		user_data = rawptr(uintptr(https_port)),
		handle = proc(h: ^Handler, req: ^Request, res: ^Response) {
			port := int(uintptr(h.user_data))
			host, has := headers_get_unsafe(req.headers, "host")
			// The host without its port, an IPv6 literal with its brackets.
			if has && len(host) > 0 && host[0] == '[' {
				if end := strings.index_byte(host, ']'); end > 0 { host = host[:end + 1] } else { has = false }
			} else if colon := strings.last_index_byte(host, ':'); colon >= 0 {
				host = host[:colon]
			}
			if !has || !is_host_name(host) {
				respond(res, Status.Bad_Request)
				return
			}

			b := strings.builder_make(context.temp_allocator)
			strings.write_string(&b, "https://")
			strings.write_string(&b, host)
			if port != 443 {
				strings.write_byte(&b, ':')
				strings.write_int(&b, port)
			}
			target := req.url.path
			if target == "" || target[0] != '/' { target = "/" }
			strings.write_string(&b, target)
			if req.url.query != "" {
				strings.write_byte(&b, '?')
				strings.write_string(&b, req.url.query)
			}
			headers_set_unsafe(&res.headers, "location", strings.to_string(b))
			respond(res, Status.Permanent_Redirect)
		},
	}
}

// Letters, digits, '-', '.', and an IPv6 literal in brackets.
@(private)
is_host_name :: proc(s: string) -> bool {
	if len(s) == 0 { return false }
	for i in 0 ..< len(s) {
		switch s[i] {
		case 'a' ..= 'z', 'A' ..= 'Z', '0' ..= '9', '-', '.', '[', ']', ':':
		case:
			return false
		}
	}
	return true
}
