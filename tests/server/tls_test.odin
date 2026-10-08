package tests_server

// The server with TLS (Server_Opts.tls), checked with our own clients (which verify certificates)
// and raw sockets. Certificates: testdata/tls (gen.sh).

import "core:bytes"
import "core:fmt"
import "core:mem"
import "core:nbio"
import "core:net"
import "core:os"
import "core:strings"
import "core:testing"
import "core:time"

import http "../.."
import "../../client"
import ws "../../websocket"

TLS_DIR :: #directory + "/testdata/tls/"

@(private="file")
tls_opts :: proc(cert := "server_a", hsts: time.Duration = 0) -> http.Server_Opts {
	opts := http.Default_Server_Opts
	opts.tls = http.TLS_Opts{
		cert_file    = strings.concatenate({TLS_DIR, cert, ".pem"}, context.temp_allocator),
		key_file     = strings.concatenate({TLS_DIR, cert, ".key"}, context.temp_allocator),
		hsts_max_age = hsts,
	}
	return opts
}

@(private="file")
CA_A :: TLS_DIR + "ca_a.pem"
@(private="file")
CA_B :: TLS_DIR + "ca_b.pem"

@(private="file")
tls_handler :: proc() -> http.Handler {
	return http.handler(proc(req: ^http.Request, res: ^http.Response) {
		switch req.url.path {
		case "/echo":
			http.body(req, -1, res, proc(res: rawptr, body: http.Body, err: http.Body_Error) {
				res := (^http.Response)(res)
				if err != nil {
					http.respond(res, http.body_error_status(err))
					return
				}
				http.respond_plain(res, body)
			})
		case "/ws":
			ws.upgrade(req, res, {compression = true, max_message_size = 4 * mem.Megabyte, send_queue_limit = 16 * mem.Megabyte}, {
				on_message = proc(c: ^ws.Conn, kind: ws.Message_Kind, data: []byte) { ws.send(c, kind, data) },
			})
		case:
			http.respond_plain(res, fmt.tprintf("tls=%v port=%v", req.tls, req.client.port))
		}
	})
}

@(test)
tls_requests :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	q: Quarantine
	context.allocator = quarantine_allocator(&q)
	ts := server_start(t, tls_handler(), tls_opts(hsts = 365 * 24 * time.Hour), threads = 2)
	defer server_stop(ts)
	base := fmt.tprintf("https://localhost:%i", ts.port)
	opts := client.Default_Opts
	opts.tls_ca_file = CA_A

	// Over TLS, the handler knows, and HSTS is sent.
	res, err := client.get(fmt.tprintf("%s/", base), opts)
	testing.expectf(t, err == nil && strings.has_prefix(res.body, "tls=true"), "%v %q", err, res.body)
	testing.expect_value(t, http.headers_get_unsafe(res.headers, "strict-transport-security"), "max-age=31536000")
	first_port := strings.clone(res.body, context.temp_allocator)
	client.response_destroy(&res)

	// Keep-alive: the next request comes on the same TLS connection.
	res, err = client.get(fmt.tprintf("%s/", base), opts)
	testing.expectf(t, err == nil && res.body == first_port, "%v %q, then %q", err, first_port, res.body)
	client.response_destroy(&res)

	// Large bodies both ways.
	{
		req: client.Request
		client.request_init(&req, .Post, context.temp_allocator)
		data := make([]byte, 3 * mem.Megabyte, context.temp_allocator)
		for &b, i in data { b = byte(i % 251) }
		bytes.buffer_write(&req.body, data)
		r, e := client.request(&req, fmt.tprintf("%s/echo", base), opts)
		testing.expectf(t, e == nil && bytes.equal(transmute([]byte)r.body, data), "echo: %v %i bytes", e, len(r.body))
		client.response_destroy(&r)
	}

	// Concurrent connections.
	{
		if !testing.expect_value(t, nbio.acquire_thread_event_loop(), nil) { return }
		defer nbio.release_thread_event_loop()
		State :: struct { done, ok: int }
		s: State
		N :: 30
		for _ in 0 ..< N {
			r: client.Request
			client.request_init(&r, .Get, context.temp_allocator)
			e := client.request_async(&r, fmt.tprintf("%s/", base), {tls_ca_file = CA_A, disable_keep_alive = true}, &s, proc(res: client.Response, err: client.Error, user_data: rawptr) {
				s := (^State)(user_data)
				s.done += 1
				if err == nil && strings.has_prefix(res.body, "tls=true") { s.ok += 1 }
				res := res
				client.response_destroy(&res)
			})
			if e != nil { s.done += 1 }
		}
		for start := time.tick_now(); s.done < N && time.tick_since(start) < 20 * time.Second; { nbio.tick(10 * time.Millisecond) }
		testing.expectf(t, s.ok == N, "%i/%i ok", s.ok, N)
	}

	// A client that doesn't trust the certificate refuses it.
	res, err = client.get(fmt.tprintf("%s/", base), {tls_ca_file = CA_B})
	testing.expect_value(t, err, client.Error.TLS_Verification_Failed)
	client.response_destroy(&res)
}

@(test)
tls_websocket :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	q: Quarantine
	context.allocator = quarantine_allocator(&q)
	ts := server_start(t, tls_handler(), tls_opts())
	defer server_stop(ts)

	if !testing.expect_value(t, nbio.acquire_thread_event_loop(), nil) { return }
	defer nbio.release_thread_event_loop()

	// The upgrade happens over TLS, then the WebSocket keeps using the same TLS session.
	r := Echo_Run{t = t}
	for size in ([]int{0, 10, 125, 70_000, 1_000_000}) {
		m := make([]byte, size, context.temp_allocator)
		for &b, i in m { b = 'a' + byte(i % 26) }
		append(&r.send, m)
	}
	_, err := ws.dial(fmt.tprintf("wss://localhost:%i/ws", ts.port), {opts = {compression = true, max_message_size = 4 * mem.Megabyte}, tls_ca_file = CA_A}, echo_callbacks(&r))
	testing.expect(t, err == nil)
	for start := time.tick_now(); !r.closed && time.tick_since(start) < 20 * time.Second; { nbio.tick(10 * time.Millisecond) }
	testing.expectf(t, r.opened && r.got == len(r.send) && r.code == 1000 && r.ok, "opened=%v %i/%i close %v ok=%v", r.opened, r.got, len(r.send), r.code, r.ok)
}

@(private="file")
Echo_Run :: struct {
	t:      ^testing.T,
	send:   [dynamic][]byte,
	got:    int,
	opened: bool,
	closed: bool,
	ok:     bool,
	code:   u16,
}

@(private="file")
echo_callbacks :: proc(r: ^Echo_Run) -> ws.Callbacks {
	r.ok = true
	r.send.allocator = context.temp_allocator
	return {
		user_data = r,
		on_open = proc(c: ^ws.Conn) {
			r := (^Echo_Run)(c.user_data)
			r.opened = true
			for m in r.send { ws.send(c, .Text, m) }
		},
		on_message = proc(c: ^ws.Conn, _: ws.Message_Kind, data: []byte) {
			r := (^Echo_Run)(c.user_data)
			if r.got >= len(r.send) || !bytes.equal(data, r.send[r.got]) { r.ok = false }
			r.got += 1
			if r.got == len(r.send) { ws.close(c) }
		},
		on_close = proc(c: ^ws.Conn, code: u16, _: string) {
			r := (^Echo_Run)(c.user_data)
			r.closed, r.code = true, code
		},
	}
}

// Plaintext, garbage and silence on the TLS port: the connection is closed (in time), the server
// carries on.
@(test)
tls_misbehaving_clients :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	q: Quarantine
	context.allocator = quarantine_allocator(&q)
	opts := tls_opts()
	opts.header_timeout = 300 * time.Millisecond
	ts := server_start(t, tls_handler(), opts)
	defer server_stop(ts)

	for input in ([]string{
		"GET / HTTP/1.1\r\nHost: x\r\n\r\n",
		"\x16\x03\x01\x00\x05garbage-after-a-record-header",
		"\x16\x03\x01\xff\xff",
		"\x00\x01\x02\x03\x04\x05\x06\x07",
	}) {
		c, ok := raw_dial(ts)
		if !testing.expect(t, ok) { continue }
		raw_send(c, input)
		resp, closed := raw_recv(c, 3 * time.Second)
		testing.expectf(t, closed, "%q: still open (got %q)", input, resp)
		raw_close(c)
	}

	// A client that connects and says nothing is closed after header_timeout.
	{
		c, _ := raw_dial(ts)
		start := time.tick_now()
		_, closed := raw_recv(c, 3 * time.Second)
		testing.expectf(t, closed && time.tick_since(start) < 2 * time.Second, "silent client: closed=%v after %v", closed, time.tick_since(start))
		raw_close(c)
	}

	res, err := client.get(fmt.tprintf("https://127.0.0.1:%i/", ts.port), {tls_ca_file = CA_A})
	testing.expectf(t, err == nil && strings.has_prefix(res.body, "tls=true"), "server after misbehaving clients: %v", err)
	client.response_destroy(&res)
}

// A renewed certificate is picked up without a restart.
@(test)
tls_certificate_reload :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	q: Quarantine
	context.allocator = quarantine_allocator(&q)

	dir, derr := os.make_directory_temp("", "odin-http-tls-*", context.temp_allocator)
	if !testing.expect(t, derr == nil) { return }
	defer os.remove_all(dir)
	cert := strings.concatenate({dir, "/cert.pem"}, context.temp_allocator)
	key := strings.concatenate({dir, "/key.pem"}, context.temp_allocator)
	install :: proc(name, cert, key: string) {
		// Written next to the target and renamed, the way certbot and lego replace files.
		for pair in ([][2]string{{".pem", cert}, {".key", key}}) {
			data, _ := os.read_entire_file(strings.concatenate({TLS_DIR, name, pair[0]}, context.temp_allocator), context.temp_allocator)
			tmp := strings.concatenate({pair[1], ".tmp"}, context.temp_allocator)
			_ = os.write_entire_file(tmp, data)
			os.rename(tmp, pair[1])
		}
	}
	install("server_a", cert, key)

	opts := http.Default_Server_Opts
	opts.tls = http.TLS_Opts{cert_file = cert, key_file = key, reload_interval = 100 * time.Millisecond}
	ts := server_start(t, tls_handler(), opts)
	defer server_stop(ts)
	url := fmt.tprintf("https://localhost:%i/", ts.port)

	trusts :: proc(url, ca: string) -> client.Error {
		res, err := client.get(url, {tls_ca_file = ca, disable_keep_alive = true})
		client.response_destroy(&res)
		return err
	}
	testing.expect_value(t, trusts(url, CA_A), client.Error.None)

	// Unreadable in between (a half-written file) keeps the current certificate.
	_ = os.write_entire_file(cert, transmute([]byte)string("not a certificate"))
	time.sleep(400 * time.Millisecond)
	testing.expect_value(t, trusts(url, CA_A), client.Error.None)

	install("server_b", cert, key)
	time.sleep(400 * time.Millisecond)
	testing.expect_value(t, trusts(url, CA_B), client.Error.None)
	testing.expect_value(t, trusts(url, CA_A), client.Error.TLS_Verification_Failed)
}

@(test)
tls_bad_certificate_files :: proc(t: ^testing.T) {
	// The reasons are logged as errors, which is right for a server but fails a test.
	context.logger = {}
	s: http.Server
	for files in ([][2]string{
		{"/does/not/exist.pem", TLS_DIR + "server_a.key"},
		{TLS_DIR + "server_a.pem", "/does/not/exist.key"},
		{TLS_DIR + "server_a.pem", TLS_DIR + "server_b.key"}, // Key of another certificate.
		{TLS_DIR + "ca_a.pem", TLS_DIR + "ca_a.pem"},
	}) {
		opts := http.Default_Server_Opts
		opts.tls = http.TLS_Opts{cert_file = files[0], key_file = files[1]}
		err := http.listen(&s, {address = net.IP4_Loopback, port = 0}, opts)
		testing.expectf(t, err == http.TLS_Error.Setup_Failed, "%v: %v", files, err)
		s = {}
	}
}

@(test)
tls_redirect_to_https :: proc(t: ^testing.T) {
	ts := server_start(t, http.redirect_to_https())
	defer server_stop(ts)
	Case :: struct { req: string, location: string }
	for c in ([]Case{
		{"GET /a/b?x=1 HTTP/1.1\r\nHost: example.com:8080\r\nConnection: close\r\n\r\n", "https://example.com/a/b?x=1"},
		{"POST / HTTP/1.1\r\nHost: [::1]:80\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", "https://[::1]/"},
	}) {
		resp := roundtrip(ts, c.req)
		testing.expectf(t, status_of(resp) == 308 && strings.contains(resp, fmt.tprintf("location: %s\r\n", c.location)), "%q", resp)
	}
	resp := roundtrip(ts, "GET / HTTP/1.1\r\nHost: bad/host\r\nConnection: close\r\n\r\n")
	testing.expectf(t, status_of(resp) == 400, "%q", resp)

	other := server_start(t, http.redirect_to_https(8443))
	defer server_stop(other)
	resp = roundtrip(other, "GET /x HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n")
	testing.expectf(t, strings.contains(resp, "location: https://example.com:8443/x\r\n"), "%q", resp)
}
