// Black-box regression tests: run a real server on an ephemeral port and talk raw bytes to it.
package tests_server

import "core:bytes"
import "core:io"
import "core:net"
import "core:strings"
import "core:sync"
import "core:testing"
import "core:thread"
import "core:time"

import http "../.."

Test_Server :: struct {
	server:  http.Server,
	handler: http.Handler,
	opts:    http.Server_Opts,
	port:    int,
	ready:   sync.Sema,
	thread:  ^thread.Thread,
}

// Starts a single-threaded server on 127.0.0.1 with an OS-assigned port.
server_start :: proc(t: ^testing.T, handler: http.Handler, opts := http.Default_Server_Opts) -> ^Test_Server {
	ts := new(Test_Server)
	ts.handler = handler
	ts.opts = opts
	ts.opts.thread_count = 1

	ts.thread = thread.create_and_start_with_poly_data(ts, proc(ts: ^Test_Server) {
		err := http.listen(&ts.server, {address = net.IP4_Loopback, port = 0}, ts.opts)
		if err != nil {
			sync.sema_post(&ts.ready)
			return
		}
		ep, _ := net.bound_endpoint(ts.server.tcp_sock)
		ts.port = ep.port
		sync.sema_post(&ts.ready)
		http.serve(&ts.server, ts.handler)
	}, context)

	sync.sema_wait(&ts.ready)
	testing.expect(t, ts.port != 0, "test server failed to listen")
	return ts
}

server_stop :: proc(ts: ^Test_Server) {
	http.server_shutdown(&ts.server)
	thread.join(ts.thread)
	thread.destroy(ts.thread)
	free(ts)
}

// Sends `req` on a fresh connection and reads until the server closes or `wait` elapses
// without new data. Returns everything the server sent.
roundtrip :: proc(ts: ^Test_Server, req: string, wait := 500 * time.Millisecond, allocator := context.temp_allocator) -> string {
	sock, err := net.dial_tcp(net.Endpoint{address = net.IP4_Loopback, port = ts.port})
	if err != nil { return "<dial failed>" }
	defer net.close(sock)
	net.set_option(sock, .Receive_Timeout, wait)

	sent := 0
	for sent < len(req) {
		n, serr := net.send_tcp(sock, transmute([]byte)req[sent:])
		if serr != nil { break }
		sent += n
	}

	out: bytes.Buffer
	bytes.buffer_init_allocator(&out, 0, 512, allocator)
	buf: [4096]byte
	for {
		n, rerr := net.recv_tcp(sock, buf[:])
		if rerr != nil || n == 0 { break }
		bytes.buffer_write(&out, buf[:n])
	}
	return bytes.buffer_to_string(&out)
}

// Status code of the first response in `resp`, or 0 if there is none.
status_of :: proc(resp: string) -> int {
	if len(resp) < 12 || resp[:9] != "HTTP/1.1 " { return 0 }
	return int(resp[9] - '0') * 100 + int(resp[10] - '0') * 10 + int(resp[11] - '0')
}

count_responses :: proc(resp: string) -> (n: int) {
	s := resp
	for {
		i := index(s, "HTTP/1.1 ")
		if i < 0 { return }
		n += 1
		s = s[i + 1:]
	}
}

@(private)
index :: proc(s, sub: string) -> int {
	for i := 0; i + len(sub) <= len(s); i += 1 {
		if s[i:i + len(sub)] == sub { return i }
	}
	return -1
}

// Handler used by most tests:
//   /echo  reads the body (1 MiB limit) and responds "got N bytes".
//   other  responds "hello" without touching the body.
echo_handler :: proc() -> http.Handler {
	return http.handler(proc(req: ^http.Request, res: ^http.Response) {
		if len(req.url.path) >= 5 && req.url.path[:5] == "/echo" {
			http.body(req, 1 << 20, res, proc(res: rawptr, body: http.Body, err: http.Body_Error) {
				res := (^http.Response)(res)
				if err != nil {
					http.respond(res, http.body_error_status(err))
					return
				}
				buf: [32]byte
				http.respond_plain(res, fmt_bytes(buf[:], len(body)))
			})
			return
		}
		if req.url.path == "/trailer" {
			Pair :: struct { req: ^http.Request, res: ^http.Response }
			pair := new(Pair, context.temp_allocator)
			pair^ = {req, res}
			http.body(req, -1, pair, proc(pair: rawptr, body: http.Body, err: http.Body_Error) {
				pair := (^Pair)(pair)
				req, res := pair.req, pair.res
				if err != nil {
					http.respond(res, http.body_error_status(err))
					return
				}
				t, has_t := http.headers_get(req.trailers, "x-t")
				_, has_h := http.headers_get(req.headers, "x-t")
				_, has_host_trailer := http.headers_get(req.trailers, "host")
				http.respond_plain(res, strings.concatenate({
					"trailer=", t if has_t else "<none>",
					" header=", "yes" if has_h else "no",
					" host-trailer=", "yes" if has_host_trailer else "no",
					" body=", body,
				}, context.temp_allocator))
			})
			return
		}
		if req.url.path == "/stream" {
			res.status = .OK
			rw: http.Response_Writer
			w := http.response_writer_init(&rw, res, nil)
			io.write_string(w, "streamed body")
			io.close(w)
			return
		}
		http.respond_plain(res, "hello")
	})
}

@(private)
fmt_bytes :: proc(buf: []byte, n: int) -> string {
	b := bytes.Buffer{}
	bytes.buffer_init_allocator(&b, 0, 32, context.temp_allocator)
	bytes.buffer_write_string(&b, "got ")
	digits: [20]byte
	i := len(digits)
	v := n
	for {
		i -= 1
		digits[i] = byte('0' + v % 10)
		v /= 10
		if v == 0 { break }
	}
	bytes.buffer_write(&b, digits[i:])
	bytes.buffer_write_string(&b, " bytes")
	return bytes.buffer_to_string(&b)
}

// A raw client connection for tests that need control over timing.
Raw :: struct {
	sock: net.TCP_Socket,
}

raw_dial :: proc(ts: ^Test_Server) -> (r: Raw, ok: bool) {
	sock, err := net.dial_tcp(net.Endpoint{address = net.IP4_Loopback, port = ts.port})
	if err != nil { return }
	return {sock}, true
}

raw_send :: proc(r: Raw, data: string) -> bool {
	sent := 0
	for sent < len(data) {
		n, err := net.send_tcp(r.sock, transmute([]byte)data[sent:])
		if err != nil { return false }
		sent += n
	}
	return true
}

// Reads whatever arrives within `wait`. `closed` reports whether the server closed the connection.
raw_recv :: proc(r: Raw, wait: time.Duration, allocator := context.temp_allocator) -> (data: string, closed: bool) {
	net.set_option(r.sock, .Receive_Timeout, wait)
	out: bytes.Buffer
	bytes.buffer_init_allocator(&out, 0, 512, allocator)
	buf: [16384]byte
	for {
		n, err := net.recv_tcp(r.sock, buf[:])
		if err != nil {
			// Timeout: still open. A reset counts as closed.
			closed = err != .Timeout && err != .Would_Block
			break
		}
		if n == 0 { closed = true; break }
		bytes.buffer_write(&out, buf[:n])
	}
	return bytes.buffer_to_string(&out), closed
}

raw_close :: proc(r: Raw) {
	net.close(r.sock)
}
