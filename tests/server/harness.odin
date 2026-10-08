// Black-box regression tests: run a real server on an ephemeral port and talk raw bytes to it.
package tests_server

import "base:runtime"

import "core:bytes"
import "core:debug/trace"
import "core:io"
import "core:log"
import "core:mem"
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

// Print a back trace when an assertion fails on a server thread (and abort), for debugging crashes:
// -define:TRACE_ASSERTIONS=true -debug
TRACE_ASSERTIONS :: #config(TRACE_ASSERTIONS, false)
trace_assertion_proc :: trace.assertion_failure_proc

// Blocking socket calls that retry when interrupted. On Linux a test thread that ran an nbio event
// loop (io_uring) can still get task work from the kernel after releasing it, and a socket call with a
// timeout set returns EINTR for that instead of restarting. The test runner reuses threads, so this
// lands in whatever test runs next.
tcp_recv :: proc(sock: net.TCP_Socket, buf: []byte) -> (n: int, err: net.TCP_Recv_Error) {
	for {
		n, err = net.recv_tcp(sock, buf)
		if err != .Interrupted { return }
	}
}

tcp_send :: proc(sock: net.TCP_Socket, buf: []byte) -> (n: int, err: net.TCP_Send_Error) {
	for {
		n, err = net.send_tcp(sock, buf)
		if err != .Interrupted { return }
	}
}

tcp_accept :: proc(sock: net.TCP_Socket) -> (conn: net.TCP_Socket, source: net.Endpoint, err: net.Accept_Error) {
	for {
		conn, source, err = net.accept_tcp(sock)
		if err != .Interrupted { return }
	}
}

// Starts a server (single-threaded by default) on 127.0.0.1 with an OS-assigned port.
server_start :: proc(t: ^testing.T, handler: http.Handler, opts := http.Default_Server_Opts, threads := 1) -> ^Test_Server {
	ts := new(Test_Server)
	ts.handler = handler
	ts.opts = opts
	ts.opts.thread_count = threads

	ts.thread = thread.create_and_start_with_poly_data(ts, proc(ts: ^Test_Server) {
		when TRACE_ASSERTIONS {
			// Inherited by the server threads: a failed assertion prints a back trace and aborts.
			context.assertion_failure_proc = trace_assertion_proc
		}
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
	// A server that failed to listen never ran, there is nothing to shut down.
	if ts.port != 0 {
		http.server_shutdown(&ts.server)
	}
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
		n, serr := tcp_send(sock, transmute([]byte)req[sent:])
		if serr != nil { break }
		sent += n
	}

	out: bytes.Buffer
	bytes.buffer_init_allocator(&out, 0, 512, allocator)
	buf: [4096]byte
	for {
		n, rerr := tcp_recv(sock, buf[:])
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
		n, err := tcp_send(r.sock, transmute([]byte)data[sent:])
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
		n, err := tcp_recv(r.sock, buf[:])
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

// Stops the server from another thread (for tests that need to interact while it shuts down).
thread_start_stop :: proc(ts: ^Test_Server) -> ^thread.Thread {
	return thread.create_and_start_with_poly_data(ts, proc(ts: ^Test_Server) { server_stop(ts) }, context)
}

thread_join_stop :: proc(th: ^thread.Thread) {
	thread.join(th)
	thread.destroy(th)
}

/*
An allocator for catching use-after-free: freed memory is zeroed and never reused, so a stale
pointer reads zeros (which trips an assertion or a nil dereference right away) instead of someone
else's data. Freeing memory it doesn't know (double free, wrong allocator) is logged as an error.
It never gives memory back, only use it for short tests:

	q: Quarantine
	context.allocator = quarantine_allocator(&q)
	ts := server_start(t, ...)
*/
Quarantine :: struct {
	mu:    sync.Mutex,
	sizes: map[rawptr]int,
}

quarantine_allocator :: proc(q: ^Quarantine) -> mem.Allocator {
	q.sizes = make(map[rawptr]int, 256, runtime.heap_allocator())
	return {procedure = quarantine_proc, data = q}
}

@(private)
quarantine_proc :: proc(data: rawptr, mode: mem.Allocator_Mode, size, alignment: int, old_memory: rawptr, old_size: int, loc := #caller_location) -> ([]byte, mem.Allocator_Error) {
	q := (^Quarantine)(data)
	heap := runtime.heap_allocator()
	sync.guard(&q.mu)

	retire :: proc(q: ^Quarantine, ptr: rawptr, loc: runtime.Source_Code_Location) -> (n: int) {
		ok: bool
		if n, ok = q.sizes[ptr]; !ok {
			log.errorf("quarantine: freeing unknown memory %p (double free or wrong allocator)", ptr, location = loc)
			return 0
		}
		mem.zero(ptr, n)
		delete_key(&q.sizes, ptr)
		return
	}

	switch mode {
	case .Alloc, .Alloc_Non_Zeroed:
		b, err := mem.alloc_bytes(size, alignment, heap)
		if err == nil && size > 0 { q.sizes[raw_data(b)] = size }
		return b, err
	case .Free:
		if old_memory != nil { retire(q, old_memory, loc) }
		return nil, nil
	case .Resize, .Resize_Non_Zeroed:
		b, err := mem.alloc_bytes(size, alignment, heap)
		if err != nil { return nil, err }
		if old_memory != nil {
			n := q.sizes[old_memory]
			copy(b, ([^]byte)(old_memory)[:min(n, size)])
			retire(q, old_memory, loc)
		}
		if size > 0 { q.sizes[raw_data(b)] = size }
		return b, nil
	case .Query_Features:
		if set := (^mem.Allocator_Mode_Set)(old_memory); set != nil {
			set^ = {.Alloc, .Alloc_Non_Zeroed, .Free, .Resize, .Resize_Non_Zeroed, .Query_Features}
		}
		return nil, nil
	case .Free_All, .Query_Info:
		return nil, .Mode_Not_Implemented
	}
	return nil, nil
}
