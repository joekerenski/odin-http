package tests_server

import "core:bytes"
import "core:math/rand"
import "core:net"
import "core:strings"
import "core:sync"
import "core:testing"
import "core:thread"
import "core:time"

SERVER_FUZZ_ITERATIONS :: #config(SERVER_FUZZ_ITERATIONS, 4000)

@(private="file")
CORPUS := []string{
	"GET / HTTP/1.1\r\nHost: x\r\n\r\n",
	"POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello",
	"POST /echo HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n",
	"POST /trailer HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhi\r\n0\r\nX-T: 1\r\n\r\n",
	"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\nExpect: 100-continue\r\n\r\nabc",
	"HEAD /stream HTTP/1.1\r\nHost: x\r\n\r\n",
	"GET /stream HTTP/1.0\r\n\r\n",
	"OPTIONS * HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
	"GET / HTTP/1.1\r\nHost: x\r\n\r\nGET / HTTP/1.1\r\nHost: x\r\n\r\n",
}

@(private="file")
NASTY := []string{"\r\n", "\n", "\r", "\x00", " ", "\t", ":", ";", ",", "-1", "+", "0x", "chunked", "Content-Length: 4\r\n", "Transfer-Encoding: chunked\r\n", "0\r\n\r\n", "ffffffffffffffff", "Expect: 100-continue\r\n", "\xff"}

@(private="file")
mutate_request :: proc(r: ^rand.Generator, allocator := context.temp_allocator) -> string {
	context.random_generator = r^
	buf := make([dynamic]byte, allocator)
	append(&buf, ..transmute([]byte)rand.choice(CORPUS))
	for _ in 0 ..< 1 + rand.int_max(4) {
		pos := rand.int_max(len(buf) + 1)
		switch rand.int_max(4) {
		case 0: inject_at(&buf, pos, ..transmute([]byte)rand.choice(NASTY))
		case 1: if pos < len(buf) { ordered_remove(&buf, pos) }
		case 2: if pos < len(buf) { buf[pos] = byte(rand.int_max(256)) }
		case 3: resize(&buf, pos)
		}
	}
	return string(buf[:])
}

// Sends `req`, half-closes, and reads until the server closes.
@(private="file")
exchange :: proc(port: int, req: string) -> (resp: string, ok: bool) {
	sock, err := net.dial_tcp(net.Endpoint{address = net.IP4_Loopback, port = port})
	if err != nil { return }
	defer net.close(sock)
	net.set_option(sock, .Receive_Timeout, 3 * time.Second)
	tcp_send(sock, transmute([]byte)req)
	net.shutdown(sock, .Send)

	out: bytes.Buffer
	bytes.buffer_init_allocator(&out, 0, 256, context.temp_allocator)
	buf: [4096]byte
	for {
		n, rerr := tcp_recv(sock, buf[:])
		if rerr == .Timeout { return bytes.buffer_to_string(&out), false }
		if rerr != nil || n == 0 { break }
		bytes.buffer_write(&out, buf[:n])
	}
	return bytes.buffer_to_string(&out), true
}

// Throws mutated requests at a live server from several threads. Every exchange must end with the
// server closing the connection (no hangs), everything it sends must be framed as HTTP/1.1
// responses, and the server must still serve a normal request afterwards.
@(test)
fuzz_live_server :: proc(t: ^testing.T) {
	opts := fast_opts()
	ts := server_start(t, echo_handler(), opts)
	defer server_stop(ts)

	Worker :: struct {
		t:        ^testing.T,
		port:     int,
		seed:     u64,
		failures: int,
		mu:       ^sync.Mutex,
	}

	WORKERS :: 8
	mu: sync.Mutex
	workers: [WORKERS]Worker
	threads: [WORKERS]^thread.Thread
	base := rand.uint64()
	for &w, i in workers {
		w = {t = t, port = ts.port, seed = base + u64(i), mu = &mu}
		threads[i] = thread.create_and_start_with_poly_data(&w, proc(w: ^Worker) {
			state := rand.create(w.seed)
			r := rand.default_random_generator(&state)
			for _ in 0 ..< SERVER_FUZZ_ITERATIONS / WORKERS {
				req := mutate_request(&r)
				resp, ok := exchange(w.port, req)
				bad := !ok
				if ok && len(resp) > 0 {
					// Every response (interim ones included) starts with a status line.
					bad = !strings.has_prefix(resp, "HTTP/1.1 ") || status_of(resp) < 100 || status_of(resp) > 599
				}
				if bad {
					sync.guard(w.mu)
					w.failures += 1
					if w.failures <= 3 {
						testing.expectf(w.t, false, "request %q -> response %q (closed=%v)", req, resp, ok)
					}
				}
				free_all(context.temp_allocator)
			}
		}, context)
	}
	for th in threads {
		thread.join(th)
		thread.destroy(th)
	}

	resp := roundtrip(ts, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	testing.expectf(t, status_of(resp) == 200, "server unhealthy after fuzzing: %q", resp)
}
