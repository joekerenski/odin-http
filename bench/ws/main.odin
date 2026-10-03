// WebSocket benchmark: a server and a load generator (using the websocket client).
//
//	bench/ws.sh                      runs every scenario (in the Linux test container)
//	ws server <port>                 echo endpoint /echo, compressed echo /echoz, broadcast /sub
//	ws load <port> <scenario> <secs> one scenario, prints a result line
//
// Scenarios: echo-32, echo-4k, echo-64k, echo-1m, echoz-4k (compressed text), bcast-1000
// (64 bytes to 1000 subscribers), bcast-4k (4KiB to 1000 subscribers).
package bench_ws

import "core:fmt"
import "core:log"
import "core:math/rand"
import "core:mem"
import "core:nbio"
import "core:net"
import "core:os"
import "core:slice"
import "core:strconv"
import "core:sync"
import "core:thread"
import "core:time"

import http "../.."
import ws "../../websocket"

main :: proc() {
	context.logger = log.create_console_logger(.Error)
	if len(os.args) < 3 {
		fmt.eprintln("usage: ws server <port> | ws load <port> <scenario> <secs>")
		os.exit(2)
	}
	port, _ := strconv.parse_int(os.args[2])
	switch os.args[1] {
	case "server":
		serve(port)
	case "load":
		secs := 5
		if len(os.args) > 4 { secs, _ = strconv.parse_int(os.args[4]) }
		load(port, os.args[3], secs)
	}
}

// Knobs (environment): WS_PING=1 keeps the default 30s keepalive pings (a timeout on every read),
// WS_LEVEL=n sets the zlib level.
bench_opts :: proc() -> ws.Opts {
	opts := ws.Opts{max_message_size = 4 * mem.Megabyte, send_queue_limit = 64 * mem.Megabyte, ping_interval = -1}
	if os.get_env("WS_PING", context.temp_allocator) == "1" { opts.ping_interval = 0 }
	if lvl, ok := strconv.parse_int(os.get_env("WS_LEVEL", context.temp_allocator)); ok { opts.compression_level = lvl }
	return opts
}

// --- Server ---

// Subscribers of /sub (64 byte broadcasts) and /sub4k (4KiB broadcasts).
Subs :: struct {
	mu:      sync.Mutex,
	handles: [dynamic]ws.Handle,
	size:    int,
}
subs_small := Subs{size = 64}
subs_big   := Subs{size = 4096}

serve :: proc(port: int) {
	s: http.Server
	handler := http.handler(proc(req: ^http.Request, res: ^http.Response) {
		opts := bench_opts()
		switch req.url.path {
		case "/echo", "/echoz":
			opts.compression = req.url.path == "/echoz"
			ws.upgrade(req, res, opts, {
				on_message = proc(c: ^ws.Conn, kind: ws.Message_Kind, data: []byte) { ws.send(c, kind, data) },
			})
		case "/sub", "/sub4k":
			ws.upgrade(req, res, opts, {
				user_data = &subs_small if req.url.path == "/sub" else &subs_big,
				on_open = proc(c: ^ws.Conn) {
					s := (^Subs)(c.user_data)
					sync.guard(&s.mu)
					append(&s.handles, ws.handle(c))
				},
				on_close = proc(c: ^ws.Conn, _: u16, _: string) {
					s := (^Subs)(c.user_data)
					h := ws.handle(c)
					sync.guard(&s.mu)
					for other, i in s.handles {
						if other.id == h.id { unordered_remove(&s.handles, i); break }
					}
				},
			})
		case:
			http.respond(res, http.Status.Not_Found)
		}
	})

	// Broadcasts timestamps to the subscribers, paced at one message per 100µs.
	for s in ([]^Subs{&subs_small, &subs_big}) {
		thread.create_and_start_with_poly_data(s, proc(s: ^Subs) {
			handles := make([dynamic]ws.Handle)
			msg := make([]byte, s.size)
			for {
				{
					sync.guard(&s.mu)
					clear(&handles)
					append(&handles, ..s.handles[:])
				}
				if len(handles) == 0 {
					time.sleep(10 * time.Millisecond)
					continue
				}
				stamp(msg)
				ws.broadcast(handles[:], .Binary, msg)
				time.sleep(100 * time.Microsecond)
			}
		})
	}

	opts := http.Default_Server_Opts
	opts.thread_count = 1
	http.server_shutdown_on_interrupt(&s)
	fmt.println(http.listen_and_serve(&s, handler, net.Endpoint{address = net.IP4_Loopback, port = port}, opts))
}

// The first 8 bytes of a payload: a monotonic timestamp, for latency.
stamp :: proc(buf: []byte) {
	(^i64)(raw_data(buf))^ = time.tick_now()._nsec
}

stamped_latency :: proc(buf: []byte) -> time.Duration {
	if len(buf) < 8 { return 0 }
	return time.tick_diff(time.Tick{(^i64)(raw_data(buf))^}, time.tick_now())
}

// --- Load generator ---

Scenario :: struct {
	path:       string,
	size:       int,
	conns:      int,
	// Messages each connection keeps in flight.
	window:     int,
	text:       bool,
	broadcast:  bool,
}

Load :: struct {
	sc:        Scenario,
	payload:   []byte,
	until:     time.Tick,
	open:      int,
	closed:    int,
	messages:  int,
	bytes:     int,
	latencies: [dynamic]time.Duration,
	stopping:  bool,
}

load :: proc(port: int, name: string, secs: int) {
	sc: Scenario
	switch name {
	case "echo-32":    sc = {path = "/echo",  size = 32,          conns = 64,   window = 16}
	case "echo-4k":    sc = {path = "/echo",  size = 4096,        conns = 64,   window = 8}
	case "echo-64k":   sc = {path = "/echo",  size = 65536,       conns = 64,   window = 2}
	case "echo-1m":    sc = {path = "/echo",  size = 1 << 20,     conns = 16,   window = 1}
	case "echoz-4k":   sc = {path = "/echoz", size = 4096,        conns = 64,   window = 8, text = true}
	case "bcast-1000": sc = {path = "/sub",   conns = 1000, broadcast = true}
	case "bcast-4k":   sc = {path = "/sub4k", conns = 1000, broadcast = true}
	case:
		fmt.eprintln("unknown scenario", name)
		os.exit(2)
	}

	if err := nbio.acquire_thread_event_loop(); err != nil {
		fmt.eprintln("event loop:", err)
		os.exit(1)
	}

	l := Load{sc = sc}
	l.payload = make([]byte, max(sc.size, 8))
	// Text: compressible, valid UTF-8 (the timestamp is hex-encoded for text, see `send_one`).
	for &b, i in l.payload { b = 'a' + byte((i * 7 + i / 13) % 26) if sc.text else byte(rand.int_max(256)) }

	opts := ws.Dial_Opts{opts = bench_opts()}
	opts.compression = sc.text
	url := fmt.aprintf("ws://127.0.0.1:%i%s", port, sc.path)
	for _ in 0 ..< sc.conns {
		if _, err := ws.dial(url, opts, {
			user_data = &l,
			on_open = proc(c: ^ws.Conn) {
				l := (^Load)(c.user_data)
				l.open += 1
				if l.sc.broadcast { return }
				for n := 0; n < l.sc.window; n += 1 { send_one(c, l) }
			},
			on_message = proc(c: ^ws.Conn, kind: ws.Message_Kind, data: []byte) {
				l := (^Load)(c.user_data)
				if l.stopping { return }
				l.messages += 1
				l.bytes += len(data)
				if l.messages % 16 == 0 { append(&l.latencies, latency_of(l, data)) }
				if !l.sc.broadcast { send_one(c, l) }
			},
			on_close = proc(c: ^ws.Conn, code: u16, reason: string) {
				l := (^Load)(c.user_data)
				l.closed += 1
				if !l.stopping { fmt.eprintfln("connection closed early: %v %s", code, reason) }
			},
		}); err != nil {
			fmt.eprintln("dial:", err)
			os.exit(1)
		}
	}

	// Wait for every connection, then measure.
	deadline := time.tick_now()
	for l.open + l.closed < sc.conns && time.tick_since(deadline) < 10 * time.Second { nbio.tick(10 * time.Millisecond) }
	if l.open < sc.conns { fmt.eprintfln("only %i/%i connections opened", l.open, sc.conns) }

	// Warm up for half a second, then count.
	warm := time.tick_now()
	for time.tick_since(warm) < 500 * time.Millisecond { nbio.tick(10 * time.Millisecond) }
	l.messages, l.bytes = 0, 0
	clear(&l.latencies)

	start := time.tick_now()
	for time.tick_since(start) < time.Duration(secs) * time.Second { nbio.tick(10 * time.Millisecond) }
	elapsed := time.duration_seconds(time.tick_since(start))
	l.stopping = true

	slice.sort(l.latencies[:])
	pct :: proc(l: []time.Duration, p: f64) -> f64 {
		if len(l) == 0 { return 0 }
		return time.duration_milliseconds(l[min(int(f64(len(l)) * p), len(l) - 1)])
	}
	fmt.printfln("%-12s %9d msg/s %7d MiB/s   p50 %7.3fms  p99 %7.3fms",
		name, int(f64(l.messages) / elapsed), int(f64(l.bytes) / elapsed / (1 << 20)), pct(l.latencies[:], 0.5), pct(l.latencies[:], 0.99))
	os.exit(0)
}

send_one :: proc(c: ^ws.Conn, l: ^Load) {
	if l.sc.text {
		// Hex timestamp in the first 16 bytes keeps the text valid UTF-8.
		HEX := "0123456789abcdef"
		buf: [16]byte
		v := u64(time.tick_now()._nsec)
		for i in 0 ..< 16 { buf[15 - i] = HEX[v & 0xF]; v >>= 4 }
		copy(l.payload, buf[:])
		ws.send(c, .Text, l.payload)
		return
	}
	stamp(l.payload)
	ws.send(c, .Binary, l.payload)
}

latency_of :: proc(l: ^Load, data: []byte) -> time.Duration {
	if !l.sc.text { return stamped_latency(data) }
	if len(data) < 16 { return 0 }
	v, ok := strconv.parse_u64(string(data[:16]), 16)
	if !ok { return 0 }
	return time.tick_diff(time.Tick{i64(v)}, time.tick_now())
}

