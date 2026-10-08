package tests_server

// Streamed responses (client.request_stream) against a server that sends its response in timed
// pieces: the body must arrive as it is sent, the total timeout must not cut a long stream short,
// a stall must, and a callback must be able to stop it.

import "core:fmt"
import "core:net"
import "core:strings"
import "core:sync"
import "core:testing"
import "core:thread"
import "core:time"

import http "../.."
import "../../client"

@(private="file")
Piece :: struct {
	wait: time.Duration, // before sending `data`
	data: string,
}

// Accepts one connection, reads the request head, sends the pieces, then closes.
@(private="file")
Drip :: struct {
	sock:   net.TCP_Socket,
	port:   int,
	pieces: []Piece,
	thread: ^thread.Thread,
}

@(private="file")
drip_start :: proc(pieces: []Piece) -> ^Drip {
	d := new(Drip)
	d.pieces = pieces
	err: net.Network_Error
	d.sock, err = net.listen_tcp({net.IP4_Loopback, 0})
	assert(err == nil)
	ep, _ := net.bound_endpoint(d.sock)
	d.port = ep.port
	net.set_option(d.sock, .Receive_Timeout, 5 * time.Second)
	d.thread = thread.create_and_start_with_poly_data(d, proc(d: ^Drip) {
		conn, _, err := tcp_accept(d.sock)
		if err != nil { return }
		defer net.close(conn)
		net.set_option(conn, .Receive_Timeout, 2 * time.Second)
		head: [dynamic]byte
		defer delete(head)
		buf: [4096]byte
		for !strings.contains(string(head[:]), "\r\n\r\n") {
			n, rerr := tcp_recv(conn, buf[:])
			if rerr != nil || n == 0 { return }
			append(&head, ..buf[:n])
		}
		for p in d.pieces {
			if p.wait > 0 { time.sleep(p.wait) }
			if _, serr := tcp_send(conn, transmute([]byte)p.data); serr != nil { return }
		}
	}, context)
	return d
}

@(private="file")
drip_stop :: proc(d: ^Drip) {
	net.close(d.sock)
	thread.join(d.thread)
	thread.destroy(d.thread)
	free(d)
}

@(private="file")
chunk :: proc(s: string) -> string {
	return fmt.tprintf("%x\r\n%s\r\n", len(s), s)
}

// What the callbacks saw.
@(private="file")
Seen :: struct {
	start:    time.Tick,
	head:     http.Status,
	heads:    int,
	body:     strings.Builder,
	arrivals: [dynamic]time.Duration, // since start, per on_body call
	stop_at:  int, // on_body returns false on this call (1-based), 0 never
	mutex:    sync.Mutex,
}

@(private="file")
seen_stream :: proc() -> client.Stream {
	return {
		on_head = proc(status: http.Status, headers: http.Headers, user_data: rawptr) -> bool {
			s := (^Seen)(user_data)
			s.head = status
			s.heads += 1
			return true
		},
		on_body = proc(data: []byte, user_data: rawptr) -> bool {
			s := (^Seen)(user_data)
			sync.guard(&s.mutex)
			strings.write_bytes(&s.body, data)
			append(&s.arrivals, time.tick_since(s.start))
			return s.stop_at == 0 || len(s.arrivals) < s.stop_at
		},
	}
}

@(private="file")
seen_init :: proc(s: ^Seen) {
	s.start = time.tick_now()
	strings.builder_init(&s.body, context.temp_allocator)
	s.arrivals.allocator = context.temp_allocator
}

@(test)
stream_arrives_as_sent :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 30 * time.Second)
	q: Quarantine
	context.allocator = quarantine_allocator(&q)

	// Five pieces 150ms apart: 750ms in all, against a 300ms total timeout, which only covers
	// the head when streaming.
	pieces := []Piece{
		{0, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nX-Kind: drip\r\n\r\n"},
		{150 * time.Millisecond, chunk("one ")},
		{150 * time.Millisecond, chunk("two ")},
		{150 * time.Millisecond, chunk("three ")},
		{150 * time.Millisecond, chunk("four ")},
		{150 * time.Millisecond, strings.concatenate({chunk("five"), "0\r\n\r\n"}, context.temp_allocator)},
	}
	d := drip_start(pieces)
	defer drip_stop(d)

	s: Seen
	seen_init(&s)
	r: client.Request
	client.request_init(&r, .Get, context.temp_allocator)
	res, err := client.request_stream(&r, fmt.tprintf("http://127.0.0.1:%i/", d.port), seen_stream(), &s, {timeout = 300 * time.Millisecond})
	defer client.response_destroy(&res)

	testing.expectf(t, err == nil, "err %v", err)
	testing.expect(t, res.status == .OK && s.head == .OK && s.heads == 1)
	testing.expect_value(t, res.body, "")
	testing.expect_value(t, http.headers_get_unsafe(res.headers, "x-kind"), "drip")
	testing.expect_value(t, strings.to_string(s.body), "one two three four five")
	// Incremental: the pieces arrived over the whole stream, not all at the end.
	if len(s.arrivals) >= 2 {
		spread := s.arrivals[len(s.arrivals) - 1] - s.arrivals[0]
		testing.expectf(t, len(s.arrivals) >= 4 && spread >= 450 * time.Millisecond, "%v calls over %v", len(s.arrivals), spread)
	} else {
		testing.expectf(t, false, "only %v body calls", len(s.arrivals))
	}
}

@(test)
stream_stall_times_out :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 30 * time.Second)
	q: Quarantine
	context.allocator = quarantine_allocator(&q)

	pieces := []Piece{
		{0, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"},
		{0, chunk("first")},
		{1500 * time.Millisecond, chunk("too late")},
	}
	d := drip_start(pieces)
	defer drip_stop(d)

	s: Seen
	seen_init(&s)
	r: client.Request
	client.request_init(&r, .Get, context.temp_allocator)
	start := time.tick_now()
	res, err := client.request_stream(&r, fmt.tprintf("http://127.0.0.1:%i/", d.port), seen_stream(), &s, {stall_timeout = 200 * time.Millisecond})
	elapsed := time.tick_since(start)
	client.response_destroy(&res)
	testing.expectf(t, err == .Timeout && elapsed < time.Second, "%v after %v", err, elapsed)
	testing.expect_value(t, strings.to_string(s.body), "first")
}

@(test)
stream_cancel_stops_promptly :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 30 * time.Second)
	q: Quarantine
	context.allocator = quarantine_allocator(&q)

	pieces := make([dynamic]Piece, context.temp_allocator)
	append(&pieces, Piece{0, "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"})
	for _ in 0 ..< 20 { append(&pieces, Piece{100 * time.Millisecond, chunk("tick ")}) }
	d := drip_start(pieces[:])
	defer drip_stop(d)

	s := Seen{stop_at = 2}
	seen_init(&s)
	r: client.Request
	client.request_init(&r, .Get, context.temp_allocator)
	start := time.tick_now()
	res, err := client.request_stream(&r, fmt.tprintf("http://127.0.0.1:%i/", d.port), seen_stream(), &s)
	elapsed := time.tick_since(start)
	client.response_destroy(&res)
	testing.expectf(t, err == .Cancelled && elapsed < time.Second && len(s.arrivals) == 2, "%v after %v, %v calls", err, elapsed, len(s.arrivals))
}

@(test)
stream_server_sent_events :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 30 * time.Second)
	q: Quarantine
	context.allocator = quarantine_allocator(&q)

	// Events split across chunks and pieces, mid-line, the way a network delivers them.
	events := ": open\n\nevent: delta\ndata: {\"text\":\"Hel\"}\n\nevent: delta\ndata: {\"text\":\"lo\"}\n\ndata: [DONE]\n\n"
	pieces := make([dynamic]Piece, context.temp_allocator)
	append(&pieces, Piece{0, "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n"})
	for i := 0; i < len(events); i += 7 {
		append(&pieces, Piece{20 * time.Millisecond, chunk(events[i:min(i + 7, len(events))])})
	}
	append(&pieces, Piece{0, "0\r\n\r\n"})
	d := drip_start(pieces[:])
	defer drip_stop(d)

	Got :: struct { list: [dynamic]string }
	got: Got
	got.list.allocator = context.temp_allocator
	sse: client.SSE
	client.sse_init(&sse, proc(ev: client.SSE_Event, user_data: rawptr) -> bool {
		g := (^Got)(user_data)
		append(&g.list, fmt.aprintf("%s %s", ev.type, ev.data, allocator = context.temp_allocator))
		return ev.data != "[DONE]"
	}, &got)
	defer client.sse_destroy(&sse)

	r: client.Request
	client.request_init(&r, .Get, context.temp_allocator)
	stream := client.Stream{on_body = proc(data: []byte, user_data: rawptr) -> bool {
		return client.sse_feed((^client.SSE)(user_data), data)
	}}
	res, err := client.request_stream(&r, fmt.tprintf("http://127.0.0.1:%i/", d.port), stream, &sse)
	client.response_destroy(&res)
	// [DONE] stops the stream from the event callback.
	testing.expectf(t, err == .Cancelled, "err %v", err)
	want := []string{"delta {\"text\":\"Hel\"}", "delta {\"text\":\"lo\"}", "message [DONE]"}
	testing.expectf(t, fmt.tprint(got.list[:]) == fmt.tprint(want), "got %v", got.list[:])
}
