package tests_server

import "core:strings"
import "core:testing"
import "core:time"

import http "../.."

fast_opts :: proc() -> http.Server_Opts {
	opts := http.Default_Server_Opts
	opts.idle_timeout      = 300 * time.Millisecond
	opts.header_timeout    = 300 * time.Millisecond
	opts.body_read_timeout = 300 * time.Millisecond
	opts.write_timeout     = 300 * time.Millisecond
	return opts
}

@(test)
idle_timeout_closes_keepalive :: proc(t: ^testing.T) {
	ts := server_start(t, echo_handler(), fast_opts())
	defer server_stop(ts)

	c, ok := raw_dial(ts)
	testing.expect(t, ok)
	defer raw_close(c)

	raw_send(c, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	resp, closed := raw_recv(c, 100 * time.Millisecond)
	testing.expectf(t, status_of(resp) == 200 && !closed, "first response: %q closed=%v", resp, closed)

	_, closed = raw_recv(c, 1500 * time.Millisecond)
	testing.expect(t, closed, "idle keep-alive connection was not closed")
}

@(test)
silent_connection_closed_quietly :: proc(t: ^testing.T) {
	ts := server_start(t, echo_handler(), fast_opts())
	defer server_stop(ts)

	c, _ := raw_dial(ts)
	defer raw_close(c)
	resp, closed := raw_recv(c, 1500 * time.Millisecond)
	testing.expectf(t, closed && resp == "", "want quiet close, got %q closed=%v", resp, closed)
}

@(test)
partial_head_gets_408 :: proc(t: ^testing.T) {
	ts := server_start(t, echo_handler(), fast_opts())
	defer server_stop(ts)

	c, _ := raw_dial(ts)
	defer raw_close(c)
	raw_send(c, "GET / HTTP/1.1\r\nHost: x\r\n")
	resp, closed := raw_recv(c, 1500 * time.Millisecond)
	testing.expectf(t, status_of(resp) == 408 && closed, "got %q closed=%v", resp, closed)
}

@(test)
slowloris_dribble_gets_408 :: proc(t: ^testing.T) {
	ts := server_start(t, echo_handler(), fast_opts())
	defer server_stop(ts)

	c, _ := raw_dial(ts)
	defer raw_close(c)
	raw_send(c, "GET / HTTP/1.1\r\n")

	// One byte every 50ms keeps every individual read fast, but the head never completes in time.
	start := time.tick_now()
	resp: string
	closed: bool
	for time.tick_since(start) < 2 * time.Second {
		if !raw_send(c, "X") { break }
		resp, closed = raw_recv(c, 50 * time.Millisecond)
		if closed || len(resp) > 0 { break }
	}
	testing.expectf(t, status_of(resp) == 408, "got %q closed=%v", resp, closed)
	testing.expectf(t, time.tick_since(start) < time.Second, "took %v to time out", time.tick_since(start))
}

@(test)
body_read_timeout :: proc(t: ^testing.T) {
	ts := server_start(t, echo_handler(), fast_opts())
	defer server_stop(ts)

	c, _ := raw_dial(ts)
	defer raw_close(c)
	raw_send(c, "POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\n\r\nhello")
	resp, closed := raw_recv(c, 1500 * time.Millisecond)
	testing.expectf(t, status_of(resp) >= 400 && closed, "got %q closed=%v", resp, closed)
}

@(test)
slow_but_steady_body_is_fine :: proc(t: ^testing.T) {
	ts := server_start(t, echo_handler(), fast_opts())
	defer server_stop(ts)

	c, _ := raw_dial(ts)
	defer raw_close(c)
	raw_send(c, "POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 10\r\n\r\n")
	// 10 bytes over ~1s: longer than any timeout in total, but never 300ms without progress.
	for _ in 0 ..< 10 {
		time.sleep(100 * time.Millisecond)
		raw_send(c, "a")
	}
	resp, _ := raw_recv(c, 500 * time.Millisecond)
	testing.expectf(t, strings.contains(resp, "got 10 bytes"), "got %q", resp)
}

@(test)
write_timeout_when_client_stops_reading :: proc(t: ^testing.T) {
	big := http.handler(proc(_: ^http.Request, res: ^http.Response) {
		http.respond_plain(res, strings.repeat("x", 64 << 20, context.temp_allocator))
	})
	ts := server_start(t, big, fast_opts())
	defer server_stop(ts)

	c, _ := raw_dial(ts)
	defer raw_close(c)
	raw_send(c, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")

	// Don't read: the server's writes stall once the socket buffers are full.
	time.sleep(1500 * time.Millisecond)
	resp, closed := raw_recv(c, 2 * time.Second)
	testing.expectf(t, closed, "server kept the stalled connection open")
	testing.expectf(t, len(resp) < 64 << 20, "got the full body (%d bytes), the write never stalled?", len(resp))
}

@(test)
max_connections_pauses_accept :: proc(t: ^testing.T) {
	opts := http.Default_Server_Opts
	opts.max_connections = 2
	ts := server_start(t, echo_handler(), opts)
	defer server_stop(ts)

	c1, _ := raw_dial(ts)
	c2, _ := raw_dial(ts)
	defer raw_close(c2)
	time.sleep(100 * time.Millisecond)

	// The kernel completes the handshake (backlog), but the server doesn't pick it up.
	c3, _ := raw_dial(ts)
	defer raw_close(c3)
	raw_send(c3, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	resp, _ := raw_recv(c3, 300 * time.Millisecond)
	testing.expectf(t, resp == "", "third connection was served over the limit: %q", resp)

	raw_close(c1)
	resp, _ = raw_recv(c3, 2 * time.Second)
	testing.expectf(t, status_of(resp) == 200, "third connection not served after one closed: %q", resp)
}

@(test)
shutdown_with_active_connection :: proc(t: ^testing.T) {
	// A handler that never responds: shutdown must still finish, after shutdown_timeout.
	hang := http.handler(proc(_: ^http.Request, _: ^http.Response) {})
	opts := fast_opts()
	opts.shutdown_timeout = 300 * time.Millisecond
	ts := server_start(t, hang, opts)

	c, _ := raw_dial(ts)
	defer raw_close(c)
	raw_send(c, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	time.sleep(100 * time.Millisecond)

	start := time.tick_now()
	server_stop(ts)
	testing.expectf(t, time.tick_since(start) < 3 * time.Second, "shutdown took %v", time.tick_since(start))
}
