package tests_server

import "core:strings"
import "core:testing"

import http "../.."

// Many requests on one connection: every response must be framed exactly, in order.
@(test)
pipelined_mixed_bodies :: proc(t: ^testing.T) {
	ts := server_start(t, echo_handler())
	defer server_stop(ts)

	req := strings.concatenate({
		"GET / HTTP/1.1\r\nHost: x\r\n\r\n",
		"POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello",
		"POST /echo HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n4;ext=1\r\ndefg\r\n0\r\n\r\n",
		"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\n\r\nxyz",
		"POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nzz\r\n0\r\n\r\n",
		"HEAD / HTTP/1.1\r\nHost: x\r\n\r\n",
		"GET /stream HTTP/1.1\r\nHost: x\r\n\r\n",
		"HEAD /stream HTTP/1.1\r\nHost: x\r\n\r\n",
		"GET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n",
		"GET /never HTTP/1.1\r\nHost: x\r\n\r\n",
	}, context.temp_allocator)
	resp := roundtrip(ts, req)

	testing.expectf(t, count_responses(resp) == 9, "want 9 responses, got %d: %q", count_responses(resp), resp)
	testing.expect(t, strings.contains(resp, "got 5 bytes"))
	testing.expect(t, strings.contains(resp, "got 7 bytes"))
	testing.expect(t, strings.count(resp, "streamed body") == 1)
	testing.expect(t, !strings.contains(resp, "/never"))
	testing.expect(t, strings.has_suffix(resp, "hello"))
}

@(test)
trailers_are_separate :: proc(t: ^testing.T) {
	resp := expect_status(t, "POST /trailer HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nhi\r\n0\r\nX-T: 1\r\nHost: evil\r\n\r\n", 200)
	testing.expectf(t, strings.has_suffix(resp, "trailer=1 header=no host-trailer=no body=hi"), "got %q", resp)
}

@(test)
trailer_limits :: proc(t: ^testing.T) {
	b := strings.builder_make(context.temp_allocator)
	strings.write_string(&b, "POST /trailer HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n")
	for _ in 0 ..< 150 { strings.write_string(&b, "X-A: 1\r\n") }
	strings.write_string(&b, "\r\n")
	expect_status(t, strings.to_string(b), 413)

	expect_status(t, "POST /trailer HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nBad Trailer: 1\r\n\r\n", 400)
}

@(test)
chunked_errors :: proc(t: ^testing.T) {
	expect_status(t, "POST /echo HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n-1\r\nx\r\n0\r\n\r\n", 400)
	expect_status(t, "POST /echo HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n8000000000000000\r\n", 400)
	expect_status(t, "POST /echo HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n", 400)
	expect_status(t, strings.concatenate({"POST /echo HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n1;", strings.repeat("a", 5000, context.temp_allocator), "\r\nx\r\n0\r\n\r\n"}, context.temp_allocator), 400)
	// Body over the handler's 1 MiB limit.
	expect_status(t, "POST /echo HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n100001\r\n", 413)
}

@(test)
transfer_encoding_rules :: proc(t: ^testing.T) {
	expect_status(t, "POST /echo HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: gzip, chunked\r\n\r\n0\r\n\r\n", 501)
	expect_status(t, "POST /echo HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked, gzip\r\n\r\n0\r\n\r\n", 400)
	expect_status(t, "POST /echo HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", 400)
	expect_status(t, "POST /echo HTTP/1.0\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", 400)
	// Split over two field lines, final coding chunked.
	expect_status(t, "POST /echo HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: gzip\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", 501)
}

@(test)
content_length_rules :: proc(t: ^testing.T) {
	expect_status(t, "POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\nhello", 200)
	expect_status(t, "POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\nhello", 400)
	expect_status(t, "POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 5, 5\r\n\r\nhello", 200)
	expect_status(t, "POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: \r\n\r\n", 400)
	// Over the server-wide default max_body_size (8 MiB) even though the handler didn't set one.
	expect_status(t, "POST /trailer HTTP/1.1\r\nHost: x\r\nContent-Length: 8388609\r\n\r\n", 413)
}

@(test)
unread_body_too_large_closes :: proc(t: ^testing.T) {
	// The handler ignores a 1 MiB body: the response is still sent, but the connection is closed
	// rather than draining that much.
	resp := expect_status(t, "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 1048576\r\n\r\nGET / HTTP/1.1\r\nHost: x\r\n\r\n", 200)
	testing.expectf(t, count_responses(resp) == 1, "got %q", resp)
}

@(test)
expect_rules :: proc(t: ^testing.T) {
	expect_status(t, "POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nExpect: something\r\n\r\nhello", 417)
	resp := expect_status(t, "POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nExpect: 100-Continue\r\n\r\nhello", 100)
	testing.expectf(t, strings.contains(resp, "got 5 bytes"), "got %q", resp)

	// Handler doesn't read the body: no 100, and the connection is closed.
	resp = expect_status(t, "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nExpect: 100-continue\r\n\r\n", 200)
	testing.expectf(t, !strings.contains(resp, "100 Continue"), "got %q", resp)
	testing.expectf(t, strings.contains(resp, "connection: close"), "got %q", resp)

	// HTTP/1.0 clients don't get an interim response.
	resp = expect_status(t, "POST /echo HTTP/1.0\r\nHost: x\r\nContent-Length: 5\r\nExpect: 100-continue\r\n\r\nhello", 200)
	testing.expectf(t, !strings.contains(resp, "100 Continue"), "got %q", resp)
}

@(test)
head_rules :: proc(t: ^testing.T) {
	resp := expect_status(t, "HEAD /stream HTTP/1.1\r\nHost: x\r\n\r\n", 200)
	testing.expectf(t, !strings.contains(resp, "streamed"), "got %q", resp)
	resp = expect_status(t, "HEAD / HTTP/1.0\r\n\r\n", 200)
	testing.expectf(t, strings.has_suffix(resp, "\r\n\r\n") && strings.contains(resp, "content-length: 5"), "got %q", resp)
}

@(test)
connection_header :: proc(t: ^testing.T) {
	ts := server_start(t, echo_handler())
	defer server_stop(ts)
	for v in ([]string{"close", "Close", "keep-alive, close", "CLOSE , foo"}) {
		resp := roundtrip(ts, strings.concatenate({"GET / HTTP/1.1\r\nHost: x\r\nConnection: ", v, "\r\n\r\nGET / HTTP/1.1\r\nHost: x\r\n\r\n"}, context.temp_allocator))
		testing.expectf(t, count_responses(resp) == 1, "Connection: %q should close, got %q", v, resp)
	}
	resp := roundtrip(ts, "GET / HTTP/1.1\r\nHost: x\r\nConnection: keep-alive\r\n\r\nGET / HTTP/1.1\r\nHost: x\r\n\r\n")
	testing.expectf(t, count_responses(resp) == 2, "got %q", resp)
}

@(test)
request_head_limits :: proc(t: ^testing.T) {
	expect_status(t, strings.concatenate({"GET /", strings.repeat("a", 9000, context.temp_allocator), " HTTP/1.1\r\nHost: x\r\n\r\n"}, context.temp_allocator), 414)

	b := strings.builder_make(context.temp_allocator)
	strings.write_string(&b, "GET / HTTP/1.1\r\nHost: x\r\n")
	for _ in 0 ..< 101 { strings.write_string(&b, "X-A: 1\r\n") }
	strings.write_string(&b, "\r\n")
	expect_status(t, strings.to_string(b), 431)

	expect_status(t, strings.concatenate({"GET / HTTP/1.1\r\nHost: x\r\nX-Big: ", strings.repeat("a", 8000, context.temp_allocator), "\r\n\r\n"}, context.temp_allocator), 431)
	// Exactly at the limit is fine: 8000 bytes including CRLFs.
	expect_status(t, strings.concatenate({"GET / HTTP/1.1\r\nHost: x\r\nX-Big: ", strings.repeat("a", 8000 - 9 - 7 - 2 - 2, context.temp_allocator), "\r\n\r\n"}, context.temp_allocator), 200)
}

@(test)
request_line_rules :: proc(t: ^testing.T) {
	expect_status(t, "get / HTTP/1.1\r\nHost: x\r\n\r\n", 501)
	expect_status(t, "G(T / HTTP/1.1\r\nHost: x\r\n\r\n", 400)
	expect_status(t, "GET / HTTP/2.0\r\nHost: x\r\n\r\n", 505)
	expect_status(t, "GET / HTTP/1.2\r\nHost: x\r\n\r\n", 200)
	expect_status(t, "GET / HTTP/1.1\r\n\r\n", 400)
	expect_status(t, "GET / HTTP/1.0\r\n\r\n", 200)
	expect_status(t, "GET /  HTTP/1.1\r\nHost: x\r\n\r\n", 400)
	expect_status(t, "OPTIONS * HTTP/1.1\r\nHost: x\r\n\r\n", 200)
	expect_status(t, "\r\nGET / HTTP/1.1\r\nHost: x\r\n\r\n", 200)
}

@(test)
host_rules :: proc(t: ^testing.T) {
	expect_status(t, "GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n", 400)
	expect_status(t, "GET / HTTP/1.1\r\nHost : a\r\n\r\n", 400)
	expect_status(t, "GET / HTTP/1.1\r\nHost:a\r\n\r\n", 200)
}

@(test)
response_header_injection_dropped :: proc(t: ^testing.T) {
	h := http.handler(proc(_: ^http.Request, res: ^http.Response) {
		http.headers_set(&res.headers, "x-ok", "fine")
		http.headers_set(&res.headers, "x-inject", "a\r\nInjected: 1")
		http.headers_set(&res.headers, "x-cr", "a\rb")
		http.headers_set(&res.headers, "bad name", "v")
		http.headers_set(&res.headers, "x-nl\nInjected", "v")
		http.respond_plain(res, "hello")
	})
	ts := server_start(t, h)
	defer server_stop(ts)
	resp := roundtrip(ts, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
	testing.expectf(t, status_of(resp) == 200 && strings.contains(resp, "x-ok: fine\r\n"), "got %q", resp)
	testing.expectf(t, !strings.contains(resp, "Injected") && !strings.contains(resp, "x-cr") && !strings.contains(resp, "bad name"), "got %q", resp)
}

@(test)
request_target_forms :: proc(t: ^testing.T) {
	expect_status(t, "GET foo/admin HTTP/1.1\r\nHost: x\r\n\r\n", 400)
	expect_status(t, "GET * HTTP/1.1\r\nHost: x\r\n\r\n", 400)
	expect_status(t, "GET /a#frag HTTP/1.1\r\nHost: x\r\n\r\n", 400)
	expect_status(t, "GET ftp://x/a HTTP/1.1\r\nHost: x\r\n\r\n", 400)
	resp := expect_status(t, "GET http://x/echo HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n", 200)
	testing.expectf(t, strings.contains(resp, "got 0 bytes"), "absolute-form not routed by path: %q", resp)
	expect_status(t, "GET HTTP://x HTTP/1.1\r\nHost: x\r\n\r\n", 200)
}
