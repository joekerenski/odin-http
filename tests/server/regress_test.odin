package tests_server

import "core:strings"
import "core:testing"
import "core:time"

expect_status :: proc(t: ^testing.T, req: string, want: int, loc := #caller_location) -> string {
	ts := server_start(t, echo_handler())
	defer server_stop(ts)
	resp := roundtrip(ts, req)
	testing.expectf(t, status_of(resp) == want, "want status %d, got %q", want, resp, loc = loc)
	return resp
}

@(test)
baseline :: proc(t: ^testing.T) {
	resp := expect_status(t, "GET / HTTP/1.1\r\nHost: x\r\n\r\n", 200)
	testing.expect(t, strings.has_suffix(resp, "hello"))
}

// --- Remote crashes (single request takes the whole process down) ---

@(test)
chunked_trailer_handler_reads :: proc(t: ^testing.T) {
	expect_status(t, "POST /echo HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\nX-T: 1\r\n\r\n", 200)
}

@(test)
chunked_trailer_handler_ignores :: proc(t: ^testing.T) {
	expect_status(t, "POST / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\nX-T: 1\r\n\r\n", 200)
}

@(test)
chunk_data_without_crlf :: proc(t: ^testing.T) {
	expect_status(t, "POST /echo HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhelloXX\r\n0\r\n\r\n", 400)
}

@(test)
negative_content_length :: proc(t: ^testing.T) {
	expect_status(t, "POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: -5\r\n\r\nhello", 400)
}

@(test)
negative_content_length_handler_ignores :: proc(t: ^testing.T) {
	expect_status(t, "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: -5\r\n\r\nhello", 400)
}

// --- Framing / smuggling ---

@(test)
content_length_must_be_digits :: proc(t: ^testing.T) {
	expect_status(t, "POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: +5\r\n\r\nhello", 400)
	expect_status(t, "POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 0_5\r\n\r\nhello", 400)
	expect_status(t, "POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 0x5\r\n\r\nhello", 400)
}

@(test)
transfer_encoding_exact_chunked :: proc(t: ^testing.T) {
	expect_status(t, "POST /echo HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: xchunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n", 400)
	// Coding names are case-insensitive.
	expect_status(t, "POST /echo HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: Chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n", 200)
}

@(test)
te_and_cl_closes_connection :: proc(t: ^testing.T) {
	resp := expect_status(t, "POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET / HTTP/1.1\r\nHost: x\r\n\r\n", 200)
	testing.expectf(t, count_responses(resp) == 1, "connection should close after TE+CL request, got %q", resp)
}

@(test)
unread_body_is_discarded :: proc(t: ^testing.T) {
	resp := expect_status(t, "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 35\r\n\r\nGET /smuggled HTTP/1.1\r\nHost: x\r\n\r\n", 200)
	testing.expectf(t, count_responses(resp) == 1, "body was parsed as a request: %q", resp)
}

@(test)
head_has_no_body :: proc(t: ^testing.T) {
	resp := expect_status(t, "HEAD / HTTP/1.1\r\nHost: x\r\n\r\nGET / HTTP/1.1\r\nHost: x\r\n\r\n", 200)
	testing.expectf(t, count_responses(resp) == 2, "want 2 responses, got %q", resp)
	testing.expectf(t, !strings.contains(resp, "helloHTTP/1.1"), "HEAD response carried a body: %q", resp)
}

@(test)
expect_100_continue :: proc(t: ^testing.T) {
	ts := server_start(t, echo_handler())
	defer server_stop(ts)
	resp := roundtrip(ts, "POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nExpect: 100-continue\r\n\r\nhello", wait = time.Second)
	testing.expectf(t, strings.contains(resp, "got 5 bytes"), "100-continue upload did not reach the handler: %q", resp)
}

// --- Syntax validation ---

@(test)
invalid_header_names :: proc(t: ^testing.T) {
	expect_status(t, "GET / HTTP/1.1\r\nHost: x\r\nBad Name: v\r\n\r\n", 400)
	expect_status(t, "GET / HTTP/1.1\r\nHost: x\r\n\tfolded\r\n\r\n", 400)
	expect_status(t, "GET / HTTP/1.1\r\nHost: x\r\nX: a\x00b\r\n\r\n", 400)
	expect_status(t, "GET / HTTP/1.1\r\nHost: x\r\nX: a\rb\r\n\r\n", 400)
}

@(test)
invalid_request_lines :: proc(t: ^testing.T) {
	expect_status(t, "GET / HTTP/1\r\nHost: x\r\n\r\n", 400)
	expect_status(t, "GET  HTTP/1.1\r\nHost: x\r\n\r\n", 400)
	expect_status(t, "GET / HTTP/1.x\r\nHost: x\r\n\r\n", 400)
	expect_status(t, "GET /\x7f HTTP/1.1\r\nHost: x\r\n\r\n", 400)
}

@(test)
huge_content_length_rejected :: proc(t: ^testing.T) {
	expect_status(t, "POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 99999999999999\r\n\r\n", 413)
	expect_status(t, "POST /echo HTTP/1.1\r\nHost: x\r\nContent-Length: 99999999999999999999999\r\n\r\n", 400)
}
