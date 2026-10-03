package tests_client

import "core:math/rand"
import "core:mem/virtual"
import "core:strings"
import "core:testing"

import http "../.."
import "../../client"

Parsed :: struct {
	arena:  virtual.Arena,
	parser: client.Parser,
	err:    client.Error,
}

parsed_destroy :: proc(p: ^Parsed) {
	delete(p.parser.body)
	virtual.arena_destroy(&p.arena)
}

/*
Feeds `input` to a parser in pieces the way the connection does (unconsumed bytes are fed again
with the next piece), then signals the end of the stream if it isn't done. `split` 0: all at once,
1: byte by byte, otherwise random pieces from that seed.
*/
parse :: proc(input: string, split: u64, head := false, opts := client.Default_Opts) -> (p: ^Parsed) {
	p = new(Parsed)
	_ = virtual.arena_init_growing(&p.arena)
	client.parser_init(&p.parser, opts, head, virtual.arena_allocator(&p.arena), context.allocator)

	buf: [dynamic]byte
	defer delete(buf)
	rng := rand.create(split)
	rest := input
	for len(rest) > 0 {
		n := len(rest)
		switch split {
		case 0:
		case 1: n = 1
		case:   n = 1 + rand.int_max(min(len(rest), 64), rand.default_random_generator(&rng))
		}
		append(&buf, ..transmute([]byte)rest[:n])
		rest = rest[n:]
		consumed, err := client.parser_feed(&p.parser, buf[:])
		remove_range(&buf, 0, consumed)
		if err != nil { p.err = err; return }
		if p.parser.state == .Done { return }
	}
	p.err = client.parser_eof(&p.parser)
	return
}

// Runs `check` for the same input split in several ways: the result must not depend on it.
each_split :: proc(t: ^testing.T, input: string, check: proc(t: ^testing.T, p: ^Parsed, split: u64), head := false, opts := client.Default_Opts) {
	for split in ([]u64{0, 1, 2, 3, 4, 5}) {
		p := parse(input, split, head, opts)
		check(t, p, split)
		parsed_destroy(p)
		free(p)
	}
}

@(test)
content_length_body :: proc(t: ^testing.T) {
	each_split(t, "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nX-A: 1\r\nX-A: 2\r\n\r\nhelloEXTRA", proc(t: ^testing.T, p: ^Parsed, split: u64) {
		testing.expectf(t, p.err == nil && p.parser.status == 200, "split %v: %v %v", split, p.err, p.parser.status)
		testing.expectf(t, string(p.parser.body[:]) == "hello", "split %v: body %q", split, string(p.parser.body[:]))
		testing.expect_value(t, http.headers_get_unsafe(p.parser.headers, "x-a"), "1, 2")
	})
}

@(test)
chunked_body_with_trailers :: proc(t: ^testing.T) {
	input := "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 999\r\n\r\n5;ext=\"x\"\r\nhello\r\n6\r\n world\r\n0\r\nX-Checksum: abc\r\n\r\n"
	each_split(t, input, proc(t: ^testing.T, p: ^Parsed, split: u64) {
		testing.expectf(t, p.err == nil, "split %v: %v", split, p.err)
		testing.expectf(t, string(p.parser.body[:]) == "hello world", "split %v: body %q", split, string(p.parser.body[:]))
		testing.expect_value(t, http.headers_get_unsafe(p.parser.trailers, "x-checksum"), "abc")
		testing.expect(t, !http.headers_has_unsafe(p.parser.headers, "x-checksum"))
	})
}

@(test)
close_delimited_body :: proc(t: ^testing.T) {
	each_split(t, "HTTP/1.0 200 OK\nServer: old\n\nuntil the end", proc(t: ^testing.T, p: ^Parsed, split: u64) {
		testing.expectf(t, p.err == nil && string(p.parser.body[:]) == "until the end", "split %v: %v %q", split, p.err, string(p.parser.body[:]))
	})
}

@(test)
no_body_responses :: proc(t: ^testing.T) {
	// HEAD, 204 and 304 have no body, whatever the headers say.
	each_split(t, "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n", proc(t: ^testing.T, p: ^Parsed, _: u64) {
		testing.expect(t, p.err == nil && len(p.parser.body) == 0)
	}, head = true)
	for input in ([]string{"HTTP/1.1 204 No Content\r\nContent-Length: 5\r\n\r\n", "HTTP/1.1 304 Not Modified\r\nTransfer-Encoding: chunked\r\n\r\n"}) {
		p := parse(input, 0)
		testing.expectf(t, p.err == nil && p.parser.state == .Done && len(p.parser.body) == 0, "%q: %v", input, p.err)
		parsed_destroy(p); free(p)
	}
}

@(test)
interim_responses_skipped :: proc(t: ^testing.T) {
	input := "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early Hints\r\nLink: </a.css>\r\nSet-Cookie: early=1\r\n\r\nHTTP/1.1 201 Created\r\nContent-Length: 2\r\n\r\nok"
	each_split(t, input, proc(t: ^testing.T, p: ^Parsed, split: u64) {
		testing.expectf(t, p.err == nil && p.parser.status == 201 && string(p.parser.body[:]) == "ok", "split %v: %v %v", split, p.err, p.parser.status)
		testing.expect(t, !http.headers_has_unsafe(p.parser.headers, "link"))
		testing.expect_value(t, len(p.parser.cookies), 0)
	})

	// 101 is never expected, and endless interim responses are cut off.
	p := parse("HTTP/1.1 101 Switching Protocols\r\n\r\n", 0)
	testing.expect_value(t, p.err, client.Error.Invalid_Response)
	parsed_destroy(p); free(p)
	p = parse(strings.repeat("HTTP/1.1 102 Processing\r\n\r\n", 20, context.temp_allocator), 0)
	testing.expect_value(t, p.err, client.Error.Invalid_Response)
	parsed_destroy(p); free(p)
}

@(test)
cookies_parsed_leniently :: proc(t: ^testing.T) {
	input := "HTTP/1.1 200 OK\r\nSet-Cookie: a=1; Path=/; HttpOnly; Whatever=x\r\nSet-Cookie: =broken\r\nSet-Cookie: b=2\r\nContent-Length: 0\r\n\r\n"
	p := parse(input, 0)
	defer { parsed_destroy(p); free(p) }
	testing.expect(t, p.err == nil)
	testing.expect_value(t, len(p.parser.cookies), 2)
	if len(p.parser.cookies) == 2 {
		testing.expect(t, p.parser.cookies[0].name == "a" && p.parser.cookies[0].http_only)
		testing.expect(t, p.parser.cookies[1].name == "b" && p.parser.cookies[1].value == "2")
	}
}

@(test)
status_lines :: proc(t: ^testing.T) {
	Case :: struct { line: string, status: int, ok: bool }
	for c in ([]Case{
		{"HTTP/1.1 200 OK", 200, true},
		{"HTTP/1.1 200", 200, true},
		{"HTTP/1.1 200 ", 200, true},
		{"HTTP/1.0 404 Not Found", 404, true},
		{"HTTP/1.1 299 Custom", 299, true},
		{"HTTP/1.1 999 Odd", 999, true},
		{"HTTP/2 200 OK", 0, false},
		{"HTTP/2.0 200 OK", 0, false},
		{"HTTP/1.1 20 OK", 0, false},
		{"HTTP/1.1 2000 OK", 0, false},
		{"HTTP/1.1 200OK", 0, false},
		{"HTTP/1.1 099 Low", 0, false},
		{"http/1.1 200 OK", 0, false},
		{"HTTP/1.1 200 O\x00K", 0, false},
		{"garbage", 0, false},
	}) {
		p := parse(strings.concatenate({c.line, "\r\nContent-Length: 0\r\n\r\n"}, context.temp_allocator), 0)
		if c.ok {
			testing.expectf(t, p.err == nil && p.parser.status == c.status, "%q: %v %v", c.line, p.err, p.parser.status)
		} else {
			testing.expectf(t, p.err == .Invalid_Response, "%q: %v, want Invalid_Response", c.line, p.err)
		}
		parsed_destroy(p); free(p)
	}
}

@(test)
invalid_responses :: proc(t: ^testing.T) {
	Case :: struct { input: string, err: client.Error }
	for c in ([]Case{
		// Header syntax.
		{"HTTP/1.1 200 OK\r\nBad Name: x\r\n\r\n", .Invalid_Response},
		{"HTTP/1.1 200 OK\r\nName : x\r\n\r\n", .Invalid_Response},
		{"HTTP/1.1 200 OK\r\nA: 1\r\n folded\r\n\r\n", .Invalid_Response},
		{"HTTP/1.1 200 OK\r\nA: x\x00y\r\n\r\n", .Invalid_Response},
		{"HTTP/1.1 200 OK\r\nA: x\ry\r\n\r\n", .Invalid_Response},
		{"HTTP/1.1 200 OK\r\nno colon\r\n\r\n", .Invalid_Response},
		{"HTTP/1.1 200 OK\r\n: empty name\r\n\r\n", .Invalid_Response},
		// Framing.
		{"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\nhello!", .Invalid_Response},
		{"HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\n", .Invalid_Response},
		{"HTTP/1.1 200 OK\r\nContent-Length: 1e3\r\n\r\n", .Invalid_Response},
		{"HTTP/1.1 200 OK\r\nContent-Length: 99999999999999999999999\r\n\r\n", .Invalid_Response},
		{"HTTP/1.1 200 OK\r\nContent-Length: +5\r\n\r\nhello", .Invalid_Response},
		{"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\nxx", .Unsupported_Encoding},
		{"HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n0\r\n\r\n", .Unsupported_Encoding},
		{"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked, gzip\r\n\r\n", .Unsupported_Encoding},
		{"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n", .Invalid_Response},
		{"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n-5\r\n", .Invalid_Response},
		{"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nfffffffffffffffffff\r\n", .Invalid_Response},
		{"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhelloXY\r\n0\r\n\r\n", .Invalid_Response},
		{"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nBad Trailer: x\r\n\r\n", .Invalid_Response},
		// Cut short.
		{"", .Connection_Closed},
		{"HTTP/1.1 200 OK\r\nContent-Le", .Connection_Closed},
		{"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nhello", .Truncated},
		{"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n", .Truncated},
		{"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhel", .Truncated},
		{"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nX: 1\r\n", .Truncated},
	}) {
		for split in ([]u64{0, 1, 7}) {
			p := parse(c.input, split)
			testing.expectf(t, p.err == c.err, "%q (split %v): %v, want %v", c.input, split, p.err, c.err)
			parsed_destroy(p); free(p)
		}
	}
}

@(test)
limits :: proc(t: ^testing.T) {
	opts := client.Default_Opts
	opts.max_header_size = 200
	opts.max_headers     = 5
	opts.max_body_size   = 100

	Case :: struct { input: string, err: client.Error }
	big_header := strings.concatenate({"HTTP/1.1 200 OK\r\nX: ", strings.repeat("a", 300, context.temp_allocator), "\r\n\r\n"}, context.temp_allocator)
	many_headers := strings.concatenate({"HTTP/1.1 200 OK\r\n", strings.repeat("A: 1\r\n", 6, context.temp_allocator), "\r\n"}, context.temp_allocator)
	big_trailers := strings.concatenate({"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n0\r\nX: ", strings.repeat("a", 300, context.temp_allocator), "\r\n\r\n"}, context.temp_allocator)
	chunks := strings.concatenate({"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n", strings.repeat("20\r\n" + "0123456789abcdef0123456789abcdef" + "\r\n", 4, context.temp_allocator), "0\r\n\r\n"}, context.temp_allocator)
	close_body := strings.concatenate({"HTTP/1.1 200 OK\r\n\r\n", strings.repeat("x", 101, context.temp_allocator)}, context.temp_allocator)
	long_chunk_line := strings.concatenate({"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5;", strings.repeat("e", 5000, context.temp_allocator)}, context.temp_allocator)
	empty_lines := strings.repeat("\r\n", 200, context.temp_allocator)
	for c in ([]Case{
		{big_header, .Response_Too_Large},
		{many_headers, .Response_Too_Large},
		{big_trailers, .Response_Too_Large},
		{"HTTP/1.1 200 OK\r\nContent-Length: 101\r\n\r\n", .Response_Too_Large},
		{"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n65\r\n", .Response_Too_Large},
		{chunks, .Response_Too_Large},
		{close_body, .Response_Too_Large},
		{long_chunk_line, .Invalid_Response},
		{empty_lines, .Response_Too_Large},
	}) {
		for split in ([]u64{0, 1, 9}) {
			p := parse(c.input, split, opts = opts)
			testing.expectf(t, p.err == c.err, "%.60q (split %v): %v, want %v", c.input, split, p.err, c.err)
			parsed_destroy(p); free(p)
		}
	}

	// Exactly at the limit is fine.
	p := parse("HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n" + "0123456789" + "0123456789" + "0123456789" + "0123456789" + "0123456789" + "0123456789" + "0123456789" + "0123456789" + "0123456789" + "0123456789", 3, opts = opts)
	testing.expectf(t, p.err == nil && len(p.parser.body) == 100, "at the limit: %v", p.err)
	parsed_destroy(p); free(p)
}
