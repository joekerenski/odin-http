package tests_client

import "core:math/rand"
import "core:mem/virtual"
import "core:strings"
import "core:testing"

import "../../client"

// The parser in streaming mode: what reached on_head / on_body, in order.
@(private="file")
Streamed :: struct {
	arena:     virtual.Arena,
	parser:    client.Parser,
	err:       client.Error,
	log:       strings.Builder, // "H<status>" then the body pieces, "|" between calls
	body:      strings.Builder,
	heads:     int,
	cancel_at: string, // on_body returns false once the body contains this
	no_head:   bool, // on_head returns false
}

@(private="file")
stream_parse :: proc(input: string, split: u64, s: ^Streamed, opts := client.Default_Opts) {
	_ = virtual.arena_init_growing(&s.arena)
	strings.builder_init(&s.log, context.temp_allocator)
	strings.builder_init(&s.body, context.temp_allocator)
	client.parser_init(&s.parser, opts, false, virtual.arena_allocator(&s.arena), context.allocator)
	s.parser.user_data = s
	s.parser.on_head = proc(p: ^client.Parser) -> bool {
		s := (^Streamed)(p.user_data)
		s.heads += 1
		strings.write_string(&s.log, "H")
		strings.write_int(&s.log, p.status)
		return !s.no_head
	}
	s.parser.on_body = proc(p: ^client.Parser, data: []byte) -> bool {
		s := (^Streamed)(p.user_data)
		strings.write_byte(&s.log, '|')
		strings.write_bytes(&s.log, data)
		strings.write_bytes(&s.body, data)
		return s.cancel_at == "" || !strings.contains(strings.to_string(s.body), s.cancel_at)
	}

	buf: [dynamic]byte
	defer delete(buf)
	rng := rand.create(split)
	rest := input
	for len(rest) > 0 {
		n := len(rest)
		switch split {
		case 0:
		case 1: n = 1
		case:   n = 1 + rand.int_max(min(len(rest), 32), rand.default_random_generator(&rng))
		}
		append(&buf, ..transmute([]byte)rest[:n])
		rest = rest[n:]
		consumed, err := client.parser_feed(&s.parser, buf[:])
		remove_range(&buf, 0, consumed)
		if err != nil { s.err = err; return }
		if s.parser.state == .Done { return }
	}
	s.err = client.parser_eof(&s.parser)
}

@(private="file")
streamed_destroy :: proc(s: ^Streamed) {
	delete(s.parser.body)
	virtual.arena_destroy(&s.arena)
}

@(test)
stream_head_before_body :: proc(t: ^testing.T) {
	inputs := []string{
		"HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nhello world",
		"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n6\r\n world\r\n0\r\nX-T: 1\r\n\r\n",
		"HTTP/1.0 200 OK\r\n\r\nhello world",
		// Interim responses don't count as the head.
		"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\nhello world",
	}
	for input in inputs {
		for split in ([]u64{0, 1, 2, 3}) {
			s: Streamed
			stream_parse(input, split, &s)
			log := strings.to_string(s.log)
			testing.expectf(t, s.err == nil, "%.30q split %v: %v", input, split, s.err)
			testing.expectf(t, s.heads == 1 && strings.has_prefix(log, "H200"), "%.30q split %v: log %q", input, split, log)
			testing.expectf(t, strings.to_string(s.body) == "hello world", "%.30q split %v: body %q", input, split, strings.to_string(s.body))
			testing.expectf(t, len(s.parser.body) == 0, "%.30q: body collected while streaming", input)
			streamed_destroy(&s)
		}
	}
}

@(test)
stream_no_body_still_has_head :: proc(t: ^testing.T) {
	s: Streamed
	stream_parse("HTTP/1.1 204 No Content\r\n\r\n", 0, &s)
	defer streamed_destroy(&s)
	testing.expect(t, s.err == nil && strings.to_string(s.log) == "H204")
}

@(test)
stream_ignores_total_body_limit :: proc(t: ^testing.T) {
	// The body isn't kept, so max_body_size limits one chunk, not the whole body.
	opts := client.Default_Opts
	opts.max_body_size = 8
	{
		s: Streamed
		stream_parse("HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\n01234567890123456789", 2, &s, opts)
		testing.expect(t, s.err == nil && strings.to_string(s.body) == "01234567890123456789")
		streamed_destroy(&s)
	}
	{
		s: Streamed
		stream_parse("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n8\r\n01234567\r\n8\r\n89012345\r\n0\r\n\r\n", 1, &s, opts)
		testing.expect(t, s.err == nil && strings.to_string(s.body) == "0123456789012345")
		streamed_destroy(&s)
	}
	{
		s: Streamed
		stream_parse("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n9\r\n012345678\r\n0\r\n\r\n", 0, &s, opts)
		testing.expect_value(t, s.err, client.Error.Response_Too_Large)
		streamed_destroy(&s)
	}
}

@(test)
stream_cancel :: proc(t: ^testing.T) {
	{
		s := Streamed{cancel_at = "stop"}
		stream_parse("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nstop\r\n5\r\nnever\r\n0\r\n\r\n", 0, &s)
		testing.expect_value(t, s.err, client.Error.Cancelled)
		testing.expect(t, !strings.contains(strings.to_string(s.body), "never"))
		streamed_destroy(&s)
	}
	{
		s := Streamed{no_head = true}
		stream_parse("HTTP/1.1 500 Oops\r\nContent-Length: 4\r\n\r\nbody", 0, &s)
		testing.expect_value(t, s.err, client.Error.Cancelled)
		testing.expect_value(t, strings.to_string(s.body), "")
		streamed_destroy(&s)
	}
}
