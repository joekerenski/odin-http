// Fuzzes the parsers with random and mutated inputs. The invariant is simple: no input may panic,
// and every successful parse must satisfy the grammar it claims to have checked.
//
// The iteration count can be raised for longer local runs: -define:FUZZ_ITERATIONS=10000000
package tests_fuzz

import "core:math/rand"
import "core:strings"
import "core:testing"

import "core:mem/virtual"

import http "../.."
import "../../client"

FUZZ_ITERATIONS :: #config(FUZZ_ITERATIONS, 200_000)

SEEDS := []string{
	"GET / HTTP/1.1",
	"POST /a/b?c=d HTTP/1.0",
	"OPTIONS * HTTP/1.1",
	"Host: example.com",
	"Content-Length: 42",
	"Transfer-Encoding: gzip, chunked",
	"Connection: keep-alive, close",
	"5;ext=val",
	"7fffffffffffffff",
	"100-continue",
	"Cookie: a=b; c=d",
	"Fri, 05 Feb 2023 09:01:10 GMT",
}

INTERESTING := []byte{0, '\r', '\n', '\t', ' ', ':', ';', ',', '=', '-', '+', '_', '0', '9', 'a', 'f', 'x', 0x7f, 0x80, 0xff, '%', '/', '?', '#'}

// Produces a random mutation of a seed (or pure random bytes), allocated in the temp allocator.
mutate :: proc(r: ^rand.Generator, seeds := SEEDS) -> string {
	context.random_generator = r^
	buf := make([dynamic]byte, context.temp_allocator)

	if rand.int_max(8) == 0 {
		n := rand.int_max(64)
		for _ in 0 ..< n { append(&buf, byte(rand.int_max(256))) }
		return string(buf[:])
	}

	append(&buf, ..transmute([]byte)rand.choice(seeds))
	for _ in 0 ..< 1 + rand.int_max(6) {
		pos := rand.int_max(len(buf) + 1)
		switch rand.int_max(5) {
		case 0: // insert interesting byte
			inject_at(&buf, pos, rand.choice(INTERESTING))
		case 1: // delete
			if pos < len(buf) { ordered_remove(&buf, pos) }
		case 2: // replace with random
			if pos < len(buf) { buf[pos] = byte(rand.int_max(256)) }
		case 3: // duplicate a slice
			if len(buf) > 0 && len(buf) < 4096 {
				a := rand.int_max(len(buf))
				b := a + rand.int_max(len(buf) - a)
				inject_at(&buf, pos, ..buf[a:b])
			}
		case 4: // splice in another seed
			inject_at(&buf, pos, ..transmute([]byte)rand.choice(seeds))
		}
	}
	return string(buf[:])
}

@(test)
fuzz_framing_parsers :: proc(t: ^testing.T) {
	r := context.random_generator
	for _ in 0 ..< FUZZ_ITERATIONS {
		s := mutate(&r)

		if n, ok := http.parse_content_length(s); ok {
			testing.expect(t, n >= 0)
			// Every accepted value only consists of digits, commas and OWS.
			for c in transmute([]byte)s {
				testing.expectf(t, (c >= '0' && c <= '9') || c == ',' || c == ' ' || c == '\t', "accepted %q", s)
			}
		}

		if n, ok := http.parse_chunk_size_line(s); ok {
			testing.expect(t, n >= 0)
			testing.expectf(t, len(s) > 0 && strings.index_any(s, "\r\n\x00") == -1, "accepted %q", s)
		}

		if http.parse_transfer_encoding(s) == .Chunked {
			testing.expectf(t, strings.contains(strings.to_lower(s, context.temp_allocator), "chunked"), "accepted %q", s)
			testing.expectf(t, http.is_field_value(s), "accepted %q", s)
		}

		_ = http.header_list_has_token(s, "close")

		if v, ok := http.parse_http_version(s); ok {
			testing.expect(t, v.major <= 9 && v.minor <= 9)
		}

		if http.is_request_target(s) {
			testing.expect(t, strings.index_any(s, " \r\n\t\x00\x7f") == -1)
		}

		free_all(context.temp_allocator)
	}
}

@(test)
fuzz_request_line :: proc(t: ^testing.T) {
	r := context.random_generator
	for _ in 0 ..< FUZZ_ITERATIONS {
		s := mutate(&r)
		line, err := http.requestline_parse(s, context.temp_allocator)
		if err == .None {
			target := line.target.(string)
			testing.expectf(t, http.is_request_target(target), "accepted target in %q", s)
			testing.expectf(t, strings.count(s, " ") == 2, "accepted %q", s)
		}
		free_all(context.temp_allocator)
	}
}

@(test)
fuzz_header_parse :: proc(t: ^testing.T) {
	r := context.random_generator
	for _ in 0 ..< FUZZ_ITERATIONS / 10 {
		h: http.Headers
		http.headers_init(&h, context.temp_allocator)
		for _ in 0 ..< 1 + int(rand.int_max(8, r)) {
			line := mutate(&r)
			if key, ok := http.header_parse(&h, line, context.temp_allocator); ok {
				testing.expectf(t, http.is_token(key), "key %q from %q", key, line)
				v, _ := http.headers_get(h, key)
				testing.expectf(t, http.is_field_value(v), "value %q from %q", v, line)
			}
		}
		// Whatever got in must satisfy the framing invariants the server relies on.
		if cl, ok := http.headers_get(h, "content-length"); ok {
			_, cl_ok := http.parse_content_length(cl)
			testing.expectf(t, cl_ok, "stored content-length %q", cl)
		}
		free_all(context.temp_allocator)
	}
}

@(test)
fuzz_cookies_and_dates :: proc(t: ^testing.T) {
	r := context.random_generator
	for _ in 0 ..< FUZZ_ITERATIONS / 2 {
		s := mutate(&r)
		_, _ = http.cookie_parse(s, context.temp_allocator)
		_, _ = http.date_parse(s)
		_ = http.url_parse(s)
		free_all(context.temp_allocator)
	}
}

RESPONSE_SEEDS := []string{
	"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello",
	"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5;x=y\r\nhello\r\n0\r\nX-T: 1\r\n\r\n",
	"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 204 No Content\r\n\r\n",
	"HTTP/1.0 200 OK\nSet-Cookie: a=b; Path=/\n\nbody until close",
	"HTTP/1.1 200 OK\r\nContent-Length: 3, 3\r\nTransfer-Encoding: gzip, chunked\r\n\r\n",
	"HTTP/1.1 304 Not Modified\r\nContent-Length: 10\r\n\r\n",
}

// The client's response parser on mutated responses, fed in random pieces.
@(test)
fuzz_client_response :: proc(t: ^testing.T) {
	r := context.random_generator
	opts := client.Default_Opts
	opts.max_header_size = 1024
	opts.max_headers     = 20
	opts.max_body_size   = 4096
	for _ in 0 ..< FUZZ_ITERATIONS / 10 {
		input := mutate(&r, RESPONSE_SEEDS)

		arena: virtual.Arena
		_ = virtual.arena_init_growing(&arena)
		p: client.Parser
		client.parser_init(&p, opts, rand.int_max(8, r) == 0, virtual.arena_allocator(&arena), context.temp_allocator)

		buf := make([dynamic]byte, context.temp_allocator)
		rest := input
		err: client.Error
		for len(rest) > 0 && err == nil && p.state != .Done {
			n := 1 + int(rand.int_max(min(len(rest), 32), r))
			append(&buf, ..transmute([]byte)rest[:n])
			rest = rest[n:]
			consumed: int
			consumed, err = client.parser_feed(&p, buf[:])
			testing.expect(t, consumed >= 0 && consumed <= len(buf))
			remove_range(&buf, 0, consumed)
		}
		if err == nil && p.state != .Done { err = client.parser_eof(&p) }

		if err == nil {
			testing.expectf(t, p.status >= 200 && p.status <= 999, "status %v from %q", p.status, input)
			testing.expectf(t, len(p.body) <= opts.max_body_size, "body of %i from %q", len(p.body), input)
			for k, v in p.headers._kv {
				testing.expectf(t, http.is_token(k) && http.is_field_value(v), "header %q: %q from %q", k, v, input)
			}
		}
		virtual.arena_destroy(&arena)
		free_all(context.temp_allocator)
	}
}
