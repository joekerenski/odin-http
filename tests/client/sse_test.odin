package tests_client

import "core:fmt"
import "core:math/rand"
import "core:strings"
import "core:testing"

import "../../client"

// The events of `input` as "type|id|data" lines, fed whole, byte by byte and in random pieces:
// all three must agree.
@(private="file")
events :: proc(t: ^testing.T, input: string, loc := #caller_location) -> (out: []string, retry_ms: int) {
	Got :: struct { list: [dynamic]string }
	runs: [3][]string
	for split in 0 ..< 3 {
		got: Got
		got.list.allocator = context.temp_allocator
		s: client.SSE
		client.sse_init(&s, proc(ev: client.SSE_Event, user_data: rawptr) -> bool {
			g := (^Got)(user_data)
			append(&g.list, fmt.aprintf("%s|%s|%s", ev.type, ev.id, ev.data, allocator = context.temp_allocator))
			return true
		}, &got)
		rng := rand.create(u64(split + 7))
		rest := transmute([]byte)input
		for len(rest) > 0 {
			n := len(rest)
			switch split {
			case 1: n = 1
			case 2: n = 1 + rand.int_max(min(len(rest), 9), rand.default_random_generator(&rng))
			}
			testing.expect(t, client.sse_feed(&s, rest[:n]), loc = loc)
			rest = rest[n:]
		}
		runs[split] = got.list[:]
		retry_ms = s.retry_ms
		client.sse_destroy(&s)
	}
	for split in 1 ..< 3 {
		testing.expectf(t, fmt.tprint(runs[split]) == fmt.tprint(runs[0]), "split %v: %v, whole: %v", split, runs[split], runs[0], loc = loc)
	}
	return runs[0], retry_ms
}

@(test)
sse_basic_events :: proc(t: ^testing.T) {
	got, _ := events(t, "data: hello\n\nevent: delta\ndata: {\"x\":1}\n\n")
	testing.expect_value(t, len(got), 2)
	if len(got) == 2 {
		testing.expect_value(t, got[0], "message||hello")
		testing.expect_value(t, got[1], "delta||{\"x\":1}")
	}
}

@(test)
sse_line_endings_and_multiline_data :: proc(t: ^testing.T) {
	// CRLF, CR and LF; data lines join with "\n"; one space after the colon is dropped, not more.
	got, _ := events(t, "data:a\r\ndata:  b\rdata\n\r\nevent:x\rdata:c\r\r")
	testing.expect_value(t, len(got), 2)
	if len(got) == 2 {
		testing.expect_value(t, got[0], "message||a\n b\n")
		testing.expect_value(t, got[1], "x||c")
	}
}

@(test)
sse_comments_ids_retry_and_unknown_fields :: proc(t: ^testing.T) {
	input := ": keep-alive\n\nid: 7\nretry: 1500\nfoo: bar\ndata: one\n\ndata: two\n\nid\ndata: three\n\nretry: soon\nid: a\x00b\ndata: four\n\n"
	got, retry := events(t, input)
	// A comment alone dispatches nothing; the id persists until changed; a bad retry and an id
	// with NUL are ignored.
	want := []string{"message|7|one", "message|7|two", "message||three", "message||four"}
	testing.expectf(t, fmt.tprint(got) == fmt.tprint(want), "got %v", got)
	testing.expect_value(t, retry, 1500)
}

@(test)
sse_no_data_no_event :: proc(t: ^testing.T) {
	// An event with no data field isn't dispatched (its type doesn't leak into the next one);
	// "data:" with nothing is an empty event; an unterminated event at the end isn't dispatched.
	got, _ := events(t, "event: ping\n\ndata:\n\nevent: x\ndata: half")
	want := []string{"message||"}
	testing.expectf(t, fmt.tprint(got) == fmt.tprint(want), "got %v", got)
}

@(test)
sse_byte_order_mark :: proc(t: ^testing.T) {
	got, _ := events(t, "\xef\xbb\xbfdata: after bom\n\n")
	testing.expectf(t, len(got) == 1 && got[0] == "message||after bom", "got %v", got)
	// Bytes that only start like a BOM are text.
	got2, _ := events(t, "\xefx: y\ndata: z\n\n")
	testing.expectf(t, len(got2) == 1 && got2[0] == "message||z", "got %v", got2)
}

@(test)
sse_stop_and_limits :: proc(t: ^testing.T) {
	count := 0
	s: client.SSE
	client.sse_init(&s, proc(ev: client.SSE_Event, user_data: rawptr) -> bool {
		(^int)(user_data)^ += 1
		return ev.data != "stop"
	}, &count)
	defer client.sse_destroy(&s)
	ok := client.sse_feed(&s, transmute([]byte)string("data: a\n\ndata: stop\n\ndata: never\n\n"))
	testing.expect(t, !ok && count == 2)

	l: client.SSE
	client.sse_init(&l, proc(ev: client.SSE_Event, user_data: rawptr) -> bool { return true })
	defer client.sse_destroy(&l)
	l.max_line = 16
	testing.expect(t, client.sse_feed(&l, transmute([]byte)string("data: short\n")))
	long := strings.repeat("x", 40, context.temp_allocator)
	testing.expect(t, !client.sse_feed(&l, transmute([]byte)long) && l.too_long)
}
