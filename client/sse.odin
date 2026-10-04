package client

import "core:mem"

/*
An incremental parser for Server-Sent Events (`text/event-stream`, WHATWG HTML 9.2), the format
streaming APIs answer in. Feed it the body as it arrives, in pieces of any size; it calls
`on_event` once per complete event.

	on_event :: proc(ev: client.SSE_Event, user_data: rawptr) -> bool {
		fmt.println(ev.type, ev.data)
		return true // false stops: sse_feed returns false, and so can on_body
	}

	sse: client.SSE
	client.sse_init(&sse, on_event, &my_state)
	defer client.sse_destroy(&sse)
	stream := client.Stream{on_body = proc(data: []byte, user_data: rawptr) -> bool {
		return client.sse_feed((^client.SSE)(user_data), data)
	}}
	res, err := client.request_stream(&req, url, stream, &sse)

Lines end in CRLF, LF or CR. `data` fields are joined with "\n", `event` names the event
("message" when it doesn't), `id` sets the last event ID (kept across events, as the spec says),
`retry` sets `retry_ms`; lines starting with ':' are comments (keep-alives), other fields are
ignored. A leading byte order mark is skipped. An event still incomplete when the stream ends is
not dispatched.
*/
SSE :: struct {
	on_event:  proc(ev: SSE_Event, user_data: rawptr) -> bool,
	user_data: rawptr,
	// The last valid `retry` field, in milliseconds; 0 if none came.
	retry_ms:  int,
	// A line longer than this (bytes) stops the parse, with `too_long` set. Defaults to 4 MiB.
	max_line:  int,
	too_long:  bool,

	line:      [dynamic]byte,
	data:      [dynamic]byte,
	type:      [dynamic]byte,
	id:        [dynamic]byte,
	after_cr:  bool,
	bom:       int, // byte order mark bytes matched at the start, 3 once past it
}

// One event. The strings are only valid during the `on_event` call.
SSE_Event :: struct {
	type: string,
	data: string,
	id:   string,
}

sse_init :: proc(s: ^SSE, on_event: proc(ev: SSE_Event, user_data: rawptr) -> bool, user_data: rawptr = nil, allocator := context.allocator) {
	s^ = {on_event = on_event, user_data = user_data, max_line = 4 * mem.Megabyte}
	s.line.allocator = allocator
	s.data.allocator = allocator
	s.type.allocator = allocator
	s.id.allocator = allocator
}

sse_destroy :: proc(s: ^SSE) {
	delete(s.line)
	delete(s.data)
	delete(s.type)
	delete(s.id)
}

// Parses `data`. False when `on_event` asked to stop or a line was too long; feeding more after
// that is a mistake.
sse_feed :: proc(s: ^SSE, data: []byte) -> bool {
	bom := [3]byte{0xef, 0xbb, 0xbf}
	for i := 0; i < len(data); i += 1 {
		b := data[i]
		if s.bom < 3 {
			if b == bom[s.bom] {
				s.bom += 1
				continue
			}
			// Not a byte order mark after all: what matched of it is text.
			append(&s.line, ..bom[:s.bom])
			s.bom = 3
		}
		if s.after_cr {
			s.after_cr = false
			if b == '\n' { continue } // the LF of a CRLF
		}
		switch b {
		case '\r':
			s.after_cr = true
			sse_line(s) or_return
		case '\n':
			sse_line(s) or_return
		case:
			// Up to the next line end at once.
			end := i + 1
			for end < len(data) && data[end] != '\n' && data[end] != '\r' { end += 1 }
			if len(s.line) + end - i > s.max_line {
				s.too_long = true
				return false
			}
			append(&s.line, ..data[i:end])
			i = end - 1
		}
	}
	return true
}

@(private="file")
sse_line :: proc(s: ^SSE) -> bool {
	defer clear(&s.line)
	line := string(s.line[:])
	if line == "" { return sse_dispatch(s) }
	if line[0] == ':' { return true }

	field, value := line, ""
	for c, i in line {
		if c == ':' {
			field, value = line[:i], line[i + 1:]
			if len(value) > 0 && value[0] == ' ' { value = value[1:] }
			break
		}
	}
	switch field {
	case "event":
		clear(&s.type)
		append(&s.type, value)
	case "data":
		append(&s.data, value)
		append(&s.data, '\n')
	case "id":
		// An id containing NUL is ignored.
		for c in transmute([]byte)value { if c == 0 { return true } }
		clear(&s.id)
		append(&s.id, value)
	case "retry":
		n := 0
		for c in transmute([]byte)value {
			if c < '0' || c > '9' { return true }
			n = n * 10 + int(c - '0')
		}
		if len(value) > 0 { s.retry_ms = n }
	}
	return true
}

// A blank line: the event so far, if it has data.
@(private="file")
sse_dispatch :: proc(s: ^SSE) -> bool {
	defer {
		clear(&s.data)
		clear(&s.type)
	}
	if len(s.data) == 0 { return true }
	ev := SSE_Event{
		type = string(s.type[:]) if len(s.type) > 0 else "message",
		data = string(s.data[:len(s.data) - 1]), // without the last "\n"
		id   = string(s.id[:]),
	}
	return s.on_event(ev, s.user_data)
}
