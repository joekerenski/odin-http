package client

import "core:bytes"
import "core:mem"
import "core:strings"

import http ".."

// Interim (1xx) responses skipped before giving up.
@(private)
MAX_INTERIM_RESPONSES :: 16

// Longest chunk-size line (with extensions) accepted.
@(private)
MAX_CHUNK_LINE :: 4096

@(private)
Parse_State :: enum u8 {
	Status_Line,
	Headers,
	Body_Length,
	Body_Close,
	Chunk_Size,
	Chunk_Data,
	Chunk_Data_End,
	Trailers,
	Done,
}

/*
Incremental HTTP/1.x response parser (RFC 9112). Feed it the bytes as they arrive (`parser_feed`),
and tell it when the stream ended (`parser_eof`). Never panics on any input.

Header names are lower-cased, repeated headers are joined with ", " (Set-Cookie goes to `cookies`
instead). Header names and values, Content-Length, Transfer-Encoding and chunk sizes are checked
with the server's strict parsers.
*/
Parser :: struct {
	// Configuration.
	max_header_size: int,
	max_headers:     int,
	max_body_size:   int,
	// The request was HEAD: the response has no body whatever its headers say.
	head_request:    bool,

	// Result.
	status:          int,
	headers:         http.Headers,
	trailers:        http.Headers,
	cookies:         [dynamic]http.Cookie,
	body:            [dynamic]byte,

	state:           Parse_State,
	section_bytes:   int,
	section_count:   int,
	left:            int,
	interim:         int,
	// Headers, cookies and trailers.
	arena:           mem.Allocator,
}

parser_init :: proc(p: ^Parser, opts: Opts, head_request: bool, arena: mem.Allocator, body_allocator: mem.Allocator) {
	p^ = {
		max_header_size = opts.max_header_size,
		max_headers     = opts.max_headers,
		max_body_size   = opts.max_body_size,
		head_request    = head_request,
		arena           = arena,
	}
	http.headers_init(&p.headers, arena)
	http.headers_init(&p.trailers, arena)
	p.cookies.allocator = arena
	p.body.allocator = body_allocator
}

// Parses as much of `data` as possible. Returns how much was consumed; the rest has to be fed
// again together with more data. Done when `p.state == .Done`.
parser_feed :: proc(p: ^Parser, data: []byte) -> (consumed: int, err: Error) {
	pos := 0
	for p.state != .Done {
		switch p.state {
		case .Status_Line, .Headers, .Chunk_Size, .Chunk_Data_End, .Trailers:
			nl := bytes.index_byte(data[pos:], '\n')
			if nl < 0 {
				// A partial line: make sure it can still fit.
				pending := len(data) - pos
				switch p.state {
				case .Chunk_Size, .Chunk_Data_End:
					if pending > MAX_CHUNK_LINE { return pos, .Invalid_Response }
				case .Status_Line, .Headers, .Trailers:
					if p.section_bytes + pending > p.max_header_size { return pos, .Response_Too_Large }
				case .Body_Length, .Body_Close, .Chunk_Data, .Done:
				}
				return pos, .None
			}
			raw := data[pos:pos + nl]
			pos += nl + 1
			// CRLF, or a bare LF (RFC 9112 2.2).
			line := string(raw[:len(raw) - 1] if len(raw) > 0 && raw[len(raw) - 1] == '\r' else raw)
			parse_line(p, line, nl + 1) or_return

		case .Body_Length, .Chunk_Data:
			n := min(p.left, len(data) - pos)
			if n == 0 { return pos, .None }
			append(&p.body, ..data[pos:pos + n])
			pos += n
			p.left -= n
			if p.left == 0 { p.state = .Done if p.state == .Body_Length else .Chunk_Data_End }

		case .Body_Close:
			if len(p.body) + len(data) - pos > p.max_body_size { return pos, .Response_Too_Large }
			append(&p.body, ..data[pos:])
			return len(data), .None

		case .Done:
		}
	}
	return pos, .None
}

// The stream ended. Fine for a body delimited by the connection closing, an error otherwise.
parser_eof :: proc(p: ^Parser) -> Error {
	#partial switch p.state {
	case .Done:
		return .None
	case .Body_Close:
		p.state = .Done
		return .None
	case .Status_Line, .Headers:
		return .Connection_Closed
	}
	return .Truncated
}

@(private)
parse_line :: proc(p: ^Parser, line: string, raw_len: int) -> Error {
	switch p.state {
	case .Status_Line:
		p.section_bytes += raw_len
		if p.section_bytes > p.max_header_size { return .Response_Too_Large }
		// Tolerate empty lines before the status line (RFC 9112 2.2); they count against the limit.
		if line == "" { return .None }
		p.status = parse_status_line(line) or_return
		p.state = .Headers

	case .Headers, .Trailers:
		p.section_bytes += raw_len
		if p.section_bytes > p.max_header_size { return .Response_Too_Large }
		if line == "" {
			if p.state == .Trailers {
				p.state = .Done
				return .None
			}
			return headers_done(p)
		}
		p.section_count += 1
		if p.section_count > p.max_headers { return .Response_Too_Large }
		add_field(p, line, trailer = p.state == .Trailers) or_return

	case .Chunk_Size:
		size, ok := http.parse_chunk_size_line(line)
		if !ok { return .Invalid_Response }
		if size == 0 {
			p.state = .Trailers
			p.section_bytes, p.section_count = 0, 0
			return .None
		}
		if size > p.max_body_size - len(p.body) { return .Response_Too_Large }
		p.left = size
		p.state = .Chunk_Data

	case .Chunk_Data_End:
		if line != "" { return .Invalid_Response }
		p.state = .Chunk_Size

	case .Body_Length, .Body_Close, .Chunk_Data, .Done:
		unreachable()
	}
	return .None
}

// status-line = HTTP-version SP 3DIGIT SP [ reason-phrase ]; the SP before an empty reason is
// often left out and accepted.
@(private)
parse_status_line :: proc(line: string) -> (status: int, err: Error) {
	if len(line) < 12 || line[8] != ' ' { return 0, .Invalid_Response }
	version, ok := http.parse_http_version(line[:8])
	if !ok || version.major != 1 { return 0, .Invalid_Response }
	for i in 9 ..< 12 {
		if line[i] < '0' || line[i] > '9' { return 0, .Invalid_Response }
		status = status * 10 + int(line[i] - '0')
	}
	if status < 100 { return 0, .Invalid_Response }
	if len(line) > 12 && (line[12] != ' ' || !http.is_field_value(line[13:])) { return 0, .Invalid_Response }
	return status, .None
}

@(private)
add_field :: proc(p: ^Parser, line: string, trailer: bool) -> Error {
	colon := strings.index_byte(line, ':')
	if colon <= 0 { return .Invalid_Response }
	// No whitespace before the colon, and no obsolete line folding (a line starting with SP/HTAB).
	name := line[:colon]
	if !http.is_token(name) { return .Invalid_Response }
	value := http.trim_ows(line[colon + 1:])
	if !http.is_field_value(value) { return .Invalid_Response }

	lower := strings.to_lower(name, p.arena)
	if !trailer && lower == "set-cookie" {
		// Unparseable cookies are skipped, they don't make the response invalid.
		if cookie, ok := http.cookie_parse(strings.clone(value, p.arena), p.arena); ok {
			append(&p.cookies, cookie)
		}
		return .None
	}

	h := &p.trailers if trailer else &p.headers
	if prev, has := http.headers_get_unsafe(h^, lower); has {
		http.headers_set_unsafe(h, lower, strings.concatenate({prev, ", ", value}, p.arena))
	} else {
		http.headers_set_unsafe(h, lower, strings.clone(value, p.arena))
	}
	return .None
}

// The end of the header section: interim responses start over, otherwise the body's framing is
// decided (RFC 9112 6.3).
@(private)
headers_done :: proc(p: ^Parser) -> Error {
	if p.status < 200 {
		// 101 Switching Protocols: we never ask for an upgrade.
		if p.status == 101 { return .Invalid_Response }
		p.interim += 1
		if p.interim > MAX_INTERIM_RESPONSES { return .Invalid_Response }
		clear(&p.headers._kv)
		clear(&p.cookies)
		p.section_bytes, p.section_count = 0, 0
		p.state = .Status_Line
		return .None
	}

	if p.head_request || p.status == 204 || p.status == 304 {
		p.state = .Done
		return .None
	}

	if te, has := http.headers_get_unsafe(p.headers, "transfer-encoding"); has {
		// We don't ask for any coding (no TE or Accept-Encoding), so only plain chunked is expected.
		if http.parse_transfer_encoding(te) != .Chunked { return .Unsupported_Encoding }
		p.state = .Chunk_Size
		return .None
	}

	if cl, has := http.headers_get_unsafe(p.headers, "content-length"); has {
		n, ok := http.parse_content_length(cl)
		if !ok { return .Invalid_Response }
		if n > p.max_body_size { return .Response_Too_Large }
		if n == 0 {
			p.state = .Done
			return .None
		}
		reserve(&p.body, n)
		p.left = n
		p.state = .Body_Length
		return .None
	}

	p.state = .Body_Close
	return .None
}
