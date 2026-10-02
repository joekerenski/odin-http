package http

import "core:bufio"
import "core:io"
import "core:log"
import "core:mem/virtual"
import "core:net"
import "core:strings"

Body :: string

Body_Callback :: #type proc(user_data: rawptr, body: Body, err: Body_Error)

Body_Error :: bufio.Scanner_Error

/*
Retrieves the request's body.

The framing (chunked Transfer-Encoding or Content-Length) has already been validated by the server
when the request head was read.

`max_length` can be used to set a maximum amount of bytes we try to read, once it goes over this,
an error is returned. The server-wide `Server_Opts.max_body_size` always applies, `max_length` can
only lower it.

If the client sent `Expect: 100-continue`, the interim 100 response is sent now, right before reading.

Do not call this more than once.

**Tip** If an error is returned, easily respond with an appropriate error code like this, `http.respond(res, http.body_error_status(err))`.
*/
body :: proc(req: ^Request, max_length: int = -1, user_data: rawptr, cb: Body_Callback) {
	assert(req._body_ok == nil, "you can only call body once per request")

	limit := req._scanner.connection.server.opts.max_body_size
	if max_length > -1 && max_length < limit {
		limit = max_length
	}

	switch req._framing {
	case .None:
		req._body_ok = true
		cb(user_data, "", nil)
		return
	case .Length:
		if req._content_length > limit {
			req._body_ok = false
			cb(user_data, "", .Too_Long)
			return
		}
	case .Chunked:
	}

	if req._expect_continue {
		_body_send_continue(req, limit, user_data, cb)
		return
	}

	_body_start(req, limit, user_data, cb)
}

@(private)
_body_start :: proc(req: ^Request, limit: int, user_data: rawptr, cb: Body_Callback) {
	switch req._framing {
	case .None:    unreachable()
	case .Length:  _body_length(req, user_data, cb)
	case .Chunked: _body_chunked(req, limit, user_data, cb)
	}
}

// Sends the interim "100 Continue" response, and starts reading the body once that is out.
@(private)
_body_send_continue :: proc(req: ^Request, limit: int, user_data: rawptr, cb: Body_Callback) {
	CONTINUE :: "HTTP/1.1 100 Continue\r\n\r\n"

	req._expect_continue = false

	Continue_State :: struct {
		req:       ^Request,
		limit:     int,
		user_data: rawptr,
		cb:        Body_Callback,
	}

	st := new(Continue_State, context.temp_allocator)
	st^ = {req, limit, user_data, cb}

	conn := req._scanner.connection
	conn.continue_state = st
	connection_send(conn, transmute([]byte)string(CONTINUE), proc(c: ^Connection, ok: bool) {
		context.temp_allocator = virtual.arena_allocator(&c.temp_allocator)
		st := (^Continue_State)(c.continue_state)
		c.continue_state = nil
		if !ok {
			st.req._body_ok = false
			st.cb(st.user_data, "", .Unknown)
			return
		}
		_body_start(st.req, st.limit, st.user_data, st.cb)
	})
}

/*
Parses a URL encoded body, aka bodies with the 'Content-Type: application/x-www-form-urlencoded'.

Key&value pairs are percent decoded and put in a map.
*/
body_url_encoded :: proc(plain: Body, allocator := context.temp_allocator) -> (res: map[string]string, ok: bool) {

	insert :: proc(m: ^map[string]string, plain: string, keys: int, vals: int, end: int, allocator := context.temp_allocator) -> bool {
		has_value := vals != -1
		key_end   := vals - 1 if has_value else end
		key       := plain[keys:key_end]
		val       := plain[vals:end] if has_value else ""

		// PERF: this could be a hot spot and I don't like that we allocate the decoded key and value here.
		keye := (net.percent_decode(key, allocator) or_return) if strings.index_byte(key, '%') > -1 else key
		vale := (net.percent_decode(val, allocator) or_return) if has_value && strings.index_byte(val, '%') > -1 else val

		m[keye] = vale
		return true
	}

	count := 1
	for b in plain {
		if b == '&' { count += 1 }
	}

	queries := make(map[string]string, count, allocator)

	keys := 0
	vals := -1
	for b, i in plain {
		switch b {
		case '=':
			vals = i + 1
		case '&':
			insert(&queries, plain, keys, vals, i) or_return
			keys = i + 1
			vals = -1
		}
	}

	insert(&queries, plain, keys, vals, len(plain)) or_return

	return queries, true
}

// Returns an appropriate status code for the given body error.
body_error_status :: proc(e: Body_Error) -> Status {
	switch t in e {
	case bufio.Scanner_Extra_Error:
		switch t {
		case .Too_Long:                            return .Payload_Too_Large
		case .Too_Short, .Bad_Read_Count:          return .Bad_Request
		case .Negative_Advance, .Advanced_Too_Far: return .Internal_Server_Error
		case .None:                                return .OK
		case:
			return .Internal_Server_Error
		}
	case io.Error:
		switch t {
		case .EOF, .Unknown, .No_Progress, .Unexpected_EOF:
			return .Bad_Request
		case .Empty, .Short_Write, .Buffer_Full, .Short_Buffer,
		     .Invalid_Write, .Negative_Read, .Invalid_Whence, .Invalid_Offset,
		     .Invalid_Unread, .Negative_Write, .Negative_Count,
		     .Permission_Denied, .No_Size, .Closed:
			return .Internal_Server_Error
		case .None:
			return .OK
		case:
			return .Internal_Server_Error
		}
	case: unreachable()
	}
}


// Reads a Content-Length delimited body. The length has been validated and checked against the limit.
@(private)
_body_length :: proc(req: ^Request, user_data: rawptr, cb: Body_Callback) {
	ilen := req._content_length
	assert(ilen > 0)

	req._body_ok = false

	Length_State :: struct {
		req:       ^Request,
		user_data: rawptr,
		cb:        Body_Callback,
	}
	st := new(Length_State, context.temp_allocator)
	st^ = {req, user_data, cb}

	req._scanner.max_token_size = ilen
	req._scanner.split          = scan_num_bytes
	req._scanner.split_data     = rawptr(uintptr(ilen))

	scanner_scan(req._scanner, st, proc(st: rawptr, token: string, err: bufio.Scanner_Error) {
		st := cast(^Length_State)st
		if err != nil {
			st.cb(st.user_data, "", err)
			return
		}
		st.req._body_ok = true
		st.cb(st.user_data, token, nil)
	})
}

// Chunk size lines (size + extensions) longer than this are rejected.
@(private)
MAX_CHUNK_LINE :: 4096

/*
Decodes a chunked transfer encoded request body (RFC 9112 7.1).

PERF: this could be made non-allocating by writing over the part of the body that contains the
metadata with the rest of the body, and then returning a slice of that.

Trailer fields are parsed into `req.trailers`, subject to the same size and count limits as the
header section. Fields that are not allowed in trailers are dropped.
*/
@(private)
_body_chunked :: proc(req: ^Request, max_length: int, user_data: rawptr, cb: Body_Callback) {
	req._body_ok = false

	fail :: proc(s: ^Chunked_State, err: bufio.Scanner_Error) {
		s.req._body_ok = false
		s.cb(s.user_data, "", err)
	}

	scan_size_line :: proc(s: ^Chunked_State) {
		s.req._scanner.max_token_size = MAX_CHUNK_LINE
		s.req._scanner.split          = scan_lines
		s.req._scanner.split_data     = nil
		scanner_scan(s.req._scanner, s, on_scan)
	}

	on_scan :: proc(s: rawptr, size_line: string, err: bufio.Scanner_Error) {
		s := cast(^Chunked_State)s

		if err != nil {
			fail(s, .Bad_Read_Count if err == .Too_Long else err)
			return
		}

		size, ok := parse_chunk_size_line(size_line)
		if !ok {
			log.infof("Encountered an invalid chunk size when decoding a chunked body: %q", size_line)
			fail(s, .Bad_Read_Count)
			return
		}

		// Last chunk, start scanning trailer fields.
		if size == 0 {
			s.trailer_bytes_left = s.req._scanner.connection.server.opts.limit_headers
			s.req._scanner.max_token_size = s.trailer_bytes_left
			scanner_scan(s.req._scanner, s, on_scan_trailer)
			return
		}

		if size > s.max_length - strings.builder_len(s.buf) {
			fail(s, .Too_Long)
			return
		}

		s.req._scanner.max_token_size = size
		s.req._scanner.split          = scan_num_bytes
		#assert(size_of(int) == size_of(uintptr))
		s.req._scanner.split_data     = rawptr(uintptr(size))

		scanner_scan(s.req._scanner, s, on_scan_chunk)
	}

	on_scan_chunk :: proc(s: rawptr, token: string, err: bufio.Scanner_Error) {
		s := cast(^Chunked_State)s

		if err != nil {
			fail(s, err)
			return
		}

		strings.write_string(&s.buf, token)

		// chunk-data is followed by CRLF, so the next line must be empty.
		on_scan_empty_line :: proc(s: rawptr, token: string, err: bufio.Scanner_Error) {
			s := cast(^Chunked_State)s

			if err != nil {
				fail(s, .Bad_Read_Count if err == .Too_Long else err)
				return
			}
			if len(token) != 0 {
				log.info("chunk data was not followed by CRLF")
				fail(s, .Bad_Read_Count)
				return
			}

			scan_size_line(s)
		}

		s.req._scanner.max_token_size = MAX_CHUNK_LINE
		s.req._scanner.split          = scan_lines
		s.req._scanner.split_data     = nil
		scanner_scan(s.req._scanner, s, on_scan_empty_line)
	}

	on_scan_trailer :: proc(s: rawptr, line: string, err: bufio.Scanner_Error) {
		s := cast(^Chunked_State)s

		if err != nil {
			fail(s, .Bad_Read_Count if err == .Too_Long else err)
			return
		}

		// Trailer section is done, success.
		if len(line) == 0 {
			s.req.trailers.readonly = true
			s.req._body_ok = true
			s.cb(s.user_data, strings.to_string(s.buf), nil)
			return
		}

		s.trailer_bytes_left -= len(line) + 2
		s.trailer_count      += 1
		opts := s.req._scanner.connection.server.opts
		if s.trailer_bytes_left < 0 || s.trailer_count > opts.limit_header_count {
			log.info("trailer section too large")
			fail(s, .Too_Long)
			return
		}

		key, ok := header_parse(&s.req.trailers, line)
		if !ok {
			log.infof("Invalid trailer field when decoding chunked body: %q", line)
			fail(s, .Bad_Read_Count)
			return
		}

		// A recipient MUST ignore (or consider as an error) any fields that are forbidden to be sent in a trailer.
		if !header_allowed_trailer(key) {
			log.infof("Invalid trailer header received, discarding it: %q", key)
			headers_delete_unsafe(&s.req.trailers, key)
		}

		s.req._scanner.max_token_size = max(s.trailer_bytes_left, 1)
		scanner_scan(s.req._scanner, s, on_scan_trailer)
	}

	Chunked_State :: struct {
		req:                ^Request,
		max_length:         int,
		user_data:          rawptr,
		cb:                 Body_Callback,
		trailer_bytes_left: int,
		trailer_count:      int,

		buf:                strings.Builder,
	}

	s := new(Chunked_State, context.temp_allocator)

	s.buf.buf.allocator = context.temp_allocator

	s.req        = req
	s.max_length = max_length
	s.user_data  = user_data
	s.cb         = cb

	scan_size_line(s)
}
