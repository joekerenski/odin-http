package http

import "base:runtime"

import "core:bufio"
import "core:bytes"
import "core:io"
import "core:mem/virtual"
import "core:strings"

/*
multipart/form-data bodies (RFC 7578): what an HTML form with a file input (`enctype="multipart/form-data"`)
sends. Each part is a form field: headers (Content-Disposition with the field's name, and a filename
for files) and its content.

`multipart_stream` reads such a body as it arrives, on top of `body_stream`, so files of any size
pass through without being held in memory. `multipart_parse` splits a body that is in memory already
(read with `body`), for small forms.
*/

Multipart_Event :: enum u8 {
	// A new part starts: `part` has its headers.
	Part,
	// The next piece of the current part's content in `data`.
	Data,
	// The current part is complete.
	Part_End,
	// The body ended, all parts were delivered; or, with `err` set, reading or parsing it failed.
	Done,
}

Multipart_Error :: union #shared_nil {
	io.Error,
	bufio.Scanner_Extra_Error,
	Multipart_Parse_Error,
}

Multipart_Parse_Error :: enum u8 {
	None,
	// The request isn't multipart/form-data with a valid boundary.
	Not_Multipart,
	// The body doesn't follow the multipart syntax, or ended before the closing delimiter.
	Malformed,
	// More parts than `Multipart_Opts.max_parts`.
	Too_Many_Parts,
	// A part's header section over `Multipart_Opts.max_header_size` or `max_headers`.
	Headers_Too_Large,
}

Multipart_Part :: struct {
	// The part's header fields, lower-case names. Read-only.
	headers:      Headers,
	// The form field's name, from Content-Disposition.
	name:         string,
	// The file's name as the client sent it (a file input), "" for other fields. Never use it as a
	// path as is: it can contain anything, "../" included.
	filename:     string,
	// The part's Content-Type, "text/plain" when it has none (RFC 7578 4.4).
	content_type: string,
}

Multipart_Opts :: struct {
	max_parts:       int,
	// Per part, in bytes, and the number of header fields.
	max_header_size: int,
	max_headers:     int,
}

Default_Multipart_Opts :: Multipart_Opts {
	max_parts       = 1000,
	max_header_size = 8 * 1024,
	max_headers     = 32,
}

/*
Gets the next event of a multipart body, see `multipart_stream`. `part` is the current part (valid
until the response is sent). `data` (for `.Data`) is valid until `multipart_next` is called or the
response is sent.
*/
Multipart_Callback :: #type proc(user_data: rawptr, event: Multipart_Event, part: ^Multipart_Part, data: []byte, err: Multipart_Error)

/*
Reads a multipart/form-data body as it arrives, part by part, see `body_stream`, which this builds
on: `cb` gets the first event, then nothing happens until `multipart_next` is called, which gets the
next one to `cb`. For each part: `.Part`, its content in `.Data` pieces (none for an empty part),
`.Part_End`; after the last part `.Done`. An error ends it with `.Done` and `err` set: respond (see
`multipart_error_status`), the connection is closed after that.

`max_length` limits the body's total size, -1 for no limit. The handler may respond at any point,
the rest of the body is then dealt with like for `body_stream`.

Example, storing files as they come (error handling and the writing itself shortened):

	http.multipart_stream(req, 1 * mem.Gigabyte, up, proc(up: rawptr, event: http.Multipart_Event, part: ^http.Multipart_Part, data: []byte, err: http.Multipart_Error) {
		up := (^Upload)(up)
		switch event {
		case .Part:     if part.filename != "" { start_file(up, part.name) }
		case .Data:     write(up, data) // then `http.multipart_next(up.req)` once written
		                return
		case .Part_End: finish_file(up)
		case .Done:
			http.respond(up.res, http.Status.Created if err == nil else http.multipart_error_status(err))
			return
		}
		http.multipart_next(up.req)
	})
*/
multipart_stream :: proc(req: ^Request, max_length: int, user_data: rawptr, cb: Multipart_Callback, opts := Default_Multipart_Opts, loc := #caller_location) {
	assert(cb != nil, "multipart_stream needs a callback", loc)
	conn := req._scanner.connection
	context.temp_allocator = virtual.arena_allocator(&conn.temp_allocator)

	m := new(Multipart_Stream, context.temp_allocator)
	m.req       = req
	m.cb        = cb
	m.user_data = user_data
	req._multipart = m

	boundary, ok := multipart_boundary(req.headers)
	if !ok {
		// The body isn't read: the response (an error) decides about it.
		m.finished = true
		cb(user_data, .Done, nil, nil, Multipart_Parse_Error.Not_Multipart)
		return
	}
	multipart_parser_init(&m.p, boundary, opts, context.temp_allocator)

	body_stream(req, max_length, m, multipart_on_piece, loc)
}

/*
Gets the next event to the callback given to `multipart_stream`. Does nothing once it's done or the
response was sent.
*/
multipart_next :: proc(req: ^Request) {
	m := req._multipart
	if m == nil || m.finished { return }
	if st := req._stream; st != nil && st.abandoned { return }
	if m.in_cb {
		m.want_next = true
		return
	}
	if m.driving { return }
	context.temp_allocator = virtual.arena_allocator(&req._scanner.connection.temp_allocator)
	multipart_drive(m)
}

// Returns an appropriate status code for the given multipart error.
multipart_error_status :: proc(err: Multipart_Error) -> Status {
	switch e in err {
	case io.Error:                  return body_error_status(e)
	case bufio.Scanner_Extra_Error: return body_error_status(e)
	case Multipart_Parse_Error:
		switch e {
		case .None:              return .OK
		case .Not_Multipart:     return .Unsupported_Media_Type
		case .Malformed:         return .Bad_Request
		case .Too_Many_Parts:    return .Payload_Too_Large
		case .Headers_Too_Large: return .Request_Header_Fields_Too_Large
		}
	}
	return .OK
}

// A form field of a body split by `multipart_parse`.
Multipart_Field :: struct {
	using part: Multipart_Part,
	// The content. A slice of the body when it's in one piece, which it is unless the part is
	// empty (then "").
	data:       string,
}

/*
Splits a multipart/form-data body that is in memory (e.g. read with `body`) into its parts, with
the boundary from the request's Content-Type. Names, headers and the field list are allocated with
`allocator`, the data are slices of `body`.
*/
multipart_parse :: proc(req: ^Request, body: Body, opts := Default_Multipart_Opts, allocator := context.temp_allocator) -> (fields: []Multipart_Field, err: Multipart_Error) {
	boundary, ok := multipart_boundary(req.headers)
	if !ok { return nil, Multipart_Parse_Error.Not_Multipart }

	p: Multipart_Parser
	multipart_parser_init(&p, boundary, opts, allocator)
	multipart_parser_input(&p, transmute([]byte)body, true)

	list := make([dynamic]Multipart_Field, allocator)
	defer if err != nil { delete(list) }
	for {
		ev, data, perr := multipart_parser_step(&p)
		switch ev {
		case .Need_Input: unreachable()
		case .Part:
			append(&list, Multipart_Field{part = p.part})
		case .Data:
			// One piece, a slice of the body: the whole body is one input, nothing is carried over.
			f := &list[len(list) - 1]
			if f.data == "" {
				f.data = string(data)
			} else {
				f.data = strings.concatenate({f.data, string(data)}, allocator)
			}
		case .Part_End:
		case .Done:
			if perr != nil { return nil, perr }
			return list[:], nil
		}
	}
}

/*
The boundary of a multipart/form-data Content-Type (RFC 2046 5.1.1): 1 to 70 characters, quoted or a
token.
*/
@(private)
multipart_boundary :: proc(headers: Headers) -> (boundary: string, ok: bool) {
	ct := headers_get_unsafe(headers, "content-type") or_return
	semi := strings.index_byte(ct, ';')
	(semi > 0) or_return
	ascii_equal_fold(trim_ows(ct[:semi]), "multipart/form-data") or_return

	params := ct[semi + 1:]
	for len(params) > 0 {
		param: string
		if i := strings.index_byte(params, ';'); i >= 0 {
			param, params = params[:i], params[i + 1:]
		} else {
			param, params = params, ""
		}
		param = trim_ows(param)
		eq := strings.index_byte(param, '=')
		if eq <= 0 || !ascii_equal_fold(param[:eq], "boundary") { continue }
		boundary = param[eq + 1:]
		if len(boundary) >= 2 && boundary[0] == '"' && boundary[len(boundary) - 1] == '"' {
			boundary = boundary[1:len(boundary) - 1]
		}
		(len(boundary) >= 1 && len(boundary) <= 70) or_return
		for c in transmute([]byte)boundary {
			switch c {
			case '0' ..= '9', 'a' ..= 'z', 'A' ..= 'Z', '\'', '(', ')', '+', '_', ',', '-', '.', '/', ':', '=', '?', ' ':
			case: return
			}
		}
		// A trailing space isn't allowed (RFC 2046).
		(boundary[len(boundary) - 1] != ' ') or_return
		return boundary, true
	}
	return
}

// --- Streaming, on top of `body_stream` ---

@(private)
Multipart_Stream :: struct {
	req:           ^Request,
	cb:            Multipart_Callback,
	user_data:     rawptr,
	p:             Multipart_Parser,
	body_err:      Body_Error,
	// `body_stream_next` was called, `multipart_on_piece` carries on with the piece.
	waiting_input: bool,
	// `multipart_drive` is on the stack.
	driving:       bool,
	in_cb:         bool,
	want_next:     bool,
	finished:      bool,
}

@(private="file")
multipart_on_piece :: proc(m: rawptr, data: []byte, done: bool, err: Body_Error) {
	m := (^Multipart_Stream)(m)
	m.waiting_input = false
	if err != nil {
		m.body_err = err
	} else {
		multipart_parser_input(&m.p, data, done)
	}
	if !m.driving { multipart_drive(m) }
}

/*
Hands events to the callback, in a loop (like `stream_drive`): a callback that asks for the next
event right away doesn't nest a call per event. After `.Done` `m` may be freed already.
*/
@(private="file")
multipart_drive :: proc(m: ^Multipart_Stream) {
	m.driving = true
	for !m.waiting_input {
		ev:   Multipart_Step
		data: []byte
		err:  Multipart_Error
		if m.body_err != nil {
			ev = .Done
			switch e in m.body_err {
			case io.Error:                  err = e
			case bufio.Scanner_Extra_Error: err = e
			}
		} else {
			ev, data, err = multipart_parser_step(&m.p)
		}

		if ev == .Need_Input {
			m.waiting_input = true
			// Delivers right away when it has data buffered, `multipart_on_piece` only stores it then.
			body_stream_next(m.req)
			continue
		}

		if ev == .Done { m.finished = true }
		m.in_cb     = true
		m.want_next = false
		m.cb(m.user_data, Multipart_Event(ev), &m.p.part, data, err)
		if ev == .Done { return }
		m.in_cb = false
		if !m.want_next { break }
	}
	m.driving = false
}

// --- The parser, over input in pieces ---

@(private)
Multipart_Step :: enum u8 {
	Part,
	Data,
	Part_End,
	Done,
	// The input is used up, give it the next piece (`multipart_parser_input`).
	Need_Input,
}

@(private)
Multipart_State :: enum u8 {
	// Before the first delimiter, discarded.
	Preamble,
	// After a delimiter: "--" (the end) or CRLF (a part follows).
	Delimiter_Tail,
	Headers,
	Data,
	// After the closing delimiter, discarded.
	Epilogue,
	Finished,
}

@(private)
Multipart_Parser :: struct {
	opts:         Multipart_Opts,
	allocator:    runtime.Allocator,
	// "\r\n--" boundary.
	delim:        string,
	state:        Multipart_State,

	input:        []byte,
	// The input is the last there is.
	input_last:   bool,

	// The end of earlier input that may be the start of a delimiter, kept until more input tells:
	// carry[c0:c1].
	carry:        [80]byte,
	c0, c1:       int,
	// The carry and the start of the input, to look for a delimiter across them.
	scratch:      [160]byte,
	// The content before a delimiter was delivered, the part's end is next.
	pending_end:  bool,

	// After a delimiter: a dash seen (of the closing "--"), CR seen, whitespace skipped.
	tail_dash:    bool,
	tail_cr:      bool,
	tail_ws:      int,

	// The current header line, and what the part's header section used so far.
	line:         [dynamic]byte,
	header_bytes: int,
	header_count: int,

	parts:        int,
	part:         Multipart_Part,
}

@(private)
multipart_parser_init :: proc(p: ^Multipart_Parser, boundary: string, opts: Multipart_Opts, allocator: runtime.Allocator) {
	p.opts = opts
	if p.opts.max_parts <= 0       { p.opts.max_parts       = Default_Multipart_Opts.max_parts }
	if p.opts.max_header_size <= 0 { p.opts.max_header_size = Default_Multipart_Opts.max_header_size }
	if p.opts.max_headers <= 0     { p.opts.max_headers     = Default_Multipart_Opts.max_headers }
	p.allocator      = allocator
	p.delim          = strings.concatenate({"\r\n--", boundary}, allocator)
	p.line.allocator = allocator
	assert(len(p.delim) < len(p.carry))

	// The first delimiter may be right at the start, without the CRLF before it: as if there was one.
	p.carry[0], p.carry[1] = '\r', '\n'
	p.c0, p.c1 = 0, 2
}

@(private)
multipart_parser_input :: proc(p: ^Multipart_Parser, data: []byte, last: bool) {
	assert(len(p.input) == 0)
	p.input      = data
	p.input_last = last
}

/*
Parses until there is something to deliver: the next event, its data for `.Data` (valid until the
next step), the error with `.Done`.
*/
@(private)
multipart_parser_step :: proc(p: ^Multipart_Parser) -> (ev: Multipart_Step, data: []byte, err: Multipart_Error) {
	fail :: proc(p: ^Multipart_Parser, err: Multipart_Parse_Error) -> (Multipart_Step, []byte, Multipart_Error) {
		p.state = .Finished
		return .Done, nil, err
	}
	// Out of input: wait for more, or it ended too early.
	out_of_input :: proc(p: ^Multipart_Parser) -> (Multipart_Step, []byte, Multipart_Error) {
		if p.input_last { return fail(p, .Malformed) }
		return .Need_Input, nil, nil
	}

	for {
		switch p.state {
		case .Finished:
			return .Done, nil, nil

		case .Preamble, .Data:
			if p.pending_end {
				p.pending_end = false
				p.state = .Delimiter_Tail
				return .Part_End, nil, nil
			}
			content, found, need := multipart_scan(p)
			if p.state == .Data && len(content) > 0 {
				p.pending_end = found
				return .Data, content, nil
			}
			if found {
				if p.state == .Data {
					p.state = .Delimiter_Tail
					return .Part_End, nil, nil
				}
				p.state = .Delimiter_Tail
			} else if need {
				return out_of_input(p)
			}

		case .Delimiter_Tail:
			if len(p.input) == 0 { return out_of_input(p) }
			b := p.input[0]
			p.input = p.input[1:]
			switch {
			case p.tail_dash:
				if b != '-' { return fail(p, .Malformed) }
				p.tail_dash = false
				p.state = .Epilogue
			case p.tail_cr:
				if b != '\n' { return fail(p, .Malformed) }
				p.tail_cr = false
				p.tail_ws = 0
				p.parts  += 1
				if p.parts > p.opts.max_parts { return fail(p, .Too_Many_Parts) }
				p.part = {}
				headers_init(&p.part.headers, p.allocator)
				p.header_bytes, p.header_count = 0, 0
				clear(&p.line)
				p.state = .Headers
			case b == '-' && p.tail_ws == 0:
				p.tail_dash = true
			case b == '\r':
				p.tail_cr = true
			case (b == ' ' || b == '\t') && p.tail_ws < 256:
				// Transport padding (RFC 2046 5.1.1).
				p.tail_ws += 1
			case:
				return fail(p, .Malformed)
			}

		case .Headers:
			if len(p.input) == 0 { return out_of_input(p) }
			nl := bytes.index_byte(p.input, '\n')
			chunk := p.input[:nl + 1] if nl >= 0 else p.input
			p.header_bytes += len(chunk)
			if p.header_bytes > p.opts.max_header_size { return fail(p, .Headers_Too_Large) }
			append(&p.line, ..chunk)
			p.input = p.input[len(chunk):]
			if nl < 0 { continue }

			line := p.line[:]
			if len(line) < 2 || line[len(line) - 2] != '\r' { return fail(p, .Malformed) }
			line = line[:len(line) - 2]
			clear(&p.line)

			if len(line) == 0 {
				// The end of the part's headers.
				if !multipart_part_finish(&p.part) { return fail(p, .Malformed) }
				p.state = .Data
				return .Part, nil, nil
			}
			p.header_count += 1
			if p.header_count > p.opts.max_headers { return fail(p, .Headers_Too_Large) }
			if _, ok := header_parse(&p.part.headers, string(line), p.allocator); !ok {
				return fail(p, .Malformed)
			}

		case .Epilogue:
			p.input = p.input[len(p.input):]
			if p.input_last {
				p.state = .Finished
				return .Done, nil, nil
			}
			return .Need_Input, nil, nil
		}
	}
}

/*
Looks for the next delimiter. Returns the content before it, or as much content as is certain
(the end of the input may be the start of a delimiter: that's kept back in `carry`). `found` when
the delimiter itself was consumed (right after `content`), `need` when the input is used up.
*/
@(private="file")
multipart_scan :: proc(p: ^Multipart_Parser) -> (content: []byte, found: bool, need: bool) {
	d := p.delim

	if p.c1 > p.c0 {
		carry := p.carry[p.c0:p.c1]
		n := copy(p.scratch[:], carry)
		n += copy(p.scratch[n:], p.input[:min(len(p.input), len(d))])
		window := p.scratch[:n]

		for k in 0 ..< len(carry) {
			rest := window[k:]
			m := min(len(rest), len(d))
			if string(rest[:m]) != d[:m] { continue }
			if k > 0 {
				// What comes before is content (delivered from the carry, which stays as it is
				// until the next step).
				content = p.carry[p.c0:p.c0 + k]
				p.c0 += k
				return
			}
			if m == len(d) {
				// A delimiter starting in the carry, ending in the input.
				p.input = p.input[len(d) - len(carry):]
				p.c0, p.c1 = 0, 0
				found = true
				return
			}
			// Still maybe a delimiter, all of the input is part of it: keep it too.
			copy(p.carry[:], carry)
			p.c0, p.c1 = 0, len(carry)
			p.c1 += copy(p.carry[p.c1:], p.input)
			p.input = p.input[len(p.input):]
			need = true
			return
		}
		// Not a delimiter after all, content.
		content = carry
		p.c0, p.c1 = 0, 0
		return
	}

	if len(p.input) == 0 {
		need = true
		return
	}
	if i := bytes.index(p.input, transmute([]byte)d); i >= 0 {
		if i > 0 {
			content = p.input[:i]
			p.input = p.input[i:]
			return
		}
		p.input = p.input[len(d):]
		found = true
		return
	}

	// The end of the input may be the start of a delimiter: keep that back.
	keep := 0
	for k := max(0, len(p.input) - len(d) + 1); k < len(p.input); k += 1 {
		if string(p.input[k:]) == d[:len(p.input) - k] {
			keep = len(p.input) - k
			break
		}
	}
	if keep < len(p.input) {
		content = p.input[:len(p.input) - keep]
		p.input = p.input[len(p.input) - keep:]
		return
	}
	p.c0, p.c1 = 0, copy(p.carry[:], p.input)
	p.input = p.input[len(p.input):]
	need = true
	return
}

// Fills in the name, filename and content type from the headers (RFC 7578 4.2, 4.4).
@(private="file")
multipart_part_finish :: proc(part: ^Multipart_Part) -> bool {
	part.headers.readonly = true
	part.content_type = headers_get_unsafe(part.headers, "content-type") or_else "text/plain"

	cd := headers_get_unsafe(part.headers, "content-disposition") or_return
	semi := strings.index_byte(cd, ';')
	(semi > 0 && ascii_equal_fold(trim_ows(cd[:semi]), "form-data")) or_return

	has_name: bool
	rest := cd[semi + 1:]
	for {
		rest = trim_ows(rest)
		if len(rest) == 0 { break }
		eq := strings.index_byte(rest, '=')
		(eq > 0) or_return
		key := trim_ows(rest[:eq])
		rest = trim_ows(rest[eq + 1:])

		value: string
		if len(rest) > 0 && rest[0] == '"' {
			// Quoted. Browsers percent-encode '"' (and CR, LF) in names and filenames, and don't
			// escape backslashes, so there are no escapes to undo: up to the next quote.
			end := strings.index_byte(rest[1:], '"')
			(end >= 0) or_return
			value = rest[1:end + 1]
			rest = rest[end + 2:]
		} else {
			end := strings.index_byte(rest, ';')
			if end < 0 { end = len(rest) }
			value = trim_ows(rest[:end])
			rest = rest[end:]
		}
		rest = trim_ows(rest)
		if len(rest) > 0 {
			(rest[0] == ';') or_return
			rest = rest[1:]
		}

		switch {
		case ascii_equal_fold(key, "name"):
			part.name = value
			has_name = true
		case ascii_equal_fold(key, "filename"):
			part.filename = value
		}
	}
	return has_name
}
