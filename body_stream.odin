package http

import "core:bufio"
import "core:log"
import "core:mem/virtual"
import "core:nbio"
import "core:time"

/*
Gets a piece of a streamed request body, see `body_stream`.

`data` is the next part of the body, its framing (chunked encoding) removed, never empty except
on the last call. It stays valid until `body_stream_next` is called or the response is sent.

`done` is set on the last call, which may or may not carry data. Trailer fields (`req.trailers`)
are there by then.

On error `err` is set (and `done`): the body can't be read further, respond (see
`body_error_status`), the connection is closed after that.
*/
Body_Stream_Callback :: #type proc(user_data: rawptr, data: []byte, done: bool, err: Body_Error)

// The read buffer a streamed body goes through, per connection.
STREAM_BUF_SIZE :: 64 * 1024

/*
Reads the request body piece by piece as it arrives, instead of all at once like `body` does: for
bodies too large to hold in memory, or to process (store, hash, forward) while they come in.

`cb` gets the first piece. After that the server reads nothing more until `body_stream_next` is
called, which gets the next piece to `cb`. So the client can't send faster than the handler
processes (TCP flow control holds it back), and the memory used is the connection's read buffer
(`STREAM_BUF_SIZE`) whatever the body's size.

`max_length` limits the body's total size in bytes, -1 for no limit; a body over it gets `.Too_Long`
(a Content-Length over it before anything is read). `Server_Opts.max_body_size` doesn't apply: it
protects memory, which a stream doesn't use. Reads are bound by `Server_Opts.body_read_timeout` and
`body_min_rate`, the time the handler holds a piece doesn't count.

The handler may respond at any point, also before the body ended (to reject an upload): the server
then reads and discards up to `Max_Post_Handler_Discard_Bytes` of the rest, so the connection can be
reused, or closes it. `cb` isn't called anymore after responding.

If the client sent `Expect: 100-continue`, the interim 100 response is sent now, before reading.

Call it once per request (not together with `body`), and it and `body_stream_next` only on the
connection's thread: in the handler, in `cb`, or in a callback of the thread's event loop.

Example, a body written to a file as it arrives (error handling shortened):

	Upload :: struct { req: ^http.Request, res: ^http.Response, fd: nbio.Handle, offset: int }
	up := new(Upload, context.temp_allocator) // lives until the response is sent
	up^ = {req = req, res = res, fd = fd}
	http.body_stream(req, 10 * mem.Gigabyte, up, proc(up: rawptr, data: []byte, done: bool, err: http.Body_Error) {
		up := (^Upload)(up)
		if err != nil {
			http.respond(up.res, http.body_error_status(err))
			return
		}
		if len(data) == 0 { http.respond(up.res, http.Status.Created); return }
		nbio.write_poly2(up.fd, up.offset, data, up, done, proc(op: ^nbio.Operation, up: ^Upload, done: bool) {
			up.offset += op.write.written
			if done { http.respond(up.res, http.Status.Created); return }
			http.body_stream_next(up.req)
		}, all = true)
	})
*/
body_stream :: proc(req: ^Request, max_length: int, user_data: rawptr, cb: Body_Stream_Callback, loc := #caller_location) {
	assert(req._body_ok == nil, "you can only call body or body_stream once per request", loc)
	assert(cb != nil, "body_stream needs a callback", loc)

	conn := req._scanner.connection
	context.temp_allocator = virtual.arena_allocator(&conn.temp_allocator)

	st := new(Body_Stream, context.temp_allocator)
	st^ = {req = req, cb = cb, user_data = user_data, limit = max_length}
	req._stream  = st
	req._body_ok = false

	switch req._framing {
	case .None:
		stream_piece(st, nil, true, nil)
		return
	case .Length:
		if max_length >= 0 && req._content_length > max_length {
			stream_piece(st, nil, true, .Too_Long)
			return
		}
		st.phase     = .Data
		st.remaining = req._content_length
	case .Chunked:
		st.phase = .Chunk_Size
	}

	s := req._scanner
	if len(s.buf) < STREAM_BUF_SIZE {
		resize(&s.buf, STREAM_BUF_SIZE)
	}

	if !req._expect_continue {
		stream_start(st)
		return
	}

	CONTINUE :: "HTTP/1.1 100 Continue\r\n\r\n"
	req._expect_continue = false
	st.waiting = true
	conn.continue_state = st
	connection_send(conn, transmute([]byte)string(CONTINUE), proc(c: ^Connection, ok: bool) {
		context.temp_allocator = virtual.arena_allocator(&c.temp_allocator)
		st := (^Body_Stream)(c.continue_state)
		c.continue_state = nil
		st.waiting = false
		if !ok {
			stream_piece(st, nil, true, .Unknown)
			return
		}
		stream_start(st)
	})
}

/*
Gets the next piece of a streamed body to the callback given to `body_stream`. Does nothing once
the body ended or the response was sent.
*/
body_stream_next :: proc(req: ^Request) {
	st := req._stream
	if st == nil || st.finished || st.abandoned { return }
	if st.in_cb {
		st.want_next = true
		return
	}
	// Already reading (called twice for one piece).
	if st.waiting || st.driving { return }

	context.temp_allocator = virtual.arena_allocator(&req._scanner.connection.temp_allocator)
	scanner_pause_rate(req._scanner, time.diff(st.paused_at, nbio.now()))
	stream_scan(st)
}

@(private)
Body_Stream :: struct {
	req:                ^Request,
	cb:                 Body_Stream_Callback,
	user_data:          rawptr,
	// Total body size allowed, -1 for no limit.
	limit:              int,
	// Body bytes received so far.
	total:              int,
	phase:              Stream_Phase,
	// Bytes left of the body (Content-Length) or the current chunk.
	remaining:          int,
	trailer_bytes_left: int,
	trailer_count:      int,

	// A piece ready for the callback.
	piece:              struct { data: []byte, done: bool, err: Body_Error },
	has_piece:          bool,
	// A read (or the 100 Continue) is in flight.
	waiting:            bool,
	// `stream_drive` is on the stack, it delivers what `stream_on_scan` produces.
	driving:            bool,
	in_cb:              bool,
	// `body_stream_next` was called from the callback.
	want_next:          bool,
	// The last piece was produced.
	finished:           bool,
	// When the handler got the last piece, for `body_min_rate`.
	paused_at:          time.Time,

	// The handler responded before the body ended: the rest is discarded, then `res` is sent.
	abandoned:          bool,
	res:                ^Response,
}

@(private)
Stream_Phase :: enum u8 {
	Data,
	Chunk_Size,
	Chunk_End,
	Trailers,
}

@(private="file")
stream_start :: proc(st: ^Body_Stream) {
	scanner_start_rate(st.req._scanner, st.req._scanner.connection.server.opts.body_min_rate)
	stream_scan(st)
}

// Scans for what the current phase needs.
@(private="file")
stream_scan :: proc(st: ^Body_Stream) {
	s := st.req._scanner
	switch st.phase {
	case .Data:
		// Whatever is buffered (up to what's left), so the buffer never grows.
		s.split          = scan_available
		s.split_data     = rawptr(uintptr(st.remaining))
		s.max_token_size = len(s.buf)
	case .Chunk_Size, .Chunk_End:
		s.split          = scan_lines
		s.split_data     = nil
		s.max_token_size = MAX_CHUNK_LINE
	case .Trailers:
		s.split          = scan_lines
		s.split_data     = nil
		s.max_token_size = max(st.trailer_bytes_left, 1)
	}
	st.waiting = true
	scanner_scan(s, st, stream_on_scan)
}

@(private="file")
scan_available :: proc(split_data: rawptr, data: []byte, at_eof: bool) -> (advance: int, token: []byte, err: bufio.Scanner_Error, final_token: bool) {
	if len(data) == 0 { return }
	n := min(len(data), int(uintptr(split_data)))
	return n, data[:n], nil, false
}

@(private="file")
stream_on_scan :: proc(st: rawptr, token: string, err: bufio.Scanner_Error) {
	st := (^Body_Stream)(st)
	st.waiting = false

	if err != nil {
		// Lines that don't fit are malformed framing, not a body that's too long.
		stream_piece(st, nil, true, .Bad_Read_Count if err == .Too_Long && st.phase != .Data else err)
		return
	}

	switch st.phase {
	case .Data:
		st.remaining -= len(token)
		st.total     += len(token)
		if st.limit >= 0 && st.total > st.limit {
			stream_piece(st, nil, true, .Too_Long)
			return
		}
		done := false
		if st.remaining == 0 {
			if st.req._framing == .Length {
				done = true
			} else {
				// chunk-data is followed by CRLF.
				st.phase = .Chunk_End
			}
		}
		stream_piece(st, transmute([]byte)token, done, nil)

	case .Chunk_Size:
		size, ok := parse_chunk_size_line(token)
		if !ok {
			log.infof("Encountered an invalid chunk size when decoding a chunked body: %q", token)
			stream_piece(st, nil, true, .Bad_Read_Count)
			return
		}
		if size == 0 {
			st.phase              = .Trailers
			st.trailer_bytes_left = st.req._scanner.connection.server.opts.limit_headers
			stream_scan(st)
			return
		}
		if st.limit >= 0 && size > st.limit - st.total {
			stream_piece(st, nil, true, .Too_Long)
			return
		}
		st.phase     = .Data
		st.remaining = size
		stream_scan(st)

	case .Chunk_End:
		if len(token) != 0 {
			log.info("chunk data was not followed by CRLF")
			stream_piece(st, nil, true, .Bad_Read_Count)
			return
		}
		st.phase = .Chunk_Size
		stream_scan(st)

	case .Trailers:
		// Trailer section is done, so is the body.
		if len(token) == 0 {
			st.req.trailers.readonly = true
			stream_piece(st, nil, true, nil)
			return
		}
		if terr := _body_trailer_line(st.req, token, &st.trailer_bytes_left, &st.trailer_count); terr != nil {
			stream_piece(st, nil, true, terr)
			return
		}
		stream_scan(st)
	}
}

// A piece is ready: deliver it, unless a `stream_drive` up the stack will.
@(private="file")
stream_piece :: proc(st: ^Body_Stream, data: []byte, done: bool, err: Body_Error) {
	if done {
		st.finished     = true
		st.req._body_ok = err == nil
	}
	st.piece     = {data, done, err}
	st.has_piece = true
	if !st.driving {
		stream_drive(st)
	}
}

/*
Hands pieces to the callback, in a loop rather than recursively: a callback that asks for the next
piece right away, with more buffered, would otherwise nest a call per piece.

After the last piece (or the response, if the handler responded early) `st` may be freed already.
*/
@(private="file")
stream_drive :: proc(st: ^Body_Stream) {
	st.driving = true
	for st.has_piece {
		p := st.piece
		st.has_piece = false

		if st.abandoned {
			if p.done || !stream_discard(st) {
				response_send_decide(st.res)
				return
			}
			continue
		}

		st.want_next = false
		st.in_cb     = true
		st.paused_at = nbio.now()
		st.cb(st.user_data, p.data, p.done, p.err)
		if p.done { return }
		st.in_cb = false

		if st.abandoned {
			// Responded from the callback, discard the rest.
			if !stream_discard(st) {
				response_send_decide(st.res)
				return
			}
			continue
		}
		if !st.want_next { break }
		scanner_pause_rate(st.req._scanner, time.diff(st.paused_at, nbio.now()))
		stream_scan(st)
	}
	st.driving = false
}

/*
The handler responded while the body is still coming: read and discard (a reasonable amount of)
the rest before sending the response, or close. Returns false when the response can be sent right
away.
*/
@(private)
body_stream_abandon :: proc(st: ^Body_Stream, res: ^Response) -> (deferred: bool) {
	if st.finished { return false }

	st.abandoned = true
	st.res       = res
	st.limit     = st.total + Max_Post_Handler_Discard_Bytes

	// The callback (or the read in flight) carries on from here, see `stream_drive`.
	if st.in_cb || st.waiting { return true }

	return stream_discard(st)
}

// Reads the next bit to discard, unless it's clear already that there's too much left; then the
// response is sent with the connection closed after. Returns whether it's reading.
@(private="file")
stream_discard :: proc(st: ^Body_Stream) -> (reading: bool) {
	if st.req._framing == .Length && st.phase == .Data && st.total + st.remaining > st.limit {
		st.finished     = true
		st.req._body_ok = false
		return false
	}
	stream_scan(st)
	return true
}
