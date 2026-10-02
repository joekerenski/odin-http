package http

import "core:encoding/json"
import "core:fmt"
import "core:io"
import "core:log"
import "core:nbio"
import "core:net"
import "core:path/filepath"
import "core:strings"

// Sets the response to one that sends the given HTML.
respond_html :: proc(r: ^Response, html: string, status: Status = .OK, loc := #caller_location) {
	r.status = status
	headers_set_content_type(&r.headers, mime_to_content_type(Mime_Type.Html))
	body_set(r, html, loc)
	respond(r, loc)
}

// Sets the response to one that sends the given plain text.
respond_plain :: proc(r: ^Response, text: string, status: Status = .OK, loc := #caller_location) {
	r.status = status
	headers_set_content_type(&r.headers, mime_to_content_type(Mime_Type.Plain))
	body_set(r, text, loc)
	respond(r, loc)
}

/*
Sends the content of the file at the given path as the response.

The file is streamed with the platform's zero-copy `sendfile` where available (emulated otherwise),
nothing is buffered in memory. Single byte ranges (`Range: bytes=a-b`) are supported (206/416).

The content type is taken from the path, optionally overwritten using the parameter.

If the file doesn't exist, or isn't a regular file (directory, pipe, device...), a 404 is sent.
*/
respond_file :: proc(r: ^Response, path: string, content_type: Maybe(Mime_Type) = nil, loc := #caller_location) {
	assert_has_td(loc)
	assert(!r.sent, "response has already been sent", loc)

	// A NUL would truncate the path when it's handed to the OS, while the content type is derived
	// from the full string.
	if strings.index_byte(path, 0) >= 0 {
		respond_with_status(r, .Not_Found)
		return
	}

	mime := content_type.? or_else mime_from_extension(path)
	headers_set_content_type(&r.headers, mime_to_content_type(mime))

	nbio.open_poly(path, r, on_open)

	on_open :: proc(op: ^nbio.Operation, r: ^Response) {
		#partial switch op.open.err {
		case nil:
			nbio.stat_poly2(op.open.handle, op.open.path, r, on_stat)
		case .Not_Found:
			log.debugf("respond_file, open %q, no such file or directory", op.open.path)
			respond_with_status(r, .Not_Found)
		case:
			log.infof("respond_file, open %q error: %v", op.open.path, op.open.err)
			respond_with_status(r, .Not_Found)
		}
	}

	on_stat :: proc(op: ^nbio.Operation, path: string, r: ^Response) {
		if op.stat.err != nil || op.stat.type != .Regular {
			if op.stat.err != nil {
				log.warnf("respond_file, could not stat %q: %v", path, op.stat.err)
			}
			nbio.close(op.stat.handle)
			respond_with_status(r, .Not_Found)
			return
		}

		size := int(op.stat.size)
		start, length := 0, size
		r.status = .OK

		headers_set_unsafe(&r.headers, "accept-ranges", "bytes")
		headers_set_unsafe(&r.headers, "x-content-type-options", "nosniff")

		req := &r._conn.loop.req
		if range_value, has_range := headers_get_unsafe(req.headers, "range"); has_range && !headers_has_unsafe(req.headers, "if-range") {
			switch rstart, rlength, res := parse_range(range_value, size); res {
			case .None:
			case .Partial:
				start, length = rstart, rlength
				r.status = .Partial_Content
				headers_set_unsafe(&r.headers, "content-range", fmt.tprintf("bytes %i-%i/%i", start, start + length - 1, size))
			case .Unsatisfiable:
				nbio.close(op.stat.handle)
				headers_set_unsafe(&r.headers, "content-range", fmt.tprintf("bytes */%i", size))
				respond_with_status(r, .Range_Not_Satisfiable)
				return
			}
		}

		_response_write_heading(r, length)

		if length > 0 && !req.is_head {
			r._file = Response_File{handle = op.stat.handle, offset = start, length = length}
		} else {
			nbio.close(op.stat.handle)
		}
		respond(r)
	}
}

/*
Responds with the given content, determining content type from the given path.

This is very useful when you want to `#load(path)` at compile time and respond with that.
*/
respond_file_content :: proc(r: ^Response, path: string, content: []byte, status: Status = .OK, loc := #caller_location) {
	mime := mime_from_extension(path)
	content_type := mime_to_content_type(mime)

	r.status = status
	headers_set_content_type(&r.headers, content_type)
	body_set(r, content, loc)
	respond(r, loc)
}

/*
Sets the response to one that, based on the request path, returns a file.
base:    The base of the request path that should be removed when retrieving the file.
target:  The path to the directory to serve (relative to the working directory, or absolute).
request: The request path (as received, percent-encoded).

The part of the request path after `base` is percent-decoded and split into segments; a request is
refused (404) if `base` doesn't match whole path segments, or if any decoded segment is "..",
contains a NUL/control character, or a backslash. So the served file is always inside `target`.
Symbolic links inside `target` are followed.

A request for a directory serves its "index.html".

The Content-Type is set based on the file extension, see the Mime_Type enum for known file extensions.
*/
respond_dir :: proc(r: ^Response, base, target, request: string, loc := #caller_location) {
	file_path, ok := dir_resolve(base, target, request, context.temp_allocator)
	if !ok {
		respond(r, Status.Not_Found)
		return
	}
	respond_file(r, file_path, loc = loc)
}

// Maps a request path onto a file inside `target`, see `respond_dir`. Exposed for testing.
dir_resolve :: proc(base, target, request: string, allocator := context.temp_allocator) -> (file_path: string, ok: bool) {
	// The query and fragment are not part of the path.
	request := request
	if i := strings.index_any(request, "?#"); i >= 0 {
		request = request[:i]
	}

	base_path := strings.trim_right(base, "/")
	if !strings.has_prefix(request, base_path) { return }
	rest := request[len(base_path):]
	// "/static" must not match "/static../x" or "/staticfoo".
	if len(rest) > 0 && rest[0] != '/' { return }

	segments := make([dynamic]string, 0, 8, allocator)
	append(&segments, target)

	trailing_slash := len(rest) == 0 || rest[len(rest) - 1] == '/'
	for raw_seg in strings.split_iterator(&rest, "/") {
		if raw_seg == "" { continue }

		seg := net.percent_decode(raw_seg, allocator) or_return
		if seg == "." { continue }
		if seg == ".." { return }
		for i in 0 ..< len(seg) {
			c := seg[i]
			// Decoded slashes would re-introduce segments; backslashes are separators on Windows.
			if c < 0x20 || c == 0x7f || c == '/' || c == '\\' { return }
		}
		append(&segments, seg)
	}

	if trailing_slash || len(segments) == 1 {
		append(&segments, "index.html")
	}

	joined, err := filepath.join(segments[:], allocator)
	if err != nil { return }
	return joined, true
}

// Sets the response to one that returns the JSON representation of the given value.
respond_json :: proc(r: ^Response, v: any, status: Status = .OK, opt: json.Marshal_Options = {}, loc := #caller_location) -> (err: json.Marshal_Error) {
	opt := opt

	r.status = status
	headers_set_content_type(&r.headers, mime_to_content_type(Mime_Type.Json))

	// Going to write a MINIMUM of 128 bytes at a time.
	rw:  Response_Writer
	buf: [128]byte
	response_writer_init(&rw, r, buf[:])

	// Ends the body and sends the response.
	defer io.close(rw.w)

	if err = json.marshal_to_writer(rw.w, v, &opt); err != nil {
		headers_set_close(&r.headers)
		response_status(r, .Internal_Server_Error)
	}

	return
}

/*
Prefer the procedure group `respond`.
*/
respond_with_none :: proc(r: ^Response, loc := #caller_location) {
	assert_has_td(loc)

	response_send(r, r._conn, loc)
}

/*
Prefer the procedure group `respond`.
*/
respond_with_status :: proc(r: ^Response, status: Status, loc := #caller_location) {
	response_status(r, status)
	respond(r, loc)
}

// Sends the response back to the client, handlers should call this.
respond :: proc {
	respond_with_none,
	respond_with_status,
}
