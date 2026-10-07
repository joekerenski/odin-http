package http

import "core:net"

Request :: struct {
	// If in a handler, this is always there and never None.
	// TODO: we should not expose this as a maybe to package users.
	line:       Maybe(Requestline),

	// Is true if the request is actually a HEAD request. If `Server_Opts.redirect_head_to_get` is set,
	// line.method will be .Get. Either way, the server never sends a body in response to a HEAD request.
	is_head:    bool,

	headers:    Headers,
	// Trailer fields received after a chunked body. Only populated once the body has been read.
	// Kept separate from `headers` so a trailer can never override a header the request was routed on.
	trailers:   Headers,
	url:        URL,
	client:     net.Endpoint,
	// The request came in over TLS (the server's own, see `Server_Opts.tls`; behind a proxy like
	// Caddy this is false, the proxy speaks plain HTTP to the server).
	tls:        bool,

	// Route params/captures, in order, as received (not percent-decoded). See `url_param`.
	url_params: []string,
	_route:     ^Route,

	// Internal usage only.
	_scanner:         ^Scanner,
	_body_ok:         Maybe(bool),
	_framing:         Body_Framing,
	_content_length:  int,
	// The client sent `Expect: 100-continue` and we have not answered it yet.
	_expect_continue: bool,
	// The message framing was suspicious (e.g. both Transfer-Encoding and Content-Length),
	// close the connection after responding.
	_close_after:     bool,
}

Body_Framing :: enum u8 {
	None,
	Length,
	Chunked,
}

request_init :: proc(r: ^Request, allocator := context.allocator) {
	headers_init(&r.headers, allocator)
	headers_init(&r.trailers, allocator)
}

// Determines how the request body is delimited (RFC 9112 6) and validates the headers that
// influence it. Returns the status to respond with when the request has to be rejected; such a
// response must always close the connection.
@(private)
request_prepare :: proc(req: ^Request, opts: Server_Opts) -> (reject: Status, ok: bool) {
	rline := req.line.(Requestline)

	// RFC 9112 3.2: A server MUST respond with a 400 (Bad Request) status code to any
	// HTTP/1.1 request message that lacks a Host header field.
	if rline.version == {1, 1} && !headers_has_unsafe(req.headers, "host") {
		return .Bad_Request, false
	}

	if te, has_te := headers_get_unsafe(req.headers, "transfer-encoding"); has_te {
		// RFC 9112 6.1: Transfer-Encoding was added in HTTP/1.1, a 1.0 message carrying it has
		// faulty framing.
		if rline.version == {1, 0} { return .Bad_Request, false }

		switch parse_transfer_encoding(te) {
		case .Invalid:     return .Bad_Request, false
		case .Unsupported: return .Not_Implemented, false
		case .Chunked:
		}
		req._framing = .Chunked

		// RFC 9112 6.1: Transfer-Encoding overrides Content-Length. Such a message might indicate an
		// attempt at request smuggling, so the connection is closed after responding.
		if headers_has_unsafe(req.headers, "content-length") {
			headers_delete_unsafe(&req.headers, "content-length")
			req._close_after = true
		}
	} else if cl, has_cl := headers_get_unsafe(req.headers, "content-length"); has_cl {
		n, cl_ok := parse_content_length(cl)
		if !cl_ok { return .Bad_Request, false }
		if n > 0 {
			req._framing = .Length
			req._content_length = n
		}
	}

	if expect, has_expect := headers_get_unsafe(req.headers, "expect"); has_expect {
		// RFC 9110 10.1.1: 100-continue is the only expectation defined.
		if !ascii_equal_fold(expect, "100-continue") { return .Expectation_Failed, false }

		// A 1.0 client can't understand a 100 response, and without a body there's nothing to wait for.
		if rline.version == {1, 1} && req._framing != .None && opts.auto_expect_continue {
			req._expect_continue = true
		}
	}

	return nil, true
}

// Validates the headers of a request, from the pov of the server.
headers_validate_for_server :: proc(headers: ^Headers) -> bool {
	if !headers_has_unsafe(headers^, "host") {
		return false
	}

	return headers_validate(headers)
}

// Validates the framing headers of a message: a Transfer-Encoding must be a list ending in a single
// "chunked", and when it is present a Content-Length is removed. Content-Length must be a number.
headers_validate :: proc(headers: ^Headers) -> bool {
	if enc_header, ok := headers_get_unsafe(headers^, "transfer-encoding"); ok {
		(parse_transfer_encoding(enc_header) == .Chunked) or_return

		if headers_has_unsafe(headers^, "content-length") {
			headers_delete_unsafe(headers, "content-length")
		}
	} else if cl, has_cl := headers_get_unsafe(headers^, "content-length"); has_cl {
		_ = parse_content_length(cl) or_return
	}

	return true
}
