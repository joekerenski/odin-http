// WebSocket server connections on top of the HTTP server.
//
// Usage, inside an HTTP handler:
//
//	websocket.upgrade(req, res, {}, {
//		on_message = proc(c: ^websocket.Conn, kind: websocket.Message_Kind, data: []byte) {
//			websocket.send(c, kind, data) // echo
//		},
//	})
package websocket

import "core:crypto/legacy/sha1"
import "core:encoding/base64"
import "core:log"
import "core:strings"

import http ".."

@(private)
GUID :: "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

// Accepts every Origin, for `Opts.check_origin` (only for APIs that don't rely on cookies/ambient auth).
allow_any_origin :: proc(_: ^http.Request, _: string) -> bool { return true }

// The default origin check: the Origin's host[:port] must equal the Host header.
same_origin :: proc(req: ^http.Request, origin: string) -> bool {
	host := http.headers_get(req.headers, "host") or_return
	i := strings.index(origin, "://")
	if i < 0 { return false }
	return http.ascii_equal_fold(origin[i + 3:], host)
}

/*
Validates the WebSocket handshake of `req` and, when valid, answers with 101 Switching Protocols and
takes over the connection. Otherwise an error response (400, 403 or 426) is sent.

Returns whether the upgrade was started. `on_close` is called in every case where `true` is returned.
*/
upgrade :: proc(req: ^http.Request, res: ^http.Response, opts: Opts, callbacks: Callbacks, allocator := context.allocator) -> bool {
	fail :: proc(res: ^http.Response, status: http.Status, why: string) -> bool {
		log.infof("websocket handshake rejected: %s", why)
		http.headers_set_close(&res.headers)
		http.respond(res, status)
		return false
	}

	rline := req.line.(http.Requestline)
	if rline.method != .Get || req.is_head { return fail(res, .Method_Not_Allowed, "not a GET") }
	if rline.version != {1, 1} { return fail(res, .Bad_Request, "not HTTP/1.1") }

	upgrade_hdr, _ := http.headers_get(req.headers, "upgrade")
	connection, _  := http.headers_get(req.headers, "connection")
	if !http.header_list_has_token(upgrade_hdr, "websocket") || !http.header_list_has_token(connection, "upgrade") {
		return fail(res, .Bad_Request, "missing Upgrade: websocket / Connection: upgrade")
	}

	if version, _ := http.headers_get(req.headers, "sec-websocket-version"); version != "13" {
		http.headers_set(&res.headers, "sec-websocket-version", "13")
		return fail(res, .Upgrade_Required, "unsupported Sec-WebSocket-Version")
	}

	key, _ := http.headers_get(req.headers, "sec-websocket-key")
	key = http.trim_ows(key)
	if decoded, err := base64.decode(key, allocator = context.temp_allocator); err != nil || len(decoded) != 16 {
		return fail(res, .Bad_Request, "invalid Sec-WebSocket-Key")
	}

	if origin, has_origin := http.headers_get(req.headers, "origin"); has_origin {
		check := opts.check_origin if opts.check_origin != nil else same_origin
		if !check(req, origin) { return fail(res, .Forbidden, "origin not allowed") }
	}

	c := new(Conn, allocator)
	conn_init(c, .Server, opts, callbacks, allocator)

	// Subprotocol: the first one the client offers that we support.
	if offered, has := http.headers_get(req.headers, "sec-websocket-protocol"); has && len(c._opts.subprotocols) > 0 {
		rest := offered
		pick: for raw_offer in strings.split_iterator(&rest, ",") {
			offer := http.trim_ows(raw_offer)
			for ours in c._opts.subprotocols {
				if offer == ours {
					c.subprotocol = ours
					break pick
				}
			}
		}
	}

	// Compression, when both sides want it.
	extensions_response: string
	if c._opts.compression {
		if offered, has := http.headers_get(req.headers, "sec-websocket-extensions"); has {
			if params, response, ok := server_negotiate_deflate(offered, context.temp_allocator); ok {
				if conn_init_compression(c, params) {
					extensions_response = response
				} else {
					log.error("websocket: could not set up compression, continuing without")
				}
			}
		}
	}

	accept := accept_key(key, context.temp_allocator)

	res.status = .Switching_Protocols
	http.headers_set(&res.headers, "upgrade", "websocket")
	http.headers_set(&res.headers, "connection", "Upgrade")
	http.headers_set(&res.headers, "sec-websocket-accept", accept)
	if c.subprotocol != "" {
		http.headers_set(&res.headers, "sec-websocket-protocol", c.subprotocol)
	}
	if extensions_response != "" {
		http.headers_set(&res.headers, "sec-websocket-extensions", extensions_response)
	}

	http.response_hijack(res, c, on_hijacked, on_server_shutdown)
	return true
}

// Sec-WebSocket-Accept for a Sec-WebSocket-Key: base64(sha1(key + GUID)).
accept_key :: proc(key: string, allocator := context.allocator) -> string {
	ctx: sha1.Context
	sha1.init(&ctx)
	sha1.update(&ctx, transmute([]byte)key)
	sha1.update(&ctx, transmute([]byte)string(GUID))
	digest: [sha1.DIGEST_SIZE]byte
	sha1.final(&ctx, digest[:])
	accept, _ := base64.encode(digest[:], allocator = allocator)
	return accept
}

@(private)
on_hijacked :: proc(user: rawptr, h: http.Hijacked, buffered: []byte, ok: bool) {
	c := (^Conn)(user)
	if !ok {
		c.state = .Closed
		c._finalized = true
		if c._cb.on_close != nil { c._cb.on_close(c, u16(Close_Code.Abnormal), "") }
		conn_destroy_compression(c)
		free(c, c._allocator)
		return
	}

	c._h = h
	c._socket = h.socket
	c._temp = http.hijacked_temp_allocator(h)
	// An HTTPS server hands its TLS session over: reads and writes go through it from now on.
	if h.tls.ssl != nil { tls_adopt(c, h.tls.ssl, h.tls.rbio, h.tls.wbio) }
	c._release = proc(c: ^Conn) {
		tls_destroy(c)
		http.hijacked_close(c._h)
	}
	if c._write_timeout == 0 {
		c._write_timeout = http.hijacked_server_opts(h).write_timeout
	}
	conn_open(c, buffered)
}

@(private)
on_server_shutdown :: proc(user: rawptr) {
	c := (^Conn)(user)
	close(c, .Going_Away, "server shutting down")
}
