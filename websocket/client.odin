// WebSocket client connections, ws:// and wss:// (TLS through the system's OpenSSL, the server's
// certificate and host name are always verified).
//
// Usage, on a thread that runs an nbio event loop (e.g. inside an HTTP handler or a timer, or
// after `nbio.acquire_thread_event_loop` with your own `nbio.tick` loop):
//
//	c, err := websocket.dial("wss://example.com/chat", {}, {
//		on_open    = proc(c: ^websocket.Conn) { websocket.send_text(c, "hi") },
//		on_message = proc(c: ^websocket.Conn, kind: websocket.Message_Kind, data: []byte) { ... },
//		on_close   = proc(c: ^websocket.Conn, code: u16, reason: string) { ... },
//	})
package websocket

import "core:encoding/base64"
import "core:crypto"
import "core:fmt"
import "core:log"
import "core:mem/virtual"
import "core:nbio"
import "core:net"
import "core:strings"
import "core:time"

import http ".."
import "../openssl"

Dial_Opts :: struct {
	// Connection options; `check_origin` doesn't apply to clients.
	using opts: Opts,
	// Extra request headers, e.g. Origin or Authorization.
	headers:    []Dial_Header,
	// Connect + handshake, defaults to 10s.
	timeout:    time.Duration,
	// wss://: a PEM file with the CA certificates to trust instead of the system's (e.g. a private
	// CA). Verification can't be turned off.
	tls_ca_file: string,
}

Dial_Header :: struct {
	name, value: string,
}

Dial_Error :: enum u8 {
	None,
	// Not a ws:// or wss:// URL with a host.
	Invalid_URL,
	// The host name could not be resolved (resolution is blocking).
	Resolve_Failed,
	// wss://: OpenSSL could not be set up, e.g. `tls_ca_file` couldn't be loaded.
	TLS_Setup_Failed,
}

// Largest handshake response head accepted.
@(private)
MAX_RESPONSE_HEAD :: 16 * 1024

@(private)
Client_State :: struct {
	arena:    virtual.Arena,
	key:      string,
	request:  string,
	head:     [dynamic]byte,
	deadline: time.Time,
	offered_compression: bool,
	// Set when the handshake failed while TLS I/O was still in flight, see `handshake_failed`.
	failing:  string,
}

/*
Opens a WebSocket connection to `url` (ws:// or wss://host[:port][/path][?query]). Returns right away: the
connection is `.Connecting`, `on_open` is called once the handshake succeeded, `on_close` (1006,
with the reason) if it failed. An error is returned (and no callback is called) when the URL is
invalid or the host can't be resolved. Name resolution is blocking.

The connection lives on the calling thread's event loop.
*/
dial :: proc(url: string, opts: Dial_Opts, callbacks: Callbacks, allocator := context.allocator) -> (c: ^Conn, err: Dial_Error) {
	target := parse_ws_url(url) or_return

	ep4, ep6, resolve_err := net.resolve(target.host_port)
	if resolve_err != nil { return nil, .Resolve_Failed }
	endpoint := ep4 if ep4 != {} else ep6
	if endpoint == {} { return nil, .Resolve_Failed }

	ctx: ^openssl.SSL_CTX
	if target.tls {
		ctx = openssl.client_ctx(opts.tls_ca_file)
		if ctx == nil {
			log.warnf("websocket: TLS setup failed: %s", openssl.error_string())
			return nil, .TLS_Setup_Failed
		}
	}
	// The connection's SSL keeps its own reference.
	defer if ctx != nil { openssl.SSL_CTX_free(ctx) }

	c = new(Conn, allocator)
	conn_init(c, .Client, opts.opts, callbacks, allocator)
	if target.tls && !tls_init(c, ctx, target.host, target.is_ip) {
		conn_destroy_compression(c)
		free(c, allocator)
		return nil, .TLS_Setup_Failed
	}
	if c._write_timeout == 0 { c._write_timeout = 30 * time.Second }
	c.state = .Connecting

	cs := new(Client_State, allocator)
	c._client = cs
	_ = virtual.arena_init_growing(&cs.arena)
	c._temp = virtual.arena_allocator(&cs.arena)
	cs.head.allocator = allocator
	cs.deadline = time.time_add(nbio.now(), opts.timeout if opts.timeout > 0 else 10 * time.Second)

	nonce: [16]byte
	crypto.rand_bytes(nonce[:])
	cs.key, _ = base64.encode(nonce[:], allocator = allocator)

	sb := strings.builder_make(allocator)
	fmt.sbprintf(&sb, "GET %s HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n", target.path, target.host_header)
	fmt.sbprintf(&sb, "Sec-WebSocket-Key: %s\r\nSec-WebSocket-Version: 13\r\n", cs.key)
	if len(c._opts.subprotocols) > 0 {
		strings.write_string(&sb, "Sec-WebSocket-Protocol: ")
		for p, i in c._opts.subprotocols {
			if i > 0 { strings.write_string(&sb, ", ") }
			strings.write_string(&sb, p)
		}
		strings.write_string(&sb, "\r\n")
	}
	if c._opts.compression {
		cs.offered_compression = true
		fmt.sbprintf(&sb, "Sec-WebSocket-Extensions: %s\r\n", CLIENT_DEFLATE_OFFER)
	}
	for h in opts.headers {
		fmt.sbprintf(&sb, "%s: %s\r\n", h.name, h.value)
	}
	strings.write_string(&sb, "\r\n")
	cs.request = strings.to_string(sb)

	nbio.dial_poly(endpoint, c, on_dialed, timeout = handshake_time_left(c))
	return c, .None
}

@(private)
Ws_URL :: struct {
	host_port:   string, // For resolving, always with a port.
	host_header: string,
	path:        string,
	tls:         bool,
	// For TLS: the name (or address) the certificate must be for, without brackets or port.
	host:        string,
	is_ip:       bool,
}

@(private)
parse_ws_url :: proc(url: string) -> (u: Ws_URL, err: Dial_Error) {
	rest: string
	switch {
	case len(url) >= 5 && http.ascii_equal_fold(url[:5], "ws://"):
		rest = url[5:]
	case len(url) >= 6 && http.ascii_equal_fold(url[:6], "wss://"):
		rest = url[6:]
		u.tls = true
	case:
		return {}, .Invalid_URL
	}

	end := len(rest)
	for ch, i in rest {
		if ch == '/' || ch == '?' || ch == '#' { end = i; break }
	}
	authority := rest[:end]
	u.path = rest[end:]
	if hash := strings.index_byte(u.path, '#'); hash >= 0 { u.path = u.path[:hash] }
	if u.path == "" || u.path[0] == '?' { u.path = strings.concatenate({"/", u.path}, context.temp_allocator) }
	if authority == "" || strings.contains_rune(authority, '@') { return {}, .Invalid_URL }
	for ch in u.path {
		if ch <= ' ' || ch == 0x7F { return {}, .Invalid_URL }
	}

	u.host_header = authority
	// A port is there if the last ':' comes after an IPv6 literal's ']'.
	has_port := false
	u.host = authority
	if colon := strings.last_index_byte(authority, ':'); colon >= 0 {
		has_port = colon > strings.last_index_byte(authority, ']')
		if has_port && colon == len(authority) - 1 { return {}, .Invalid_URL }
		if has_port { u.host = authority[:colon] }
	}
	if len(u.host) >= 2 && u.host[0] == '[' && u.host[len(u.host) - 1] == ']' {
		u.host = u.host[1:len(u.host) - 1]
		u.is_ip = true
	} else if _, ok := net.parse_ip4_address(u.host); ok {
		u.is_ip = true
	}
	if u.host == "" { return {}, .Invalid_URL }
	u.host_port = authority if has_port else strings.concatenate({authority, ":443" if u.tls else ":80"}, context.temp_allocator)
	return u, .None
}

@(private)
handshake_time_left :: proc(c: ^Conn) -> time.Duration {
	return max(time.diff(nbio.now(), c._client.deadline), time.Millisecond)
}

@(private)
on_dialed :: proc(op: ^nbio.Operation, c: ^Conn) {
	if op.dial.err != nil {
		handshake_failed(c, fmt.tprintf("connect failed: %v", op.dial.err))
		return
	}
	c._socket = op.dial.socket
	if c._tls != nil {
		tls_handshake(c, proc(c: ^Conn, why: string) {
			if why != "" {
				handshake_failed(c, why)
				return
			}
			send_request(c)
		})
		return
	}
	send_request(c)
}

@(private)
send_request :: proc(c: ^Conn) {
	transport_send(c, {transmute([]byte)c._client.request}, handshake_time_left(c), on_request_sent, all = true)
}

@(private)
on_request_sent :: proc(c: ^Conn, _: int, err: IO_Error) {
	if err != .None {
		handshake_failed(c, fmt.tprintf("sending the handshake failed: %v", err))
		return
	}
	recv_head(c)
}

@(private)
recv_head :: proc(c: ^Conn) {
	cs := c._client
	if cap(cs.head) - len(cs.head) < 1024 { reserve(&cs.head, len(cs.head) + 4096) }
	spare := ([^]byte)(raw_data(cs.head))[len(cs.head):cap(cs.head)]
	transport_recv(c, spare, handshake_time_left(c), on_head_recv)
}

@(private)
on_head_recv :: proc(c: ^Conn, received: int, err: IO_Error) {
	cs := c._client
	if err == .Closed {
		handshake_failed(c, "the server closed the connection during the handshake")
		return
	}
	if err != .None {
		handshake_failed(c, fmt.tprintf("reading the handshake response failed: %v", err))
		return
	}
	non_zero_resize(&cs.head, len(cs.head) + received)

	end := strings.index(string(cs.head[:]), "\r\n\r\n")
	if end < 0 {
		if len(cs.head) > MAX_RESPONSE_HEAD {
			handshake_failed(c, "handshake response head too large")
			return
		}
		recv_head(c)
		return
	}

	context.temp_allocator = c._temp
	if why := check_handshake_response(c, string(cs.head[:end + 2])); why != "" {
		handshake_failed(c, why)
		return
	}

	// Done: hand over to the connection, with whatever the server already sent after the head.
	// (Nothing may touch `c` or `cs` after `conn_open`, it can finish and free the connection.)
	append(&c._rbuf, ..cs.head[end + 4:])
	delete(cs.head)
	cs.head = {}
	c._release = client_release
	conn_open(c, nil)
}

// Validates the 101 response (head without the final empty line), "" when it's fine.
@(private)
check_handshake_response :: proc(c: ^Conn, head: string) -> (why: string) {
	rest := head
	status_line, _ := strings.split_iterator(&rest, "\r\n")
	if !strings.has_prefix(status_line, "HTTP/1.1 101") || (len(status_line) > 12 && status_line[12] != ' ') {
		return fmt.tprintf("expected 101 Switching Protocols, got %q", status_line[:min(len(status_line), 80)])
	}

	// Header values by lower-case name, repeated headers joined with ", ".
	headers := make(map[string]string, 16, context.temp_allocator)
	for line in strings.split_iterator(&rest, "\r\n") {
		colon := strings.index_byte(line, ':')
		if colon <= 0 { return "malformed header line in the handshake response" }
		name := strings.to_lower(http.trim_ows(line[:colon]), context.temp_allocator)
		value := http.trim_ows(line[colon + 1:])
		if prev, ok := headers[name]; ok {
			headers[name] = strings.concatenate({prev, ", ", value}, context.temp_allocator)
		} else {
			headers[name] = value
		}
	}

	if !http.header_list_has_token(headers["upgrade"], "websocket") { return "missing Upgrade: websocket" }
	if !http.header_list_has_token(headers["connection"], "upgrade") { return "missing Connection: Upgrade" }
	if headers["sec-websocket-accept"] != accept_key(c._client.key, context.temp_allocator) {
		return "wrong Sec-WebSocket-Accept"
	}

	if protocol, has := headers["sec-websocket-protocol"]; has {
		found := false
		for p in c._opts.subprotocols {
			if p == protocol {
				c.subprotocol = p
				found = true
				break
			}
		}
		if !found { return fmt.tprintf("the server picked a subprotocol we didn't offer: %q", protocol) }
	}

	if extensions, has := headers["sec-websocket-extensions"]; has {
		if !c._client.offered_compression { return "the server enabled an extension we didn't offer" }
		params, present, ok := client_accept_deflate(extensions)
		if !ok { return fmt.tprintf("invalid or unsupported extension response: %q", extensions) }
		if present && !conn_init_compression(c, params) { return "could not set up compression" }
	}
	return ""
}

// The handshake failed: the connection never opened.
@(private)
handshake_failed :: proc(c: ^Conn, reason: string) {
	if transport_busy(c) {
		// TLS I/O is in flight: fail it, the last completion comes back here.
		if c._client.failing == "" { c._client.failing = strings.clone(reason, virtual.arena_allocator(&c._client.arena)) }
		net.shutdown(c._socket, .Both)
		return
	}
	c.state = .Closed
	c._finalized = true
	context.temp_allocator = c._temp
	if c._cb.on_close != nil { c._cb.on_close(c, u16(Close_Code.Abnormal), reason) }
	conn_destroy_compression(c)
	client_release(c)
	free(c, c._allocator)
}

@(private)
client_release :: proc(c: ^Conn) {
	cs := c._client
	tls_destroy(c)
	if c._socket != 0 { net.close(c._socket) }
	virtual.arena_destroy(&cs.arena)
	delete(cs.key, c._allocator)
	delete(cs.request, c._allocator)
	delete(cs.head)
	free(cs, c._allocator)
}
