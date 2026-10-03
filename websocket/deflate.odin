// permessage-deflate (RFC 7692): extension negotiation and per-connection compression state.
package websocket

import "core:c"
import "core:strconv"
import "core:strings"

import zlib "vendor:zlib"

import http ".."

// Messages smaller than this are sent uncompressed (allowed per message), compression wouldn't pay off.
COMPRESS_MIN_SIZE :: 32

// What the client offered (server side) or the server agreed to (client side).
Deflate_Params :: struct {
	server_no_context_takeover: bool,
	client_no_context_takeover: bool,
	// LZ77 window of the server's / client's compressor, 8..15; 0 when not given (15).
	server_max_window_bits:     int,
	// -1: given without a value (only in a client's offer: "I can limit my window").
	client_max_window_bits:     int,
}

// The offer a client sends.
CLIENT_DEFLATE_OFFER :: "permessage-deflate; client_max_window_bits"

/*
Parses the parameters of one permessage-deflate element (the part after the extension name, e.g.
"; client_max_window_bits; server_no_context_takeover"). Unknown or duplicate parameters and bad
values make the element invalid (RFC 7692 7.1).
*/
parse_deflate_params :: proc(params: string) -> (p: Deflate_Params, ok: bool) {
	seen: bit_set[0 ..< 4]
	rest := params
	for raw in strings.split_iterator(&rest, ";") {
		param := http.trim_ows(raw)
		if param == "" { continue }

		name, value := param, ""
		has_value := false
		if i := strings.index_byte(param, '='); i >= 0 {
			name = http.trim_ows(param[:i])
			value = http.trim_ows(param[i + 1:])
			has_value = true
			if len(value) >= 2 && value[0] == '"' && value[len(value) - 1] == '"' {
				value = value[1:len(value) - 1]
			}
		}

		window_bits :: proc(v: string) -> (int, bool) {
			if len(v) == 0 || len(v) > 2 { return 0, false }
			for ch in v { if ch < '0' || ch > '9' { return 0, false } }
			n, _ := strconv.parse_int(v, 10)
			return n, n >= 8 && n <= 15
		}

		idx: int
		switch {
		case http.ascii_equal_fold(name, "server_no_context_takeover"):
			if has_value { return {}, false }
			idx = 0
			p.server_no_context_takeover = true
		case http.ascii_equal_fold(name, "client_no_context_takeover"):
			if has_value { return {}, false }
			idx = 1
			p.client_no_context_takeover = true
		case http.ascii_equal_fold(name, "server_max_window_bits"):
			idx = 2
			p.server_max_window_bits = window_bits(value) or_return
		case http.ascii_equal_fold(name, "client_max_window_bits"):
			idx = 3
			if has_value {
				p.client_max_window_bits = window_bits(value) or_return
			} else {
				p.client_max_window_bits = -1
			}
		case:
			return {}, false
		}
		if idx in seen { return {}, false }
		seen += {idx}
	}
	return p, true
}

/*
Server side: picks the first acceptable permessage-deflate offer from the client's
Sec-WebSocket-Extensions header. Returns the agreed parameters and the response header value.

Offers asking for an 8-bit server window are declined: zlib can't compress with a 256 byte
window (it silently uses 512), which a strict peer would reject.
*/
server_negotiate_deflate :: proc(header: string, allocator := context.allocator) -> (p: Deflate_Params, response: string, ok: bool) {
	rest := header
	for element in strings.split_iterator(&rest, ",") {
		name, params := element, ""
		if i := strings.index_byte(element, ';'); i >= 0 {
			name, params = element[:i], element[i:]
		}
		if !http.ascii_equal_fold(http.trim_ows(name), "permessage-deflate") { continue }

		offer := parse_deflate_params(params) or_continue
		if offer.server_max_window_bits == 8 { continue }

		p = offer
		// We don't limit the client's window (our decompressor uses the full 15 bits).
		p.client_max_window_bits = 0

		sb := strings.builder_make(allocator)
		strings.write_string(&sb, "permessage-deflate")
		if p.server_no_context_takeover { strings.write_string(&sb, "; server_no_context_takeover") }
		if p.client_no_context_takeover { strings.write_string(&sb, "; client_no_context_takeover") }
		if p.server_max_window_bits > 0 {
			strings.write_string(&sb, "; server_max_window_bits=")
			strings.write_int(&sb, p.server_max_window_bits)
		}
		return p, strings.to_string(sb), true
	}
	return {}, "", false
}

/*
Client side: validates the server's Sec-WebSocket-Extensions response to `CLIENT_DEFLATE_OFFER`.
`present` is false when the server didn't accept compression; `ok` is false when the response is
invalid (the connection must be failed).
*/
client_accept_deflate :: proc(header: string) -> (p: Deflate_Params, present: bool, ok: bool) {
	h := http.trim_ows(header)
	if h == "" { return {}, false, true }
	if strings.contains_rune(h, ',') { return {}, true, false } // More than one extension: we offered one.

	name, params := h, ""
	if i := strings.index_byte(h, ';'); i >= 0 {
		name, params = h[:i], h[i:]
	}
	if !http.ascii_equal_fold(http.trim_ows(name), "permessage-deflate") { return {}, true, false }

	valid: bool
	if p, valid = parse_deflate_params(params); !valid { return {}, true, false }
	// The server must give a value, and we can't compress with an 8-bit window (see above).
	if p.client_max_window_bits == -1 || p.client_max_window_bits == 8 { return {}, true, false }
	return p, true, true
}

// --- Compression state ---

@(private)
Deflater :: struct {
	strm:  zlib.z_stream,
	ready: bool,
	// Reset after every message (no_context_takeover for our side).
	reset: bool,
}

@(private)
Inflater :: struct {
	strm:  zlib.z_stream,
	ready: bool,
	reset: bool,
}

@(private)
deflater_init :: proc(d: ^Deflater, window_bits: int, level: int, reset: bool) -> bool {
	bits := window_bits if window_bits > 0 else 15
	lvl := level if level > 0 else 1
	// Raw deflate (negative window bits), memLevel 8 (zlib's default).
	d.ready = zlib.deflateInit2(&d.strm, c.int(lvl), zlib.DEFLATED, -c.int(bits), 8, zlib.DEFAULT_STRATEGY) == zlib.OK
	d.reset = reset
	return d.ready
}

@(private)
inflater_init :: proc(i: ^Inflater, reset: bool) -> bool {
	// Always the full window: decodes anything compressed with a window of up to 15 bits.
	i.ready = zlib.inflateInit2(&i.strm, -15) == zlib.OK
	i.reset = reset
	return i.ready
}

@(private)
deflater_destroy :: proc(d: ^Deflater) {
	if d.ready { zlib.deflateEnd(&d.strm) }
	d.ready = false
}

@(private)
inflater_destroy :: proc(i: ^Inflater) {
	if i.ready { zlib.inflateEnd(&i.strm) }
	i.ready = false
}

// Compresses a whole message: the deflate output, flushed and without the trailing 00 00 FF FF.
@(private)
deflate_message :: proc(d: ^Deflater, data: []byte, allocator := context.allocator) -> (out: [dynamic]byte, ok: bool) {
	out = make([dynamic]byte, 0, len(data) / 2 + 64, allocator)
	d.strm.next_in = raw_data(data)
	d.strm.avail_in = zlib.uInt(len(data))
	for {
		if cap(out) - len(out) < 64 { reserve(&out, 2 * cap(out) + 64) }
		avail := cap(out) - len(out)
		d.strm.next_out = &([^]byte)(raw_data(out))[len(out)]
		d.strm.avail_out = zlib.uInt(avail)
		r := zlib.deflate(&d.strm, zlib.SYNC_FLUSH)
		if r != zlib.OK && r != zlib.BUF_ERROR {
			delete(out)
			return nil, false
		}
		non_zero_resize(&out, len(out) + avail - int(d.strm.avail_out))
		// Done once deflate didn't fill the output: all input is consumed and flushed.
		if d.strm.avail_out != 0 { break }
	}
	d.strm.next_in, d.strm.next_out = nil, nil

	n := len(out)
	if n >= 4 && out[n - 4] == 0 && out[n - 3] == 0 && out[n - 2] == 0xFF && out[n - 1] == 0xFF {
		non_zero_resize(&out, n - 4)
	}
	if d.reset { zlib.deflateReset(&d.strm) }
	return out, true
}

@(private)
Inflate_Result :: enum {
	Ok,
	Too_Big,
	Error,
}

// Decompresses `data`, appending to `out`, which may not grow beyond `max` bytes.
@(private)
inflate_append :: proc(i: ^Inflater, data: []byte, out: ^[dynamic]byte, max: int) -> Inflate_Result {
	CHUNK :: 16 * 1024
	i.strm.next_in = raw_data(data)
	i.strm.avail_in = zlib.uInt(len(data))
	defer i.strm.next_in, i.strm.next_out = nil, nil

	for {
		// One byte more than allowed, to notice going over.
		room := min(CHUNK, max - len(out) + 1)
		if room <= 0 { return .Too_Big }
		if cap(out) - len(out) < room { reserve(out, len(out) + room) }
		i.strm.next_out = &([^]byte)(raw_data(out^))[len(out)]
		i.strm.avail_out = zlib.uInt(room)

		r := zlib.inflate(&i.strm, zlib.NO_FLUSH)
		non_zero_resize(out, len(out) + room - int(i.strm.avail_out))
		if len(out) > max { return .Too_Big }

		switch r {
		case zlib.OK:
		case zlib.STREAM_END:
			// The peer ended the deflate stream (a final block); later data starts a new one.
			zlib.inflateReset(&i.strm)
			if i.strm.avail_in == 0 { return .Ok }
			continue
		case zlib.BUF_ERROR:
			// No progress possible: all input consumed.
			return .Ok
		case:
			return .Error
		}
		if i.strm.avail_in == 0 && i.strm.avail_out != 0 { return .Ok }
	}
}

// Ends a message: feeds the 00 00 FF FF tail that the sender stripped.
@(private)
inflate_finish :: proc(i: ^Inflater, out: ^[dynamic]byte, max: int) -> Inflate_Result {
	tail := [4]byte{0, 0, 0xFF, 0xFF}
	res := inflate_append(i, tail[:], out, max)
	if res == .Ok && i.reset { zlib.inflateReset(&i.strm) }
	return res
}
