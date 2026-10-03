// RFC 6455 framing, without any I/O: header parsing and writing, masking, close payloads and
// incremental UTF-8 validation. Nothing here allocates or panics on any input.
package websocket

import "base:intrinsics"

import "core:encoding/endian"

Opcode :: enum u8 {
	Continuation = 0x0,
	Text         = 0x1,
	Binary       = 0x2,
	Close        = 0x8,
	Ping         = 0x9,
	Pong         = 0xA,
}

is_control :: #force_inline proc "contextless" (op: Opcode) -> bool {
	return u8(op) & 0x8 != 0
}

Frame_Header :: struct {
	fin:         bool,
	rsv:         u8, // The three RSV bits, 0 unless an extension negotiated them.
	opcode:      Opcode,
	masked:      bool,
	mask:        [4]byte,
	payload_len: int,
}

// Largest possible header: 2 + 8 (64-bit length) + 4 (mask).
MAX_HEADER_SIZE :: 14

// RSV1 in `Frame_Header.rsv`: the message is compressed (permessage-deflate).
RSV1 :: 0b100

Parse_Result :: enum {
	Ok,
	// Not enough bytes for the whole header yet.
	Need_More,
	// Protocol violation, fail the connection with 1002.
	Protocol_Error,
}

// Parses a frame header at the start of `buf`. `require_mask` is true on the server side (client
// frames must be masked), false on the client side (server frames must not be). `allowed_rsv` are
// the RSV bits an extension negotiated (`RSV1` for compression), others are a protocol error.
parse_header :: proc "contextless" (buf: []byte, require_mask: bool, allowed_rsv: u8 = 0) -> (h: Frame_Header, header_len: int, res: Parse_Result) {
	if len(buf) < 2 { return {}, 0, .Need_More }

	b0, b1 := buf[0], buf[1]
	h.fin    = b0 & 0x80 != 0
	h.rsv    = (b0 >> 4) & 0x7
	h.masked = b1 & 0x80 != 0

	switch b0 & 0x0F {
	case 0x0, 0x1, 0x2, 0x8, 0x9, 0xA: h.opcode = Opcode(b0 & 0x0F)
	case:                              return {}, 0, .Protocol_Error // Reserved opcodes.
	}

	// RSV bits are only allowed when an extension negotiated them.
	if h.rsv & ~allowed_rsv != 0 { return {}, 0, .Protocol_Error }
	if h.masked != require_mask { return {}, 0, .Protocol_Error }

	n := 2
	len7 := int(b1 & 0x7F)
	switch len7 {
	case 126:
		if len(buf) < n + 2 { return {}, 0, .Need_More }
		v, _ := endian.get_u16(buf[n:], .Big)
		// Lengths must use the minimal encoding.
		if v < 126 { return {}, 0, .Protocol_Error }
		h.payload_len = int(v)
		n += 2
	case 127:
		if len(buf) < n + 8 { return {}, 0, .Need_More }
		v, _ := endian.get_u64(buf[n:], .Big)
		// The most significant bit must be 0, and the minimal encoding must be used.
		if v >> 63 != 0 || v <= 0xFFFF { return {}, 0, .Protocol_Error }
		h.payload_len = int(v)
		n += 8
	case:
		h.payload_len = len7
	}

	// Control frames: at most 125 bytes of payload, and never fragmented.
	if is_control(h.opcode) && (h.payload_len > 125 || !h.fin) { return {}, 0, .Protocol_Error }

	if h.masked {
		if len(buf) < n + 4 { return {}, 0, .Need_More }
		copy(h.mask[:], buf[n:n + 4])
		n += 4
	}

	return h, n, .Ok
}

// Writes a frame header into `buf` (which must have room for MAX_HEADER_SIZE bytes) and returns
// the used part. A mask is written when `mask` is non-nil.
write_header :: proc "contextless" (buf: []byte, fin: bool, opcode: Opcode, payload_len: int, mask: Maybe([4]byte) = nil, rsv: u8 = 0) -> []byte {
	buf[0] = u8(opcode) | (0x80 if fin else 0) | (rsv & 0x7) << 4
	mask_bit: u8 = 0x80 if mask != nil else 0
	n := 2
	switch {
	case payload_len < 126:
		buf[1] = mask_bit | u8(payload_len)
	case payload_len <= 0xFFFF:
		buf[1] = mask_bit | 126
		endian.put_u16(buf[2:], .Big, u16(payload_len))
		n += 2
	case:
		buf[1] = mask_bit | 127
		endian.put_u64(buf[2:], .Big, u64(payload_len))
		n += 8
	}
	if m, has := mask.?; has {
		copy(buf[n:], m[:])
		n += 4
	}
	return buf[:n]
}

// XORs `data` with the mask, `offset` is the position of data[0] within the frame's payload
// (so a payload can be unmasked in pieces).
apply_mask :: proc "contextless" (data: []byte, mask: [4]byte, offset := 0) {
	// Rotate the key so that key[0] lines up with data[0].
	k: [8]byte
	for i in 0 ..< 8 { k[i] = mask[(offset + i) & 3] }
	k64 := transmute(u64)k

	i := 0
	for ; i + 8 <= len(data); i += 8 {
		p := (^u64)(&data[i])
		intrinsics.unaligned_store(p, intrinsics.unaligned_load(p) ~ k64)
	}
	for ; i < len(data); i += 1 {
		data[i] ~= k[i & 7]
	}
}

// Close status codes (RFC 6455 7.4).
Close_Code :: enum u16 {
	Normal               = 1000,
	Going_Away           = 1001,
	Protocol_Error       = 1002,
	Unsupported_Data     = 1003,
	// Never sent on the wire, reported when the peer's close frame had no status code.
	No_Status            = 1005,
	// Never sent on the wire, reported when the connection was lost without a close frame.
	Abnormal             = 1006,
	Invalid_Payload      = 1007,
	Policy_Violation     = 1008,
	Message_Too_Big      = 1009,
	Mandatory_Extension  = 1010,
	Internal_Error       = 1011,
}

// Whether a code may appear in a close frame on the wire.
close_code_valid :: proc "contextless" (code: u16) -> bool {
	switch code {
	case 1000 ..= 1003, 1007 ..= 1011: return true
	case 3000 ..= 4999:                return true // Registered (3xxx) and private (4xxx) codes.
	}
	return false
}

// Parses a close frame payload: empty, or a 2-byte code followed by a UTF-8 reason.
parse_close_payload :: proc "contextless" (payload: []byte) -> (code: u16, reason: string, ok: bool) {
	switch len(payload) {
	case 0:
		return u16(Close_Code.No_Status), "", true
	case 1:
		return 0, "", false
	}
	code, _ = endian.get_u16(payload, .Big)
	if !close_code_valid(code) { return 0, "", false }
	reason = string(payload[2:])
	v: Utf8_Validator
	if !utf8_feed(&v, payload[2:]) || !utf8_complete(&v) { return 0, "", false }
	return code, reason, true
}

// Incremental UTF-8 validation (RFC 3629): rejects overlongs, surrogates and code points above
// U+10FFFF as soon as the offending byte is seen, so invalid text fails fast even across fragments.
Utf8_Validator :: struct {
	// Continuation bytes still expected for the current code point.
	need:  u8,
	// Allowed range for the next continuation byte.
	lo, hi: u8,
}

utf8_feed :: proc "contextless" (v: ^Utf8_Validator, data: []byte) -> bool {
	i := 0
	for i < len(data) {
		b := data[i]
		if v.need == 0 {
			// Fast path for ASCII, 8 bytes at a time.
			for i + 8 <= len(data) && intrinsics.unaligned_load((^u64)(&data[i])) & 0x8080808080808080 == 0 {
				i += 8
			}
			if i >= len(data) { break }
			b = data[i]
			switch b {
			case 0x00 ..= 0x7F: v.need = 0
			case 0xC2 ..= 0xDF: v.need = 1; v.lo, v.hi = 0x80, 0xBF
			case 0xE0:          v.need = 2; v.lo, v.hi = 0xA0, 0xBF
			case 0xE1 ..= 0xEC: v.need = 2; v.lo, v.hi = 0x80, 0xBF
			case 0xED:          v.need = 2; v.lo, v.hi = 0x80, 0x9F
			case 0xEE ..= 0xEF: v.need = 2; v.lo, v.hi = 0x80, 0xBF
			case 0xF0:          v.need = 3; v.lo, v.hi = 0x90, 0xBF
			case 0xF1 ..= 0xF3: v.need = 3; v.lo, v.hi = 0x80, 0xBF
			case 0xF4:          v.need = 3; v.lo, v.hi = 0x80, 0x8F
			case:               return false
			}
		} else {
			if b < v.lo || b > v.hi { return false }
			v.need -= 1
			v.lo, v.hi = 0x80, 0xBF
		}
		i += 1
	}
	return true
}

// Whether the input so far ended on a code point boundary.
utf8_complete :: #force_inline proc "contextless" (v: ^Utf8_Validator) -> bool {
	return v.need == 0
}
