package tests_websocket

import "core:math/rand"
import "core:testing"
import "core:unicode/utf8"

import ws "../../websocket"

@(test)
header_roundtrip :: proc(t: ^testing.T) {
	buf: [ws.MAX_HEADER_SIZE]byte
	for n in ([]int{0, 1, 125, 126, 127, 65535, 65536, 1 << 40}) {
		for masked in ([]bool{false, true}) {
			mask: Maybe([4]byte) = [4]byte{1, 2, 3, 4} if masked else nil
			hb := ws.write_header(buf[:], true, .Binary, n, mask)
			h, hl, res := ws.parse_header(hb, masked)
			testing.expectf(t, res == .Ok && hl == len(hb) && h.payload_len == n && h.fin && h.opcode == .Binary && h.masked == masked, "len %v masked %v: %v %v %v", n, masked, h, hl, res)
			// Every strict prefix needs more bytes.
			for i in 0 ..< len(hb) {
				_, _, r := ws.parse_header(hb[:i], masked)
				testing.expectf(t, r == .Need_More, "prefix %d of len %v: %v", i, n, r)
			}
		}
	}
}

@(test)
header_violations :: proc(t: ^testing.T) {
	Case :: struct { bytes: []byte, require_mask: bool, want: ws.Parse_Result }
	cases := []Case{
		{{0x81, 0x80, 0, 0, 0, 0}, true, .Ok},                  // masked text, empty
		{{0x81, 0x00}, true, .Protocol_Error},                  // unmasked from client
		{{0x81, 0x80, 0, 0, 0, 0}, false, .Protocol_Error},     // masked from server
		{{0x83, 0x80, 0, 0, 0, 0}, true, .Protocol_Error},      // reserved opcode 3
		{{0x8B, 0x80, 0, 0, 0, 0}, true, .Protocol_Error},      // reserved opcode B
		{{0xC1, 0x80, 0, 0, 0, 0}, true, .Protocol_Error},      // RSV1
		{{0x91, 0x80, 0, 0, 0, 0}, true, .Protocol_Error},      // RSV3
		{{0x09, 0x80, 0, 0, 0, 0}, true, .Protocol_Error},      // fragmented ping
		{{0x89, 0xFE, 0x00, 0x7E}, true, .Protocol_Error},      // ping with 126 bytes
		{{0x82, 0xFE, 0x00, 0x05}, true, .Protocol_Error},      // non-minimal 16-bit length
		{{0x82, 0xFF, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF}, true, .Protocol_Error}, // non-minimal 64-bit
		{{0x82, 0xFF, 0x80, 0, 0, 0, 0, 0, 0, 0}, true, .Protocol_Error},    // 64-bit MSB set
		{{0x00, 0x80, 0, 0, 0, 0}, true, .Ok},                  // continuation, not final
	}
	for c in cases {
		_, _, res := ws.parse_header(c.bytes, c.require_mask)
		testing.expectf(t, res == c.want, "% x: got %v want %v", c.bytes, res, c.want)
	}
}

@(test)
masking :: proc(t: ^testing.T) {
	mask := [4]byte{0x37, 0xfa, 0x21, 0x3d}
	// RFC 6455 5.7: "Hello" masked.
	data := []byte{0x7f, 0x9f, 0x4d, 0x51, 0x58}
	ws.apply_mask(data, mask)
	testing.expect(t, string(data) == "Hello")

	// Unmasking in pieces at any offset equals unmasking at once.
	r := rand.create(1)
	context.random_generator = rand.default_random_generator(&r)
	for _ in 0 ..< 200 {
		n := rand.int_max(100)
		orig := make([]byte, n, context.temp_allocator)
		for &b in orig { b = byte(rand.int_max(256)) }
		a := make([]byte, n, context.temp_allocator); copy(a, orig)
		b := make([]byte, n, context.temp_allocator); copy(b, orig)
		ws.apply_mask(a, mask)
		split := rand.int_max(n + 1)
		ws.apply_mask(b[:split], mask, 0)
		ws.apply_mask(b[split:], mask, split)
		testing.expect(t, string(a) == string(b))
		ws.apply_mask(a, mask)
		testing.expect(t, string(a) == string(orig))
	}
}

@(test)
close_payloads :: proc(t: ^testing.T) {
	code, reason, ok := ws.parse_close_payload({})
	testing.expect(t, ok && code == 1005)
	code, reason, ok = ws.parse_close_payload({0x03, 0xE8, 'b', 'y', 'e'})
	testing.expect(t, ok && code == 1000 && reason == "bye")
	_, _, ok = ws.parse_close_payload({0x03})
	testing.expect(t, !ok)
	for bad in ([]u16{0, 999, 1004, 1005, 1006, 1012, 1015, 1016, 2999, 5000, 65535}) {
		_, _, ok = ws.parse_close_payload({byte(bad >> 8), byte(bad)})
		testing.expectf(t, !ok, "code %v accepted", bad)
	}
	for good in ([]u16{1000, 1001, 1002, 1003, 1007, 1008, 1009, 1010, 1011, 3000, 4999}) {
		_, _, ok = ws.parse_close_payload({byte(good >> 8), byte(good)})
		testing.expectf(t, ok, "code %v rejected", good)
	}
	_, _, ok = ws.parse_close_payload({0x03, 0xE8, 0xC0, 0x80})
	testing.expect(t, !ok, "invalid UTF-8 reason accepted")
}

@(test)
utf8_validation :: proc(t: ^testing.T) {
	valid := []string{"", "hello", "κόσμε", "é", "€", "\U0001F600", "￿", "\U0010FFFF", "aaaaaaaaaaaaaaaaaaaaébbbbbbbbbbbbb"}
	for s in valid {
		v: ws.Utf8_Validator
		testing.expectf(t, ws.utf8_feed(&v, transmute([]byte)s) && ws.utf8_complete(&v), "rejected %q", s)
	}
	invalid := [][]byte{
		{0x80}, {0xBF}, {0xC0, 0x80}, {0xC1, 0xBF}, {0xE0, 0x80, 0x80}, {0xED, 0xA0, 0x80},
		{0xF0, 0x80, 0x80, 0x80}, {0xF4, 0x90, 0x80, 0x80}, {0xF5, 0x80, 0x80, 0x80}, {0xFF},
		{0xCE, 0xBA, 0xE1, 0xBD, 0xB9, 0xCF, 0x83, 0xCE, 0xBC, 0xCE, 0xB5, 0xED, 0xA0, 0x80, 0x65, 0x64, 0x69, 0x74, 0x65, 0x64},
	}
	for b in invalid {
		v: ws.Utf8_Validator
		testing.expectf(t, !ws.utf8_feed(&v, b), "accepted % x", b)
	}

	// Incomplete at the end is valid so far, but not complete.
	v: ws.Utf8_Validator
	testing.expect(t, ws.utf8_feed(&v, {0xE2, 0x82}) && !ws.utf8_complete(&v))
	testing.expect(t, ws.utf8_feed(&v, {0xAC}) && ws.utf8_complete(&v))

	// Agrees with core:unicode/utf8 on random input, fed in random pieces.
	r := rand.create(2)
	context.random_generator = rand.default_random_generator(&r)
	for _ in 0 ..< 20000 {
		n := rand.int_max(12)
		b := make([]byte, n, context.temp_allocator)
		for &x in b {
			x = byte(rand.int_max(256)) if rand.int_max(3) == 0 else byte(0x80 + rand.int_max(0x50))
			if rand.int_max(4) == 0 { x = byte(rand.choice([]int{0xC2, 0xE0, 0xED, 0xF0, 0xF4})) }
		}
		want := utf8.valid_string(string(b))
		vv: ws.Utf8_Validator
		split := rand.int_max(n + 1)
		got := ws.utf8_feed(&vv, b[:split]) && ws.utf8_feed(&vv, b[split:]) && ws.utf8_complete(&vv)
		testing.expectf(t, got == want, "% x: got %v want %v", b, got, want)
		free_all(context.temp_allocator)
	}
}
