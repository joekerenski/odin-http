package tests_websocket

import "core:testing"

import ws "../../websocket"

@(test)
deflate_params :: proc(t: ^testing.T) {
	Case :: struct { params: string, ok: bool, want: ws.Deflate_Params }
	cases := []Case{
		{"", true, {}},
		{"; client_max_window_bits", true, {client_max_window_bits = -1}},
		{"; client_max_window_bits=10", true, {client_max_window_bits = 10}},
		{"; client_max_window_bits=\"12\"", true, {client_max_window_bits = 12}},
		{"; server_max_window_bits=9; server_no_context_takeover", true, {server_max_window_bits = 9, server_no_context_takeover = true}},
		{";CLIENT_NO_CONTEXT_TAKEOVER", true, {client_no_context_takeover = true}},
		{" ; server_no_context_takeover ; client_no_context_takeover ", true, {server_no_context_takeover = true, client_no_context_takeover = true}},
		// Invalid: unknown, duplicate, out of range, missing/unexpected values.
		{"; unknown", false, {}},
		{"; server_no_context_takeover; server_no_context_takeover", false, {}},
		{"; server_max_window_bits=7", false, {}},
		{"; server_max_window_bits=16", false, {}},
		{"; server_max_window_bits=015", false, {}},
		{"; server_max_window_bits=1x", false, {}},
		{"; server_max_window_bits", false, {}},
		{"; server_no_context_takeover=1", false, {}},
		{"; client_max_window_bits=", false, {}},
	}
	for c in cases {
		p, ok := ws.parse_deflate_params(c.params)
		testing.expectf(t, ok == c.ok && (!ok || p == c.want), "%q: got %v %v, want %v %v", c.params, p, ok, c.want, c.ok)
	}
}

@(test)
deflate_server_negotiation :: proc(t: ^testing.T) {
	Case :: struct { header: string, ok: bool, response: string }
	cases := []Case{
		{"permessage-deflate", true, "permessage-deflate"},
		{"permessage-deflate; client_max_window_bits", true, "permessage-deflate"},
		{"permessage-deflate; server_no_context_takeover; client_no_context_takeover", true, "permessage-deflate; server_no_context_takeover; client_no_context_takeover"},
		{"permessage-deflate; server_max_window_bits=10", true, "permessage-deflate; server_max_window_bits=10"},
		// An 8-bit server window is declined, the next offer is taken.
		{"permessage-deflate; server_max_window_bits=8, permessage-deflate", true, "permessage-deflate"},
		{"permessage-deflate; server_max_window_bits=8", false, ""},
		// Invalid offers are skipped, unknown extensions ignored.
		{"x-webkit-deflate-frame, permessage-deflate; bogus, permessage-deflate; client_no_context_takeover", true, "permessage-deflate; client_no_context_takeover"},
		{"x-webkit-deflate-frame", false, ""},
		{"", false, ""},
	}
	for c in cases {
		_, response, ok := ws.server_negotiate_deflate(c.header, context.temp_allocator)
		testing.expectf(t, ok == c.ok && response == c.response, "%q: got %q %v, want %q %v", c.header, response, ok, c.response, c.ok)
	}
}

@(test)
deflate_client_acceptance :: proc(t: ^testing.T) {
	Case :: struct { header: string, present, ok: bool }
	cases := []Case{
		{"", false, true},
		{"permessage-deflate", true, true},
		{"permessage-deflate; server_no_context_takeover; client_max_window_bits=12", true, true},
		// Must give a value; 8 bits we can't do; nothing we didn't offer.
		{"permessage-deflate; client_max_window_bits", true, false},
		{"permessage-deflate; client_max_window_bits=8", true, false},
		{"permessage-deflate, permessage-deflate", true, false},
		{"x-other", true, false},
		{"permessage-deflate; bogus", true, false},
	}
	for c in cases {
		_, present, ok := ws.client_accept_deflate(c.header)
		testing.expectf(t, present == c.present && ok == c.ok, "%q: got present=%v ok=%v", c.header, present, ok)
	}
}

@(test)
rsv_bits :: proc(t: ^testing.T) {
	buf: [ws.MAX_HEADER_SIZE]byte
	hb := ws.write_header(buf[:], true, .Text, 5, [4]byte{1, 2, 3, 4}, rsv = ws.RSV1)
	h, _, res := ws.parse_header(hb, true, allowed_rsv = ws.RSV1)
	testing.expectf(t, res == .Ok && h.rsv == ws.RSV1, "RSV1 allowed: %v %v", h, res)
	_, _, res = ws.parse_header(hb, true)
	testing.expectf(t, res == .Protocol_Error, "RSV1 not negotiated: %v", res)
	hb = ws.write_header(buf[:], true, .Text, 5, [4]byte{1, 2, 3, 4}, rsv = 0b010)
	_, _, res = ws.parse_header(hb, true, allowed_rsv = ws.RSV1)
	testing.expectf(t, res == .Protocol_Error, "RSV2: %v", res)
}
