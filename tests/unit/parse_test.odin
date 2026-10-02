package tests_unit

import "core:testing"

import http "../.."

@(test)
content_length :: proc(t: ^testing.T) {
	Case :: struct { input: string, n: int, ok: bool }
	cases := []Case{
		{"0", 0, true},
		{"5", 5, true},
		{"0005", 5, true},
		{"9223372036854775807", max(int), true},
		{"5, 5", 5, true},
		{"5,5 ,\t5", 5, true},
		{"", 0, false},
		{" ", 0, false},
		{"-5", 0, false},
		{"+5", 0, false},
		{"0_5", 0, false},
		{"0x5", 0, false},
		{"5 5", 0, false},
		{"5, 6", 0, false},
		{"5,", 0, false},
		{",5", 0, false},
		{"9223372036854775808", 0, false},
		{"99999999999999999999999", 0, false},
		{"18446744073709551621", 0, false},
		{"5\x00", 0, false},
	}
	for c in cases {
		n, ok := http.parse_content_length(c.input)
		testing.expectf(t, ok == c.ok && n == c.n, "parse_content_length(%q) = %v, %v; want %v, %v", c.input, n, ok, c.n, c.ok)
	}
}

@(test)
chunk_size_line :: proc(t: ^testing.T) {
	Case :: struct { input: string, n: int, ok: bool }
	cases := []Case{
		{"0", 0, true},
		{"5", 5, true},
		{"fF", 255, true},
		{"5;ext=1", 5, true},
		{"5 ; ext", 5, true},
		{"7fffffffffffffff", max(int), true},
		{"", 0, false},
		{";", 0, false},
		{"-1", 0, false},
		{"+1", 0, false},
		{"0x5", 0, false},
		{"5_0", 0, false},
		{"5 5", 0, false},
		{"8000000000000000", 0, false},
		{"ffffffffffffffffff", 0, false},
		{"5;\x00", 0, false},
		{"g", 0, false},
	}
	for c in cases {
		n, ok := http.parse_chunk_size_line(c.input)
		testing.expectf(t, ok == c.ok && n == c.n, "parse_chunk_size_line(%q) = %v, %v; want %v, %v", c.input, n, ok, c.n, c.ok)
	}
}

@(test)
transfer_encoding :: proc(t: ^testing.T) {
	Case :: struct { input: string, want: http.Transfer_Encoding_Result }
	cases := []Case{
		{"chunked", .Chunked},
		{"Chunked", .Chunked},
		{"CHUNKED", .Chunked},
		{" chunked ", .Chunked},
		{", chunked", .Chunked},
		{"gzip, chunked", .Unsupported},
		{"gzip;q=1, chunked", .Unsupported},
		{"", .Invalid},
		{",", .Invalid},
		{"xchunked", .Invalid},
		{"chunkedx", .Invalid},
		{"chunked, gzip", .Invalid},
		{"chunked, chunked", .Invalid},
		{"chunked;x=1", .Invalid},
		{"gzip", .Invalid},
		{"chu nked", .Invalid},
		{"chunked\x00", .Invalid},
		{"\"chunked\"", .Invalid},
	}
	for c in cases {
		got := http.parse_transfer_encoding(c.input)
		testing.expectf(t, got == c.want, "parse_transfer_encoding(%q) = %v; want %v", c.input, got, c.want)
	}
}

@(test)
list_tokens :: proc(t: ^testing.T) {
	testing.expect(t, http.header_list_has_token("close", "close"))
	testing.expect(t, http.header_list_has_token("Close", "close"))
	testing.expect(t, http.header_list_has_token("keep-alive, close", "close"))
	testing.expect(t, http.header_list_has_token("Upgrade,\tHTTP2-Settings", "upgrade"))
	testing.expect(t, !http.header_list_has_token("closed", "close"))
	testing.expect(t, !http.header_list_has_token("", "close"))
	testing.expect(t, !http.header_list_has_token("keep-alive", "close"))
}

@(test)
http_version :: proc(t: ^testing.T) {
	Case :: struct { input: string, v: http.Version, ok: bool }
	cases := []Case{
		{"HTTP/1.1", {1, 1}, true},
		{"HTTP/1.0", {1, 0}, true},
		{"HTTP/2.0", {2, 0}, true},
		{"HTTP/1", {}, false},
		{"HTTP/1.x", {}, false},
		{"http/1.1", {}, false},
		{"HTTP/1.1 ", {}, false},
		{"HTTP/11.1", {}, false},
		{"HTTP/1,1", {}, false},
		{"", {}, false},
	}
	for c in cases {
		v, ok := http.parse_http_version(c.input)
		testing.expectf(t, ok == c.ok && v == c.v, "parse_http_version(%q) = %v, %v; want %v, %v", c.input, v, ok, c.v, c.ok)
	}
}

@(test)
tokens_and_values :: proc(t: ^testing.T) {
	testing.expect(t, http.is_token("Content-Length"))
	testing.expect(t, http.is_token("x!#$%&'*+-.^_`|~9"))
	testing.expect(t, !http.is_token(""))
	testing.expect(t, !http.is_token("Bad Name"))
	testing.expect(t, !http.is_token("a:b"))
	testing.expect(t, !http.is_token("\tfolded"))
	testing.expect(t, !http.is_token("x\x80"))

	testing.expect(t, http.is_field_value(""))
	testing.expect(t, http.is_field_value("a b\tc \x80\xff"))
	testing.expect(t, !http.is_field_value("a\x00b"))
	testing.expect(t, !http.is_field_value("a\rb"))
	testing.expect(t, !http.is_field_value("a\nb"))
	testing.expect(t, !http.is_field_value("a\x7fb"))

	testing.expect(t, http.trim_ows(" \t a b \t") == "a b")
	testing.expect(t, http.trim_ows("\va\f") == "\va\f")

	testing.expect(t, http.is_request_target("/"))
	testing.expect(t, http.is_request_target("*"))
	testing.expect(t, http.is_request_target("/a?b=c%20d"))
	testing.expect(t, !http.is_request_target(""))
	testing.expect(t, !http.is_request_target("/a b"))
	testing.expect(t, !http.is_request_target("/\x7f"))
	testing.expect(t, !http.is_request_target("/\x00"))
	testing.expect(t, !http.is_request_target("/\xc3\xa9"))
}
