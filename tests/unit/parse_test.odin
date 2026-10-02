package tests_unit

import "core:path/filepath"
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

@(test)
range_header :: proc(t: ^testing.T) {
	Case :: struct { input: string, size, start, length: int, res: http.Range_Result }
	cases := []Case{
		{"bytes=0-9", 100, 0, 10, .Partial},
		{"bytes=10-", 100, 10, 90, .Partial},
		{"bytes=-10", 100, 90, 10, .Partial},
		{"bytes=-1000", 100, 0, 100, .Partial},
		{"bytes=90-1000", 100, 90, 10, .Partial},
		{"Bytes=0-0", 100, 0, 1, .Partial},
		{"bytes = 0-0", 100, 0, 0, .None},
		{"bytes=100-", 100, 0, 0, .Unsatisfiable},
		{"bytes=-0", 100, 0, 0, .Unsatisfiable},
		{"bytes=0-", 0, 0, 0, .Unsatisfiable},
		{"bytes=0-1,5-6", 100, 0, 0, .None},
		{"bytes=5-1", 100, 0, 0, .None},
		{"bytes=a-b", 100, 0, 0, .None},
		{"bytes=-", 100, 0, 0, .None},
		{"items=0-1", 100, 0, 0, .None},
		{"bytes=0-99999999999999999999", 100, 0, 0, .None},
		{"", 100, 0, 0, .None},
	}
	for c in cases {
		start, length, res := http.parse_range(c.input, c.size)
		testing.expectf(t, res == c.res && (res != .Partial || (start == c.start && length == c.length)),
			"parse_range(%q, %v) = %v, %v, %v; want %v, %v, %v", c.input, c.size, start, length, res, c.start, c.length, c.res)
	}
}

@(test)
dir_resolve :: proc(t: ^testing.T) {
	Case :: struct { base, target, request, want: string, ok: bool }
	cases := []Case{
		{"/static", "www", "/static/a.txt", "www/a.txt", true},
		{"/static/", "www", "/static/a.txt", "www/a.txt", true},
		{"/static", "www", "/static/sub/b.css?v=1", "www/sub/b.css", true},
		{"/static", "www", "/static/", "www/index.html", true},
		{"/static", "www", "/static", "www/index.html", true},
		{"/static", "www", "/static/sub/", "www/sub/index.html", true},
		{"/static", "www", "/static/./a.txt", "www/a.txt", true},
		{"/static", "www", "/static//a.txt", "www/a.txt", true},
		{"/static", "www", "/static/hello%20world.txt", "www/hello world.txt", true},
		{"/static", "/var/www", "/static/a.txt", "/var/www/a.txt", true},
		{"", "www", "/a.txt", "www/a.txt", true},
		{"/static", "www", "/static../secret.txt", "", false},
		{"/static", "www", "/staticfoo", "", false},
		{"/static", "www", "/static/../secret.txt", "", false},
		{"/static", "www", "/static/sub/../../secret.txt", "", false},
		{"/static", "www", "/static/%2e%2e/secret.txt", "", false},
		{"/static", "www", "/static/%2E%2E/secret.txt", "", false},
		{"/static", "www", "/static/..%2fsecret.txt", "", false},
		{"/static", "www", "/static/..%5csecret.txt", "", false},
		{"/static", "www", "/static/a%00.txt", "", false},
		{"/static", "www", "/static/a%0a.txt", "", false},
		{"/static", "www", "/static/%zz", "", false},
		{"/static", "www", "/other/a.txt", "", false},
	}
	for c in cases {
		got, ok := http.dir_resolve(c.base, c.target, c.request, context.temp_allocator)
		want, _ := filepath.clean(c.want, context.temp_allocator) // Native separators.
		testing.expectf(t, ok == c.ok && (!ok || got == want), "dir_resolve(%q, %q, %q) = %q, %v; want %q, %v", c.base, c.target, c.request, got, ok, c.want, c.ok)
	}
}

@(test)
mime_types :: proc(t: ^testing.T) {
	testing.expect(t, http.mime_from_extension("a.PNG") == .Png)
	testing.expect(t, http.mime_from_extension("a.jpg") == .Jpeg)
	testing.expect(t, http.mime_from_extension("a.mjs") == .Js)
	testing.expect(t, http.mime_from_extension("a.txt") == .Plain)
	testing.expect(t, http.mime_from_extension("a.exe") == .Octet_Stream)
	testing.expect(t, http.mime_from_extension("noext") == .Octet_Stream)
	testing.expect(t, http.mime_from_extension("a.verylongextension") == .Octet_Stream)
}
