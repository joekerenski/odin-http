package tests_client

import "core:bytes"
import "core:strings"
import "core:testing"

import http "../.."
import "../../client"

@(test)
urls :: proc(t: ^testing.T) {
	Case :: struct { url: string, err: client.Error, tls: bool, host: string, port: int, host_header: string, target: string }
	for c in ([]Case{
		{"http://example.com", nil, false, "example.com", 80, "example.com", "/"},
		{"HTTPS://Example.com/a/b?x=1#frag", nil, true, "Example.com", 443, "Example.com", "/a/b?x=1"},
		{"https://example.com:443/", nil, true, "example.com", 443, "example.com", "/"},
		{"http://example.com:8080?q", nil, false, "example.com", 8080, "example.com:8080", "/?q"},
		{"http://127.0.0.1:9/x", nil, false, "127.0.0.1", 9, "127.0.0.1:9", "/x"},
		{"https://[::1]:8443/", nil, true, "::1", 8443, "[::1]:8443", "/"},
		{"https://[::1]/", nil, true, "::1", 443, "[::1]", "/"},
		{"http://x/a b/\"q\"?v=<1>|é", nil, false, "x", 80, "x", "/a%20b/%22q%22?v=%3C1%3E%7C%C3%A9"},
		{"http://x/already%20encoded", nil, false, "x", 80, "x", "/already%20encoded"},
		{"ftp://x/", .Unsupported_Scheme, false, "", 0, "", ""},
		{"ws://x/", .Unsupported_Scheme, false, "", 0, "", ""},
		{"example.com", .Invalid_URL, false, "", 0, "", ""},
		{"http://", .Invalid_URL, false, "", 0, "", ""},
		{"http://user:pw@x/", .Invalid_URL, false, "", 0, "", ""},
		{"http://x:/", .Invalid_URL, false, "", 0, "", ""},
		{"http://x:0/", .Invalid_URL, false, "", 0, "", ""},
		{"http://x:65536/", .Invalid_URL, false, "", 0, "", ""},
		{"http://x:8a/", .Invalid_URL, false, "", 0, "", ""},
		{"http://[::1/", .Invalid_URL, false, "", 0, "", ""},
		{"http://[nope]/", .Invalid_URL, false, "", 0, "", ""},
		{"http://ex ample.com/", .Invalid_URL, false, "", 0, "", ""},
		{"http://x\r\nInjected: 1/", .Invalid_URL, false, "", 0, "", ""},
	}) {
		got, err := client.parse_url(c.url)
		testing.expectf(t, err == c.err, "%q: %v, want %v", c.url, err, c.err)
		if err != nil || c.err != nil { continue }
		testing.expectf(t, got.tls == c.tls && got.host == c.host && got.port == c.port && got.host_header == c.host_header && got.target == c.target,
			"%q: got %#v", c.url, got)
	}
}

@(test)
request_format :: proc(t: ^testing.T) {
	target, _ := client.parse_url("http://example.com:8080/p?q=1")

	{
		r: client.Request
		client.request_init(&r, .Get, context.temp_allocator)
		defer client.request_destroy(&r)
		http.headers_set(&r.headers, "X-Trace", "abc")
		append(&r.cookies, http.Cookie{name = "session", value = "s1"}, http.Cookie{name = "b", value = "2"})

		out, err := client.format_request(&r, target)
		defer delete(out)
		s := string(out)
		testing.expect(t, err == nil)
		testing.expectf(t, strings.has_prefix(s, "GET /p?q=1 HTTP/1.1\r\n"), "%q", s)
		testing.expectf(t, strings.contains(s, "host: example.com:8080\r\n"), "%q", s)
		testing.expectf(t, strings.contains(s, "connection: close\r\n"), "%q", s)
		testing.expectf(t, strings.contains(s, "x-trace: abc\r\n"), "%q", s)
		testing.expectf(t, strings.contains(s, "cookie: session=s1; b=2\r\n"), "%q", s)
		testing.expectf(t, !strings.contains(s, "content-length"), "GET without a body has no Content-Length: %q", s)
		testing.expect(t, strings.has_suffix(s, "\r\n\r\n"))
	}

	{
		r: client.Request
		client.request_init(&r, .Post, context.temp_allocator)
		defer client.request_destroy(&r)
		bytes.buffer_write_string(&r.body, "hello")
		http.headers_set(&r.headers, "Host", "override.test")

		out, err := client.format_request(&r, target)
		defer delete(out)
		s := string(out)
		testing.expect(t, err == nil)
		testing.expectf(t, strings.contains(s, "content-length: 5\r\n") && strings.has_suffix(s, "\r\n\r\nhello"), "%q", s)
		testing.expectf(t, strings.contains(s, "host: override.test\r\n") && !strings.contains(s, "example.com"), "%q", s)
	}

	{
		// POST without a body still says so.
		r: client.Request
		client.request_init(&r, .Post, context.temp_allocator)
		defer client.request_destroy(&r)
		out, err := client.format_request(&r, target)
		defer delete(out)
		testing.expect(t, err == nil && strings.contains(string(out), "content-length: 0\r\n"))
	}

	// Refused: header injection, invalid names, reserved headers, invalid cookies.
	Bad :: struct { name, value: string, cookie: http.Cookie }
	for b in ([]Bad{
		{name = "X-A", value = "1\r\nInjected: yes"},
		{name = "X-A", value = "a\x00b"},
		{name = "Bad Name", value = "x"},
		{name = "X\nY", value = "x"},
		{name = "Content-Length", value = "5"},
		{name = "Transfer-Encoding", value = "chunked"},
		{name = "Connection", value = "keep-alive"},
		{name = "Upgrade", value = "websocket"},
		{cookie = {name = "a b", value = "1"}},
		{cookie = {name = "a", value = "1; Injected=2"}},
		{cookie = {name = "a", value = "x\r\ny"}},
	}) {
		r: client.Request
		client.request_init(&r, .Get, context.temp_allocator)
		if b.name != "" { http.headers_set(&r.headers, b.name, b.value) }
		if b.cookie.name != "" { append(&r.cookies, b.cookie) }
		out, err := client.format_request(&r, target)
		testing.expectf(t, err == .Invalid_Request && out == nil, "%v: %v", b, err)
		client.request_destroy(&r)
	}
}
