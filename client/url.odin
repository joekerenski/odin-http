package client

import "core:net"
import "core:strings"

import http ".."

// A parsed http:// or https:// URL, as the client uses it.
Target :: struct {
	tls:         bool,
	// The host name, or the IP address without brackets.
	host:        string,
	is_ip:       bool,
	port:        int,
	// Host header value: the host (IPv6 in brackets) and the port unless it's the default.
	host_header: string,
	// The request-target: path and query, percent-encoded where needed, without the fragment.
	target:      string,
}

/*
Parses `url` (http:// or https://, scheme case-insensitive). User info (`user@host`) is refused
rather than silently sent somewhere, the fragment is dropped, and bytes that can't appear in a
request-target (spaces, controls, non-ASCII, `"<>\^`{|}`) are percent-encoded. Existing `%`
escapes are kept.
*/
parse_url :: proc(url: string, allocator := context.temp_allocator) -> (t: Target, err: Error) {
	sep := strings.index(url, "://")
	if sep < 0 { return {}, .Invalid_URL }
	switch {
	case http.ascii_equal_fold(url[:sep], "http"):
	case http.ascii_equal_fold(url[:sep], "https"):
		t.tls = true
	case:
		return {}, .Unsupported_Scheme
	}
	rest := url[sep + 3:]

	end := len(rest)
	for i in 0 ..< len(rest) {
		if rest[i] == '/' || rest[i] == '?' || rest[i] == '#' { end = i; break }
	}
	authority := rest[:end]
	path := rest[end:]
	if hash := strings.index_byte(path, '#'); hash >= 0 { path = path[:hash] }

	if authority == "" || strings.contains_rune(authority, '@') { return {}, .Invalid_URL }

	// host [":" port], the host possibly an IPv6 literal in brackets.
	host, port_str := authority, ""
	has_port := false
	if authority[0] == '[' {
		close := strings.index_byte(authority, ']')
		if close < 0 { return {}, .Invalid_URL }
		host = authority[1:close]
		after := authority[close + 1:]
		if len(after) > 0 {
			if after[0] != ':' { return {}, .Invalid_URL }
			port_str, has_port = after[1:], true
		}
		if _, ok := net.parse_ip6_address(host); !ok { return {}, .Invalid_URL }
		t.is_ip = true
	} else {
		if colon := strings.last_index_byte(authority, ':'); colon >= 0 {
			host, port_str, has_port = authority[:colon], authority[colon + 1:], true
		}
		if !is_reg_name(host) { return {}, .Invalid_URL }
		if _, ok := net.parse_ip4_address(host); ok { t.is_ip = true }
	}
	t.host = host

	default_port := 443 if t.tls else 80
	t.port = default_port
	if has_port {
		p, ok := http.parse_decimal(port_str)
		if !ok || p < 1 || p > 65535 { return {}, .Invalid_URL }
		t.port = p
	}

	hb := strings.builder_make(allocator)
	if t.is_ip && strings.contains_rune(host, ':') {
		strings.write_byte(&hb, '[')
		strings.write_string(&hb, host)
		strings.write_byte(&hb, ']')
	} else {
		strings.write_string(&hb, host)
	}
	if t.port != default_port {
		strings.write_byte(&hb, ':')
		strings.write_int(&hb, t.port)
	}
	t.host_header = strings.to_string(hb)

	t.target = encode_target(path, allocator)
	return t, .None
}

// reg-name (RFC 3986), limited to what DNS names use: letters, digits, '-', '.', '_', '~'.
@(private)
is_reg_name :: proc(s: string) -> bool {
	if len(s) == 0 || len(s) > 253 { return false }
	for i in 0 ..< len(s) {
		switch s[i] {
		case 'a' ..= 'z', 'A' ..= 'Z', '0' ..= '9', '-', '.', '_', '~':
		case:
			return false
		}
	}
	return true
}

// Percent-encodes the bytes that can't appear in a request-target; "" becomes "/".
@(private)
encode_target :: proc(path: string, allocator := context.temp_allocator) -> string {
	path := path
	if path == "" || path[0] == '?' {
		path = strings.concatenate({"/", path}, allocator)
	}
	needs := false
	for i in 0 ..< len(path) {
		if must_encode(path[i]) { needs = true; break }
	}
	if !needs { return path }

	HEX := "0123456789ABCDEF"
	sb := strings.builder_make(0, len(path) + 16, allocator)
	for i in 0 ..< len(path) {
		ch := path[i]
		if must_encode(ch) {
			strings.write_byte(&sb, '%')
			strings.write_byte(&sb, HEX[ch >> 4])
			strings.write_byte(&sb, HEX[ch & 0xF])
		} else {
			strings.write_byte(&sb, ch)
		}
	}
	return strings.to_string(sb)
}

@(private)
must_encode :: proc(ch: byte) -> bool {
	switch ch {
	case 0 ..= 0x20, 0x7F ..= 0xFF, '"', '<', '>', '\\', '^', '`', '{', '|', '}':
		return true
	}
	return false
}
