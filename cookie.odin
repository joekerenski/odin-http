package http

import "core:io"
import "core:strconv"
import "core:strings"
import "core:time"

Cookie_Same_Site :: enum {
	Unspecified,
	None,
	Strict,
	Lax,
}

Cookie :: struct {
	_raw:         string,
	name:         string,
	value:        string,
	domain:       Maybe(string),
	expires_gmt:  Maybe(time.Time),
	max_age_secs: Maybe(int),
	path:         Maybe(string),
	http_only:    bool,
	partitioned:  bool,
	secure:       bool,
	same_site:    Cookie_Same_Site,
}

// Reports whether the cookie can be written without injecting attributes or headers:
// the name is a token, the value consists of cookie-octets (optionally in double quotes, RFC 6265 4.1.1),
// and domain/path contain no ';' or control characters.
cookie_valid :: proc(c: Cookie) -> bool {
	is_cookie_octet :: proc(b: byte) -> bool {
		// %x21 / %x23-2B / %x2D-3A / %x3C-5B / %x5D-7E: US-ASCII without CTLs, whitespace, DQUOTE, comma, semicolon and backslash.
		return b == 0x21 || (b >= 0x23 && b <= 0x2B) || (b >= 0x2D && b <= 0x3A) || (b >= 0x3C && b <= 0x5B) || (b >= 0x5D && b <= 0x7E)
	}
	is_attr_value :: proc(s: string) -> bool {
		for i in 0 ..< len(s) {
			if s[i] < 0x20 || s[i] == 0x7f || s[i] == ';' { return false }
		}
		return true
	}

	if !is_token(c.name) { return false }

	v := c.value
	if len(v) >= 2 && v[0] == '"' && v[len(v) - 1] == '"' {
		v = v[1:len(v) - 1]
	}
	for i in 0 ..< len(v) {
		if !is_cookie_octet(v[i]) { return false }
	}

	if d, ok := c.domain.(string); ok && !is_attr_value(d) { return false }
	if p, ok := c.path.(string); ok && !is_attr_value(p) { return false }
	return true
}

// Builds the Set-Cookie header string representation of the given cookie.
//
// Returns `.Invalid_Write` without writing anything if the cookie is not `cookie_valid`.
cookie_write :: proc(w: io.Writer, c: Cookie) -> io.Error {
	if !cookie_valid(c) { return .Invalid_Write }

	// odinfmt:disable
	io.write_string(w, "set-cookie: ") or_return
	io.write_string(w, c.name)         or_return
	io.write_byte(w, '=')              or_return
	io.write_string(w, c.value)        or_return

	if d, ok := c.domain.(string); ok {
		io.write_string(w, "; Domain=") or_return
		io.write_string(w, d)           or_return
	}

	if e, ok := c.expires_gmt.(time.Time); ok {
		io.write_string(w, "; Expires=") or_return
		date_write(w, e)                 or_return
	}

	if a, ok := c.max_age_secs.(int); ok {
		io.write_string(w, "; Max-Age=") or_return
		io.write_int(w, a)               or_return
	}

	if p, ok := c.path.(string); ok {
		io.write_string(w, "; Path=") or_return
		io.write_string(w, p)         or_return
	}

	switch c.same_site {
	case .None:   io.write_string(w, "; SameSite=None")   or_return
	case .Lax:    io.write_string(w, "; SameSite=Lax")    or_return
	case .Strict: io.write_string(w, "; SameSite=Strict") or_return
	case .Unspecified: // no-op.
	}
	// odinfmt:enable

	if c.secure {
		io.write_string(w, "; Secure") or_return
	}

	if c.partitioned {
		io.write_string(w, "; Partitioned") or_return
	}

	if c.http_only {
		io.write_string(w, "; HttpOnly") or_return
	}

	return nil
}

// Builds the Set-Cookie header string representation of the given cookie.
cookie_string :: proc(c: Cookie, allocator := context.allocator) -> string {
	b: strings.Builder
	strings.builder_init(&b, 0, 20, allocator)

	cookie_write(strings.to_writer(&b), c)

	return strings.to_string(b)
}

// Parses a Set-Cookie header value following RFC 6265 5.2: the name must be non-empty, the value may
// be empty, unknown attributes and attributes with invalid values are ignored.
//
// All the returned strings (inside cookie) are slices into the given value string, nothing is allocated.
cookie_parse :: proc(value: string, allocator := context.allocator) -> (cookie: Cookie, ok: bool) {
	cookie._raw = value

	pair, _, attrs := strings.partition(value, ";")
	eq := strings.index_byte(pair, '=')
	if eq < 0 { return }

	cookie.name  = trim_ows(pair[:eq])
	cookie.value = trim_ows(pair[eq + 1:])
	if len(cookie.name) == 0 { return }

	rest := attrs
	for part in strings.split_iterator(&rest, ";") {
		key, _, val := strings.partition(part, "=")
		key = trim_ows(key)
		val = trim_ows(val)

		switch {
		case ascii_equal_fold(key, "httponly"):    cookie.http_only = true
		case ascii_equal_fold(key, "partitioned"): cookie.partitioned = true
		case ascii_equal_fold(key, "secure"):      cookie.secure = true
		case ascii_equal_fold(key, "domain"):      cookie.domain = val
		case ascii_equal_fold(key, "path"):        cookie.path = val
		case ascii_equal_fold(key, "expires"):
			if t, tok := cookie_date_parse(val); tok { cookie.expires_gmt = t }
		case ascii_equal_fold(key, "max-age"):
			// RFC 6265 5.2.2: 1*DIGIT, optionally preceded by '-'.
			neg := len(val) > 0 && val[0] == '-'
			if n, nok := parse_decimal(val[1:] if neg else val); nok { cookie.max_age_secs = -n if neg else n }
		case ascii_equal_fold(key, "samesite"):
			switch {
			case ascii_equal_fold(val, "lax"):    cookie.same_site = .Lax
			case ascii_equal_fold(val, "none"):   cookie.same_site = .None
			case ascii_equal_fold(val, "strict"): cookie.same_site = .Strict
			}
		}
	}

	ok = true
	return
}

/*
Implementation of the algorithm described in RFC 6265 section 5.1.1.
*/
cookie_date_parse :: proc(value: string) -> (t: time.Time, ok: bool) {

	iter_delim :: proc(value: ^string) -> (token: string, ok: bool) {
		start := -1
		start_loop: for ch, i in transmute([]byte)value^ {
			switch ch {
			case 0x09, 0x20..=0x2F, 0x3B..=0x40, 0x5B..=0x60, 0x7B..=0x7E:
			case:
				start = i
				break start_loop
			}
		}

		if start == -1 {
			return
		}

		token = value[start:]
		length := len(token)
		end_loop: for ch, i in transmute([]byte)token {
			switch ch {
			case 0x09, 0x20..=0x2F, 0x3B..=0x40, 0x5B..=0x60, 0x7B..=0x7E:
				length = i
				break end_loop
			}
		}

		ok = true

		token  = token[:length]
		value^ = value[start+length:]
		return
	}

	parse_digits :: proc(value: string, min, max: int, trailing_ok: bool) -> (int, bool) {
		count: int
		for ch in transmute([]byte)value {
			if ch <= 0x2f || ch >= 0x3a {
				break
			}
			count += 1
		}

		if count < min || count > max {
			return 0, false
		}

		if !trailing_ok && len(value) != count {
			return 0, false
		}

		return strconv.parse_int(value[:count], 10)
	}

	parse_time :: proc(token: string) -> (t: Time, ok: bool) {
		hours, match1, tail := strings.partition(token, ":")
		if match1 != ":" { return }
		minutes, match2, seconds := strings.partition(tail,  ":")
		if match2 != ":" { return }

		t.hours   = parse_digits(hours,   1, 2, false) or_return
		t.minutes = parse_digits(minutes, 1, 2, false) or_return
		t.seconds = parse_digits(seconds, 1, 2, true)  or_return

		ok = true
		return
	}

	parse_month :: proc(token: string) -> (month: int) {
		if len(token) < 3 {
			return
		}

		lower: [3]byte
		for &ch, i in lower {
			#no_bounds_check orig := token[i]
			switch orig {
			case 'A'..='Z':
				ch = orig + 32
			case:
				ch = orig
			}
		}

		switch string(lower[:]) {
		case "jan":
			return 1
		case "feb":
			return 2
		case "mar":
			return 3
		case "apr":
			return 4
		case "may":
			return 5
		case "jun":
			return 6
		case "jul":
			return 7
		case "aug":
			return 8
		case "sep":
			return 9
		case "oct":
			return 10
		case "nov":
			return 11
		case "dec":
			return 12
		case:
			return
		}
	}

	Time :: struct {
		hours, minutes, seconds: int,
	}

	clock: Maybe(Time)
	day_of_month, month, year: Maybe(int)

	value := value
	for token in iter_delim(&value) {
		if _, has_time := clock.?; !has_time {
			if t, tok := parse_time(token); tok {
				clock = t
				continue
			}
		}

		if _, has_day_of_month := day_of_month.?; !has_day_of_month {
			if dom, dok := parse_digits(token, 1, 2, true); dok {
				day_of_month = dom
				continue
			}
		}

		if _, has_month := month.?; !has_month {
			if mon := parse_month(token); mon > 0 {
				month = mon
				continue
			}
		}

		if _, has_year := year.?; !has_year {
			if yr, yrok := parse_digits(token, 2, 4, true); yrok {

				if yr >= 70 && yr <= 99 {
					yr += 1900
				} else if yr >= 0 && yr <= 69 {
					yr += 2000
				}

				year = yr
				continue
			}
		}
	}

	c := clock.? or_return
	y := year.?  or_return

	if y < 1601 {
		return
	}

	t = time.datetime_to_time(
		y,
		month.?        or_return,
		day_of_month.? or_return,
		c.hours,
		c.minutes,
		c.seconds,
	) or_return

	ok = true
	return
}

/*
Retrieves the cookie with the given `key` out of the requests `Cookie` header.

If the same key is in the header multiple times the first one is returned: browsers send cookies with
more specific paths first, and a sibling (sub)domain can add a cookie with the same name but can't
make it come first.
*/
request_cookie_get :: proc(r: ^Request, key: string) -> (value: string, ok: bool) {
	cookies := headers_get_unsafe(r.headers, "cookie") or_return

	for k, v in request_cookies_iter(&cookies) {
		if key == k { return v, true }
	}

	return
}

/*
Allocates a map with the given allocator and puts all cookie pairs from the requests `Cookie` header into it.

If the same key is in the header multiple times the first one is kept, see `request_cookie_get`.
*/
request_cookies :: proc(r: ^Request, allocator := context.temp_allocator) -> (res: map[string]string) {
	res.allocator = allocator

	cookies := headers_get_unsafe(r.headers, "cookie") or_else ""
	for k, v in request_cookies_iter(&cookies) {
		if k in res { continue }
		res[k] = v
	}

	return
}

/*
Iterates the `name=value` pairs of a Cookie header from left to right. Pairs are separated by ';'
(with optional whitespace); pairs without '=' or with an empty name are skipped. A value in double
quotes is returned without them.
*/
request_cookies_iter :: proc(cookies: ^string) -> (key: string, value: string, ok: bool) {
	for len(cookies) > 0 {
		pair: string
		if semi := strings.index_byte(cookies^, ';'); semi >= 0 {
			pair, cookies^ = cookies[:semi], cookies[semi + 1:]
		} else {
			pair, cookies^ = cookies^, ""
		}

		eq := strings.index_byte(pair, '=')
		if eq < 0 { continue }
		key   = trim_ows(pair[:eq])
		value = trim_ows(pair[eq + 1:])
		if len(key) == 0 { continue }
		if len(value) >= 2 && value[0] == '"' && value[len(value) - 1] == '"' {
			value = value[1:len(value) - 1]
		}
		return key, value, true
	}
	return
}
