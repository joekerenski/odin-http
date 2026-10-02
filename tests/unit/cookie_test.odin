package tests_unit

import "core:testing"

import http "../.."

@(test)
cookie_validation :: proc(t: ^testing.T) {
	testing.expect(t, http.cookie_valid({name = "session", value = "abc123"}))
	testing.expect(t, http.cookie_valid({name = "s", value = ""}))
	testing.expect(t, http.cookie_valid({name = "s", value = "\"quoted\""}))
	testing.expect(t, http.cookie_valid({name = "s", value = "v", domain = "example.com", path = "/a"}))

	testing.expect(t, !http.cookie_valid({name = "", value = "v"}))
	testing.expect(t, !http.cookie_valid({name = "a b", value = "v"}))
	testing.expect(t, !http.cookie_valid({name = "a=b", value = "v"}))
	testing.expect(t, !http.cookie_valid({name = "s", value = "x; Domain=evil.com"}))
	testing.expect(t, !http.cookie_valid({name = "s", value = "x\r\nInjected: 1"}))
	testing.expect(t, !http.cookie_valid({name = "s", value = "a,b"}))
	testing.expect(t, !http.cookie_valid({name = "s", value = "a b"}))
	testing.expect(t, !http.cookie_valid({name = "s", value = "v", domain = "evil.com; Path=/"}))
	testing.expect(t, !http.cookie_valid({name = "s", value = "v", path = "/\r\nx"}))
}

@(test)
set_cookie_parse :: proc(t: ^testing.T) {
	c, ok := http.cookie_parse("a=b; Priority=High; Path=/; SameSite=lax; Max-Age=-1; Expires=garbage; HttpOnly")
	testing.expect(t, ok)
	testing.expect(t, c.name == "a" && c.value == "b")
	testing.expect(t, c.path.? == "/" && c.same_site == .Lax && c.max_age_secs.? == -1 && c.http_only)
	_, has_expires := c.expires_gmt.?
	testing.expect(t, !has_expires)

	c, ok = http.cookie_parse("name=; Path=/")
	testing.expect(t, ok && c.name == "name" && c.value == "")

	c, ok = http.cookie_parse(" a = b ")
	testing.expect(t, ok && c.name == "a" && c.value == "b")

	_, ok = http.cookie_parse("=b")
	testing.expect(t, !ok)
	_, ok = http.cookie_parse("novalue")
	testing.expect(t, !ok)
}

@(test)
request_cookie_header :: proc(t: ^testing.T) {
	Pair :: struct { k, v: string }
	collect :: proc(header: string) -> [dynamic]Pair {
		out := make([dynamic]Pair, context.temp_allocator)
		h := header
		for k, v in http.request_cookies_iter(&h) { append(&out, Pair{k, v}) }
		return out
	}

	got := collect("a=1; b=2;c=3 ;  d = 4")
	testing.expectf(t, len(got) == 4 && got[0] == {"a", "1"} && got[2] == {"c", "3"} && got[3] == {"d", "4"}, "%v", got)

	got = collect("bad; =x; a=\"q\"; ; b=")
	testing.expectf(t, len(got) == 2 && got[0] == {"a", "q"} && got[1] == {"b", ""}, "%v", got)

	got = collect("")
	testing.expect(t, len(got) == 0)
}
