package tests_unit

import "core:testing"
import "core:time"

import http "../.."

@(private="file")
noop := http.Handler{handle = proc(_: ^http.Handler, _: ^http.Request, _: ^http.Response) {}}

@(test)
segment_routes :: proc(t: ^testing.T) {
	r: http.Router
	http.router_init(&r)
	defer http.router_destroy(&r)

	http.route_get(&r, "/", noop)
	http.route_get(&r, "/users/:id", noop)
	http.route_get(&r, "/users/:id/comments/:cid", noop)
	http.route_get(&r, "/dir/", noop)
	http.route_get(&r, "/static/*path", noop)
	http.route_post(&r, "/users", noop)

	Case :: struct { method: http.Method, path, pattern: string, params: []string }
	cases := []Case{
		{.Get, "/", "/", {}},
		{.Get, "/users/42", "/users/:id", {"42"}},
		{.Get, "/users/a%2Fb", "/users/:id", {"a%2Fb"}},
		{.Get, "/users/42/comments/7", "/users/:id/comments/:cid", {"42", "7"}},
		{.Get, "/dir/", "/dir/", {}},
		{.Get, "/static", "/static/*path", {""}},
		{.Get, "/static/", "/static/*path", {""}},
		{.Get, "/static/a/b.css", "/static/*path", {"a/b.css"}},
		{.Post, "/users", "/users", {}},
		{.Get, "/users", "", nil},
		{.Get, "/users/", "", nil},
		{.Get, "/users//comments/7", "", nil},
		{.Get, "/users/42/", "", nil},
		{.Get, "/users/42/comments", "", nil},
		{.Get, "/dir", "", nil},
		{.Get, "//", "", nil},
		{.Get, "", "", nil},
		{.Get, "users/42", "", nil},
		{.Put, "/users", "", nil},
	}
	for c in cases {
		route, params, ok := http.router_match(&r, c.method, c.path)
		if c.pattern == "" {
			testing.expectf(t, !ok, "%v %q matched %q", c.method, c.path, route.pattern if ok else "")
			continue
		}
		testing.expectf(t, ok && route.pattern == c.pattern, "%v %q: want %q, got %v", c.method, c.path, c.pattern, route.pattern if ok else "<none>")
		if ok {
			testing.expectf(t, len(params) == len(c.params), "%q params %v", c.path, params)
			for p, i in c.params {
				if i < len(params) { testing.expectf(t, params[i] == p, "%q params %v", c.path, params) }
			}
		}
	}
}

@(test)
pattern_routes_are_bounded :: proc(t: ^testing.T) {
	r: http.Router
	http.router_init(&r)
	defer http.router_destroy(&r)

	// Pathological backtracking pattern.
	http.route_add_pattern(&r, .Get, "/(.*)/(.*)/edit", noop)

	_, params, ok := http.router_match(&r, .Get, "/a/b/edit")
	testing.expect(t, ok && len(params) == 2 && params[0] == "a" && params[1] == "b")

	// 8000 slashes: without the length cap this takes seconds.
	path := make([]byte, 8000, context.temp_allocator)
	for &b in path { b = '/' }
	start := time.tick_now()
	_, _, ok = http.router_match(&r, .Get, string(path))
	testing.expect(t, !ok)
	testing.expectf(t, time.tick_since(start) < 50 * time.Millisecond, "took %v", time.tick_since(start))

	// Invalid UTF-8 doesn't match (and doesn't log errors).
	_, _, ok = http.router_match(&r, .Get, "/\xff/x/edit")
	testing.expect(t, !ok)
}
