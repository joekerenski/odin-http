package http

import "base:runtime"

import "core:log"
import "core:net"
import "core:strconv"
import "core:strings"
import "core:text/match"

URL :: struct {
	raw:    string, // All other fields are views/slices into this string.
	scheme: string,
	host:   string,
	path:   string,
	query:  string,
}

// Splits a URL or request-target into its parts (no decoding or validation is done).
//
// A target starting with '/' (origin-form) is all path (and query); only other targets are checked
// for a "scheme://host" prefix. The fragment ('#...') is dropped.
url_parse :: proc(raw: string) -> (url: URL) {
	url.raw = raw
	s := raw

	if i := strings.index_byte(s, '#'); i >= 0 {
		s = s[:i]
	}

	// Per RFC 3986 3.4 the query component can contain both ':' and '/' characters unescaped.
	// Since the scheme may be absent in a HTTP request line, the query should be separated first.
	if i := strings.index_byte(s, '?'); i >= 0 {
		url.query = s[i+1:]
		s = s[:i]
	}

	if len(s) > 0 && s[0] == '/' {
		url.path = s
		return
	}

	if i := strings.index(s, "://"); i >= 0 {
		url.scheme = s[:i]
		s = s[i+3:]
	}

	if i := strings.index_byte(s, '/'); i == -1 {
		url.host = s
	} else {
		url.host = s[:i]
		url.path = s[i:]
	}

	return
}

Query_Entry :: struct {
	key, value: string,
}

query_iter :: proc(query: ^string) -> (entry: Query_Entry, ok: bool) {
	if len(query) == 0 { return }

	ok = true

	param: string
	i := strings.index(query^, "&")
	if i < 0 {
		param = query^
		query^ = ""
	} else {
		param = query[:i]
		query^ = query[i+1:]
	}

	i = strings.index(param, "=")
	if i < 0 {
		entry.key = param
		entry.value = ""
		return
	}

	entry.key = param[:i]
	entry.value = param[i+1:]

	return
}

query_get :: proc(url: URL, key: string) -> (val: string, ok: bool) #optional_ok {
	q := url.query
	for entry in #force_inline query_iter(&q) {
		if entry.key == key {
			return entry.value, true
		}
	}
	return
}

query_get_percent_decoded :: proc(url: URL, key: string, allocator := context.temp_allocator) -> (val: string, ok: bool) {
	str := query_get(url, key) or_return
	return net.percent_decode(str, allocator)
}

query_get_bool :: proc(url: URL, key: string) -> (result, set: bool) #optional_ok {
	str := query_get(url, key) or_return
	set = true
	switch str {
	case "", "false", "0", "no":
	case:
		result = true
	}
	return
}

query_get_int :: proc(url: URL, key: string, base := 0) -> (result: int, ok: bool, set: bool) {
	str := query_get(url, key) or_return
	set = true
	result, ok = strconv.parse_int(str, base)
	return
}

query_get_uint :: proc(url: URL, key: string, base := 0) -> (result: uint, ok: bool, set: bool) {
	str := query_get(url, key) or_return
	set = true
	result, ok = strconv.parse_uint(str, base)
	return
}

// Routing.
//
// The default route syntax is segment based, matched in linear time:
//
//	"/users/:id/comments/:comment"   ":name" matches exactly one non-empty path segment
//	"/static/" + "*path"             "*name" (last segment only) matches the rest of the path, possibly empty
//	"/about"                         anything else matches literally, trailing slashes included
//
// Captured values are in `req.url_params` (in order, raw/percent-encoded as received) and can be
// looked up by name, percent-decoded, with `url_param`.
//
// Lua patterns (`core:text/match`) are still available through `route_add_pattern` and
// `route_all_pattern`. Backtracking patterns can take super-linear time on hostile paths, so they
// only run against paths up to `Router.max_pattern_path` bytes (longer paths never match them),
// and position captures `()` are rejected.
Route :: struct {
	handler:  Handler,
	// The pattern as given by the user.
	pattern:  string,
	kind:     Route_Kind,
	// For segment routes: the pattern split on '/'.
	segments: []string,
	// For segment routes: the capture names, in order.
	names:    []string,
}

Route_Kind :: enum u8 {
	Segments,
	Lua_Pattern,
}

Router :: struct {
	allocator:        runtime.Allocator,
	routes:           map[Method][dynamic]Route,
	all:              [dynamic]Route,
	// Paths longer than this never match Lua pattern routes. Defaults to 256.
	max_pattern_path: int,
}

router_init :: proc(router: ^Router, allocator := context.allocator) {
	router.allocator = allocator
	router.routes = make(map[Method][dynamic]Route, len(Method), allocator)
	router.max_pattern_path = 256
}

router_destroy :: proc(router: ^Router) {
	context.allocator = router.allocator

	route_destroy :: proc(route: Route) {
		delete(route.pattern)
		delete(route.segments)
		delete(route.names)
	}

	for route in router.all {
		route_destroy(route)
	}
	delete(router.all)

	for _, routes in router.routes {
		for route in routes {
			route_destroy(route)
		}
		delete(routes)
	}

	delete(router.routes)
}

// Returns a handler that matches against the given routes.
//
// If no route matches, but a route for another method matches the path, a 405 with an Allow header
// is sent; otherwise a 404.
router_handler :: proc(router: ^Router) -> Handler {
	h: Handler
	h.user_data = router

	h.handle = proc(handler: ^Handler, req: ^Request, res: ^Response) {
		router := (^Router)(handler.user_data)
		rline := req.line.(Requestline)

		if routes_try(router, router.routes[rline.method][:], req, res) {
			return
		}

		if routes_try(router, router.all[:], req, res) {
			return
		}

		allowed: [len(Method)]string
		n_allowed := 0
		for method, routes in router.routes {
			if method == rline.method { continue }
			for &route in routes {
				if _, ok := route_match(router, &route, req.url.path, nil); ok {
					allowed[n_allowed] = method_string(method)
					n_allowed += 1
					break
				}
			}
		}
		if n_allowed > 0 {
			headers_set_unsafe(&res.headers, "allow", strings.join(allowed[:n_allowed], ", ", context.temp_allocator))
			res.status = .Method_Not_Allowed
			respond(res)
			return
		}

		log.debugf("no route matched %s %s", method_string(rline.method), rline.target)
		res.status = .Not_Found
		respond(res)
	}

	return h
}

// Adds a segment route (see the package docs above) for the given method.
route_add :: proc(router: ^Router, method: Method, pattern: string, handler: Handler, loc := #caller_location) {
	route := route_make_segments(router, pattern, handler, loc)
	route_append(router, method, route)
}

// Adds a Lua pattern route for the given method, the pattern is anchored (`^...$`).
route_add_pattern :: proc(router: ^Router, method: Method, pattern: string, handler: Handler, loc := #caller_location) {
	route := route_make_pattern(router, pattern, handler, loc)
	route_append(router, method, route)
}

route_get     :: proc(router: ^Router, pattern: string, handler: Handler, loc := #caller_location) { route_add(router, .Get, pattern, handler, loc) }
route_post    :: proc(router: ^Router, pattern: string, handler: Handler, loc := #caller_location) { route_add(router, .Post, pattern, handler, loc) }
route_put     :: proc(router: ^Router, pattern: string, handler: Handler, loc := #caller_location) { route_add(router, .Put, pattern, handler, loc) }
route_patch   :: proc(router: ^Router, pattern: string, handler: Handler, loc := #caller_location) { route_add(router, .Patch, pattern, handler, loc) }
route_delete  :: proc(router: ^Router, pattern: string, handler: Handler, loc := #caller_location) { route_add(router, .Delete, pattern, handler, loc) }
route_options :: proc(router: ^Router, pattern: string, handler: Handler, loc := #caller_location) { route_add(router, .Options, pattern, handler, loc) }
route_trace   :: proc(router: ^Router, pattern: string, handler: Handler, loc := #caller_location) { route_add(router, .Trace, pattern, handler, loc) }
route_connect :: proc(router: ^Router, pattern: string, handler: Handler, loc := #caller_location) { route_add(router, .Connect, pattern, handler, loc) }
// NOTE: this does not get called when `Server_Opts.redirect_head_to_get` is set to true.
route_head    :: proc(router: ^Router, pattern: string, handler: Handler, loc := #caller_location) { route_add(router, .Head, pattern, handler, loc) }

// Adds a catch-all fallback segment route (all methods, ran if no other routes match).
route_all :: proc(router: ^Router, pattern: string, handler: Handler, loc := #caller_location) {
	route_all_append(router, route_make_segments(router, pattern, handler, loc))
}

// Adds a catch-all fallback Lua pattern route (all methods, ran if no other routes match).
route_all_pattern :: proc(router: ^Router, pattern: string, handler: Handler, loc := #caller_location) {
	route_all_append(router, route_make_pattern(router, pattern, handler, loc))
}

// Looks up a named capture of the matched segment route, percent-decoded.
url_param :: proc(req: ^Request, name: string, allocator := context.temp_allocator) -> (value: string, ok: bool) {
	route := req._route
	if route == nil { return }
	for n, i in route.names {
		if n == name && i < len(req.url_params) {
			return net.percent_decode(req.url_params[i], allocator)
		}
	}
	return
}

@(private)
route_all_append :: proc(router: ^Router, route: Route) {
	if router.all == nil {
		router.all = make([dynamic]Route, 0, 1, router.allocator)
	}
	append(&router.all, route)
}

@(private)
route_append :: proc(router: ^Router, method: Method, route: Route) {
	if method not_in router.routes {
		router.routes[method] = make([dynamic]Route, router.allocator)
	}

	append(&router.routes[method], route)
}

@(private)
route_make_segments :: proc(router: ^Router, pattern: string, handler: Handler, loc := #caller_location) -> Route {
	assert(len(pattern) > 0 && pattern[0] == '/', "segment routes must start with '/'", loc)

	route := Route{handler = handler, kind = .Segments}
	route.pattern  = strings.clone(pattern, router.allocator)
	route.segments = strings.split(route.pattern, "/", router.allocator)

	names := make([dynamic]string, router.allocator)
	for seg, i in route.segments {
		if len(seg) == 0 { continue }
		switch seg[0] {
		case ':':
			assert(len(seg) > 1, "a ':' capture needs a name", loc)
			append(&names, seg[1:])
		case '*':
			assert(len(seg) > 1, "a '*' capture needs a name", loc)
			assert(i == len(route.segments) - 1, "a '*' capture must be the last segment", loc)
			append(&names, seg[1:])
		}
	}
	route.names = names[:]
	return route
}

@(private)
route_make_pattern :: proc(router: ^Router, pattern: string, handler: Handler, loc := #caller_location) -> Route {
	// A position capture "()" yields byte offsets past the subject, and slicing with them panics.
	assert(!strings.contains(pattern, "()"), "position captures '()' are not supported in routes", loc)

	return Route{
		handler = handler,
		kind    = .Lua_Pattern,
		pattern = strings.concatenate([]string{"^", pattern, "$"}, router.allocator),
	}
}

// Matches `path` against the route. When `captures` is non-nil the captured values are stored in it
// (allocated in the temp allocator).
@(private)
route_match :: proc(router: ^Router, route: ^Route, path: string, captures: ^[]string) -> (n: int, ok: bool) {
	switch route.kind {
	case .Segments:
		caps: [dynamic]string
		if captures != nil {
			caps = make([dynamic]string, 0, len(route.names), context.temp_allocator)
		}
		defer if ok && captures != nil { captures^ = caps[:] }

		if len(path) == 0 || path[0] != '/' { return 0, false }
		p := path[1:]

		// segments[0] is the empty string before the pattern's leading '/'.
		for seg, i in route.segments[1:] {
			is_last := i == len(route.segments) - 2

			if len(seg) > 0 && seg[0] == '*' {
				if captures != nil { append(&caps, p) }
				return n + 1, true
			}

			part, has_more := p, false
			if slash := strings.index_byte(p, '/'); slash >= 0 {
				part, p, has_more = p[:slash], p[slash + 1:], true
			} else {
				p = ""
			}

			if len(seg) > 0 && seg[0] == ':' {
				if len(part) == 0 { return 0, false }
				if captures != nil { append(&caps, part) }
				n += 1
			} else if part != seg {
				return 0, false
			}

			if is_last {
				// Extra path segments (or a trailing '/') the pattern doesn't have.
				if has_more { return 0, false }
				return n, true
			}

			if !has_more {
				// The path ended early, only a final '*' segment can still match (empty).
				next := route.segments[i + 2]
				if i + 2 == len(route.segments) - 1 && len(next) > 0 && next[0] == '*' {
					if captures != nil { append(&caps, "") }
					return n + 1, true
				}
				return 0, false
			}
		}
		return n, true

	case .Lua_Pattern:
		if len(path) > router.max_pattern_path { return 0, false }

		try_captures: [match.MAX_CAPTURES]match.Match = ---
		count, err := match.find_aux(path, route.pattern, 0, true, &try_captures)
		if err != .OK {
			// Most likely invalid UTF-8 in the path, which can't match anyway.
			log.debugf("route %q: match error %v", route.pattern, err)
			return 0, false
		}
		if count == 0 { return 0, false }

		if captures != nil {
			caps := make([]string, count - 1, context.temp_allocator)
			for cap, i in try_captures[1:count] {
				if cap.byte_start < 0 || cap.byte_end > len(path) || cap.byte_start > cap.byte_end { return 0, false }
				caps[i] = path[cap.byte_start:cap.byte_end]
			}
			captures^ = caps
		}
		return count - 1, true
	}
	return 0, false
}

@(private)
routes_try :: proc(router: ^Router, routes: []Route, req: ^Request, res: ^Response) -> bool {
	for &route in routes {
		captures: []string
		if _, ok := route_match(router, &route, req.url.path, &captures); ok {
			req.url_params = captures
			req._route = &route
			rh := route.handler
			rh.handle(&rh, req, res)
			return true
		}
	}

	return false
}

// Finds the route that would handle `method` + `path`, without calling it. Fallback (`route_all`)
// routes are considered after the method's routes. Captures are allocated in the temp allocator.
router_match :: proc(router: ^Router, method: Method, path: string) -> (route: ^Route, params: []string, ok: bool) {
	if routes, has := router.routes[method]; has {
		for &r in routes {
			if _, matched := route_match(router, &r, path, &params); matched {
				return &r, params, true
			}
		}
	}
	for &r in router.all {
		if _, matched := route_match(router, &r, path, &params); matched {
			return &r, params, true
		}
	}
	return
}
