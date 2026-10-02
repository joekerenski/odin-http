package tests_server

import "base:runtime"

import "core:fmt"
import "core:strings"
import "core:testing"
import "core:time"

import http "../.."

@(private="file")
test_router: http.Router

@(private="file", init)
router_setup :: proc "contextless" () {
	context = runtime.default_context()
	context.allocator = runtime.heap_allocator()
	http.router_init(&test_router)
	http.route_get(&test_router, "/users/:id", http.handler(proc(req: ^http.Request, res: ^http.Response) {
		id, _ := http.url_param(req, "id")
		http.respond_plain(res, fmt.tprintf("user %s raw %s", id, req.url_params[0]))
	}))
	http.route_post(&test_router, "/users/:id", http.handler(proc(req: ^http.Request, res: ^http.Response) {
		http.respond_plain(res, "posted")
	}))
	http.route_add_pattern(&test_router, .Get, "/slow/(.*)/(.*)/(.*)/x", http.handler(proc(req: ^http.Request, res: ^http.Response) {
		http.respond_plain(res, "slow")
	}))
}

@(test)
router_end_to_end :: proc(t: ^testing.T) {
	ts := server_start(t, http.router_handler(&test_router))
	defer server_stop(ts)

	resp := roundtrip(ts, "GET /users/a%20b HTTP/1.1\r\nHost: x\r\n\r\n")
	testing.expectf(t, strings.has_suffix(resp, "user a b raw a%20b"), "got %q", resp)

	resp = roundtrip(ts, "DELETE /users/1 HTTP/1.1\r\nHost: x\r\n\r\n")
	testing.expectf(t, status_of(resp) == 405 && (strings.contains(resp, "allow: GET, POST") || strings.contains(resp, "allow: POST, GET")), "got %q", resp)

	resp = roundtrip(ts, "GET /nope HTTP/1.1\r\nHost: x\r\n\r\n")
	testing.expectf(t, status_of(resp) == 404, "got %q", resp)

	// A long path against the backtracking pattern: answered (404) quickly.
	start := time.tick_now()
	resp = roundtrip(ts, strings.concatenate({"GET /slow", strings.repeat("/", 7000, context.temp_allocator), " HTTP/1.1\r\nHost: x\r\n\r\n"}, context.temp_allocator))
	testing.expectf(t, status_of(resp) == 404, "got %q", resp)
	testing.expectf(t, time.tick_since(start) < 2 * time.Second, "took %v", time.tick_since(start))
}
