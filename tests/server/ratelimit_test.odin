package tests_server

import "core:fmt"
import "core:strings"
import "core:testing"
import "core:time"

import http "../.."

@(test)
rate_limit_rules :: proc(t: ^testing.T) {
	ok_handler := http.handler(proc(_: ^http.Request, res: ^http.Response) { http.respond_plain(res, "ok") })
	opts := http.Rate_Limit_Opts{window = 5 * time.Second, max = 2, max_clients = 3, trusted_proxies = 1}
	data: http.Rate_Limit_Data
	limited := http.rate_limit(&data, &ok_handler, &opts)
	defer http.rate_limit_destroy(&data)

	ts := server_start(t, limited)
	defer server_stop(ts)

	req :: proc(ts: ^Test_Server, client: string) -> string {
		return roundtrip(ts, fmt.tprintf("GET / HTTP/1.1\r\nHost: x\r\nX-Forwarded-For: 6.6.6.6, %s\r\nConnection: close\r\n\r\n", client), wait = 200 * time.Millisecond)
	}

	// Exactly `max` requests are allowed.
	testing.expect(t, status_of(req(ts, "1.1.1.1")) == 200)
	testing.expect(t, status_of(req(ts, "1.1.1.1")) == 200)
	resp := req(ts, "1.1.1.1")
	testing.expectf(t, status_of(resp) == 429, "third request: %q", resp)
	testing.expectf(t, strings.contains(resp, "retry-after: 5") || strings.contains(resp, "retry-after: 4"), "got %q", resp)

	// The right-most X-Forwarded-For entry is the key, the spoofable left part isn't.
	testing.expect(t, status_of(req(ts, "2.2.2.2")) == 200)

	// IPv6 clients in the same /64 share a bucket.
	testing.expect(t, status_of(req(ts, "2001:db8::1")) == 200)
	testing.expect(t, status_of(req(ts, "2001:db8::2")) == 200)
	testing.expect(t, status_of(req(ts, "2001:db8::3")) == 429)

	// Table full (3 clients tracked): new clients are limited.
	testing.expect(t, status_of(req(ts, "4.4.4.4")) == 429)
}
