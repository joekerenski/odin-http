package http

import "base:runtime"

import "core:net"
import "core:strconv"
import "core:strings"
import "core:sync"
import "core:time"

Handler_Proc :: proc(handler: ^Handler, req: ^Request, res: ^Response)
Handle_Proc :: proc(req: ^Request, res: ^Response)

Handler :: struct {
	user_data: rawptr,
	next:      Maybe(^Handler),
	handle:    Handler_Proc,
}

// TODO: something like http.handler_with_body which gets the body before calling the handler.

handler :: proc(handle: Handle_Proc) -> Handler {
	h: Handler
	h.user_data = rawptr(handle)

	handle := proc(h: ^Handler, req: ^Request, res: ^Response) {
		p := (Handle_Proc)(h.user_data)
		p(req, res)
	}

	h.handle = handle
	return h
}

middleware_proc :: proc(next: Maybe(^Handler), handle: Handler_Proc) -> Handler {
	h: Handler
	h.next = next
	h.handle = handle
	return h
}

Rate_Limit_On_Limit :: struct {
	user_data: rawptr,
	on_limit:  proc(req: ^Request, res: ^Response, user_data: rawptr),
}

// Convenience method to create a Rate_Limit_On_Limit that writes the given message.
rate_limit_message :: proc(message: ^string) -> Rate_Limit_On_Limit {
	return Rate_Limit_On_Limit{user_data = message, on_limit = proc(_: ^Request, res: ^Response, user_data: rawptr) {
		message := (^string)(user_data)
		body_set(res, message^)
		respond(res)
	}}
}

Rate_Limit_Opts :: struct {
	window:      time.Duration,
	// Requests allowed per client per window.
	max:         int,

	// Optional handler to call when a request is being rate-limited, allows you to customize the response.
	on_limit:    Maybe(Rate_Limit_On_Limit),

	// The most clients tracked per window, defaults to 100_000. Once full, requests from clients that
	// aren't tracked yet are limited (fail closed) until the window ends, so the table can't be used
	// to exhaust memory.
	max_clients: int,

	// How many reverse proxies, that each append to X-Forwarded-For, are in front of the server.
	// 0 (default) uses the TCP peer address. With 1 (e.g. Caddy), the right-most X-Forwarded-For entry
	// is used, which the proxy set to the address it saw. Only set this when clients can't reach the
	// server directly, otherwise they can pick their own key.
	trusted_proxies: int,
}

Rate_Limit_Data :: struct {
	opts:       ^Rate_Limit_Opts,
	next_sweep: time.Time,
	hits:       map[net.Address]int,
	allocator:  runtime.Allocator,
	mu:         sync.Mutex,
}

rate_limit_destroy :: proc(data: ^Rate_Limit_Data) {
	sync.guard(&data.mu)
	delete(data.hits)
}

// The address a request is attributed to: the TCP peer, or with `trusted_proxies > 0` the matching
// X-Forwarded-For entry (falling back to the peer when the header is missing or malformed).
// IPv6 addresses are reduced to their /64 prefix, a single client typically controls a whole /64.
request_client_key :: proc(req: ^Request, trusted_proxies: int) -> net.Address {
	addr := req.client.address

	if trusted_proxies > 0 {
		if xff, has := headers_get_unsafe(req.headers, "x-forwarded-for"); has {
			// The proxies each appended one entry, the one we want is `trusted_proxies` from the right.
			entries := strings.split(xff, ",", context.temp_allocator)
			if idx := len(entries) - trusted_proxies; idx >= 0 {
				if parsed := net.parse_address(trim_ows(entries[idx])); parsed != nil {
					addr = parsed
				}
			}
		}
	}

	if ip6, is_ip6 := addr.(net.IP6_Address); is_ip6 {
		for i in 4 ..< 8 { ip6[i] = 0 }
		addr = ip6
	}
	return addr
}

// Basic fixed-window rate limit per client address.
rate_limit :: proc(data: ^Rate_Limit_Data, next: ^Handler, opts: ^Rate_Limit_Opts, allocator := context.allocator) -> Handler {
	assert(next != nil)

	h: Handler
	h.next = next

	if opts.max_clients <= 0 { opts.max_clients = 100_000 }

	data.opts = opts
	data.allocator = allocator
	data.hits = make(map[net.Address]int, 16, allocator)
	data.next_sweep = time.time_add(time.now(), opts.window)
	h.user_data = data

	h.handle = proc(h: ^Handler, req: ^Request, res: ^Response) {
		data := (^Rate_Limit_Data)(h.user_data)
		key := request_client_key(req, data.opts.trusted_proxies)

		limited: bool
		retry_after: time.Duration
		{
			sync.guard(&data.mu)

			now := time.now()
			if time.diff(data.next_sweep, now) >= 0 {
				// Re-make instead of clear, so a burst of clients doesn't pin the map's capacity.
				delete(data.hits)
				data.hits = make(map[net.Address]int, 16, data.allocator)
				data.next_sweep = time.time_add(now, data.opts.window)
			}

			if hits, tracked := &data.hits[key]; tracked {
				hits^ += 1
				limited = hits^ > data.opts.max
			} else if len(data.hits) >= data.opts.max_clients {
				limited = true
			} else {
				data.hits[key] = 1
				limited = 1 > data.opts.max
			}
			retry_after = time.diff(now, data.next_sweep)
		}

		if limited {
			res.status = .Too_Many_Requests

			// Round up, and never tell a client to retry "now".
			secs := max(1, i64((retry_after + time.Second - 1) / time.Second))
			buf := make([]byte, 32, context.temp_allocator)
			headers_set_unsafe(&res.headers, "retry-after", strconv.write_int(buf, secs, 10))

			if on, ok := data.opts.on_limit.(Rate_Limit_On_Limit); ok {
				on.on_limit(req, res, on.user_data)
			} else {
				respond(res)
			}
			return
		}

		next := h.next.(^Handler)
		next.handle(next, req, res)
	}

	return h
}
