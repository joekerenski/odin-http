// Server for the interop tests (tests/interop/test_interop.py, run by scripts/interop.sh): real
// clients (curl, Python, Caddy as a reverse proxy) against the endpoints below.
//
//	interop <port> <file>   <file> is served at /file (ranges, conditional requests)
package interop_server

import "core:fmt"
import "core:io"
import "core:log"
import "core:mem"
import "core:net"
import "core:os"
import "core:strconv"
import "core:time"

import http "../../.."
import ws "../../../websocket"

file_path: string

main :: proc() {
	context.logger = log.create_console_logger(.Debug if os.get_env("DEBUG", context.temp_allocator) != "" else .Warning)
	if len(os.args) < 3 {
		fmt.eprintln("usage: interop <port> <file>")
		os.exit(2)
	}
	port, _ := strconv.parse_int(os.args[1])
	file_path = os.args[2]

	router: http.Router
	http.router_init(&router)

	// Plain response.
	http.route_get(&router, "/hello", http.handler(proc(_: ^http.Request, res: ^http.Response) {
		http.respond_plain(res, "hello")
	}))

	// The request body (Content-Length or chunked, Expect: 100-continue honoured), back as is.
	http.route_post(&router, "/echo", http.handler(proc(req: ^http.Request, res: ^http.Response) {
		http.body(req, -1, res, proc(res: rawptr, body: http.Body, err: http.Body_Error) {
			res := (^http.Response)(res)
			if err != nil {
				http.respond(res, http.body_error_status(err))
				return
			}
			http.headers_set_content_type(&res.headers, "application/octet-stream")
			http.body_set(res, body)
			http.respond(res, http.Status.OK)
		})
	}))

	// ?size=N bytes of a known pattern (byte i is i % 251).
	http.route_get(&router, "/big", http.handler(proc(req: ^http.Request, res: ^http.Response) {
		size, _ := strconv.parse_int(http.query_get(req.url, "size"))
		size = clamp(size, 0, 64 * mem.Megabyte)
		buf := make([]byte, size, context.temp_allocator)
		for &b, i in buf { b = byte(i % 251) }
		http.headers_set_content_type(&res.headers, "application/octet-stream")
		http.body_set(res, buf)
		http.respond(res, http.Status.OK)
	}))

	// ?n=N lines, sent with chunked Transfer-Encoding.
	http.route_get(&router, "/stream", http.handler(proc(req: ^http.Request, res: ^http.Response) {
		n, _ := strconv.parse_int(http.query_get(req.url, "n"))
		buf: [512]byte
		res.status = .OK // Before the writer, which writes the heading.
		rw: http.Response_Writer
		w := http.response_writer_init(&rw, res, buf[:])
		for i in 0 ..< clamp(n, 0, 100_000) {
			fmt.wprintf(w, "line %i\n", i)
		}
		io.close(w)
	}))

	http.route_get(&router, "/file", http.handler(proc(_: ^http.Request, res: ^http.Response) {
		http.respond_file(res, file_path)
	}))

	// The client address the server attributes the request to (what the rate limiter keys on),
	// assuming one trusted proxy.
	http.route_get(&router, "/whoami", http.handler(proc(req: ^http.Request, res: ^http.Response) {
		http.respond_plain(res, net.to_string(http.request_client_key(req, 1), context.temp_allocator))
	}))

	// 3 requests per client per minute, behind one proxy.
	limited_inner := http.handler(proc(_: ^http.Request, res: ^http.Response) { http.respond_plain(res, "ok") })
	limit_opts := http.Rate_Limit_Opts{window = time.Minute, max = 3, trusted_proxies = 1}
	limit_data: http.Rate_Limit_Data
	http.route_get(&router, "/limited", http.rate_limit(&limit_data, &limited_inner, &limit_opts))

	// WebSocket echo, compression offered, the default (same origin) check.
	http.route_get(&router, "/ws", http.handler(proc(req: ^http.Request, res: ^http.Response) {
		ws.upgrade(req, res, {compression = true, max_message_size = 16 * mem.Megabyte, send_queue_limit = 64 * mem.Megabyte}, {
			on_message = proc(c: ^ws.Conn, kind: ws.Message_Kind, data: []byte) { ws.send(c, kind, data) },
		})
	}))

	s: http.Server
	http.server_shutdown_on_interrupt(&s)
	opts := http.Default_Server_Opts
	opts.thread_count = 2
	opts.max_body_size = 32 * mem.Megabyte
	// Shorter than Caddy's pool idle timeout (2 minutes), so the tests see the server closing pooled connections.
	opts.idle_timeout = 2 * time.Second
	err := http.listen_and_serve(&s, http.router_handler(&router), net.Endpoint{address = net.IP4_Loopback, port = port}, opts)
	if err != nil { fmt.eprintln("listen:", err) }
}
