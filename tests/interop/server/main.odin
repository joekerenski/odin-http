// Server for the interop tests (tests/interop/test_interop.py, run by scripts/interop.sh): real
// clients (curl, Python, Caddy as a reverse proxy) against the endpoints below.
//
//	interop <port> <file> [<tls port> <cert> <key>]
//
// <file> is served at /file (ranges). With a TLS port the same routes are also served over the
// server's own TLS (HSTS on), for testing it without Caddy.
package interop_server

import "core:crypto/sha2"
import "core:encoding/hex"
import "core:fmt"
import "core:io"
import "core:log"
import "core:mem"
import "core:net"
import "core:os"
import "core:strconv"
import "core:strings"
import "core:thread"
import "core:time"

import http "../../.."
import ws "../../../websocket"

file_path: string

sha_hex :: proc(sha: ^sha2.Context_256) -> string {
	sum: [sha2.DIGEST_SIZE_256]byte
	sha2.final(sha, sum[:])
	return string(hex.encode(sum[:], context.temp_allocator))
}

main :: proc() {
	context.logger = log.create_console_logger(.Debug if os.get_env("DEBUG", context.temp_allocator) != "" else .Warning)
	if len(os.args) < 3 {
		fmt.eprintln("usage: interop <port> <file> [<tls port> <cert> <key>]")
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

	// The body streamed (body_stream): "<bytes> <sha256 hex>".
	http.route_post(&router, "/upload", http.handler(proc(req: ^http.Request, res: ^http.Response) {
		Up :: struct { req: ^http.Request, res: ^http.Response, n: int, sha: sha2.Context_256 }
		up := new(Up, context.temp_allocator)
		up^ = {req = req, res = res}
		sha2.init_256(&up.sha)
		http.body_stream(req, -1, up, proc(up: rawptr, data: []byte, done: bool, err: http.Body_Error) {
			up := (^Up)(up)
			if err != nil {
				http.respond(up.res, http.body_error_status(err))
				return
			}
			up.n += len(data)
			sha2.update(&up.sha, data)
			if !done {
				http.body_stream_next(up.req)
				return
			}
			http.respond_plain(up.res, fmt.tprintf("%i %s", up.n, sha_hex(&up.sha)))
		})
	}))

	// Rejects the upload after its first piece, 413.
	http.route_post(&router, "/upload-reject", http.handler(proc(req: ^http.Request, res: ^http.Response) {
		http.body_stream(req, -1, res, proc(res: rawptr, _: []byte, _: bool, err: http.Body_Error) {
			http.respond((^http.Response)(res), http.Status.Payload_Too_Large)
		})
	}))

	// A multipart/form-data form, streamed: a line per part, "<name>|<filename>|<content type>|<bytes>|<sha256 hex>".
	http.route_post(&router, "/form", http.handler(proc(req: ^http.Request, res: ^http.Response) {
		Form :: struct { req: ^http.Request, res: ^http.Response, out: strings.Builder, n: int, sha: sha2.Context_256 }
		f := new(Form, context.temp_allocator)
		f^ = {req = req, res = res, out = strings.builder_make(context.temp_allocator)}
		http.multipart_stream(req, -1, f, proc(f: rawptr, event: http.Multipart_Event, part: ^http.Multipart_Part, data: []byte, err: http.Multipart_Error) {
			f := (^Form)(f)
			switch event {
			case .Part:
				f.n = 0
				sha2.init_256(&f.sha)
			case .Data:
				f.n += len(data)
				sha2.update(&f.sha, data)
			case .Part_End:
				fmt.sbprintf(&f.out, "%s|%s|%s|%i|%s\n", part.name, part.filename, part.content_type, f.n, sha_hex(&f.sha))
			case .Done:
				if err != nil {
					http.respond(f.res, http.multipart_error_status(err))
				} else {
					http.respond_plain(f.res, strings.to_string(f.out))
				}
				return
			}
			http.multipart_next(f.req)
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

	handler := http.router_handler(&router)
	if len(os.args) >= 6 {
		tls_port, _ := strconv.parse_int(os.args[3])
		tls_opts := opts
		tls_opts.tls = http.TLS_Opts{cert_file = os.args[4], key_file = os.args[5], hsts_max_age = 24 * time.Hour}
		TLS_Server :: struct { s: http.Server, handler: http.Handler, port: int, opts: http.Server_Opts }
		ts := new(TLS_Server)
		ts^ = {handler = handler, port = tls_port, opts = tls_opts}
		thread.create_and_start_with_poly_data(ts, proc(ts: ^TLS_Server) {
			err := http.listen_and_serve(&ts.s, ts.handler, net.Endpoint{address = net.IP4_Loopback, port = ts.port}, ts.opts)
			if err != nil { fmt.eprintln("listen (TLS):", err) }
		}, context)
	}

	err := http.listen_and_serve(&s, handler, net.Endpoint{address = net.IP4_Loopback, port = port}, opts)
	if err != nil { fmt.eprintln("listen:", err) }
}
