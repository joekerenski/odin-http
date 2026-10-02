// Benchmark server. Builds against any version of the library (no router, only APIs that exist
// upstream too), so numbers can be compared across versions:
//
//	odin build bench/server -o:speed -collection:lib=<path containing the http package dir>
package bench_server

import "core:fmt"
import "core:log"
import "core:net"
import "core:os"
import "core:strconv"
import "core:strings"

import http "lib:http"

BIG: string

main :: proc() {
	context.logger = log.create_console_logger(.Error)
	BIG = strings.repeat("x", 64 * 1024)

	port := 8081
	if len(os.args) > 1 { port, _ = strconv.parse_int(os.args[1]) }

	s: http.Server
	handler := http.handler(proc(req: ^http.Request, res: ^http.Response) {
		switch req.url.path {
		case "/plain":
			http.respond_plain(res, "Hello, World!")
		case "/json":
			res.status = .OK
			http.headers_set_content_type(&res.headers, "application/json")
			http.body_set(res, `{"message":"Hello, World!"}`)
			http.respond(res)
		case "/big":
			http.respond_plain(res, BIG)
		case "/echo":
			http.body(req, -1, res, proc(res: rawptr, body: http.Body, err: http.Body_Error) {
				res := (^http.Response)(res)
				if err != nil {
					http.respond(res, http.body_error_status(err))
					return
				}
				http.respond_plain(res, body)
			})
		case:
			if strings.has_prefix(req.url.path, "/static/") {
				http.respond_dir(res, "/static", "bench/static", req.url.path)
				return
			}
			http.respond(res, http.Status.Not_Found)
		}
	})

	opts := http.Default_Server_Opts
	when #config(NO_TIMEOUTS, false) {
		opts.idle_timeout      = -1
		opts.header_timeout    = -1
		opts.body_read_timeout = -1
		opts.write_timeout     = -1
	}

	http.server_shutdown_on_interrupt(&s)
	fmt.println(http.listen_and_serve(&s, handler, net.Endpoint{address = net.IP4_Loopback, port = port}, opts))
}
