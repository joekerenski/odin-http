// Echo server for the Autobahn TestSuite (fuzzingclient), see autobahn/run.sh.
//
//	odin run autobahn/server -o:speed -- 9001
package autobahn_server

import "core:fmt"
import "core:log"
import "core:mem"
import "core:net"
import "core:os"
import "core:strconv"

import http "../.."
import ws "../../websocket"

main :: proc() {
	context.logger = log.create_console_logger(.Error)

	port := 9001
	if len(os.args) > 1 { port, _ = strconv.parse_int(os.args[1]) }

	s: http.Server
	handler := http.handler(proc(req: ^http.Request, res: ^http.Response) {
		// Autobahn's case 9 sends messages up to 16MiB.
		opts := ws.Opts{
			max_message_size = 64 * mem.Megabyte,
			send_queue_limit = 256 * mem.Megabyte,
			ping_interval    = -1,
			check_origin     = ws.allow_any_origin,
			compression      = true,
		}
		ws.upgrade(req, res, opts, {
			on_message = proc(c: ^ws.Conn, kind: ws.Message_Kind, data: []byte) {
				if ws.send(c, kind, data) == .Queue_Full {
					log.error("send queue full")
				}
			},
		})
	})

	http.server_shutdown_on_interrupt(&s)
	// Any address so the suite can reach it from inside its container.
	fmt.println(http.listen_and_serve(&s, handler, net.Endpoint{address = net.IP4_Any, port = port}))
}
