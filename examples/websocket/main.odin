// A chat: every message sent to /chat goes to everyone connected. Open http://localhost:8080 in a
// few tabs.
//
//	odin run examples/websocket
package websocket_example

import "core:fmt"
import "core:log"
import "core:net"
import "core:sync"

import http "../.."
import ws "../../websocket"

// The connected clients. Connections live on the server's threads; handles can be used from any.
members: struct {
	mu:      sync.Mutex,
	handles: [dynamic]ws.Handle,
}

PAGE :: `<!doctype html>
<input id=msg autofocus placeholder="say something"><pre id=log></pre>
<script>
const sock = new WebSocket("ws://" + location.host + "/chat")
sock.onmessage = e => log.textContent += e.data + "\n"
msg.onkeydown = e => { if (e.key == "Enter") { sock.send(msg.value); msg.value = "" } }
</script>`

main :: proc() {
	context.logger = log.create_console_logger(.Info)

	router: http.Router
	http.router_init(&router)
	defer http.router_destroy(&router)

	http.route_get(&router, "/", http.handler(proc(_: ^http.Request, res: ^http.Response) {
		http.respond_html(res, PAGE)
	}))

	http.route_get(&router, "/chat", http.handler(proc(req: ^http.Request, res: ^http.Response) {
		ws.upgrade(req, res, {compression = true}, {
			on_open = proc(c: ^ws.Conn) {
				sync.guard(&members.mu)
				append(&members.handles, ws.handle(c))
			},
			on_message = proc(c: ^ws.Conn, kind: ws.Message_Kind, data: []byte) {
				if kind != .Text { return }
				msg := fmt.tprintf("%i: %s", ws.handle(c).id, string(data))
				sync.guard(&members.mu)
				ws.broadcast(members.handles[:], .Text, transmute([]byte)msg)
			},
			on_close = proc(c: ^ws.Conn, _: u16, _: string) {
				h := ws.handle(c)
				sync.guard(&members.mu)
				for other, i in members.handles {
					if other == h { unordered_remove(&members.handles, i); break }
				}
			},
		})
	}))

	s: http.Server
	http.server_shutdown_on_interrupt(&s)
	log.info("listening on http://localhost:8080")
	if err := http.listen_and_serve(&s, http.router_handler(&router), net.Endpoint{net.IP4_Loopback, 8080}); err != nil {
		log.error(err)
	}
}
