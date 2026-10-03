// Autobahn TestSuite client driver (fuzzingserver mode), see autobahn/run-client.sh.
//
// Asks the fuzzing server for the number of cases, runs each one (echoing every message back),
// then asks it to write the report.
//
//	odin run autobahn/client -o:speed -- ws://127.0.0.1:9001
package autobahn_client

import "core:fmt"
import "core:log"
import "core:mem"
import "core:nbio"
import "core:os"
import "core:strconv"

import ws "../../websocket"

AGENT :: "odin-http"

base:  string
cases: int
next:  int
done:  bool

opts := ws.Dial_Opts{
	opts = {
		// Case 9 sends messages up to 16MiB.
		max_message_size = 64 * mem.Megabyte,
		send_queue_limit = 256 * mem.Megabyte,
		ping_interval    = -1,
		compression      = true,
	},
}

main :: proc() {
	context.logger = log.create_console_logger(.Error)
	base = os.args[1] if len(os.args) > 1 else "ws://127.0.0.1:9001"

	if err := nbio.acquire_thread_event_loop(); err != nil {
		fmt.eprintln("event loop:", err)
		os.exit(1)
	}
	defer nbio.release_thread_event_loop()

	start(fmt.aprintf("%s/getCaseCount", base), {
		on_message = proc(_: ^ws.Conn, _: ws.Message_Kind, data: []byte) {
			cases, _ = strconv.parse_int(string(data))
		},
		on_close = proc(_: ^ws.Conn, _: u16, reason: string) {
			if cases <= 0 {
				fmt.eprintln("could not get the case count:", reason)
				done = true
				return
			}
			fmt.printfln("running %i cases", cases)
			run_next()
		},
	})

	for !done {
		if err := nbio.tick(); err != nil {
			fmt.eprintln("tick:", err)
			os.exit(1)
		}
	}
}

start :: proc(url: string, cb: ws.Callbacks) {
	if _, err := ws.dial(url, opts, cb); err != nil {
		fmt.eprintfln("dial %s: %v", url, err)
		done = true
	}
}

run_next :: proc() {
	next += 1
	if next > cases {
		start(fmt.aprintf("%s/updateReports?agent=%s", base, AGENT), {
			on_close = proc(_: ^ws.Conn, _: u16, _: string) {
				fmt.println("report written")
				done = true
			},
		})
		return
	}
	if next % 50 == 0 { fmt.printfln("case %i/%i", next, cases) }
	start(fmt.aprintf("%s/runCase?case=%i&agent=%s", base, next, AGENT), {
		on_message = proc(c: ^ws.Conn, kind: ws.Message_Kind, data: []byte) {
			ws.send(c, kind, data)
		},
		on_close = proc(_: ^ws.Conn, _: u16, _: string) {
			run_next()
		},
	})
}
