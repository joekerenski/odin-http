// The WebSocket client against Caddy (wss://) and the interop server, run by
// tests/interop/test_interop.py (Proxy.test_odin_ws_client). Prints one line per check, exits 1
// if any failed.
//
//	interop-client <caddy root CA (PEM)>
package interop_client

import "core:bytes"
import "core:fmt"
import "core:log"
import "core:mem"
import "core:nbio"
import "core:os"
import "core:strings"
import "core:time"

import ws "../../../websocket"

ca_file: string
failed: bool

main :: proc() {
	context.logger = log.create_console_logger(.Error)
	if len(os.args) < 2 {
		fmt.eprintln("usage: interop-client <ca file>")
		os.exit(2)
	}
	ca_file = os.args[1]
	if err := nbio.acquire_thread_event_loop(); err != nil {
		fmt.eprintln("event loop:", err)
		os.exit(1)
	}

	echo("wss echo, compressed", "wss://localhost:8443/ws", true)
	echo("wss echo, uncompressed", "wss://localhost:8443/ws", false)
	echo("ws echo, direct", "ws://127.0.0.1:8080/ws", true)
	echo("wss to an IP address certificate", "wss://127.0.0.1:8446/ws", false, small = true)
	concurrent("wss, 50 connections at once", "wss://localhost:8443/ws", 50)

	// Verification can't be skipped: Caddy's CA isn't in the system store...
	refused("wss, untrusted CA", "wss://localhost:8443/ws", "", "certificate verification failed")
	// ...and a valid certificate for another name is refused (alias.test resolves to 127.0.0.1,
	// Caddy answers unknown names with the certificate for localhost).
	refused("wss, certificate for another host", "wss://alias.test:8443/ws", ca_file, "mismatch")

	os.exit(1 if failed else 0)
}

Run :: struct {
	send:       [][]byte,
	got:        int,
	opened:     bool,
	closed:     bool,
	compressed: bool,
	code:       u16,
	reason:     [256]byte,
	reason_len: int,
	mismatch:   string,
}

callbacks :: proc(r: ^Run) -> ws.Callbacks {
	return {
		user_data = r,
		on_open = proc(c: ^ws.Conn) {
			r := (^Run)(c.user_data)
			r.opened = true
			r.compressed = c.compressed
			for m, i in r.send {
				ws.send(c, .Text if i % 2 == 0 else .Binary, m)
			}
			if len(r.send) == 0 { ws.close(c) }
		},
		on_message = proc(c: ^ws.Conn, kind: ws.Message_Kind, data: []byte) {
			r := (^Run)(c.user_data)
			if r.got < len(r.send) && r.mismatch == "" && !bytes.equal(data, r.send[r.got]) {
				r.mismatch = fmt.aprintf("echo %i: got %i bytes, want %i", r.got, len(data), len(r.send[r.got]))
			}
			r.got += 1
			if r.got == len(r.send) { ws.close(c) }
		},
		on_close = proc(c: ^ws.Conn, code: u16, reason: string) {
			r := (^Run)(c.user_data)
			r.closed = true
			r.code = code
			r.reason_len = copy(r.reason[:], reason)
		},
	}
}

wait :: proc(runs: []Run, limit := 30 * time.Second) {
	start := time.tick_now()
	loop: for time.tick_since(start) < limit {
		for r in runs { if !r.closed { nbio.tick(10 * time.Millisecond); continue loop } }
		return
	}
}

report :: proc(name: string, ok: bool, detail: string) {
	if ok {
		fmt.printfln("ok   %s", name)
	} else {
		fmt.printfln("FAIL %s: %s", name, detail)
		failed = true
	}
}

messages :: proc(small: bool) -> [][]byte {
	sizes := []int{0, 1, 125, 126, 65535, 65536, mem.Megabyte, 5 * mem.Megabyte}
	if small { sizes = sizes[:5] }
	msgs := make([dynamic][]byte)
	for size in sizes {
		m := make([]byte, size)
		for &b, i in m { b = 'a' + byte((i * 7 + i / 13) % 26) }
		append(&msgs, m)
	}
	// Then many small ones, pipelined.
	for i in 0 ..< (10 if small else 2000) {
		append(&msgs, transmute([]byte)fmt.aprintf("message %i %s", i, strings.repeat("x", i % 50)))
	}
	return msgs[:]
}

echo :: proc(name, url: string, compression: bool, small := false) {
	runs := []Run{{send = messages(small)}}
	r := &runs[0]
	if _, err := ws.dial(url, {opts = {compression = compression, max_message_size = 16 * mem.Megabyte, send_queue_limit = 64 * mem.Megabyte}, tls_ca_file = ca_file}, callbacks(r)); err != nil {
		report(name, false, fmt.tprint("dial:", err))
		return
	}
	wait(runs)
	switch {
	case !r.opened:
		report(name, false, fmt.tprintf("never opened: %v %s", r.code, string(r.reason[:r.reason_len])))
	case r.mismatch != "":
		report(name, false, r.mismatch)
	case r.got != len(r.send) || r.code != 1000:
		report(name, false, fmt.tprintf("%i/%i echoes, close %v %s", r.got, len(r.send), r.code, string(r.reason[:r.reason_len])))
	case r.compressed != compression:
		report(name, false, fmt.tprintf("compression negotiated: %v", r.compressed))
	case:
		report(name, true, "")
	}
}

concurrent :: proc(name, url: string, n: int) {
	runs := make([]Run, n)
	for &r, i in runs {
		r.send = make([][]byte, 20)
		for &m, j in r.send { m = transmute([]byte)fmt.aprintf("conn %i message %i %s", i, j, strings.repeat("y", (i * j) % 3000)) }
		if _, err := ws.dial(url, {opts = {compression = i % 2 == 0}, tls_ca_file = ca_file}, callbacks(&r)); err != nil {
			report(name, false, fmt.tprint("dial:", err))
			return
		}
	}
	wait(runs)
	for &r, i in runs {
		if !r.opened || r.mismatch != "" || r.got != len(r.send) || r.code != 1000 {
			report(name, false, fmt.tprintf("connection %i: opened=%v %i/%i %s close %v %s", i, r.opened, r.got, len(r.send), r.mismatch, r.code, string(r.reason[:r.reason_len])))
			return
		}
	}
	report(name, true, "")
}

refused :: proc(name, url, ca: string, want: string) {
	runs := []Run{{}}
	r := &runs[0]
	if _, err := ws.dial(url, {tls_ca_file = ca, timeout = 5 * time.Second}, callbacks(r)); err != nil {
		report(name, false, fmt.tprint("dial:", err))
		return
	}
	wait(runs)
	reason := string(r.reason[:r.reason_len])
	report(name, !r.opened && r.code == 1006 && strings.contains(reason, want),
		fmt.tprintf("opened=%v %v %q, want a failure mentioning %q", r.opened, r.code, reason, want))
}
