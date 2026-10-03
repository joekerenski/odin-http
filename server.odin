package http

import "base:runtime"

import "core:bufio"
import "core:c/libc"
import "core:log"
import "core:mem"
import "core:mem/virtual"
import "core:nbio"
import "core:net"
import "core:os"
import "core:slice"
import "core:strings"
import "core:sync"
import "core:thread"
import "core:time"

Server_Opts :: struct {
	// Whether the server should accept every request that sends a "Expect: 100-continue" header automatically.
	// The interim 100 response is sent when the handler starts reading the body.
	// Defaults to true.
	auto_expect_continue:    bool,
	// When this is true, any HEAD request is automatically redirected to the handler as a GET request.
	// The body is never sent for a HEAD request.
	// Defaults to true.
	redirect_head_to_get:    bool,
	// Limit the maximum number of bytes to read for the request line (first line of request containing the URI).
	// The HTTP spec does not specify any limits but in practice it is safer.
	// RFC 9112 3: It is RECOMMENDED that all HTTP senders and recipients support,
	// at a minimum, request-line lengths of 8000 octets.
	// defaults to 8000.
	limit_request_line:      int,
	// Limit the total size of the header section (and, separately, of the trailer section), in bytes,
	// including line endings.
	// The HTTP spec does not specify any limits but in practice it is safer.
	// defaults to 8000.
	limit_headers:           int,
	// Limit the number of header (and trailer) field lines, defaults to 100.
	limit_header_count:      int,
	// The maximum request body size the server will read, in bytes. A handler can ask for less
	// with the `max_length` argument of `body`, but never for more.
	// Bodies over the limit get a 413 and the connection is closed. Defaults to 8MiB.
	max_body_size:           int,
	// The thread count to use, defaults to your core count.
	thread_count:            int,
	// The maximum number of open connections, across all threads. When reached, the server stops
	// accepting (new connections wait in the kernel's backlog) until a connection closes.
	// 0 means no limit other than the operating system's.
	max_connections:         int,

	// Timeouts. A zero value means the default, a negative value disables the timeout.
	// They are checked periodically, so one fires up to a quarter of the shortest timeout late (at most a
	// second).
	//
	// How long a keep-alive connection may sit idle waiting for the next request. Defaults to 3 minutes.
	// When the server runs behind a reverse proxy that pools connections, keep this above the
	// proxy's idle timeout (Caddy: 2 minutes), so the proxy is the one closing idle connections.
	idle_timeout:            time.Duration,
	// How long the client may take to send a request head (request line + headers). Exceeding
	// it gets a 408 and the connection is closed. Defaults to 30 seconds.
	header_timeout:          time.Duration,
	// How long a body read may go without receiving any data. Defaults to 30 seconds.
	body_read_timeout:       time.Duration,
	// How long a response write may go without making any progress. Defaults to 30 seconds.
	write_timeout:           time.Duration,
	// How long a graceful shutdown waits for active requests before forcefully closing their
	// connections. Defaults to 30 seconds.
	shutdown_timeout:        time.Duration,
}

Default_Server_Opts := Server_Opts {
	auto_expect_continue    = true,
	redirect_head_to_get    = true,
	limit_request_line      = 8000,
	limit_headers           = 8000,
	limit_header_count      = 100,
	max_body_size           = 8 * mem.Megabyte,
	idle_timeout            = 3 * time.Minute,
	header_timeout          = 30 * time.Second,
	body_read_timeout       = 30 * time.Second,
	write_timeout           = 30 * time.Second,
	shutdown_timeout        = 30 * time.Second,
}

Server_State :: enum {
	Uninitialized,
	Idle,
	Listening,
	Serving,
	Running,
	Closing,
	Cleaning,
	Closed,
}

Server :: struct {
	opts:           Server_Opts,
	tcp_sock:       net.TCP_Socket,
	conn_allocator: mem.Allocator,
	handler:        Handler,

	threads:        []Server_Thread,
	// Once the server starts closing/shutdown this is set to true, all threads will check it
	// and start their thread local shutdown procedure.
	closing:        Atomic(bool),
	// Threads will decrement the wait group when they have fully closed/shutdown.
	// The main thread waits on this to clean up global data and return.
	threads_closed: sync.Wait_Group,
	// Open connections across all threads, used for `max_connections`.
	conn_count:     Atomic(int),
}

Server_Thread :: struct {
	server:       ^Server,
	thread:       ^thread.Thread,
	event_loop:   ^nbio.Event_Loop,
	conns:        map[net.TCP_Socket]^Connection,
	state:        Server_State,
	accept:       ^nbio.Operation,
	// A pending timer that re-arms accepting (back-off after errors, or waiting for room under
	// `max_connections`).
	accept_retry: ^nbio.Operation,

	// Updated every second with an updated date, this speeds up the server considerably
	// because it would otherwise need to call time.now() and format the date on each response.
	// Every thread has its own, so no synchronization is needed.
	date:         Server_Date,
	date_timer:   ^nbio.Operation,
	signal_timer: ^nbio.Operation,
	sweep_timer:  ^nbio.Operation,
}

@(private, disabled = ODIN_DISABLE_ASSERT)
assert_has_td :: #force_inline proc(loc := #caller_location) {
	assert(td != nil && td.state != .Uninitialized, "The thread you are calling from is not a server/handler thread", loc)
}

@(thread_local)
td: ^Server_Thread

Default_Endpoint := net.Endpoint {
	address = net.IP4_Any,
	port    = 8080,
}

listen :: proc(
	s: ^Server,
	endpoint: net.Endpoint = Default_Endpoint,
	opts: Server_Opts = Default_Server_Opts,
) -> (err: net.Network_Error) {
	s.opts = opts
	// Zero values mean "use the default", so a partially filled `Server_Opts{...}` stays safe.
	if s.opts.limit_request_line <= 0 { s.opts.limit_request_line = Default_Server_Opts.limit_request_line }
	if s.opts.limit_headers      <= 0 { s.opts.limit_headers      = Default_Server_Opts.limit_headers }
	if s.opts.limit_header_count <= 0 { s.opts.limit_header_count = Default_Server_Opts.limit_header_count }
	if s.opts.max_body_size      <= 0 { s.opts.max_body_size      = Default_Server_Opts.max_body_size }
	if s.opts.max_connections    <  0 { s.opts.max_connections    = 0 }
	if s.opts.idle_timeout       == 0 { s.opts.idle_timeout       = Default_Server_Opts.idle_timeout }
	if s.opts.header_timeout     == 0 { s.opts.header_timeout     = Default_Server_Opts.header_timeout }
	if s.opts.body_read_timeout  == 0 { s.opts.body_read_timeout  = Default_Server_Opts.body_read_timeout }
	if s.opts.write_timeout      == 0 { s.opts.write_timeout      = Default_Server_Opts.write_timeout }
	if s.opts.shutdown_timeout   == 0 { s.opts.shutdown_timeout   = Default_Server_Opts.shutdown_timeout }
	s.conn_allocator = context.allocator

	if acquire_err := nbio.acquire_thread_event_loop(); acquire_err != nil {
		// The enum holds raw OS error codes, most have no name, so log the number.
		when ODIN_OS == .Linux {
			log.errorf("could not acquire event loop (os error %i): io_uring may be unavailable or blocked, e.g. by a container seccomp profile", i32(acquire_err))
		} else {
			log.errorf("could not acquire event loop (os error %i)", i32(acquire_err))
		}
		return net.Create_Socket_Error.Insufficient_Resources
	}

	s.tcp_sock, err = nbio.listen_tcp(endpoint)
	if err != nil {
		nbio.release_thread_event_loop()
		atomic_store(&s.closing, true)
	}
	return
}

serve :: proc(s: ^Server, h: Handler) -> (err: net.Network_Error) {
	if atomic_load(&s.closing) { return }
	s.handler = h

	if s.opts.thread_count == 0 {
		s.opts.thread_count = os.get_processor_core_count()
	}

	thread_count := max(1, s.opts.thread_count)
	sync.wait_group_add(&s.threads_closed, thread_count)
	s.threads = make([]Server_Thread, thread_count, s.conn_allocator)
	for &td in s.threads[1:] {
		td.thread = thread.create_and_start_with_poly_data2(s, &td, _server_thread_init, context)
	}

	_server_thread_init(s, &s.threads[0])

	sync.wait(&s.threads_closed)

	log.debug("server threads are done, shutting down")

	net.shutdown(s.tcp_sock, .Both)
	net.close(s.tcp_sock)
	for t in s.threads[1:] { thread.destroy(t.thread) }
	delete(s.threads, s.conn_allocator)

	return nil
}

listen_and_serve :: proc(
	s: ^Server,
	h: Handler,
	endpoint: net.Endpoint = Default_Endpoint,
	opts: Server_Opts = Default_Server_Opts,
) -> (err: net.Network_Error) {
	listen(s, endpoint, opts) or_return
	return serve(s, h)
}

_server_thread_init :: proc(s: ^Server, ttd: ^Server_Thread) {
	td = ttd
	td.server = s

	td.conns = make(map[net.TCP_Socket]^Connection)

	if td != &s.threads[0] {
		if err := nbio.acquire_thread_event_loop(); err != nil {
			// Can't serve on this thread, the others carry on.
			log.errorf("server thread could not acquire an event loop: %v", err)
			delete(td.conns)
			sync.wait_group_done(&s.threads_closed)
			return
		}
	}

	td.event_loop = nbio.current_thread_event_loop()

	// Start keeping track of and caching the date for the required date header.
	server_date_start(td)
	server_sweep_start(td)

	if td == &s.threads[0] && atomic_load(&on_interrupt_server) == s {
		_server_watch_interrupts(td)
	}

	log.debug("accepting connections")
	server_accept(td)

	log.debug("starting event loop")
	td.state = .Serving
	for td.state != .Closed {
		if atomic_load(&s.closing) {
			_server_thread_shutdown(s)
			break
		}

		err := nbio.tick()
		if err != nil {
			log.errorf("non-blocking io tick error: %v", err)
			_server_thread_shutdown(s)
			break
		}
	}

	log.debug("event loop end")

	if td != &s.threads[0] {
		runtime.default_temp_allocator_destroy(auto_cast context.temp_allocator.data)
	}
	sync.wait_group_done(&s.threads_closed)
}

// The time between checks and closes of connections in a graceful shutdown.
@(private)
SHUTDOWN_INTERVAL :: time.Millisecond * 100

// Starts a graceful shutdown.
//
// 1. Stops 'serve' from accepting new connections.
// 2. Close and free non-active connections.
// 3. Repeat 2 every SHUTDOWN_INTERVAL until no more connections are open.
//    After `Server_Opts.shutdown_timeout`, active connections are shut down forcefully.
// 4. Close the main socket.
// 5. Signal 'serve' it can return.
//
// Safe to call from any thread.
server_shutdown :: proc(s: ^Server) {
	atomic_store(&s.closing, true)
	for t in s.threads {
		if t.event_loop != nil {
			nbio.wake_up(t.event_loop)
		}
	}
}

_server_thread_shutdown :: proc(s: ^Server, loc := #caller_location) {
	assert_has_td(loc)

	td.state = .Closing
	defer delete(td.conns)

	nbio.remove(td.accept);       td.accept       = nil
	nbio.remove(td.accept_retry); td.accept_retry = nil
	nbio.remove(td.date_timer);   td.date_timer   = nil
	nbio.remove(td.signal_timer); td.signal_timer = nil
	nbio.remove(td.sweep_timer);  td.sweep_timer  = nil

	start  := time.tick_now()
	forced := false
	for len(td.conns) > 0 {
		force := s.opts.shutdown_timeout > 0 && time.tick_since(start) > s.opts.shutdown_timeout

		for sock, conn in td.conns {
			#partial switch conn.state {
			case .Active, .Will_Close:
				if force && !forced {
					// Shutting the socket down makes the pending operations of the connection
					// fail, which runs the normal cleanup path.
					log.warnf("shutdown: forcefully closing active connection %i", sock)
					net.shutdown(sock, .Both)
				} else {
					log.debugf("shutdown: connection %i still active", sock)
				}
			case .Hijacked:
				hijacked_on_server_shutdown(conn, force && !forced)
			case .New, .Idle, .Pending:
				log.debugf("shutdown: closing connection %i", sock)
				// The connection waits for a request: shutting down the read side too ends that
				// read, which would otherwise wait for a keep-alive client that stays quiet (and
				// with it the event loop, which runs until no operation is pending).
				net.shutdown(sock, .Both)
				connection_close(conn)
			case .Closing:
				log.debugf("shutdown: connection %i is closing", sock)
			case .Closed:
				log.warn("closed connection in connections map, maybe a race or logic error")
			}
		}
		if force { forced = true }

		server_sweep_conns(td)

		// Give up on connections that don't finish even after being shut down: their handler never
		// responded and has no I/O pending. Their memory is leaked on purpose, the handler may
		// still hold on to the request/response.
		if forced && time.tick_since(start) > 2 * s.opts.shutdown_timeout + 2 * Conn_Close_Delay {
			log.warnf("shutdown: abandoning %i connections whose handlers never responded", len(td.conns))
			// Their sockets have no I/O pending (and the loop goes away), close them so the
			// file descriptors don't leak with the memory.
			for sock in td.conns {
				net.close(sock)
			}
			break
		}

		if err := nbio.tick(SHUTDOWN_INTERVAL); err != nil {
			log.errorf("IO tick error during shutdown: %v", err)
			break
		}
	}

	td.state = .Cleaning

	nbio.run()
	nbio.release_thread_event_loop()

	td.state = .Closed

	log.info("shutdown: done")
}

@(private)
on_interrupt_server: Atomic(^Server)
@(private)
interrupt_count: Atomic(int)

// Registers a SIGINT handler to shutdown the server gracefully. A second SIGINT exits immediately.
//
// Call this before `serve`. Only one server can be registered.
server_shutdown_on_interrupt :: proc(s: ^Server) {
	atomic_store(&on_interrupt_server, s)

	// Only async-signal-safe things happen here: an atomic increment and _Exit. The server
	// notices the interrupt from a timer on its first thread.
	libc.signal(libc.SIGINT, proc "c" (_: i32) {
		if sync.atomic_add(&interrupt_count.raw, 1) >= 1 {
			libc._Exit(1)
		}
	})
}

@(private)
_server_watch_interrupts :: proc(td: ^Server_Thread) {
	td.signal_timer = nbio.timeout_poly(100 * time.Millisecond, td, proc(_: ^nbio.Operation, td: ^Server_Thread) {
		td.signal_timer = nil
		if atomic_load(&interrupt_count) > 0 {
			log.info("interrupt received, shutting down")
			server_shutdown(td.server)
			return
		}
		_server_watch_interrupts(td)
	})
}

// Taken from Go's implementation,
// The maximum amount of bytes we will read (if handler did not)
// in order to get the connection ready for the next request.
@(private)
Max_Post_Handler_Discard_Bytes :: 256 << 10

// How long to wait before actually closing a connection.
// This is to make sure the client can fully receive the response.
@(private)
Conn_Close_Delay :: time.Millisecond * 500

Connection_State :: enum {
	Pending, // Pending a client to attach.
	New, // Got client, waiting to service first request.
	Active, // Servicing request.
	Idle, // Waiting for next request.
	Hijacked, // Taken over by another protocol (see `response_hijack`).
	Will_Close, // Closing after the current response is sent.
	Closing, // Going to close, cleaning up.
	Closed, // Fully closed.
}

@(private)
connection_set_state :: proc(c: ^Connection, s: Connection_State) -> bool {
	if s < .Closing && c.state >= .Closing {
		return false
	}

	if s == .Closing && c.state == .Closed {
		return false
	}

	c.state = s
	return true
}

// TODO/PERF: pool the connections, saves having to allocate scanner buf and temp_allocator every time.
Connection :: struct {
	server:         ^Server,
	socket:         net.TCP_Socket,
	state:          Connection_State,
	scanner:        Scanner,
	temp_allocator: virtual.Arena,
	loop:           Loop,

	// The in-flight write, see `connection_send`.
	send_buf:       []byte,
	send_done:      proc(c: ^Connection, ok: bool),

	// Deadlines of the pending read / write, zero for none. The thread's sweeper (`server_sweep`)
	// shuts the socket down once one passes, which fails the pending operation, and sets the
	// matching `_expired` flag so the failure is reported as a timeout.
	read_deadline:  time.Time,
	write_deadline: time.Time,
	read_expired:   bool,
	write_expired:  bool,
	// State of a pending "100 Continue" write.
	continue_state: rawptr,
	// Set once the connection is hijacked, see `response_hijack`.
	hijack:         ^Hijack_State,
}

// Loop/request cycle state.
@(private)
Loop :: struct {
	conn:              ^Connection,
	req:               Request,
	res:               Response,
	header_bytes_left: int,
	header_count:      int,
}

// Writes all of `buf` to the connection, failing if no progress is made for `write_timeout`.
// Only one write can be in flight per connection.
@(private)
connection_send :: proc(c: ^Connection, buf: []byte, done: proc(c: ^Connection, ok: bool)) {
	assert(c.send_done == nil, "a write is already in flight on this connection")

	if len(buf) == 0 {
		done(c, true)
		return
	}

	c.send_buf  = buf
	c.send_done = done

	send :: proc(c: ^Connection) {
		wt := c.server.opts.write_timeout
		c.write_deadline = time.time_add(nbio.now(), wt) if wt > 0 else {}
		nbio.send_poly(c.socket, {c.send_buf}, c, on_sent, all = false)
	}
	send(c)

	on_sent :: proc(op: ^nbio.Operation, c: ^Connection) {
		c.write_deadline = {}
		if op.send.err != nil || c.write_expired {
			if c.write_expired || op.send.err == net.TCP_Send_Error.Timeout {
				log.infof("write timed out on connection %i", c.socket)
			} else {
				log.debugf("could not send on connection %i: %v", c.socket, op.send.err)
			}
			done := c.send_done
			c.send_done = nil
			c.send_buf  = nil
			done(c, false)
			return
		}

		c.send_buf = c.send_buf[op.send.sent:]
		if len(c.send_buf) > 0 {
			send(c)
			return
		}

		done := c.send_done
		c.send_done = nil
		done(c, true)
	}
}

@(private)
connection_close :: proc(c: ^Connection, loc := #caller_location) {
	assert_has_td(loc)

	if c.state >= .Closing {
		log.debugf("connection %i already closing/closed", c.socket)
		return
	}

	log.debugf("closing connection: %i", c.socket)

	c.state = .Closing

	// RFC 9112 9.6: close the write side first, then wait a little bit, allowing the client
	// to process the closing and receive any remaining data.
	net.shutdown(c.socket, net.Shutdown_Manner.Send)

	nbio.timeout_poly(Conn_Close_Delay, c, proc(_: ^nbio.Operation, c: ^Connection) {
		nbio.close_poly(c.socket, c, proc(_: ^nbio.Operation, c: ^Connection) {
			log.debugf("closed connection: %i", c.socket)

			c.state = .Closed

			virtual.arena_destroy(&c.temp_allocator)

			scanner_destroy(&c.scanner)
			delete_key(&td.conns, c.socket)
			server := c.server
			free(c, server.conn_allocator)

			sync.atomic_sub(&server.conn_count.raw, 1)
			if td.accept == nil && td.accept_retry == nil && td.state == .Serving {
				server_accept(td)
			}
		})
	})
}

// Starts accepting a connection on the given server thread, unless the connection limit is reached,
// then it checks again shortly.
@(private)
server_accept :: proc(td: ^Server_Thread) {
	s := td.server
	if td.state > .Serving && td.state != .Uninitialized { return }
	if atomic_load(&s.closing) { return }

	if s.opts.max_connections > 0 && atomic_load(&s.conn_count) >= s.opts.max_connections {
		server_accept_retry(td, 50 * time.Millisecond)
		return
	}

	td.accept = nbio.accept_poly(s.tcp_sock, s, on_accept)
}

@(private)
server_accept_retry :: proc(td: ^Server_Thread, after: time.Duration) {
	if td.accept_retry != nil { return }
	td.accept_retry = nbio.timeout_poly(after, td, proc(_: ^nbio.Operation, td: ^Server_Thread) {
		td.accept_retry = nil
		server_accept(td)
	})
}

@(private)
on_accept :: proc(op: ^nbio.Operation, server: ^Server) {
	td.accept = nil

	if op.accept.err != nil {
		#partial switch op.accept.err {
		case .Aborted, .Interrupted, .Would_Block, .Timeout:
			// Transient, the client went away or we got interrupted.
			log.debugf("accept: %v, retrying", op.accept.err)
			server_accept(td)
		case .Insufficient_Resources:
			log.error("accept: out of resources (file descriptors?), trying again in a bit")
			server_accept_retry(td, 100 * time.Millisecond)
		case .Not_Listening, .Invalid_Argument, .Unsupported_Socket:
			// The listening socket is gone (shutdown) or unusable, nothing to retry.
			if !atomic_load(&server.closing) {
				log.errorf("accept: %v, this thread stops accepting connections", op.accept.err)
			}
		case:
			log.errorf("accept: %v, retrying in a second", op.accept.err)
			server_accept_retry(td, time.Second)
		}
		return
	}

	sync.atomic_add(&server.conn_count.raw, 1)

	// Accept next connection.
	server_accept(td)

	// Responses are written in as few sends as possible already; without this, a heading and body
	// sent separately (files, 100-continue) hit Nagle + delayed ACK stalls of ~40ms.
	net.set_option(op.accept.client, .TCP_Nodelay, true)

	c := new(Connection, server.conn_allocator)
	c.state = .New
	c.server = server
	c.socket = op.accept.client
	c.loop.req.client = op.accept.client_endpoint

	td.conns[c.socket] = c

	log.debugf("new connection with thread, got %d conns", len(td.conns))
	conn_handle_reqs(c)
}

@(private)
conn_handle_reqs :: proc(c: ^Connection) {
	scanner_init(&c.scanner, c, c.server.conn_allocator)

	if err := virtual.arena_init_growing(&c.temp_allocator); err != nil {
		log.errorf("could not allocate connection arena: %v", err)
		c.state = .Will_Close
		connection_close(c)
		return
	}
	context.temp_allocator = virtual.arena_allocator(&c.temp_allocator)

	conn_handle_req(c, context.temp_allocator)
}

@(private)
conn_handle_req :: proc(c: ^Connection, allocator := context.temp_allocator) {
	// Rejects the request with the given status and closes the connection after responding.
	reject :: proc(l: ^Loop, status: Status) {
		headers_set_close(&l.res.headers)
		l.req._close_after = true
		l.res.status = status
		respond(&l.res)
	}

	on_rline1 :: proc(loop: rawptr, token: string, err: bufio.Scanner_Error) {
		l := cast(^Loop)loop

		if !connection_set_state(l.conn, .Active) { return }

		if err != nil {
			if l.conn.scanner.timed_out {
				// Nothing received: an idle connection timing out, close quietly. Part of a request
				// received: tell the client.
				if l.conn.scanner.end > l.conn.scanner.start {
					log.info("request-line timed out")
					l.req.line = Requestline{version = {1, 1}}
					reject(l, .Request_Timeout)
					return
				}
				log.debug("idle connection timed out")
			} else if err == .EOF {
				log.debugf("client disconnected (EOF)")
			} else if err == .Too_Long {
				log.info("request-line too long")
				l.req.line = Requestline{version = {1, 1}}
				reject(l, .URI_Too_Long)
				return
			} else {
				log.warnf("request scanner error: %v", err)
			}

			clean_request_loop(l.conn, close = true)
			return
		}

		// In the interest of robustness, a server that is expecting to receive
		// and parse a request-line SHOULD ignore at least one empty line (CRLF)
		// received prior to the request-line.
		if len(token) == 0 {
			log.debug("first request line empty, skipping in interest of robustness")
			scanner_scan(&l.conn.scanner, loop, on_rline2)
			return
		}

		// The rest of the request head has to arrive within `header_timeout` from now.
		opts := l.conn.server.opts
		l.conn.scanner.deadline = time.time_add(nbio.now(), opts.header_timeout) if opts.header_timeout > 0 else {}

		on_rline2(loop, token, err)
	}

	on_rline2 :: proc(loop: rawptr, token: string, err: bufio.Scanner_Error) {
		l := cast(^Loop)loop

		if err != nil {
			log.warnf("request scanning error: %v", err)
			if err == .Too_Long {
				// We can't know the version of a request we couldn't read, so answer as 1.1.
				l.req.line = Requestline{version = {1, 1}}
				reject(l, .URI_Too_Long)
				return
			}
			clean_request_loop(l.conn, close = true)
			return
		}

		rline, rerr := requestline_parse(token, context.temp_allocator)
		switch rerr {
		case .None:
			l.req.line = rline
		case .Method_Not_Implemented:
			log.infof("request-line %q invalid method", token)
			l.req.line = Requestline{version = {1, 1}}
			reject(l, .Not_Implemented)
			return
		case .Invalid_Version_Format, .Not_Enough_Fields, .Invalid_Method, .Invalid_Target:
			log.infof("request-line %q invalid: %s", token, rerr)
			l.req.line = Requestline{version = {1, 1}}
			reject(l, .Bad_Request)
			return
		}

		// RFC 9112 2.3: a 1.x message with a higher minor version is processed as the highest
		// minor version we support. Other major versions are not supported.
		if rline.version.major != 1 {
			log.infof("request http version not supported %v", rline.version)
			l.req.line = Requestline{version = {1, 1}}
			reject(l, .HTTP_Version_Not_Supported)
			return
		}
		if rline.version.minor > 1 {
			(&l.req.line.(Requestline)).version.minor = 1
		}

		// RFC 9112 3.2: origin-form ("/path?query") is what clients send to servers; absolute-form
		// ("http://host/path") must be accepted too; asterisk-form only for OPTIONS; authority-form
		// only for CONNECT. Anything else, or a fragment, is a bad request.
		target := rline.target.(string)
		target_ok: bool
		switch {
		case strings.index_byte(target, '#') >= 0: target_ok = false
		case target[0] == '/':                     target_ok = true
		case target == "*":                        target_ok = rline.method == .Options
		case rline.method == .Connect:             target_ok = true
		case:
			scheme_end := strings.index(target, "://")
			target_ok = scheme_end > 0 && (ascii_equal_fold(target[:scheme_end], "http") || ascii_equal_fold(target[:scheme_end], "https"))
		}
		if !target_ok {
			log.infof("request-target %q invalid for %v", target, rline.method)
			reject(l, .Bad_Request)
			return
		}

		l.req.url = url_parse(target)
		if len(l.req.url.path) == 0 && target != "*" && rline.method != .Connect {
			// "http://host" without a path means "/".
			l.req.url.path = "/"
		}

		l.header_bytes_left = l.conn.server.opts.limit_headers
		l.header_count      = 0
		l.conn.scanner.max_token_size = l.header_bytes_left
		scanner_scan(&l.conn.scanner, loop, on_header_line)
	}

	on_header_line :: proc(loop: rawptr, token: string, err: bufio.Scanner_Error) {
		l := cast(^Loop)loop

		if err != nil {
			if l.conn.scanner.timed_out {
				log.info("request headers timed out")
				reject(l, .Request_Timeout)
				return
			}
			log.infof("request scanning error: %v", err)
			if err == .Too_Long {
				reject(l, .Request_Header_Fields_Too_Large)
				return
			}
			clean_request_loop(l.conn, close = true)
			return
		}

		// The first empty line denotes the end of the headers section.
		if len(token) == 0 {
			on_headers_end(l)
			return
		}

		// Account for the line ending too, so the limit is on bytes received.
		l.header_bytes_left -= len(token) + 2
		l.header_count      += 1
		if l.header_bytes_left < 0 || l.header_count > l.conn.server.opts.limit_header_count {
			log.warn("request headers too large")
			reject(l, .Request_Header_Fields_Too_Large)
			return
		}

		if _, ok := header_parse(&l.req.headers, token); !ok {
			log.infof("header-line %q is invalid", token)
			reject(l, .Bad_Request)
			return
		}

		l.conn.scanner.max_token_size = max(l.header_bytes_left, 1)
		scanner_scan(&l.conn.scanner, loop, on_header_line)
	}

	on_headers_end :: proc(l: ^Loop) {
		if status, ok := request_prepare(&l.req, l.conn.server.opts); !ok {
			log.infof("request rejected: %v", status)
			reject(l, status)
			return
		}

		l.req.headers.readonly = true

		l.conn.scanner.max_token_size = bufio.DEFAULT_MAX_SCAN_TOKEN_SIZE

		// Body reads are bound by a per-read timeout instead of a deadline, so large uploads
		// work as long as data keeps flowing.
		l.conn.scanner.deadline     = {}
		l.conn.scanner.read_timeout = l.conn.server.opts.body_read_timeout

		rline := &l.req.line.(Requestline)
		// An options request with the "*" is a no-op/ping request to
		// check for server capabilities and should not be sent to handlers.
		if rline.method == .Options && rline.target.(string) == "*" {
			l.res.status = .OK
			respond(&l.res)
		} else {
			// Give the handler this request as a GET, since the HTTP spec
			// says a HEAD is identical to a GET but just without writing the body,
			// handlers shouldn't have to worry about it.
			l.req.is_head = rline.method == .Head
			if l.req.is_head && l.conn.server.opts.redirect_head_to_get {
				rline.method = .Get
			}

			l.conn.server.handler.handle(&l.conn.server.handler, &l.req, &l.res)
		}
	}

	c.loop.conn = c
	c.loop.res._conn = c
	c.loop.req._scanner = &c.scanner
	request_init(&c.loop.req, allocator)
	response_init(&c.loop.res, allocator)

	// A fresh connection has `header_timeout` to send its first request, a keep-alive connection
	// may wait `idle_timeout` for the next one.
	wait := c.server.opts.idle_timeout if c.state == .Idle else c.server.opts.header_timeout
	c.scanner.deadline = time.time_add(nbio.now(), wait) if wait > 0 else {}

	c.scanner.max_token_size = c.server.opts.limit_request_line
	scanner_scan(&c.scanner, &c.loop, on_rline1)
}

/*
Timeouts are deadlines on the connection (`read_deadline`, `write_deadline`), checked by a timer per
thread, instead of a timeout on every read and write: those cost an extra timer operation per I/O
(io_uring: a linked timeout and its completion), measured at 10-25% of the throughput of small
requests.

A deadline fires up to `sweep_interval` late: a quarter of the shortest configured timeout, at most
a second.
*/
@(private)
server_sweep_start :: proc(td: ^Server_Thread) {
	td.sweep_timer = nbio.timeout_poly(sweep_interval(td.server.opts), td, proc(_: ^nbio.Operation, td: ^Server_Thread) {
		td.sweep_timer = nil
		if td.state != .Serving { return }
		server_sweep_conns(td)
		server_sweep_start(td)
	})
}

@(private)
sweep_interval :: proc(opts: Server_Opts) -> time.Duration {
	interval := time.Second
	for t in ([]time.Duration{opts.idle_timeout, opts.header_timeout, opts.body_read_timeout, opts.write_timeout}) {
		if t > 0 { interval = min(interval, t / 4) }
	}
	return max(interval, 5 * time.Millisecond)
}

// Shuts down the sockets of connections whose pending read or write is past its deadline.
@(private)
server_sweep_conns :: proc(td: ^Server_Thread) {
	now := nbio.now()
	for sock, c in td.conns {
		if c.state == .Hijacked || c.state >= .Closing { continue }

		if c.write_deadline != {} && time.diff(now, c.write_deadline) <= 0 {
			c.write_deadline = {}
			c.write_expired  = true
			// Nothing more can be written (or read) usefully.
			net.shutdown(sock, .Both)
		}
		if c.read_deadline != {} && time.diff(now, c.read_deadline) <= 0 {
			c.read_deadline = {}
			c.read_expired  = true
			// Only the read side, so a 408 can still be sent.
			net.shutdown(sock, .Receive)
		}
	}
}

// A buffer that will contain the date header for the current second.
@(private)
Server_Date :: struct {
	buf: [DATE_LENGTH]byte,
}

@(private)
server_date_start :: proc(td: ^Server_Thread) {
	server_date_update(nil, td)
}

// Updates the time and schedules itself for after a second.
@(private)
server_date_update :: proc(_: ^nbio.Operation, td: ^Server_Thread) {
	td.date_timer = nil
	if atomic_load(&td.server.closing) { return }

	td.date_timer = nbio.timeout_poly(time.Second, td, server_date_update)

	b: strings.Builder
	b.buf = slice.into_dynamic(td.date.buf[:])
	date_write(strings.to_writer(&b), time.now())
}

// The cached date of the calling server thread.
@(private)
server_date :: proc(_: ^Server) -> string {
	assert_has_td()
	return string(td.date.buf[:])
}
