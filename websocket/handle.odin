package websocket

import "base:runtime"

import "core:nbio"
import "core:sync"

/*
A reference to a connection that can be used from any thread, e.g. to broadcast to connections that
live on different event loops. It stays safe to use after the connection closed (sends are dropped).
*/
Handle :: struct {
	id:   u64,
	loop: ^nbio.Event_Loop,
}

// The handle of a connection, call on the connection's thread.
handle :: proc(c: ^Conn) -> Handle {
	return {c._id, c._loop}
}

/*
Sends a message to the connection behind `h` from any thread. `data` is copied. The send happens on
the connection's event loop; if the connection is gone by then (or its queue is full) the message is
dropped, `on_result` (optional, called on the connection's thread) tells which.
*/
send_from_any_thread :: proc(h: Handle, kind: Message_Kind, data: []byte, on_result: proc(h: Handle, res: Send_Result) = nil) {
	Cross_Send :: struct {
		h:         Handle,
		kind:      Message_Kind,
		data:      []byte,
		on_result: proc(h: Handle, res: Send_Result),
	}

	allocator := runtime.heap_allocator()
	msg := new(Cross_Send, allocator)
	msg^ = {h = h, kind = kind, data = make([]byte, len(data), allocator), on_result = on_result}
	copy(msg.data, data)

	nbio.timeout_poly(0, msg, proc(_: ^nbio.Operation, msg: ^Cross_Send) {
		res := Send_Result.Closed
		if c, ok := registry[msg.h.id]; ok {
			res = send(c, msg.kind, msg.data)
		}
		if msg.on_result != nil { msg.on_result(msg.h, res) }

		allocator := runtime.heap_allocator()
		delete(msg.data, allocator)
		free(msg, allocator)
	}, l = h.loop)
}

// Starts the closing handshake of the connection behind `h` from any thread.
close_from_any_thread :: proc(h: Handle, code: Close_Code = .Normal) {
	Cross_Close :: struct {
		id:   u64,
		code: Close_Code,
	}
	msg := new(Cross_Close, runtime.heap_allocator())
	msg^ = {h.id, code}
	nbio.timeout_poly(0, msg, proc(_: ^nbio.Operation, msg: ^Cross_Close) {
		if c, ok := registry[msg.id]; ok {
			close(c, msg.code)
		}
		free(msg, runtime.heap_allocator())
	}, l = h.loop)
}

// Sends `data` to every handle, see `send_from_any_thread`.
broadcast :: proc(handles: []Handle, kind: Message_Kind, data: []byte) {
	for h in handles {
		send_from_any_thread(h, kind, data)
	}
}

// Open connections of the current thread, by id.
@(private, thread_local)
registry: map[u64]^Conn

@(private)
next_id: u64

@(private)
register :: proc(c: ^Conn) {
	c._id = sync.atomic_add(&next_id, 1) + 1
	c._loop = nbio.current_thread_event_loop()
	if registry == nil {
		registry = make(map[u64]^Conn, 16, runtime.heap_allocator())
	}
	registry[c._id] = c
}

@(private)
unregister :: proc(c: ^Conn) {
	delete_key(&registry, c._id)
	if len(registry) == 0 {
		delete(registry)
		registry = nil
	}
}
