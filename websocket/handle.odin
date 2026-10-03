package websocket

import "base:runtime"

import "core:mem"
import "core:nbio"
import "core:slice"
import "core:sync"

/*
A reference to a connection that can be used from any thread, e.g. to broadcast to connections that
live on different event loops. It stays safe to use after the connection closed and after the
server shut down (sends are dropped).
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
dropped, `on_result` (optional, called on the connection's thread) tells which. Messages to
connections that are already gone, or to an event loop that can't keep up (`MAILBOX_LIMIT`), are
dropped right away, without `on_result`.
*/
send_from_any_thread :: proc(h: Handle, kind: Message_Kind, data: []byte, on_result: proc(h: Handle, res: Send_Result) = nil) {
	post(h, Mail{id = h.id, kind = kind, data = data, on_result = on_result})
}

// Starts the closing handshake of the connection behind `h` from any thread.
close_from_any_thread :: proc(h: Handle, code: Close_Code = .Normal) {
	post(h, Mail{id = h.id, close = true, code = code})
}

/*
Sends `data` to every handle, like `send_from_any_thread` (without results). Cheaper than sending
one by one: one mailbox entry and one copy of `data` per event loop, and uncompressed server
connections on a loop share a single encoded frame.
*/
broadcast :: proc(handles: []Handle, kind: Message_Kind, data: []byte) {
	if len(handles) == 0 { return }
	sorted := make([]Handle, len(handles), context.temp_allocator)
	copy(sorted, handles)
	slice.sort_by(sorted, proc(a, b: Handle) -> bool { return uintptr(a.loop) < uintptr(b.loop) })

	allocator := runtime.heap_allocator()
	for i := 0; i < len(sorted); {
		j := i
		for j < len(sorted) && sorted[j].loop == sorted[i].loop { j += 1 }
		ids := make([]u64, j - i, allocator)
		for h, k in sorted[i:j] { ids[k] = h.id }
		post(sorted[i], Mail{ids = ids, kind = kind, data = data})
		i = j
	}
}

// Most bytes of cross-thread messages waiting for one event loop, more are dropped.
MAILBOX_LIMIT :: 64 * mem.Megabyte

/*
Cross-thread messages go through one mailbox per event loop. A mailbox exists while its loop has
WebSocket connections: a handle whose loop has none belongs to a closed connection, so sends to
it are dropped without touching the loop, which may not exist anymore (after a server shutdown).

At most one wake-up per mailbox is queued on the loop (`nbio` cross-thread operations), so the
loop's operation queue can't fill up however fast other threads send.
*/
@(private)
Mailbox :: struct {
	loop:   ^nbio.Event_Loop,
	mail:   [dynamic]Mail,
	bytes:  int,
	open:   bool, // The loop has connections, see `register`.
	waking: bool, // A drain is queued on the loop.
}

@(private)
Mail :: struct {
	// A broadcast to these connections (heap allocated), else a message to `id`.
	ids:       []u64,
	id:        u64,
	close:     bool,
	code:      Close_Code,
	kind:      Message_Kind,
	data:      []byte,
	on_result: proc(h: Handle, res: Send_Result),
}

// Guards `mailboxes` and every mailbox's fields.
@(private)
mailboxes_mu: sync.Mutex
@(private)
mailboxes: map[^nbio.Event_Loop]^Mailbox

@(private)
post :: proc(h: Handle, m: Mail) {
	allocator := runtime.heap_allocator()
	m := m

	sync.guard(&mailboxes_mu)
	mb := mailboxes[h.loop]
	if mb == nil || !mb.open || mb.bytes + len(m.data) > MAILBOX_LIMIT {
		delete(m.ids, allocator)
		return
	}

	if len(m.data) > 0 {
		data := make([]byte, len(m.data), allocator)
		copy(data, m.data)
		m.data = data
	}
	if mb.mail.allocator.procedure == nil { mb.mail.allocator = allocator }
	append(&mb.mail, m)
	mb.bytes += len(m.data)

	if !mb.waking {
		mb.waking = true
		// While the mailbox is open its loop is alive (its connections are on it), and holding the
		// lock keeps it open until this is queued.
		nbio.timeout_poly(0, mb, drain, l = mb.loop)
	}
}

// Runs on the mailbox's loop.
@(private)
drain :: proc(_: ^nbio.Operation, mb: ^Mailbox) {
	allocator := runtime.heap_allocator()

	mail: [dynamic]Mail
	closed: bool
	{
		sync.guard(&mailboxes_mu)
		mail = mb.mail
		mb.mail = {}
		mb.bytes = 0
		mb.waking = false
		closed = !mb.open
	}

	for m in mail {
		if m.ids != nil {
			deliver_broadcast(m)
			delete(m.ids, allocator)
			delete(m.data, allocator)
			continue
		}
		c, ok := registry[m.id]
		switch {
		case m.close:
			if ok { close(c, m.code) }
		case:
			res := Send_Result.Closed
			if ok { res = send(c, m.kind, m.data) }
			if m.on_result != nil { m.on_result({m.id, mb.loop}, res) }
		}
		delete(m.data, allocator)
	}
	delete(mail)

	// Closed while this drain was queued: nothing refers to the mailbox anymore.
	if closed { free(mb, allocator) }
}

@(private)
deliver_broadcast :: proc(m: Mail) {
	sf: ^Shared_Frame
	defer if sf != nil { shared_frame_release(sf) }
	for id in m.ids {
		c := registry[id] or_continue
		if can_share_frames(c) {
			if sf == nil { sf = shared_frame_make(m.kind, m.data, runtime.heap_allocator()) }
			queue_shared_frame(c, sf, len(m.data))
		} else {
			send(c, m.kind, m.data)
		}
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

		// The loop's first connection: open its mailbox.
		sync.guard(&mailboxes_mu)
		if mailboxes == nil {
			mailboxes = make(map[^nbio.Event_Loop]^Mailbox, 16, runtime.heap_allocator())
		}
		mb := new(Mailbox, runtime.heap_allocator())
		mb^ = {loop = c._loop, open = true}
		mailboxes[c._loop] = mb
	}
	registry[c._id] = c
}

@(private)
unregister :: proc(c: ^Conn) {
	delete_key(&registry, c._id)
	if len(registry) == 0 {
		delete(registry)
		registry = nil

		// The loop's last connection: close its mailbox, pending mail is for closed connections.
		allocator := runtime.heap_allocator()
		sync.guard(&mailboxes_mu)
		mb := mailboxes[c._loop]
		delete_key(&mailboxes, c._loop)
		if mb == nil { return }
		mb.open = false
		if !mb.waking {
			for m in mb.mail {
				delete(m.data, allocator)
				delete(m.ids, allocator)
			}
			delete(mb.mail)
			free(mb, allocator)
		}
		// Otherwise the queued drain frees it.
	}
}
