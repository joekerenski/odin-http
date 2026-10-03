package client

import "base:runtime"

import "core:fmt"
import "core:net"
import "core:sync"
import "core:sys/posix"
import "core:time"

import "../openssl"

/*
Idle connections, kept for later requests to the same origin (scheme, host, port, and CA file).
Shared by all threads: a connection is only in the pool while nothing is in flight on it, and nbio
keeps no per-socket state between operations (one-shot kqueue filters, io_uring), so the next
request can use it from any event loop.
*/

// Idle connections kept at most, over all origins.
MAX_IDLE_TOTAL :: 64

@(private)
Idle_Conn :: struct {
	socket:     net.TCP_Socket,
	ssl:        ^openssl.SSL,
	rbio, wbio: ^openssl.BIO,
	expires:    time.Tick,
}

@(private)
pool: struct {
	mu:    sync.Mutex,
	// By origin key, the most recently used last.
	conns: map[string][dynamic]Idle_Conn,
	total: int,
	stats: Stats,
}

// Connections opened and requests that reused one, since the start (for tests and tuning).
Stats :: struct {
	dials:  int,
	reused: int,
}

stats :: proc() -> Stats {
	sync.guard(&pool.mu)
	return pool.stats
}

// Closes all idle connections (they are closed after `Opts.idle_timeout` otherwise, checked lazily).
close_idle_connections :: proc() {
	sync.guard(&pool.mu)
	for key, &list in pool.conns {
		for ic in list { idle_close(ic) }
		delete(list)
		delete(key, runtime.heap_allocator())
	}
	delete(pool.conns)
	pool.conns = nil
	pool.total = 0
}

@(private)
origin_key :: proc(t: Target, ca_file: string, allocator := context.temp_allocator) -> string {
	return fmt.aprintf("%s|%s|%i|%s", "https" if t.tls else "http", t.host, t.port, ca_file, allocator = allocator)
}

// An idle connection to the origin that still looks usable, the most recently used first.
@(private)
pool_get :: proc(key: string) -> (ic: Idle_Conn, ok: bool) {
	sync.guard(&pool.mu)
	list, has := &pool.conns[key]
	if !has { return }
	now := time.tick_now()
	for len(list) > 0 {
		ic = pop(list)
		pool.total -= 1
		if time.tick_diff(now, ic.expires) > 0 && idle_alive(ic) {
			ok = true
			pool.stats.reused += 1
			break
		}
		idle_close(ic)
	}
	if len(list) == 0 { pool_delete_key(key) }
	return
}

// Keeps `ic` for later, unless the origin or the pool is full.
@(private)
pool_put :: proc(key: string, ic: Idle_Conn, max_per_origin: int) {
	sync.guard(&pool.mu)
	pool_purge_expired()

	if pool.total >= MAX_IDLE_TOTAL {
		idle_close(ic)
		return
	}
	if pool.conns == nil { pool.conns = make(map[string][dynamic]Idle_Conn, 8, runtime.heap_allocator()) }
	list, has := &pool.conns[key]
	if !has {
		pool.conns[cloned_key(key)] = make([dynamic]Idle_Conn, 0, 4, runtime.heap_allocator())
		list = &pool.conns[key]
	}
	if len(list) >= max_per_origin {
		// Drop the oldest.
		idle_close(list[0])
		ordered_remove(list, 0)
		pool.total -= 1
	}
	append(list, ic)
	pool.total += 1
}

@(private)
pool_record_dial :: proc() {
	sync.guard(&pool.mu)
	pool.stats.dials += 1
}

@(private="file")
cloned_key :: proc(key: string) -> string {
	b := make([]byte, len(key), runtime.heap_allocator())
	copy(b, key)
	return string(b)
}

@(private="file")
pool_delete_key :: proc(key: string) {
	k, v := delete_key(&pool.conns, key)
	delete(v)
	delete(k, runtime.heap_allocator())
}

@(private="file")
pool_purge_expired :: proc() {
	now := time.tick_now()
	empty: [dynamic]string
	empty.allocator = context.temp_allocator
	for key, &list in pool.conns {
		for i := 0; i < len(list); {
			if time.tick_diff(now, list[i].expires) <= 0 {
				idle_close(list[i])
				ordered_remove(&list, i)
				pool.total -= 1
			} else {
				i += 1
			}
		}
		if len(list) == 0 { append(&empty, key) }
	}
	for key in empty { pool_delete_key(key) }
}

/*
An idle connection has nothing to say: if it's readable, the server closed it (or sent something
it shouldn't have, e.g. a close_notify or a 408), either way it can't be used.
*/
@(private="file")
idle_alive :: proc(ic: Idle_Conn) -> bool {
	fds := [1]posix.pollfd{{fd = posix.FD(ic.socket), events = {.IN}}}
	return posix.poll(&fds[0], 1, 0) == 0
}

@(private)
idle_close :: proc(ic: Idle_Conn) {
	if ic.ssl != nil { openssl.SSL_free(ic.ssl) }
	net.close(ic.socket)
}
