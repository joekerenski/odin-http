package client

import "base:runtime"

import "core:log"
import "core:mem"
import "core:nbio"
import "core:sync"
import "core:thread"

/*
The client's own thread: an event loop that runs every blocking `request`/`request_stream`/`get`.
Started on first use and kept for the life of the process, so blocking requests share one
connection pool (connections stay on the event loop that opened them, see pool.odin) and no
thread is created per request.

A blocking call posts a job to this loop (nbio runs operations queued from other threads on the
loop's thread) and waits for it to finish.
*/
@(private)
background: struct {
	once:  sync.Once,
	ready: sync.Sema,
	loop:  ^nbio.Event_Loop,
	ok:    bool,
}

// Set on the client's thread, where a blocking call would wait for itself.
@(private, thread_local)
on_background_thread: bool

@(private)
background_start :: proc() -> bool {
	sync.once_do(&background.once, proc() {
		// The thread lives as long as the process: nothing of it comes from the caller's allocator.
		context.allocator = runtime.heap_allocator()
		t := thread.create(proc(_: ^thread.Thread) {
			on_background_thread = true
			if err := nbio.acquire_thread_event_loop(); err != nil {
				sync.sema_post(&background.ready)
				return
			}
			background.loop = nbio.current_thread_event_loop()
			background.ok = true
			sync.sema_post(&background.ready)
			for {
				if err := nbio.tick(); err != nil {
					log.errorf("client: event loop error: %v", err)
				}
			}
		})
		t.init_context = runtime.default_context()
		thread.start(t)
		sync.sema_wait(&background.ready)
	})
	return background.ok
}

@(private)
Job :: struct {
	req:       ^Request,
	url:       string,
	opts:      Opts,
	stream:    Stream,
	streaming: bool,
	user_data: rawptr,
	allocator: mem.Allocator,
	logger:    runtime.Logger,
	res:       Response,
	err:       Error,
	done:      sync.Sema,
}

// Runs the request on the client's thread and waits for it.
@(private)
run_blocking :: proc(job: ^Job) -> (Response, Error) {
	assert(!on_background_thread, "client: a blocking request from a client callback (request_stream's) would wait for itself, use request_async")
	if !background_start() { return {}, .Network_Error }
	job.logger = context.logger

	nbio.timeout_poly(0, job, proc(_: ^nbio.Operation, job: ^Job) {
		// The caller waits, so its logger (and the request, and the allocator) are still there.
		context.logger = job.logger
		done :: proc(res: Response, err: Error, user_data: rawptr) {
			job := (^Job)(user_data)
			job.res, job.err = res, err
			sync.sema_post(&job.done)
		}
		err: Error
		if job.streaming {
			err = start(job.req, job.url, job.opts, job, done, job.allocator, job.stream, job.user_data)
		} else {
			err = start(job.req, job.url, job.opts, job, done, job.allocator)
		}
		if err != nil {
			job.err = err
			sync.sema_post(&job.done)
		}
	}, l = background.loop)

	sync.sema_wait(&job.done)
	return job.res, job.err
}

// Closes the client thread's idle connections (from another thread), see `close_idle_connections`.
@(private)
background_close_idle :: proc() {
	if on_background_thread || background.loop == nil { return }
	done: sync.Sema
	nbio.timeout_poly(0, &done, proc(_: ^nbio.Operation, done: ^sync.Sema) {
		pool_close_all()
		sync.sema_post(done)
	}, l = background.loop)
	sync.sema_wait(&done)
}
