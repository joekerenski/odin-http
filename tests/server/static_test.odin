package tests_server

import "base:runtime"

import "core:fmt"
import "core:os"
import "core:path/filepath"
import "core:strings"
import "core:sync"
import "core:testing"

import http "../.."

// A directory tree shared by the static file tests:
//   <root>/secret.txt          outside the served dir
//   <root>/www/a.txt           "hello file"
//   <root>/www/empty.txt       0 bytes
//   <root>/www/big.bin         20 MiB pattern
//   <root>/www/sub/index.html
//   <root>/www/noindex/x.txt
//   <root>/www/fifo            (POSIX only)
@(private="file")
static_root: string
@(private="file")
static_once: sync.Once

BIG_SIZE :: 20 << 20

@(private="file")
static_setup :: proc() {
	sync.once_do(&static_once, proc() {
		// Lives for the whole test run, so keep it out of the per-test tracking allocator.
		context.allocator = runtime.heap_allocator()
		tmp, _ := os.temp_directory(context.allocator)
		root, err := os.make_directory_temp(tmp, "odin-http-static-*", context.allocator)
		assert(err == nil)
		static_root = root

		join :: proc(parts: ..string) -> string {
			p, _ := filepath.join(parts, context.allocator)
			return p
		}
		www := join(root, "www")
		os.make_directory(www)
		os.make_directory(join(www, "sub"))
		os.make_directory(join(www, "noindex"))
		_ = os.write_entire_file(join(root, "secret.txt"), transmute([]byte)string("secret"))
		_ = os.write_entire_file(join(www, "a.txt"), transmute([]byte)string("hello file"))
		_ = os.write_entire_file(join(www, "empty.txt"), []byte{})
		_ = os.write_entire_file(join(www, "sub", "index.html"), transmute([]byte)string("<p>index</p>"))
		_ = os.write_entire_file(join(www, "noindex", "x.txt"), transmute([]byte)string("x"))
		big := make([]byte, BIG_SIZE)
		for &b, i in big { b = byte(i % 251) }
		_ = os.write_entire_file(join(www, "big.bin"), big)
		delete(big)
		when ODIN_OS != .Windows {
			make_fifo(join(www, "fifo"))
		}
	})
}

@(fini, private="file")
static_cleanup :: proc "contextless" () {
	if static_root == "" { return }
	context = runtime.default_context()
	_ = os.remove_all(static_root)
}

static_handler :: proc() -> http.Handler {
	static_setup()
	return http.handler(proc(req: ^http.Request, res: ^http.Response) {
		www, _ := filepath.join({static_root, "www"}, context.temp_allocator)
		http.respond_dir(res, "/static", www, req.url.raw)
	})
}

@(test)
static_files :: proc(t: ^testing.T) {
	ts := server_start(t, static_handler())
	defer server_stop(ts)

	resp := roundtrip(ts, "GET /static/a.txt HTTP/1.1\r\nHost: x\r\n\r\n")
	testing.expectf(t, status_of(resp) == 200 && strings.has_suffix(resp, "\r\n\r\nhello file"), "got %q", resp)
	testing.expectf(t, strings.contains(resp, "content-type: text/plain; charset=utf-8") && strings.contains(resp, "content-length: 10"), "got %q", resp)

	resp = roundtrip(ts, "GET /static/empty.txt HTTP/1.1\r\nHost: x\r\n\r\nGET /static/a.txt HTTP/1.1\r\nHost: x\r\n\r\n")
	testing.expectf(t, count_responses(resp) == 2 && strings.contains(resp, "content-length: 0"), "got %q", resp)

	resp = roundtrip(ts, "HEAD /static/a.txt HTTP/1.1\r\nHost: x\r\n\r\nGET /static/a.txt HTTP/1.1\r\nHost: x\r\n\r\n")
	testing.expectf(t, count_responses(resp) == 2 && strings.count(resp, "hello file") == 1, "got %q", resp)

	resp = roundtrip(ts, "GET /static/sub/ HTTP/1.1\r\nHost: x\r\n\r\n")
	testing.expectf(t, status_of(resp) == 200 && strings.has_suffix(resp, "<p>index</p>"), "got %q", resp)

	for path in ([]string{"/static/noindex/", "/static/sub", "/static/nope.txt", "/static/fifo"}) {
		resp = roundtrip(ts, fmt.tprintf("GET %s HTTP/1.1\r\nHost: x\r\n\r\n", path))
		testing.expectf(t, status_of(resp) == 404, "%s: got %q", path, resp)
	}
}

@(test)
static_traversal :: proc(t: ^testing.T) {
	ts := server_start(t, static_handler())
	defer server_stop(ts)

	for path in ([]string{
		"/static/../secret.txt",
		"/static../secret.txt",
		"/static/%2e%2e/secret.txt",
		"/static/..%2fsecret.txt",
		"/static/sub/../../secret.txt",
		"/static/a.txt%00.html",
	}) {
		resp := roundtrip(ts, fmt.tprintf("GET %s HTTP/1.1\r\nHost: x\r\n\r\n", path))
		testing.expectf(t, !strings.contains(resp, "secret") && (status_of(resp) == 404 || status_of(resp) == 400), "%s: got %q", path, resp)
	}
}

@(test)
static_ranges :: proc(t: ^testing.T) {
	ts := server_start(t, static_handler())
	defer server_stop(ts)

	resp := roundtrip(ts, "GET /static/a.txt HTTP/1.1\r\nHost: x\r\nRange: bytes=0-4\r\n\r\n")
	testing.expectf(t, status_of(resp) == 206 && strings.has_suffix(resp, "\r\n\r\nhello") && strings.contains(resp, "content-range: bytes 0-4/10"), "got %q", resp)

	resp = roundtrip(ts, "GET /static/a.txt HTTP/1.1\r\nHost: x\r\nRange: bytes=-4\r\n\r\n")
	testing.expectf(t, status_of(resp) == 206 && strings.has_suffix(resp, "\r\n\r\nfile"), "got %q", resp)

	resp = roundtrip(ts, "GET /static/a.txt HTTP/1.1\r\nHost: x\r\nRange: bytes=50-\r\n\r\n")
	testing.expectf(t, status_of(resp) == 416 && strings.contains(resp, "content-range: bytes */10"), "got %q", resp)

	// Multiple ranges are not supported: the full file.
	resp = roundtrip(ts, "GET /static/a.txt HTTP/1.1\r\nHost: x\r\nRange: bytes=0-1,3-4\r\n\r\n")
	testing.expectf(t, status_of(resp) == 200 && strings.has_suffix(resp, "hello file"), "got %q", resp)
}

@(test)
static_big_file_streams :: proc(t: ^testing.T) {
	ts := server_start(t, static_handler())
	defer server_stop(ts)

	// Pipelined: the big body must be framed exactly so the second response follows it.
	resp := roundtrip(ts, "GET /static/big.bin HTTP/1.1\r\nHost: x\r\n\r\nGET /static/a.txt HTTP/1.1\r\nHost: x\r\n\r\n", allocator = context.allocator)
	defer delete(resp)

	head_end := strings.index(resp, "\r\n\r\n")
	testing.expect(t, head_end > 0 && status_of(resp) == 200)
	if head_end < 0 { return }
	body := resp[head_end + 4:]
	testing.expectf(t, len(body) >= BIG_SIZE, "short body: %d", len(body))
	if len(body) < BIG_SIZE { return }
	ok := true
	for i in 0 ..< BIG_SIZE {
		if body[i] != byte(i % 251) { ok = false; break }
	}
	testing.expect(t, ok, "big file content corrupted")
	testing.expectf(t, strings.has_suffix(body[BIG_SIZE:], "hello file"), "second response: %q", body[BIG_SIZE:][:min(200, len(body) - BIG_SIZE)])
}
