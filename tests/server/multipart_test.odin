package tests_server

// multipart/form-data bodies: streamed (`multipart_stream`), split at every byte, with pauses, and
// in memory (`multipart_parse`).

import "core:fmt"
import "core:hash"
import "core:nbio"
import "core:net"
import "core:strings"
import "core:testing"
import "core:time"

import http "../.."

@(private="file")
Mp :: struct {
	req:   ^http.Request,
	res:   ^http.Response,
	async: bool,
	out:   strings.Builder,
	n:     int,
	sum:   u64,
	ended: bool,
}

/*
/mp streams the parts, /mp-async asks for each event from a timer, /mp-parse reads the body and
splits it in memory. Responds with a line per part: "name|filename|content-type|bytes|fnv64a", and
the error's status when it fails.
*/
@(private="file")
multipart_handler :: proc() -> http.Handler {
	return http.handler(proc(req: ^http.Request, res: ^http.Response) {
		mp := new(Mp, context.temp_allocator)
		mp^ = {req = req, res = res, async = req.url.path == "/mp-async"}
		mp.out = strings.builder_make(context.temp_allocator)

		if req.url.path == "/mp-parse" {
			http.body(req, -1, mp, proc(mp: rawptr, body: http.Body, err: http.Body_Error) {
				mp := (^Mp)(mp)
				if err != nil { http.respond(mp.res, http.body_error_status(err)); return }
				fields, perr := http.multipart_parse(mp.req, body)
				if perr != nil { http.respond(mp.res, http.multipart_error_status(perr)); return }
				for f in fields {
					fmt.sbprintf(&mp.out, "%s|%s|%s|%i|%x\n", f.name, f.filename, f.content_type, len(f.data), hash.fnv64a(transmute([]byte)f.data))
				}
				http.respond_plain(mp.res, strings.to_string(mp.out))
			})
			return
		}

		http.multipart_stream(req, -1, mp, proc(mp: rawptr, event: http.Multipart_Event, part: ^http.Multipart_Part, data: []byte, err: http.Multipart_Error) {
			mp := (^Mp)(mp)
			switch event {
			case .Part:
				mp.n, mp.sum, mp.ended = 0, 0xcbf29ce484222325, false
			case .Data:
				assert(len(data) > 0 && !mp.ended)
				mp.n  += len(data)
				mp.sum = hash.fnv64a(data, mp.sum)
			case .Part_End:
				mp.ended = true
				fmt.sbprintf(&mp.out, "%s|%s|%s|%i|%x\n", part.name, part.filename, part.content_type, mp.n, mp.sum)
			case .Done:
				if err != nil {
					http.respond(mp.res, http.multipart_error_status(err))
				} else {
					http.respond_plain(mp.res, strings.to_string(mp.out))
				}
				return
			}
			if mp.async {
				nbio.timeout_poly(time.Millisecond, mp, proc(_: ^nbio.Operation, mp: ^Mp) { http.multipart_next(mp.req) })
				return
			}
			http.multipart_next(mp.req)
		})
	})
}

@(private="file")
Form_Part :: struct {
	headers: string, // header lines, each with CRLF
	name, filename, content_type: string,
	data: string,
}

@(private="file")
BOUNDARY :: "----OdinFormBoundary7MA4YWxkTrZu0gW"

// A form body as a browser sends it (plus a preamble, padding and an epilogue to skip).
@(private="file")
form_body :: proc(parts: []Form_Part, preamble := "", epilogue := "", padding := "") -> string {
	b := strings.builder_make(context.temp_allocator)
	strings.write_string(&b, preamble)
	for p in parts {
		fmt.sbprintf(&b, "--%s%s\r\n", BOUNDARY, padding)
		strings.write_string(&b, p.headers)
		strings.write_string(&b, "\r\n")
		strings.write_string(&b, p.data)
		strings.write_string(&b, "\r\n")
	}
	fmt.sbprintf(&b, "--%s--%s", BOUNDARY, epilogue)
	return strings.to_string(b)
}

@(private="file")
form_want :: proc(parts: []Form_Part) -> string {
	b := strings.builder_make(context.temp_allocator)
	for p in parts {
		fmt.sbprintf(&b, "%s|%s|%s|%i|%x\n", p.name, p.filename, p.content_type, len(p.data), hash.fnv64a(transmute([]byte)p.data))
	}
	return strings.to_string(b)
}

@(private="file")
form_request :: proc(path, body: string, content_type := "multipart/form-data; boundary=" + BOUNDARY) -> string {
	return fmt.tprintf("POST %s HTTP/1.1\r\nHost: x\r\nContent-Type: %s\r\nContent-Length: %i\r\nConnection: close\r\n\r\n%s", path, content_type, len(body), body)
}

// Content made to look like delimiters (which can't be in it: CRLF "--" boundary): partial ones,
// the boundary without the CRLF before it or with a lone CR, and at the end the start of one right
// before the real one.
@(private="file")
TRICKY :: "a\r\n--" + "----OdinFormBound" + "\r\n-\r\n--x\r\r\n-" + BOUNDARY + "\r\nx--" + BOUNDARY + "\r\n\r--" + BOUNDARY + "\r\n\r\n--" + "----OdinFormBoundary7"

@(private="file")
test_parts :: proc() -> []Form_Part {
	big := make([]byte, 3 << 20, context.temp_allocator)
	for &c, i in big { c = byte(i * 7 + i >> 9) }
	parts := make([]Form_Part, 6, context.temp_allocator)
	parts[0] = {headers = "Content-Disposition: form-data; name=\"title\"\r\n", name = "title", content_type = "text/plain", data = "hello"}
	parts[1] = {headers = "Content-Disposition: form-data; name=\"empty\"\r\n", name = "empty", content_type = "text/plain"}
	parts[2] = {headers = "content-disposition: form-data; name=\"doc\"; filename=\"a b;c.bin\"\r\nContent-Type: application/octet-stream\r\n", name = "doc", filename = "a b;c.bin", content_type = "application/octet-stream", data = TRICKY}
	parts[3] = {headers = "Content-Disposition: form-data; name=\"nofile\"; filename=\"\"\r\nContent-Type: application/octet-stream\r\n", name = "nofile", content_type = "application/octet-stream"}
	parts[4] = {headers = "Content-Disposition: FORM-DATA ; filename=back\\slash.txt ; name=unquoted\r\n", name = "unquoted", filename = "back\\slash.txt", content_type = "text/plain", data = "x"}
	parts[5] = {headers = "Content-Disposition: form-data; name=\"big\"; filename=\"big.bin\"\r\n", name = "big", filename = "big.bin", content_type = "text/plain", data = string(big)}
	return parts
}

@(test)
multipart_forms :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	ts := server_start(t, multipart_handler())
	defer server_stop(ts)

	parts := test_parts()
	want := form_want(parts)
	bodies := []string{
		form_body(parts),
		form_body(parts, preamble = "This is the preamble.\r\n--not it\r\n", epilogue = "\r\nand an epilogue --" + BOUNDARY + "--\r\n", padding = " \t "),
	}
	for body in bodies {
		for path in ([]string{"/mp", "/mp-async", "/mp-parse"}) {
			resp := roundtrip(ts, form_request(path, body), wait = 5 * time.Second)
			testing.expectf(t, strings.has_suffix(resp, want), "%s: %q\nwant %q", path, resp[max(0, len(resp) - 400):], want)
		}
	}

	// A quoted boundary, and the first part right at the start without a CRLF before it.
	small := parts[:3]
	resp := roundtrip(ts, form_request("/mp", form_body(small), "Multipart/Form-Data; charset=utf-8; boundary=\"" + BOUNDARY + "\""))
	testing.expectf(t, strings.has_suffix(resp, form_want(small)), "quoted: %q", resp)

	// No parts at all is a valid (empty) form.
	resp = roundtrip(ts, form_request("/mp", "--" + BOUNDARY + "--\r\n"))
	testing.expectf(t, status_of(resp) == 200 && strings.has_suffix(resp, "\r\n\r\n"), "empty form: %q", resp)
}

// The body arrives in pieces of every size, so delimiters and header lines are split everywhere.
@(test)
multipart_split :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	ts := server_start(t, multipart_handler())
	defer server_stop(ts)

	parts := test_parts()[:5]
	want := form_want(parts)
	req := form_request("/mp", form_body(parts, preamble = "pre\r\n", padding = " "))
	for size in ([]int{1, 2, 3, 5, 8, 13, 41, 64}) {
		c, ok := raw_dial(ts)
		testing.expect(t, ok)
		net.set_option(c.sock, .TCP_Nodelay, true)
		for i := 0; i < len(req); i += size {
			raw_send(c, req[i:min(i + size, len(req))])
			if (i / size) % 3 == 0 { time.sleep(100 * time.Microsecond) }
		}
		resp, _ := raw_recv(c, time.Second)
		testing.expectf(t, strings.has_suffix(resp, want), "pieces of %i: %q", size, resp)
		raw_close(c)
	}
}

@(test)
multipart_errors :: proc(t: ^testing.T) {
	ts := server_start(t, multipart_handler())
	defer server_stop(ts)

	ok_part := Form_Part{headers = "Content-Disposition: form-data; name=\"a\"\r\n", data = "x"}
	many := make([]Form_Part, 1001, context.temp_allocator)
	for &p in many { p = ok_part }
	cases := []struct { content_type: string, body: string, status: int } {
		{"text/plain", "hi", 415},
		{"multipart/form-data", "hi", 415},
		{"multipart/form-data; boundary=", "hi", 415},
		{"multipart/form-data; boundary=a@b", "hi", 415},
		{"multipart/mixed; boundary=" + BOUNDARY, form_body({ok_part}), 415},
		// No closing delimiter, nothing but a preamble.
		{"", "--" + BOUNDARY + "\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nx", 400},
		{"", "just text", 400},
		// Not CRLF or "--" after the delimiter.
		{"", "--" + BOUNDARY + "x\r\n", 400},
		// No (form-data) Content-Disposition, no name, a bad header line.
		{"", form_body({{headers = "Content-Type: text/plain\r\n"}}), 400},
		{"", form_body({{headers = "Content-Disposition: attachment; name=\"a\"\r\n"}}), 400},
		{"", form_body({{headers = "Content-Disposition: form-data; filename=\"a\"\r\n"}}), 400},
		{"", form_body({{headers = "Content-Disposition: form-data; name=\"a\r\n"}}), 400},
		{"", form_body({{headers = "no colon\r\n"}}), 400},
		// Limits.
		{"", form_body({{headers = strings.concatenate({"Content-Disposition: form-data; name=\"a\"\r\nX: ", strings.repeat("y", 9000, context.temp_allocator), "\r\n"}, context.temp_allocator)}}), 431},
		{"", form_body(many), 413},
	}
	for tc in cases {
		ct := tc.content_type if tc.content_type != "" else "multipart/form-data; boundary=" + BOUNDARY
		for path in ([]string{"/mp", "/mp-parse"}) {
			resp := roundtrip(ts, form_request(path, tc.body, ct))
			testing.expectf(t, status_of(resp) == tc.status, "%s %q %.80q: %q", path, ct, tc.body, resp)
		}
	}
}

// A large file part goes through the stream's buffer, nothing piles up.
@(test)
multipart_large_file :: proc(t: ^testing.T) {
	testing.set_fail_timeout(t, 60 * time.Second)
	ts := server_start(t, multipart_handler())
	defer server_stop(ts)

	data := make([]byte, 64 << 20, context.temp_allocator)
	for &c, i in data { c = byte(i * 13 + i >> 11) }
	parts := []Form_Part{
		{headers = "Content-Disposition: form-data; name=\"f\"; filename=\"f.bin\"\r\nContent-Type: application/octet-stream\r\n", name = "f", filename = "f.bin", content_type = "application/octet-stream", data = string(data)},
		{headers = "Content-Disposition: form-data; name=\"after\"\r\n", name = "after", content_type = "text/plain", data = "done"},
	}
	resp := roundtrip(ts, form_request("/mp", form_body(parts)), wait = 10 * time.Second)
	testing.expectf(t, strings.has_suffix(resp, form_want(parts)), "%q", resp[max(0, len(resp) - 300):])
}
