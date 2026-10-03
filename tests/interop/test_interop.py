"""
Interop tests: real clients (Python's http.client, curl, the websockets library) against the
interop server (tests/interop/server), directly and through Caddy. Run by scripts/interop.sh,
which sets:

    DIRECT  http://127.0.0.1:8080    the server
    PROXY   https://localhost:8443   Caddy in front of it (TLS, HTTP/2 to clients, pooled upstream)
    CA      Caddy's root certificate
    FILE    the file the server serves at /file
"""

import asyncio
import concurrent.futures
import hashlib
import http.client
import os
import random
import ssl
import subprocess
import tempfile
import time
import unittest
import urllib.parse

import websockets

DIRECT = os.environ["DIRECT"]
PROXY = os.environ["PROXY"]
CA = os.environ["CA"]
with open(os.environ["FILE"], "rb") as f:
    FILE_DATA = f.read()

MiB = 1 << 20


def pattern(n):
    """What /big?size=n returns: byte i is i % 251."""
    return (bytes(range(251)) * (n // 251 + 1))[:n]


def tls_context():
    return ssl.create_default_context(cafile=CA)


class Common:
    """Tests that run both directly and through Caddy (subclasses set `base`)."""

    base = ""

    def conn(self, timeout=30):
        u = urllib.parse.urlsplit(self.base)
        if u.scheme == "https":
            return http.client.HTTPSConnection(u.hostname, u.port, timeout=timeout, context=tls_context())
        return http.client.HTTPConnection(u.hostname, u.port, timeout=timeout)

    def request(self, method, path, body=None, headers=None, conn=None):
        c = conn or self.conn()
        try:
            c.request(method, path, body=body, headers=headers or {})
            r = c.getresponse()
            return r, r.read()
        finally:
            if conn is None:
                c.close()

    def curl(self, *args):
        p = subprocess.run(["curl", "-fsS", "--max-time", "30", "--cacert", CA, *args], capture_output=True, timeout=60)
        self.assertEqual(p.returncode, 0, p.stderr.decode())
        return p.stdout

    def ws_url(self, path="/ws"):
        return self.base.replace("http", "ws", 1) + path

    def ws_connect(self, **kw):
        ssl_ctx = tls_context() if self.base.startswith("https") else None
        return websockets.connect(self.ws_url(), ssl=ssl_ctx, max_size=32 * MiB, open_timeout=10, close_timeout=10, **kw)

    # --- HTTP ---

    def test_hello(self):
        r, body = self.request("GET", "/hello")
        self.assertEqual((r.status, body), (200, b"hello"))

    def test_not_found(self):
        r, _ = self.request("GET", "/nope")
        self.assertEqual(r.status, 404)

    def test_keep_alive_mixed(self):
        """Many requests of different shapes on one connection."""
        rng = random.Random(1)
        c = self.conn()
        try:
            for i in range(300):
                kind = i % 4
                if kind == 0:
                    r, body = self.request("GET", "/hello", conn=c)
                    self.assertEqual(body, b"hello")
                elif kind == 1:
                    data = rng.randbytes(rng.choice([0, 1, 100, 5000, 70000, 300000]))
                    r, body = self.request("POST", "/echo", body=data, conn=c)
                    self.assertEqual(body, data, f"echo {len(data)}")
                elif kind == 2:
                    n = rng.randrange(0, 200000)
                    r, body = self.request("GET", f"/big?size={n}", conn=c)
                    self.assertEqual(body, pattern(n))
                else:
                    r, body = self.request("HEAD", "/file", conn=c)
                    self.assertEqual((body, int(r.getheader("content-length"))), (b"", len(FILE_DATA)))
                self.assertIn(r.status, (200,), f"request {i}")
        finally:
            c.close()

    def test_chunked_upload(self):
        chunks = [os.urandom(n) for n in (1, 10, 1000, 65536, 3, 200000)]
        r, body = self.request("POST", "/echo", body=iter(chunks))  # An iterator: http.client sends it chunked.
        self.assertEqual((r.status, body), (200, b"".join(chunks)))

    def test_large_echo(self):
        data = os.urandom(10 * MiB)
        r, body = self.request("POST", "/echo", body=data)
        self.assertEqual(r.status, 200)
        self.assertEqual(hashlib.sha256(body).digest(), hashlib.sha256(data).digest())

    def test_expect_continue(self):
        """curl waits for the interim 100 before sending the body."""
        data = os.urandom(2 * MiB)
        with tempfile.NamedTemporaryFile() as f:
            f.write(data)
            f.flush()
            out = self.curl("-H", "Expect: 100-continue", "-H", "Content-Type: application/octet-stream",
                            "--data-binary", f"@{f.name}", self.base + "/echo")
        self.assertEqual(hashlib.sha256(out).digest(), hashlib.sha256(data).digest())

    def test_stream(self):
        r, body = self.request("GET", "/stream?n=20000")
        self.assertEqual(r.status, 200)
        self.assertEqual(body, "".join(f"line {i}\n" for i in range(20000)).encode())

    def test_file_and_ranges(self):
        r, body = self.request("GET", "/file")
        self.assertEqual((r.status, body), (200, FILE_DATA))
        self.assertEqual(r.getheader("accept-ranges"), "bytes")

        size = len(FILE_DATA)
        for rng, want in [("bytes=100-199", FILE_DATA[100:200]), (f"bytes={size - 10}-", FILE_DATA[-10:]), ("bytes=-50", FILE_DATA[-50:])]:
            r, body = self.request("GET", "/file", headers={"Range": rng})
            self.assertEqual(r.status, 206, rng)
            self.assertEqual(body, want, rng)

        r, _ = self.request("GET", "/file", headers={"Range": f"bytes={size}-"})
        self.assertEqual(r.status, 416)
        self.assertEqual(r.getheader("content-range"), f"bytes */{size}")

    def test_curl_http10(self):
        self.assertEqual(self.curl("--http1.0", self.base + "/hello"), b"hello")

    def test_curl_reuses_connection(self):
        urls = [self.base + p for p in ("/hello", "/big?size=100000", "/hello", "/file", "/hello")]
        args = []
        for u in urls:
            args += ["-o", "/dev/null", u]
        out = self.curl("--http1.1", "-w", "%{num_connects}\n", *args)
        self.assertEqual(sum(int(x) for x in out.split()), 1, out)

    def test_concurrent_clients(self):
        """Clients in parallel, each with a keep-alive connection; through Caddy this multiplexes onto
        its pooled upstream connections."""

        def client(seed):
            rng = random.Random(seed)
            c = self.conn()
            try:
                for _ in range(25):
                    if rng.random() < 0.5:
                        data = rng.randbytes(rng.randrange(0, 100000))
                        r, body = self.request("POST", "/echo", body=data, conn=c)
                        assert r.status == 200 and body == data, f"echo {len(data)}: {r.status}"
                    else:
                        n = rng.randrange(0, 100000)
                        r, body = self.request("GET", f"/big?size={n}", conn=c)
                        assert r.status == 200 and body == pattern(n), f"big {n}: {r.status}"
            finally:
                c.close()

        with concurrent.futures.ThreadPoolExecutor(32) as pool:
            for f in [pool.submit(client, s) for s in range(64)]:
                f.result()

    def test_aborted_download(self):
        """A client that goes away in the middle of a large response doesn't hurt the server."""
        for _ in range(5):
            c = self.conn()
            c.request("GET", f"/big?size={50 * MiB}")
            r = c.getresponse()
            self.assertEqual(len(r.read(MiB)), MiB)
            c.sock.close()
            c.close()
        r, body = self.request("GET", "/hello")
        self.assertEqual((r.status, body), (200, b"hello"))

    # --- WebSocket ---

    def test_websocket_echo(self):
        async def run():
            async with self.ws_connect(compression="deflate") as w:
                ext = w.response_headers.get("Sec-WebSocket-Extensions", "")
                self.assertIn("permessage-deflate", ext)
                rng = random.Random(2)
                for n in (0, 1, 125, 126, 65535, 65536, MiB, 5 * MiB):
                    text = "".join(rng.choice("abcdefgh ") for _ in range(min(n, 70000))) * (n // 70000 + 1)
                    text = text[:n]
                    await w.send(text)
                    self.assertEqual(await w.recv(), text)
                    data = rng.randbytes(n)
                    await w.send(data)
                    self.assertEqual(await w.recv(), data)

                # Pipelined: everything sent before reading the echoes, which come back in order.
                msgs = [f"message {i} " * (i % 50) for i in range(2000)]
                for m in msgs:
                    await w.send(m)
                for m in msgs:
                    self.assertEqual(await w.recv(), m)
                await w.close()
                self.assertEqual(w.close_code, 1000)

        asyncio.run(run())

    def test_websocket_uncompressed(self):
        async def run():
            async with self.ws_connect(compression=None) as w:
                self.assertNotIn("Sec-WebSocket-Extensions", w.response_headers)
                await w.send(b"\x00" * 100000)
                self.assertEqual(await w.recv(), b"\x00" * 100000)

        asyncio.run(run())

    def test_websocket_origin(self):
        u = urllib.parse.urlsplit(self.base)

        async def run(origin):
            async with self.ws_connect(origin=origin) as w:
                await w.send("hi")
                return await w.recv()

        # The default check: the Origin's host must be the Host the server sees (Caddy keeps it).
        self.assertEqual(asyncio.run(run(f"{u.scheme}://{u.netloc}")), "hi")
        with self.assertRaises(Exception) as cm:
            asyncio.run(run("https://evil.example"))
        self.assertIn("403", str(cm.exception))


class Direct(Common, unittest.TestCase):
    base = DIRECT

    def test_body_too_large(self):
        """Refused from the headers alone: with Expect: 100-continue the body is never sent."""
        c = self.conn()
        try:
            c.putrequest("POST", "/echo")
            c.putheader("Content-Length", str(64 * MiB))
            c.putheader("Expect", "100-continue")
            c.endheaders()
            r = c.getresponse()
            self.assertEqual(r.status, 413)
        finally:
            c.close()

    def test_stream_is_chunked(self):
        r, _ = self.request("GET", "/stream?n=10")
        self.assertEqual(r.getheader("transfer-encoding"), "chunked")


class Proxy(Common, unittest.TestCase):
    base = PROXY

    def test_client_address_not_spoofable(self):
        """Caddy replaces a client's X-Forwarded-For, so the server sees the real client."""
        r, body = self.request("GET", "/whoami", headers={"X-Forwarded-For": "6.6.6.6"})
        self.assertEqual(r.status, 200)
        self.assertIn(body.decode(), ("127.0.0.1", "::"))  # IPv6 is reduced to its /64.

    def test_rate_limit_per_client(self):
        """3 per minute per client, whatever X-Forwarded-For the client claims."""
        statuses = []
        for i in range(5):
            r, _ = self.request("GET", "/limited", headers={"X-Forwarded-For": f"10.0.0.{i}"})
            statuses.append(r.status)
            if r.status == 429:
                self.assertIsNotNone(r.getheader("retry-after"))
        self.assertEqual(statuses, [200, 200, 200, 429, 429])

    def test_pooled_connection_closed_by_server(self):
        """The server closes idle connections (after 2s here) that Caddy keeps in its pool, Caddy must
        notice and not hand them to new requests."""
        for i in range(3):
            for path in ("/hello", "/big?size=1000"):
                r, _ = self.request("GET", path)
                self.assertEqual(r.status, 200, f"round {i} {path}")
            data = os.urandom(1000)
            r, body = self.request("POST", "/echo", body=data)
            self.assertEqual((r.status, body), (200, data), f"round {i}")
            time.sleep(2.5)

    def test_http2_parallel(self):
        """HTTP/2 to Caddy, many streams at once, HTTP/1.1 from Caddy to the server."""
        with tempfile.TemporaryDirectory() as d:
            args = []
            for i in range(40):
                args += ["-o", f"{d}/{i}", self.base + (f"/big?size={i * 5000}" if i % 2 else "/hello")]
            out = self.curl("--http2", "--parallel", "--parallel-max", "40", "-w", "%{http_version}\n", *args)
            self.assertEqual(set(out.split()), {b"2"}, out)
            for i in range(40):
                with open(f"{d}/{i}", "rb") as f:
                    self.assertEqual(f.read(), pattern(i * 5000) if i % 2 else b"hello", i)


if __name__ == "__main__":
    unittest.main(verbosity=2)
