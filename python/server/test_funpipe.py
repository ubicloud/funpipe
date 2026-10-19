"""Tests for the funpipe server: python3 -m unittest, from this directory.

Each test runs the server on a pair of pipes, speaks the wire format from
the client's end, and dials socketpairs whose far ends the test holds, so a
test decides what an upstream reads and when.
"""

import os, queue, select, socket, struct, threading, unittest
from unittest import mock

import funpipe
from funpipe import HDR, SYN, DATA, WIN, FIN


class Client:
    def __init__(self):
        c2s_r, self.w = os.pipe()
        os.set_blocking(self.w, False)
        self.r, s2c_w = os.pipe()
        self.upstreams = queue.Queue()
        self.done = threading.Event()

        def dial(host, port):
            return self.upstreams.get(timeout=5)

        def run():
            funpipe.run(c2s_r, s2c_w, dial)
            self.done.set()

        threading.Thread(target=run, daemon=True).start()
        threading.Thread(target=self._drain, daemon=True).start()

    def _drain(self):
        # The server's frames, credit and data, which the tests need not read.
        while os.read(self.r, 65536):
            pass

    def send(self, t, fl, sid, p=b""):
        b = memoryview(struct.pack(HDR, t, fl, sid, len(p)) + p)
        while b:
            try:
                b = b[os.write(self.w, b):]
            except BlockingIOError:
                if not select.select([], [self.w], [], 5)[1]:
                    raise AssertionError("the server stopped reading")

    def upstream(self, wrap=lambda s: s):
        """Queue an upstream for the next dial, and return its far end."""
        mine, theirs = socket.socketpair()
        theirs.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
        self.upstreams.put(wrap(theirs))
        mine.settimeout(5)
        return mine

    def open(self, sid):
        """Open stream sid to a new upstream, and return its far end."""
        mine = self.upstream()
        self.send(SYN, 0, sid, b"dest 1")
        return mine


def read(sock, n):
    b = b""
    while len(b) < n:
        c = sock.recv(n - len(b))
        if not c:
            break
        b += c
    return b


class SlowShutdown:
    """An upstream whose shutdown(), in the thread named, waits for go."""

    def __init__(self, thread):
        self.thread = thread
        self.entered = threading.Event()
        self.go = threading.Event()
        self.closed = threading.Event()

    def wrap(self, sock):
        self.sock = sock
        return self

    def __getattr__(self, name):
        return getattr(self.sock, name)

    def shutdown(self, how):
        if threading.current_thread().name.endswith(f"({self.thread})"):
            self.entered.set()
            self.go.wait()
        self.sock.shutdown(how)

    def close(self):
        self.closed.set()
        self.sock.close()


class TestServer(unittest.TestCase):
    def test_small_frames_within_window(self):
        # A client may split its window into as many frames as it likes.
        c = Client()
        upstream = c.open(1)
        n = 20_000
        for i in range(n):
            c.send(DATA, 0, 1, bytes([i % 256]))
        # The upstream has read nothing; the tunnel still carries others.
        other = c.open(3)
        c.send(DATA, 0, 3, b"hi")
        self.assertEqual(read(other, 2), b"hi")
        self.assertEqual(read(upstream, n), bytes(i % 256 for i in range(n)))

    def test_close_ends_stream(self):
        # A client's close ends the stream even when the upstream neither
        # sends nor closes, so such streams do not pile up to STREAMS_MAX.
        c = Client()
        held = []
        for i in range(2 * funpipe.STREAMS_MAX):
            sid = 2 * i + 1
            upstream = c.open(sid)
            held.append(upstream)
            c.send(DATA, FIN, sid, b"ping")
            self.assertEqual(read(upstream, 4), b"ping")
            self.assertEqual(upstream.recv(1), b"")

    def test_tunnel_end_ends_streams(self):
        # The tunnel's end ends a stream whose upstream has stopped reading.
        c = Client()
        upstream = c.open(1)
        chunk = bytes(funpipe.MAX)
        for _ in range(funpipe.INITIAL // funpipe.MAX):
            c.send(DATA, 0, 1, chunk)
        os.close(c.w)
        self.assertTrue(c.done.wait(5))
        upstream.close()

    def test_tunnel_end_during_dial(self):
        # The tunnel ends while a stream dials, with INITIAL bytes queued for
        # an upstream that will not read them. run() gets None from accept()
        # only once the reader has walked the streams.
        walked = threading.Event()
        accept = funpipe.Mux.accept

        def spy(mux):
            s = accept(mux)
            if s is None:
                walked.set()
            return s

        with mock.patch.object(funpipe.Mux, "accept", spy):
            c = Client()
            c.send(SYN, 0, 1, b"dest 1")
            chunk = bytes(funpipe.MAX)
            for _ in range(funpipe.INITIAL // funpipe.MAX):
                c.send(DATA, 0, 1, chunk)
            os.close(c.w)
            self.assertTrue(walked.wait(5))
            upstream = c.upstream()
            self.assertTrue(c.done.wait(5))
        upstream.close()

    def test_no_close_during_shutdown(self):
        # serve() may not close an upstream, freeing its fd for reuse, while
        # the reader is in shutdown() on it.
        c = Client()
        slow = SlowShutdown("_read_loop")
        self.addCleanup(slow.go.set)
        upstream = c.upstream(slow.wrap)
        c.send(SYN, 0, 1, b"dest 1")
        chunk = bytes(funpipe.MAX)
        for _ in range(funpipe.INITIAL // funpipe.MAX):
            c.send(DATA, 0, 1, chunk)
        self.assertEqual(read(upstream, 1), b"\0")
        os.close(c.w)
        self.assertTrue(slow.entered.wait(5))
        # Let c2s send the rest, reach the EOF and call shutdown() itself.
        n = funpipe.INITIAL - 1
        self.assertEqual(len(read(upstream, n)), n)
        self.assertFalse(slow.closed.wait(0.2))
        slow.go.set()
        self.assertTrue(c.done.wait(5))

    def test_slow_shutdown_holds_up_no_other_stream(self):
        c = Client()
        slow = SlowShutdown("c2s")
        self.addCleanup(slow.go.set)
        c.upstream(slow.wrap)
        c.send(SYN, 0, 1, b"dest 1")
        c.send(DATA, FIN, 1)
        self.assertTrue(slow.entered.wait(5))
        c.send(WIN, 0, 1, struct.pack("!I", 1))
        other = c.open(3)
        c.send(DATA, 0, 3, b"hi")
        self.assertEqual(read(other, 2), b"hi")

    def test_open_twice_ends_tunnel(self):
        c = Client()
        upstream = c.open(1)
        raised = queue.Queue()
        with mock.patch("threading.excepthook", raised.put):
            c.send(SYN, 0, 1, b"dest 1")
            self.assertIn("opened twice", str(raised.get(timeout=5).exc_value))
        self.assertTrue(c.done.wait(5))
        upstream.close()


if __name__ == "__main__":
    unittest.main()
