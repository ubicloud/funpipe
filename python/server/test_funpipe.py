"""Tests for the funpipe server: python3 -m unittest, from this directory.

Each test runs the server on a pair of pipes, speaks the wire format from
the client's end, and dials socketpairs whose far ends the test holds, so a
test decides what a destination reads and when.
"""

import os, queue, select, socket, struct, threading, unittest

import funpipe
from funpipe import HDR, SYN, DATA


class Client:
    def __init__(self):
        c2s_r, self.w = os.pipe()
        os.set_blocking(self.w, False)
        self.r, s2c_w = os.pipe()
        self.dests = queue.Queue()
        self.done = threading.Event()

        def dial(host, port):
            return self.dests.get(timeout=5)

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

    def open(self, sid):
        """Open stream sid to a new destination, and return its far end."""
        mine, theirs = socket.socketpair()
        theirs.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
        self.dests.put(theirs)
        self.send(SYN, 0, sid, b"dest 1")
        mine.settimeout(5)
        return mine


def read(sock, n):
    b = b""
    while len(b) < n:
        c = sock.recv(n - len(b))
        if not c:
            break
        b += c
    return b


class TestServer(unittest.TestCase):
    def test_small_frames_within_window(self):
        # A client may split its window into as many frames as it likes.
        c = Client()
        dest = c.open(1)
        n = 20_000
        for i in range(n):
            c.send(DATA, 0, 1, bytes([i % 256]))
        # The destination has read nothing; the tunnel still carries others.
        other = c.open(3)
        c.send(DATA, 0, 3, b"hi")
        self.assertEqual(read(other, 2), b"hi")
        self.assertEqual(read(dest, n), bytes(i % 256 for i in range(n)))


if __name__ == "__main__":
    unittest.main()
