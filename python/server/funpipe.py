"""funpipe protocol: server side.

Implements the server half of the funpipe stream-multiplexing protocol: reads
the wire format off a pair of fds, and for each stream a peer opens, dials the
requested destination and splices bytes both ways until close. It is a library
first -- Mux/Stream/serve/run take their fds and their dialer as arguments, so
the same code drives the CLI (run(0, 1) over an SSH session channel) and an
embedding process (arbitrary fds, a custom dialer routing through a netns, a
unix socket, or an allowlist). run() as a script entry point is just the
default wiring.

Each stream's SYN payload is a "host port" destination (space-separated; bare
IPv6 literals need no bracket disambiguation), dialed by the injected dialer
(default: a plain TCP connect from the current netns).

Wire: type:u8 flags:u8 stream:u32-BE length:u16-BE  payload
Types: 0=SYN(payload=destination) 1=DATA 2=WIN(u32 credit)
Flags: 1=FIN (DATA only)

FIN semantics -- CLIENT-DEPENDENT, read before reusing. This server treats a
DATA|FIN as a *full* close and tears down the upstream->client writer too. That
is correct only against a client that does not distinguish half-close from
close on the wire: the reference client (mews's mux.go) emits the same DATA|FIN
for CloseWrite and Close, so the server genuinely cannot tell them apart, and
treating FIN as half-close would wedge the upstream writer forever once a
closed client stops granting WIN. The cost is that write-FIN-then-read-response
(half-close request, then read the reply) is NOT supported. The reference
callers never do this -- http.Transport and the WS splice hold streams open
until done. A client that needs half-close must first grow a distinct RST (or
separate shutdown) frame; until then, do not point a half-closing client at
this server.
"""

import os, socket, struct, threading, queue

HDR = "!BBIH"
SYN, DATA, WIN = 0, 1, 2
FIN = 1
MAX, INITIAL = 32_768, 256 * 1024
# Safety caps. Client misuse is the client's problem, but the server must not
# let a buggy or hostile client OOM the bastion (and thus other processes).
# Invariant: a client honoring flow control has at most INITIAL bytes in
# flight per stream, however it frames them, so a backlog past INITIAL is a
# protocol violation.
STREAMS_MAX = 64    # concurrent streams per tunnel; cap on threads + sockets + memory


class Mux:
    def __init__(self, rfd, wfd):
        self.rfd, self.wfd = rfd, wfd
        self.wm = threading.Lock()
        self.streams = {}
        self.accept_q = queue.Queue()
        self._reader = threading.Thread(target=self._read_loop, daemon=True)

    def start(self):
        # Separate from __init__ so a Mux can be constructed without touching
        # its fds (tests, embedding). Call once.
        self._reader.start()
        return self

    def accept(self):
        # Blocks for the next SYN'd stream; None = tunnel closed.
        return self.accept_q.get()

    def frame(self, t, fl, sid, payload=b""):
        mv = memoryview(struct.pack(HDR, t, fl, sid, len(payload)) + payload)
        try:
            with self.wm:
                while mv:  # pipe writes beyond PIPE_BUF can be partial
                    mv = mv[os.write(self.wfd, mv) :]
        except OSError:
            pass  # stdout gone: session is dead; read side will EOF and tear down

    def retire(self, sid):
        # serve() calls this on exit; frees a slot for STREAMS_MAX accounting.
        self.streams.pop(sid, None)

    def _readn(self, n):
        buf = bytearray()
        while len(buf) < n:  # os.read on a pipe returns short reads
            try:
                c = os.read(self.rfd, n - len(buf))
            except OSError:
                return None
            if not c:
                return None
            buf += c
        return bytes(buf)

    def _read_loop(self):
        try:
            while (h := self._readn(8)) is not None:
                t, fl, sid, ln = struct.unpack(HDR, h)
                p = self._readn(ln) if ln else b""
                if p is None:
                    break
                if t == SYN:
                    if len(self.streams) >= STREAMS_MAX:
                        # cap reached: refuse without registering. Client sees
                        # immediate EOF on the stream's read side.
                        self.frame(DATA, FIN, sid)
                        continue
                    s = self.streams[sid] = Stream(self, sid, p)
                    self.accept_q.put(s)
                    continue
                # Unknown sid: silently drop. Could be a late frame for a
                # retired stream, or a frame for a SYN we refused.
                s = self.streams.get(sid)
                if s is None:
                    continue
                if t == DATA:
                    if p:
                        s.push(p)
                    if fl & FIN:
                        s.push(None)
                elif t == WIN:
                    s.grant(struct.unpack("!I", p)[0])  # malformed = tunnel-fatal
        finally:
            for s in list(self.streams.values()):
                s.push(None)
            self.accept_q.put(None)


class Stream:
    def __init__(self, mux, sid, dest):
        self.mux, self.id, self.dest = mux, sid, dest
        self.rq = queue.Queue()
        self.backlog = 0  # bytes pushed and not yet read
        self.swin = INITIAL
        self.cv = threading.Condition()
        self.dead = False

    def read(self):
        # Frame payloads are <= u16 max, so chunks pass through whole; the
        # WIN credit returned is exactly what the splice loop consumed.
        c = self.rq.get()
        if c is None:
            return None
        with self.cv:
            self.backlog -= len(c)
        self.mux.frame(WIN, 0, self.id, struct.pack("!I", len(c)))
        return c

    def write(self, s):
        o = 0
        while o < len(s):
            with self.cv:
                while self.swin <= 0 and not self.dead:
                    self.cv.wait()
                if self.dead:
                    # Client FIN'd (= closed, see module docstring): no more
                    # WIN is coming. Raising (an OSError) breaks s2c's loop
                    # instead of silently draining the upstream forever.
                    raise BrokenPipeError(f"stream {self.id}: closed by client")
                k = min(len(s) - o, self.swin, MAX)
                self.swin -= k
            self.mux.frame(DATA, 0, self.id, s[o : o + k])
            o += k

    def close_write(self):
        self.mux.frame(DATA, FIN, self.id)

    def grant(self, d):
        with self.cv:
            self.swin += d
            self.cv.notify_all()

    def push(self, c):
        # None = EOF, always admitted; it also kills a writer parked on WIN
        # credit that will never arrive. Data is subject to the hard backlog
        # clamp, in bytes: a well-behaved client stalls naturally at INITIAL
        # (we stop sending WIN while c2s blocks on the upstream); this catches
        # a client ignoring flow control. Tunnel-fatal on purpose.
        if c is None:
            self.rq.put(c)
            with self.cv:
                self.dead = True
                self.cv.notify_all()
            return
        with self.cv:
            n = self.backlog + len(c)
            if n > INITIAL:
                raise RuntimeError(f"stream {self.id}: backlog {n} > {INITIAL} bytes")
            self.backlog = n
        self.rq.put(c)


def _dial(host, port):
    sock = socket.create_connection((host, int(port)), timeout=10)
    # In Python, but unlike Unix, the connect() timeout is further
    # applied to read() and write() for that connection which breaks
    # useful idle streams.
    sock.settimeout(None)
    return sock


def serve(stream, dial=_dial):
    # dial(host: str, port: str) -> socket-like with recv/sendall/shutdown/
    # setsockopt/close. Injectable so embedders can route via a netns,
    # a unix socket, or an allowlist. Must raise OSError/ValueError to refuse.
    try:
        host, _, port = stream.dest.decode("ascii").rpartition(" ")
        sock = dial(host, port)
    except (OSError, ValueError, UnicodeDecodeError):
        stream.close_write()
        stream.mux.retire(stream.id)
        return

    def s2c():
        try:
            while data := sock.recv(65536):
                stream.write(data)
        except OSError:
            pass
        stream.close_write()

    def c2s():
        try:
            while data := stream.read():
                sock.sendall(data)
        except OSError:
            pass
        try:
            sock.shutdown(socket.SHUT_WR)
        except OSError:
            pass

    t1 = threading.Thread(target=s2c, daemon=True)
    t1.start()
    t2 = threading.Thread(target=c2s, daemon=True)
    t2.start()
    t1.join()
    t2.join()
    sock.close()
    stream.mux.retire(stream.id)


def run(rfd, wfd, dial=_dial):
    # Library entry point: serve one tunnel over the given fds, blocking
    # until the read side EOFs, then joining every serve() thread so upstream
    # sockets are closed deterministically before we return (matters when
    # embedded in a longer-lived process). Returns the Mux for inspection.
    #
    # On EOF the reader's finally-block push(None)s every live stream, which
    # unblocks each serve()'s s2c/c2s, so these joins are bounded by in-flight
    # upstream I/O, not indefinite. Threads stay daemon so a hung upstream
    # can't wedge interpreter shutdown.
    mux = Mux(rfd, wfd).start()
    workers = []
    while (s := mux.accept()) is not None:
        t = threading.Thread(target=serve, args=(s, dial), daemon=True)
        t.start()
        # Prune finished threads so the list stays O(live streams), not
        # O(streams ever served), on a long-lived high-churn tunnel.
        workers = [w for w in workers if w.is_alive()]
        workers.append(t)
    for t in workers:
        t.join()
    return mux


def main():
    run(0, 1)


__all__ = ["Mux", "Stream", "serve", "run", "SYN", "DATA", "WIN", "FIN", "HDR"]

if __name__ == "__main__":
    main()
