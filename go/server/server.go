// Package server is funpipe's server. A client opens many streams over
// one byte stream, typically an ssh session's stdin and stdout; for each
// one, the server dials the destination the client names and splices the
// two until they close.
//
// A frame is a kind (u8), flags (u8), a stream (u32) and a length (u16),
// big-endian, then that many bytes of payload. The kinds are OPEN (0),
// whose payload is the destination; DATA (1); and WIN (2), whose payload
// is a u32 of credit. The one flag is FIN (1), on DATA.
//
// A destination is "host port", split at the last space so that an IPv6
// address needs no brackets, or the absolute path of a Unix socket, which
// a Server serves only when its Unix field says so.
//
// Flow control counts bytes. Each side may have 256 KiB outstanding on a
// stream, and the receiver returns credit for the bytes it consumes. A
// client that sends past its credit ends the tunnel.
//
// A client's FIN closes the stream. The clients send the same FIN for a
// half-close and a close, so the server cannot tell them apart: it
// delivers what the client sent, closes the destination both ways, and
// sends the client nothing more.
package server

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	kindOpen = 0
	kindData = 1
	kindWin  = 2
	flagFIN  = 1

	maxFrame    = 32 << 10  // payload of the DATA frames the server sends
	window      = 256 << 10 // bytes a sender may have outstanding on a stream
	maxStreams  = 64        // streams open at once on one tunnel
	dialTimeout = 10 * time.Second
)

// drainTimeout is how long a destination has, after the client closes a
// stream, to take the bytes the client sent before it. A var for tests.
var drainTimeout = 10 * time.Second

// ErrProtocol is wrapped by the error Serve returns when a client breaks
// the protocol, which ends the tunnel: it sends past its credit, opens a
// stream twice, or sends a WIN that is not four bytes.
var ErrProtocol = errors.New("protocol violation")

var (
	errTunnel = errors.New("tunnel ended")
	errFull   = fmt.Errorf("%d streams open already", maxStreams)
	errClosed = errors.New("closed by the client")
	errUnix   = errors.New("not serving Unix sockets")
)

// An Event is a stream when a client opens it and when it ends.
type Event struct {
	Stream  uint32 // the client's number for it; 0 for Splice's one stream
	Network string // "tcp" or "unix"; "" when the destination is not one
	Address string // host:port or a socket's path; as sent when Network is ""
	Opened  time.Time
	End     bool // false when it opens, true when it ends

	// When End is true:
	Up   int64 // bytes delivered to the destination
	Down int64 // bytes delivered to the client
	Err  error // why it ended; nil when both sides closed it
}

// A Hook sees each stream twice: when it opens, where an error refuses it
// and the client sees it end at once, and when it ends, where its return
// is ignored. A stream the server refuses itself, past the streams it
// holds at once, with a destination that is not one, or to a Unix socket
// when Unix is false, is seen only at its end. Hooks run on many
// goroutines at once, and should return promptly.
type Hook func(Event) error

// A Server holds the policy of the tunnels it serves. The zero value
// admits every TCP destination and no Unix socket, logs none, and dials
// with a 10 second timeout.
type Server struct {
	Hook Hook
	// Dial reaches a destination; nil is a net.Dialer.
	Dial func(ctx context.Context, network, address string) (net.Conn, error)
	// Unix serves destinations that are Unix sockets' paths, for a Hook
	// to admit one by one. Off, they are refused before the Hook sees
	// them: the sockets a user can reach are often more than the user
	// means to share, and a Hook written for TCP would admit them all.
	Unix bool
}

func (s *Server) hook(e Event) error {
	if s.Hook == nil {
		return nil
	}
	return s.Hook(e)
}

// admit decides whether a stream opens: the server's own rules, then the
// Hook's.
func (s *Server) admit(e Event) error {
	if e.Network == "unix" && !s.Unix {
		return errUnix
	}
	return s.hook(e)
}

func (s *Server) dial(ctx context.Context, network, address string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	if s.Dial != nil {
		return s.Dial(ctx, network, address)
	}
	var d net.Dialer
	return d.DialContext(ctx, network, address)
}

// Serve carries streams over r and w until r ends. Then it ends the
// streams still open and returns once they have. The clean end of r is
// a nil error.
func (s *Server) Serve(r io.Reader, w io.Writer) error {
	ctx, cancel := context.WithCancel(context.Background())
	t := &tunnel{s: s, ctx: ctx, w: w, streams: map[uint32]*stream{}}
	err := t.read(bufio.NewReaderSize(r, 64<<10))
	cancel()
	t.end()
	return err
}

type tunnel struct {
	s   *Server
	ctx context.Context

	wmu  sync.Mutex
	w    io.Writer
	werr error

	mu      sync.Mutex
	streams map[uint32]*stream
	wg      sync.WaitGroup
}

func (t *tunnel) read(r io.Reader) error {
	var h [8]byte
	for {
		if _, err := io.ReadFull(r, h[:]); err != nil {
			if err == io.EOF {
				return nil
			}
			return fmt.Errorf("a frame cut short: %w", err)
		}
		id := binary.BigEndian.Uint32(h[2:6])
		p := make([]byte, binary.BigEndian.Uint16(h[6:8]))
		if _, err := io.ReadFull(r, p); err != nil {
			return fmt.Errorf("a frame cut short: %w", err)
		}
		var err error
		switch h[0] {
		case kindOpen:
			err = t.open(id, string(p))
		case kindData:
			err = t.data(id, h[1]&flagFIN != 0, p)
		case kindWin:
			err = t.win(id, p)
		}
		if err != nil {
			return err
		}
	}
}

func (t *tunnel) stream(id uint32) *stream {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.streams[id]
}

func (t *tunnel) open(id uint32, dest string) error {
	t.mu.Lock()
	if t.streams[id] != nil {
		t.mu.Unlock()
		return fmt.Errorf("%w: stream %d opened twice", ErrProtocol, id)
	}
	if len(t.streams) >= maxStreams {
		t.mu.Unlock()
		e := Event{Stream: id, Opened: time.Now(), End: true, Err: errFull}
		if n, a, err := parseDest(dest); err == nil {
			e.Network, e.Address = n, a
		} else {
			e.Address = dest
		}
		t.s.hook(e)
		t.fin(id)
		return nil
	}
	st := &stream{t: t, id: id, credit: window}
	st.cond = sync.NewCond(&st.mu)
	t.streams[id] = st
	t.wg.Add(1)
	t.mu.Unlock()
	go st.run(dest)
	return nil
}

func (t *tunnel) data(id uint32, fin bool, p []byte) error {
	st := t.stream(id)
	if st == nil {
		return nil // late, for a stream that has ended or was refused
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.queued+len(p) > window {
		return fmt.Errorf("%w: stream %d sent %d bytes past its credit", ErrProtocol, id, st.queued+len(p)-window)
	}
	if len(p) > 0 {
		// A small frame joins the chunk before it, so that a client's
		// tiny frames cost the server the bytes they carry, not a slice
		// each, and the destination fewer writes.
		if n := len(st.in); n > 0 && len(st.in[n-1])+len(p) <= maxFrame {
			st.in[n-1] = append(st.in[n-1], p...)
		} else {
			st.in = append(st.in, p)
		}
		st.queued += len(p)
	}
	if fin && !st.fin {
		st.fin = true
		if st.conn != nil {
			// What the client sent still goes, but a destination that
			// stops reading does not hold the stream open for good.
			st.conn.SetWriteDeadline(time.Now().Add(drainTimeout))
		}
	}
	st.cond.Broadcast()
	return nil
}

func (t *tunnel) win(id uint32, p []byte) error {
	if len(p) != 4 {
		return fmt.Errorf("%w: stream %d: a WIN of %d bytes", ErrProtocol, id, len(p))
	}
	if st := t.stream(id); st != nil {
		st.mu.Lock()
		st.credit += int64(binary.BigEndian.Uint32(p))
		st.cond.Broadcast()
		st.mu.Unlock()
	}
	return nil
}

// send writes one frame; b[:8] is room for its header.
func (t *tunnel) send(kind, flags byte, id uint32, b []byte) error {
	b[0], b[1] = kind, flags
	binary.BigEndian.PutUint32(b[2:6], id)
	binary.BigEndian.PutUint16(b[6:8], uint16(len(b)-8))
	t.wmu.Lock()
	defer t.wmu.Unlock()
	if t.werr == nil {
		_, t.werr = t.w.Write(b)
	}
	return t.werr
}

func (t *tunnel) fin(id uint32) error {
	return t.send(kindData, flagFIN, id, make([]byte, 8))
}

func (t *tunnel) credit(id uint32, n int) error {
	b := make([]byte, 12)
	binary.BigEndian.PutUint32(b[8:], uint32(n))
	return t.send(kindWin, 0, id, b)
}

// end ends the streams still open, and waits for them.
func (t *tunnel) end() {
	t.mu.Lock()
	for _, st := range t.streams {
		st.mu.Lock()
		st.ended = true
		if st.conn != nil {
			st.conn.Close()
		}
		st.cond.Broadcast()
		st.mu.Unlock()
	}
	t.mu.Unlock()
	t.wg.Wait()
}

type stream struct {
	t  *tunnel
	id uint32

	mu     sync.Mutex
	cond   *sync.Cond
	in     [][]byte // the client's bytes, not yet delivered
	queued int      // how many
	fin    bool     // the client has closed the stream
	ended  bool     // the tunnel has ended
	failed bool     // the destination's connection failed, and is closed
	credit int64    // bytes the client will take
	conn   net.Conn
}

func (st *stream) run(dest string) {
	defer st.t.wg.Done()
	e := Event{Stream: st.id, Opened: time.Now()}
	e.Up, e.Down, e.Err = st.serve(dest, &e)
	st.t.mu.Lock()
	delete(st.t.streams, st.id)
	st.t.mu.Unlock()
	e.End = true
	st.t.s.hook(e)
}

func (st *stream) serve(dest string, e *Event) (up, down int64, err error) {
	if e.Network, e.Address, err = parseDest(dest); err != nil {
		e.Address = dest
		st.t.fin(st.id)
		return 0, 0, err
	}
	if err = st.t.s.admit(*e); err != nil {
		st.t.fin(st.id)
		return 0, 0, err
	}
	conn, err := st.t.s.dial(st.t.ctx, e.Network, e.Address)
	if err != nil {
		st.t.fin(st.id)
		return 0, 0, err
	}
	st.mu.Lock()
	if st.ended {
		st.mu.Unlock()
		conn.Close()
		return 0, 0, errTunnel
	}
	st.conn = conn
	if st.fin {
		conn.SetWriteDeadline(time.Now().Add(drainTimeout))
	}
	st.mu.Unlock()

	var upErr error
	done := make(chan struct{})
	go func() {
		up, upErr = st.up(conn)
		close(done)
	}()
	down, err = st.down(conn)
	st.t.fin(st.id)
	<-done
	conn.Close()
	if err == nil {
		err = upErr
	}
	return up, down, err
}

// up delivers the client's bytes to the destination, and credits the
// client for each chunk, until the client closes the stream. Then, or when
// it fails, it closes the destination both ways.
func (st *stream) up(conn net.Conn) (int64, error) {
	defer conn.Close()
	var n int64
	for {
		st.mu.Lock()
		for len(st.in) == 0 && !st.fin && !st.ended {
			st.cond.Wait()
		}
		if len(st.in) == 0 {
			ended := st.ended
			st.mu.Unlock()
			if ended {
				return n, errTunnel
			}
			return n, nil
		}
		p := st.in[0]
		st.in[0] = nil
		st.in = st.in[1:]
		st.queued -= len(p)
		st.mu.Unlock()
		if _, err := conn.Write(p); err != nil {
			return n, st.why(err, true)
		}
		n += int64(len(p))
		st.t.credit(st.id, len(p))
	}
}

// down sends the destination's bytes to the client, as its credit allows,
// until the destination's side ends or the client closes the stream.
func (st *stream) down(conn net.Conn) (int64, error) {
	var sent int64
	b := make([]byte, 8+maxFrame)
	for {
		n, err := conn.Read(b[8:])
		for off := 0; off < n; {
			k, err := st.take(n - off)
			if err != nil {
				if err == errClosed {
					return sent, nil
				}
				return sent, err
			}
			// The header goes before the next bytes, over ones already sent.
			if err := st.t.send(kindData, 0, st.id, b[off:off+8+k]); err != nil {
				return sent, st.why(err, false)
			}
			off += k
			sent += int64(k)
		}
		if err != nil {
			if err == io.EOF {
				return sent, nil
			}
			return sent, st.why(err, false)
		}
	}
}

// take waits for credit, and takes up to n bytes of it.
func (st *stream) take(n int) (int, error) {
	st.mu.Lock()
	defer st.mu.Unlock()
	for st.credit <= 0 && !st.fin && !st.ended {
		st.cond.Wait()
	}
	switch {
	case st.ended:
		return 0, errTunnel
	case st.fin:
		return 0, errClosed
	}
	k := min(int64(n), st.credit)
	st.credit -= k
	return int(k), nil
}

// why names the end of one way of a stream, up to the destination or
// down from it: the tunnel's end, or else the first error, which closes
// the destination's connection so that the other way ends too, without an
// error of its own. After the client's close, an error down is no error,
// as the client wants nothing more; one up is bytes the client sent that
// the destination did not take.
func (st *stream) why(err error, up bool) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	switch {
	case st.ended:
		return errTunnel
	case st.failed, st.fin && !up:
		return nil
	}
	st.failed = true
	st.conn.Close()
	if st.fin {
		return fmt.Errorf("after the client's close: %w", err)
	}
	return err
}

// Splice serves one stream to dest straight over r and w, with no frames.
// Each way closes on its own, as nc -N does: the end of r closes the
// destination's writing side, and the end of the destination's closes w,
// by CloseWrite if w has one, else by Close. It returns when both have
// ended.
func (s *Server) Splice(r io.Reader, w io.Writer, dest string) error {
	e := Event{Opened: time.Now()}
	e.Up, e.Down, e.Err = s.splice(r, w, dest, &e)
	e.End = true
	s.hook(e)
	return e.Err
}

func (s *Server) splice(r io.Reader, w io.Writer, dest string, e *Event) (up, down int64, err error) {
	if e.Network, e.Address, err = parseDest(dest); err != nil {
		e.Address = dest
		closeWrite(w)
		return 0, 0, err
	}
	if err = s.admit(*e); err != nil {
		closeWrite(w)
		return 0, 0, err
	}
	conn, err := s.dial(context.Background(), e.Network, e.Address)
	if err != nil {
		closeWrite(w)
		return 0, 0, err
	}
	defer conn.Close()
	var upErr error
	done := make(chan struct{})
	go func() {
		up, upErr = io.Copy(conn, r)
		closeWrite(conn)
		close(done)
	}()
	down, err = io.Copy(w, conn)
	closeWrite(w)
	<-done
	if err == nil {
		err = upErr
	}
	return up, down, err
}

func closeWrite(x any) {
	if c, ok := x.(interface{ CloseWrite() error }); ok {
		c.CloseWrite()
	} else if c, ok := x.(io.Closer); ok {
		c.Close()
	}
}

// parseDest reads a destination: "host port", split at the last space so
// that an IPv6 address needs no brackets, or a Unix socket's absolute path.
func parseDest(d string) (network, address string, err error) {
	for i := 0; i < len(d); i++ {
		if d[i] < ' ' || d[i] > '~' {
			return "", "", errors.New("destination not printable ASCII")
		}
	}
	if strings.HasPrefix(d, "/") && !strings.Contains(d, " ") {
		return "unix", filepath.Clean(d), nil
	}
	i := strings.LastIndexByte(d, ' ')
	if i < 0 {
		return "", "", errors.New(`destination not "host port" or a socket's path`)
	}
	host, port := strings.TrimSuffix(strings.TrimPrefix(d[:i], "["), "]"), d[i+1:]
	if host == "" || strings.Contains(host, " ") {
		return "", "", errors.New(`destination not "host port"`)
	}
	if n, err := strconv.ParseUint(port, 10, 16); err != nil || n == 0 {
		return "", "", fmt.Errorf("destination port %q not 1 to 65535", port)
	}
	return "tcp", net.JoinHostPort(host, port), nil
}
