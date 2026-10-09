package server

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	mux "github.com/ubicloud/funpipe/go/client"
)

// pair serves s on one end of two pipes and returns a client on the other,
// and a func that ends the tunnel from the client's side and returns what
// Serve did.
func pair(t *testing.T, s *Server) (*mux.Mux, func() error) {
	t.Helper()
	cr, sw := io.Pipe()
	sr, cw := io.Pipe()
	res := make(chan error, 1)
	go func() {
		err := s.Serve(sr, sw)
		sw.Close()
		res <- err
	}()
	m := mux.NewRW(cr, cw)
	var once sync.Once
	var err error
	stop := func() error {
		once.Do(func() {
			cw.Close()
			select {
			case err = <-res:
			case <-time.After(5 * time.Second):
				err = errors.New("Serve did not return")
			}
			m.Close()
		})
		return err
	}
	t.Cleanup(func() { stop() })
	return m, stop
}

// ends collects the events a hook sees at streams' ends.
type ends chan Event

func newEnds() ends { return make(ends, 4*maxStreams) }

func (c ends) hook(e Event) error {
	if e.End {
		c <- e
	}
	return nil
}

func (c ends) next(t *testing.T) Event {
	t.Helper()
	select {
	case e := <-c:
		return e
	case <-time.After(5 * time.Second):
		t.Fatal("no stream ended")
		return Event{}
	}
}

// pipes is a Dial that hands the server one end of a net.Pipe and the test
// the other, so a test decides what the destination reads and when.
type pipes chan net.Conn

func (p pipes) dial(ctx context.Context, network, address string) (net.Conn, error) {
	a, b := net.Pipe()
	p <- b
	return a, nil
}

func (p pipes) next(t *testing.T) net.Conn {
	t.Helper()
	select {
	case c := <-p:
		t.Cleanup(func() { c.Close() })
		return c
	case <-time.After(5 * time.Second):
		t.Fatal("no stream dialled")
		return nil
	}
}

func listen(t *testing.T, network string, serve func(net.Conn)) string {
	t.Helper()
	addr := "127.0.0.1:0"
	if network == "unix" {
		addr = filepath.Join(t.TempDir(), "s")
	}
	l, err := net.Listen(network, addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func() {
				serve(c)
				c.Close()
			}()
		}
	}()
	if network == "unix" {
		return addr
	}
	host, port, _ := net.SplitHostPort(l.Addr().String())
	return host + " " + port
}

func echo(c net.Conn) { io.Copy(c, c) }

func TestEcho(t *testing.T) {
	for _, network := range []string{"tcp", "unix"} {
		t.Run(network, func(t *testing.T) {
			dest := listen(t, network, echo)
			c := newEnds()
			m, stop := pair(t, &Server{Hook: c.hook, Unix: network == "unix"})
			const n, size = 8, 1 << 20
			var wg sync.WaitGroup
			for i := 0; i < n; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					s, err := m.Open([]byte(dest))
					if err != nil {
						t.Error(err)
						return
					}
					want := make([]byte, size)
					rand.Read(want)
					go s.Write(want)
					got := make([]byte, size)
					if _, err := io.ReadFull(s, got); err != nil || !bytes.Equal(got, want) {
						t.Errorf("echo: %v, equal %v", err, bytes.Equal(got, want))
					}
					s.Close()
				}()
			}
			wg.Wait()
			for i := 0; i < n; i++ {
				e := c.next(t)
				if e.Err != nil || e.Up != size || e.Down != size || e.Network != network {
					t.Errorf("end: %+v", e)
				}
			}
			if err := stop(); err != nil {
				t.Error(err)
			}
		})
	}
}

// A client may split its credit into as many frames as it likes: the
// server holds what it has not delivered by the byte, not by the frame.
func TestSmallFramesWithinCredit(t *testing.T) {
	p := make(pipes, 1)
	m, stop := pair(t, &Server{Dial: p.dial})
	s, _ := m.Open([]byte("stalled 1"))
	dest := p.next(t)
	const n = 20000
	for i := 0; i < n; i++ {
		if _, err := s.Write([]byte{byte(i)}); err != nil {
			t.Fatal(err)
		}
	}
	// The destination has read nothing yet; the tunnel still carries others.
	e, _ := m.Open([]byte("other 1"))
	other := p.next(t)
	go e.Write([]byte("hi"))
	b := make([]byte, 2)
	if _, err := io.ReadFull(other, b); err != nil || string(b) != "hi" {
		t.Fatalf("other stream: %q, %v", b, err)
	}
	got := make([]byte, n)
	if _, err := io.ReadFull(dest, got); err != nil {
		t.Fatal(err)
	}
	for i := range got {
		if got[i] != byte(i) {
			t.Fatalf("byte %d: %d", i, got[i])
		}
	}
	if err := stop(); err != nil {
		t.Error(err)
	}
}

// Tiny frames are held in chunks of up to maxFrame, not a slice each, so
// a stream's backlog costs about the bytes in it.
func TestSmallFramesJoin(t *testing.T) {
	tn := &tunnel{streams: map[uint32]*stream{}}
	st := &stream{t: tn, id: 1, credit: window}
	st.cond = sync.NewCond(&st.mu)
	tn.streams[1] = st
	for i := 0; i < window; i++ {
		if err := tn.data(1, false, []byte{byte(i)}); err != nil {
			t.Fatal(err)
		}
	}
	if len(st.in) != window/maxFrame {
		t.Fatalf("%d bytes held in %d chunks", window, len(st.in))
	}
	for _, c := range st.in {
		for i := range c {
			if c[i] != byte(i) {
				t.Fatalf("byte %d: %d", i, c[i])
			}
		}
	}
	if err := tn.data(1, false, []byte{0}); !errors.Is(err, ErrProtocol) {
		t.Fatalf("past credit: %v", err)
	}
}

// Unix sockets are served only when the Server says so, and then by the
// Hook's leave.
func TestUnix(t *testing.T) {
	dest := listen(t, "unix", echo)
	for _, unix := range []bool{false, true} {
		c := newEnds()
		m, _ := pair(t, &Server{Hook: c.hook, Unix: unix})
		s, _ := m.Open([]byte(dest))
		go s.Write([]byte("ping"))
		b, _ := io.ReadAll(io.LimitReader(s, 4))
		s.Close()
		e := c.next(t)
		if unix && (string(b) != "ping" || e.Err != nil) {
			t.Errorf("Unix on: read %q, end %+v", b, e)
		}
		if !unix && (len(b) != 0 || e.Err != errUnix || e.Network != "unix") {
			t.Errorf("Unix off: read %q, end %+v", b, e)
		}
	}
}

// Bytes the client sent before its close that the destination does not
// take are an error, not a clean end.
func TestUndeliveredAfterClose(t *testing.T) {
	old := drainTimeout
	drainTimeout = 100 * time.Millisecond
	t.Cleanup(func() { drainTimeout = old }) // after pair's cleanup ends the server
	p := make(pipes, 1)
	c := newEnds()
	m, _ := pair(t, &Server{Dial: p.dial, Hook: c.hook})
	s, _ := m.Open([]byte("stalled 1"))
	p.next(t) // never read
	s.Write([]byte("lost"))
	s.Close()
	if e := c.next(t); e.Err == nil || e.Up != 0 {
		t.Fatalf("end: %+v", e)
	}
}

func frame(kind, flags byte, id uint32, p []byte) []byte {
	b := make([]byte, 8, 8+len(p))
	b[0], b[1] = kind, flags
	binary.BigEndian.PutUint32(b[2:6], id)
	binary.BigEndian.PutUint16(b[6:8], uint16(len(p)))
	return append(b, p...)
}

func TestPastCredit(t *testing.T) {
	p := make(pipes, 1)
	sr, cw := io.Pipe()
	cr, sw := io.Pipe()
	go io.Copy(io.Discard, cr)
	res := make(chan error, 1)
	go func() {
		err := (&Server{Dial: p.dial}).Serve(sr, sw)
		sr.Close() // the client's next write fails
		res <- err
	}()
	cw.Write(frame(kindOpen, 0, 1, []byte("stalled 1")))
	p.next(t) // never read
	chunk := make([]byte, maxFrame)
	sent := 0
	for sent <= window+2*maxFrame {
		if _, err := cw.Write(frame(kindData, 0, 1, chunk)); err != nil {
			break // Serve has returned, and stopped reading
		}
		sent += len(chunk)
	}
	cw.Close()
	if err := <-res; !errors.Is(err, ErrProtocol) {
		t.Fatalf("Serve: %v", err)
	}
}

// A client's close ends the stream even when the destination neither
// sends nor closes, so such streams do not pile up to the limit.
func TestCloseEndsStream(t *testing.T) {
	p := make(pipes, 1)
	c := newEnds()
	m, _ := pair(t, &Server{Dial: p.dial, Hook: c.hook})
	for i := 0; i < 2*maxStreams; i++ {
		s, err := m.Open([]byte("silent 1"))
		if err != nil {
			t.Fatal(err)
		}
		dest := p.next(t)
		go s.Write([]byte("ping"))
		b := make([]byte, 4)
		if _, err := io.ReadFull(dest, b); err != nil {
			t.Fatalf("stream %d: %v", i, err)
		}
		s.Close()
		if e := c.next(t); e.Err != nil || e.Up != 4 {
			t.Fatalf("stream %d end: %+v", i, e)
		}
		if _, err := dest.Read(b); err != io.EOF {
			t.Fatalf("destination after close: %v", err)
		}
	}
}

// The destination's end reaches the client, who may still send.
func TestDestinationClosesFirst(t *testing.T) {
	got := make(chan string, 1)
	dest := listen(t, "tcp", func(c net.Conn) {
		c.Write([]byte("hello"))
		c.(*net.TCPConn).CloseWrite()
		b, _ := io.ReadAll(c)
		got <- string(b)
	})
	m, _ := pair(t, &Server{})
	s, _ := m.Open([]byte(dest))
	b, err := io.ReadAll(s)
	if err != nil || string(b) != "hello" {
		t.Fatalf("read %q, %v", b, err)
	}
	s.Write([]byte("more"))
	s.Close()
	select {
	case b := <-got:
		if b != "more" {
			t.Fatalf("destination read %q", b)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("destination not closed")
	}
}

func TestRefuse(t *testing.T) {
	no := errors.New("not on the list")
	c := newEnds()
	m, _ := pair(t, &Server{Hook: func(e Event) error {
		if !e.End {
			return no
		}
		return c.hook(e)
	}})
	s, _ := m.Open([]byte("192.0.2.1 22"))
	if b, err := io.ReadAll(s); err != nil || len(b) != 0 {
		t.Fatalf("refused stream: %q, %v", b, err)
	}
	if e := c.next(t); e.Err != no || e.Address != "192.0.2.1:22" {
		t.Fatalf("end: %+v", e)
	}
}

func TestTooMany(t *testing.T) {
	p := make(pipes, 1)
	c := newEnds()
	m, _ := pair(t, &Server{Dial: p.dial, Hook: c.hook})
	var open []*mux.Stream
	for i := 0; i < maxStreams; i++ {
		s, _ := m.Open([]byte("silent 1"))
		p.next(t)
		open = append(open, s)
	}
	s, _ := m.Open([]byte("silent 1"))
	if b, err := io.ReadAll(s); err != nil || len(b) != 0 {
		t.Fatalf("stream past the limit: %q, %v", b, err)
	}
	if e := c.next(t); e.Err != errFull {
		t.Fatalf("end: %+v", e)
	}
	open[0].Close()
	c.next(t)
	s, _ = m.Open([]byte("silent 1"))
	dest := p.next(t)
	go s.Write([]byte("x"))
	if _, err := dest.Read(make([]byte, 1)); err != nil {
		t.Fatal(err)
	}
}

func TestTunnelEnd(t *testing.T) {
	p := make(pipes, 1)
	c := newEnds()
	m, stop := pair(t, &Server{Dial: p.dial, Hook: c.hook})
	var dests []net.Conn
	for i := 0; i < 3; i++ {
		m.Open([]byte("silent 1"))
		dests = append(dests, p.next(t))
	}
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if e := c.next(t); e.Err != errTunnel {
			t.Errorf("end: %+v", e)
		}
	}
	for _, d := range dests {
		if _, err := d.Read(make([]byte, 1)); err != io.EOF {
			t.Errorf("destination: %v", err)
		}
	}
}

// Splice closes each way on its own, as nc -N does.
func TestSplice(t *testing.T) {
	dest := listen(t, "tcp", func(c net.Conn) {
		b, _ := io.ReadAll(c)
		fmt.Fprintf(c, "got %d", len(b))
	})
	var w bytes.Buffer
	c := newEnds()
	s := &Server{Hook: c.hook}
	if err := s.Splice(strings.NewReader("hello"), &w, dest); err != nil {
		t.Fatal(err)
	}
	if w.String() != "got 5" {
		t.Fatalf("got %q", w.String())
	}
	if e := c.next(t); e.Err != nil || e.Up != 5 || e.Down != 5 || e.Stream != 0 {
		t.Fatalf("end: %+v", e)
	}
}

func TestParseDest(t *testing.T) {
	for _, c := range []struct{ in, network, address string }{
		{"10.0.0.1 22", "tcp", "10.0.0.1:22"},
		{"fd00::1 22", "tcp", "[fd00::1]:22"},
		{"[fd00::1] 22", "tcp", "[fd00::1]:22"},
		{"example.com 443", "tcp", "example.com:443"},
		{"/run/x.sock", "unix", "/run/x.sock"},
		{"/run/../run/x.sock", "unix", "/run/x.sock"},
		{"10.0.0.1", "", ""},
		{"10.0.0.1 0", "", ""},
		{"10.0.0.1 65536", "", ""},
		{"10.0.0.1 ssh", "", ""},
		{"a b 22", "", ""},
		{" 22", "", ""},
		{"host\n 22", "", ""},
		{"", "", ""},
	} {
		n, a, err := parseDest(c.in)
		if n != c.network || a != c.address || (err == nil) != (c.network != "") {
			t.Errorf("%q: %q %q %v", c.in, n, a, err)
		}
	}
}
