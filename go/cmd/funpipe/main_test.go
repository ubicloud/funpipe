package main

import (
	"encoding/binary"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ubicloud/funpipe/go/server"
)

// TestMain runs the command itself when a test starts this binary with
// FUNPIPE_MAIN set.
func TestMain(m *testing.M) {
	if os.Getenv("FUNPIPE_MAIN") != "" {
		os.Args = append(os.Args[:1], strings.Fields(os.Getenv("FUNPIPE_MAIN"))...)
		main()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// command starts funpipe with args, on pipes the test holds the far ends of.
func command(t *testing.T, args string) (*exec.Cmd, *os.File, *os.File) {
	t.Helper()
	inR, inW, _ := os.Pipe()
	outR, outW, _ := os.Pipe()
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), "FUNPIPE_MAIN="+args, "SSH_ORIGINAL_COMMAND=")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = inR, outW, os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	inR.Close()
	outW.Close()
	return cmd, inW, outR
}

// A client that goes without closing its streams still has each one's end
// logged, rather than the server dying of SIGPIPE first.
func TestClientGone(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, _ := l.Accept()
		accepted <- c
	}()
	log := filepath.Join(t.TempDir(), "log")
	cmd, in, out := command(t, "-log "+log)

	dest := strings.Replace(l.Addr().String(), ":", " ", 1)
	open := make([]byte, 8, 8+len(dest))
	binary.BigEndian.PutUint32(open[2:6], 1)
	binary.BigEndian.PutUint16(open[6:8], uint16(len(dest)))
	in.Write(append(open, dest...))
	select {
	case c := <-accepted:
		defer c.Close()
	case <-time.After(5 * time.Second):
		t.Fatal("no stream dialled")
	}
	out.Close() // as sshd does when the client goes
	in.Close()

	err = cmd.Wait()
	if ws, ok := cmd.ProcessState.Sys().(interface{ Signaled() bool }); ok && ws.Signaled() {
		t.Fatalf("funpipe died of a signal: %v", err)
	}
	b, _ := os.ReadFile(log)
	if !strings.Contains(string(b), "stream 1 tcp "+l.Addr().String()+" ended") {
		t.Fatalf("no end logged:\n%s", b)
	}
}

func TestAllowed(t *testing.T) {
	list := filepath.Join(t.TempDir(), "allow")
	os.WriteFile(list, []byte(`# a comment
fd25:185d:32f9:1330::/64 22   # a bastion
fd25:185d:32f9:4524::/64 443
192.168.188.1 22
/run/postgresql/.s.PGSQL.5432
`), 0o600)
	for _, c := range []struct {
		network, address string
		ok               bool
	}{
		{"tcp", "[fd25:185d:32f9:1330::22]:22", true},
		{"tcp", "[fd25:185d:32f9:1330::22]:443", false},
		{"tcp", "[fd25:185d:32f9:4524::1]:443", true},
		{"tcp", "192.168.188.1:22", true},
		{"tcp", "[::ffff:192.168.188.1]:22", true},
		{"tcp", "192.168.188.2:22", false},
		{"tcp", "bastion.example:22", false},
		{"tcp", "[fe80::1%eth0]:22", false},
		{"unix", "/run/postgresql/.s.PGSQL.5432", true},
		{"unix", "/run/postgresql/other", false},
	} {
		if err := allowed(list, c.network, c.address); (err == nil) != c.ok {
			t.Errorf("%s %s: %v", c.network, c.address, err)
		}
	}
	os.WriteFile(list, []byte("192.168.188.1 22\n192.168.188.1\n"), 0o600)
	if err := allowed(list, "tcp", "192.168.188.1:22"); err == nil {
		t.Error("a list with a bad line admitted a stream")
	}
	if err := allowed(filepath.Join(t.TempDir(), "none"), "tcp", "192.168.188.1:22"); err == nil {
		t.Error("a missing list admitted a stream")
	}
}

// TestPass passes sessions from -pass to -listen as sshd gives them, a pipe
// each way: one to an echo the list admits, one to a destination it does
// not.
// relay starts a funpipe -listen at sock, admitting the echo server at
// dev, and logging to logTo.
func relay(t *testing.T) (sock, dev, logTo string) {
	t.Helper()
	dir := t.TempDir()
	dev = filepath.Join(dir, "dev.sock")
	dl, err := net.ListenUnix("unix", &net.UnixAddr{Name: dev, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dl.Close() })
	go func() {
		for {
			c, err := dl.AcceptUnix()
			if err != nil {
				return
			}
			go func() { io.Copy(c, c); c.CloseWrite() }()
		}
	}()
	list, logTo, sock := filepath.Join(dir, "allow"), filepath.Join(dir, "log"), filepath.Join(dir, "relay.sock")
	os.WriteFile(list, []byte(dev+"\n"), 0o600)
	lg, err := newLogger(logTo)
	if err != nil {
		t.Fatal(err)
	}
	go listenOn(sock, &server.Server{Hook: hook(lg, list), Unix: true}, lg)
	for i := 0; i < 100; i++ {
		if _, err := os.Stat(sock); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	return sock, dev, logTo
}

// session passes a session asking for dest to the listener at sock, sends
// "hello" after wait, and returns what came back and -pass's exit status.
func session(sock, dest string, wait time.Duration) (string, int) {
	inR, inW, _ := os.Pipe()
	outR, outW, _ := os.Pipe()
	code := make(chan int)
	go func() { code <- passOn(sock, dest, inR, outW) }()
	time.Sleep(wait)
	inW.Write([]byte("hello\n"))
	inW.Close()
	b, _ := io.ReadAll(outR)
	outR.Close()
	return string(b), <-code
}

func TestPass(t *testing.T) {
	sock, dev, logTo := relay(t)
	if got, code := session(sock, dev, 0); got != "hello\n" || code != 0 {
		t.Errorf("a destination on the list: %q back, exit %d", got, code)
	}
	if got, code := session(sock, "192.0.2.1 22", 0); got != "" || code != 1 {
		t.Errorf("a destination not on the list: %q back, exit %d", got, code)
	}
	b, _ := os.ReadFile(logTo)
	if !strings.Contains(string(b), "session passed in at "+sock+": one stream to") || !strings.Contains(string(b), "not on the list") {
		t.Errorf("the log:\n%s", b)
	}
}

// A connection that passes nothing is hung up on, so idle ones cannot
// pile up and starve the listener of descriptors; a session itself may
// last as long as it likes.
func TestIdleHandoff(t *testing.T) {
	old := handoffTimeout
	handoffTimeout = 100 * time.Millisecond
	t.Cleanup(func() { handoffTimeout = old })
	sock, dev, _ := relay(t)
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	if b, err := io.ReadAll(c); err != nil || !strings.HasPrefix(string(b), "1 ") {
		t.Fatalf("idle connection: %q, %v", b, err)
	}
	if got, code := session(sock, dev, 3*handoffTimeout); got != "hello\n" || code != 0 {
		t.Errorf("a slow session: %q back, exit %d", got, code)
	}
}

func TestCheckFlags(t *testing.T) {
	for _, c := range []struct {
		pass, listen, allow, log string
		nargs                    int
		ok                       bool
	}{
		{"", "", "", "", 0, true},
		{"", "", "a", "l", 2, true},
		{"s", "", "", "", 2, true},
		{"", "s", "a", "l", 0, true},
		{"s", "s", "", "", 0, false},
		{"s", "", "a", "", 0, false},
		{"s", "", "", "l", 0, false},
		{"", "s", "", "", 1, false},
	} {
		if err := checkFlags(c.pass, c.listen, c.allow, c.log, c.nargs); (err == nil) != c.ok {
			t.Errorf("%+v: %v", c, err)
		}
	}
}
