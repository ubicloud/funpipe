package main

import (
	"encoding/binary"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
