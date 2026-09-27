// Command funpipe serves funpipe on its standard input and output, most
// often as sshd's forced command:
//
//	funpipe [-allow FILE] [-log FILE] [HOST PORT | PATH]
//
// With no destination it serves the stream multiplexer that mews and the
// other clients speak. With one, in its arguments or in
// SSH_ORIGINAL_COMMAND (as "ssh -T bastion HOST PORT" sends it from a
// ProxyCommand), it serves that one stream, each way closing on its own
// as nc -N does. An empty SSH_ORIGINAL_COMMAND, or "funpipe", is the
// multiplexer.
//
// It logs a line as each stream opens and as it ends: to syslog, or to
// FILE with -log. With -allow it admits only the destinations FILE lists,
// read afresh for each stream: a line is "NET PORT", NET an address or a
// prefix, or a Unix socket's absolute path, and # starts a comment. A
// destination named by a host name is on no list, and a list with a line
// it cannot read admits nothing. Without -allow it admits every TCP
// destination and no Unix socket.
package main

import (
	"errors"
	"flag"
	"fmt"
	"log/syslog"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/ubicloud/funpipe/go/server"
)

func main() {
	// When the client goes, sshd closes our stdin and stdout, and the
	// streams still open each send it a last frame. Go's default for a
	// write to a closed stdout is to die of SIGPIPE, before the streams'
	// ends are logged; ignored, the write fails and the streams end.
	signal.Ignore(syscall.SIGPIPE)
	allow := flag.String("allow", "", "admit only the destinations this file lists")
	logTo := flag.String("log", "", "log to this file, not to syslog")
	flag.Parse()
	lg, err := newLogger(*logTo)
	if err != nil {
		fmt.Fprintln(os.Stderr, "funpipe:", err)
		os.Exit(1)
	}
	s := &server.Server{Hook: hook(lg, *allow), Unix: *allow != ""}

	dest := strings.Join(flag.Args(), " ")
	if dest == "" {
		dest = strings.TrimSpace(os.Getenv("SSH_ORIGINAL_COMMAND"))
	}
	who := "a local user"
	if c := strings.Fields(os.Getenv("SSH_CONNECTION")); len(c) >= 2 {
		who = c[0] + " port " + c[1]
	}
	if dest == "" || dest == "funpipe" {
		lg.printf("session from %s, uid %d: the multiplexer", who, os.Getuid())
		err = s.Serve(os.Stdin, os.Stdout)
	} else {
		lg.printf("session from %s, uid %d: one stream to %q", who, os.Getuid(), dest)
		err = s.Splice(os.Stdin, stdout{os.Stdout}, dest)
	}
	if err != nil {
		lg.printf("session from %s ended: %v", who, err)
		fmt.Fprintln(os.Stderr, "funpipe:", err)
		os.Exit(1)
	}
}

// hook admits a stream by the list, if there is one, and logs it.
func hook(lg *logger, list string) server.Hook {
	return func(e server.Event) error {
		where := e.Network + " " + e.Address
		if e.Network == "" {
			where = strconv.Quote(e.Address)
		}
		if e.End {
			if e.Err != nil {
				lg.printf("stream %d %s ended: %v", e.Stream, where, e.Err)
			} else {
				lg.printf("stream %d %s ended, up %d down %d in %s", e.Stream, where, e.Up, e.Down,
					time.Since(e.Opened).Round(time.Millisecond))
			}
			return nil
		}
		if list != "" {
			if err := allowed(list, e.Network, e.Address); err != nil {
				return err
			}
		}
		lg.printf("stream %d %s open", e.Stream, where)
		return nil
	}
}

type entry struct {
	net  netip.Prefix
	port uint64
	path string
}

// allowed reads the list afresh, so an edit applies to the next stream.
func allowed(list, network, address string) error {
	b, err := os.ReadFile(list)
	if err != nil {
		return err
	}
	var entries []entry
	for i, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(strings.SplitN(line, "#", 2)[0])
		switch {
		case len(f) == 0:
			continue
		case len(f) == 1 && strings.HasPrefix(f[0], "/"):
			entries = append(entries, entry{path: filepath.Clean(f[0])})
			continue
		case len(f) == 2:
			n, err := prefix(f[0])
			p, perr := strconv.ParseUint(f[1], 10, 16)
			if err == nil && perr == nil {
				entries = append(entries, entry{net: n, port: p})
				continue
			}
		}
		return fmt.Errorf(`%s:%d: not "NET PORT" or a socket's path`, list, i+1)
	}
	switch network {
	case "unix":
		for _, e := range entries {
			if e.path != "" && e.path == address {
				return nil
			}
		}
	case "tcp":
		host, p, _ := net.SplitHostPort(address)
		ip, err := netip.ParseAddr(host)
		if err != nil {
			return fmt.Errorf("%s: not an address", host)
		}
		ip = ip.Unmap()
		port, _ := strconv.ParseUint(p, 10, 16)
		for _, e := range entries {
			if e.path == "" && e.net.Contains(ip) && e.port == port {
				return nil
			}
		}
	}
	return errors.New("not on the list")
}

func prefix(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		return p.Masked(), err
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}

type logger struct {
	mu   sync.Mutex
	file *os.File
	sys  *syslog.Writer
}

// newLogger logs to the file, else to syslog, else to stderr.
func newLogger(path string) (*logger, error) {
	if path != "" {
		f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
		return &logger{file: f}, err
	}
	sys, _ := syslog.New(syslog.LOG_AUTH|syslog.LOG_INFO, "funpipe")
	return &logger{sys: sys}, nil
}

func (l *logger) printf(format string, a ...any) {
	line := fmt.Sprintf(format, a...)
	l.mu.Lock()
	defer l.mu.Unlock()
	switch {
	case l.file != nil:
		fmt.Fprintf(l.file, "%s %d %s\n", time.Now().UTC().Format(time.RFC3339), os.Getpid(), line)
	case l.sys != nil:
		l.sys.Info(line)
	default:
		fmt.Fprintln(os.Stderr, "funpipe:", line)
	}
}

// stdout closes the session's writing side. sshd may give a command one
// socket for stdin and stdout; closing stdout alone does not end that.
type stdout struct{ *os.File }

func (o stdout) CloseWrite() error {
	if c, err := net.FileConn(o.File); err == nil {
		if cw, ok := c.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}
		c.Close()
	}
	return o.File.Close()
}
