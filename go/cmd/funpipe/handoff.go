package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ubicloud/funpipe/go/server"
)

// Passing a session on. Where sshd runs, the destinations may be out of
// reach: in a container on the far side of a gap, with no route across.
// funpipe -pass, as the forced command, hands the session's stdin and
// stdout, and what the session asks for, over a Unix socket to funpipe
// -listen on the far side (SCM_RIGHTS), and keeps no copy. The listener
// serves the session as it would its own, and answers "0 done", or "1"
// and why, which -pass exits with.

// handoffTimeout is how long the listener waits for a connection to pass
// it a session, so that idle connections cannot pile up. A var for tests.
var handoffTimeout = 5 * time.Second

// passOn passes the session on in and out to the funpipe listening on
// sock, and returns the exit status it answers.
func passOn(sock, dest string, in, out *os.File) int {
	c, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: sock, Net: "unix"})
	if err == nil {
		defer c.Close()
		_, _, err = c.WriteMsgUnix([]byte(dest+"\n"), syscall.UnixRights(int(in.Fd()), int(out.Fd())), nil)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "funpipe:", err)
		return 1
	}
	in.Close() // so the listener's close is the session's end
	out.Close()
	b, _ := io.ReadAll(c)
	code, why, _ := strings.Cut(strings.TrimSpace(string(b)), " ")
	if code == "" {
		why = "the listener hung up"
	}
	if code != "0" {
		fmt.Fprintln(os.Stderr, "funpipe:", why)
	}
	if n, err := strconv.Atoi(code); err == nil {
		return n
	}
	return 1
}

// listenOn serves each session passed to sock on the descriptors it came
// with. The socket is 0666: who may pass a session on is who can reach
// its path.
func listenOn(sock string, s *server.Server, lg *logger) error {
	os.Remove(sock)
	ln, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		return err
	}
	if err := os.Chmod(sock, 0o666); err != nil {
		return err
	}
	lg.printf("listening on %s", sock)
	var delay time.Duration
	for {
		c, err := ln.AcceptUnix()
		if errors.Is(err, net.ErrClosed) {
			return err
		}
		if err != nil {
			// Out of descriptors, say. Ending here would end every
			// session being served, so wait for some to end, and retry.
			delay = min(max(2*delay, 5*time.Millisecond), time.Second)
			lg.printf("accept: %v; retrying in %v", err, delay)
			time.Sleep(delay)
			continue
		}
		delay = 0
		go passedIn(c, s, lg, sock)
	}
}

func passedIn(c *net.UnixConn, s *server.Server, lg *logger, sock string) {
	defer c.Close()
	buf, oob := make([]byte, 4096), make([]byte, syscall.CmsgSpace(2*4))
	c.SetReadDeadline(time.Now().Add(handoffTimeout))
	n, oobn, _, _, err := c.ReadMsgUnix(buf, oob)
	var fds []int
	if err == nil {
		msgs, _ := syscall.ParseSocketControlMessage(oob[:oobn])
		for i := range msgs {
			got, _ := syscall.ParseUnixRights(&msgs[i])
			fds = append(fds, got...)
		}
	}
	word := "0 done"
	if len(fds) != 2 {
		for _, fd := range fds {
			syscall.Close(fd)
		}
		word = "1 pass two descriptors"
	} else {
		in, out := os.NewFile(uintptr(fds[0]), "stdin"), os.NewFile(uintptr(fds[1]), "stdout")
		if err := serve(s, lg, "session passed in at "+sock, in, out, strings.TrimSpace(string(buf[:n]))); err != nil {
			word = "1 " + err.Error()
		}
		in.Close()
		out.Close()
	}
	fmt.Fprintln(c, word)
}
