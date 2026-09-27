# funpipe

funpipe carries many streams over one byte stream, usually an ssh
session's stdin and stdout. A client opens streams, each naming a
destination; the server, run as sshd's forced command, dials each one
and splices the two until they close. [mews](https://github.com/ubicloud/mews)
reaches BMCs this way, many HTTPS and WebSocket streams over one
session.

sshd forwards on its own, with `direct-tcpip`. funpipe exists to take
the forwarding out of sshd and put it in an ordinary program on stdin
and stdout, which can then be placed, limited and audited like any
other program:

- **Namespace pivots.** sshd dials from its own network namespace.
  funpipe dials from wherever it runs: under `nsenter -n`, as a systemd
  unit in another namespace, or in another container that is handed the
  session's descriptors.
- **Unix sockets, one by one.** OpenSSH's `permitopen` takes `host:port`
  only. A key with it can reach no Unix socket, and a key without it can
  reach every socket its user can (OpenSSH 9.6). funpipe admits exactly
  the sockets it is told to, and none unless told.
- **Programmable admission and logging.** One hook sees each stream as
  it opens, and can refuse it, and as it ends, with the bytes each way
  and why.
- **systemd's limits.** As a unit (`systemd-run --pipe` keeps the
  session's stdin and stdout), it takes systemd's limits like any
  service: `MemoryMax=`, `TasksMax=`, `CapabilityBoundingSet=`, and for
  where it may connect, `IPAddressAllow=`, `IPAddressDeny=`,
  `RestrictAddressFamilies=` and `InaccessiblePaths=`.

## The pieces

- `go/cmd/funpipe`: the server as a command. `-allow FILE` admits only
  the destinations FILE lists, `NET PORT` or a socket's path a line;
  without it, every TCP destination and no Unix socket is admitted.
  `-log FILE` logs there instead of to syslog. Given a destination, as
  arguments or in `SSH_ORIGINAL_COMMAND`, it serves just that stream, so
  a ProxyCommand can use it as it would `nc -N`.
- `go/server`: the server as a package, for programs of their own: a
  `Server` with the hook and, optionally, its own `Dial`. It serves Unix
  sockets only when its `Unix` field is set.
- `python/server`: the first server, a library as well; `run(rfd, wfd,
  dial)` takes a dial function for its policy.
- `go/client`, `ruby/client`: clients.

```
restrict,command="/usr/local/bin/funpipe -allow /etc/funpipe/allow" sk-ssh-ed25519@openssh.com AAAA...
```

```
ProxyCommand ssh -T bastion %h %p
```

The list names addresses, not host names, so with `-allow` the `%h` a
ProxyCommand passes on must be one: a `HostName 10.0.0.5` in the
destination's `Host` block, say.

To build for another machine, such as an ARMv7 appliance:

```
cd go && CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 go build -trimpath -ldflags '-s -w' ./cmd/funpipe
```

## The protocol

A frame is a kind (u8), flags (u8), a stream (u32) and a length (u16),
big-endian, then the payload. OPEN (0) carries the destination: `host
port`, split at the last space, or, for the Go server, a Unix socket's
absolute path. DATA (1) carries bytes, and its flag FIN (1) closes the
stream. WIN (2) carries a u32 of credit.

Flow control counts bytes: each side may have 256 KiB outstanding on a
stream and returns credit as it consumes. The clients send the same FIN
to half-close and to close, so the servers take it as a close.
