#
# Ruby client for the mews mux protocol (see muxer.py).
#
# frozen_string_literal: true
# Wire: type:u8 flags:u8 stream:u32-BE length:u16-BE  payload
# Types: 0=SYN(payload=destination "host port") 1=DATA 2=WIN(u32 credit)
#   (destination is space-separated, matching mews/muxer.py; bare IPv6
#   literals need no bracket disambiguation)
# Flags: 1=FIN (DATA only)
#
# Mux::Session multiplexes many logical streams over a single byte transport
# (e.g. one Net::SSH channel). Each Mux::Stream exposes a real Unix-socket
# fd (Stream#fd); the framing happens in two threads behind it. Read/write
# the fd like any IO; wrap it with OpenSSL::SSL::SSLSocket if you want TLS.
#
# Threading contract: Mux#feed is called from one thread (the SSH worker).
# The transport's write may be called from that thread AND from each stream's
# outbound thread; Session serializes those calls under its own write mutex.

require 'socket'




module Mux
  HDR_FMT  = 'CCNn'
  HDR_LEN  = 8
  TYPE_SYN, TYPE_DATA, TYPE_WIN = 0, 1, 2
  FLAG_FIN = 1
  # Protocol constants shared with muxer.py (MAX, INITIAL) and Go's
  # internal/mux (maxFrame, initialWindow). Not negotiated on the wire, so
  # they only change in lockstep with the relay:
  #  - MAX_PAYLOAD must stay <= 0xFFFF (the length field is u16; 65536
  #    truncates to 0 and permanently desyncs the session).
  #  - The relay bounds each stream's backlog at INITIAL_WINDOW bytes, as
  #    a compliant client has no more in flight; a larger window here is a
  #    protocol violation the relay kills the tunnel over.
  MAX_PAYLOAD    = 32_768
  INITIAL_WINDOW = 256 * 1024
  BINARY         = Encoding::BINARY

  class Stream
    attr_reader :id, :fd

    # Raised inside send_data when the session is torn down (transport gone)
    # while the outbound thread is parked on the send window. Subclasses
    # IOError so the outbound thread's existing rescue runs the FIN+retire
    # teardown in ensure.
    Closed = Class.new(IOError)

    def initialize(mux, id)
      @mux, @id = mux, id
      @swin = INITIAL_WINDOW
      @closed = false
      @smu, @scv = Mutex.new, ConditionVariable.new
      @fd, @inner = UNIXSocket.pair

      # Size the socket-pair kernel buffer so @inner.write (called from
      # the SSH worker thread in push_data) never blocks under normal
      # peer-side flow control. Peer has at most INITIAL_WINDOW bytes in
      # flight; 2× gives margin for a user-side reader that's draining
      # @fd slightly behind real time. If a peer ignores flow control and
      # the buffer ever fills, the SSH worker WILL block here — that's
      # the new backpressure mechanism, replacing the old MAX_BACKLOG
      # check.
      [@fd, @inner].each do |s|
        s.setsockopt(:SOCKET, :SNDBUF, 2 * INITIAL_WINDOW) rescue nil
        s.setsockopt(:SOCKET, :RCVBUF, 2 * INITIAL_WINDOW) rescue nil
      end

      # Outbound only. User writes to @fd, we read from @inner and send
      # DATA frames respecting the send window. On EOF (user closed @fd
      # or did close_write) send FIN, signal user-side EOF if they
      # haven't already, and retire the stream.
      #
      # Inbound no longer has a thread: push_data writes to @inner and
      # sends the WIN credit synchronously in the SSH worker thread. One
      # fewer thread per stream; WIN goes out in the same ssh.process
      # iteration that received the DATA, rather than after a Queue#pop
      # and GVL handoff.
      Thread.new do
        loop { send_data(@inner.readpartial(MAX_PAYLOAD)) }
      rescue EOFError, IOError, SystemCallError
      ensure
        @mux.send_frame(TYPE_DATA, FLAG_FIN, @id, '')
        @inner.close_write rescue nil
        @mux.retire(self)
      end
    end

    # --- called by Mux::Session#dispatch in the SSH worker thread ---

    # Coalesce inbound credit: defer the WIN frame until accumulated
    # credit reaches a quarter-window. For Redfish-shaped traffic (small
    # responses, few frames each) this collapses near-1:1 DATA→WIN into
    # ~one WIN per response. Empirically worth 11–47% inbound throughput
    # depending on frame count; see bench_mux.rb.

    CREDIT_FLUSH = INITIAL_WINDOW / 4   # 64 KiB consumed; the empirically validated flush point

    def push_data(bytes)
      return if bytes.empty?
      @pending_credit ||= 0
      @pending_credit += bytes.bytesize
      if @pending_credit >= CREDIT_FLUSH
        @mux.send_frame(TYPE_WIN, 0, @id, [@pending_credit].pack('N'))
        @pending_credit = 0
      end
      
      @inner.write(bytes) 

    rescue Errno::EPIPE, IOError
      # User closed @fd; outbound thread will retire the stream. Drop the
      # bytes (credit for them may already have flushed above; harmless —
      # the peer stalls on its own send window once we stop crediting,
      # which is correct since this stream is dead).
    end

    def push_eof
      # Peer is done sending. Flush any held credit so a small response
      # that never reached CREDIT_FLUSH still credits the peer, then
      # signal EOF to the user side. Outbound thread (and therefore
      # retire) only runs after user closes @fd.
      if @pending_credit && @pending_credit > 0
        @mux.send_frame(TYPE_WIN, 0, @id, [@pending_credit].pack('N')) rescue nil
        @pending_credit = 0
      end
      @inner.close_write rescue nil
    end

    def grant(credit)
      @smu.synchronize { @swin += credit; @scv.broadcast }
    end

    # Session teardown (transport gone). Deliver read-side EOF as push_eof
    # does, then wake any sender parked on the send window so its outbound
    # thread unwinds through ensure (FIN + retire) instead of leaking.
    # Distinct from push_eof, which is a per-stream peer FIN and must leave
    # the send side alive.
    def shutdown
      push_eof
      @smu.synchronize { @closed = true; @scv.broadcast }
    end

    private

    def send_data(data)
      offset = 0
      while offset < data.bytesize
        take = @smu.synchronize do
          @scv.wait(@smu) while @swin <= 0 && !@closed
          raise Closed if @closed
          t = [data.bytesize - offset, @swin, MAX_PAYLOAD].min
          @swin -= t
          t
        end
        chunk = data.byteslice(offset, take)
        @mux.send_frame(TYPE_DATA, 0, @id, chunk)
        offset += chunk.bytesize
      end
    end
  end

  class Session
    # `transport` is any object that responds to `write(*bufs)` writing the
    # given byte strings atomically (as one writev when on Linux). A
    # UNIXSocket end satisfies this without adaptation; tests can pass an
    # Array-collecting double. The Session owns serialization of writes
    # across all stream threads and the dispatch path — callers don't
    # provide a mutex.
    def initialize(transport:)
      @transport  = transport
      @write_mu   = Mutex.new
      @streams    = {}
      @streams_mu = Mutex.new
      @next_id    = 1
      @inbound    = String.new(encoding: BINARY)
    end

    def open(dest)
      stream = @streams_mu.synchronize do
        id = @next_id; @next_id += 1
        @streams[id] = Stream.new(self, id)
      end
      send_frame(TYPE_SYN, 0, stream.id, dest.b)
      stream
    end

    # Called by Stream when its outbound thread exits (user closed @fd).
    def retire(stream)
      @streams_mu.synchronize { @streams.delete(stream.id) }
    end

    # Feed inbound bytes from the transport. Single-caller (SSH worker).
    def feed(bytes)
      @inbound << bytes.b
      loop do
        break if @inbound.bytesize < HDR_LEN
        type, flags, sid, ln = @inbound.byteslice(0, HDR_LEN).unpack(HDR_FMT)
        break if @inbound.bytesize < HDR_LEN + ln
        payload  = @inbound.byteslice(HDR_LEN, ln)
        @inbound = @inbound.byteslice(HDR_LEN + ln, @inbound.bytesize)
        dispatch(type, flags, sid, payload)
      end
    end

    def feed_eof
      @streams_mu.synchronize { @streams.each_value(&:shutdown) }
    end

    # Single writev call on Linux because UNIXSocket#write(*args) packs into
    # iovec when given multiple binary strings. EPIPE/IOError is silent —
    # transport closure is a normal shutdown signal; callers that care
    # (Stream#push_data, Stream#send_data) catch their own EPIPE via @inner.
    def send_frame(type, flags, sid, payload)
      # The length field is u16; pack('n') silently truncates anything
      # larger (65536 -> 0), which desyncs the peer's parser forever.
      # Make that bug class a crash, not wire corruption.
      raise ArgumentError, "mux frame payload #{payload.bytesize} > 0xFFFF" if payload.bytesize > 0xFFFF
      hdr = [type, flags, sid, payload.bytesize].pack(HDR_FMT)
      @write_mu.synchronize { @transport.write(hdr, payload) }
    rescue Errno::EPIPE, IOError
    end

    private

    def dispatch(type, flags, sid, payload)
        #warn "[mux ←] type=#{type} flags=#{flags} sid=#{sid} len=#{payload.bytesize}"

      stream = @streams_mu.synchronize { @streams[sid] }
      # Late frame after the stream was retired (user closed @fd, peer's
      # ack-FIN arrives just after our retire). Expected race; drop silently.
      return unless stream
      case type
      when TYPE_DATA
        stream.push_data(payload)
        stream.push_eof if (flags & FLAG_FIN) != 0
      when TYPE_WIN
        stream.grant(payload.unpack1('N'))
        # Unknown / unsupported types (e.g. inbound SYN, future extensions):
        # silent-drop rather than crash the SSH worker. A hostile or buggy
        # peer shouldn't be able to take down the whole session.
      end
    end
  end
end