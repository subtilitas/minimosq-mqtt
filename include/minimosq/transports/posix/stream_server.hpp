// minimosq — poll()-based stream-socket server transport.
//
// The listening-socket setup is the only difference between a TCP and
// a unix-domain-socket MQTT server, so both (tcp.hpp, unix_socket.hpp)
// derive from this class and just provide open(). Everything here is
// nonblocking; each connection owns a fixed output ring for bytes the
// peer has not accepted yet.
//
// Write policy: send() only appends. Every ring that gained bytes during
// a poll pass is written once at the end of that pass, after
// broker.tick(), so a pass costs one send() per connection rather than
// one per packet. A ring that fills mid-pass is written and the append
// retried once; a span that still does not fit is refused (send()
// returns false) and the broker drops the connection as a slow consumer.
//
// SPDX-License-Identifier: MIT
#ifndef MINIMOSQ_TRANSPORTS_POSIX_STREAM_SERVER_HPP
#define MINIMOSQ_TRANSPORTS_POSIX_STREAM_SERVER_HPP

#include <cerrno>
#include <csignal>
#include <cstddef>
#include <cstdint>

#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../../core/error.hpp"
#include "../../core/span.hpp"
#include "common.hpp"

namespace minimosq {

// Not every stack defines MSG_NOSIGNAL — lwIP (ESP-IDF, Zephyr) has no
// SIGPIPE to suppress in the first place.
#ifdef MSG_NOSIGNAL
constexpr int stream_send_flags = MSG_NOSIGNAL;
#else
constexpr int stream_send_flags = 0;
#endif

template <size_t MaxConns, size_t OutBufSize = 4096>
class StreamServerTransport {
public:
    // Published so Broker can static_assert that the transport has at
    // least Traits::max_connections slots.
    static constexpr size_t max_connections = MaxConns;

    // Published so Broker can static_assert that one whole packet fits.
    // OutBufSize is declared here and max_packet_size in Traits, with
    // nothing forcing them to agree.
    static constexpr size_t out_buf_size = OutBufSize;

    // Reads taken from one connection per poll pass. Without a cap, a
    // peer that keeps its socket full is drained until EAGAIN, which
    // starves every other connection and stops broker.tick() — and with
    // it the keep-alive and handshake timeouts — from running at all.
    static constexpr int max_reads_per_pass = 8;

    StreamServerTransport() = default;
    StreamServerTransport(const StreamServerTransport&) = delete;
    StreamServerTransport& operator=(const StreamServerTransport&) = delete;

    ~StreamServerTransport() {
        for (size_t i = 0; i < MaxConns; ++i) {
            if (slots_[i].fd >= 0) {
                ::close(slots_[i].fd);
            }
        }
        if (listen_fd_ >= 0) {
            ::close(listen_fd_);
        }
    }

    // ------------------------------------ transport policy (broker-facing)

    // Queue bytes; they leave at the end of the current poll pass, or at
    // the end of the next one when called from outside poll_once().
    bool send(size_t ci, ByteSpan bytes) {
        if (ci >= MaxConns) {
            return false;  // mis-sized transport; see the static_assert in Broker
        }
        Slot& s = slots_[ci];
        if (s.fd < 0) {
            return false;
        }
        if (!s.ring.append(bytes)) {
            // The ring is full mid-pass. Write what is already in it and try
            // once more, so that deferring the write does not turn a merely
            // busy connection into a slow consumer. A span that still does
            // not fit -- the kernel took too little -- is refused.
            flush(ci);
            if (!s.ring.append(bytes)) {
                return false;  // slow consumer: broker will drop this connection
            }
        }
        s.dirty = true;
        return true;
    }

    void close(size_t ci) {
        if (ci >= MaxConns) {
            return;
        }
        Slot& s = slots_[ci];
        if (s.fd < 0) {
            return;
        }
        flush(ci);  // best effort so refusal packets reach the peer
        ::close(s.fd);
        s.fd = -1;
        s.ring.clear();
        s.dirty = false;
    }

    // The descriptor behind a connection index, or -1 when the slot is
    // free. For peer-address lookups and socket options; the transport
    // keeps ownership.
    int native_handle(size_t ci) const noexcept { return ci < MaxConns ? slots_[ci].fd : -1; }

    // ------------------------------------------------- event loop driving

    // One poll iteration. Returns the number of fds with events, 0 on
    // timeout/EINTR. Always calls broker.tick() once, then writes every
    // ring that gained bytes during the pass.
    template <typename B>
    int poll_once(B& broker, int timeout_ms) {
        pollfd pfds[MaxConns + 1];
        size_t slot_of[MaxConns + 1];
        nfds_t n = 0;

        // After a hard accept() failure (e.g. fd exhaustion) the
        // listener stays readable forever; pause it briefly instead of
        // busy-spinning the loop.
        const bool listener_paused =
            accept_backoff_armed_ && static_cast<int32_t>(posix_now_ms() - accept_retry_at_ms_) < 0;
        if (listen_fd_ >= 0 && !listener_paused) {
            pfds[n].fd = listen_fd_;
            pfds[n].events = POLLIN;
            pfds[n].revents = 0;
            slot_of[n] = MaxConns;  // marker: the listener
            ++n;
        }
        for (size_t ci = 0; ci < MaxConns; ++ci) {
            if (slots_[ci].fd < 0) {
                continue;
            }
            pfds[n].fd = slots_[ci].fd;
            pfds[n].events = static_cast<short>(POLLIN | (slots_[ci].ring.empty() ? 0 : POLLOUT));
            pfds[n].revents = 0;
            slot_of[n] = ci;
            ++n;
        }

        const int rc = ::poll(pfds, n, timeout_ms);
        const uint32_t now = posix_now_ms();
        if (rc < 0) {
            // EINTR and friends: still run the tick, and still write what
            // it produced — a stop() from a signal handler lands here.
            broker.tick(now);
            flush_all();
            return 0;
        }

        for (nfds_t i = 0; i < n; ++i) {
            if (pfds[i].revents == 0) {
                continue;
            }
            if (slot_of[i] == MaxConns) {
                accept_new(broker, now);
                continue;
            }
            const size_t ci = slot_of[i];
            const Slot& s = slots_[ci];
            if (s.fd != pfds[i].fd) {
                continue;  // slot was closed/reused earlier in this loop
            }
            if ((pfds[i].revents & POLLOUT) != 0) {
                flush(ci);
            }
            if ((pfds[i].revents & (POLLIN | POLLHUP | POLLERR)) != 0) {
                read_into_broker(broker, ci, now);
            }
        }

        broker.tick(now);
        flush_all();
        return rc;
    }

    // Run until stop(). tick_ms bounds the poll timeout so timeouts and
    // keep-alives are checked regularly.
    template <typename B>
    void run(B& broker, int tick_ms = 100) {
        running_ = 1;
        while (running_ != 0) {
            poll_once(broker, tick_ms);
        }
    }

    // Callable from a signal handler.
    void stop() noexcept { running_ = 0; }

protected:
    int listen_fd_ = -1;

    // Set by a derived class whose accepted sockets are TCP; the option
    // does not exist on other socket families.
    bool tcp_nodelay_ = false;

private:
    struct Slot {
        int fd = -1;
        bool dirty = false;  // gained bytes since the last flush_all()
        OutRing<OutBufSize> ring;
    };

    template <typename B>
    void accept_new(B& broker, uint32_t now) {
        accept_backoff_armed_ = false;
        while (true) {
            const int fd = ::accept(listen_fd_, nullptr, nullptr);
            if (fd < 0) {
                if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR &&
                    errno != ECONNABORTED) {
                    // Hard failure (EMFILE/ENFILE/...): the pending
                    // connection stays in the backlog, so back off.
                    accept_backoff_armed_ = true;
                    accept_retry_at_ms_ = now + 1000;
                }
                return;
            }
            size_t ci = MaxConns;
            for (size_t i = 0; i < MaxConns; ++i) {
                if (slots_[i].fd < 0) {
                    ci = i;
                    break;
                }
            }
            if (ci == MaxConns || !set_nonblocking(fd)) {
                ::close(fd);  // no free slot: refuse at the socket level
                continue;
            }
            if (tcp_nodelay_) {
                set_nodelay(fd);
            }
            slots_[ci].fd = fd;
            slots_[ci].ring.clear();
            slots_[ci].dirty = false;
            if (broker.conn_open(ci, now) != Err::ok) {
                ::close(fd);
                slots_[ci].fd = -1;
            }
        }
    }

    template <typename B>
    void read_into_broker(B& broker, size_t ci, uint32_t now) {
        uint8_t buf[2048];
        // Bounded drain: whatever is left stays readable and the next
        // poll() picks it up, so one busy peer cannot monopolise the loop.
        for (int reads = 0; reads < max_reads_per_pass && slots_[ci].fd >= 0; ++reads) {
            const ssize_t r = ::read(slots_[ci].fd, buf, sizeof buf);
            if (r > 0) {
                broker.conn_data(ci, ByteSpan{buf, static_cast<size_t>(r)}, now);
                continue;  // broker may close the slot mid-loop; the guard catches it
            }
            if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                return;
            }
            if (r < 0 && errno == EINTR) {
                continue;
            }
            // EOF or fatal error: the peer is gone. A peer that only shut
            // its write side may still read, so replies queued earlier in
            // this pass are written first, best effort.
            flush(ci);
            ::close(slots_[ci].fd);
            slots_[ci].fd = -1;
            slots_[ci].ring.clear();
            slots_[ci].dirty = false;
            broker.conn_closed(ci);
            return;
        }
    }

    // One write per connection that gained bytes this pass. A ring left
    // non-empty by EAGAIN is not retried here: poll() reports POLLOUT for
    // it, and the next pass writes it then.
    void flush_all() {
        for (size_t ci = 0; ci < MaxConns; ++ci) {
            Slot& s = slots_[ci];
            if (s.fd >= 0 && s.dirty) {
                s.dirty = false;
                flush(ci);
            }
        }
    }

    void flush(size_t ci) {
        Slot& s = slots_[ci];
        while (s.fd >= 0 && !s.ring.empty()) {
            const ByteSpan chunk = s.ring.front_chunk();
            const ssize_t w = ::send(s.fd, chunk.data, chunk.len, stream_send_flags);
            if (w > 0) {
                s.ring.consume(static_cast<size_t>(w));
                continue;
            }
            if (w < 0 && errno == EINTR) {
                continue;
            }
            return;  // EAGAIN: poll for POLLOUT; hard errors surface via poll
        }
    }

    Slot slots_[MaxConns];
    uint32_t accept_retry_at_ms_ = 0;
    bool accept_backoff_armed_ = false;
    volatile sig_atomic_t running_ = 1;
};

}  // namespace minimosq

#endif  // MINIMOSQ_TRANSPORTS_POSIX_STREAM_SERVER_HPP
