// minimosq — poll()-based stream-socket server transport.
//
// The listening-socket setup is the only difference between a TCP and
// a unix-domain-socket MQTT server, so both (tcp.hpp, unix_socket.hpp)
// derive from this class and just provide open(). Everything here is
// nonblocking; each connection owns a fixed output ring for bytes the
// peer has not accepted yet. A connection that overflows its ring is a
// slow consumer and gets dropped by the broker (send() returns false).
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

template <size_t MaxConns, size_t OutBufSize = 4096>
class StreamServerTransport {
public:
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

    bool send(size_t ci, ByteSpan bytes) {
        Slot& s = slots_[ci];
        if (s.fd < 0) {
            return false;
        }
        if (!s.ring.append(bytes)) {
            return false;  // slow consumer: broker will drop this connection
        }
        flush(ci);  // opportunistic immediate write
        return true;
    }

    void close(size_t ci) {
        Slot& s = slots_[ci];
        if (s.fd < 0) {
            return;
        }
        flush(ci);  // best effort so refusal packets reach the peer
        ::close(s.fd);
        s.fd = -1;
        s.ring.clear();
    }

    // ------------------------------------------------- event loop driving

    // One poll iteration. Returns the number of fds with events, 0 on
    // timeout/EINTR. Always calls broker.tick() once.
    template <typename B>
    int poll_once(B& broker, int timeout_ms) {
        pollfd pfds[MaxConns + 1];
        size_t slot_of[MaxConns + 1];
        nfds_t n = 0;

        // After a hard accept() failure (e.g. fd exhaustion) the
        // listener stays readable forever; pause it briefly instead of
        // busy-spinning the loop.
        const bool listener_paused =
            accept_backoff_armed_ &&
            static_cast<int32_t>(posix_now_ms() - accept_retry_at_ms_) < 0;
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

        int rc = ::poll(pfds, n, timeout_ms);
        const uint32_t now = posix_now_ms();
        if (rc < 0) {
            broker.tick(now);
            return 0;  // EINTR and friends: just run the tick
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
            Slot& s = slots_[ci];
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

private:
    struct Slot {
        int fd = -1;
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
            slots_[ci].fd = fd;
            slots_[ci].ring.clear();
            if (broker.conn_open(ci, now) != Err::ok) {
                ::close(fd);
                slots_[ci].fd = -1;
            }
        }
    }

    template <typename B>
    void read_into_broker(B& broker, size_t ci, uint32_t now) {
        uint8_t buf[2048];
        while (slots_[ci].fd >= 0) {
            const ssize_t r = ::read(slots_[ci].fd, buf, sizeof buf);
            if (r > 0) {
                broker.conn_data(ci, ByteSpan{buf, static_cast<size_t>(r)}, now);
                continue;  // drain until EAGAIN (edge cases: broker may close mid-loop)
            }
            if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                return;
            }
            if (r < 0 && errno == EINTR) {
                continue;
            }
            // EOF or fatal error: the peer is gone.
            ::close(slots_[ci].fd);
            slots_[ci].fd = -1;
            slots_[ci].ring.clear();
            broker.conn_closed(ci);
            return;
        }
    }

    void flush(size_t ci) {
        Slot& s = slots_[ci];
        while (s.fd >= 0 && !s.ring.empty()) {
            const ByteSpan chunk = s.ring.front_chunk();
            const ssize_t w = ::send(s.fd, chunk.data, chunk.len, MSG_NOSIGNAL);
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

} // namespace minimosq

#endif // MINIMOSQ_TRANSPORTS_POSIX_STREAM_SERVER_HPP
