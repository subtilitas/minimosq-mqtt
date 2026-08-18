// minimosq — pipe transport (POSIX example).
//
// Serves exactly one client over a pair of file descriptors: one to
// read MQTT bytes from, one to write them to. The descriptors can be
// anything stream-like — pipe(2) ends, FIFOs, a pty, a socketpair
// half, stdin/stdout of a forked child. This is the smallest possible
// demonstration of the transport contract, and the natural fit when
// the "network" is another process on the same box.
//
// The single connection uses index 0; the broker's Traits only needs
// max_connections >= 1.
//
// Usage:
//   minimosq::PipeTransport<> transport;
//   transport.open(read_fd, write_fd);
//   minimosq::Broker<Traits, decltype(transport)> broker{transport};
//   transport.run(broker);   // returns when the connection ends
//
// SPDX-License-Identifier: MIT
#ifndef MINIMOSQ_TRANSPORTS_POSIX_PIPE_HPP
#define MINIMOSQ_TRANSPORTS_POSIX_PIPE_HPP

#include <cerrno>
#include <csignal>
#include <cstddef>
#include <cstdint>

#include <poll.h>
#include <unistd.h>

#include "../../core/error.hpp"
#include "../../core/span.hpp"
#include "common.hpp"

namespace minimosq {

template <size_t OutBufSize = 4096>
class PipeTransport {
public:
    // The pipe transport serves exactly one connection, index 0.
    static constexpr size_t max_connections = 1;

    // See StreamServerTransport: bounded drain so a chatty peer cannot
    // starve broker.tick().
    static constexpr int max_reads_per_pass = 8;

    PipeTransport() = default;
    PipeTransport(const PipeTransport&) = delete;
    PipeTransport& operator=(const PipeTransport&) = delete;

    ~PipeTransport() { close_fds(); }

    // Takes ownership of both descriptors.
    bool open(int read_fd, int write_fd) {
        if (read_fd < 0 || write_fd < 0) {
            return false;
        }
        rfd_ = read_fd;
        wfd_ = write_fd;
        started_ = false;
        ring_.clear();
        return set_nonblocking(rfd_) && set_nonblocking(wfd_);
    }

    bool closed() const noexcept { return rfd_ < 0; }

    // ------------------------------------ transport policy (broker-facing)

    bool send(size_t ci, ByteSpan bytes) {
        (void)ci;  // always connection 0
        if (wfd_ < 0 || !ring_.append(bytes)) {
            return false;
        }
        flush();
        return true;
    }

    void close(size_t ci) {
        (void)ci;
        flush();
        close_fds();
    }

    // ------------------------------------------------- event loop driving

    template <typename B>
    int poll_once(B& broker, int timeout_ms) {
        const uint32_t now_start = posix_now_ms();
        if (!started_ && rfd_ >= 0) {
            started_ = true;
            if (broker.conn_open(0, now_start) != Err::ok) {
                close_fds();
            }
        }
        if (rfd_ < 0) {
            broker.tick(now_start);
            return 0;
        }

        pollfd pfds[2];
        nfds_t n = 0;
        pfds[n].fd = rfd_;
        pfds[n].events = POLLIN;
        pfds[n].revents = 0;
        ++n;
        if (!ring_.empty() && wfd_ >= 0) {
            pfds[n].fd = wfd_;
            pfds[n].events = POLLOUT;
            pfds[n].revents = 0;
            ++n;
        }

        const int rc = ::poll(pfds, n, timeout_ms);
        const uint32_t now = posix_now_ms();
        if (rc < 0) {
            broker.tick(now);
            return 0;
        }

        if (n > 1 && (pfds[1].revents & POLLOUT) != 0) {
            flush();
        }
        if ((pfds[0].revents & (POLLIN | POLLHUP | POLLERR)) != 0) {
            read_into_broker(broker, now);
        }

        broker.tick(now);
        return rc;
    }

    // Run until the connection ends (or stop() is called).
    template <typename B>
    void run(B& broker, int tick_ms = 100) {
        running_ = 1;
        while (running_ != 0 && rfd_ >= 0) {
            poll_once(broker, tick_ms);
        }
    }

    void stop() noexcept { running_ = 0; }

private:
    template <typename B>
    void read_into_broker(B& broker, uint32_t now) {
        uint8_t buf[2048];
        for (int reads = 0; reads < max_reads_per_pass && rfd_ >= 0; ++reads) {
            const ssize_t r = ::read(rfd_, buf, sizeof buf);
            if (r > 0) {
                broker.conn_data(0, ByteSpan{buf, static_cast<size_t>(r)}, now);
                continue;
            }
            if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
                return;
            }
            if (r < 0 && errno == EINTR) {
                continue;
            }
            close_fds();  // EOF or fatal error
            broker.conn_closed(0);
            return;
        }
    }

    void flush() {
        while (wfd_ >= 0 && !ring_.empty()) {
            const ByteSpan chunk = ring_.front_chunk();
            const ssize_t w = ::write(wfd_, chunk.data, chunk.len);
            if (w > 0) {
                ring_.consume(static_cast<size_t>(w));
                continue;
            }
            if (w < 0 && errno == EINTR) {
                continue;
            }
            return;  // EAGAIN: poll for POLLOUT
        }
    }

    void close_fds() noexcept {
        if (rfd_ >= 0) {
            ::close(rfd_);
        }
        if (wfd_ >= 0 && wfd_ != rfd_) {
            ::close(wfd_);
        }
        rfd_ = -1;
        wfd_ = -1;
        ring_.clear();
    }

    OutRing<OutBufSize> ring_;
    int rfd_ = -1;
    int wfd_ = -1;
    bool started_ = false;
    volatile sig_atomic_t running_ = 1;
};

} // namespace minimosq

#endif // MINIMOSQ_TRANSPORTS_POSIX_PIPE_HPP
