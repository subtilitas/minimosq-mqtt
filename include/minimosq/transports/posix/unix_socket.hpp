// minimosq — unix domain socket server transport (POSIX example).
//
// Identical to the TCP transport except for the listening socket:
// everything else lives in StreamServerTransport. Handy for brokers
// that only serve local processes (no network exposure, no ports).
//
// Usage:
//   minimosq::UnixSocketTransport<Traits::max_connections> transport;
//   if (!transport.open("/tmp/minimosq.sock")) { ...error... }
//   minimosq::Broker<Traits, decltype(transport)> broker{transport};
//   transport.run(broker);
//
// SPDX-License-Identifier: MIT
#ifndef MINIMOSQ_TRANSPORTS_POSIX_UNIX_SOCKET_HPP
#define MINIMOSQ_TRANSPORTS_POSIX_UNIX_SOCKET_HPP

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "stream_server.hpp"

namespace minimosq {

template <size_t MaxConns, size_t OutBufSize = 4096>
class UnixSocketTransport : public StreamServerTransport<MaxConns, OutBufSize> {
public:
    ~UnixSocketTransport() {
        if (path_[0] != '\0') {
            ::unlink(path_);
        }
    }

    bool open(const char* path) {
        const size_t len = cstr_len(path);
        if (len == 0 || len >= sizeof path_) {
            return false;
        }
        const int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd < 0) {
            return false;
        }
        ::unlink(path);  // remove a stale socket from a previous run

        sockaddr_un addr{};
        addr.sun_family = AF_UNIX;
        for (size_t i = 0; i <= len; ++i) {
            addr.sun_path[i] = path[i];
        }
        if (::bind(fd, reinterpret_cast<const sockaddr*>(&addr), sizeof addr) != 0 ||
            ::listen(fd, 8) != 0 || !set_nonblocking(fd)) {
            ::close(fd);
            return false;
        }
        for (size_t i = 0; i <= len; ++i) {
            path_[i] = path[i];
        }
        this->listen_fd_ = fd;
        return true;
    }

private:
    char path_[sizeof(sockaddr_un{}.sun_path)] = {};
};

} // namespace minimosq

#endif // MINIMOSQ_TRANSPORTS_POSIX_UNIX_SOCKET_HPP
