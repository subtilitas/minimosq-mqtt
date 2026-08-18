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
#include <sys/stat.h>
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

    // The socket file is created with mode 0600 by default: this
    // transport's entire security story is filesystem permissions, and
    // inheriting the process umask usually means 0755 — connectable by
    // every local user. Pass a wider mode (e.g. 0660 with a shared
    // group) deliberately if clients run as other users.
    bool open(const char* path, mode_t mode = 0600) {
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
        // umask around bind() closes the window in which the socket
        // exists with permissions wider than requested; chmod afterwards
        // pins the exact mode regardless of what the umask allowed.
        const mode_t old_umask = ::umask(static_cast<mode_t>(0777) & ~mode);
        const int bind_rc = ::bind(fd, reinterpret_cast<const sockaddr*>(&addr), sizeof addr);
        ::umask(old_umask);
        if (bind_rc != 0 || ::chmod(path, mode) != 0 || ::listen(fd, 8) != 0 ||
            !set_nonblocking(fd)) {
            ::close(fd);
            ::unlink(path);
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
