// minimosq — TCP server transport (POSIX example).
//
// Usage:
//   minimosq::TcpTransport<Traits::max_connections> transport;
//   if (!transport.open(1883)) { ...error... }
//   minimosq::Broker<Traits, decltype(transport)> broker{transport};
//   transport.run(broker);
//
// SPDX-License-Identifier: MIT
#ifndef MINIMOSQ_TRANSPORTS_POSIX_TCP_HPP
#define MINIMOSQ_TRANSPORTS_POSIX_TCP_HPP

#include <cstring>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include "stream_server.hpp"

namespace minimosq {

template <size_t MaxConns, size_t OutBufSize = 4096>
class TcpTransport : public StreamServerTransport<MaxConns, OutBufSize> {
public:
    // Listen on all interfaces. Pass port 0 to let the OS pick one
    // (see port() afterwards — handy for tests).
    //
    // bind_addr restricts the listening interface: "127.0.0.1" keeps a
    // plaintext broker off the network entirely, which is the right
    // default for anything not fronted by TLS. nullptr means all
    // interfaces.
    bool open(uint16_t port, const char* bind_addr = nullptr) {
        const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) {
            return false;
        }
        int yes = 1;
        ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);

        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        if (bind_addr != nullptr && ::inet_pton(AF_INET, bind_addr, &addr.sin_addr) != 1) {
            ::close(fd);
            return false;  // unparseable address: fail loudly, never fall back to ANY
        }
        addr.sin_port = htons(port);
        if (::bind(fd, reinterpret_cast<const sockaddr*>(&addr), sizeof addr) != 0 ||
            ::listen(fd, 8) != 0 || !set_nonblocking(fd)) {
            ::close(fd);
            return false;
        }
        this->listen_fd_ = fd;
        return true;
    }

    // The actually bound port (differs from open()'s argument for port 0).
    uint16_t port() const {
        sockaddr_in addr{};
        socklen_t len = sizeof addr;
        if (this->listen_fd_ < 0 ||
            ::getsockname(this->listen_fd_, reinterpret_cast<sockaddr*>(&addr), &len) != 0) {
            return 0;
        }
        return ntohs(addr.sin_port);
    }
};

} // namespace minimosq

#endif // MINIMOSQ_TRANSPORTS_POSIX_TCP_HPP
