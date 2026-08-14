// Integration test: the broker behind the unix-domain-socket transport.
// SPDX-License-Identifier: MIT
#include "test.hpp"
#include "wire_util.hpp"

#include <minimosq/broker/broker.hpp>
#include <minimosq/transports/posix/unix_socket.hpp>

#include <csignal>
#include <cstdio>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

using namespace minimosq;

namespace {

struct TinyTraits {
    static constexpr size_t max_connections = 2;
    static constexpr size_t max_sessions = 2;
    static constexpr size_t max_subscriptions_per_session = 2;
    static constexpr size_t max_topic_len = 64;
    static constexpr size_t max_client_id_len = 32;
    static constexpr size_t max_packet_size = 512;
    static constexpr size_t max_payload_len = 256;
    static constexpr size_t max_retained = 2;
    static constexpr size_t max_pending_per_session = 2;
    static constexpr size_t max_inbound_qos2 = 2;
    static constexpr uint32_t connect_timeout_ms = 5000;
};

using Transport = UnixSocketTransport<TinyTraits::max_connections>;

int connect_client(const char* path) {
    const int fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }
    sockaddr_un addr{};
    addr.sun_family = AF_UNIX;
    for (size_t i = 0; path[i] != '\0'; ++i) {
        addr.sun_path[i] = path[i];
    }
    if (::connect(fd, reinterpret_cast<const sockaddr*>(&addr), sizeof addr) != 0) {
        ::close(fd);
        return -1;
    }
    set_nonblocking(fd);
    return fd;
}

void send_all(int fd, ByteSpan b) {
    size_t off = 0;
    while (off < b.len) {
        const ssize_t w = ::send(fd, b.data + off, b.len - off, MSG_NOSIGNAL);
        if (w > 0) {
            off += static_cast<size_t>(w);
        }
    }
}

// Pump the loop until a complete packet arrives on fd.
template <typename B>
bool wait_packet(Transport& t, B& b, int fd, uint8_t* buf, size_t cap, size_t& got) {
    got = 0;
    for (int i = 0; i < 200; ++i) {
        t.poll_once(b, 5);
        const ssize_t r = ::read(fd, buf + got, cap - got);
        if (r > 0) {
            got += static_cast<size_t>(r);
        }
        if (got >= 2) {
            const size_t body_len = buf[1];  // small packets: 1-byte varint
            if (got >= 2 + body_len) {
                return true;
            }
        }
    }
    return false;
}

} // namespace

TEST(uds_end_to_end_pubsub) {
    std::signal(SIGPIPE, SIG_IGN);
    char path[64];
    std::snprintf(path, sizeof path, "/tmp/minimosq-test-%d.sock", static_cast<int>(::getpid()));

    Transport t;
    Broker<TinyTraits, Transport> b{t};
    CHECK(t.open(path));

    const int fd = connect_client(path);
    CHECK(fd >= 0);

    uint8_t buf[512];
    size_t got = 0;

    send_all(fd, wire::make_connect("uds-client").span());
    CHECK(wait_packet(t, b, fd, buf, sizeof buf, got));
    CHECK(packet_type(buf[0]) == PacketType::connack);
    CHECK_EQ(buf[3], 0);  // accepted

    send_all(fd, wire::make_subscribe(1, {{"u/#", 0}}).span());
    CHECK(wait_packet(t, b, fd, buf, sizeof buf, got));
    CHECK(packet_type(buf[0]) == PacketType::suback);

    // Publish to ourselves over the socket.
    send_all(fd, wire::make_publish("u/x", wire::bs("via-uds")).span());
    CHECK(wait_packet(t, b, fd, buf, sizeof buf, got));
    PublishPacket p;
    CHECK(parse_publish(buf[0], ByteSpan{buf + 2, got - 2}, p) == Err::ok);
    CHECK(p.topic == StrView("u/x"));
    CHECK(p.payload == wire::bs("via-uds"));

    ::close(fd);
    for (int i = 0; i < 10; ++i) {
        t.poll_once(b, 5);
    }
}
