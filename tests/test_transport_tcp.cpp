// Integration test: the broker behind the real TCP transport, exercised
// with plain client sockets over loopback.
// SPDX-License-Identifier: MIT
#include "test.hpp"
#include "wire_util.hpp"

#include <minimosq/broker/broker.hpp>
#include <minimosq/transports/posix/tcp.hpp>

#include <arpa/inet.h>
#include <csignal>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

using namespace minimosq;

namespace {

struct TinyTraits {
    static constexpr size_t max_connections = 4;
    static constexpr size_t max_sessions = 4;
    static constexpr size_t max_subscriptions_per_session = 4;
    static constexpr size_t max_topic_len = 64;
    static constexpr size_t max_client_id_len = 32;
    static constexpr size_t max_packet_size = 512;
    static constexpr size_t max_payload_len = 256;
    static constexpr size_t max_retained = 4;
    static constexpr size_t max_pending_per_session = 4;
    static constexpr size_t max_inbound_qos2 = 4;
    static constexpr uint32_t connect_timeout_ms = 5000;
};

using Transport = TcpTransport<TinyTraits::max_connections>;

// A blocking client socket speaking raw MQTT, with a pump() hook that
// keeps the broker's event loop turning while we wait.
struct Client {
    int fd = -1;
    uint8_t rx[4096];
    size_t rx_len = 0;
    size_t rpos = 0;

    bool connect_to(uint16_t port) {
        fd = ::socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0) {
            return false;
        }
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        if (::connect(fd, reinterpret_cast<const sockaddr*>(&addr), sizeof addr) != 0) {
            return false;
        }
        return set_nonblocking(fd);
    }

    void send_pkt(const wire::Pkt& p) {
        size_t off = 0;
        while (off < p.len) {
            const ssize_t w = ::send(fd, p.data + off, p.len - off, MSG_NOSIGNAL);
            if (w > 0) {
                off += static_cast<size_t>(w);
            }
        }
    }

    // Read whatever is available right now.
    void drain() {
        while (true) {
            const ssize_t r = ::read(fd, rx + rx_len, sizeof rx - rx_len);
            if (r <= 0) {
                return;
            }
            rx_len += static_cast<size_t>(r);
        }
    }

    // Next complete packet already received, if any.
    bool next(uint8_t& first_byte, ByteSpan& body) {
        if (rx_len - rpos < 2) {
            return false;
        }
        size_t i = rpos;
        first_byte = rx[i++];
        uint32_t rem = 0;
        uint8_t shift = 0;
        while (i < rx_len) {
            const uint8_t b = rx[i++];
            rem |= static_cast<uint32_t>(b & 0x7F) << shift;
            if ((b & 0x80) == 0) {
                break;
            }
            shift = static_cast<uint8_t>(shift + 7);
        }
        if (i + rem > rx_len) {
            return false;
        }
        body = ByteSpan{rx + i, rem};
        rpos = i + rem;
        return true;
    }

    void close() {
        if (fd >= 0) {
            ::close(fd);
            fd = -1;
        }
    }
};

// Pump the broker loop and the client until the client has a packet.
template <typename B>
bool wait_packet(Transport& t, B& b, Client& c, uint8_t& fb, ByteSpan& body) {
    for (int i = 0; i < 200; ++i) {
        t.poll_once(b, 5);
        c.drain();
        if (c.next(fb, body)) {
            return true;
        }
    }
    return false;
}

}  // namespace

TEST(tcp_end_to_end_pubsub) {
    std::signal(SIGPIPE, SIG_IGN);
    Transport t;
    Broker<TinyTraits, Transport> b{t};
    CHECK(t.open(0));  // OS-assigned port
    const uint16_t port = t.port();
    CHECK(port != 0);

    Client sub;
    Client pub;
    CHECK(sub.connect_to(port));
    CHECK(pub.connect_to(port));

    uint8_t fb = 0;
    ByteSpan body{};

    sub.send_pkt(wire::make_connect("tcp-sub"));
    CHECK(wait_packet(t, b, sub, fb, body));
    CHECK(packet_type(fb) == PacketType::connack);
    CHECK_EQ(body[1], 0);  // accepted

    pub.send_pkt(wire::make_connect("tcp-pub"));
    CHECK(wait_packet(t, b, pub, fb, body));
    CHECK(packet_type(fb) == PacketType::connack);

    sub.send_pkt(wire::make_subscribe(1, {{"demo/#", 1}}));
    CHECK(wait_packet(t, b, sub, fb, body));
    CHECK(packet_type(fb) == PacketType::suback);

    pub.send_pkt(
        wire::make_publish("demo/x", wire::bs("over-tcp"), QoS::at_least_once, false, false, 21));
    CHECK(wait_packet(t, b, pub, fb, body));
    CHECK(packet_type(fb) == PacketType::puback);

    CHECK(wait_packet(t, b, sub, fb, body));
    PublishPacket got;
    CHECK(parse_publish(fb, body, got) == Err::ok);
    CHECK(got.topic == StrView("demo/x"));
    CHECK(got.payload == wire::bs("over-tcp"));
    CHECK(got.qos == QoS::at_least_once);
    sub.send_pkt(wire::make_ack(PacketType::puback, got.packet_id));

    // Abrupt client death is noticed and the slot becomes reusable.
    pub.close();
    for (int i = 0; i < 20; ++i) {
        t.poll_once(b, 5);
    }
    Client again;
    CHECK(again.connect_to(port));
    again.send_pkt(wire::make_connect("tcp-again"));
    CHECK(wait_packet(t, b, again, fb, body));
    CHECK(packet_type(fb) == PacketType::connack);

    sub.close();
    again.close();
}

TEST(tcp_rejects_when_full) {
    std::signal(SIGPIPE, SIG_IGN);
    Transport t;
    Broker<TinyTraits, Transport> b{t};
    CHECK(t.open(0));
    const uint16_t port = t.port();

    Client c[5];
    uint8_t fb = 0;
    ByteSpan body{};
    for (int i = 0; i < 4; ++i) {
        CHECK(c[i].connect_to(port));
        char id[8] = {'c', static_cast<char>('0' + i), 0};
        c[i].send_pkt(wire::make_connect(id));
        CHECK(wait_packet(t, b, c[i], fb, body));
    }
    // A fifth connection finds no slot: accepted by the OS, closed by
    // the transport. The client observes EOF rather than a CONNACK.
    Client extra;
    CHECK(extra.connect_to(port));
    extra.send_pkt(wire::make_connect("extra"));
    CHECK(!wait_packet(t, b, extra, fb, body));
    for (auto& cl : c) {
        cl.close();
    }
    extra.close();
}

// ------------------------------------------- post-review regressions

TEST(transport_publishes_its_capacity) {
    // Broker static_asserts against this, which is what stops a
    // mis-sized transport becoming an out-of-bounds write.
    static_assert(TcpTransport<4>::max_connections == 4, "capacity must be visible");
    static_assert(transport_max_connections<TcpTransport<4>>::value == 4, "the probe must see it");
    struct Unsized {};  // a transport that does not publish a capacity
    static_assert(transport_max_connections<Unsized>::value == 0,
                  "an unsized transport reads as 0 and is left to the author");
}

TEST(out_of_range_connection_index_is_refused_not_written) {
    TcpTransport<2> t;
    CHECK(t.open(0, "127.0.0.1"));

    const uint8_t byte = 0x42;
    CHECK(!t.send(2, ByteSpan{&byte, 1}));   // == MaxConns
    CHECK(!t.send(99, ByteSpan{&byte, 1}));  // far past it
    t.close(2);                              // must not touch slots_
    t.close(99);

    // In-range but unopened slots are refused on their own merits.
    CHECK(!t.send(0, ByteSpan{&byte, 1}));
}

TEST(tcp_bind_address_is_honoured) {
    TcpTransport<2> loopback;
    CHECK(loopback.open(0, "127.0.0.1"));
    CHECK(loopback.port() != 0);

    TcpTransport<2> bad;
    CHECK(!bad.open(0, "not-an-address"));  // never silently falls back to ANY
    CHECK_EQ(bad.port(), 0);
}
