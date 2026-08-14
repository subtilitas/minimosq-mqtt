// Integration test: the broker behind the pipe transport, over
// anonymous pipe(2) descriptors.
// SPDX-License-Identifier: MIT
#include "test.hpp"
#include "wire_util.hpp"

#include <minimosq/broker/broker.hpp>
#include <minimosq/transports/posix/pipe.hpp>

#include <csignal>
#include <unistd.h>

using namespace minimosq;

namespace {

struct PipeTraits {
    static constexpr size_t max_connections = 1;
    static constexpr size_t max_sessions = 1;
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

using Transport = PipeTransport<>;

struct PipePair {
    int c2b[2];  // client writes -> broker reads
    int b2c[2];  // broker writes -> client reads
    bool make() { return ::pipe(c2b) == 0 && ::pipe(b2c) == 0; }
};

void send_all(int fd, ByteSpan b) {
    size_t off = 0;
    while (off < b.len) {
        const ssize_t w = ::write(fd, b.data + off, b.len - off);
        if (w > 0) {
            off += static_cast<size_t>(w);
        }
    }
}

// Parse the packet starting at pos (assumes 1-byte varints: small packets).
bool packet_at(const uint8_t* buf, size_t got, size_t& pos, uint8_t& fb, ByteSpan& body) {
    if (got - pos < 2) {
        return false;
    }
    const size_t body_len = buf[pos + 1];
    if (got - pos < 2 + body_len) {
        return false;
    }
    fb = buf[pos];
    body = ByteSpan{buf + pos + 2, body_len};
    pos += 2 + body_len;
    return true;
}

// Pump the loop until the packet at pos is complete.
template <typename B>
bool wait_packet(Transport& t, B& b, int fd, uint8_t* buf, size_t cap, size_t& got, size_t& pos,
                 uint8_t& fb, ByteSpan& body) {
    for (int i = 0; i < 200; ++i) {
        if (packet_at(buf, got, pos, fb, body)) {
            return true;
        }
        t.poll_once(b, 5);
        const ssize_t r = ::read(fd, buf + got, cap - got);
        if (r > 0) {
            got += static_cast<size_t>(r);
        }
    }
    return false;
}

} // namespace

TEST(pipe_end_to_end_pubsub) {
    std::signal(SIGPIPE, SIG_IGN);
    PipePair pp;
    CHECK(pp.make());
    set_nonblocking(pp.b2c[0]);

    Transport t;
    Broker<PipeTraits, Transport> b{t};
    CHECK(t.open(pp.c2b[0], pp.b2c[1]));

    uint8_t buf[512];
    size_t got = 0;
    size_t pos = 0;
    uint8_t fb = 0;
    ByteSpan body{};

    send_all(pp.c2b[1], wire::make_connect("pipe-client").span());
    CHECK(wait_packet(t, b, pp.b2c[0], buf, sizeof buf, got, pos, fb, body));
    CHECK(packet_type(fb) == PacketType::connack);
    CHECK_EQ(body[1], 0);  // accepted

    send_all(pp.c2b[1], wire::make_subscribe(1, {{"p/#", 1}}).span());
    CHECK(wait_packet(t, b, pp.b2c[0], buf, sizeof buf, got, pos, fb, body));
    CHECK(packet_type(fb) == PacketType::suback);

    // QoS 1 loopback over the pipes: the broker forwards the PUBLISH to
    // the (same) client first, then acks the inbound publish.
    send_all(pp.c2b[1], wire::make_publish("p/x", wire::bs("via-pipe"), QoS::at_least_once,
                                           false, false, 11)
                            .span());
    CHECK(wait_packet(t, b, pp.b2c[0], buf, sizeof buf, got, pos, fb, body));
    PublishPacket p;
    CHECK(parse_publish(fb, body, p) == Err::ok);
    CHECK(p.topic == StrView("p/x"));
    CHECK(p.payload == wire::bs("via-pipe"));
    CHECK(p.qos == QoS::at_least_once);

    CHECK(wait_packet(t, b, pp.b2c[0], buf, sizeof buf, got, pos, fb, body));
    CHECK(packet_type(fb) == PacketType::puback);
    uint16_t acked = 0;
    CHECK(parse_packet_id_only(body, acked) == Err::ok);
    CHECK_EQ(acked, 11u);

    send_all(pp.c2b[1], wire::make_ack(PacketType::puback, p.packet_id).span());
    t.poll_once(b, 5);
}

TEST(pipe_client_eof_closes_transport) {
    std::signal(SIGPIPE, SIG_IGN);
    PipePair pp;
    CHECK(pp.make());

    Transport t;
    Broker<PipeTraits, Transport> b{t};
    CHECK(t.open(pp.c2b[0], pp.b2c[1]));

    t.poll_once(b, 5);  // opens connection 0
    ::close(pp.c2b[1]);  // client goes away
    ::close(pp.b2c[0]);
    for (int i = 0; i < 10 && !t.closed(); ++i) {
        t.poll_once(b, 5);
    }
    CHECK(t.closed());
}

TEST(pipe_protocol_error_makes_broker_close) {
    std::signal(SIGPIPE, SIG_IGN);
    PipePair pp;
    CHECK(pp.make());

    Transport t;
    Broker<PipeTraits, Transport> b{t};
    CHECK(t.open(pp.c2b[0], pp.b2c[1]));

    // First packet is not CONNECT: the broker must drop the connection,
    // which for a pipe transport means closing the descriptors.
    send_all(pp.c2b[1], wire::make_pingreq().span());
    for (int i = 0; i < 10 && !t.closed(); ++i) {
        t.poll_once(b, 5);
    }
    CHECK(t.closed());
    ::close(pp.c2b[1]);
    ::close(pp.b2c[0]);
}
