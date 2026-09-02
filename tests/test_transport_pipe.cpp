// Integration test: the broker behind the pipe transport, over
// anonymous pipe(2) descriptors.
// SPDX-License-Identifier: MIT
#include "test.hpp"
#include "wire_util.hpp"

#include <minimosq/broker/broker.hpp>
#include <minimosq/transports/posix/pipe.hpp>

#include <csignal>
#include <cstring>
#include <sys/time.h>
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

}  // namespace

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
    send_all(pp.c2b[1],
             wire::make_publish("p/x", wire::bs("via-pipe"), QoS::at_least_once, false, false, 11)
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

    t.poll_once(b, 5);   // opens connection 0
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

// ------------------------------------------------------- write policy
//
// Same policy as the stream transport: send() appends, the ring is written
// once at the end of the pass. See test_transport_tcp.cpp for the rationale.

namespace {

template <typename T>
struct Scripted {
    T& t;
    ByteSpan reply{};
    int replies = 1;
    ByteSpan from_tick{};
    int sends_ok = 0;
    int sends_failed = 0;
    int closed = 0;

    explicit Scripted(T& transport) : t(transport) {}
    Err conn_open(size_t, uint32_t) { return Err::ok; }
    Err conn_data(size_t ci, ByteSpan, uint32_t) {
        for (int i = 0; i < replies; ++i) {
            (t.send(ci, reply) ? sends_ok : sends_failed)++;
        }
        return Err::ok;
    }
    void conn_closed(size_t) { ++closed; }
    void tick(uint32_t) {
        if (!from_tick.empty()) {
            (t.send(0, from_tick) ? sends_ok : sends_failed)++;
            from_tick = ByteSpan{};
        }
    }
};

// Read from the broker->client pipe until `want` bytes arrived, pumping
// the loop in between.
template <typename T, typename B>
size_t receive(T& t, B& b, int fd, uint8_t* buf, size_t want) {
    size_t got = 0;
    for (int i = 0; i < 50 && got < want; ++i) {
        const ssize_t r = ::read(fd, buf + got, want - got);
        if (r > 0) {
            got += static_cast<size_t>(r);
        } else {
            t.poll_once(b, 5);
        }
    }
    return got;
}

void on_alarm(int) {}

}  // namespace

TEST(pipe_output_from_tick_leaves_in_the_same_pass) {
    std::signal(SIGPIPE, SIG_IGN);
    PipePair pp;
    CHECK(pp.make());
    set_nonblocking(pp.b2c[0]);
    Transport t;
    Scripted<Transport> b{t};
    CHECK(t.open(pp.c2b[0], pp.b2c[1]));
    t.poll_once(b, 5);  // opens connection 0

    b.from_tick = wire::bs("tick");
    t.poll_once(b, 5);  // nothing readable: times out, ticks, must still write
    CHECK_EQ(b.sends_ok, 1);
    uint8_t buf[8];
    CHECK_EQ(receive(t, b, pp.b2c[0], buf, 4), size_t{4});
    CHECK(std::memcmp(buf, "tick", 4) == 0);
    ::close(pp.c2b[1]);
    ::close(pp.b2c[0]);
}

TEST(pipe_pass_larger_than_the_ring_is_written_not_dropped) {
    std::signal(SIGPIPE, SIG_IGN);
    using Small = PipeTransport<256>;
    PipePair pp;
    CHECK(pp.make());
    set_nonblocking(pp.b2c[0]);
    Small t;
    Scripted<Small> b{t};
    CHECK(t.open(pp.c2b[0], pp.b2c[1]));
    t.poll_once(b, 5);

    uint8_t chunk[100];
    std::memset(chunk, 0x55, sizeof chunk);
    b.reply = ByteSpan{chunk, sizeof chunk};
    b.replies = 8;  // 800 bytes into a 256-byte ring from one conn_data()
    send_all(pp.c2b[1], wire::make_pingreq().span());
    t.poll_once(b, 50);
    CHECK_EQ(b.sends_ok, 8);
    CHECK_EQ(b.sends_failed, 0);
    CHECK(!t.closed());
    uint8_t buf[800];
    CHECK_EQ(receive(t, b, pp.b2c[0], buf, sizeof buf), sizeof buf);
    ::close(pp.c2b[1]);
    ::close(pp.b2c[0]);
}

TEST(pipe_reply_reaches_a_peer_that_closed_its_write_end) {
    std::signal(SIGPIPE, SIG_IGN);
    PipePair pp;
    CHECK(pp.make());
    set_nonblocking(pp.b2c[0]);
    Transport t;
    Scripted<Transport> b{t};
    CHECK(t.open(pp.c2b[0], pp.b2c[1]));
    t.poll_once(b, 5);

    b.reply = wire::bs("pong");
    send_all(pp.c2b[1], wire::make_pingreq().span());
    ::close(pp.c2b[1]);  // data, then EOF, in one pass
    for (int i = 0; i < 20 && !t.closed(); ++i) {
        t.poll_once(b, 5);
    }
    CHECK(t.closed());
    CHECK_EQ(b.closed, 1);
    CHECK_EQ(b.sends_ok, 1);
    uint8_t buf[8];
    CHECK_EQ(receive(t, b, pp.b2c[0], buf, 4), size_t{4});
    CHECK(std::memcmp(buf, "pong", 4) == 0);
    ::close(pp.b2c[0]);
}

TEST(pipe_span_that_still_does_not_fit_after_a_write_is_refused) {
    std::signal(SIGPIPE, SIG_IGN);
    using Small = PipeTransport<256>;
    PipePair pp;
    CHECK(pp.make());
    Small t;
    Scripted<Small> b{t};
    CHECK(t.open(pp.c2b[0], pp.b2c[1]));
    t.poll_once(b, 5);

    // Nobody reads b2c: the pipe takes its capacity (64 KiB by default),
    // then every write is EAGAIN and the ring cannot be emptied.
    uint8_t chunk[100];
    std::memset(chunk, 0x55, sizeof chunk);
    b.reply = ByteSpan{chunk, sizeof chunk};
    b.replies = 2000;  // 200 KB
    send_all(pp.c2b[1], wire::make_pingreq().span());
    t.poll_once(b, 50);
    CHECK(b.sends_ok > 0);
    CHECK(b.sends_failed > 0);
    t.close(0);
    CHECK(t.closed());
    ::close(pp.c2b[1]);
    ::close(pp.b2c[0]);
}

TEST(pipe_signal_interrupted_pass_still_writes) {
    std::signal(SIGPIPE, SIG_IGN);
    PipePair pp;
    CHECK(pp.make());
    set_nonblocking(pp.b2c[0]);
    Transport t;
    Scripted<Transport> b{t};
    CHECK(t.open(pp.c2b[0], pp.b2c[1]));
    t.poll_once(b, 5);

    struct sigaction sa {};
    sa.sa_handler = on_alarm;
    sigemptyset(&sa.sa_mask);
    struct sigaction old {};
    CHECK(::sigaction(SIGALRM, &sa, &old) == 0);
    itimerval arm{};
    arm.it_value.tv_usec = 20000;  // 20 ms, well inside the 2 s poll
    CHECK(::setitimer(ITIMER_REAL, &arm, nullptr) == 0);

    b.from_tick = wire::bs("tick");
    const int rc = t.poll_once(b, 2000);

    const itimerval off{};
    ::setitimer(ITIMER_REAL, &off, nullptr);
    ::sigaction(SIGALRM, &old, nullptr);

    CHECK_EQ(rc, 0);
    CHECK_EQ(b.sends_ok, 1);
    uint8_t buf[8];
    CHECK_EQ(receive(t, b, pp.b2c[0], buf, 4), size_t{4});
    ::close(pp.c2b[1]);
    ::close(pp.b2c[0]);
}
