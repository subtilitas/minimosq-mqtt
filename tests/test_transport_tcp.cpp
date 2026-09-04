// Integration test: the broker behind the real TCP transport, exercised
// with plain client sockets over loopback.
// SPDX-License-Identifier: MIT
#include "broker_util.hpp"
#include "test.hpp"
#include "wire_util.hpp"

#include <minimosq/broker/broker.hpp>
#include <minimosq/transports/posix/tcp.hpp>

#include <arpa/inet.h>
#include <cerrno>
#include <csignal>
#include <cstring>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/time.h>
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
        // See test_transport_uds.cpp: a dead fd would spin forever here.
        CHECK(fd >= 0);
        size_t off = 0;
        while (fd >= 0 && off < p.len) {
            const ssize_t w = ::send(fd, p.data + off, p.len - off, MSG_NOSIGNAL);
            if (w > 0) {
                off += static_cast<size_t>(w);
            } else if (w < 0 && errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
                break;
            }
        }
        CHECK(off == p.len);
    }

    // Read whatever is available right now.
    void drain() {
        while (rx_len < sizeof rx) {
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

// ------------------------------------------------- sizes the broker checks

// OutBufSize is declared on the transport and max_packet_size in Traits, with
// nothing tying them together: a ring smaller than one packet cannot fail
// transiently, because send() appends the packet whole and would refuse it
// every time. Broker static_asserts the two agree, which only works while the
// transport keeps publishing its capacity.
TEST(tcp_transport_publishes_its_outbound_capacity) {
    using Small = minimosq::TcpTransport<4, 2048>;
    static_assert(Small::out_buf_size == 2048,
                  "the transport must publish OutBufSize for Broker to check it");
    static_assert(minimosq::transport_out_buf_size<Small>::value == 2048,
                  "and the detection trait must see it");
    CHECK_EQ(Small::out_buf_size, size_t{2048});
    CHECK_EQ(minimosq::transport_out_buf_size<Small>::value, size_t{2048});

    // A transport that publishes nothing opts out rather than failing to
    // compile, which is what keeps the check from breaking a third-party
    // transport that does not buffer at all.
    struct Unbuffered {
        bool send(size_t, minimosq::ByteSpan) { return true; }
        void close(size_t) {}
    };
    static_assert(minimosq::transport_out_buf_size<Unbuffered>::value == 0,
                  "a transport that does not say is left alone");
    CHECK_EQ(minimosq::transport_out_buf_size<Unbuffered>::value, size_t{0});
}

namespace {
// design.md advises max_payload_len >= max_packet_size; these traits take
// that advice, which makes the stored parts wider than max_packet_size.
struct WideTraits : TinyTraits {
    static constexpr size_t max_payload_len = TinyTraits::max_packet_size;
};
}  // namespace

// The ring must hold what send() is handed, not what the frame parser
// accepts. max_packet_size bounds an inbound Remaining Length — the body
// alone — while send() receives the framed packet: fixed header, length
// varint, body. Packets built from stored parts are not bounded by
// max_packet_size at all. Broker::out_size is that whole quantity, and
// the static_assert compares the ring against it.
TEST(broker_out_size_covers_the_whole_framed_packet) {
    using Ring = minimosq::TcpTransport<TinyTraits::max_connections, 4096>;
    using B = minimosq::Broker<TinyTraits, Ring>;

    constexpr size_t stored = 2 + TinyTraits::max_topic_len + 2 + TinyTraits::max_payload_len;
    constexpr size_t widest =
        TinyTraits::max_packet_size > stored ? TinyTraits::max_packet_size : stored;
    static_assert(B::out_size == minimosq::packet_overhead + widest,
                  "out_size is the framed size of the widest packet the broker builds");
    // A ring sized to max_packet_size — what the check used to ask for —
    // is short by the fixed header and cannot hold that packet.
    static_assert(B::out_size > TinyTraits::max_packet_size,
                  "max_packet_size alone is not a sufficient ring size");
    CHECK_EQ(B::out_size, minimosq::packet_overhead + widest);

    // design.md advises max_payload_len >= max_packet_size. That makes
    // the stored parts the wider of the two, so max_packet_size stops
    // bounding the packet at all.
    using W = minimosq::Broker<WideTraits, Ring>;
    constexpr size_t wide_stored = 2 + WideTraits::max_topic_len + 2 + WideTraits::max_payload_len;
    static_assert(wide_stored > WideTraits::max_packet_size,
                  "the stored parts are the wider case here");
    static_assert(W::out_size == minimosq::packet_overhead + wide_stored,
                  "so out_size follows the stored parts, not max_packet_size");
    CHECK_EQ(W::out_size, minimosq::packet_overhead + wide_stored);
}

// ------------------------------------------------------- write policy
//
// send() appends; every ring that gained bytes is written once at the end
// of the poll pass, after tick(). These pin that, since the pub/sub tests
// above pass just as well with a per-packet write.

namespace {

using bt::Scripted;

// Connect a client and pump until the transport holds its socket in slot 0.
template <typename T, typename B>
bool accept_one(T& t, B& b, Client& c) {
    if (!c.connect_to(t.port())) {
        return false;
    }
    for (int i = 0; i < 20 && t.native_handle(0) < 0; ++i) {
        t.poll_once(b, 5);
    }
    return t.native_handle(0) >= 0;
}

// Drain until the client holds `want` bytes, pumping the loop in between so
// a ring left over by EAGAIN gets its POLLOUT pass.
template <typename T, typename B>
void receive(T& t, B& b, Client& c, size_t want) {
    for (int i = 0; i < 50 && c.rx_len < want; ++i) {
        c.drain();
        if (c.rx_len < want) {
            t.poll_once(b, 5);
        }
    }
}

void on_alarm(int) {}

}  // namespace

TEST(tcp_accepted_sockets_have_nodelay) {
    TcpTransport<2> t;
    Scripted<TcpTransport<2>> b{t};
    CHECK(t.open(0, "127.0.0.1"));
    Client c;
    CHECK(accept_one(t, b, c));
    CHECK_EQ(t.native_handle(1), -1);
    CHECK_EQ(t.native_handle(2), -1);  // out of range reads as free

    int on = 0;
    socklen_t len = sizeof on;
    CHECK(::getsockopt(t.native_handle(0), IPPROTO_TCP, TCP_NODELAY, &on, &len) == 0);
    CHECK(on != 0);
    c.close();
}

TEST(tcp_output_from_tick_leaves_in_the_same_pass) {
    TcpTransport<2> t;
    Scripted<TcpTransport<2>> b{t};
    CHECK(t.open(0, "127.0.0.1"));
    Client c;
    CHECK(accept_one(t, b, c));

    b.from_tick = wire::bs("tick");
    t.poll_once(b, 5);  // nothing readable: times out, ticks, must still write
    CHECK_EQ(b.sends_ok, 1);
    receive(t, b, c, 4);
    CHECK_EQ(c.rx_len, size_t{4});
    CHECK(std::memcmp(c.rx, "tick", 4) == 0);
    c.close();
}

TEST(tcp_pass_larger_than_the_ring_is_written_not_dropped) {
    using Small = TcpTransport<1, 256>;
    Small t;
    Scripted<Small> b{t};
    CHECK(t.open(0, "127.0.0.1"));
    Client c;
    CHECK(accept_one(t, b, c));

    uint8_t chunk[100];
    std::memset(chunk, 0x55, sizeof chunk);
    b.reply = ByteSpan{chunk, sizeof chunk};
    b.replies = 8;  // 800 bytes into a 256-byte ring from one conn_data()
    c.send_pkt(wire::make_pingreq());
    t.poll_once(b, 50);
    CHECK_EQ(b.sends_ok, 8);
    CHECK_EQ(b.sends_failed, 0);  // a busy connection is not a slow consumer
    CHECK(t.native_handle(0) >= 0);
    receive(t, b, c, 800);
    CHECK_EQ(c.rx_len, size_t{800});
    c.close();
}

TEST(tcp_reply_reaches_a_peer_that_half_closed) {
    TcpTransport<2> t;
    Scripted<TcpTransport<2>> b{t};
    CHECK(t.open(0, "127.0.0.1"));
    Client c;
    CHECK(accept_one(t, b, c));

    b.reply = wire::bs("pong");
    c.send_pkt(wire::make_pingreq());
    CHECK(::shutdown(c.fd, SHUT_WR) == 0);  // data, then EOF, in one pass
    for (int i = 0; i < 20 && b.closed == 0; ++i) {
        t.poll_once(b, 5);
    }
    CHECK_EQ(b.closed, 1);
    CHECK_EQ(b.sends_ok, 1);
    CHECK_EQ(t.native_handle(0), -1);
    receive(t, b, c, 4);
    CHECK_EQ(c.rx_len, size_t{4});
    CHECK(std::memcmp(c.rx, "pong", 4) == 0);
    c.close();
}

TEST(tcp_signal_interrupted_pass_still_writes) {
    TcpTransport<2> t;
    Scripted<TcpTransport<2>> b{t};
    CHECK(t.open(0, "127.0.0.1"));
    Client c;
    CHECK(accept_one(t, b, c));

    // A handler without SA_RESTART makes poll() return EINTR, which is
    // the path a stop() from a signal handler takes.
    // Process-global state is only touched once its setup succeeded, and
    // is restored in reverse order; CHECK() does not abort, so the test
    // returns instead.
    struct sigaction sa {};
    sa.sa_handler = on_alarm;
    sigemptyset(&sa.sa_mask);
    struct sigaction old {};
    const bool handler_installed = ::sigaction(SIGALRM, &sa, &old) == 0;
    CHECK(handler_installed);
    if (!handler_installed) {
        return;
    }
    itimerval arm{};
    arm.it_value.tv_usec = 20000;  // 20 ms, well inside the 2 s poll
    const bool timer_armed = ::setitimer(ITIMER_REAL, &arm, nullptr) == 0;
    CHECK(timer_armed);
    if (!timer_armed) {
        ::sigaction(SIGALRM, &old, nullptr);
        return;
    }

    b.from_tick = wire::bs("tick");
    const int rc = t.poll_once(b, 2000);

    const itimerval off{};
    ::setitimer(ITIMER_REAL, &off, nullptr);
    ::sigaction(SIGALRM, &old, nullptr);

    CHECK_EQ(rc, 0);
    CHECK_EQ(b.sends_ok, 1);
    receive(t, b, c, 4);
    CHECK_EQ(c.rx_len, size_t{4});
    c.close();
}

TEST(tcp_span_that_still_does_not_fit_after_a_write_is_refused) {
    using Small = TcpTransport<1, 256>;
    Small t;
    Scripted<Small> b{t};
    CHECK(t.open(0, "127.0.0.1"));

    // A peer that never reads, with the smallest buffers the kernel allows
    // on both ends, so the socket fills within one conn_data().
    Client c;
    c.fd = ::socket(AF_INET, SOCK_STREAM, 0);
    CHECK(c.fd >= 0);
    int small = 1;
    CHECK(::setsockopt(c.fd, SOL_SOCKET, SO_RCVBUF, &small, sizeof small) == 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(t.port());
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    CHECK(::connect(c.fd, reinterpret_cast<const sockaddr*>(&addr), sizeof addr) == 0);
    CHECK(set_nonblocking(c.fd));
    for (int i = 0; i < 20 && t.native_handle(0) < 0; ++i) {
        t.poll_once(b, 5);
    }
    CHECK(t.native_handle(0) >= 0);
    CHECK(::setsockopt(t.native_handle(0), SOL_SOCKET, SO_SNDBUF, &small, sizeof small) == 0);

    uint8_t chunk[100];
    std::memset(chunk, 0x55, sizeof chunk);
    b.reply = ByteSpan{chunk, sizeof chunk};
    b.replies = 2000;  // 200 KB at a peer that takes a few KB and stops
    c.send_pkt(wire::make_pingreq());
    t.poll_once(b, 50);
    CHECK(b.sends_ok > 0);      // the ring was written and reused first
    CHECK(b.sends_failed > 0);  // then refused: this is the slow-consumer signal
    t.close(0);
    CHECK_EQ(t.native_handle(0), -1);
    c.close();
}

// ------------------------------------------------ listener and ring edges

// A second open() used to assign over listen_fd_, leaking the first
// descriptor and, for a unix socket, leaving its path bound to nothing.
TEST(a_second_open_releases_the_first_listener) {
    Transport t;
    CHECK(t.open(0));
    const uint16_t first = t.port();
    CHECK(first != 0);

    CHECK(t.open(0));
    const uint16_t second = t.port();
    CHECK(second != 0);
    CHECK(second != first);

    // The first port is listenable again, which it would not be if the
    // descriptor were still held.
    int probe = ::socket(AF_INET, SOCK_STREAM, 0);
    CHECK(probe >= 0);
    int yes = 1;
    ::setsockopt(probe, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof yes);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(first);
    const bool bound = ::bind(probe, reinterpret_cast<const sockaddr*>(&addr), sizeof addr) == 0;
    ::close(probe);
    CHECK(bound);
}

// OutRing::consume() is handed the count a write actually took. A count
// past what is held would wrap the unsigned length and every later read
// would run off the end; the two fixed-capacity containers guard the
// same shape, and this one now does too.
TEST(out_ring_consume_clamps_instead_of_wrapping) {
    minimosq::OutRing<64> ring;
    const uint8_t bytes[] = {'a', 'b', 'c'};
    CHECK(ring.append(minimosq::ByteSpan{bytes, sizeof bytes}));
    CHECK_EQ(ring.size(), size_t{3});

    ring.consume(100);  // more than is held
    CHECK_EQ(ring.size(), size_t{0});
    CHECK(ring.empty());

    // Still usable afterwards.
    CHECK(ring.append(minimosq::ByteSpan{bytes, sizeof bytes}));
    CHECK_EQ(ring.size(), size_t{3});
}
