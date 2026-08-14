// Test-only fixtures for driving the broker: a capturing transport, a
// small traits configuration, and packet-expectation helpers.
// SPDX-License-Identifier: MIT
#ifndef MINIMOSQ_TESTS_BROKER_UTIL_HPP
#define MINIMOSQ_TESTS_BROKER_UTIL_HPP

#include "test.hpp"
#include "wire_util.hpp"

#include <minimosq/broker/broker.hpp>

namespace bt {

using namespace minimosq;

// Deliberately tiny limits so capacity behaviour is testable.
struct SmallTraits {
    static constexpr size_t max_connections = 4;
    static constexpr size_t max_sessions = 3;
    static constexpr size_t max_subscriptions_per_session = 3;
    static constexpr size_t max_topic_len = 32;
    static constexpr size_t max_client_id_len = 16;
    static constexpr size_t max_packet_size = 256;
    static constexpr size_t max_payload_len = 64;
    static constexpr size_t max_retained = 3;
    static constexpr size_t max_pending_per_session = 4;
    static constexpr size_t max_inbound_qos2 = 2;
    static constexpr uint32_t connect_timeout_ms = 5000;
};

struct CapturedPacket {
    bool ok = false;
    uint8_t first_byte = 0;
    ByteSpan body{};
};

template <size_t MaxConns>
struct CaptureTransport {
    struct Log {
        uint8_t bytes[16384];
        size_t len = 0;
        size_t rpos = 0;
        bool closed = false;
    };
    Log logs[MaxConns];
    bool send_ok = true;

    bool send(size_t ci, ByteSpan b) {
        if (!send_ok) {
            return false;
        }
        Log& l = logs[ci];
        CHECK(l.len + b.len <= sizeof l.bytes);
        for (size_t i = 0; i < b.len; ++i) {
            l.bytes[l.len + i] = b.data[i];
        }
        l.len += b.len;
        return true;
    }

    void close(size_t ci) { logs[ci].closed = true; }

    // Pop the next complete packet captured on a connection.
    CapturedPacket next(size_t ci) {
        Log& l = logs[ci];
        CapturedPacket p;
        if (l.rpos >= l.len) {
            return p;
        }
        size_t i = l.rpos;
        p.first_byte = l.bytes[i++];
        uint32_t rem = 0;
        uint8_t shift = 0;
        while (i < l.len) {
            const uint8_t b = l.bytes[i++];
            rem |= static_cast<uint32_t>(b & 0x7F) << shift;
            if ((b & 0x80) == 0) {
                break;
            }
            shift = static_cast<uint8_t>(shift + 7);
        }
        if (i + rem > l.len) {
            return p;  // incomplete
        }
        p.body = ByteSpan{l.bytes + i, rem};
        p.ok = true;
        l.rpos = i + rem;
        return p;
    }

    bool no_more(size_t ci) const { return logs[ci].rpos == logs[ci].len; }
};

// A broker wired to a capture transport, plus driving helpers.
template <typename Security = AllowAllSecurity>
struct BedT {
    using Transport = CaptureTransport<SmallTraits::max_connections>;
    Transport t;
    Broker<SmallTraits, Transport, Security> b{t};
    uint32_t now = 1000;

    void open(size_t c) { CHECK(b.conn_open(c, now) == Err::ok); }
    void feed(size_t c, const wire::Pkt& p) { b.conn_data(c, p.span(), now); }
    void connect(size_t c, const char* id) { connect(c, id, wire::ConnectOpts{}); }
    void connect(size_t c, const char* id, const wire::ConnectOpts& o) {
        open(c);
        feed(c, wire::make_connect(id, o));
    }
};
using Bed = BedT<>;

// ------------------------------------------------- expectation helpers

template <typename T>
inline void expect_connack(T& t, size_t ci, bool session_present, ConnackCode code) {
    CapturedPacket p = t.next(ci);
    CHECK(p.ok);
    CHECK(packet_type(p.first_byte) == PacketType::connack);
    CHECK_EQ(p.body.len, 2u);
    CHECK_EQ(p.body[0], session_present ? 1 : 0);
    CHECK_EQ(p.body[1], static_cast<uint8_t>(code));
}

// Returns the packet id (0 for QoS 0).
template <typename T>
inline uint16_t expect_publish(T& t, size_t ci, StrView topic, ByteSpan payload, QoS qos,
                               bool retain, bool dup = false) {
    CapturedPacket p = t.next(ci);
    CHECK(p.ok);
    if (!p.ok) {
        return 0;
    }
    CHECK(packet_type(p.first_byte) == PacketType::publish);
    PublishPacket pub;
    CHECK(parse_publish(p.first_byte, p.body, pub) == Err::ok);
    CHECK(pub.topic == topic);
    CHECK(pub.payload == payload);
    CHECK(pub.qos == qos);
    CHECK(pub.retain == retain);
    CHECK(pub.dup == dup);
    return pub.packet_id;
}

template <typename T, size_t N>
inline void expect_suback(T& t, size_t ci, uint16_t id, const uint8_t (&codes)[N]) {
    CapturedPacket p = t.next(ci);
    CHECK(p.ok);
    CHECK(packet_type(p.first_byte) == PacketType::suback);
    Reader r{p.body};
    CHECK_EQ(r.u16(), id);
    CHECK_EQ(p.body.len, 2u + N);
    for (size_t i = 0; i < N; ++i) {
        CHECK_EQ(r.u8(), codes[i]);
    }
}

template <typename T>
inline void expect_ack(T& t, size_t ci, PacketType type, uint16_t id) {
    CapturedPacket p = t.next(ci);
    CHECK(p.ok);
    CHECK(packet_type(p.first_byte) == type);
    uint16_t got = 0;
    CHECK(parse_packet_id_only(p.body, got) == Err::ok);
    CHECK_EQ(got, id);
}

template <typename T>
inline void expect_pingresp(T& t, size_t ci) {
    CapturedPacket p = t.next(ci);
    CHECK(p.ok);
    CHECK(packet_type(p.first_byte) == PacketType::pingresp);
    CHECK_EQ(p.body.len, 0u);
}

template <typename T>
inline void expect_silence(T& t, size_t ci) {
    CHECK(t.no_more(ci));
}

} // namespace bt

#endif // MINIMOSQ_TESTS_BROKER_UTIL_HPP
