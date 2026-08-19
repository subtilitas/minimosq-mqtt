// Test-only helpers that craft client-side MQTT packets, so broker and
// protocol tests can speak realistic wire bytes.
// SPDX-License-Identifier: MIT
#ifndef MINIMOSQ_TESTS_WIRE_UTIL_HPP
#define MINIMOSQ_TESTS_WIRE_UTIL_HPP

#include <cstddef>
#include <cstdint>
#include <initializer_list>

#include <minimosq/protocol/packets.hpp>

namespace wire {

using minimosq::ByteSpan;
using minimosq::PacketType;
using minimosq::QoS;
using minimosq::StrView;

// A self-contained packet (bytes + length), returnable by value.
struct Pkt {
    uint8_t data[1600] = {};
    size_t len = 0;
    ByteSpan span() const { return ByteSpan{data, len}; }
};

// Payload literal → bytes.
inline ByteSpan bs(const char* s) {
    return StrView(s).bytes();
}

// The body (variable header + payload) of a framed packet.
inline ByteSpan body_of(const Pkt& p) {
    size_t i = 1;  // skip first byte
    uint32_t rem = 0;
    uint8_t shift = 0;
    while (true) {
        const uint8_t b = p.data[i++];
        rem |= static_cast<uint32_t>(b & 0x7F) << shift;
        if ((b & 0x80) == 0) {
            break;
        }
        shift = static_cast<uint8_t>(shift + 7);
    }
    return ByteSpan{p.data + i, rem};
}

struct ConnectOpts {
    bool clean = true;
    uint16_t keepalive_s = 60;
    const char* will_topic = nullptr;
    ByteSpan will_payload{};
    QoS will_qos = QoS::at_most_once;
    bool will_retain = false;
    const char* username = nullptr;
    const char* password = nullptr;
    const char* protocol_name = "MQTT";
    uint8_t protocol_level = 4;
    uint8_t extra_flags = 0;  // for crafting malformed packets
};

inline Pkt make_connect(StrView client_id, const ConnectOpts& o = {}) {
    namespace cf = minimosq::connect_flags;
    Pkt p;
    minimosq::Writer w{p.data + minimosq::packet_overhead,
                       sizeof p.data - minimosq::packet_overhead};
    uint8_t flags = o.extra_flags;
    if (o.clean) {
        flags |= cf::clean_session;
    }
    if (o.will_topic != nullptr) {
        flags |= cf::will;
        flags =
            static_cast<uint8_t>(flags | (static_cast<uint8_t>(o.will_qos) << cf::will_qos_shift));
        if (o.will_retain) {
            flags |= cf::will_retain;
        }
    }
    if (o.username != nullptr) {
        flags |= cf::username;
    }
    if (o.password != nullptr) {
        flags |= cf::password;
    }
    w.utf8(o.protocol_name);
    w.u8(o.protocol_level);
    w.u8(flags);
    w.u16(o.keepalive_s);
    w.utf8(client_id);
    if (o.will_topic != nullptr) {
        w.utf8(o.will_topic);
        w.u16(static_cast<uint16_t>(o.will_payload.len));
        w.bytes(o.will_payload);
    }
    if (o.username != nullptr) {
        w.utf8(o.username);
    }
    if (o.password != nullptr) {
        const ByteSpan pw = bs(o.password);
        w.u16(static_cast<uint16_t>(pw.len));
        w.bytes(pw);
    }
    const ByteSpan full =
        minimosq::frame_packet(p.data, minimosq::make_first_byte(PacketType::connect, 0), w.size());
    // frame_packet may not start at data[0]; normalize to the front.
    for (size_t i = 0; i < full.len; ++i) {
        p.data[i] = full.data[i];
    }
    p.len = full.len;
    return p;
}

inline Pkt from_span(ByteSpan s) {
    Pkt p;
    for (size_t i = 0; i < s.len; ++i) {
        p.data[i] = s.data[i];
    }
    p.len = s.len;
    return p;
}

inline Pkt make_publish(StrView topic, ByteSpan payload, QoS qos = QoS::at_most_once,
                        bool retain = false, bool dup = false, uint16_t id = 0) {
    uint8_t buf[1600];
    return from_span(
        minimosq::build_publish(buf, sizeof buf, topic, payload, qos, retain, dup, id));
}

struct SubEntry {
    const char* filter;
    uint8_t qos;
};

inline Pkt make_subscribe(uint16_t id, std::initializer_list<SubEntry> entries) {
    Pkt p;
    minimosq::Writer w{p.data + minimosq::packet_overhead,
                       sizeof p.data - minimosq::packet_overhead};
    w.u16(id);
    for (const SubEntry& e : entries) {
        w.utf8(e.filter);
        w.u8(e.qos);
    }
    const ByteSpan full = minimosq::frame_packet(
        p.data, minimosq::make_first_byte(PacketType::subscribe, 0x02), w.size());
    return from_span(full);
}

inline Pkt make_unsubscribe(uint16_t id, std::initializer_list<const char*> filters) {
    Pkt p;
    minimosq::Writer w{p.data + minimosq::packet_overhead,
                       sizeof p.data - minimosq::packet_overhead};
    w.u16(id);
    for (const char* f : filters) {
        w.utf8(f);
    }
    const ByteSpan full = minimosq::frame_packet(
        p.data, minimosq::make_first_byte(PacketType::unsubscribe, 0x02), w.size());
    return from_span(full);
}

inline Pkt make_ack(PacketType t, uint16_t id) {
    uint8_t buf[16];
    return from_span(minimosq::build_packet_id_only(buf, sizeof buf, t, id));
}

inline Pkt make_empty(PacketType t) {
    Pkt p;
    p.data[0] = minimosq::make_first_byte(t, 0);
    p.data[1] = 0;
    p.len = 2;
    return p;
}

inline Pkt make_pingreq() {
    return make_empty(PacketType::pingreq);
}
inline Pkt make_disconnect() {
    return make_empty(PacketType::disconnect);
}

}  // namespace wire

#endif  // MINIMOSQ_TESTS_WIRE_UTIL_HPP
