// minimosq — MQTT 3.1.1 packet parsing and serialization.
//
// Parsers work on the body span produced by FrameParser and enforce the
// *syntactic* rules of the spec (structure, flag consistency, trailing
// bytes). Semantic rules that need broker state — client-id policy,
// session handling, topic validity against capacities — live in the
// broker.
//
// Builders write complete packets (fixed header included) into a
// caller-provided buffer and return the packet span, or an empty span
// when it does not fit.
//
// SPDX-License-Identifier: MIT
#ifndef MINIMOSQ_PROTOCOL_PACKETS_HPP
#define MINIMOSQ_PROTOCOL_PACKETS_HPP

#include <cstddef>
#include <cstdint>

#include "../core/error.hpp"
#include "../core/span.hpp"
#include "constants.hpp"
#include "reader.hpp"
#include "writer.hpp"

namespace minimosq {

// ------------------------------------------------------------- parsing

struct ConnectPacket {
    StrView client_id;
    StrView will_topic;
    ByteSpan will_payload;
    StrView username;
    ByteSpan password;
    uint16_t keepalive_s = 0;
    uint8_t protocol_level = 0;
    QoS will_qos = QoS::at_most_once;
    bool protocol_name_ok = false;
    bool clean_session = false;
    bool has_will = false;
    bool will_retain = false;
    bool has_username = false;
    bool has_password = false;
};

// Parse a CONNECT body, [MQTT-3.1]. protocol_name_ok / protocol_level are
// reported rather than enforced so the broker can answer with the proper
// CONNACK code.
inline Err parse_connect(ByteSpan body, ConnectPacket& out) {
    Reader r{body};
    const StrView name = r.utf8();
    out.protocol_name_ok = (name == StrView("MQTT"));
    out.protocol_level = r.u8();
    const uint8_t flags = r.u8();
    out.keepalive_s = r.u16();
    if (!r.ok()) {
        return Err::truncated;
    }
    if ((flags & connect_flags::reserved) != 0) {
        return Err::malformed;  // [MQTT-3.1.2-3]
    }
    out.clean_session = (flags & connect_flags::clean_session) != 0;
    out.has_will = (flags & connect_flags::will) != 0;
    out.will_retain = (flags & connect_flags::will_retain) != 0;
    out.has_username = (flags & connect_flags::username) != 0;
    out.has_password = (flags & connect_flags::password) != 0;

    const uint8_t will_qos_raw = static_cast<uint8_t>((flags & connect_flags::will_qos_mask) >>
                                                      connect_flags::will_qos_shift);
    if (will_qos_raw > 2) {
        return Err::malformed;  // [MQTT-3.1.2-14]
    }
    if (!out.has_will && (will_qos_raw != 0 || out.will_retain)) {
        return Err::malformed;  // [MQTT-3.1.2-11, -13, -15]
    }
    if (out.has_password && !out.has_username) {
        return Err::malformed;  // [MQTT-3.1.2-22]
    }
    out.will_qos = static_cast<QoS>(will_qos_raw);

    out.client_id = r.utf8();
    if (out.has_will) {
        out.will_topic = r.utf8();
        out.will_payload = r.len_prefixed_bytes();
    }
    if (out.has_username) {
        out.username = r.utf8();
    }
    if (out.has_password) {
        out.password = r.len_prefixed_bytes();
    }
    if (!r.ok()) {
        return Err::truncated;
    }
    if (!r.at_end()) {
        return Err::malformed;  // payload longer than the flags announce
    }
    return Err::ok;
}

struct PublishPacket {
    StrView topic;
    ByteSpan payload;
    uint16_t packet_id = 0;  // only meaningful for QoS > 0
    QoS qos = QoS::at_most_once;
    bool retain = false;
    bool dup = false;
};

// Parse a PUBLISH fixed-header flags + body, [MQTT-3.3].
inline Err parse_publish(uint8_t first_byte, ByteSpan body, PublishPacket& out) {
    const uint8_t flags = packet_flags(first_byte);
    const uint8_t qos_raw = static_cast<uint8_t>((flags & publish_qos_mask) >> publish_qos_shift);
    if (qos_raw > 2) {
        return Err::malformed;  // [MQTT-3.3.1-4]
    }
    out.qos = static_cast<QoS>(qos_raw);
    out.dup = (flags & publish_dup_bit) != 0;
    out.retain = (flags & publish_retain_bit) != 0;
    if (out.qos == QoS::at_most_once && out.dup) {
        return Err::malformed;  // [MQTT-3.3.1-2]
    }

    Reader r{body};
    out.topic = r.utf8();
    if (out.qos != QoS::at_most_once) {
        out.packet_id = r.u16();
    }
    // Truncation is checked first: a short read yields a zero packet id,
    // which would otherwise be misreported as malformed.
    if (!r.ok()) {
        return Err::truncated;
    }
    if (out.qos != QoS::at_most_once && out.packet_id == 0) {
        return Err::malformed;  // [MQTT-2.3.1-1]
    }
    out.payload = r.rest();
    return Err::ok;
}

// Parse the 2-byte packet-identifier body shared by PUBACK, PUBREC,
// PUBREL, PUBCOMP and UNSUBACK.
inline Err parse_packet_id_only(ByteSpan body, uint16_t& id) {
    Reader r{body};
    id = r.u16();
    if (!r.ok()) {
        return Err::truncated;
    }
    if (!r.at_end()) {
        return Err::malformed;
    }
    if (id == 0) {
        return Err::malformed;  // [MQTT-2.3.1-1]
    }
    return Err::ok;
}

// Streaming parser for the SUBSCRIBE/UNSUBSCRIBE payload: a packet id
// followed by one or more topic filters (each with a requested-QoS byte
// for SUBSCRIBE). Usage:
//
//   TopicListParser p{body, /*with_qos=*/true};
//   StrView filter; QoS qos;
//   while (p.next(filter, qos)) { ...handle entry... }
//   if (p.status() != Err::ok) { ...protocol error, close... }
class TopicListParser {
public:
    TopicListParser(ByteSpan body, bool with_qos) noexcept : r_(body), with_qos_(with_qos) {
        packet_id_ = r_.u16();
        if (!r_.ok()) {
            err_ = Err::truncated;
        } else if (packet_id_ == 0) {
            err_ = Err::malformed;  // [MQTT-2.3.1-1]
        }
    }

    uint16_t packet_id() const noexcept { return packet_id_; }

    // Sticky result; Err::malformed also covers an empty filter list
    // ([MQTT-3.8.3-3] / [MQTT-3.10.3-2]).
    Err status() const noexcept { return err_; }

    bool next(StrView& filter, QoS& qos) noexcept {
        if (err_ != Err::ok) {
            return false;
        }
        if (r_.at_end()) {
            if (count_ == 0) {
                err_ = Err::malformed;
            }
            return false;
        }
        filter = r_.utf8();
        uint8_t q = 0;
        if (with_qos_) {
            q = r_.u8();
        }
        if (!r_.ok()) {
            err_ = Err::truncated;
            return false;
        }
        if (q > 2) {
            err_ = Err::malformed;  // [MQTT-3.8.3-4]
            return false;
        }
        qos = static_cast<QoS>(q);
        ++count_;
        return true;
    }

private:
    Reader r_;
    uint16_t packet_id_ = 0;
    size_t count_ = 0;
    Err err_ = Err::ok;
    bool with_qos_;
};

// ------------------------------------------------------- serialization

// Every builder needs at most this much room in front of the body for
// the fixed header (1 first byte + up to 4 Remaining Length bytes).
constexpr size_t packet_overhead = 5;

// Frame a body that was written at buf + packet_overhead: places the
// fixed header directly before the body so the packet is contiguous.
// Returns the full packet span, or an empty span when body_len exceeds
// what a Remaining Length varint can express — returning the span
// regardless would describe bytes that were never written.
inline ByteSpan frame_packet(uint8_t* buf, uint8_t first_byte, size_t body_len) {
    if (body_len > max_remaining_length) {
        return ByteSpan{};
    }
    const size_t vs = varint_size(static_cast<uint32_t>(body_len));
    const size_t start = packet_overhead - 1 - vs;
    Writer w{buf + start, 1 + vs};
    w.u8(first_byte);
    w.varint(static_cast<uint32_t>(body_len));
    if (!w.ok()) {
        return ByteSpan{};
    }
    return ByteSpan{buf + start, 1 + vs + body_len};
}

inline ByteSpan build_connack(uint8_t* buf, size_t cap, bool session_present, ConnackCode code) {
    if (cap < packet_overhead + 2) {
        return ByteSpan{};
    }
    Writer w{buf + packet_overhead, cap - packet_overhead};
    w.u8(session_present ? 0x01 : 0x00);
    w.u8(static_cast<uint8_t>(code));
    if (!w.ok()) {
        return ByteSpan{};
    }
    return frame_packet(buf, make_first_byte(PacketType::connack, 0), w.size());
}

inline ByteSpan build_publish(uint8_t* buf, size_t cap, StrView topic, ByteSpan payload, QoS qos,
                              bool retain, bool dup, uint16_t packet_id) {
    uint8_t flags = static_cast<uint8_t>(static_cast<uint8_t>(qos) << publish_qos_shift);
    if (retain) {
        flags |= publish_retain_bit;
    }
    if (dup) {
        flags |= publish_dup_bit;
    }
    if (cap < packet_overhead) {
        return ByteSpan{};
    }
    Writer w{buf + packet_overhead, cap - packet_overhead};
    w.utf8(topic);
    if (qos != QoS::at_most_once) {
        w.u16(packet_id);
    }
    w.bytes(payload);
    if (!w.ok()) {
        return ByteSpan{};
    }
    return frame_packet(buf, make_first_byte(PacketType::publish, flags), w.size());
}

// PUBACK / PUBREC / PUBREL / PUBCOMP / UNSUBACK all carry just a packet
// id; PUBREL gets its mandated flag nibble 0x02 [MQTT-3.6.1-1].
inline ByteSpan build_packet_id_only(uint8_t* buf, size_t cap, PacketType type,
                                     uint16_t packet_id) {
    if (cap < packet_overhead + 2) {
        return ByteSpan{};
    }
    Writer w{buf + packet_overhead, cap - packet_overhead};
    w.u16(packet_id);
    if (!w.ok()) {
        return ByteSpan{};
    }
    const uint8_t flags = (type == PacketType::pubrel) ? 0x02 : 0x00;
    return frame_packet(buf, make_first_byte(type, flags), w.size());
}

inline ByteSpan build_pingresp(uint8_t* buf, size_t cap) {
    if (cap < 2) {
        return ByteSpan{};
    }
    buf[0] = make_first_byte(PacketType::pingresp, 0);
    buf[1] = 0;
    return ByteSpan{buf, 2};
}

}  // namespace minimosq

#endif  // MINIMOSQ_PROTOCOL_PACKETS_HPP
