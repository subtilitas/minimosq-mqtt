// minimosq — MQTT 3.1.1 wire-protocol constants.
//
// Reference: MQTT Version 3.1.1, OASIS Standard, 29 October 2014.
// Section references in comments (e.g. [MQTT-2.2]) point into that text.
//
// SPDX-License-Identifier: MIT
#ifndef MINIMOSQ_PROTOCOL_CONSTANTS_HPP
#define MINIMOSQ_PROTOCOL_CONSTANTS_HPP

#include <cstddef>
#include <cstdint>

namespace minimosq {

// Control packet types, [MQTT-2.2.1].
enum class PacketType : uint8_t {
    connect = 1,
    connack = 2,
    publish = 3,
    puback = 4,
    pubrec = 5,
    pubrel = 6,
    pubcomp = 7,
    subscribe = 8,
    suback = 9,
    unsubscribe = 10,
    unsuback = 11,
    pingreq = 12,
    pingresp = 13,
    disconnect = 14,
};

enum class QoS : uint8_t {
    at_most_once = 0,
    at_least_once = 1,
    exactly_once = 2,
};

// CONNACK return codes, [MQTT-3.2.2.3].
enum class ConnackCode : uint8_t {
    accepted = 0,
    unacceptable_protocol = 1,
    identifier_rejected = 2,
    server_unavailable = 3,
    bad_credentials = 4,
    not_authorized = 5,
};

constexpr uint8_t protocol_level_311 = 4;      // [MQTT-3.1.2.2]
constexpr uint8_t suback_failure = 0x80;       // SUBACK "Failure" return code
constexpr uint32_t max_remaining_length = 268435455;  // [MQTT-2.2.3]
constexpr uint16_t max_utf8_len = 0xFFFF;

// ------------------------------------------------ fixed header helpers

constexpr uint8_t make_first_byte(PacketType t, uint8_t flags) noexcept {
    return static_cast<uint8_t>((static_cast<uint8_t>(t) << 4) | (flags & 0x0F));
}

constexpr PacketType packet_type(uint8_t first_byte) noexcept {
    return static_cast<PacketType>(first_byte >> 4);
}

constexpr uint8_t packet_flags(uint8_t first_byte) noexcept {
    return static_cast<uint8_t>(first_byte & 0x0F);
}

// PUBLISH fixed-header flag bits, [MQTT-3.3.1].
constexpr uint8_t publish_retain_bit = 0x01;
constexpr uint8_t publish_qos_shift = 1;
constexpr uint8_t publish_qos_mask = 0x06;
constexpr uint8_t publish_dup_bit = 0x08;

// CONNECT variable-header flag bits, [MQTT-3.1.2.3].
namespace connect_flags {
constexpr uint8_t reserved = 0x01;
constexpr uint8_t clean_session = 0x02;
constexpr uint8_t will = 0x04;
constexpr uint8_t will_qos_shift = 3;
constexpr uint8_t will_qos_mask = 0x18;
constexpr uint8_t will_retain = 0x20;
constexpr uint8_t password = 0x40;
constexpr uint8_t username = 0x80;
} // namespace connect_flags

// Number of bytes the Remaining Length varint needs for value v.
constexpr size_t varint_size(uint32_t v) noexcept {
    return v < 128 ? 1 : v < 16384 ? 2 : v < 2097152 ? 3 : 4;
}

// Non-PUBLISH packets have fixed, mandated flag nibbles, [MQTT-2.2.2].
constexpr bool fixed_flags_valid(PacketType t, uint8_t flags) noexcept {
    if (t == PacketType::publish) {
        return true;  // PUBLISH flags carry DUP/QoS/RETAIN and are checked separately
    }
    if (t == PacketType::pubrel || t == PacketType::subscribe || t == PacketType::unsubscribe) {
        return flags == 0x02;
    }
    return flags == 0x00;
}

} // namespace minimosq

#endif // MINIMOSQ_PROTOCOL_CONSTANTS_HPP
