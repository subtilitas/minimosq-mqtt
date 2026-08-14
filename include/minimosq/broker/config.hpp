// minimosq — compile-time broker configuration.
//
// The broker is parameterized on a Traits type providing the constants
// below. All storage is sized from these at compile time; the broker
// performs no allocation, so the memory cost of a configuration is
// simply sizeof(Broker<Traits, ...>) and can be inspected at build time
// (e.g. with static_assert).
//
// Define your own traits struct with the same members to tune capacity;
// DefaultTraits documents each knob.
//
// SPDX-License-Identifier: MIT
#ifndef MINIMOSQ_BROKER_CONFIG_HPP
#define MINIMOSQ_BROKER_CONFIG_HPP

#include <cstddef>
#include <cstdint>

namespace minimosq {

struct DefaultTraits {
    // Simultaneous transport connections (sockets). Connection indices
    // handed to the broker must be < max_connections.
    static constexpr size_t max_connections = 8;

    // MQTT sessions, including disconnected persistent (clean-session=0)
    // sessions. Must be >= max_connections to accept every connection.
    static constexpr size_t max_sessions = 8;

    static constexpr size_t max_subscriptions_per_session = 8;

    // Longest accepted topic name / topic filter, in bytes.
    static constexpr size_t max_topic_len = 128;

    static constexpr size_t max_client_id_len = 64;

    // Largest accepted inbound packet body (variable header + payload).
    // Bigger packets close the connection with Err::oversize.
    static constexpr size_t max_packet_size = 1024;

    // Largest payload the broker will *store* (retained messages, wills,
    // and queued/in-flight QoS>0 deliveries). Pass-through QoS 0
    // delivery is bounded by max_packet_size instead.
    static constexpr size_t max_payload_len = 512;

    static constexpr size_t max_retained = 16;

    // Per-session outbound queue: in-flight QoS 1/2 messages plus
    // messages queued for a disconnected persistent session.
    static constexpr size_t max_pending_per_session = 8;

    // Inbound QoS 2 PUBLISH ids being tracked for exactly-once
    // delivery (between PUBLISH and PUBREL). Size to the peak number of
    // unacknowledged QoS 2 publishes a client may have in flight.
    static constexpr size_t max_inbound_qos2 = 8;

    // A connection must complete its CONNECT handshake within this time.
    static constexpr uint32_t connect_timeout_ms = 10000;
};

} // namespace minimosq

#endif // MINIMOSQ_BROKER_CONFIG_HPP
