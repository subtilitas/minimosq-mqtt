// minimosq — compile-time broker configuration.
//
// The broker is parameterized on a Traits type providing the constants
// below. All storage is sized from these at compile time; the broker
// performs no allocation, so the memory cost of a configuration is
// sizeof(Broker<Traits, ...>), which can be inspected at build time
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
    // sessions. At least max_connections to give every connection a
    // session of its own. A smaller value is supported: a CONNECT that
    // finds the pool full evicts the session disconnected longest, and
    // is refused with CONNACK 0x03 when every session is connected.
    static constexpr size_t max_sessions = 8;

    // Topic filters one session may hold. A SUBSCRIBE beyond this
    // answers 0x80 for the excess entries.
    static constexpr size_t max_subscriptions_per_session = 8;

    // Longest accepted topic name / topic filter, in bytes. The one
    // bound with four different consequences, because a filter can be
    // refused per entry and a topic cannot:
    //   - SUBSCRIBE filter too long: 0x80 for that entry, connection
    //     survives, the rest of the packet is granted normally.
    //   - PUBLISH topic too long: protocol_violation with Err::oversize
    //     and the connection closes. 3.1.1 has no per-message refusal,
    //     and a topic the broker cannot own could not be retained or
    //     queued, so half-delivering it is the worse answer.
    //   - Will topic too long: CONNACK 0x03, at CONNECT.
    //   - Broker::publish() with too long a topic: Err::oversize, no
    //     delivery.
    static constexpr size_t max_topic_len = 128;

    // Longest accepted client identifier, in bytes. Longer ids are
    // refused with CONNACK 0x02. The spec only requires 23.
    static constexpr size_t max_client_id_len = 64;

    // Largest accepted inbound packet body (variable header + payload).
    // Bigger packets close the connection with Err::oversize.
    static constexpr size_t max_packet_size = 1024;

    // Largest payload the broker will *store* (retained messages, wills,
    // and queued/in-flight QoS>0 deliveries). Pass-through QoS 0
    // delivery is bounded by max_packet_size instead.
    //
    // Exceeding it is invisible to the publisher. A QoS>0 subscriber
    // that would need an owned copy is skipped and delivery_dropped is
    // reported, but the PUBLISH is still acknowledged, because 3.1.1 has
    // no error acknowledgement and no way for a server to advertise a
    // limit. Set max_payload_len >= max_packet_size to rule the case out
    // entirely; otherwise the Observer is the only place it is visible.
    // Contrast max_topic_len, whose SUBSCRIBE half the client does see:
    // SUBACK carries a code per filter, so a refusal has somewhere to go.
    static constexpr size_t max_payload_len = 512;

    // Retained messages held, one per topic. A full store is a
    // best-effort miss: the message is still delivered live.
    static constexpr size_t max_retained = 16;

    // Per-session outbound queue: in-flight QoS 1/2 messages plus
    // messages queued for a disconnected persistent session.
    static constexpr size_t max_pending_per_session = 8;

    // Inbound QoS 2 PUBLISH ids being tracked for exactly-once
    // delivery (between PUBLISH and PUBREL). Size to the peak number of
    // unacknowledged QoS 2 publishes a client may have in flight.
    //
    // A client that exceeds it has the oldest tracked id forgotten,
    // reported as inbound_qos2_evicted. That id alone loses its
    // duplicate suppression: a redelivery of it is routed a second time.
    // The connection is kept, because the table outlives a disconnect —
    // dropping the client left a persistent session that no reconnect
    // could recover.
    static constexpr size_t max_inbound_qos2 = 8;

    // A connection must complete its CONNECT handshake within this
    // time. 0 disables it, as with the two windows below — a connection
    // that never sends CONNECT is then held until the peer drops it.
    static constexpr uint32_t connect_timeout_ms = 10000;

    // Reclaim connections from clients that connected with keep-alive 0
    // (which MQTT defines as "never time out") after this long without
    // traffic. 0 disables it, matching the letter of the spec.
    //
    // Without this, a client that connects with keep-alive 0 and then
    // goes silent holds its connection and session slot forever. That is
    // conformant, but on a broker with a handful of slots it is also all
    // an attacker needs. The member is optional: traits that omit it
    // behave as if it were 0.
    static constexpr uint32_t max_idle_ms = 0;

    // Every duration above is bounded by 2^31 - 1 ms (24 days 20 hours).
    // The deadline comparison tolerates the clock wrapping by comparing
    // signed differences, which leaves it half the uint32_t range; a
    // longer interval reads as already passed and fires at once. Broker
    // static_asserts each one.

    // Discard a disconnected persistent (clean-session=0) session after
    // this long without a connection. 0 disables it, which is the letter
    // of MQTT 3.1.1 — the protocol has no session expiry, so a session
    // is meant to live until its client returns.
    //
    // That is fine for a closed system and untenable for an open one. A
    // client that connects with clean-session=0 and then disconnects
    // cleanly leaves its session behind forever; max_sessions of those
    // fill the pool with no connection left to reclaim, and every later
    // client gets CONNACK 0x03. Independently of this timer the broker
    // evicts the longest-disconnected session rather than refuse a new
    // client, so a full pool is never fatal — but the timer is what
    // stops dead sessions accumulating in the first place, and eviction
    // is the fallback, not the plan. The member is optional: traits that
    // omit it behave as if it were 0.
    static constexpr uint32_t session_expiry_ms = 0;
};

}  // namespace minimosq

#endif  // MINIMOSQ_BROKER_CONFIG_HPP
