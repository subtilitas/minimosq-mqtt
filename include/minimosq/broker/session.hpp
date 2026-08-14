// minimosq — MQTT session state.
//
// A Session is the MQTT-level state of a client, identified by its
// client id. It outlives the network connection when the client
// connected with clean-session=0. Sessions live in a fixed Pool inside
// the broker; all members are fixed-capacity.
//
// SPDX-License-Identifier: MIT
#ifndef MINIMOSQ_BROKER_SESSION_HPP
#define MINIMOSQ_BROKER_SESSION_HPP

#include <cstddef>
#include <cstdint>

#include "../core/fixed_buffer.hpp"
#include "../core/fixed_string.hpp"
#include "../core/static_vector.hpp"
#include "../protocol/constants.hpp"

namespace minimosq {

// Delivery state of an outbound (broker → client) message.
enum class OutState : unsigned char {
    queued,            // waiting to be sent (client offline, or fresh)
    awaiting_puback,   // QoS 1 PUBLISH sent
    awaiting_pubrec,   // QoS 2 PUBLISH sent
    awaiting_pubcomp,  // PUBREC received, PUBREL sent
};

template <typename Traits>
struct Session {
    struct Subscription {
        FixedString<Traits::max_topic_len> filter;
        QoS granted = QoS::at_most_once;
    };

    // An owned copy of a QoS 1/2 message being delivered to this
    // session (in flight, or queued while the client is offline).
    struct OutMsg {
        FixedString<Traits::max_topic_len> topic;
        FixedBuffer<Traits::max_payload_len> payload;
        uint16_t packet_id = 0;
        QoS qos = QoS::at_least_once;
        OutState state = OutState::queued;
        bool retain = false;  // set only for retained delivery on subscribe
        bool dup = false;     // set when retransmitting after reconnect
    };

    static constexpr uint16_t no_conn = 0xFFFF;

    FixedString<Traits::max_client_id_len> client_id;
    StaticVector<Subscription, Traits::max_subscriptions_per_session> subs;

    // Outbound deliveries in order; in-order delivery relies on ordered
    // removal. Survives reconnects of a persistent session.
    StaticVector<OutMsg, Traits::max_pending_per_session> pending;
    uint16_t last_packet_id = 0;

    // Inbound QoS 2 PUBLISH packet ids between PUBLISH and PUBREL,
    // for exactly-once delivery. Survives reconnects of a persistent
    // session, as the spec requires.
    StaticVector<uint16_t, Traits::max_inbound_qos2> inbound_qos2;

    // Will message, armed while the client is connected and discarded
    // on a clean DISCONNECT.
    FixedString<Traits::max_topic_len> will_topic;
    FixedBuffer<Traits::max_payload_len> will_payload;
    QoS will_qos = QoS::at_most_once;
    bool will_retain = false;
    bool has_will = false;

    bool clean_session = true;
    uint16_t conn = no_conn;  // connection index while connected

    bool connected() const noexcept { return conn != no_conn; }

    Subscription* find_sub(StrView filter) noexcept {
        for (Subscription& sub : subs) {
            if (sub.filter.equals(filter)) {
                return &sub;
            }
        }
        return nullptr;
    }

    bool has_inbound_qos2(uint16_t id) const noexcept {
        for (uint16_t v : inbound_qos2) {
            if (v == id) {
                return true;
            }
        }
        return false;
    }

    void remove_inbound_qos2(uint16_t id) noexcept {
        for (size_t i = 0; i < inbound_qos2.size(); ++i) {
            if (inbound_qos2[i] == id) {
                inbound_qos2.remove_unordered(i);
                return;
            }
        }
    }

    // Next unused outbound packet id (non-zero, [MQTT-2.3.1]).
    uint16_t alloc_packet_id() noexcept {
        bool in_use = true;
        while (in_use) {
            ++last_packet_id;
            if (last_packet_id == 0) {
                last_packet_id = 1;
            }
            in_use = false;
            for (const OutMsg& m : pending) {
                if (m.state != OutState::queued && m.packet_id == last_packet_id) {
                    in_use = true;
                    break;
                }
            }
        }
        return last_packet_id;
    }

    // First pending entry with a given id in one of the given states.
    OutMsg* find_pending(uint16_t id, OutState a, OutState b, size_t* index) noexcept {
        for (size_t i = 0; i < pending.size(); ++i) {
            if (pending[i].packet_id == id &&
                (pending[i].state == a || pending[i].state == b)) {
                if (index != nullptr) {
                    *index = i;
                }
                return &pending[i];
            }
        }
        return nullptr;
    }
};

} // namespace minimosq

#endif // MINIMOSQ_BROKER_SESSION_HPP
