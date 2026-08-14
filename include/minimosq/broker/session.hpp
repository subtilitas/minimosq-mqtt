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

template <typename Traits>
struct Session {
    struct Subscription {
        FixedString<Traits::max_topic_len> filter;
        QoS granted = QoS::at_most_once;
    };

    static constexpr uint16_t no_conn = 0xFFFF;

    FixedString<Traits::max_client_id_len> client_id;
    StaticVector<Subscription, Traits::max_subscriptions_per_session> subs;

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
};

} // namespace minimosq

#endif // MINIMOSQ_BROKER_SESSION_HPP
