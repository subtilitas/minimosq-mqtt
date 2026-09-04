// minimosq — broker observability seam.
//
// The broker already decides everything worth recording: why a
// connection went away, which packet was a protocol violation, which
// message could not be stored, which delivery was dropped. Without a
// seam none of it is visible from outside, so an integrator can log
// authentication and authorization decisions (through the Security
// policy) and nothing else.
//
// Observer is the fourth Broker template parameter. It follows the same
// static-polymorphism pattern as Transport and Security: one method, no
// virtuals, no allocation, and the default (NullObserver) has an empty
// body that optimizes away entirely.
//
//     struct MyObserver {
//         void on_event(const minimosq::Event& e) noexcept {
//             log(event_kind_name(e.kind), e.client_id, e.topic);
//         }
//     };
//     minimosq::Broker<Traits, Transport, Security, MyObserver> broker{transport};
//
// The contract:
//
//   * on_event() is called from inside a broker entry point, on the same
//     thread, with the broker mid-operation. It must not call back into
//     the broker (publish(), conn_data(), …). Copy what you need and
//     return.
//
//     The consequence is worse than a garbled packet. receive_denied and
//     the delivery drops are raised from inside the loop over sessions
//     that routes a publish, and that loop holds a reference to the
//     session it is visiting. A nested publish() runs its own routing
//     and then the deferred teardown, which can release that very
//     session — leaving the outer loop reading an object that no longer
//     exists. connection_closed is raised while its connection is being
//     torn down, so re-entering with conn_data() for it feeds a parser
//     mid-teardown.
//
//     Republishing an event to an audit topic is the obvious way to hit
//     this. Queue it and publish from your own loop instead. Nothing
//     enforces the rule: it is a contract, not a guard.
//   * on_event() must not throw. The broker's entry points are not
//     noexcept, but some of the paths that reach on_event() run inside
//     Pool::for_each(), which is — the loop over sessions that routes a
//     publish is one — and an exception leaving on_event() there
//     terminates rather than propagating. The requirement covers every
//     event, since an observer cannot tell which path raised one.
//   * Every StrView in an Event borrows broker-owned storage and is
//     valid only for the duration of the call.
//   * Events are notifications, not a control point. Nothing the
//     observer does changes what the broker then does.
//
// Adding a new EventKind is not a breaking change: an observer switching
// on kind does not match the new value. That is why this is one
// method with a tagged struct rather than a method per event.
//
// SPDX-License-Identifier: MIT
#ifndef MINIMOSQ_BROKER_OBSERVER_HPP
#define MINIMOSQ_BROKER_OBSERVER_HPP

#include <cstddef>
#include <cstdint>

#include "../core/error.hpp"
#include "../core/span.hpp"
#include "../protocol/constants.hpp"

namespace minimosq {

enum class EventKind : uint8_t {
    // --- connection lifecycle
    connection_opened,      // ci
    connection_closed,      // ci, client_id (empty before CONNECT)
    connect_refused,        // ci, client_id, connack — CONNACK != accepted
    protocol_violation,     // ci, client_id, err — connection is being closed
    transport_send_failed,  // ci, client_id — the transport refused a write
    connect_timeout,        // ci — CONNECT did not arrive in time
    keepalive_timeout,      // ci, client_id — 1.5 x keep-alive elapsed
    idle_timeout,           // ci, client_id — Traits::max_idle_ms elapsed

    // --- session lifecycle
    session_created,     // ci, client_id
    session_resumed,     // ci, client_id — persistent session found
    session_taken_over,  // ci, client_id — second client claimed the id
    session_expired,     // client_id — Traits::session_expiry_ms elapsed
    session_evicted,     // client_id — pool full, longest-disconnected wins

    // --- authorization (the Security policy said no)
    publish_denied,    // ci, client_id, topic
    subscribe_denied,  // ci, client_id, topic (the filter)
    receive_denied,    // ci, client_id, topic

    // --- data the broker could not keep or deliver
    retained_store_failed,  // topic — store full, or too large to own
    retained_stale_purged,  // topic — an unstorable update evicted the old value
    delivery_dropped,       // client_id, topic, qos, err (oversize | capacity)
    inbound_qos2_evicted,   // ci, client_id — tracking table full, oldest id forgotten
};

inline const char* event_kind_name(EventKind k) noexcept {
    switch (k) {
    case EventKind::connection_opened:
        return "connection_opened";
    case EventKind::connection_closed:
        return "connection_closed";
    case EventKind::connect_refused:
        return "connect_refused";
    case EventKind::protocol_violation:
        return "protocol_violation";
    case EventKind::transport_send_failed:
        return "transport_send_failed";
    case EventKind::connect_timeout:
        return "connect_timeout";
    case EventKind::keepalive_timeout:
        return "keepalive_timeout";
    case EventKind::idle_timeout:
        return "idle_timeout";
    case EventKind::session_created:
        return "session_created";
    case EventKind::session_resumed:
        return "session_resumed";
    case EventKind::session_taken_over:
        return "session_taken_over";
    case EventKind::session_expired:
        return "session_expired";
    case EventKind::session_evicted:
        return "session_evicted";
    case EventKind::inbound_qos2_evicted:
        return "inbound_qos2_evicted";
    case EventKind::publish_denied:
        return "publish_denied";
    case EventKind::subscribe_denied:
        return "subscribe_denied";
    case EventKind::receive_denied:
        return "receive_denied";
    case EventKind::retained_store_failed:
        return "retained_store_failed";
    case EventKind::retained_stale_purged:
        return "retained_stale_purged";
    case EventKind::delivery_dropped:
        return "delivery_dropped";
    }
    return "unknown";
}

// A broker event. Every field beyond `kind` is optional context; which
// ones are set is listed against each EventKind above. Unset fields hold
// the defaults below, so an observer that reads one that does not apply
// gets an empty view rather than garbage.
struct Event {
    static constexpr size_t no_conn = static_cast<size_t>(-1);

    EventKind kind;
    size_t ci = no_conn;                          // connection index, or no_conn
    StrView client_id{};                          // empty when not known yet
    StrView topic{};                              // topic name or filter, when relevant
    Err err = Err::ok;                            // protocol_violation, delivery_dropped
    ConnackCode connack = ConnackCode::accepted;  // connect_refused
    QoS qos = QoS::at_most_once;                  // delivery_dropped

    explicit Event(EventKind k) noexcept : kind(k) {}
};

// The default: records nothing, costs nothing.
struct NullObserver {
    void on_event(const Event&) noexcept {}
};

}  // namespace minimosq

#endif  // MINIMOSQ_BROKER_OBSERVER_HPP
