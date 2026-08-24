// minimosq — the broker core.
//
// Broker<Traits, Transport, Security, Observer> is a single-threaded
// MQTT 3.1.1 broker. All state lives inside the object (sized by Traits
// at compile time); after construction it never allocates and never
// throws.
//
// The transport drives the broker through four entry points:
//
//   conn_open(ci, now_ms)        a new connection was accepted
//   conn_data(ci, bytes, now_ms) bytes arrived on a connection
//   conn_closed(ci)              the peer/transport closed a connection
//   tick(now_ms)                 called periodically for timeouts
//
// and the broker talks back through the Transport policy:
//
//   bool send(size_t ci, ByteSpan bytes)  queue bytes; false = fatal
//   void close(size_t ci)                 tear a connection down
//
// Contract details:
//   - Connection indices are dense in [0, Traits::max_connections).
//   - When the broker calls close(ci), the transport must free the
//     connection WITHOUT calling conn_closed(ci) back; conn_closed is
//     only for closes the broker did not initiate.
//   - send() must queue the whole span (transports buffer internally);
//     returning false means the connection is beyond saving (e.g. its
//     buffer overflowed) and makes the broker drop it.
//   - now_ms is any monotonic millisecond clock; wrap-around is fine.
//
// Reentrancy: teardown work (will publishing, transport close) is
// deferred to flush_dead() at the tail of each entry point, so nothing
// reenters the packet-build buffer while a message is being routed.
//
// Observability: every decision worth recording is reported through the
// Observer policy (see observer.hpp). The default records nothing and
// costs nothing.
//
// SPDX-License-Identifier: MIT
#ifndef MINIMOSQ_BROKER_BROKER_HPP
#define MINIMOSQ_BROKER_BROKER_HPP

#include <cstddef>
#include <cstdint>

#include "../core/error.hpp"
#include "../core/pool.hpp"
#include "../core/span.hpp"
#include "../protocol/constants.hpp"
#include "../protocol/frame.hpp"
#include "../protocol/packets.hpp"
#include "../protocol/utf8.hpp"
#include "../protocol/writer.hpp"
#include "../topic.hpp"
#include "config.hpp"
#include "observer.hpp"
#include "retained.hpp"
#include "session.hpp"

namespace minimosq {

// The security policy: authentication plus authorization. The broker
// authenticates once per CONNECT; the policy fills in a Context (any
// trivially copyable type — a role id, a permission bitmask) that is
// stored in the session and handed to every authorization check, so
// per-message checks never re-derive identity.
//
// Deny semantics (MQTT 3.1.1-conformant):
//   - authorize_publish == false  → the message is silently discarded
//     but still acknowledged (PUBACK/PUBREC); 3.1.1 has no error ack,
//     and silent drop avoids leaking topic existence [MQTT-3.3.5-2].
//     Wills pass through the same check when they fire.
//   - authorize_subscribe == false → SUBACK 0x80 for that entry.
//   - authorize_receive is checked per delivery (including retained
//     and queued messages), so a broadly-subscribed client still only
//     receives what it is cleared for.
//
// AllowAllSecurity is the default: every check passes.
struct AllowAllSecurity {
    struct Context {};

    ConnackCode authenticate(StrView client_id, const StrView* username, const ByteSpan* password,
                             Context& ctx) {
        (void)client_id;
        (void)username;
        (void)password;
        (void)ctx;
        return ConnackCode::accepted;
    }

    bool authorize_publish(const Context&, StrView topic) {
        (void)topic;
        return true;
    }

    bool authorize_subscribe(const Context&, StrView filter) {
        (void)filter;
        return true;
    }

    bool authorize_receive(const Context&, StrView topic) {
        (void)topic;
        return true;
    }
};

// ------------------------------------------------ optional trait probes
//
// The members below were added after the initial release. Detecting
// them instead of requiring them keeps existing user-written Traits
// compiling unchanged.

template <typename T, typename = void>
struct traits_max_idle_ms {
    static constexpr uint32_t value = 0;
};
template <typename T>
struct traits_max_idle_ms<T, decltype((void)T::max_idle_ms)> {
    static constexpr uint32_t value = T::max_idle_ms;
};

template <typename T, typename = void>
struct traits_session_expiry_ms {
    static constexpr uint32_t value = 0;
};
template <typename T>
struct traits_session_expiry_ms<T, decltype((void)T::session_expiry_ms)> {
    static constexpr uint32_t value = T::session_expiry_ms;
};

// A transport that publishes its connection capacity lets the broker
// check at compile time that the two agree; one that does not is
// assumed to be correctly sized (0 = "did not say").
template <typename T, typename = void>
struct transport_max_connections {
    static constexpr size_t value = 0;
};
template <typename T>
struct transport_max_connections<T, decltype((void)T::max_connections)> {
    static constexpr size_t value = T::max_connections;
};

template <typename Traits, typename Transport, typename Security = AllowAllSecurity,
          typename Observer = NullObserver>
class Broker {
    // A transport with fewer slots than the broker hands out indices for
    // is an out-of-bounds write waiting to happen, and nothing about the
    // two declarations forces them to agree — so check it here.
    static_assert(transport_max_connections<Transport>::value == 0 ||
                      transport_max_connections<Transport>::value >= Traits::max_connections,
                  "Transport has fewer connection slots than Traits::max_connections; "
                  "size the transport with Traits::max_connections");

public:
    static constexpr size_t max_connections = Traits::max_connections;

    explicit Broker(Transport& transport) noexcept : tr_(transport) {}

    Broker(const Broker&) = delete;
    Broker& operator=(const Broker&) = delete;

    Security& security() noexcept { return security_; }
    Observer& observer() noexcept { return observer_; }

    // ------------------------------------------------ transport-side API

    // A new connection was accepted by the transport.
    Err conn_open(size_t ci, uint32_t now_ms) {
        if (ci >= max_connections || conns_[ci].active) {
            return Err::state;
        }
        Conn& c = conns_[ci];
        c.reset();
        c.active = true;
        c.deadline_ms = now_ms + Traits::connect_timeout_ms;
        notify_conn(EventKind::connection_opened, ci);
        return Err::ok;
    }

    // The peer (or the transport on its own) closed the connection.
    // Counts as an abnormal disconnect: the will, if armed, is published.
    void conn_closed(size_t ci) {
        if (ci >= max_connections || !conns_[ci].active) {
            return;
        }
        conns_[ci].notify_transport = false;  // the transport already knows
        conns_[ci].dead = true;
        flush_dead();
    }

    // Bytes arrived. May contain partial or multiple packets.
    Err conn_data(size_t ci, ByteSpan data, uint32_t now_ms) {
        if (ci >= max_connections || !conns_[ci].active) {
            return Err::state;
        }
        Conn& c = conns_[ci];
        if (c.dead) {
            return Err::ok;
        }
        now_ms_ = now_ms;
        // Any traffic refreshes the keep-alive deadline [MQTT-3.1.2.10],
        // or the idle deadline when keep-alive is disabled.
        if (c.session != no_session) {
            refresh_deadline(c, now_ms);
        }
        const Err e = c.parser.feed(data, [&](uint8_t first_byte, ByteSpan body) {
            return on_packet(ci, first_byte, body);
        });
        if (e != Err::ok) {
            notify_violation(ci, e);
            c.dead = true;  // framing error: abnormal disconnect, will fires
        }
        flush_dead();
        return e;
    }

    // Drive timeouts: keep-alive expiry and CONNECT-handshake timeouts.
    void tick(uint32_t now_ms) {
        now_ms_ = now_ms;
        for (size_t i = 0; i < max_connections; ++i) {
            Conn& c = conns_[i];
            if (!c.active || c.dead) {
                continue;
            }
            const bool armed = (c.session == no_session) || c.keepalive_s > 0 || max_idle_ms > 0;
            if (armed && deadline_passed(now_ms, c.deadline_ms)) {
                if (c.session == no_session) {
                    notify_conn(EventKind::connect_timeout, i);
                } else if (c.keepalive_s > 0) {
                    notify_conn(EventKind::keepalive_timeout, i);
                } else {
                    notify_conn(EventKind::idle_timeout, i);
                }
                c.dead = true;  // abnormal: will fires [MQTT-3.1.2-24]
            }
        }
        flush_dead();
        expire_sessions(now_ms);
    }

    // ---------------------------------------------- application-side API

    // Publish a message that originates in the embedding application
    // (not from any client).
    Err publish(StrView topic, ByteSpan payload, QoS qos, bool retain) {
        if (!topic_name_valid(topic)) {
            return Err::malformed;
        }
        // 2-byte topic length prefix, the topic, the packet identifier
        // that QoS > 0 adds, and the payload.
        const size_t id_len = (qos == QoS::at_most_once) ? 0u : 2u;
        if (2 + topic.len + id_len + payload.len > out_size - packet_overhead) {
            return Err::oversize;  // could never be built for any subscriber
        }
        Err result = Err::ok;
        if (retain && !apply_retain(topic, payload, qos)) {
            result = Err::capacity;  // delivery still happens below
        }
        route_publish(topic, payload, qos);
        flush_dead();
        return result;
    }

    size_t retained_count() const noexcept { return retained_.size(); }

private:
    static constexpr uint16_t no_session = 0xFFFF;
    using SessionT = Session<Traits, typename Security::Context>;

    struct Conn {
        FrameParser<Traits::max_packet_size> parser;
        uint32_t deadline_ms = 0;
        uint16_t session = no_session;
        uint16_t keepalive_s = 0;
        bool active = false;
        bool dead = false;             // scheduled for teardown in flush_dead()
        bool notify_transport = true;  // call Transport::close() on teardown

        void reset() noexcept {
            parser.reset();
            deadline_ms = 0;
            session = no_session;
            keepalive_s = 0;
            active = false;
            dead = false;
            notify_transport = true;
        }
    };

    // ---------------------------------------------------------- helpers

    static constexpr uint32_t max_idle_ms = traits_max_idle_ms<Traits>::value;
    static constexpr uint32_t session_expiry_ms = traits_session_expiry_ms<Traits>::value;

    // ---------------------------------------------------- observability
    //
    // One helper per shape of event, so call sites stay one line and the
    // Event stays a local the optimizer can fold away entirely when the
    // Observer's on_event() is empty.

    void notify(EventKind kind) {
        Event e{kind};
        observer_.on_event(e);
    }

    // A connection-scoped event; picks up the client id when the
    // connection has got as far as having a session.
    void notify_conn(EventKind kind, size_t ci) {
        Event e{kind};
        e.ci = ci;
        if (const SessionT* s = session_of(conns_[ci])) {
            e.client_id = s->client_id.view();
        }
        observer_.on_event(e);
    }

    // Mark a connection dead because of a protocol error, reporting it
    // first. Every close the broker initiates for a peer's mistake goes
    // through here, so an observer sees them all.
    void violation(size_t ci, Err err) {
        notify_violation(ci, err);
        conns_[ci].dead = true;
    }

    void notify_violation(size_t ci, Err err) {
        Event e{EventKind::protocol_violation};
        e.ci = ci;
        e.err = err;
        if (const SessionT* s = session_of(conns_[ci])) {
            e.client_id = s->client_id.view();
        }
        observer_.on_event(e);
    }

    void notify_refused(size_t ci, StrView client_id, ConnackCode code) {
        Event e{EventKind::connect_refused};
        e.ci = ci;
        e.client_id = client_id;
        e.connack = code;
        observer_.on_event(e);
    }

    void notify_session(EventKind kind, const SessionT& s) {
        Event e{kind};
        e.client_id = s.client_id.view();
        if (s.connected()) {
            e.ci = s.conn;
        }
        observer_.on_event(e);
    }

    void notify_denied(EventKind kind, const SessionT& s, StrView topic) {
        Event e{kind};
        e.client_id = s.client_id.view();
        e.topic = topic;
        if (s.connected()) {
            e.ci = s.conn;
        }
        observer_.on_event(e);
    }

    void notify_topic(EventKind kind, StrView topic) {
        Event e{kind};
        e.topic = topic;
        observer_.on_event(e);
    }

    // A QoS>0 delivery the broker accepted responsibility for and then
    // could not make: err is oversize (too large to own) or capacity
    // (the session's queue is full).
    void notify_drop(const SessionT& s, StrView topic, QoS qos, Err err) {
        Event e{EventKind::delivery_dropped};
        e.client_id = s.client_id.view();
        e.topic = topic;
        e.qos = qos;
        e.err = err;
        if (s.connected()) {
            e.ci = s.conn;
        }
        observer_.on_event(e);
    }

    static constexpr uint32_t keepalive_window_ms(uint16_t keepalive_s) noexcept {
        // The server must allow one and a half keep-alive periods
        // [MQTT-3.1.2-24].
        return static_cast<uint32_t>(keepalive_s) * 1500u;
    }

    // Deadline for a connected session: the keep-alive window, or the
    // optional idle timeout when the client asked for no keep-alive.
    static void refresh_deadline(Conn& c, uint32_t now_ms) noexcept {
        if (c.keepalive_s > 0) {
            c.deadline_ms = now_ms + keepalive_window_ms(c.keepalive_s);
        } else if (max_idle_ms > 0) {
            c.deadline_ms = now_ms + max_idle_ms;
        }
    }

    static bool deadline_passed(uint32_t now, uint32_t deadline) noexcept {
        return static_cast<int32_t>(now - deadline) >= 0;
    }

    static QoS qos_min(QoS a, QoS b) noexcept { return a < b ? a : b; }
    static QoS qos_max(QoS a, QoS b) noexcept { return a > b ? a : b; }

    // Server-assigned client ids: "mmq-<n>", unique among live sessions.
    static constexpr size_t auto_id_len_max = 4 + 5;  // "mmq-" + up to 5 digits

    StrView generate_client_id(char* buf) noexcept {
        while (true) {
            ++auto_id_counter_;  // uint16 wrap is fine: uniqueness is checked
            size_t n = 0;
            buf[n++] = 'm';
            buf[n++] = 'm';
            buf[n++] = 'q';
            buf[n++] = '-';
            char digits[5];
            size_t d = 0;
            uint16_t v = auto_id_counter_;
            do {
                digits[d++] = static_cast<char>('0' + v % 10);
                v = static_cast<uint16_t>(v / 10);
            } while (v != 0);
            while (d > 0) {
                buf[n++] = digits[--d];
            }
            const StrView id{buf, n};
            if (sessions_.find([&](SessionT& s) { return s.client_id.equals(id); }) == nullptr) {
                return id;
            }
        }
    }

    SessionT* session_of(const Conn& c) noexcept {
        return c.session != no_session ? sessions_.at(c.session) : nullptr;
    }

    void send_to(size_t ci, ByteSpan pkt) {
        Conn& c = conns_[ci];
        if (!c.active || c.dead || pkt.empty()) {
            return;
        }
        if (!tr_.send(ci, pkt)) {
            notify_conn(EventKind::transport_send_failed, ci);
            c.dead = true;  // abnormal disconnect: will fires
        }
    }

    // ------------------------------------------------- deferred teardown
    //
    // Dropping a connection can publish a will, which routes a message,
    // which can drop further connections. To keep that iterative (and to
    // never reenter out_ while routing), drops only set the `dead` flag;
    // flush_dead() runs the actual teardown after the main work is done.

    void flush_dead() {
        bool again = true;
        while (again) {
            again = false;
            for (size_t i = 0; i < max_connections; ++i) {
                if (conns_[i].active && conns_[i].dead) {
                    teardown(i);
                    again = true;  // teardown may have marked others dead
                }
            }
        }
    }

    // ------------------------------------------------- session lifetime
    //
    // MQTT 3.1.1 has no session expiry: a clean-session=0 session is
    // meant to live until its client returns. Taken literally that lets
    // a client fill max_sessions with sessions nothing will ever come
    // back for, leaving no connection to reclaim and every later client
    // refused. The two mechanisms below bound that. The timer is the
    // policy; the eviction is the guarantee that a full pool never means
    // a refused client.

    void expire_sessions(uint32_t now_ms) {
        if (session_expiry_ms == 0) {
            return;
        }
        sessions_.for_each([&](SessionT& s) {
            if (s.connected()) {
                return;
            }
            if (deadline_passed(now_ms, s.disconnect_ms + session_expiry_ms)) {
                notify_session(EventKind::session_expired, s);
                sessions_.release(&s);  // releasing during for_each is safe
            }
        });
    }

    // The disconnected session that has been gone longest, or nullptr if
    // every session currently has a connection.
    SessionT* oldest_disconnected_session() noexcept {
        SessionT* oldest = nullptr;
        sessions_.for_each([&](SessionT& s) {
            if (s.connected()) {
                return;
            }
            if (oldest == nullptr ||
                static_cast<int32_t>(s.disconnect_order - oldest->disconnect_order) < 0) {
                oldest = &s;
            }
        });
        return oldest;
    }

    void teardown(size_t ci) {
        Conn& c = conns_[ci];
        SessionT* s = session_of(c);
        const bool notify = c.notify_transport;
        notify_conn(EventKind::connection_closed, ci);

        // Detach first: nothing published below may reach this connection.
        c.active = false;
        c.dead = false;
        c.session = no_session;

        if (s != nullptr) {
            s->conn = SessionT::no_conn;
            // Stamped even for clean sessions (released just below) so
            // there is one place that records "this session lost its
            // connection at T".
            s->disconnect_ms = now_ms_;
            s->disconnect_order = ++disconnect_order_;
            if (s->has_will) {
                // Publish the will exactly like a client PUBLISH
                // [MQTT-3.1.2-8]: same authorization, retained if
                // requested, routed to matching subscribers.
                s->has_will = false;
                if (security_.authorize_publish(s->auth_ctx, s->will_topic.view())) {
                    if (s->will_retain) {
                        apply_retain(s->will_topic.view(), s->will_payload.view(), s->will_qos);
                    }
                    route_publish(s->will_topic.view(), s->will_payload.view(), s->will_qos);
                }
                // route_publish may release s only via other sessions'
                // teardown paths, never s itself (s is disconnected), so
                // using s afterwards is safe.
            }
            if (s->clean_session) {
                sessions_.release(s);
            }
        }

        if (notify) {
            tr_.close(ci);
        }
    }

    // ------------------------------------------------------ publishing

    // Store/remove a retained message; best-effort, see RetainedStore.
    bool apply_retain(StrView topic, ByteSpan payload, QoS qos) {
        if (payload.empty()) {
            retained_.remove(topic);  // [MQTT-3.3.1-10]
            return true;
        }
        return retained_.set(topic, payload, qos);
    }

    // Deliver a message to every matching subscriber. Each session gets
    // the message once, at min(publish QoS, max granted QoS over its
    // matching subscriptions) [MQTT-3.3.5]. QoS 0 is sent straight
    // through; QoS 1/2 goes via the session's pending queue (which also
    // covers offline persistent sessions). Packets are built per
    // subscriber for simplicity — out_ is never held across a send.
    void route_publish(StrView topic, ByteSpan payload, QoS qos) {
        sessions_.for_each([&](SessionT& s) {
            bool matched = false;
            QoS granted_max = QoS::at_most_once;
            for (const typename SessionT::Subscription& sub : s.subs) {
                if (topic_matches(sub.filter.view(), topic)) {
                    matched = true;
                    granted_max = qos_max(granted_max, sub.granted);
                }
            }
            if (!matched) {
                return;
            }
            if (!security_.authorize_receive(s.auth_ctx, topic)) {
                notify_denied(EventKind::receive_denied, s, topic);
                return;  // this subscriber is not cleared for the topic
            }
            const bool online = s.connected() && !conns_[s.conn].dead;
            const QoS eff = qos_min(qos, granted_max);
            if (eff == QoS::at_most_once) {
                if (online) {  // QoS 0 is not queued for offline sessions
                    send_to(s.conn, build_publish(out_, sizeof out_, topic, payload,
                                                  QoS::at_most_once, false, false, 0));
                }
            } else if (online || !s.clean_session) {
                enqueue(s, topic, payload, eff, /*retain=*/false);
            }
        });
    }

    // Append a QoS 1/2 delivery to a session's queue and, if the client
    // is online, put it on the wire.
    void enqueue(SessionT& s, StrView topic, ByteSpan payload, QoS eff, bool retain) {
        if (topic.len > Traits::max_topic_len || payload.len > Traits::max_payload_len) {
            // Documented policy: too large for owned storage — this
            // subscriber is skipped. Size max_payload_len >=
            // max_packet_size to rule this out entirely.
            notify_drop(s, topic, eff, Err::oversize);
            return;
        }
        typename SessionT::OutMsg* m = s.pending.emplace_back();
        if (m == nullptr) {
            // Queue full: the newest message is dropped (documented).
            notify_drop(s, topic, eff, Err::capacity);
            return;
        }
        m->topic.assign(topic);
        m->payload.assign(payload);
        m->qos = eff;
        m->retain = retain;
        if (s.connected() && !conns_[s.conn].dead) {
            pump_session(s);
        }
    }

    // Send every not-yet-sent queued entry of a connected session.
    void pump_session(SessionT& s) {
        for (size_t i = 0; i < s.pending.size(); ++i) {
            if (conns_[s.conn].dead) {
                return;
            }
            typename SessionT::OutMsg& m = s.pending[i];
            if (m.state != OutState::queued) {
                continue;
            }
            m.packet_id = s.alloc_packet_id();
            m.state = (m.qos == QoS::at_least_once) ? OutState::awaiting_puback
                                                    : OutState::awaiting_pubrec;
            send_to(s.conn, build_publish(out_, sizeof out_, m.topic.view(), m.payload.view(),
                                          m.qos, m.retain, m.dup, m.packet_id));
        }
    }

    // On reconnect of a persistent session: retransmit in-flight
    // messages with DUP=1 and unacknowledged PUBRELs, then flush the
    // offline queue — in original order [MQTT-4.4.0-1, MQTT-4.6].
    void resume_session(SessionT& s) {
        for (size_t i = 0; i < s.pending.size(); ++i) {
            if (conns_[s.conn].dead) {
                return;
            }
            typename SessionT::OutMsg& m = s.pending[i];
            switch (m.state) {
            case OutState::queued:
                m.packet_id = s.alloc_packet_id();
                m.state = (m.qos == QoS::at_least_once) ? OutState::awaiting_puback
                                                        : OutState::awaiting_pubrec;
                break;
            case OutState::awaiting_puback:
            case OutState::awaiting_pubrec:
                m.dup = true;
                break;
            case OutState::awaiting_pubcomp:
                send_to(s.conn,
                        build_packet_id_only(out_, sizeof out_, PacketType::pubrel, m.packet_id));
                continue;
            }
            send_to(s.conn, build_publish(out_, sizeof out_, m.topic.view(), m.payload.view(),
                                          m.qos, m.retain, m.dup, m.packet_id));
        }
    }

    // ------------------------------------------------- packet dispatch

    // Returns false to make the frame parser stop feeding us (the
    // connection is being torn down).
    bool on_packet(size_t ci, uint8_t first_byte, ByteSpan body) {
        const Conn& c = conns_[ci];
        const PacketType type = packet_type(first_byte);

        if (!fixed_flags_valid(type, packet_flags(first_byte))) {
            violation(ci, Err::malformed);  // [MQTT-2.2.2-2]
            return false;
        }
        if (c.session == no_session && type != PacketType::connect) {
            violation(ci, Err::state);  // first packet must be CONNECT [MQTT-3.1.0-1]
            return false;
        }

        switch (type) {
        case PacketType::connect:
            handle_connect(ci, body);
            break;
        case PacketType::publish:
            handle_publish(ci, first_byte, body);
            break;
        case PacketType::pubrel:
            handle_pubrel(ci, body);
            break;
        case PacketType::puback:
            handle_puback(ci, body);
            break;
        case PacketType::pubrec:
            handle_pubrec(ci, body);
            break;
        case PacketType::pubcomp:
            handle_pubcomp(ci, body);
            break;
        case PacketType::subscribe:
            handle_subscribe(ci, body);
            break;
        case PacketType::unsubscribe:
            handle_unsubscribe(ci, body);
            break;
        case PacketType::pingreq:
            if (!body.empty()) {
                violation(ci, Err::malformed);
            } else {
                send_to(ci, build_pingresp(out_, sizeof out_));
            }
            break;
        case PacketType::disconnect:
            handle_disconnect(ci, body);
            break;
        default:
            // CONNACK/SUBACK/UNSUBACK/PINGRESP (server-to-client only)
            // or reserved types: protocol violation.
            violation(ci, Err::malformed);
            break;
        }
        return !conns_[ci].dead;
    }

    // ------------------------------------------------------- handlers

    // Send a CONNACK refusal and drop the connection. The client id is
    // passed in because the connection has no session yet, so there is
    // nowhere else for the observer to learn who was turned away.
    void refuse(size_t ci, ConnackCode code, StrView client_id = StrView{}) {
        notify_refused(ci, client_id, code);
        send_to(ci, build_connack(out_, sizeof out_, false, code));
        conns_[ci].dead = true;
    }

    void handle_connect(size_t ci, ByteSpan body) {
        Conn& c = conns_[ci];
        if (c.session != no_session) {
            violation(ci, Err::state);  // a second CONNECT [MQTT-3.1.0-2]
            return;
        }

        ConnectPacket p;
        if (parse_connect(body, p) != Err::ok) {
            notify_violation(ci, Err::malformed);
            c.dead = true;
            return;
        }
        if (!p.protocol_name_ok) {
            notify_violation(ci, Err::malformed);
            c.dead = true;  // close without CONNACK [MQTT-3.1.2-1]
            return;
        }
        if (p.protocol_level != protocol_level_311) {
            refuse(ci, ConnackCode::unacceptable_protocol);  // [MQTT-3.1.2-2]
            return;
        }
        // Zero-byte client id: assign one for clean sessions (common
        // client default, [MQTT-3.1.3-6/-7]); reject for persistent
        // sessions as the spec requires [MQTT-3.1.3-8].
        char auto_id_buf[auto_id_len_max];
        StrView client_id = p.client_id;
        if (client_id.empty()) {
            if (!p.clean_session) {
                refuse(ci, ConnackCode::identifier_rejected, client_id);
                return;
            }
            client_id = generate_client_id(auto_id_buf);
        }
        if (client_id.len > Traits::max_client_id_len) {
            refuse(ci, ConnackCode::identifier_rejected, client_id);
            return;
        }
        // Ill-formed UTF-8 anywhere requires closing the connection
        // [MQTT-1.5.3-1/-2]. (Passwords are binary data.)
        if (!utf8_valid(client_id) || (p.has_username && !utf8_valid(p.username))) {
            notify_violation(ci, Err::malformed);
            c.dead = true;
            return;
        }
        if (p.has_will) {
            if (!topic_name_valid(p.will_topic)) {
                notify_violation(ci, Err::malformed);
                c.dead = true;  // will topic must be a valid name [MQTT-3.1.3.1]
                return;
            }
            if (p.will_topic.len > Traits::max_topic_len ||
                p.will_payload.len > Traits::max_payload_len) {
                refuse(ci, ConnackCode::server_unavailable, client_id);  // capacity policy
                return;
            }
        }
        typename Security::Context auth_ctx{};
        const ConnackCode ac =
            security_.authenticate(client_id, p.has_username ? &p.username : nullptr,
                                   p.has_password ? &p.password : nullptr, auth_ctx);
        if (ac != ConnackCode::accepted) {
            refuse(ci, ac, client_id);
            return;
        }

        SessionT* existing =
            sessions_.find([&](SessionT& s) { return s.client_id.equals(client_id); });

        // Session takeover: an existing connection with this client id is
        // dropped like a network failure (its will fires) [MQTT-3.1.4-2].
        if (existing != nullptr && existing->connected()) {
            notify_session(EventKind::session_taken_over, *existing);
            conns_[existing->conn].dead = true;
            flush_dead();
            existing = sessions_.find([&](SessionT& s) { return s.client_id.equals(client_id); });
        }

        bool session_present = false;
        if (p.clean_session) {
            if (existing != nullptr) {
                sessions_.release(existing);  // [MQTT-3.1.2-6]
                existing = nullptr;
            }
        } else if (existing != nullptr) {
            session_present = true;  // [MQTT-3.2.2-2]
        }

        SessionT* s = existing;
        if (s == nullptr) {
            s = sessions_.alloc();
            if (s == nullptr) {
                // The pool is full. Every session in it that still has a
                // connection is in use, but a disconnected persistent
                // session is only a promise to a client that may never
                // come back — and MQTT 3.1.1 gives it no expiry, so
                // without this the first max_sessions clients to
                // disconnect lock the broker shut. Break the oldest such
                // promise rather than refuse the client in front of us.
                if (SessionT* victim = oldest_disconnected_session()) {
                    notify_session(EventKind::session_evicted, *victim);
                    sessions_.release(victim);
                    s = sessions_.alloc();
                }
            }
            if (s == nullptr) {
                refuse(ci, ConnackCode::server_unavailable, client_id);
                return;
            }
            s->client_id.assign(client_id);
        }

        s->clean_session = p.clean_session;
        s->conn = static_cast<uint16_t>(ci);
        s->auth_ctx = auth_ctx;  // re-authenticated on every connect
        s->has_will = p.has_will;
        if (p.has_will) {
            s->will_topic.assign(p.will_topic);
            s->will_payload.assign(p.will_payload);
            s->will_qos = p.will_qos;
            s->will_retain = p.will_retain;
        }

        c.session = static_cast<uint16_t>(sessions_.index_of(s));
        c.keepalive_s = p.keepalive_s;
        refresh_deadline(c, now_ms_);

        notify_session(session_present ? EventKind::session_resumed : EventKind::session_created,
                       *s);
        send_to(ci, build_connack(out_, sizeof out_, session_present, ConnackCode::accepted));

        // Resumed persistent session: retransmit in-flight deliveries
        // and flush anything queued while the client was away.
        if (session_present) {
            resume_session(*s);
        }
    }

    void handle_publish(size_t ci, uint8_t first_byte, ByteSpan body) {
        Conn& c = conns_[ci];
        SessionT& s = *session_of(c);

        PublishPacket p;
        if (parse_publish(first_byte, body, p) != Err::ok || !topic_name_valid(p.topic)) {
            notify_violation(ci, Err::malformed);
            c.dead = true;  // [MQTT-3.3.2-2]
            return;
        }

        bool deliver = true;
        if (p.qos == QoS::exactly_once) {
            if (s.has_inbound_qos2(p.packet_id)) {
                deliver = false;  // redelivery of an unreleased id: already routed
            } else if (s.inbound_qos2.full()) {
                // Documented capacity policy: we cannot track another id
                // without risking duplicate delivery, so drop the client.
                violation(ci, Err::capacity);
                return;
            } else {
                s.inbound_qos2.push_back(p.packet_id);
            }
        }

        // Unauthorized publishes are silently discarded but still
        // acknowledged below — 3.1.1 has no error ack, and silence
        // avoids leaking topic existence [MQTT-3.3.5-2]. The QoS 2 id
        // bookkeeping above is protocol state and happens regardless.
        if (deliver && !security_.authorize_publish(s.auth_ctx, p.topic)) {
            notify_denied(EventKind::publish_denied, s, p.topic);
        } else if (deliver) {
            if (p.retain) {
                // Best-effort store [MQTT-3.3.1-5]; forwarded to current
                // subscribers with retain=0 either way [MQTT-3.3.1-9].
                apply_retain(p.topic, p.payload, p.qos);
            }
            route_publish(p.topic, p.payload, p.qos);
        }

        if (p.qos == QoS::at_least_once) {
            send_to(ci, build_packet_id_only(out_, sizeof out_, PacketType::puback, p.packet_id));
        } else if (p.qos == QoS::exactly_once) {
            send_to(ci, build_packet_id_only(out_, sizeof out_, PacketType::pubrec, p.packet_id));
        }
    }

    // Client acknowledged a QoS 1 delivery: the message is done.
    void handle_puback(size_t ci, ByteSpan body) {
        const Conn& c = conns_[ci];
        uint16_t id = 0;
        if (parse_packet_id_only(body, id) != Err::ok) {
            violation(ci, Err::malformed);
            return;
        }
        SessionT& s = *session_of(c);
        size_t index = 0;
        if (s.find_pending(id, OutState::awaiting_puback, OutState::awaiting_puback, &index) !=
            nullptr) {
            s.pending.remove_ordered(index);
        }
        // Unknown ids are ignored (late/duplicate acks are harmless).
    }

    // Client received a QoS 2 delivery: release it with PUBREL. A
    // duplicate PUBREC (entry already awaiting PUBCOMP) repeats the
    // PUBREL [MQTT-4.3.3].
    void handle_pubrec(size_t ci, ByteSpan body) {
        const Conn& c = conns_[ci];
        uint16_t id = 0;
        if (parse_packet_id_only(body, id) != Err::ok) {
            violation(ci, Err::malformed);
            return;
        }
        SessionT& s = *session_of(c);
        typename SessionT::OutMsg* m =
            s.find_pending(id, OutState::awaiting_pubrec, OutState::awaiting_pubcomp, nullptr);
        if (m == nullptr) {
            return;
        }
        m->state = OutState::awaiting_pubcomp;
        send_to(ci, build_packet_id_only(out_, sizeof out_, PacketType::pubrel, id));
    }

    // Client completed a QoS 2 delivery.
    void handle_pubcomp(size_t ci, ByteSpan body) {
        const Conn& c = conns_[ci];
        uint16_t id = 0;
        if (parse_packet_id_only(body, id) != Err::ok) {
            violation(ci, Err::malformed);
            return;
        }
        SessionT& s = *session_of(c);
        size_t index = 0;
        if (s.find_pending(id, OutState::awaiting_pubcomp, OutState::awaiting_pubcomp, &index) !=
            nullptr) {
            s.pending.remove_ordered(index);
        }
    }

    void handle_pubrel(size_t ci, ByteSpan body) {
        const Conn& c = conns_[ci];
        uint16_t id = 0;
        if (parse_packet_id_only(body, id) != Err::ok) {
            violation(ci, Err::malformed);
            return;
        }
        session_of(c)->remove_inbound_qos2(id);
        // PUBCOMP is always the answer, known id or not [MQTT-3.6.4-1].
        send_to(ci, build_packet_id_only(out_, sizeof out_, PacketType::pubcomp, id));
    }

    // SUBSCRIBE is handled in three passes so that a packet which turns
    // out to be a protocol error has no effect at all, and so that
    // retained replay follows the grants this packet actually made
    // rather than being re-derived from the subscription table.
    void handle_subscribe(size_t ci, ByteSpan body) {
        Conn& c = conns_[ci];
        SessionT& s = *session_of(c);

        // Pass 1: validate every entry before touching session state.
        // A malformed filter anywhere means the whole packet is a
        // protocol error [MQTT-4.8], so nothing may have been applied.
        {
            TopicListParser check{body, /*with_qos=*/true};
            StrView filter;
            QoS requested = QoS::at_most_once;
            while (check.next(filter, requested)) {
                if (!topic_filter_valid(filter)) {
                    notify_violation(ci, Err::malformed);
                    c.dead = true;  // ill-formed filter [MQTT-4.7.3-1, -1.5.3-1]
                    return;
                }
            }
            if (check.status() != Err::ok) {
                notify_violation(ci, check.status());
                c.dead = true;
                return;
            }
        }

        // Pass 2: apply subscriptions, streaming the SUBACK return codes
        // straight into the outgoing packet buffer. Every entry is known
        // to be syntactically valid by now, so this pass cannot bail out.
        for (typename SessionT::Subscription& sub : s.subs) {
            sub.retain_pending = false;  // stale flags from an earlier packet
        }
        TopicListParser entries{body, /*with_qos=*/true};
        Writer w{out_ + packet_overhead, sizeof out_ - packet_overhead};
        w.u16(entries.packet_id());

        StrView filter;
        QoS requested = QoS::at_most_once;
        while (entries.next(filter, requested)) {
            if (!security_.authorize_subscribe(s.auth_ctx, filter)) {
                notify_denied(EventKind::subscribe_denied, s, filter);
                w.u8(suback_failure);  // authorization refusal [MQTT-3.8.4-5]
                continue;
            }
            typename SessionT::Subscription* sub = nullptr;
            w.u8(subscribe_one(s, filter, requested, &sub));
            if (sub != nullptr) {
                // Marks the grant for pass 3. A filter repeated inside
                // one SUBSCRIBE resolves to the same Subscription, so
                // its retained messages are still replayed only once.
                sub->retain_pending = true;
            }
        }
        if (!w.ok()) {
            notify_violation(ci, Err::oversize);
            c.dead = true;  // SUBACK does not fit: cannot answer, so close
            return;
        }
        send_to(ci, frame_packet(out_, make_first_byte(PacketType::suback, 0), w.size()));

        // Pass 3: deliver retained messages for the entries this packet
        // granted [MQTT-3.3.1-6]. Runs after the SUBACK is on the wire.
        // Driven off the session's own table rather than the packet, so
        // a subscription that merely already existed — and was refused
        // this time round — replays nothing.
        for (typename SessionT::Subscription& sub : s.subs) {
            if (!sub.retain_pending) {
                continue;
            }
            sub.retain_pending = false;
            retained_.for_each_match(
                sub.filter.view(), [&](typename RetainedStore<Traits>::Entry& e) {
                    if (!security_.authorize_receive(s.auth_ctx, e.topic.view())) {
                        notify_denied(EventKind::receive_denied, s, e.topic.view());
                        return;
                    }
                    // Retained delivery at min(granted, stored QoS), with
                    // the retain flag set [MQTT-3.3.1-8].
                    const QoS eff = qos_min(sub.granted, e.qos);
                    if (eff == QoS::at_most_once) {
                        send_to(ci, build_publish(out_, sizeof out_, e.topic.view(),
                                                  e.payload.view(), QoS::at_most_once,
                                                  /*retain=*/true, false, 0));
                    } else {
                        enqueue(s, e.topic.view(), e.payload.view(), eff, /*retain=*/true);
                    }
                });
        }
    }

    // Apply a single (syntactically valid) subscription request;
    // returns the SUBACK code — 0x80 for capacity refusals. On success
    // *out_sub points at the resulting subscription, otherwise nullptr.
    uint8_t subscribe_one(SessionT& s, StrView filter, QoS requested,
                          typename SessionT::Subscription** out_sub) {
        *out_sub = nullptr;
        if (filter.len > Traits::max_topic_len) {
            return suback_failure;
        }
        typename SessionT::Subscription* sub = s.find_sub(filter);
        if (sub == nullptr) {
            sub = s.subs.emplace_back();
            if (sub == nullptr) {
                return suback_failure;  // subscription table full
            }
            sub->filter.assign(filter);
        }
        sub->granted = requested;  // full requested QoS is supported
        *out_sub = sub;
        return static_cast<uint8_t>(sub->granted);
    }

    void handle_unsubscribe(size_t ci, ByteSpan body) {
        const Conn& c = conns_[ci];
        SessionT& s = *session_of(c);

        // Validate the whole packet before removing anything, so an
        // UNSUBSCRIBE that is a protocol error has no partial effect.
        {
            TopicListParser check{body, /*with_qos=*/false};
            StrView filter;
            QoS ignored = QoS::at_most_once;
            while (check.next(filter, ignored)) {
                if (!topic_filter_valid(filter)) {
                    violation(ci, Err::malformed);  // ill-formed filter [MQTT-4.7.3-1]
                    return;
                }
            }
            if (check.status() != Err::ok) {
                violation(ci, check.status());
                return;
            }
        }

        TopicListParser entries{body, /*with_qos=*/false};
        StrView filter;
        QoS ignored = QoS::at_most_once;
        while (entries.next(filter, ignored)) {
            for (size_t i = 0; i < s.subs.size(); ++i) {
                if (s.subs[i].filter.equals(filter)) {
                    s.subs.remove_ordered(i);  // exact match only [MQTT-3.10.4]
                    break;
                }
            }
        }
        send_to(ci,
                build_packet_id_only(out_, sizeof out_, PacketType::unsuback, entries.packet_id()));
    }

    void handle_disconnect(size_t ci, ByteSpan body) {
        Conn& c = conns_[ci];
        if (!body.empty()) {
            violation(ci, Err::malformed);
            return;
        }
        session_of(c)->has_will = false;  // clean close discards the will [MQTT-3.14.4-3]
        c.dead = true;
    }

    // -------------------------------------------------------- storage

    // The outgoing packet build buffer must hold either a forwarded
    // inbound packet (bounded by max_packet_size) or a packet built from
    // stored parts (topic + payload + packet id).
    static constexpr size_t stored_body_max =
        2 + Traits::max_topic_len + 2 + Traits::max_payload_len;
    static constexpr size_t out_size =
        packet_overhead +
        (Traits::max_packet_size > stored_body_max ? Traits::max_packet_size : stored_body_max);

    Transport& tr_;
    Security security_{};
    Observer observer_{};
    Conn conns_[max_connections];
    Pool<SessionT, Traits::max_sessions> sessions_;
    RetainedStore<Traits> retained_;
    uint8_t out_[out_size];
    uint32_t now_ms_ = 0;
    // Monotonic ticket stamped on each disconnect, so "gone longest" is
    // a total order independent of the clock.
    uint32_t disconnect_order_ = 0;
    uint16_t auto_id_counter_ = 0;
};

}  // namespace minimosq

#endif  // MINIMOSQ_BROKER_BROKER_HPP
