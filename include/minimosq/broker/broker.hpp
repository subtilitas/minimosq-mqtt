// minimosq — the broker core.
//
// Broker<Traits, Transport, Auth> is a single-threaded MQTT 3.1.1
// broker. All state lives inside the object (sized by Traits at compile
// time); after construction it never allocates and never throws.
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
// SPDX-License-Identifier: MIT
#ifndef MINIMOSQ_BROKER_BROKER_HPP
#define MINIMOSQ_BROKER_BROKER_HPP

#include <cstddef>
#include <cstdint>

#include "../core/error.hpp"
#include "../core/span.hpp"
#include "../protocol/constants.hpp"
#include "../protocol/frame.hpp"
#include "../protocol/packets.hpp"
#include "../protocol/utf8.hpp"
#include "../protocol/writer.hpp"
#include "../topic.hpp"
#include "config.hpp"
#include "retained.hpp"
#include "session.hpp"

namespace minimosq {

// Default authenticator: accept everyone. Provide your own policy with
// the same signature to check credentials; return bad_credentials or
// not_authorized to refuse.
struct AllowAllAuth {
    ConnackCode check(StrView client_id, const StrView* username, const ByteSpan* password) {
        (void)client_id;
        (void)username;
        (void)password;
        return ConnackCode::accepted;
    }
};

template <typename Traits, typename Transport, typename Auth = AllowAllAuth>
class Broker {
public:
    static constexpr size_t max_connections = Traits::max_connections;

    explicit Broker(Transport& transport) noexcept : tr_(transport) {}

    Broker(const Broker&) = delete;
    Broker& operator=(const Broker&) = delete;

    Auth& auth() noexcept { return auth_; }

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
        // Any traffic refreshes the keep-alive deadline [MQTT-3.1.2.10].
        if (c.session != no_session && c.keepalive_s > 0) {
            c.deadline_ms = now_ms + keepalive_window_ms(c.keepalive_s);
        }
        const Err e = c.parser.feed(
            data, [&](uint8_t first_byte, ByteSpan body) { return on_packet(ci, first_byte, body); });
        if (e != Err::ok) {
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
            const bool armed = (c.session == no_session) || c.keepalive_s > 0;
            if (armed && deadline_passed(now_ms, c.deadline_ms)) {
                c.dead = true;  // abnormal: will fires [MQTT-3.1.2-24]
            }
        }
        flush_dead();
    }

    // ---------------------------------------------- application-side API

    // Publish a message that originates in the embedding application
    // (not from any client).
    Err publish(StrView topic, ByteSpan payload, QoS qos, bool retain) {
        if (!topic_name_valid(topic)) {
            return Err::malformed;
        }
        if (2 + topic.len + payload.len > out_size - packet_overhead) {
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
    using SessionT = Session<Traits>;

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

    static constexpr uint32_t keepalive_window_ms(uint16_t keepalive_s) noexcept {
        // The server must allow one and a half keep-alive periods
        // [MQTT-3.1.2-24].
        return static_cast<uint32_t>(keepalive_s) * 1500u;
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

    void teardown(size_t ci) {
        Conn& c = conns_[ci];
        SessionT* s = session_of(c);
        const bool notify = c.notify_transport;

        // Detach first: nothing published below may reach this connection.
        c.active = false;
        c.dead = false;
        c.session = no_session;

        if (s != nullptr) {
            s->conn = SessionT::no_conn;
            if (s->has_will) {
                // Publish the will exactly like a client PUBLISH
                // [MQTT-3.1.2-8]: retained if requested, routed to
                // matching subscribers.
                s->has_will = false;
                if (s->will_retain) {
                    apply_retain(s->will_topic.view(), s->will_payload.view(), s->will_qos);
                }
                route_publish(s->will_topic.view(), s->will_payload.view(), s->will_qos);
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
            return;
        }
        typename SessionT::OutMsg* m = s.pending.emplace_back();
        if (m == nullptr) {
            return;  // queue full: the newest message is dropped (documented)
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
        Conn& c = conns_[ci];
        const PacketType type = packet_type(first_byte);

        if (!fixed_flags_valid(type, packet_flags(first_byte))) {
            c.dead = true;  // [MQTT-2.2.2-2]
            return false;
        }
        if (c.session == no_session && type != PacketType::connect) {
            c.dead = true;  // first packet must be CONNECT [MQTT-3.1.0-1]
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
                c.dead = true;
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
            c.dead = true;
            break;
        }
        return !conns_[ci].dead;
    }

    // ------------------------------------------------------- handlers

    // Send a CONNACK refusal and drop the connection.
    void refuse(size_t ci, ConnackCode code) {
        send_to(ci, build_connack(out_, sizeof out_, false, code));
        conns_[ci].dead = true;
    }

    void handle_connect(size_t ci, ByteSpan body) {
        Conn& c = conns_[ci];
        if (c.session != no_session) {
            c.dead = true;  // a second CONNECT is a violation [MQTT-3.1.0-2]
            return;
        }

        ConnectPacket p;
        if (parse_connect(body, p) != Err::ok) {
            c.dead = true;
            return;
        }
        if (!p.protocol_name_ok) {
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
                refuse(ci, ConnackCode::identifier_rejected);
                return;
            }
            client_id = generate_client_id(auto_id_buf);
        }
        if (client_id.len > Traits::max_client_id_len) {
            refuse(ci, ConnackCode::identifier_rejected);
            return;
        }
        // Ill-formed UTF-8 anywhere requires closing the connection
        // [MQTT-1.5.3-1/-2]. (Passwords are binary data.)
        if (!utf8_valid(client_id) || (p.has_username && !utf8_valid(p.username))) {
            c.dead = true;
            return;
        }
        if (p.has_will) {
            if (!topic_name_valid(p.will_topic)) {
                c.dead = true;  // will topic must be a valid name [MQTT-3.1.3.1]
                return;
            }
            if (p.will_topic.len > Traits::max_topic_len ||
                p.will_payload.len > Traits::max_payload_len) {
                refuse(ci, ConnackCode::server_unavailable);  // capacity policy
                return;
            }
        }
        const ConnackCode ac = auth_.check(client_id, p.has_username ? &p.username : nullptr,
                                           p.has_password ? &p.password : nullptr);
        if (ac != ConnackCode::accepted) {
            refuse(ci, ac);
            return;
        }

        SessionT* existing =
            sessions_.find([&](SessionT& s) { return s.client_id.equals(client_id); });

        // Session takeover: an existing connection with this client id is
        // dropped like a network failure (its will fires) [MQTT-3.1.4-2].
        if (existing != nullptr && existing->connected()) {
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
                refuse(ci, ConnackCode::server_unavailable);
                return;
            }
            s->client_id.assign(client_id);
        }

        s->clean_session = p.clean_session;
        s->conn = static_cast<uint16_t>(ci);
        s->has_will = p.has_will;
        if (p.has_will) {
            s->will_topic.assign(p.will_topic);
            s->will_payload.assign(p.will_payload);
            s->will_qos = p.will_qos;
            s->will_retain = p.will_retain;
        }

        c.session = static_cast<uint16_t>(sessions_.index_of(s));
        c.keepalive_s = p.keepalive_s;
        if (p.keepalive_s > 0) {
            c.deadline_ms = now_ms_ + keepalive_window_ms(p.keepalive_s);
        }

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
                c.dead = true;
                return;
            } else {
                s.inbound_qos2.push_back(p.packet_id);
            }
        }

        if (deliver) {
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
        Conn& c = conns_[ci];
        uint16_t id = 0;
        if (parse_packet_id_only(body, id) != Err::ok) {
            c.dead = true;
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
        Conn& c = conns_[ci];
        uint16_t id = 0;
        if (parse_packet_id_only(body, id) != Err::ok) {
            c.dead = true;
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
        Conn& c = conns_[ci];
        uint16_t id = 0;
        if (parse_packet_id_only(body, id) != Err::ok) {
            c.dead = true;
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
        Conn& c = conns_[ci];
        uint16_t id = 0;
        if (parse_packet_id_only(body, id) != Err::ok) {
            c.dead = true;
            return;
        }
        session_of(c)->remove_inbound_qos2(id);
        // PUBCOMP is always the answer, known id or not [MQTT-3.6.4-1].
        send_to(ci, build_packet_id_only(out_, sizeof out_, PacketType::pubcomp, id));
    }

    void handle_subscribe(size_t ci, ByteSpan body) {
        Conn& c = conns_[ci];
        SessionT& s = *session_of(c);

        // First pass: apply subscriptions while streaming the SUBACK
        // return codes straight into the outgoing packet buffer.
        TopicListParser entries{body, /*with_qos=*/true};
        Writer w{out_ + packet_overhead, sizeof out_ - packet_overhead};
        w.u16(entries.packet_id());

        StrView filter;
        QoS requested = QoS::at_most_once;
        bool violation = false;
        while (entries.next(filter, requested)) {
            if (!topic_filter_valid(filter)) {
                violation = true;  // ill-formed filter [MQTT-4.7.3-1, -1.5.3-1]
                break;
            }
            w.u8(subscribe_one(s, filter, requested));
        }
        if (violation || entries.status() != Err::ok || !w.ok()) {
            c.dead = true;  // protocol error: close without SUBACK [MQTT-4.8]
            return;
        }
        send_to(ci, frame_packet(out_, make_first_byte(PacketType::suback, 0), w.size()));

        // Second pass: deliver retained messages for the accepted
        // entries [MQTT-3.3.1-6]. Runs after the SUBACK is on the wire.
        TopicListParser again{body, /*with_qos=*/true};
        while (again.next(filter, requested)) {
            typename SessionT::Subscription* sub = s.find_sub(filter);
            if (sub == nullptr) {
                continue;  // this entry was refused above
            }
            retained_.for_each_match(filter, [&](typename RetainedStore<Traits>::Entry& e) {
                // Retained delivery at min(granted, stored QoS), with
                // the retain flag set [MQTT-3.3.1-8].
                const QoS eff = qos_min(sub->granted, e.qos);
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
    // returns the SUBACK code — 0x80 for capacity refusals.
    uint8_t subscribe_one(SessionT& s, StrView filter, QoS requested) {
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
        return static_cast<uint8_t>(sub->granted);
    }

    void handle_unsubscribe(size_t ci, ByteSpan body) {
        Conn& c = conns_[ci];
        SessionT& s = *session_of(c);

        TopicListParser entries{body, /*with_qos=*/false};
        StrView filter;
        QoS ignored = QoS::at_most_once;
        while (entries.next(filter, ignored)) {
            if (!topic_filter_valid(filter)) {
                c.dead = true;  // ill-formed filter [MQTT-4.7.3-1]
                return;
            }
            for (size_t i = 0; i < s.subs.size(); ++i) {
                if (s.subs[i].filter.equals(filter)) {
                    s.subs.remove_ordered(i);  // exact match only [MQTT-3.10.4]
                    break;
                }
            }
        }
        if (entries.status() != Err::ok) {
            c.dead = true;
            return;
        }
        send_to(ci, build_packet_id_only(out_, sizeof out_, PacketType::unsuback,
                                         entries.packet_id()));
    }

    void handle_disconnect(size_t ci, ByteSpan body) {
        Conn& c = conns_[ci];
        if (!body.empty()) {
            c.dead = true;
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
    Auth auth_{};
    Conn conns_[max_connections];
    Pool<SessionT, Traits::max_sessions> sessions_;
    RetainedStore<Traits> retained_;
    uint8_t out_[out_size];
    uint32_t now_ms_ = 0;
    uint16_t auto_id_counter_ = 0;
};

} // namespace minimosq

#endif // MINIMOSQ_BROKER_BROKER_HPP
