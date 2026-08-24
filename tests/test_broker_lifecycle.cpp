// Session lifetime, capacity honesty and the observer seam.
//
// Every test here pins behaviour that used to be silent: a session slot
// nothing could reclaim, a retained value that outlived its own update,
// a QoS 1 delivery dropped without telling anyone, and a SUBSCRIBE whose
// output grew with the product of two capacities.
// SPDX-License-Identifier: MIT
#include "broker_util.hpp"

using namespace bt;

namespace {

// ---------------------------------------------------------- fixtures

// SmallTraits with sessions that expire, so the timer path is testable.
struct ExpiringTraits : SmallTraits {
    static constexpr uint32_t session_expiry_ms = 60000;
};

// Records every event the broker reports, in order.
struct Recorder {
    struct Row {
        EventKind kind;
        char client_id[24] = {};
        char topic[40] = {};
        Err err = Err::ok;
        ConnackCode connack = ConnackCode::accepted;
        QoS qos = QoS::at_most_once;
        size_t ci = Event::no_conn;
    };
    Row rows[128];
    size_t count = 0;

    static void copy(char* dst, size_t cap, StrView v) {
        const size_t n = v.len < cap - 1 ? v.len : cap - 1;
        for (size_t i = 0; i < n; ++i) {
            dst[i] = v.data[i];
        }
        dst[n] = '\0';
    }

    void on_event(const Event& e) noexcept {
        if (count >= sizeof rows / sizeof rows[0]) {
            return;
        }
        Row& r = rows[count++];
        r.kind = e.kind;
        r.err = e.err;
        r.connack = e.connack;
        r.qos = e.qos;
        r.ci = e.ci;
        copy(r.client_id, sizeof r.client_id, e.client_id);
        copy(r.topic, sizeof r.topic, e.topic);
    }

    size_t times(EventKind k) const {
        size_t n = 0;
        for (size_t i = 0; i < count; ++i) {
            if (rows[i].kind == k) {
                ++n;
            }
        }
        return n;
    }

    const Row* first(EventKind k) const {
        for (size_t i = 0; i < count; ++i) {
            if (rows[i].kind == k) {
                return &rows[i];
            }
        }
        return nullptr;
    }

    bool saw(EventKind k) const { return first(k) != nullptr; }
};

bool str_eq(const char* a, const char* b) {
    while (*a != '\0' && *a == *b) {
        ++a;
        ++b;
    }
    return *a == *b;
}

// Connect, then disconnect cleanly, leaving a persistent session behind.
template <typename B>
void leave_persistent_session(B& x, size_t ci, const char* id) {
    wire::ConnectOpts o;
    o.clean = false;
    x.connect(ci, id, o);
    expect_connack(x.t, ci, false, ConnackCode::accepted);
    x.feed(ci, wire::make_disconnect());
}

}  // namespace

// ----------------------------------------------- session reclamation

TEST(abandoned_persistent_sessions_do_not_lock_the_broker_shut) {
    // MQTT 3.1.1 has no session expiry, so before eviction existed one
    // connection could fill every session slot and walk away, leaving
    // nothing to reclaim and every later client refused.
    BedT<> x;
    for (size_t i = 0; i < SmallTraits::max_sessions; ++i) {
        char id[8] = {'p', static_cast<char>('0' + i), '\0'};
        leave_persistent_session(x, 0, id);
    }

    // Zero connections are live and the pool is full. A new client still
    // gets in: the longest-disconnected session is evicted for it.
    x.connect(1, "fresh");
    expect_connack(x.t, 1, false, ConnackCode::accepted);

    // And the one evicted is the oldest, not an arbitrary victim: p1 and
    // p2 are still resumable, p0 is gone.
    wire::ConnectOpts o;
    o.clean = false;
    x.connect(2, "p1", o);
    expect_connack(x.t, 2, /*session_present=*/true, ConnackCode::accepted);
}

TEST(eviction_reports_which_session_was_broken) {
    BedT<AllowAllSecurity, Recorder> x;
    for (size_t i = 0; i < SmallTraits::max_sessions; ++i) {
        char id[8] = {'p', static_cast<char>('0' + i), '\0'};
        leave_persistent_session(x, 0, id);
    }
    x.connect(1, "fresh");

    const Recorder::Row* ev = x.b.observer().first(EventKind::session_evicted);
    CHECK(ev != nullptr);
    if (ev != nullptr) {
        CHECK(str_eq(ev->client_id, "p0"));
    }
}

TEST(session_expiry_reclaims_before_the_pool_fills) {
    BedT<AllowAllSecurity, Recorder, ExpiringTraits> x;
    leave_persistent_session(x, 0, "gone");
    CHECK(x.b.observer().times(EventKind::session_expired) == 0u);

    // Just short of the timer: still resumable.
    x.now += ExpiringTraits::session_expiry_ms - 1;
    x.b.tick(x.now);
    CHECK(x.b.observer().times(EventKind::session_expired) == 0u);

    x.now += 1;
    x.b.tick(x.now);
    CHECK(x.b.observer().times(EventKind::session_expired) == 1u);

    // Reconnecting now is a fresh session, not a resumed one.
    wire::ConnectOpts o;
    o.clean = false;
    x.connect(1, "gone", o);
    expect_connack(x.t, 1, /*session_present=*/false, ConnackCode::accepted);
}

TEST(session_expiry_leaves_connected_sessions_alone) {
    BedT<AllowAllSecurity, Recorder, ExpiringTraits> x;
    wire::ConnectOpts o;
    o.clean = false;
    o.keepalive_s = 0;  // nothing else may reclaim it either
    x.connect(0, "here", o);
    expect_connack(x.t, 0, false, ConnackCode::accepted);

    x.now += ExpiringTraits::session_expiry_ms * 4;
    x.b.tick(x.now);
    CHECK(x.b.observer().times(EventKind::session_expired) == 0u);
    CHECK(!x.t.logs[0].closed);
}

// ------------------------------------------ retained values gone stale

TEST(an_unstorable_retained_update_purges_the_value_it_replaces) {
    // The publisher is acknowledged and live subscribers see the new
    // value, so leaving the old one in the store would hand every later
    // subscriber a stale reading that looks current.
    BedT<AllowAllSecurity, Recorder> x;
    x.connect(0, "pub");
    expect_connack(x.t, 0, false, ConnackCode::accepted);

    x.feed(0, wire::make_publish("t", wire::bs("old"), QoS::at_most_once, /*retain=*/true));
    CHECK_EQ(x.b.retained_count(), 1u);

    uint8_t big[SmallTraits::max_payload_len + 1];
    for (uint8_t& b : big) {
        b = 'x';
    }
    x.feed(0, wire::make_publish("t", ByteSpan{big, sizeof big}, QoS::at_most_once,
                                 /*retain=*/true));
    CHECK_EQ(x.b.retained_count(), 0u);
    CHECK(x.b.observer().saw(EventKind::retained_stale_purged));
    CHECK(x.b.observer().saw(EventKind::retained_store_failed));

    // A subscriber joining now is told nothing rather than told 'old'.
    x.connect(1, "sub");
    expect_connack(x.t, 1, false, ConnackCode::accepted);
    x.feed(1, wire::make_subscribe(1, {{"t", 0}}));
    const uint8_t codes[] = {0};
    expect_suback(x.t, 1, 1, codes);
    expect_silence(x.t, 1);
}

TEST(a_full_retained_store_purges_nothing_it_did_not_own) {
    BedT<AllowAllSecurity, Recorder> x;
    x.connect(0, "pub");
    expect_connack(x.t, 0, false, ConnackCode::accepted);
    for (size_t i = 0; i < SmallTraits::max_retained; ++i) {
        char topic[8] = {'t', static_cast<char>('0' + i), '\0'};
        x.feed(0, wire::make_publish(topic, wire::bs("v"), QoS::at_most_once, /*retain=*/true));
    }
    CHECK_EQ(x.b.retained_count(), SmallTraits::max_retained);

    x.feed(0, wire::make_publish("new", wire::bs("v"), QoS::at_most_once, /*retain=*/true));
    CHECK_EQ(x.b.retained_count(), SmallTraits::max_retained);  // nothing displaced
    CHECK(x.b.observer().saw(EventKind::retained_store_failed));
    CHECK(!x.b.observer().saw(EventKind::retained_stale_purged));
}

// ------------------------------ capacity limits enforced at the door

TEST(a_publish_topic_beyond_capacity_is_refused_not_half_delivered) {
    // It would reach QoS 0 subscribers and silently skip QoS>0 ones,
    // while the publisher is acknowledged either way. Requesting a
    // higher QoS must not make delivery less reliable.
    BedT<AllowAllSecurity, Recorder> x;
    x.connect(0, "pub");
    expect_connack(x.t, 0, false, ConnackCode::accepted);

    char topic[SmallTraits::max_topic_len + 2];
    for (char& c : topic) {
        c = 'a';
    }
    topic[sizeof topic - 1] = '\0';
    x.feed(0, wire::make_publish(topic, wire::bs("v"), QoS::at_most_once));

    CHECK(x.t.logs[0].closed);
    const Recorder::Row* v = x.b.observer().first(EventKind::protocol_violation);
    CHECK(v != nullptr);
    if (v != nullptr) {
        CHECK(v->err == Err::oversize);
    }
}

TEST(the_application_publish_api_applies_the_same_rule) {
    Bed x;
    char topic[SmallTraits::max_topic_len + 2];
    for (char& c : topic) {
        c = 'a';
    }
    topic[sizeof topic - 1] = '\0';
    CHECK(x.b.publish(topic, wire::bs("v"), QoS::at_most_once, false) == Err::oversize);

    char fits[SmallTraits::max_topic_len + 1];
    for (char& c : fits) {
        c = 'a';
    }
    fits[sizeof fits - 1] = '\0';
    CHECK(x.b.publish(fits, wire::bs("v"), QoS::at_most_once, false) == Err::ok);
}

TEST(an_oversize_payload_still_passes_through_at_qos0_and_is_reported_at_qos1) {
    // Payload is deliberately different from topic: QoS 0 pass-through is
    // bounded by max_packet_size, so a payload too large to *own* is
    // still forwarded live. What must not stay silent is the QoS>0
    // subscriber that consequently gets nothing.
    BedT<AllowAllSecurity, Recorder> x;
    x.connect(0, "pub");
    expect_connack(x.t, 0, false, ConnackCode::accepted);
    x.connect(1, "s0");
    expect_connack(x.t, 1, false, ConnackCode::accepted);
    x.connect(2, "s1");
    expect_connack(x.t, 2, false, ConnackCode::accepted);

    x.feed(1, wire::make_subscribe(1, {{"t", 0}}));
    const uint8_t c0[] = {0};
    expect_suback(x.t, 1, 1, c0);
    x.feed(2, wire::make_subscribe(1, {{"t", 1}}));
    const uint8_t c1[] = {1};
    expect_suback(x.t, 2, 1, c1);

    uint8_t big[SmallTraits::max_payload_len + 8];
    for (uint8_t& b : big) {
        b = 'x';
    }
    // Published at QoS 1, so the QoS 0 subscriber is a pass-through and
    // the QoS 1 subscriber needs an owned copy the broker cannot make.
    x.feed(0,
           wire::make_publish("t", ByteSpan{big, sizeof big}, QoS::at_least_once, false, false, 3));
    expect_ack(x.t, 0, PacketType::puback, 3);

    expect_publish(x.t, 1, "t", ByteSpan{big, sizeof big}, QoS::at_most_once, false);
    expect_silence(x.t, 2);
    const Recorder::Row* d = x.b.observer().first(EventKind::delivery_dropped);
    CHECK(d != nullptr);
    if (d != nullptr) {
        CHECK(d->err == Err::oversize);
        CHECK(str_eq(d->client_id, "s1"));
        CHECK(str_eq(d->topic, "t"));
    }
}

TEST(a_full_session_queue_reports_the_message_it_drops) {
    BedT<AllowAllSecurity, Recorder> x;
    x.connect(0, "pub");
    expect_connack(x.t, 0, false, ConnackCode::accepted);
    x.connect(1, "sub");
    expect_connack(x.t, 1, false, ConnackCode::accepted);
    x.feed(1, wire::make_subscribe(1, {{"t", 1}}));
    const uint8_t codes[] = {1};
    expect_suback(x.t, 1, 1, codes);

    // Never acknowledged, so the queue fills and stays full.
    for (size_t i = 0; i < SmallTraits::max_pending_per_session + 2; ++i) {
        x.feed(0, wire::make_publish("t", wire::bs("v"), QoS::at_least_once, false, false,
                                     static_cast<uint16_t>(i + 1)));
    }
    CHECK(x.b.observer().times(EventKind::delivery_dropped) == 2u);
    const Recorder::Row* d = x.b.observer().first(EventKind::delivery_dropped);
    CHECK(d != nullptr);
    if (d != nullptr) {
        CHECK(d->err == Err::capacity);
    }
}

// ---------------------- retained replay: per message, not per filter

TEST(overlapping_filters_replay_a_retained_message_once) {
    // route_publish already delivers a live message once per session
    // however many of its filters match. Retained replay must agree —
    // and the per-filter form also made one SUBSCRIBE cost
    // subscriptions x retained messages in output packets.
    Bed x;
    x.connect(0, "pub");
    expect_connack(x.t, 0, false, ConnackCode::accepted);
    x.feed(0, wire::make_publish("a/x", wire::bs("v"), QoS::at_most_once, /*retain=*/true));

    x.connect(1, "sub");
    expect_connack(x.t, 1, false, ConnackCode::accepted);
    x.feed(1, wire::make_subscribe(1, {{"a/x", 0}, {"a/#", 0}}));
    const uint8_t codes[] = {0, 0};
    expect_suback(x.t, 1, 1, codes);

    expect_publish(x.t, 1, "a/x", wire::bs("v"), QoS::at_most_once, /*retain=*/true);
    expect_silence(x.t, 1);
}

TEST(overlapping_filters_replay_at_the_highest_granted_qos) {
    // Same rule route_publish uses: min(stored QoS, max granted across
    // the session's matching filters).
    Bed x;
    x.connect(0, "pub");
    expect_connack(x.t, 0, false, ConnackCode::accepted);
    x.feed(0,
           wire::make_publish("a/x", wire::bs("v"), QoS::exactly_once, /*retain=*/true, false, 7));
    expect_ack(x.t, 0, PacketType::pubrec, 7);

    x.connect(1, "sub");
    expect_connack(x.t, 1, false, ConnackCode::accepted);
    x.feed(1, wire::make_subscribe(1, {{"a/x", 0}, {"a/#", 1}}));
    const uint8_t codes[] = {0, 1};
    expect_suback(x.t, 1, 1, codes);

    expect_publish(x.t, 1, "a/x", wire::bs("v"), QoS::at_least_once, /*retain=*/true);
    expect_silence(x.t, 1);
}

TEST(retained_replay_is_bounded_by_the_store_not_the_subscription_count) {
    // The amplification check: K filters over R retained messages used to
    // produce K*R packets. It must be at most R.
    Bed x;
    x.connect(0, "pub");
    expect_connack(x.t, 0, false, ConnackCode::accepted);
    for (size_t i = 0; i < SmallTraits::max_retained; ++i) {
        char topic[8] = {'a', '/', static_cast<char>('0' + i), '\0'};
        x.feed(0, wire::make_publish(topic, wire::bs("v"), QoS::at_most_once, /*retain=*/true));
    }

    x.connect(1, "sub");
    expect_connack(x.t, 1, false, ConnackCode::accepted);
    x.feed(1, wire::make_subscribe(1, {{"a/#", 0}, {"a/+", 0}, {"#", 0}}));
    const uint8_t codes[] = {0, 0, 0};
    expect_suback(x.t, 1, 1, codes);

    size_t delivered = 0;
    while (!x.t.no_more(1)) {
        CapturedPacket p = x.t.next(1);
        CHECK(p.ok);
        if (!p.ok) {
            break;
        }
        CHECK(packet_type(p.first_byte) == PacketType::publish);
        ++delivered;
    }
    CHECK_EQ(delivered, SmallTraits::max_retained);
}

TEST(retained_replay_skips_messages_no_granted_filter_matches) {
    // Inverting pass 3 to iterate the store means every retained message
    // is now considered for every SUBSCRIBE; the ones nothing granted
    // matches must be skipped, not delivered.
    Bed x;
    x.connect(0, "pub");
    expect_connack(x.t, 0, false, ConnackCode::accepted);
    x.feed(0, wire::make_publish("a/x", wire::bs("in"), QoS::at_most_once, /*retain=*/true));
    x.feed(0, wire::make_publish("b/y", wire::bs("out"), QoS::at_most_once, /*retain=*/true));

    x.connect(1, "sub");
    expect_connack(x.t, 1, false, ConnackCode::accepted);
    x.feed(1, wire::make_subscribe(1, {{"a/#", 0}}));
    const uint8_t codes[] = {0};
    expect_suback(x.t, 1, 1, codes);

    expect_publish(x.t, 1, "a/x", wire::bs("in"), QoS::at_most_once, /*retain=*/true);
    expect_silence(x.t, 1);
}

TEST(an_overfull_inbound_qos2_window_reports_a_capacity_violation) {
    // Dropping the client is the documented policy — duplicate delivery
    // is never risked — but it used to be indistinguishable from a
    // malformed packet from outside.
    BedT<AllowAllSecurity, Recorder> x;
    x.connect(0, "pub");
    expect_connack(x.t, 0, false, ConnackCode::accepted);
    for (size_t i = 0; i < SmallTraits::max_inbound_qos2 + 1; ++i) {
        x.feed(0, wire::make_publish("t", wire::bs("v"), QoS::exactly_once, false, false,
                                     static_cast<uint16_t>(i + 1)));
    }
    CHECK(x.t.logs[0].closed);
    const Recorder::Row* v = x.b.observer().first(EventKind::protocol_violation);
    CHECK(v != nullptr);
    if (v != nullptr) {
        CHECK(v->err == Err::capacity);
    }
}

// ---------------------------------------------------- the observer

TEST(the_connection_lifecycle_is_visible) {
    BedT<AllowAllSecurity, Recorder> x;
    x.connect(0, "c");
    expect_connack(x.t, 0, false, ConnackCode::accepted);
    x.feed(0, wire::make_disconnect());

    const Recorder& r = x.b.observer();
    CHECK(r.times(EventKind::connection_opened) == 1u);
    CHECK(r.times(EventKind::session_created) == 1u);
    CHECK(r.times(EventKind::connection_closed) == 1u);
    const Recorder::Row* closed = r.first(EventKind::connection_closed);
    CHECK(closed != nullptr);
    if (closed != nullptr) {
        CHECK(str_eq(closed->client_id, "c"));  // known, even on the way out
        CHECK_EQ(closed->ci, 0u);
    }
}

TEST(a_refused_connect_reports_the_code_and_the_client_id) {
    BedT<AllowAllSecurity, Recorder> x;
    x.open(0);
    wire::ConnectOpts o;
    o.protocol_level = 3;
    x.feed(0, wire::make_connect("legacy", o));

    const Recorder::Row* ref = x.b.observer().first(EventKind::connect_refused);
    CHECK(ref != nullptr);
    if (ref != nullptr) {
        CHECK(ref->connack == ConnackCode::unacceptable_protocol);
    }
}

TEST(takeover_and_resume_are_distinguishable) {
    BedT<AllowAllSecurity, Recorder> x;
    wire::ConnectOpts o;
    o.clean = false;
    x.connect(0, "dup", o);
    expect_connack(x.t, 0, false, ConnackCode::accepted);
    x.connect(1, "dup", o);
    expect_connack(x.t, 1, /*session_present=*/true, ConnackCode::accepted);

    const Recorder& r = x.b.observer();
    CHECK(r.times(EventKind::session_taken_over) == 1u);
    CHECK(r.times(EventKind::session_created) == 1u);
    CHECK(r.times(EventKind::session_resumed) == 1u);
}

TEST(timeouts_say_which_timer_fired) {
    BedT<AllowAllSecurity, Recorder> a;
    a.open(0);
    a.now += SmallTraits::connect_timeout_ms;
    a.b.tick(a.now);
    CHECK(a.b.observer().times(EventKind::connect_timeout) == 1u);
    CHECK(a.b.observer().times(EventKind::keepalive_timeout) == 0u);

    BedT<AllowAllSecurity, Recorder> b;
    wire::ConnectOpts o;
    o.keepalive_s = 10;
    b.connect(0, "k", o);
    expect_connack(b.t, 0, false, ConnackCode::accepted);
    b.now += 15000;
    b.b.tick(b.now);
    CHECK(b.b.observer().times(EventKind::keepalive_timeout) == 1u);
    CHECK(b.b.observer().times(EventKind::connect_timeout) == 0u);
}

TEST(a_protocol_violation_carries_its_error_code) {
    BedT<AllowAllSecurity, Recorder> x;
    x.connect(0, "c");
    expect_connack(x.t, 0, false, ConnackCode::accepted);
    x.feed(0, wire::make_connect("again"));  // second CONNECT [MQTT-3.1.0-2]

    const Recorder::Row* v = x.b.observer().first(EventKind::protocol_violation);
    CHECK(v != nullptr);
    if (v != nullptr) {
        CHECK(v->err == Err::state);
    }
}

TEST(the_default_observer_changes_nothing) {
    // NullObserver is the default and must be invisible: same wire
    // behaviour, and no member that could be observed from outside.
    Bed x;
    x.connect(0, "c");
    expect_connack(x.t, 0, false, ConnackCode::accepted);
    x.feed(0, wire::make_subscribe(1, {{"t", 0}}));
    const uint8_t codes[] = {0};
    expect_suback(x.t, 0, 1, codes);
    expect_silence(x.t, 0);
}
