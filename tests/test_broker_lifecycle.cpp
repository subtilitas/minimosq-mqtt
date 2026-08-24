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

}  // namespace

// ----------------------------------------------- session reclamation

// ------------------------------------------ retained values gone stale

// ------------------------------ capacity limits enforced at the door

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
