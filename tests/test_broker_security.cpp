// Broker tests: the security policy's authorization hooks — silent
// drop of unauthorized publishes, SUBACK 0x80 for unauthorized
// subscriptions, per-delivery receive filtering, will gating.
// SPDX-License-Identifier: MIT
#include "broker_util.hpp"

using namespace bt;

namespace {

bool starts_with(StrView s, StrView prefix) {
    if (s.len < prefix.len) {
        return false;
    }
    return StrView(s.data, prefix.len) == prefix;
}

// Role model for the tests:
//   role 'w' — may publish anywhere, receive nothing
//   role 'r' — may publish nothing, subscribe/receive only under "pub/"
//   role 'l' — lenient reader: may subscribe to anything, but receives
//              only topics under "pub/" (exercises the receive gate as
//              distinct from the subscribe gate)
// Clients authenticate with username "w", "r" or "l"; no username maps
// to role 0 (allowed to do everything — keeps unrelated fixtures easy).
struct RoleSecurity {
    struct Context {
        char role = 0;
    };

    minimosq::ConnackCode authenticate(minimosq::StrView, const minimosq::StrView* username,
                                       const minimosq::ByteSpan*, Context& ctx) {
        // Both arms are char: with a literal 0 the conditional yields int
        // and narrows on assignment, which is implementation-defined for
        // values above CHAR_MAX when char is signed.
        ctx.role = (username != nullptr && username->len == 1) ? username->data[0] : '\0';
        return minimosq::ConnackCode::accepted;
    }

    bool authorize_publish(const Context& c, minimosq::StrView topic) {
        (void)topic;
        return c.role == 0 || c.role == 'w';
    }

    bool authorize_subscribe(const Context& c, minimosq::StrView filter) {
        if (c.role == 0 || c.role == 'l') {
            return true;
        }
        if (c.role == 'r') {
            return starts_with(filter, "pub/");
        }
        return false;  // 'w' cannot subscribe at all
    }

    bool authorize_receive(const Context& c, minimosq::StrView topic) {
        if (c.role == 0) {
            return true;
        }
        return (c.role == 'r' || c.role == 'l') && starts_with(topic, "pub/");
    }
};

using SecBed = BedT<RoleSecurity>;

void connect_role(SecBed& x, size_t ci, const char* id, const char* role) {
    wire::ConnectOpts o;
    o.username = role;
    x.connect(ci, id, o);
    x.t.next(ci);  // drain CONNACK
}

}  // namespace

TEST(unauthorized_publish_dropped_but_acked) {
    SecBed x;
    connect_role(x, 0, "reader", "r");
    connect_role(x, 1, "anyone", "l");
    x.feed(1, wire::make_subscribe(1, {{"#", 0}}));
    x.t.next(1);

    // QoS 1: acked as if accepted, but nothing is routed.
    x.feed(0, wire::make_publish("pub/x", wire::bs("nope"), QoS::at_least_once, false, false, 4));
    expect_ack(x.t, 0, PacketType::puback, 4);
    expect_silence(x.t, 1);
    CHECK(!x.t.logs[0].closed);

    // QoS 2 completes its whole handshake without delivering.
    x.feed(0, wire::make_publish("pub/y", wire::bs("nope"), QoS::exactly_once, false, false, 5));
    expect_ack(x.t, 0, PacketType::pubrec, 5);
    x.feed(0, wire::make_ack(PacketType::pubrel, 5));
    expect_ack(x.t, 0, PacketType::pubcomp, 5);
    expect_silence(x.t, 1);

    // Retained flag of a denied publish must not touch the store.
    x.feed(0, wire::make_publish("pub/r", wire::bs("nope"), QoS::at_most_once, true));
    CHECK_EQ(x.b.retained_count(), 0u);
}

TEST(authorized_publish_flows_normally) {
    SecBed x;
    connect_role(x, 0, "writer", "w");
    connect_role(x, 1, "reader", "r");
    x.feed(1, wire::make_subscribe(1, {{"pub/#", 1}}));
    x.t.next(1);

    x.feed(0, wire::make_publish("pub/x", wire::bs("hello"), QoS::at_least_once, false, false, 7));
    expect_ack(x.t, 0, PacketType::puback, 7);
    expect_publish(x.t, 1, "pub/x", wire::bs("hello"), QoS::at_least_once, false);
}

TEST(unauthorized_subscribe_gets_0x80) {
    SecBed x;
    connect_role(x, 0, "reader", "r");
    x.feed(0, wire::make_subscribe(3, {{"pub/+", 1}, {"secret/#", 1}, {"pub/ok", 2}}));
    const uint8_t codes[] = {0x01, 0x80, 0x02};
    expect_suback(x.t, 0, 3, codes);
    CHECK(!x.t.logs[0].closed);

    // The refused filter really is not installed: matching publishes
    // don't reach the client.
    connect_role(x, 1, "writer", "w");
    x.feed(1, wire::make_publish("secret/x", wire::bs("s")));
    expect_silence(x.t, 0);
}

TEST(receive_gate_filters_broad_subscriptions) {
    SecBed x;
    connect_role(x, 0, "lenient", "l");
    x.feed(0, wire::make_subscribe(1, {{"#", 0}}));  // allowed for 'l'
    x.t.next(0);

    connect_role(x, 1, "writer", "w");
    x.feed(1, wire::make_publish("pub/visible", wire::bs("yes")));
    x.feed(1, wire::make_publish("private/hidden", wire::bs("no")));
    expect_publish(x.t, 0, "pub/visible", wire::bs("yes"), QoS::at_most_once, false);
    expect_silence(x.t, 0);  // the second publish never arrived
}

TEST(retained_delivery_respects_receive_gate) {
    SecBed x;
    connect_role(x, 0, "writer", "w");
    x.feed(0, wire::make_publish("pub/state", wire::bs("a"), QoS::at_most_once, true));
    x.feed(0, wire::make_publish("private/state", wire::bs("b"), QoS::at_most_once, true));
    CHECK_EQ(x.b.retained_count(), 2u);

    connect_role(x, 1, "lenient", "l");
    x.feed(1, wire::make_subscribe(1, {{"+/state", 0}}));
    x.t.next(1);
    expect_publish(x.t, 1, "pub/state", wire::bs("a"), QoS::at_most_once, true);
    expect_silence(x.t, 1);  // private/state withheld
}

TEST(unauthorized_will_is_not_published) {
    SecBed x;
    connect_role(x, 1, "lenient", "l");
    x.feed(1, wire::make_subscribe(1, {{"pub/#", 0}}));
    x.t.next(1);

    // 'r' may not publish; its will is discarded when it fires.
    wire::ConnectOpts o;
    o.username = "r";
    o.will_topic = "pub/wills/r";
    o.will_payload = wire::bs("gone");
    o.will_retain = true;
    x.connect(0, "reader", o);
    x.t.next(0);
    x.b.conn_closed(0);
    expect_silence(x.t, 1);
    CHECK_EQ(x.b.retained_count(), 0u);

    // An authorized will still fires.
    wire::ConnectOpts w;
    w.username = "w";
    w.will_topic = "pub/wills/w";
    w.will_payload = wire::bs("gone");
    x.connect(2, "writer", w);
    x.t.next(2);
    x.b.conn_closed(2);
    expect_publish(x.t, 1, "pub/wills/w", wire::bs("gone"), QoS::at_most_once, false);
}

TEST(context_refreshed_on_reconnect) {
    SecBed x;
    // Persistent session connects as unrestricted role 0, then
    // reconnects as restricted 'r': the stored context must be the
    // fresh one, so publishing is now denied.
    wire::ConnectOpts p0;
    p0.clean = false;
    x.connect(0, "chameleon", p0);
    x.t.next(0);
    x.b.conn_closed(0);

    connect_role(x, 2, "sink", "l");
    x.feed(2, wire::make_subscribe(1, {{"#", 0}}));
    x.t.next(2);

    wire::ConnectOpts p1;
    p1.clean = false;
    p1.username = "r";
    x.connect(1, "chameleon", p1);
    x.t.next(1);  // CONNACK (session present)
    x.feed(1, wire::make_publish("pub/x", wire::bs("v"), QoS::at_least_once, false, false, 9));
    expect_ack(x.t, 1, PacketType::puback, 9);
    expect_silence(x.t, 2);  // denied under the refreshed context
}

// ------------------------------------------- post-review regressions

// A policy whose subscribe check is stricter than its receive check —
// the shape that exposed the retained-replay bypass. Real examples: a
// wildcard-subscription ban, or a per-filter subscription quota.
namespace {
struct StricterSubscribeSecurity {
    struct Context {
        int unused = 0;
    };
    bool allow_subscribe = true;

    ConnackCode authenticate(StrView, const StrView*, const ByteSpan*, Context&) {
        return ConnackCode::accepted;
    }
    bool authorize_publish(const Context&, StrView) { return true; }
    bool authorize_subscribe(const Context&, StrView) { return allow_subscribe; }
    bool authorize_receive(const Context&, StrView) { return true; }
};
}  // namespace

TEST(refused_resubscribe_does_not_replay_retained_messages) {
    bt::BedT<StricterSubscribeSecurity> x;
    x.connect(0, "pub");
    expect_connack(x.t, 0, false, ConnackCode::accepted);
    x.feed(0, wire::make_publish("a/x", wire::bs("RET"), QoS::at_most_once, /*retain=*/true));

    // First SUBSCRIBE is granted and replays the retained message.
    x.connect(1, "sub");
    expect_connack(x.t, 1, false, ConnackCode::accepted);
    x.feed(1, wire::make_subscribe(1, {{"a/x", 0}}));
    const uint8_t granted[] = {0};
    expect_suback(x.t, 1, 1, granted);
    expect_publish(x.t, 1, "a/x", wire::bs("RET"), QoS::at_most_once, /*retain=*/true);
    expect_silence(x.t, 1);

    // Policy revoked. The same SUBSCRIBE must be refused *and* must not
    // replay anything, even though the earlier subscription still
    // exists in the session's table.
    x.b.security().allow_subscribe = false;
    x.feed(1, wire::make_subscribe(2, {{"a/x", 0}}));
    const uint8_t refused[] = {suback_failure};
    expect_suback(x.t, 1, 2, refused);
    expect_silence(x.t, 1);
}

TEST(duplicate_filter_in_one_subscribe_replays_retained_once) {
    bt::Bed x;
    x.connect(0, "pub");
    expect_connack(x.t, 0, false, ConnackCode::accepted);
    x.feed(0, wire::make_publish("a/x", wire::bs("RET"), QoS::at_most_once, /*retain=*/true));

    x.connect(1, "sub");
    expect_connack(x.t, 1, false, ConnackCode::accepted);
    x.feed(1, wire::make_subscribe(1, {{"a/x", 0}, {"a/x", 0}}));

    // One return code per entry [MQTT-3.8.4-5], but the two entries
    // resolve to a single subscription, so one retained delivery.
    const uint8_t codes[] = {0, 0};
    expect_suback(x.t, 1, 1, codes);
    expect_publish(x.t, 1, "a/x", wire::bs("RET"), QoS::at_most_once, /*retain=*/true);
    expect_silence(x.t, 1);
}

TEST(malformed_subscribe_applies_nothing_at_all) {
    bt::Bed x;
    wire::ConnectOpts persistent;
    persistent.clean = false;

    // "bad/#/x" is an invalid filter, so the whole packet is a protocol
    // error and the valid entry ahead of it must not take effect.
    x.connect(0, "keeper", persistent);
    expect_connack(x.t, 0, false, ConnackCode::accepted);
    x.feed(0, wire::make_subscribe(1, {{"good/topic", 0}, {"bad/#/x", 0}}));
    CHECK(x.t.logs[0].closed);
    expect_silence(x.t, 0);  // closed without SUBACK [MQTT-4.8]

    // Resume the persistent session: the subscription must be absent.
    x.connect(1, "keeper", persistent);
    expect_connack(x.t, 1, /*session_present=*/true, ConnackCode::accepted);
    x.connect(2, "pub");
    expect_connack(x.t, 2, false, ConnackCode::accepted);
    x.feed(2, wire::make_publish("good/topic", wire::bs("hi")));
    expect_silence(x.t, 1);
}

TEST(malformed_unsubscribe_removes_nothing) {
    bt::Bed x;
    wire::ConnectOpts persistent;
    persistent.clean = false;
    x.connect(0, "keeper", persistent);
    expect_connack(x.t, 0, false, ConnackCode::accepted);
    x.feed(0, wire::make_subscribe(1, {{"good/topic", 0}}));
    const uint8_t codes[] = {0};
    expect_suback(x.t, 0, 1, codes);

    // Valid entry first, invalid second: nothing may be removed.
    x.feed(0, wire::make_unsubscribe(2, {"good/topic", "bad/#/x"}));
    CHECK(x.t.logs[0].closed);

    x.connect(1, "keeper", persistent);
    expect_connack(x.t, 1, /*session_present=*/true, ConnackCode::accepted);
    x.connect(2, "pub");
    expect_connack(x.t, 2, false, ConnackCode::accepted);
    x.feed(2, wire::make_publish("good/topic", wire::bs("still-here")));
    expect_publish(x.t, 1, "good/topic", wire::bs("still-here"), QoS::at_most_once, false);
}
