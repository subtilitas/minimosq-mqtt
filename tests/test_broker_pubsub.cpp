// Broker tests: SUBSCRIBE/UNSUBSCRIBE, QoS 0 routing, retained
// messages, inbound QoS 1/2 publishes, wills.
// SPDX-License-Identifier: MIT
#include "broker_util.hpp"

using namespace bt;

namespace {
// Connect and drain the CONNACK so tests start from a quiet wire.
void connected(Bed& x, size_t ci, const char* id,
               const wire::ConnectOpts& o = wire::ConnectOpts{}) {
    x.connect(ci, id, o);
    expect_connack(x.t, ci, false, ConnackCode::accepted);
}
} // namespace

TEST(subscribe_gets_suback) {
    Bed x;
    connected(x, 0, "alice");
    x.feed(0, wire::make_subscribe(5, {{"a/+", 0}, {"b/#", 2}}));
    const uint8_t codes[] = {0x00, 0x00};  // QoS 0 granted at this stage
    expect_suback(x.t, 0, 5, codes);
}

TEST(publish_routes_to_matching_subscribers_only) {
    Bed x;
    connected(x, 0, "pub");
    connected(x, 1, "s1");
    connected(x, 2, "s2");
    x.feed(1, wire::make_subscribe(1, {{"x/#", 0}}));
    x.feed(2, wire::make_subscribe(1, {{"y", 0}}));
    x.t.next(1);  // drain SUBACKs
    x.t.next(2);

    x.feed(0, wire::make_publish("x/1", wire::bs("hello")));
    expect_publish(x.t, 1, "x/1", wire::bs("hello"), QoS::at_most_once, false);
    expect_silence(x.t, 2);
    expect_silence(x.t, 0);  // publisher has no matching subscription
}

TEST(publisher_receives_own_publish_when_subscribed) {
    Bed x;
    connected(x, 0, "alice");
    x.feed(0, wire::make_subscribe(1, {{"loop", 0}}));
    x.t.next(0);
    x.feed(0, wire::make_publish("loop", wire::bs("me")));
    expect_publish(x.t, 0, "loop", wire::bs("me"), QoS::at_most_once, false);
}

TEST(invalid_filter_gets_failure_code) {
    Bed x;
    connected(x, 0, "alice");
    x.feed(0, wire::make_subscribe(9, {{"ok/+", 0}, {"bad/#/x", 1}, {"also+bad", 0}}));
    const uint8_t codes[] = {0x00, 0x80, 0x80};
    expect_suback(x.t, 0, 9, codes);
    CHECK(!x.t.logs[0].closed);
}

TEST(subscription_table_full_gets_failure_code) {
    Bed x;  // max_subscriptions_per_session == 3
    connected(x, 0, "alice");
    x.feed(0, wire::make_subscribe(1, {{"a", 0}, {"b", 0}, {"c", 0}, {"d", 0}}));
    const uint8_t codes[] = {0x00, 0x00, 0x00, 0x80};
    expect_suback(x.t, 0, 1, codes);

    // Resubscribing an existing filter is a replace, not a new slot.
    x.feed(0, wire::make_subscribe(2, {{"b", 0}}));
    const uint8_t codes2[] = {0x00};
    expect_suback(x.t, 0, 2, codes2);
}

TEST(unsubscribe_stops_delivery) {
    Bed x;
    connected(x, 0, "pub");
    connected(x, 1, "sub");
    x.feed(1, wire::make_subscribe(1, {{"t", 0}}));
    x.t.next(1);

    x.feed(0, wire::make_publish("t", wire::bs("1")));
    expect_publish(x.t, 1, "t", wire::bs("1"), QoS::at_most_once, false);

    x.feed(1, wire::make_unsubscribe(2, {"t"}));
    expect_ack(x.t, 1, PacketType::unsuback, 2);

    x.feed(0, wire::make_publish("t", wire::bs("2")));
    expect_silence(x.t, 1);
}

TEST(retained_message_delivered_on_subscribe) {
    Bed x;
    connected(x, 0, "pub");
    x.feed(0, wire::make_publish("state/x", wire::bs("v1"), QoS::at_most_once, true));

    connected(x, 1, "sub");
    x.feed(1, wire::make_subscribe(1, {{"state/#", 0}}));
    const uint8_t codes[] = {0x00};
    expect_suback(x.t, 1, 1, codes);
    // Retained delivery carries retain=1 [MQTT-3.3.1-8].
    expect_publish(x.t, 1, "state/x", wire::bs("v1"), QoS::at_most_once, true);
}

TEST(retained_message_replaced_and_removed) {
    Bed x;
    connected(x, 0, "pub");
    x.feed(0, wire::make_publish("s", wire::bs("old"), QoS::at_most_once, true));
    x.feed(0, wire::make_publish("s", wire::bs("new"), QoS::at_most_once, true));
    CHECK_EQ(x.b.retained_count(), 1u);

    connected(x, 1, "sub1");
    x.feed(1, wire::make_subscribe(1, {{"s", 0}}));
    x.t.next(1);
    expect_publish(x.t, 1, "s", wire::bs("new"), QoS::at_most_once, true);

    // Zero-length retained payload clears the entry [MQTT-3.3.1-10].
    x.feed(0, wire::make_publish("s", ByteSpan{}, QoS::at_most_once, true));
    CHECK_EQ(x.b.retained_count(), 0u);
    connected(x, 2, "sub2");
    x.feed(2, wire::make_subscribe(1, {{"s", 0}}));
    x.t.next(2);
    expect_silence(x.t, 2);
}

TEST(retain_publish_still_routed_live_with_retain_cleared) {
    Bed x;
    connected(x, 0, "pub");
    connected(x, 1, "sub");
    x.feed(1, wire::make_subscribe(1, {{"s", 0}}));
    x.t.next(1);
    x.feed(0, wire::make_publish("s", wire::bs("v"), QoS::at_most_once, true));
    // Live forwarding clears the retain flag [MQTT-3.3.1-9].
    expect_publish(x.t, 1, "s", wire::bs("v"), QoS::at_most_once, false);
}

TEST(retained_store_full_is_best_effort) {
    Bed x;  // max_retained == 3
    connected(x, 0, "pub");
    x.feed(0, wire::make_publish("r/1", wire::bs("1"), QoS::at_most_once, true));
    x.feed(0, wire::make_publish("r/2", wire::bs("2"), QoS::at_most_once, true));
    x.feed(0, wire::make_publish("r/3", wire::bs("3"), QoS::at_most_once, true));
    x.feed(0, wire::make_publish("r/4", wire::bs("4"), QoS::at_most_once, true));
    CHECK_EQ(x.b.retained_count(), 3u);
    CHECK(!x.t.logs[0].closed);  // not an error, just not stored
}

TEST(inbound_qos1_is_acked_and_routed_once) {
    Bed x;
    connected(x, 0, "pub");
    connected(x, 1, "sub");
    x.feed(1, wire::make_subscribe(1, {{"t", 0}}));
    x.t.next(1);

    x.feed(0, wire::make_publish("t", wire::bs("v"), QoS::at_least_once, false, false, 42));
    expect_ack(x.t, 0, PacketType::puback, 42);
    expect_publish(x.t, 1, "t", wire::bs("v"), QoS::at_most_once, false);
    expect_silence(x.t, 1);
}

TEST(inbound_qos2_exactly_once_flow) {
    Bed x;
    connected(x, 0, "pub");
    connected(x, 1, "sub");
    x.feed(1, wire::make_subscribe(1, {{"t", 0}}));
    x.t.next(1);

    x.feed(0, wire::make_publish("t", wire::bs("v"), QoS::exactly_once, false, false, 7));
    expect_ack(x.t, 0, PacketType::pubrec, 7);
    expect_publish(x.t, 1, "t", wire::bs("v"), QoS::at_most_once, false);

    // Redelivery before PUBREL: not routed again, PUBREC repeated.
    x.feed(0, wire::make_publish("t", wire::bs("v"), QoS::exactly_once, false, true, 7));
    expect_ack(x.t, 0, PacketType::pubrec, 7);
    expect_silence(x.t, 1);

    x.feed(0, wire::make_ack(PacketType::pubrel, 7));
    expect_ack(x.t, 0, PacketType::pubcomp, 7);

    // The id is released: a new publish with it flows again.
    x.feed(0, wire::make_publish("t", wire::bs("w"), QoS::exactly_once, false, false, 7));
    expect_ack(x.t, 0, PacketType::pubrec, 7);
    expect_publish(x.t, 1, "t", wire::bs("w"), QoS::at_most_once, false);
}

TEST(pubrel_for_unknown_id_still_gets_pubcomp) {
    Bed x;
    connected(x, 0, "alice");
    x.feed(0, wire::make_ack(PacketType::pubrel, 99));
    expect_ack(x.t, 0, PacketType::pubcomp, 99);
}

TEST(publish_with_wildcard_topic_is_fatal) {
    Bed x;
    connected(x, 0, "alice");
    x.feed(0, wire::make_publish("a/+", wire::bs("x")));
    CHECK(x.t.logs[0].closed);
}

TEST(will_published_on_abnormal_close_only) {
    Bed x;
    connected(x, 1, "watcher");
    x.feed(1, wire::make_subscribe(1, {{"wills/#", 0}}));
    x.t.next(1);

    wire::ConnectOpts w;
    w.will_topic = "wills/a";
    w.will_payload = wire::bs("died");
    connected(x, 0, "a", w);
    x.b.conn_closed(0);  // network death → will fires
    expect_publish(x.t, 1, "wills/a", wire::bs("died"), QoS::at_most_once, false);

    wire::ConnectOpts w2;
    w2.will_topic = "wills/b";
    w2.will_payload = wire::bs("died");
    connected(x, 2, "b", w2);
    x.feed(2, wire::make_disconnect());  // clean close → will discarded
    expect_silence(x.t, 1);
}

TEST(will_published_on_keepalive_timeout_and_takeover) {
    Bed x;
    connected(x, 1, "watcher");
    x.feed(1, wire::make_subscribe(1, {{"wills/#", 0}}));
    x.t.next(1);

    wire::ConnectOpts w;
    w.will_topic = "wills/t";
    w.will_payload = wire::bs("timeout");
    w.keepalive_s = 1;
    connected(x, 0, "a", w);
    x.b.tick(x.now + 1500);
    CHECK(x.t.logs[0].closed);
    expect_publish(x.t, 1, "wills/t", wire::bs("timeout"), QoS::at_most_once, false);

    wire::ConnectOpts w2;
    w2.will_topic = "wills/k";
    w2.will_payload = wire::bs("kicked");
    connected(x, 2, "dup", w2);
    connected(x, 3, "dup");  // takeover → old connection's will fires
    expect_publish(x.t, 1, "wills/k", wire::bs("kicked"), QoS::at_most_once, false);
}

TEST(retained_will_is_stored) {
    Bed x;
    wire::ConnectOpts w;
    w.will_topic = "wills/r";
    w.will_payload = wire::bs("gone");
    w.will_retain = true;
    connected(x, 0, "a", w);
    x.b.conn_closed(0);
    CHECK_EQ(x.b.retained_count(), 1u);

    connected(x, 1, "sub");
    x.feed(1, wire::make_subscribe(1, {{"wills/r", 0}}));
    x.t.next(1);
    expect_publish(x.t, 1, "wills/r", wire::bs("gone"), QoS::at_most_once, true);
}

TEST(send_failure_drops_subscriber) {
    Bed x;
    connected(x, 0, "pub");
    connected(x, 1, "sub");
    x.feed(1, wire::make_subscribe(1, {{"t", 0}}));
    x.t.next(1);

    x.t.send_ok = false;
    x.feed(0, wire::make_publish("t", wire::bs("v")));
    x.t.send_ok = true;
    CHECK(x.t.logs[1].closed);
    CHECK(!x.t.logs[0].closed);

    // Broker state is consistent: the slot can be reused.
    x.t.logs[1].closed = false;
    x.connect(1, "sub2");
    expect_connack(x.t, 1, false, ConnackCode::accepted);
}

TEST(app_publish_reaches_subscribers) {
    Bed x;
    connected(x, 0, "sub");
    x.feed(0, wire::make_subscribe(1, {{"app/#", 0}}));
    x.t.next(0);
    CHECK(x.b.publish("app/x", wire::bs("hi"), QoS::at_most_once, false) == Err::ok);
    expect_publish(x.t, 0, "app/x", wire::bs("hi"), QoS::at_most_once, false);
}
