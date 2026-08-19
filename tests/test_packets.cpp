// Unit tests for packet parsing and serialization.
// SPDX-License-Identifier: MIT
#include "test.hpp"
#include "wire_util.hpp"

#include <minimosq/protocol/packets.hpp>

using namespace minimosq;

// ------------------------------------------------------------- CONNECT

TEST(parse_connect_minimal) {
    const wire::Pkt pkt = wire::make_connect("client-1");
    ConnectPacket c;
    CHECK(parse_connect(wire::body_of(pkt), c) == Err::ok);
    CHECK(c.protocol_name_ok);
    CHECK_EQ(c.protocol_level, 4);
    CHECK(c.client_id == StrView("client-1"));
    CHECK(c.clean_session);
    CHECK(!c.has_will);
    CHECK(!c.has_username);
    CHECK_EQ(c.keepalive_s, 60u);
}

TEST(parse_connect_full_options) {
    wire::ConnectOpts o;
    o.clean = false;
    o.keepalive_s = 30;
    o.will_topic = "dead/letter";
    o.will_payload = wire::bs("gone");
    o.will_qos = QoS::at_least_once;
    o.will_retain = true;
    o.username = "user";
    o.password = "pass";
    const wire::Pkt pkt = wire::make_connect("c2", o);

    ConnectPacket c;
    CHECK(parse_connect(wire::body_of(pkt), c) == Err::ok);
    CHECK(!c.clean_session);
    CHECK(c.has_will);
    CHECK(c.will_topic == StrView("dead/letter"));
    CHECK(c.will_payload == wire::bs("gone"));
    CHECK(c.will_qos == QoS::at_least_once);
    CHECK(c.will_retain);
    CHECK(c.has_username && c.username == StrView("user"));
    CHECK(c.has_password && c.password == wire::bs("pass"));
}

TEST(parse_connect_reserved_flag_rejected) {
    wire::ConnectOpts o;
    o.extra_flags = 0x01;  // reserved bit must be zero [MQTT-3.1.2-3]
    const wire::Pkt pkt = wire::make_connect("c", o);
    ConnectPacket c;
    CHECK(parse_connect(wire::body_of(pkt), c) == Err::malformed);
}

TEST(parse_connect_will_flag_consistency) {
    // will_retain without will flag: forbidden.
    wire::ConnectOpts o;
    o.extra_flags = connect_flags::will_retain;
    ConnectPacket c;
    CHECK(parse_connect(wire::body_of(wire::make_connect("c", o)), c) == Err::malformed);

    // will qos bits without will flag: forbidden.
    wire::ConnectOpts o2;
    o2.extra_flags = static_cast<uint8_t>(1u << connect_flags::will_qos_shift);
    CHECK(parse_connect(wire::body_of(wire::make_connect("c", o2)), c) == Err::malformed);

    // will qos = 3: forbidden.
    wire::ConnectOpts o3;
    o3.extra_flags = connect_flags::will_qos_mask;
    CHECK(parse_connect(wire::body_of(wire::make_connect("c", o3)), c) == Err::malformed);
}

TEST(parse_connect_password_needs_username) {
    wire::ConnectOpts o;
    o.password = "p";
    ConnectPacket c;
    CHECK(parse_connect(wire::body_of(wire::make_connect("c", o)), c) == Err::malformed);
}

TEST(parse_connect_truncated_and_trailing) {
    const wire::Pkt pkt = wire::make_connect("client-1");
    const ByteSpan body = wire::body_of(pkt);
    ConnectPacket c;
    CHECK(parse_connect(body.slice(0, body.len - 1), c) == Err::truncated);

    // Extra byte after the announced fields.
    uint8_t extended[128];
    for (size_t i = 0; i < body.len; ++i) {
        extended[i] = body[i];
    }
    extended[body.len] = 0xFF;
    CHECK(parse_connect(ByteSpan{extended, body.len + 1}, c) == Err::malformed);
}

TEST(parse_connect_reports_wrong_protocol) {
    wire::ConnectOpts o;
    o.protocol_name = "MQIsdp";
    o.protocol_level = 3;
    ConnectPacket c;
    CHECK(parse_connect(wire::body_of(wire::make_connect("c", o)), c) == Err::ok);
    CHECK(!c.protocol_name_ok);
    CHECK_EQ(c.protocol_level, 3);
}

// ------------------------------------------------------------- PUBLISH

TEST(parse_publish_qos0) {
    const wire::Pkt pkt = wire::make_publish("a/b", wire::bs("hello"), QoS::at_most_once, true);
    PublishPacket p;
    CHECK(parse_publish(pkt.data[0], wire::body_of(pkt), p) == Err::ok);
    CHECK(p.topic == StrView("a/b"));
    CHECK(p.payload == wire::bs("hello"));
    CHECK(p.qos == QoS::at_most_once);
    CHECK(p.retain);
    CHECK(!p.dup);
}

TEST(parse_publish_qos1_packet_id) {
    const wire::Pkt pkt =
        wire::make_publish("a", wire::bs("x"), QoS::at_least_once, false, true, 0x1234);
    PublishPacket p;
    CHECK(parse_publish(pkt.data[0], wire::body_of(pkt), p) == Err::ok);
    CHECK_EQ(p.packet_id, 0x1234u);
    CHECK(p.dup);
}

TEST(parse_publish_rejects_bad_flags) {
    PublishPacket p;
    // QoS 3 is malformed [MQTT-3.3.1-4].
    const uint8_t fb_qos3 = make_first_byte(PacketType::publish, 0x06);
    const wire::Pkt pkt = wire::make_publish("a", wire::bs("x"));
    CHECK(parse_publish(fb_qos3, wire::body_of(pkt), p) == Err::malformed);

    // DUP with QoS 0 is malformed [MQTT-3.3.1-2].
    const uint8_t fb_dup0 = make_first_byte(PacketType::publish, publish_dup_bit);
    CHECK(parse_publish(fb_dup0, wire::body_of(pkt), p) == Err::malformed);
}

TEST(parse_publish_rejects_zero_packet_id) {
    const wire::Pkt pkt =
        wire::make_publish("a", wire::bs("x"), QoS::at_least_once, false, false, 0);
    PublishPacket p;
    CHECK(parse_publish(pkt.data[0], wire::body_of(pkt), p) == Err::malformed);
}

TEST(parse_publish_empty_payload_ok) {
    const wire::Pkt pkt = wire::make_publish("a", ByteSpan{});
    PublishPacket p;
    CHECK(parse_publish(pkt.data[0], wire::body_of(pkt), p) == Err::ok);
    CHECK(p.payload.empty());
}

// ----------------------------------------------------- packet-id acks

TEST(parse_packet_id_only_cases) {
    uint16_t id = 0;
    const uint8_t good[] = {0x12, 0x34};
    CHECK(parse_packet_id_only(ByteSpan{good, 2}, id) == Err::ok);
    CHECK_EQ(id, 0x1234u);

    const uint8_t shrt[] = {0x12};
    CHECK(parse_packet_id_only(ByteSpan{shrt, 1}, id) == Err::truncated);

    const uint8_t trailing[] = {0x12, 0x34, 0x00};
    CHECK(parse_packet_id_only(ByteSpan{trailing, 3}, id) == Err::malformed);

    const uint8_t zero[] = {0x00, 0x00};
    CHECK(parse_packet_id_only(ByteSpan{zero, 2}, id) == Err::malformed);
}

// ------------------------------------------- SUBSCRIBE / UNSUBSCRIBE

TEST(topic_list_subscribe_iteration) {
    const wire::Pkt pkt = wire::make_subscribe(7, {{"a/+", 1}, {"b/#", 2}});
    TopicListParser p{wire::body_of(pkt), true};
    CHECK_EQ(p.packet_id(), 7u);

    StrView f;
    QoS q = QoS::at_most_once;
    CHECK(p.next(f, q));
    CHECK(f == StrView("a/+"));
    CHECK(q == QoS::at_least_once);
    CHECK(p.next(f, q));
    CHECK(f == StrView("b/#"));
    CHECK(q == QoS::exactly_once);
    CHECK(!p.next(f, q));
    CHECK(p.status() == Err::ok);
}

TEST(topic_list_empty_is_malformed) {
    const wire::Pkt pkt = wire::make_subscribe(7, {});
    TopicListParser p{wire::body_of(pkt), true};
    StrView f;
    QoS q;
    CHECK(!p.next(f, q));
    CHECK(p.status() == Err::malformed);  // [MQTT-3.8.3-3]
}

TEST(topic_list_bad_qos_is_malformed) {
    const wire::Pkt pkt = wire::make_subscribe(7, {{"a", 3}});
    TopicListParser p{wire::body_of(pkt), true};
    StrView f;
    QoS q;
    CHECK(!p.next(f, q));
    CHECK(p.status() == Err::malformed);
}

TEST(topic_list_zero_packet_id_is_malformed) {
    const wire::Pkt pkt = wire::make_subscribe(0, {{"a", 0}});
    TopicListParser p{wire::body_of(pkt), true};
    CHECK(p.status() == Err::malformed);
}

TEST(topic_list_unsubscribe_iteration) {
    const wire::Pkt pkt = wire::make_unsubscribe(9, {"x", "y/z"});
    TopicListParser p{wire::body_of(pkt), false};
    StrView f;
    QoS q;
    CHECK(p.next(f, q));
    CHECK(f == StrView("x"));
    CHECK(p.next(f, q));
    CHECK(f == StrView("y/z"));
    CHECK(!p.next(f, q));
    CHECK(p.status() == Err::ok);
}

// ------------------------------------------------------------ builders

TEST(build_connack_bytes) {
    uint8_t buf[16];
    const ByteSpan pkt = build_connack(buf, sizeof buf, true, ConnackCode::accepted);
    const uint8_t expect[] = {0x20, 0x02, 0x01, 0x00};
    CHECK(pkt == ByteSpan(expect, 4));

    const ByteSpan rejected = build_connack(buf, sizeof buf, false, ConnackCode::not_authorized);
    const uint8_t expect2[] = {0x20, 0x02, 0x00, 0x05};
    CHECK(rejected == ByteSpan(expect2, 4));
}

TEST(build_publish_bytes) {
    uint8_t buf[64];
    const ByteSpan pkt = build_publish(buf, sizeof buf, "a/b", wire::bs("hi"), QoS::at_least_once,
                                       true, false, 0x0102);
    // 0x33 = PUBLISH | qos1<<1 | retain; body: len(2)+topic(3)+id(2)+payload(2) = 9
    const uint8_t expect[] = {0x33, 0x09, 0x00, 0x03, 'a', '/', 'b', 0x01, 0x02, 'h', 'i'};
    CHECK(pkt == ByteSpan(expect, sizeof expect));
}

TEST(build_publish_too_big_fails) {
    uint8_t buf[8];
    CHECK(build_publish(buf, sizeof buf, "topic", wire::bs("payload"), QoS::at_most_once, false,
                        false, 0)
              .empty());
}

TEST(build_pubrel_has_mandated_flags) {
    uint8_t buf[16];
    const ByteSpan pkt = build_packet_id_only(buf, sizeof buf, PacketType::pubrel, 5);
    const uint8_t expect[] = {0x62, 0x02, 0x00, 0x05};
    CHECK(pkt == ByteSpan(expect, 4));
}

TEST(build_pingresp_bytes) {
    uint8_t buf[4];
    const ByteSpan pkt = build_pingresp(buf, sizeof buf);
    const uint8_t expect[] = {0xD0, 0x00};
    CHECK(pkt == ByteSpan(expect, 2));
}

// --------------------------------------------- post-review regressions

TEST(parse_publish_truncated_is_truncated_not_malformed) {
    // QoS 1 PUBLISH that ends right after the topic: the packet id is
    // missing, so the short read must be reported as truncation rather
    // than as the "packet id 0" malformation it looks like.
    uint8_t body[16];
    Writer w{body, sizeof body};
    w.utf8("a/b");
    PublishPacket p;
    const uint8_t fb = make_first_byte(PacketType::publish, 0x02);
    CHECK(parse_publish(fb, ByteSpan{body, w.size()}, p) == Err::truncated);

    // A genuinely zero packet id is still malformed.
    Writer w2{body, sizeof body};
    w2.utf8("a/b");
    w2.u16(0);
    CHECK(parse_publish(fb, ByteSpan{body, w2.size()}, p) == Err::malformed);
}

TEST(frame_packet_rejects_a_body_it_cannot_describe) {
    // varint() refuses anything above the Remaining Length maximum and
    // writes nothing; frame_packet must not hand back a span describing
    // bytes that were never written.
    uint8_t buf[64] = {0};
    CHECK(frame_packet(buf, make_first_byte(PacketType::publish, 0), max_remaining_length + 1)
              .empty());

    // The largest expressible body is still accepted.
    const ByteSpan ok =
        frame_packet(buf, make_first_byte(PacketType::publish, 0), max_remaining_length);
    CHECK(!ok.empty());
    CHECK_EQ(ok.len, 1u + 4u + max_remaining_length);
}

TEST(builders_reject_a_buffer_that_is_too_small) {
    uint8_t buf[packet_overhead + 1];  // one byte short of a 2-byte body
    CHECK(build_connack(buf, sizeof buf, false, ConnackCode::accepted).empty());
    CHECK(build_packet_id_only(buf, sizeof buf, PacketType::puback, 1).empty());
    CHECK(build_pingresp(buf, 1).empty());
}
