// Protocol-violation handling: what the broker does with input a
// conforming client never sends.
//
// Every case here is a rule the specification states and docs/design.md
// records as a policy, but which nothing exercised — the paths a hostile
// or broken client reaches first. They matter more than the happy path,
// because getting them wrong means either accepting malformed input or
// dropping a connection that should have survived.
//
// SPDX-License-Identifier: MIT
#include "broker_util.hpp"

using namespace bt;

namespace {

// A packet built byte by byte, for shapes the wire helpers deliberately
// cannot produce: reserved types, illegal flag nibbles, oversize bodies.
wire::Pkt raw(uint8_t first_byte, std::initializer_list<uint8_t> body) {
    wire::Pkt p;
    p.data[0] = first_byte;
    p.data[1] = static_cast<uint8_t>(body.size());
    size_t i = 2;
    for (const uint8_t b : body) {
        p.data[i++] = b;
    }
    p.len = i;
    return p;
}

// A connected client with its CONNACK already drained.
void connected(Bed& x, size_t ci, const char* id) {
    x.connect(ci, id);
    expect_connack(x.t, ci, false, ConnackCode::accepted);
}

}  // namespace

// ------------------------------------------------ fixed-header rules

TEST(non_publish_packets_with_wrong_flag_nibbles_are_rejected) {
    // [MQTT-2.2.2-2]: the flag bits of every non-PUBLISH packet are
    // mandated, and a mismatch is a protocol violation rather than
    // something to ignore.
    struct Case {
        PacketType type;
        uint8_t bad_flags;
    };
    const Case cases[] = {
        {PacketType::puback, 0x0F},       // must be 0x00
        {PacketType::pingreq, 0x01},      // must be 0x00
        {PacketType::pubrel, 0x00},       // must be 0x02
        {PacketType::subscribe, 0x00},    // must be 0x02
        {PacketType::unsubscribe, 0x0A},  // must be 0x02
    };

    for (const Case& c : cases) {
        Bed x;
        connected(x, 0, "alice");
        x.feed(0, raw(make_first_byte(c.type, c.bad_flags), {0x00, 0x01}));
        CHECK(x.t.logs[0].closed);
        expect_silence(x.t, 0);
    }
}

TEST(server_to_client_packet_types_from_a_client_are_rejected) {
    // A client has no business sending these; they only travel
    // broker to client.
    const PacketType server_only[] = {PacketType::connack, PacketType::suback, PacketType::unsuback,
                                      PacketType::pingresp};
    for (const PacketType t : server_only) {
        Bed x;
        connected(x, 0, "alice");
        x.feed(0, raw(make_first_byte(t, 0), {}));
        CHECK(x.t.logs[0].closed);
    }
}

TEST(reserved_packet_types_are_rejected) {
    // Types 0 and 15 are Reserved/Forbidden in [MQTT-2.2.1].
    for (const uint8_t type : {uint8_t{0}, uint8_t{15}}) {
        Bed x;
        connected(x, 0, "alice");
        x.feed(0, raw(static_cast<uint8_t>(type << 4), {}));
        CHECK(x.t.logs[0].closed);
    }
}

// ------------------------------------------------------ framing rules

TEST(oversize_packet_closes_the_connection) {
    // Bigger than Traits::max_packet_size: the broker must refuse it
    // outright rather than buffer it, since the buffer is fixed.
    Bed x;
    connected(x, 0, "alice");

    wire::Pkt p;
    p.data[0] = make_first_byte(PacketType::publish, 0);
    // Remaining Length 300, as a two-byte varint, against a 256-byte cap.
    p.data[1] = 0xAC;
    p.data[2] = 0x02;
    p.len = 3 + 300;
    x.feed(0, p);
    CHECK(x.t.logs[0].closed);
}

TEST(malformed_remaining_length_closes_the_connection) {
    // A Remaining Length varint may be at most four bytes [MQTT-2.2.3];
    // a fifth continuation byte is malformed.
    Bed x;
    connected(x, 0, "alice");

    wire::Pkt p;
    p.data[0] = make_first_byte(PacketType::publish, 0);
    p.data[1] = 0x80;
    p.data[2] = 0x80;
    p.data[3] = 0x80;
    p.data[4] = 0x80;
    p.data[5] = 0x01;
    p.len = 6;
    x.feed(0, p);
    CHECK(x.t.logs[0].closed);
}

// ------------------------------------------- packets with a stray body

TEST(pingreq_with_a_body_is_a_violation) {
    Bed x;
    connected(x, 0, "alice");
    x.feed(0, raw(make_first_byte(PacketType::pingreq, 0), {0x00}));
    CHECK(x.t.logs[0].closed);
    expect_silence(x.t, 0);  // no PINGRESP for a malformed PINGREQ
}

TEST(disconnect_with_a_body_is_a_violation) {
    // A stray body makes DISCONNECT a protocol error, which means it is
    // *not* the clean disconnect that discards the will.
    Bed x;
    wire::ConnectOpts o;
    o.will_topic = "gone/alice";
    o.will_payload = wire::bs("bye");
    x.connect(0, "alice", o);
    expect_connack(x.t, 0, false, ConnackCode::accepted);

    connected(x, 1, "watcher");
    x.feed(1, wire::make_subscribe(1, {{"gone/+", 0}}));
    const uint8_t codes[] = {0};
    expect_suback(x.t, 1, 1, codes);

    x.feed(0, raw(make_first_byte(PacketType::disconnect, 0), {0x00}));
    CHECK(x.t.logs[0].closed);
    // Abnormal close, so the will fires [MQTT-3.1.2-8].
    expect_publish(x.t, 1, "gone/alice", wire::bs("bye"), QoS::at_most_once, false);
}

TEST(malformed_acknowledgement_bodies_close_the_connection) {
    // PUBACK, PUBREC, PUBREL, PUBCOMP and UNSUBACK all carry exactly a
    // two-byte packet identifier. Anything else is a violation, and a
    // zero identifier is forbidden by [MQTT-2.3.1-1].
    struct Case {
        PacketType type;
        uint8_t flags;
    };
    const Case cases[] = {
        {PacketType::puback, 0x00},
        {PacketType::pubrec, 0x00},
        {PacketType::pubrel, 0x02},
        {PacketType::pubcomp, 0x00},
    };

    for (const Case& c : cases) {
        Bed truncated;
        connected(truncated, 0, "alice");
        truncated.feed(0, raw(make_first_byte(c.type, c.flags), {0x00}));  // one byte short
        CHECK(truncated.t.logs[0].closed);

        Bed trailing;
        connected(trailing, 0, "alice");
        trailing.feed(0, raw(make_first_byte(c.type, c.flags), {0x00, 0x01, 0xFF}));
        CHECK(trailing.t.logs[0].closed);

        Bed zero_id;
        connected(zero_id, 0, "alice");
        zero_id.feed(0, raw(make_first_byte(c.type, c.flags), {0x00, 0x00}));
        CHECK(zero_id.t.logs[0].closed);
    }
}

// --------------------------------------------------- CONNECT validity

TEST(truncated_connect_closes_without_a_connack) {
    // The broker cannot answer a CONNECT it could not parse, so it must
    // close silently rather than guess a return code.
    Bed x;
    x.open(0);
    x.feed(0, raw(make_first_byte(PacketType::connect, 0), {0x00, 0x04, 'M', 'Q'}));
    CHECK(x.t.logs[0].closed);
    expect_silence(x.t, 0);
}

TEST(will_topic_with_a_wildcard_closes_the_connection) {
    // A will topic is a topic *name*: wildcards are not allowed
    // [MQTT-3.1.3.1], and this is a protocol error rather than a
    // refusal, so no CONNACK is sent.
    Bed x;
    wire::ConnectOpts o;
    o.will_topic = "sensors/+/died";
    o.will_payload = wire::bs("x");
    x.connect(0, "alice", o);
    CHECK(x.t.logs[0].closed);
    expect_silence(x.t, 0);
}

TEST(will_beyond_capacity_is_refused_with_server_unavailable) {
    // Documented capacity policy: a will the broker cannot store is
    // refused cleanly with CONNACK 0x03 rather than silently dropped,
    // so the client knows its will will not fire.
    {
        Bed x;
        uint8_t big[SmallTraits::max_payload_len + 1];
        for (uint8_t& b : big) {
            b = 'x';
        }
        wire::ConnectOpts o;
        o.will_topic = "gone/alice";
        o.will_payload = ByteSpan{big, sizeof big};
        x.connect(0, "alice", o);
        expect_connack(x.t, 0, false, ConnackCode::server_unavailable);
        CHECK(x.t.logs[0].closed);
    }
    {
        Bed x;
        char long_topic[SmallTraits::max_topic_len + 2];
        for (char& ch : long_topic) {
            ch = 'a';
        }
        long_topic[sizeof long_topic - 1] = '\0';
        wire::ConnectOpts o;
        o.will_topic = long_topic;
        o.will_payload = wire::bs("x");
        x.connect(0, "alice", o);
        expect_connack(x.t, 0, false, ConnackCode::server_unavailable);
    }
}

// ------------------------------------------- empty (UN)SUBSCRIBE lists

TEST(subscribe_with_no_filters_is_a_violation) {
    // [MQTT-3.8.3-3]: a SUBSCRIBE must carry at least one filter.
    Bed x;
    connected(x, 0, "alice");
    x.feed(0, raw(make_first_byte(PacketType::subscribe, 0x02), {0x00, 0x01}));
    CHECK(x.t.logs[0].closed);
    expect_silence(x.t, 0);
}

TEST(unsubscribe_with_no_filters_is_a_violation) {
    // [MQTT-3.10.3-2], the same rule for UNSUBSCRIBE.
    Bed x;
    connected(x, 0, "alice");
    x.feed(0, raw(make_first_byte(PacketType::unsubscribe, 0x02), {0x00, 0x01}));
    CHECK(x.t.logs[0].closed);
    expect_silence(x.t, 0);
}

TEST(truncated_subscribe_payload_is_a_violation) {
    // A filter length that runs off the end of the packet.
    Bed x;
    connected(x, 0, "alice");
    x.feed(0, raw(make_first_byte(PacketType::subscribe, 0x02),
                  {0x00, 0x01, 0x00, 0x20, 'a'}));  // announces 32 bytes, supplies 1
    CHECK(x.t.logs[0].closed);
}

// ------------------------------------------------ transport-side guards

TEST(connection_index_misuse_is_reported_not_crashed) {
    // The transport contract says indices are dense and in range. If a
    // transport breaks it, the broker must refuse rather than corrupt
    // its own state.
    Bed x;
    CHECK(x.b.conn_open(0, 1000) == Err::ok);
    CHECK(x.b.conn_open(0, 1000) == Err::state);  // already active
    CHECK(x.b.conn_open(SmallTraits::max_connections, 1000) == Err::state);
    CHECK(x.b.conn_open(9999, 1000) == Err::state);

    // Data for a connection that was never opened.
    const wire::Pkt ping = wire::make_pingreq();
    CHECK(x.b.conn_data(1, ping.span(), 1000) == Err::state);
    CHECK(x.b.conn_data(9999, ping.span(), 1000) == Err::state);

    // Closing something unknown is a no-op, not a fault.
    x.b.conn_closed(2);
    x.b.conn_closed(9999);
    CHECK(!x.t.logs[0].closed);
}

// ------------------------------------------------ application publish

TEST(app_publish_rejects_an_invalid_topic) {
    // The application-side entry point validates its topic like any
    // other publisher: no wildcards, no empty name, well-formed UTF-8.
    Bed x;
    CHECK(x.b.publish("", wire::bs("v"), QoS::at_most_once, false) == Err::malformed);
    CHECK(x.b.publish("a/+/b", wire::bs("v"), QoS::at_most_once, false) == Err::malformed);
    CHECK(x.b.publish("a/#", wire::bs("v"), QoS::at_most_once, false) == Err::malformed);

    const char bad_utf8[] = {'a', static_cast<char>(0xC3), '\0'};  // truncated sequence
    CHECK(x.b.publish(StrView{bad_utf8, 2}, wire::bs("v"), QoS::at_most_once, false) ==
          Err::malformed);
}

TEST(app_publish_reports_capacity_when_the_retained_store_is_full) {
    // The message is still delivered live; only the retained copy is
    // dropped, and the caller is told which happened.
    Bed x;
    connected(x, 0, "sub");
    x.feed(0, wire::make_subscribe(1, {{"full/#", 0}}));
    const uint8_t codes[] = {0};
    expect_suback(x.t, 0, 1, codes);

    for (size_t i = 0; i < SmallTraits::max_retained; ++i) {
        char topic[16];
        std::snprintf(topic, sizeof topic, "fill/%zu", i);
        CHECK(x.b.publish(topic, wire::bs("v"), QoS::at_most_once, /*retain=*/true) == Err::ok);
    }
    CHECK_EQ(x.b.retained_count(), SmallTraits::max_retained);

    // One more retained topic has nowhere to go.
    CHECK(x.b.publish("full/extra", wire::bs("late"), QoS::at_most_once, /*retain=*/true) ==
          Err::capacity);
    // ...but the live subscriber still receives it.
    expect_publish(x.t, 0, "full/extra", wire::bs("late"), QoS::at_most_once, false);
}

TEST(app_publish_rejects_a_payload_that_could_never_be_built) {
    Bed x;
    uint8_t huge[SmallTraits::max_packet_size + 64];
    for (uint8_t& b : huge) {
        b = 'x';
    }
    CHECK(x.b.publish("big/one", ByteSpan{huge, sizeof huge}, QoS::at_most_once, false) ==
          Err::oversize);
}
