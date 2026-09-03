// Unit tests for the incremental frame parser.
// SPDX-License-Identifier: MIT
#include "test.hpp"
#include "wire_util.hpp"

#include <minimosq/protocol/frame.hpp>

using namespace minimosq;

namespace {

// Collects everything the parser emits.
struct Sink {
    struct Item {
        uint8_t first_byte;
        uint8_t body[512];
        size_t body_len;
    };
    Item items[8];
    size_t count = 0;
    size_t stop_after = static_cast<size_t>(-1);  // emit false after N packets

    bool operator()(uint8_t first_byte, ByteSpan body) {
        Item& it = items[count++];
        it.first_byte = first_byte;
        it.body_len = body.len;
        for (size_t i = 0; i < body.len; ++i) {
            it.body[i] = body[i];
        }
        return count != stop_after;
    }
};

}  // namespace

TEST(frame_single_packet) {
    FrameParser<512> fp;
    Sink sink;
    const wire::Pkt pkt = wire::make_publish("a/b", wire::bs("hi"));
    CHECK(fp.feed(pkt.span(), sink) == Err::ok);
    CHECK_EQ(sink.count, 1u);
    CHECK(packet_type(sink.items[0].first_byte) == PacketType::publish);
    CHECK(ByteSpan(sink.items[0].body, sink.items[0].body_len) == wire::body_of(pkt));
}

TEST(frame_byte_by_byte) {
    FrameParser<512> fp;
    Sink sink;
    const wire::Pkt pkt = wire::make_publish("t", wire::bs("payload"));
    for (size_t i = 0; i < pkt.len; ++i) {
        CHECK(fp.feed(pkt.span().slice(i, 1), sink) == Err::ok);
    }
    CHECK_EQ(sink.count, 1u);
    CHECK(ByteSpan(sink.items[0].body, sink.items[0].body_len) == wire::body_of(pkt));
}

TEST(frame_multiple_packets_in_one_feed) {
    FrameParser<512> fp;
    Sink sink;
    uint8_t stream[64];
    const wire::Pkt a = wire::make_pingreq();
    const wire::Pkt b = wire::make_publish("x", wire::bs("1"));
    const wire::Pkt c = wire::make_pingreq();
    size_t n = 0;
    for (const wire::Pkt* p : {&a, &b, &c}) {
        for (size_t i = 0; i < p->len; ++i) {
            stream[n++] = p->data[i];
        }
    }
    CHECK(fp.feed(ByteSpan{stream, n}, sink) == Err::ok);
    CHECK_EQ(sink.count, 3u);
    CHECK(packet_type(sink.items[0].first_byte) == PacketType::pingreq);
    CHECK(packet_type(sink.items[1].first_byte) == PacketType::publish);
    CHECK(packet_type(sink.items[2].first_byte) == PacketType::pingreq);
    CHECK_EQ(sink.items[0].body_len, 0u);
}

TEST(frame_two_byte_length) {
    // A body longer than 127 bytes forces a 2-byte Remaining Length.
    uint8_t big[200];
    for (size_t i = 0; i < sizeof big; ++i) {
        big[i] = static_cast<uint8_t>(i);
    }
    const wire::Pkt pkt = wire::make_publish("t", ByteSpan{big, sizeof big});
    FrameParser<512> fp;
    Sink sink;
    CHECK(fp.feed(pkt.span(), sink) == Err::ok);
    CHECK_EQ(sink.count, 1u);
    CHECK(ByteSpan(sink.items[0].body, sink.items[0].body_len) == wire::body_of(pkt));
}

TEST(frame_oversize_rejected) {
    FrameParser<16> fp;  // tiny body limit
    Sink sink;
    const wire::Pkt pkt = wire::make_publish("topic", wire::bs("this is too long"));
    CHECK(fp.feed(pkt.span(), sink) == Err::oversize);
    CHECK_EQ(sink.count, 0u);
}

TEST(frame_malformed_varint_rejected) {
    // Five continuation bytes: forbidden by [MQTT-2.2.3].
    const uint8_t bad[] = {0xC0, 0x80, 0x80, 0x80, 0x80, 0x01};
    FrameParser<512> fp;
    Sink sink;
    CHECK(fp.feed(ByteSpan{bad, sizeof bad}, sink) == Err::malformed);
}

TEST(frame_callback_stop_discards_rest) {
    FrameParser<512> fp;
    Sink sink;
    sink.stop_after = 1;
    uint8_t stream[16];
    const wire::Pkt a = wire::make_pingreq();
    const wire::Pkt b = wire::make_pingreq();
    size_t n = 0;
    for (const wire::Pkt* p : {&a, &b}) {
        for (size_t i = 0; i < p->len; ++i) {
            stream[n++] = p->data[i];
        }
    }
    CHECK(fp.feed(ByteSpan{stream, n}, sink) == Err::ok);
    CHECK_EQ(sink.count, 1u);  // second packet never delivered
}

TEST(frame_reset_recovers) {
    FrameParser<512> fp;
    Sink sink;
    const wire::Pkt pkt = wire::make_pingreq();
    // Feed half a packet, reset, then a full one.
    fp.feed(pkt.span().slice(0, 1), sink);
    fp.reset();
    CHECK(fp.feed(pkt.span(), sink) == Err::ok);
    CHECK_EQ(sink.count, 1u);
}

// A stop leaves the parser on a packet boundary, so a caller that keeps
// feeding — the contract scopes the "undefined state" warning to non-ok
// results, and a stop returns Err::ok — reads the next packet rather
// than this one again.
TEST(frame_stop_after_a_body_does_not_redeliver_it) {
    FrameParser<512> fp;
    Sink sink;
    sink.stop_after = 1;

    const uint8_t payload[] = {'t'};
    const wire::Pkt pub = wire::make_publish("a", ByteSpan{payload, sizeof payload});
    CHECK(fp.feed(pub.span(), sink) == Err::ok);
    CHECK_EQ(sink.count, 1u);

    // Feeding again must not re-fire the completed packet. Without the
    // fix the parser stayed in State::body with body_len_ == rem_len_,
    // so the completion branch fired once more per feed — for a QoS 1
    // PUBLISH, a duplicate delivery to every subscriber.
    sink.stop_after = 0;
    const wire::Pkt ping = wire::make_pingreq();
    CHECK(fp.feed(ping.span(), sink) == Err::ok);
    CHECK_EQ(sink.count, 2u);  // the PUBLISH once, then the PINGREQ
    CHECK_EQ(sink.items[1].first_byte, ping.data[0]);
}

TEST(frame_stop_after_a_zero_length_packet_stays_in_sync) {
    FrameParser<512> fp;
    Sink sink;
    sink.stop_after = 1;

    const wire::Pkt ping = wire::make_pingreq();
    CHECK(fp.feed(ping.span(), sink) == Err::ok);
    CHECK_EQ(sink.count, 1u);

    // Without the fix the parser stayed in State::length and swallowed
    // the next first byte as a length continuation, desynchronising the
    // stream: two further PINGREQs produced no callbacks at all.
    sink.stop_after = 0;
    uint8_t two[8];
    size_t n = 0;
    for (int k = 0; k < 2; ++k) {
        for (size_t i = 0; i < ping.len; ++i) {
            two[n++] = ping.data[i];
        }
    }
    CHECK(fp.feed(ByteSpan{two, n}, sink) == Err::ok);
    CHECK_EQ(sink.count, 3u);
}
