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
