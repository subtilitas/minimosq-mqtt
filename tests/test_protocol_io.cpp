// Unit tests for the wire primitives: Reader, Writer, varint encoding.
// SPDX-License-Identifier: MIT
#include "test.hpp"

#include <minimosq/protocol/constants.hpp>
#include <minimosq/protocol/reader.hpp>
#include <minimosq/protocol/writer.hpp>

using namespace minimosq;

TEST(reader_reads_big_endian) {
    const uint8_t raw[] = {0x12, 0x01, 0x02, 0xAB, 0xCD};
    Reader r{ByteSpan{raw, sizeof raw}};
    CHECK_EQ(r.u8(), 0x12);
    CHECK_EQ(r.u16(), 0x0102);
    CHECK_EQ(r.u16(), 0xABCD);
    CHECK(r.ok());
    CHECK(r.at_end());
}

TEST(reader_failure_is_sticky) {
    const uint8_t raw[] = {0x01};
    Reader r{ByteSpan{raw, 1}};
    CHECK_EQ(r.u16(), 0);  // underrun
    CHECK(!r.ok());
    CHECK_EQ(r.u8(), 0);  // still failing even though a byte "exists"
    CHECK(!r.ok());
}

TEST(reader_len_prefixed) {
    // "ab" as a length-prefixed string, then one trailing byte.
    const uint8_t raw[] = {0x00, 0x02, 'a', 'b', 0x07};
    Reader r{ByteSpan{raw, sizeof raw}};
    CHECK(r.utf8() == StrView("ab"));
    CHECK_EQ(r.u8(), 0x07);
    CHECK(r.ok());

    // Declared length exceeds the available bytes.
    const uint8_t bad[] = {0x00, 0x05, 'a'};
    Reader r2{ByteSpan{bad, sizeof bad}};
    CHECK(r2.utf8().empty());
    CHECK(!r2.ok());
}

TEST(reader_rest) {
    const uint8_t raw[] = {1, 2, 3};
    Reader r{ByteSpan{raw, 3}};
    r.u8();
    CHECK(r.rest() == ByteSpan(raw + 1, 2));
    CHECK(r.at_end());
    CHECK(r.ok());
}

TEST(writer_round_trip) {
    uint8_t buf[32];
    Writer w{buf, sizeof buf};
    w.u8(0x10);
    w.u16(0xBEEF);
    w.utf8("hi");
    CHECK(w.ok());
    CHECK_EQ(w.size(), 7u);

    Reader r{w.span()};
    CHECK_EQ(r.u8(), 0x10);
    CHECK_EQ(r.u16(), 0xBEEF);
    CHECK(r.utf8() == StrView("hi"));
    CHECK(r.at_end());
}

TEST(writer_overflow_is_sticky) {
    uint8_t buf[3];
    Writer w{buf, sizeof buf};
    w.u16(1);
    w.u16(2);  // does not fit
    CHECK(!w.ok());
    w.u8(3);  // still failing even though one byte would fit
    CHECK(!w.ok());
}

TEST(varint_boundaries) {
    // Encoded sizes at the MQTT-defined boundaries, [MQTT-2.2.3].
    CHECK_EQ(varint_size(0), 1u);
    CHECK_EQ(varint_size(127), 1u);
    CHECK_EQ(varint_size(128), 2u);
    CHECK_EQ(varint_size(16383), 2u);
    CHECK_EQ(varint_size(16384), 3u);
    CHECK_EQ(varint_size(2097151), 3u);
    CHECK_EQ(varint_size(2097152), 4u);
    CHECK_EQ(varint_size(max_remaining_length), 4u);

    const uint32_t samples[] = {0,     1,     127,     128,     321,
                                16383, 16384, 2097151, 2097152, max_remaining_length};
    for (uint32_t v : samples) {
        uint8_t buf[8];
        Writer w{buf, sizeof buf};
        w.varint(v);
        CHECK(w.ok());
        CHECK_EQ(w.size(), varint_size(v));
        // Spec example: 321 encodes as 0xC1 0x02.
        if (v == 321) {
            CHECK_EQ(buf[0], 0xC1);
            CHECK_EQ(buf[1], 0x02);
        }
    }

    uint8_t buf[8];
    Writer w{buf, sizeof buf};
    w.varint(max_remaining_length + 1);
    CHECK(!w.ok());
}

TEST(first_byte_helpers) {
    const uint8_t fb = make_first_byte(PacketType::publish, 0x0B);
    CHECK(packet_type(fb) == PacketType::publish);
    CHECK_EQ(packet_flags(fb), 0x0B);

    CHECK(fixed_flags_valid(PacketType::pubrel, 0x02));
    CHECK(!fixed_flags_valid(PacketType::pubrel, 0x00));
    CHECK(fixed_flags_valid(PacketType::pingreq, 0x00));
    CHECK(!fixed_flags_valid(PacketType::connect, 0x01));
    CHECK(fixed_flags_valid(PacketType::publish, 0x0D));  // PUBLISH flags are free-form here
}

// ------------------------------------------ sticky failure, in detail
//
// Reader and Writer promise that once a read or write runs past the end,
// every later call is a no-op returning an empty/zero value. Parsing
// code leans on that to stay linear — it checks ok() once at the end
// instead of after every field — so the promise has to hold for the
// compound accessors too, not just the primitive ones.

TEST(reader_compound_reads_are_no_ops_after_failure) {
    const uint8_t raw[] = {0x00, 0x02, 'h', 'i'};
    Reader r{ByteSpan{raw, sizeof raw}};

    CHECK(r.len_prefixed_bytes() == ByteSpan(raw + 2, 2));
    CHECK(r.ok());
    CHECK(r.at_end());

    // Reading past the end trips the sticky flag...
    (void)r.u8();
    CHECK(!r.ok());

    // ...and every compound accessor then yields nothing without
    // touching the buffer.
    CHECK(r.len_prefixed_bytes().empty());
    CHECK(r.utf8().empty());
    CHECK(r.rest().empty());
    CHECK(r.bytes(1).empty());
    CHECK(!r.ok());
}

TEST(reader_rejects_a_length_prefix_longer_than_the_buffer) {
    // The prefix announces 8 bytes but only 2 follow: a truncated
    // packet, not a short string.
    const uint8_t raw[] = {0x00, 0x08, 'h', 'i'};
    Reader r{ByteSpan{raw, sizeof raw}};
    CHECK(r.len_prefixed_bytes().empty());
    CHECK(!r.ok());
}

TEST(writer_refuses_a_string_longer_than_the_wire_allows) {
    // MQTT strings carry a 16-bit length, so anything above 65535 has no
    // representation. The check is on the length alone, so it can be
    // exercised without allocating 64 KB.
    uint8_t buf[8];
    Writer w{buf, sizeof buf};
    const char text[] = "irrelevant";
    w.utf8(StrView{text, 65536});
    CHECK(!w.ok());
    CHECK_EQ(w.size(), 0u);  // nothing was written
}

TEST(writer_refuses_a_varint_beyond_the_remaining_length_maximum) {
    uint8_t buf[8];
    Writer w{buf, sizeof buf};
    w.varint(max_remaining_length + 1);
    CHECK(!w.ok());
    CHECK_EQ(w.size(), 0u);

    Writer ok{buf, sizeof buf};
    ok.varint(max_remaining_length);
    CHECK(ok.ok());
    CHECK_EQ(ok.size(), 4u);
}
