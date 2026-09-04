// Compile- and plumbing-test for the TLS seam: a broker behind
// TlsAdapter<NullTlsEngine> must behave exactly like a bare broker.
// SPDX-License-Identifier: MIT
#include "broker_util.hpp"

#include <minimosq/transports/tls_adapter.hpp>

using namespace bt;

TEST(tls_adapter_passes_mqtt_through) {
    using Raw = CaptureTransport<SmallTraits::max_connections>;
    using Tls = TlsAdapter<NullTlsEngine, Raw, SmallTraits::max_connections>;

    Raw raw;
    Tls tls{raw};
    Broker<SmallTraits, Tls> broker{tls};
    auto driver = tls.driver(broker);

    // Drive the *driver* exactly like a raw transport would.
    CHECK(driver.conn_open(0, 1000) == Err::ok);
    CHECK(driver.conn_data(0, wire::make_connect("tls-client").span(), 1000) == Err::ok);
    expect_connack(raw, 0, false, ConnackCode::accepted);

    CHECK(driver.conn_data(0, wire::make_subscribe(1, {{"t", 0}}).span(), 1000) == Err::ok);
    const uint8_t codes[] = {0x00};
    expect_suback(raw, 0, 1, codes);

    CHECK(driver.conn_data(0, wire::make_publish("t", wire::bs("sealed")).span(), 1000) == Err::ok);
    expect_publish(raw, 0, "t", wire::bs("sealed"), QoS::at_most_once, false);
    expect_silence(raw, 0);

    driver.conn_closed(0);
    driver.tick(2000);
}

// The adapter's job is not just pass-through. It has to carry handshake
// bytes the engine produces, drop the connection when the engine fails,
// and refuse an index outside its own capacity. None of that was
// covered by the plumbing test above.

namespace {

using Raw = CaptureTransport<SmallTraits::max_connections>;

// An engine with a scripted handshake: the first record it sees produces
// ciphertext to transmit and no plaintext, as a real TLS library does
// mid-handshake. After that it behaves like NullTlsEngine.
struct HandshakeEngine {
    bool handshaken = false;
    bool fail_next = false;

    void reset() noexcept {
        handshaken = false;
        fail_next = false;
    }

    bool on_ciphertext(ByteSpan in, uint8_t* plain, size_t plain_cap, size_t& plain_len,
                       uint8_t* cipher, size_t cipher_cap, size_t& cipher_len) noexcept {
        plain_len = 0;
        cipher_len = 0;
        if (fail_next) {
            return false;  // fatal TLS error
        }
        if (!handshaken) {
            handshaken = true;
            const char reply[] = "SERVER-HELLO";
            const size_t n = sizeof reply - 1;
            if (n > cipher_cap) {
                return false;
            }
            for (size_t i = 0; i < n; ++i) {
                cipher[i] = static_cast<uint8_t>(reply[i]);
            }
            cipher_len = n;
            return true;  // handshake record consumed, no application data
        }
        if (in.len > plain_cap) {
            return false;
        }
        for (size_t i = 0; i < in.len; ++i) {
            plain[i] = in.data[i];
        }
        plain_len = in.len;
        return true;
    }

    bool encrypt(ByteSpan plain, uint8_t* cipher, size_t cipher_cap, size_t& cipher_len) noexcept {
        if (plain.len > cipher_cap) {
            return false;
        }
        for (size_t i = 0; i < plain.len; ++i) {
            cipher[i] = plain.data[i];
        }
        cipher_len = plain.len;
        return true;
    }
};

using HsTls = TlsAdapter<HandshakeEngine, Raw, SmallTraits::max_connections>;

}  // namespace

TEST(tls_adapter_writes_handshake_records_to_the_raw_transport) {
    Raw raw;
    HsTls tls{raw};
    Broker<SmallTraits, HsTls> broker{tls};
    auto driver = tls.driver(broker);

    CHECK(driver.conn_open(0, 1000) == Err::ok);

    // The handshake record yields ciphertext but no MQTT: the broker
    // must not see anything, and the bytes must reach the wire.
    const uint8_t hello[] = {'C', 'L', 'I', 'E', 'N', 'T'};
    CHECK(driver.conn_data(0, ByteSpan{hello, sizeof hello}, 1000) == Err::ok);
    CHECK_EQ(raw.logs[0].len, 12u);  // "SERVER-HELLO"
    raw.logs[0].rpos = raw.logs[0].len;

    // Once the handshake is done, MQTT flows as usual.
    CHECK(driver.conn_data(0, wire::make_connect("tls-client").span(), 1000) == Err::ok);
    expect_connack(raw, 0, false, ConnackCode::accepted);
}

TEST(tls_adapter_drops_the_connection_when_the_engine_fails) {
    Raw raw;
    HsTls tls{raw};
    Broker<SmallTraits, HsTls> broker{tls};
    auto driver = tls.driver(broker);

    CHECK(driver.conn_open(0, 1000) == Err::ok);
    const uint8_t hello[] = {'C', 'L', 'I', 'E', 'N', 'T'};
    CHECK(driver.conn_data(0, ByteSpan{hello, sizeof hello}, 1000) == Err::ok);
    raw.logs[0].rpos = raw.logs[0].len;

    // A fatal TLS error must tear the connection down at both ends
    // rather than pass anything to the broker.
    HandshakeEngine* engine = tls.engine(0);
    CHECK(engine != nullptr);
    engine->fail_next = true;

    const uint8_t garbage[] = {0xDE, 0xAD};
    CHECK(driver.conn_data(0, ByteSpan{garbage, sizeof garbage}, 1000) == Err::malformed);
    CHECK(raw.logs[0].closed);
}

TEST(tls_adapter_refuses_indices_outside_its_capacity) {
    // Same contract as the raw transports: an out-of-range index is
    // refused, never used to index the engine array.
    Raw raw;
    HsTls tls{raw};
    Broker<SmallTraits, HsTls> broker{tls};
    auto driver = tls.driver(broker);

    CHECK(tls.engine(SmallTraits::max_connections) == nullptr);
    CHECK(tls.engine(9999) == nullptr);
    CHECK(tls.engine(0) != nullptr);

    const uint8_t byte = 0x42;
    CHECK(!tls.send(SmallTraits::max_connections, ByteSpan{&byte, 1}));
    tls.close(SmallTraits::max_connections);  // must not touch raw

    CHECK(driver.conn_open(SmallTraits::max_connections, 1000) == Err::state);
    CHECK(driver.conn_data(SmallTraits::max_connections, ByteSpan{&byte, 1}, 1000) == Err::state);
    driver.conn_closed(SmallTraits::max_connections);
    CHECK(!raw.logs[0].closed);
}

TEST(tls_adapter_capacity_is_visible_to_the_broker) {
    static_assert(HsTls::max_connections == SmallTraits::max_connections,
                  "the adapter must publish its capacity like a raw transport");
    static_assert(transport_max_connections<HsTls>::value == SmallTraits::max_connections,
                  "so Broker's static_assert can check it");

    static_assert(transport_out_buf_size<HsTls>::value == HsTls::out_buf_size,
                  "the adapter must publish its packet bound as well, or a "
                  "TLS-wrapped transport opts out of the check silently");
    static_assert(transport_out_buf_size<HsTls>::value >= SmallTraits::max_packet_size,
                  "and this fixture must satisfy it, as Broker requires");
    CHECK_EQ(transport_out_buf_size<HsTls>::value, HsTls::out_buf_size);
    CHECK(transport_out_buf_size<HsTls>::value >= SmallTraits::max_packet_size);
}

namespace {
// A raw transport that publishes both capacities, and is tighter than
// the adapter wrapped around it on each.
struct NarrowRaw {
    static constexpr size_t max_connections = 2;
    static constexpr size_t out_buf_size = 64;
    bool send(size_t, ByteSpan) { return true; }
    void close(size_t) {}
};

// A raw transport that publishes neither.
struct SilentRaw {
    bool send(size_t, ByteSpan) { return true; }
    void close(size_t) {}
};
}  // namespace

// The adapter is what the broker's static_asserts inspect, so publishing
// its own template parameters hides the transport underneath: the broker
// would check a scratch buffer and a slot count that no byte ever passes
// through. Both are the narrower of the adapter's and the wrapped
// transport's.
TEST(tls_adapter_publishes_the_narrower_capacity) {
    using OverTls = TlsAdapter<NullTlsEngine, NarrowRaw, 16, 4096>;
    static_assert(OverTls::max_connections == 2,
                  "the wrapped transport's slots, not the adapter's 16: handing out an "
                  "index the raw transport refuses closes the fresh socket");
    static_assert(transport_max_connections<OverTls>::value == 2,
                  "and that is the number Broker's check sees");
    CHECK_EQ(OverTls::max_connections, size_t{2});

    static_assert(OverTls::out_buf_size == 64,
                  "and the wrapped transport's ring, not the adapter's 4096 scratch");
    CHECK_EQ(OverTls::out_buf_size, size_t{64});

    // The published capacity is the bound the adapter itself uses, so it
    // hands out no engine for an index the wrapped transport refuses.
    NarrowRaw raw;
    OverTls tls{raw};
    CHECK(tls.engine(0) != nullptr);
    CHECK(tls.engine(1) != nullptr);
    CHECK(tls.engine(2) == nullptr);   // past the wrapped transport's slots
    CHECK(tls.engine(15) == nullptr);  // and well past, though MaxConns is 16

    // A wrapped transport that publishes nothing constrains nothing, so
    // the adapter's own numbers stand.
    using OverUnbuffered = TlsAdapter<NullTlsEngine, SilentRaw, 16, 4096>;
    static_assert(OverUnbuffered::max_connections == 16, "nothing to narrow against");
    static_assert(OverUnbuffered::out_buf_size == 4096, "likewise for the buffer");
    CHECK_EQ(OverUnbuffered::out_buf_size, size_t{4096});

    // And the adapter is the tighter one when its own buffer is smaller.
    using TightScratch = TlsAdapter<NullTlsEngine, SilentRaw, 4, 128>;
    static_assert(TightScratch::out_buf_size == 128, "the adapter's own scratch bound");
    CHECK_EQ(TightScratch::out_buf_size, size_t{128});
}

// ------------------------------------------- buffering engines and sizing

namespace {
// Holds the first record it is given and only yields it when drained —
// the shape the Engine contract permits ("the library can buffer") and
// which nothing used to pump.
struct BufferingEngine {
    static constexpr size_t record_overhead = 8;

    uint8_t held[256];
    size_t held_len = 0;

    bool on_ciphertext(ByteSpan in, uint8_t* plain, size_t plain_cap, size_t& plain_len, uint8_t*,
                       size_t, size_t& cipher_len) {
        cipher_len = 0;
        plain_len = in.len < plain_cap ? in.len : plain_cap;
        for (size_t i = 0; i < plain_len; ++i) {
            plain[i] = in.data[i];
        }
        return true;
    }

    // Accepts the plaintext and writes nothing: the record is buffered.
    bool encrypt(ByteSpan plain, uint8_t*, size_t, size_t& cipher_len) {
        cipher_len = 0;
        if (held_len == 0 && plain.len <= sizeof held) {
            for (size_t i = 0; i < plain.len; ++i) {
                held[i] = plain.data[i];
            }
            held_len = plain.len;
        }
        return true;
    }

    void reset() { held_len = 0; }

    bool drain(uint8_t* cipher, size_t cipher_cap, size_t& cipher_len) {
        cipher_len = held_len <= cipher_cap ? held_len : 0;
        for (size_t i = 0; i < cipher_len; ++i) {
            cipher[i] = held[i];
        }
        held_len = 0;
        return true;
    }
};
}  // namespace

TEST(a_buffered_record_is_drained_rather_than_stranded) {
    static_assert(engine_has_drain<BufferingEngine>::value, "the engine offers drain()");
    static_assert(!engine_has_drain<NullTlsEngine>::value,
                  "and an engine that never buffers may omit it");

    using RawCapture = CaptureTransport<SmallTraits::max_connections>;
    using Tls = TlsAdapter<BufferingEngine, RawCapture, SmallTraits::max_connections>;
    RawCapture raw;
    Tls tls{raw};
    Broker<SmallTraits, Tls> b{tls};
    auto driver = tls.driver(b);

    CHECK(driver.conn_open(0, 1000) == Err::ok);
    const wire::Pkt connect = wire::make_connect("buffered");
    driver.conn_data(0, connect.span(), 1000);

    // encrypt() took the CONNACK and reported success with nothing
    // written, so the raw transport has seen no bytes yet.
    CHECK_EQ(raw.logs[0].len, size_t{0});

    // The pass drains it.
    driver.tick(1100);
    CHECK(raw.logs[0].len > 0);
}

// A drain() refusal is a fatal TLS error, and a write the raw transport
// refuses has already taken the record out of the engine — the peer's
// stream would resume mid-record. Both end the connection rather than
// losing bytes quietly.
namespace {
struct FailingDrainEngine : BufferingEngine {
    bool drain(uint8_t*, size_t, size_t& cipher_len) {
        cipher_len = 0;
        return false;  // fatal
    }
};
}  // namespace

TEST(a_failed_drain_closes_the_connection) {
    using RawCapture = CaptureTransport<SmallTraits::max_connections>;
    using Tls = TlsAdapter<FailingDrainEngine, RawCapture, SmallTraits::max_connections>;
    RawCapture raw;
    Tls tls{raw};
    Broker<SmallTraits, Tls> b{tls};
    auto driver = tls.driver(b);

    CHECK(driver.conn_open(0, 1000) == Err::ok);
    driver.tick(1100);
    CHECK(raw.logs[0].closed);  // not left half-open with bytes lost
}

TEST(the_published_buffer_size_accounts_for_record_growth) {
    using RawCapture = CaptureTransport<SmallTraits::max_connections>;
    using Tls = TlsAdapter<BufferingEngine, RawCapture, SmallTraits::max_connections, 1024>;
    // 1024 of scratch, 8 of which every record spends on framing.
    static_assert(Tls::out_buf_size == 1024 - 8,
                  "the broker must check what a packet may occupy, not the raw scratch");
    CHECK_EQ(Tls::out_buf_size, size_t{1016});

    // When the wrapped transport is the tighter buffer, the overhead
    // comes off its size, not off the adapter's scratch.
    using OverNarrow = TlsAdapter<BufferingEngine, NarrowRaw, SmallTraits::max_connections, 4096>;
    static_assert(OverNarrow::out_buf_size == 64 - 8,
                  "the wrapped transport's 64-byte ring, less the record overhead");
    CHECK_EQ(OverNarrow::out_buf_size, size_t{56});

    // An engine that declares no overhead publishes the scratch size.
    using Plain = TlsAdapter<NullTlsEngine, RawCapture, SmallTraits::max_connections, 1024>;
    static_assert(Plain::out_buf_size == 1024, "nothing to subtract");
    CHECK_EQ(Plain::out_buf_size, size_t{1024});
}
