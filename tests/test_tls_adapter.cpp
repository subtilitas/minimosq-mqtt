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
