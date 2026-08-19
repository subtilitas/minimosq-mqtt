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
