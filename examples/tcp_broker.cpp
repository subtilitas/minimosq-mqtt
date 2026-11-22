// minimosq example: an MQTT broker on a TCP port.
//
//   ./tcp_broker [port]        (default 1883)
//
// Try it with any MQTT 3.1.1 client, e.g.:
//   mosquitto_sub -p 1883 -q 1 -t 'demo/#' &
//   mosquitto_pub -p 1883 -q 1 -t demo/hello -m 'hi'
//
// Note how everything is statically allocated: the broker and the
// transport live in static storage, sized entirely by BrokerTraits.
//
// SPDX-License-Identifier: MIT
#include <charconv>
#include <csignal>
#include <cstdint>
#include <iostream>

#include <minimosq/minimosq.hpp>
#include <minimosq/transports/posix/tcp.hpp>

namespace {

using BrokerTraits = minimosq::DefaultTraits;
using Transport = minimosq::TcpTransport<BrokerTraits::max_connections>;

Transport transport;
minimosq::Broker<BrokerTraits, Transport> broker{transport};

void on_signal(int) {
    transport.stop();
}

// Strict port parsing. std::from_chars reports failure and the end of
// the number, so the whole argument must be consumed: "1883x" is
// rejected rather than read as 1883, and "0" and "abc" are errors.
bool parse_port(const char* text, uint16_t& out) {
    const minimosq::StrView s{text};
    int value = 0;
    const auto result = std::from_chars(s.data, s.data + s.len, value);
    if (result.ec != std::errc{} || result.ptr != s.data + s.len || value < 1 || value > 65535) {
        return false;
    }
    out = static_cast<uint16_t>(value);
    return true;
}

}  // namespace

int main(int argc, char** argv) {
    uint16_t port = 1883;
    if (argc > 1 && !parse_port(argv[1], port)) {
        std::cerr << "usage: " << argv[0] << " [port]   (1-65535)\n";
        return 1;
    }

    std::signal(SIGPIPE, SIG_IGN);
    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);

    if (!transport.open(port)) {
        std::cerr << "tcp_broker: cannot listen on port " << port << '\n';
        return 1;
    }
    std::cout << "tcp_broker: MQTT 3.1.1 broker listening on port " << transport.port() << '\n';
    std::cout << "tcp_broker: broker state is " << sizeof broker
              << " bytes, statically allocated\n";

    transport.run(broker);
    std::cout << "tcp_broker: shutting down\n";
    return 0;
}
