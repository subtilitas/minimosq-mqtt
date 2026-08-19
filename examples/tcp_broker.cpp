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
#include <cerrno>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>

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

// Strict port parsing. atol() reports no error at all: it cannot tell
// "0" from "abc", and it silently accepts trailing garbage, so "1883x"
// would start a broker on 1883 rather than complain.
bool parse_port(const char* text, uint16_t& out) {
    errno = 0;
    char* end = nullptr;
    const long value = std::strtol(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || value < 1 || value > 65535) {
        return false;
    }
    out = static_cast<uint16_t>(value);
    return true;
}

}  // namespace

int main(int argc, char** argv) {
    uint16_t port = 1883;
    if (argc > 1 && !parse_port(argv[1], port)) {
        std::fprintf(stderr, "usage: %s [port]   (1-65535)\n", argv[0]);
        return 1;
    }

    std::signal(SIGPIPE, SIG_IGN);
    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);

    if (!transport.open(port)) {
        std::fprintf(stderr, "tcp_broker: cannot listen on port %u\n", port);
        return 1;
    }
    std::printf("tcp_broker: MQTT 3.1.1 broker listening on port %u\n", transport.port());
    std::printf("tcp_broker: broker state is %zu bytes, statically allocated\n", sizeof broker);

    transport.run(broker);
    std::printf("tcp_broker: shutting down\n");
    return 0;
}
