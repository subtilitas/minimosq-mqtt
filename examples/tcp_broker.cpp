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
#include <csignal>
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

}  // namespace

int main(int argc, char** argv) {
    const long port_arg = argc > 1 ? std::atol(argv[1]) : 1883;
    if (port_arg < 1 || port_arg > 65535) {
        std::fprintf(stderr, "usage: %s [port]\n", argv[0]);
        return 1;
    }
    const auto port = static_cast<uint16_t>(port_arg);

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
