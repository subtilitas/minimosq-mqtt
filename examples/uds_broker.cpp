// minimosq example: an MQTT broker on a unix domain socket.
//
//   ./uds_broker [socket-path]     (default /tmp/minimosq.sock)
//
// Try it with any client that speaks unix sockets, e.g.:
//   mosquitto_sub --unix /tmp/minimosq.sock -t 'demo/#' &
//   mosquitto_pub --unix /tmp/minimosq.sock -t demo/hello -m 'hi'
//
// SPDX-License-Identifier: MIT
#include <csignal>
#include <iostream>

#include <minimosq/minimosq.hpp>
#include <minimosq/transports/posix/unix_socket.hpp>

namespace {

using BrokerTraits = minimosq::DefaultTraits;
using Transport = minimosq::UnixSocketTransport<BrokerTraits::max_connections>;

Transport transport;
minimosq::Broker<BrokerTraits, Transport> broker{transport};

void on_signal(int) {
    transport.stop();
}

}  // namespace

int main(int argc, char** argv) {
    const char* path = argc > 1 ? argv[1] : "/tmp/minimosq.sock";

    std::signal(SIGPIPE, SIG_IGN);
    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);

    if (!transport.open(path)) {
        std::cerr << "uds_broker: cannot listen on " << path << '\n';
        return 1;
    }
    std::cout << "uds_broker: MQTT 3.1.1 broker listening on " << path << '\n';

    transport.run(broker);
    std::cout << "uds_broker: shutting down\n";
    return 0;
}
