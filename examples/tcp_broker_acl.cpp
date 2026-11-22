// minimosq example: a TCP broker with users, roles and topic ACLs.
//
//   ./tcp_broker_acl [port]        (default 1883)
//
// Roles:
//   sensor    may publish under sensors/#, nothing else
//   dashboard may read sensors/#, read and write control/#
//   anonymous refused
//
// Try it:
//   mosquitto_sub -p 1883 -u dashboard -P d4sh -t 'sensors/#' -v &
//   mosquitto_pub -p 1883 -u sensor-1 -P s3cret -t sensors/1/temp -m 21.5
//   mosquitto_pub -p 1883 -u sensor-1 -P s3cret -t control/reboot -m now
//     (silently dropped: sensors may not write control/#)
//   mosquitto_pub -p 1883 -t sensors/1/temp -m 0
//     (refused: anonymous connections are not authorized)
//
// SPDX-License-Identifier: MIT
#include <charconv>
#include <csignal>
#include <cstdint>
#include <iostream>

#include <minimosq/broker/table_acl.hpp>
#include <minimosq/minimosq.hpp>
#include <minimosq/transports/posix/tcp.hpp>

namespace {

using BrokerTraits = minimosq::DefaultTraits;
using Transport = minimosq::TcpTransport<BrokerTraits::max_connections>;
using Acl = minimosq::TableAcl<8, 16>;

constexpr uint8_t ROLE_SENSOR = 1;
constexpr uint8_t ROLE_DASHBOARD = 2;

Transport transport;
minimosq::Broker<BrokerTraits, Transport, Acl> broker{transport};

void on_signal(int) {
    transport.stop();
}

// Strict port parsing; see tcp_broker.cpp for why std::from_chars is used.
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

bool configure_acl(Acl& acl) {
    // In a real deployment, load these from provisioning data instead
    // of hard-coding them.
    return acl.add_user("sensor-1", "s3cret", ROLE_SENSOR) &&
           acl.add_user("sensor-2", "s3cret", ROLE_SENSOR) &&
           acl.add_user("dashboard", "d4sh", ROLE_DASHBOARD) &&
           acl.add_rule(ROLE_SENSOR, "sensors/#", Acl::write) &&
           acl.add_rule(ROLE_DASHBOARD, "sensors/#", Acl::read) &&
           acl.add_rule(ROLE_DASHBOARD, "control/#", Acl::read_write);
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

    if (!configure_acl(broker.security())) {
        std::cerr << "tcp_broker_acl: ACL tables too small\n";
        return 1;
    }
    if (!transport.open(port)) {
        std::cerr << "tcp_broker_acl: cannot listen on port " << port << '\n';
        return 1;
    }
    std::cout << "tcp_broker_acl: broker with ACLs on port " << transport.port()
              << " (users: sensor-1, sensor-2, dashboard; anonymous refused)\n";

    transport.run(broker);
    std::cout << "tcp_broker_acl: shutting down\n";
    return 0;
}
