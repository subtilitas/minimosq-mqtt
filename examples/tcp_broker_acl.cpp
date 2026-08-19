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
#include <cerrno>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <cstdlib>

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

// Strict port parsing; see tcp_broker.cpp for why atol() is not enough.
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
        std::fprintf(stderr, "usage: %s [port]   (1-65535)\n", argv[0]);
        return 1;
    }

    std::signal(SIGPIPE, SIG_IGN);
    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);

    if (!configure_acl(broker.security())) {
        std::fprintf(stderr, "tcp_broker_acl: ACL tables too small\n");
        return 1;
    }
    if (!transport.open(port)) {
        std::fprintf(stderr, "tcp_broker_acl: cannot listen on port %u\n", port);
        return 1;
    }
    std::printf("tcp_broker_acl: broker with ACLs on port %u (users: sensor-1, sensor-2, "
                "dashboard; anonymous refused)\n",
                transport.port());

    transport.run(broker);
    std::printf("tcp_broker_acl: shutting down\n");
    return 0;
}
