// minimosq example: an MQTT broker over a pair of named pipes (FIFOs).
//
//   ./pipe_broker [in-fifo] [out-fifo]
//     in-fifo:  client -> broker bytes (default /tmp/minimosq.in)
//     out-fifo: broker -> client bytes (default /tmp/minimosq.out)
//
// The FIFOs are created if missing. One client at a time; when it
// disconnects, the broker waits for the next one.
//
// To attach a standard TCP MQTT client through socat:
//   socat TCP-LISTEN:1884,reuseaddr 'GOPEN:/tmp/minimosq.out!!GOPEN:/tmp/minimosq.in'
//   mosquitto_pub -p 1884 -t demo -m hi
//
// The same PipeTransport works over anonymous pipe(2)/socketpair(2)
// descriptors — e.g. talking MQTT to a forked child process.
//
// SPDX-License-Identifier: MIT
#include <csignal>
#include <cstdio>

#include <fcntl.h>
#include <sys/stat.h>

#include <minimosq/minimosq.hpp>
#include <minimosq/transports/posix/pipe.hpp>

namespace {

// One connection is all a pipe can carry.
struct PipeTraits : minimosq::DefaultTraits {
    static constexpr size_t max_connections = 1;
};

using Transport = minimosq::PipeTransport<>;

Transport transport;
minimosq::Broker<PipeTraits, Transport> broker{transport};
volatile sig_atomic_t stop_requested = 0;

void on_signal(int) {
    stop_requested = 1;
    transport.stop();
}

int open_fifo(const char* path, int flags) {
    ::mkfifo(path, 0666);  // best effort; fails harmlessly if it exists
    // O_RDWR keeps the FIFO open across client generations (no EOF
    // storm while no peer is attached, no open() deadlock).
    return ::open(path, flags | O_RDWR | O_NONBLOCK);
}

}  // namespace

int main(int argc, char** argv) {
    const char* in_path = argc > 1 ? argv[1] : "/tmp/minimosq.in";
    const char* out_path = argc > 2 ? argv[2] : "/tmp/minimosq.out";

    std::signal(SIGPIPE, SIG_IGN);
    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);

    std::printf("pipe_broker: MQTT 3.1.1 broker on %s (in) / %s (out)\n", in_path, out_path);

    while (stop_requested == 0) {
        const int rfd = open_fifo(in_path, 0);
        const int wfd = open_fifo(out_path, 0);
        if (rfd < 0 || wfd < 0) {
            std::fprintf(stderr, "pipe_broker: cannot open FIFOs\n");
            return 1;
        }
        if (!transport.open(rfd, wfd)) {
            std::fprintf(stderr, "pipe_broker: cannot set up transport\n");
            return 1;
        }
        transport.run(broker);  // returns when this client's connection ends
    }
    std::printf("pipe_broker: shutting down\n");
    return 0;
}
