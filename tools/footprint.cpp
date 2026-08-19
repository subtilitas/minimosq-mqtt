// minimosq — report the static memory footprint of the broker for a
// range of configurations.
//
// The whole cost of a minimosq broker is sizeof(Broker<...>), so this
// program is the authoritative answer to "how much RAM does it need?".
// CI runs it and feeds the numbers into the generated documentation.
//
// Output is TSV so the doc generator can format it:
//   config<TAB>name<TAB>conns<TAB>sessions<TAB>packet<TAB>payload<TAB>bytes
//   component<TAB>name<TAB>bytes
//
// SPDX-License-Identifier: MIT
#include <cstdio>

#include <minimosq/broker/table_acl.hpp>
#include <minimosq/minimosq.hpp>

using minimosq::Broker;
using minimosq::NullTransport;

namespace {

// A deliberately small build: a handful of local devices.
struct MinimalTraits {
    static constexpr size_t max_connections = 2;
    static constexpr size_t max_sessions = 2;
    static constexpr size_t max_subscriptions_per_session = 2;
    static constexpr size_t max_topic_len = 32;
    static constexpr size_t max_client_id_len = 23;
    static constexpr size_t max_packet_size = 256;
    static constexpr size_t max_payload_len = 128;
    static constexpr size_t max_retained = 2;
    static constexpr size_t max_pending_per_session = 2;
    static constexpr size_t max_inbound_qos2 = 2;
    static constexpr uint32_t connect_timeout_ms = 10000;
};

struct SmallTraits {
    static constexpr size_t max_connections = 4;
    static constexpr size_t max_sessions = 4;
    static constexpr size_t max_subscriptions_per_session = 4;
    static constexpr size_t max_topic_len = 64;
    static constexpr size_t max_client_id_len = 32;
    static constexpr size_t max_packet_size = 512;
    static constexpr size_t max_payload_len = 256;
    static constexpr size_t max_retained = 4;
    static constexpr size_t max_pending_per_session = 4;
    static constexpr size_t max_inbound_qos2 = 4;
    static constexpr uint32_t connect_timeout_ms = 10000;
};

// A gateway-sized build.
struct LargeTraits {
    static constexpr size_t max_connections = 16;
    static constexpr size_t max_sessions = 24;
    static constexpr size_t max_subscriptions_per_session = 16;
    static constexpr size_t max_topic_len = 128;
    static constexpr size_t max_client_id_len = 64;
    static constexpr size_t max_packet_size = 2048;
    static constexpr size_t max_payload_len = 1024;
    static constexpr size_t max_retained = 32;
    static constexpr size_t max_pending_per_session = 16;
    static constexpr size_t max_inbound_qos2 = 16;
    static constexpr uint32_t connect_timeout_ms = 10000;
};

template <typename Traits>
void report(const char* name) {
    // sizeof() alone does not use every trait, so state the invariants
    // here: it keeps each configuration honest and, incidentally, keeps
    // compilers from reporting the constants as unused.
    static_assert(Traits::max_sessions >= Traits::max_connections,
                  "max_sessions < max_connections cannot serve every connection");
    static_assert(Traits::connect_timeout_ms > 0, "connect timeout must be non-zero");
    static_assert(Traits::max_payload_len <= Traits::max_packet_size,
                  "stored payloads cannot exceed the largest accepted packet");

    std::printf("config\t%s\t%zu\t%zu\t%zu\t%zu\t%zu\n", name, Traits::max_connections,
                Traits::max_sessions, Traits::max_packet_size, Traits::max_payload_len,
                sizeof(Broker<Traits, NullTransport>));
}

}  // namespace

int main() {
    report<MinimalTraits>("Minimal");
    report<SmallTraits>("Small");
    report<minimosq::DefaultTraits>("DefaultTraits");
    report<LargeTraits>("Gateway");

    // Where the bytes go, for the default configuration.
    using T = minimosq::DefaultTraits;
    std::printf("component\tPer connection (frame parser + state)\t%zu\n",
                sizeof(minimosq::FrameParser<T::max_packet_size>));
    std::printf("component\tPer session (subs, queues, will)\t%zu\n",
                sizeof(minimosq::Session<T, minimosq::AllowAllSecurity::Context>));
    std::printf("component\tPer retained message\t%zu\n",
                sizeof(minimosq::RetainedStore<T>::Entry));
    std::printf("component\tWith TableAcl<8,16> instead of AllowAllSecurity\t%zu\n",
                sizeof(Broker<T, NullTransport, minimosq::TableAcl<8, 16>>));
    return 0;
}
