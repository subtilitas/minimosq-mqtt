# minimosq

[![CI](https://github.com/subtilitas/minimosq-mqtt/actions/workflows/ci.yml/badge.svg)](https://github.com/subtilitas/minimosq-mqtt/actions/workflows/ci.yml)
[![Analysis](https://github.com/subtilitas/minimosq-mqtt/actions/workflows/analysis.yml/badge.svg)](https://github.com/subtilitas/minimosq-mqtt/actions/workflows/analysis.yml)
[![codecov](https://codecov.io/gh/subtilitas/minimosq-mqtt/branch/main/graph/badge.svg)](https://codecov.io/gh/subtilitas/minimosq-mqtt)
[![C++17](https://img.shields.io/badge/C%2B%2B-17-blue.svg)](https://en.cppreference.com/w/cpp/17)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

A small MQTT 3.1.1 broker as a **header-only C++17 template library**
for embedded use:

- **Fully static after startup** — every capacity is a compile-time
  traits parameter; all state lives inside the `Broker` object, which
  can sit in `.bss`. No heap. Ever.
- **No exceptions, no RTTI** — the whole repository builds with
  `-fno-exceptions -fno-rtti`; errors are explicit codes.
- **No dependencies** — the core uses only freestanding C++ headers
  (`<cstdint>`, `<cstddef>`, `<new>`). POSIX is touched only by the
  example transports.
- **Pluggable transports** — the broker speaks to a transport policy
  (static polymorphism, no virtuals). Reference transports: TCP, unix
  domain sockets, and plain pipes; a documented TLS seam
  ([docs/tls.md](docs/tls.md)) shows where mbedTLS/wolfSSL plug in.
- **QoS 0, 1 and 2** — full receiver and sender state machines,
  retained messages, wills, keep-alive, persistent sessions with
  offline queueing and DUP retransmission on resume.

MIT licensed. Verified against stock `mosquitto_pub`/`mosquitto_sub`
clients over all three transports.

## A complete broker

```cpp
#include <minimosq/minimosq.hpp>
#include <minimosq/transports/posix/tcp.hpp>

using Traits = minimosq::DefaultTraits;                    // or your own
minimosq::TcpTransport<Traits::max_connections> transport; // static
minimosq::Broker<Traits, decltype(transport)> broker{transport};

int main() {
    if (!transport.open(1883)) return 1;
    transport.run(broker);   // poll loop: feeds broker, drives timeouts
}
```

That is [examples/tcp_broker.cpp](examples/tcp_broker.cpp), minus
argument parsing. `examples/uds_broker.cpp` (unix domain socket) and
`examples/pipe_broker.cpp` (FIFO pair — MQTT over plain pipes) differ
only in the transport.

## Sizing the broker

Capacities come from a traits struct; `DefaultTraits`
([broker/config.hpp](include/minimosq/broker/config.hpp)) documents
every knob:

```cpp
struct MyTraits {
    static constexpr size_t max_connections = 4;
    static constexpr size_t max_sessions = 4;
    static constexpr size_t max_subscriptions_per_session = 8;
    static constexpr size_t max_topic_len = 64;
    static constexpr size_t max_client_id_len = 32;
    static constexpr size_t max_packet_size = 512;   // largest inbound packet
    static constexpr size_t max_payload_len = 512;   // largest stored payload
    static constexpr size_t max_retained = 8;
    static constexpr size_t max_pending_per_session = 4;
    static constexpr size_t max_inbound_qos2 = 4;
    static constexpr uint32_t connect_timeout_ms = 10000;
};
```

The complete memory cost is `sizeof(minimosq::Broker<MyTraits, ...>)`
— a compile-time constant you can `static_assert` against your budget.

## Security: authentication and ACLs

The third template parameter is a security policy. It authenticates
each CONNECT and produces a per-session `Context` (any trivially
copyable type — typically a role id) that every authorization check
receives:

```cpp
struct MySecurity {
    struct Context { uint8_t role = 0; };

    minimosq::ConnackCode authenticate(minimosq::StrView client_id,
                                       const minimosq::StrView* username,
                                       const minimosq::ByteSpan* password,
                                       Context& ctx);
    bool authorize_publish(const Context&, minimosq::StrView topic);
    bool authorize_subscribe(const Context&, minimosq::StrView filter);
    bool authorize_receive(const Context&, minimosq::StrView topic);
};
minimosq::Broker<Traits, Transport, MySecurity> broker{transport};
```

Denied publishes are silently dropped but acknowledged (the
3.1.1-conformant behaviour), denied subscriptions answer SUBACK 0x80,
and `authorize_receive` runs per delivery so broad subscriptions never
leak restricted topics. The default (`AllowAllSecurity`) permits
everything.

For the common case there is a ready-made deny-by-default policy,
`minimosq::TableAcl` — fixed user and rule tables mapping credentials
to roles and roles to readable/writable topic patterns; see
[examples/tcp_broker_acl.cpp](examples/tcp_broker_acl.cpp) and the
security section of [docs/design.md](docs/design.md).

## Custom transports

A transport is any type with `bool send(size_t, ByteSpan)` and
`void close(size_t)` that feeds the broker's four entry points
(`conn_open`, `conn_data`, `conn_closed`, `tick`). The full contract
is documented in
[include/minimosq/transport.hpp](include/minimosq/transport.hpp); the
pipe transport (~150 lines) is the smallest worked example. The same
seam carries TLS: see [docs/tls.md](docs/tls.md).

## Building

The library itself is header-only — add `include/` to your include
path. Tests and examples:

```sh
cmake -B build -DMINIMOSQ_WERROR=ON
cmake --build build
ctest --test-dir build --output-on-failure
```

Try it out with real clients:

```sh
./build/examples/tcp_broker 1883 &
mosquitto_sub -p 1883 -q 1 -t 'demo/#' -v &
mosquitto_pub -p 1883 -q 2 -t demo/hello -m 'hi' -r
```

## Testing and coverage

154 test cases across the protocol, broker, ACL and transport layers,
run on every push under GCC and Clang, 32-bit and MSVC, plus
AddressSanitizer + UndefinedBehaviorSanitizer and an end-to-end smoke
test against stock `mosquitto` clients. The whole repository builds
warning-free with `-Wall -Wextra -Wpedantic -Wconversion
-Wsign-conversion -Wshadow -Werror`.

Static analysis runs separately ([`analysis.yml`](.github/workflows/analysis.yml)):
CodeQL with the `security-and-quality` queries, clang-tidy against the
curated check list in [`.clang-tidy`](.clang-tidy), and a
`clang-format` check.

Coverage of `include/minimosq/`:

| Layer | Lines | Coverage |
| --- | ---: | ---: |
| `topic.hpp` (matching, subsumption) | 96 | 99.0% |
| protocol (parse/serialize) | 315 | 95.6% |
| core (containers, spans) | 174 | 93.1% |
| broker (sessions, routing, ACL) | 610 | 92.5% |
| transports (POSIX, TLS seam) | 338 | 80.8% |
| **total** | **1533** | **91.0% lines, 79.9% branches** |

Reproduce it locally:

```sh
cmake -B build -DCMAKE_BUILD_TYPE=Debug -DCMAKE_CXX_FLAGS="--coverage -O0 -g"
cmake --build build && ctest --test-dir build
python3 tools/coverage.py --build-dir build --show-missing
```

> **Why `tools/coverage.py` and not `gcovr` directly?** minimosq is
> header-only and templated, so every test binary and every instantiation
> (`Broker<SmallTraits>`, `Broker<TinyTraits>`, …) emits its own gcov
> records for the same source lines. Tools that sum those records rather
> than merging them report ~58% and claim `broker.hpp` has 4400 lines
> when it has ~950. `tools/coverage.py` merges by source line — a line
> counts as covered if any instantiation executed it — and emits the
> merged result as Cobertura XML so CI, Codecov and a local run all agree.
> CI fails if line coverage drops below 90% or branch below 78%.

## Documentation

Full documentation lives in the
[wiki](https://github.com/subtilitas/minimosq-mqtt/wiki), which CI
regenerates from this repository on every push to `main` — including a
[configuration reference](https://github.com/subtilitas/minimosq-mqtt/wiki/Configuration)
with measured footprints, an
[API reference](https://github.com/subtilitas/minimosq-mqtt/wiki/API-Reference),
and a [porting guide](https://github.com/subtilitas/minimosq-mqtt/wiki/Porting)
(ESP32, bare metal, other targets). The sources are the Markdown files
under `docs/`; edit those, never the wiki.

## Design, conformance and policies

[docs/design.md](docs/design.md) covers the layering, the memory and
threading model, the QoS state machines, and a table of every
deliberate policy decision (capacity behaviour, empty client ids,
oversize payloads, …). Out of scope: MQTT 5.0, `$SYS` topics,
bridging, persistence across reboots.

## License

MIT — see [LICENSE](LICENSE).
