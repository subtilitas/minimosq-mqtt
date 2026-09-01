# minimosq

[![CI](https://github.com/subtilitas/minimosq-mqtt/actions/workflows/ci.yml/badge.svg?branch=main&event=push)](https://github.com/subtilitas/minimosq-mqtt/actions/workflows/ci.yml?query=branch%3Amain)
[![Analysis](https://github.com/subtilitas/minimosq-mqtt/actions/workflows/analysis.yml/badge.svg?branch=main&event=push)](https://github.com/subtilitas/minimosq-mqtt/actions/workflows/analysis.yml?query=branch%3Amain)
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
- **Nothing is silent** — every refusal, authorization denial, protocol
  violation and dropped delivery is reported through an observer policy
  ([docs/observability.md](docs/observability.md)). The default records
  nothing and compiles away.
- **QoS 0, 1 and 2** — full receiver and sender state machines,
  retained messages, wills, keep-alive, persistent sessions with
  offline queueing and DUP retransmission on resume.

MIT licensed. Every push runs an end-to-end smoke test against stock
`mosquitto_pub`/`mosquitto_sub` over TCP; the same clients drive the
unix-socket broker with `--unix`, and the pipe broker through a `socat`
bridge.

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
    static constexpr uint32_t max_idle_ms = 300000;      // keep-alive-0 clients
    static constexpr uint32_t session_expiry_ms = 3600000;  // absent clients
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

To report a vulnerability, see [SECURITY.md](SECURITY.md) — privately,
through GitHub, not a public issue. It also lists the documented
limitations that are deliberate and not vulnerabilities (no TLS engine
is bundled, chief among them).

## Observability

The fourth template parameter is an observer. The broker decides plenty
worth recording — why a connection went away, which packet was a
protocol violation, which retained message could not be stored, which
QoS 1 delivery was skipped while its publisher was acknowledged anyway —
and this is where it comes out:

```cpp
struct MyObserver {
    void on_event(const minimosq::Event& e) noexcept {
        log(minimosq::event_kind_name(e.kind), e.client_id, e.topic);
    }
};
minimosq::Broker<Traits, Transport, Security, MyObserver> broker{transport};
```

One method, one tagged `Event`, no allocation; adding an event kind never
breaks an existing observer. The default (`NullObserver`) has an empty
body and optimizes away entirely, so the seam is free if you do not want
it. There is no logger, no metrics and no audit storage in the library —
those need a clock, storage and policy, all of which are yours. See
[docs/observability.md](docs/observability.md) for the contract, the full
event table, and the mapping to IEC 62443-4-2 CR 2.8–2.12 and CR 6.1–6.2.

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
path, or pick it up with CMake:

```cmake
# installed (cmake --install build), or from a package manager
find_package(minimosq 0.5 REQUIRED)

# or vendored, without installing anything
add_subdirectory(third_party/minimosq-mqtt)

target_link_libraries(my_app PRIVATE minimosq::minimosq)
```

`minimosq::minimosq` is an INTERFACE target: an include path and a C++17
requirement, nothing else. `<minimosq/version.hpp>` identifies the copy
you have — `MINIMOSQ_VERSION_AT_LEAST(0, 5, 0)` works in the
preprocessor, which matters for a library people vendor by copying
headers.

Tests and examples:

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

217 test cases across the protocol, broker, ACL and transport layers,
run on every push under GCC and Clang, 32-bit and MSVC, plus
AddressSanitizer + UndefinedBehaviorSanitizer and an end-to-end smoke
test against stock `mosquitto` clients. The whole repository builds
warning-free with `-Wall -Wextra -Wpedantic -Wconversion
-Wsign-conversion -Wshadow -Werror`.

Static analysis runs separately ([`analysis.yml`](.github/workflows/analysis.yml)):
CodeQL with the `security-and-quality` queries, clang-tidy against the
curated check list in [`.clang-tidy`](.clang-tidy), and a
`clang-format` check.

Coverage of `include/minimosq/` is measured on every push and published
to [Codecov](https://codecov.io/gh/subtilitas/minimosq-mqtt); the
coverage job prints a per-layer and per-file breakdown in its summary.
CI fails if it drops below the floor set in
[`ci.yml`](.github/workflows/ci.yml).

Reproduce the CI number exactly — the compiler matters, see below:

```sh
sudo apt-get install -y g++-13
cmake -B build -DCMAKE_BUILD_TYPE=Debug \
      -DCMAKE_CXX_COMPILER=g++-13 -DCMAKE_CXX_FLAGS="--coverage -O0 -g"
cmake --build build && ctest --test-dir build
python3 tools/coverage.py --build-dir build --gcov gcov-13 --show-missing
```

> **Why `tools/coverage.py` and not `gcovr` directly?** minimosq is
> header-only and templated, so every test binary and every instantiation
> (`Broker<SmallTraits>`, `Broker<TinyTraits>`, …) emits its own gcov
> records for the same source lines. Tools that sum those records rather
> than merging them report ~58% and claim `broker.hpp` has 4400 lines
> when it has ~950. `tools/coverage.py` merges by source line — a line
> counts as covered if any instantiation executed it — and emits the
> merged result as Cobertura XML so CI, Codecov and a local run all agree.
>
> **Two numbers, and they differ by about seven points.** A line can be
> *executed* without every branch on it being taken. Classic line
> coverage counts it; Codecov counts it as *partial* and reports only
> fully covered lines. On this tree that is 94.7% executed against 87.4%
> fully covered. `tools/coverage.py` prints both and the CI floor gates
> the stricter one, so the gate and the badge always agree.
>
> **The compiler is part of the measurement too.** Different GCC
> releases instrument a different number of lines in template-heavy
> headers, so a percentage is only comparable against the same
> compiler — worth roughly one point here. The coverage job pins one and
> `tools/coverage.py` takes `--gcov` to match it.

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

---

In collaboration with Claude Code.
