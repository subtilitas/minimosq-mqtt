# Porting guide

The broker core is written against nothing but freestanding C++17
(`<cstdint>`, `<cstddef>`, `<new>`): no heap, no exceptions, no RTTI, no
OS calls. Porting minimosq means providing two things — a transport and
a millisecond clock — and choosing capacities that fit your RAM.

## What the target must provide

| Requirement | Notes |
| --- | --- |
| C++17 compiler | CI builds GCC, Clang (64- and 32-bit) and MSVC. Any conforming C++17 compiler should do — the core uses no language extension and no library beyond the three headers below. `-fno-exceptions -fno-rtti` are supported, not required |
| `<cstdint>`, `<cstddef>`, `<new>` | Freestanding headers; `<new>` is needed for placement `new` and `std::launder` |
| A monotonic millisecond counter | Any `uint32_t`; wrap-around is handled |
| Somewhere to put the broker | Static storage is the intended home — see sizing below |

Everything else — sockets, threads, timers, a filesystem — is *not*
required. The POSIX transports under `include/minimosq/transports/posix/`
are examples that happen to ship with the library, not part of the core.

## Sizing

`sizeof(minimosq::Broker<Traits, Transport>)` is the entire footprint;
the [Configuration](Configuration) page carries CI-measured numbers for
several configurations. As a rule of thumb:

| Configuration | Roughly |
| --- | --- |
| 2 connections, 256 B packets | ~2.7 KB |
| 4 connections, 512 B packets | ~12.6 KB |
| 8 connections, 1 KB packets (`DefaultTraits`) | ~78 KB |

Pin the budget at compile time so a later capacity change cannot quietly
overflow your RAM:

```cpp
static_assert(sizeof(minimosq::Broker<MyTraits, MyTransport>) < 40 * 1024,
              "broker no longer fits the reserved region");
```

**Put the broker in static storage, not on a stack.** A 78 KB object on a
task stack will overflow it on most embedded targets. All the examples
declare the broker at namespace scope for this reason.

## ESP32 (ESP-IDF)

Less work than most targets: ESP-IDF's lwIP provides BSD sockets and
`poll()`, so the bundled
[`TcpTransport`](https://github.com/subtilitas/minimosq-mqtt/blob/main/include/minimosq/transports/posix/tcp.hpp)
compiles and runs as-is. `clock_gettime(CLOCK_MONOTONIC)` is available
too, so `posix_now_ms()` works unchanged.

Use it as an ESP-IDF component: drop the repository (or a submodule) into
`components/minimosq/` with a `CMakeLists.txt` of

```cmake
idf_component_register(INCLUDE_DIRS "include")
```

and a broker task along these lines:

```cpp
#include <minimosq/minimosq.hpp>
#include <minimosq/transports/posix/tcp.hpp>

namespace {
struct EspTraits {
    static constexpr size_t max_connections = 4;   // <= CONFIG_LWIP_MAX_SOCKETS - 1
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

using Transport = minimosq::TcpTransport<EspTraits::max_connections>;

// Static storage: never build these on a task stack.
Transport transport;
minimosq::Broker<EspTraits, Transport> broker{transport};
}  // namespace

void broker_task(void*) {
    transport.open(1883);
    transport.run(broker);   // never returns; poll loop with 100 ms ticks
    vTaskDelete(nullptr);
}

// After the network is up (e.g. from your got-IP event handler):
//   xTaskCreate(broker_task, "mqtt-broker", 4096, nullptr, 5, nullptr);
```

Points specific to the ESP32 worth getting right:

* **Socket budget.** lwIP caps concurrent sockets at
  `CONFIG_LWIP_MAX_SOCKETS` (default 10). `max_connections` must stay
  below it, leaving room for the listening socket and anything else the
  firmware opens.
* **RAM.** An ESP32 has roughly 320 KB of DRAM, much of it claimed by
  Wi-Fi and lwIP buffers. The configuration above measures 12,680 bytes,
  which is comfortable; `DefaultTraits` at ~78 KB is usually
  still fine, but measure with `heap_caps_get_free_size(MALLOC_CAP_8BIT)`
  before and after. The broker itself lives in `.bss`, so it never
  competes with the heap at runtime.
* **Task stack.** The poll loop uses a couple of kilobytes of stack for
  its read buffers; 4 KB is a safe task stack. The broker object is
  static, so it does not count.
* **No `SIGPIPE`.** ESP-IDF has no signals to ignore, and the transport
  falls back to plain `send()` where `MSG_NOSIGNAL` is not defined.
* **Not available on lwIP:** the unix-socket and pipe transports. Only
  include `transports/posix/tcp.hpp`.
* **Exceptions.** IDF disables C++ exceptions by default, which suits
  minimosq exactly — nothing in the library throws.
* **TLS.** ESP-IDF bundles mbedTLS, which is the engine the
  [TLS](tls.md) adapter is designed around.

The same recipe applies with minor edits to any FreeRTOS + lwIP target.

## Other targets

* **Zephyr.** BSD sockets and `poll()` are available with
  `CONFIG_POSIX_API=y`; the TCP transport then compiles unchanged.
  Otherwise write a thin transport over `zsock_*`.
* **Bare metal with a raw TCP stack** (lwIP raw API, uIP, a vendor
  stack). Write a transport: accept a connection, hand the broker its
  index and bytes, and implement `send`/`close`. The
  [pipe transport](https://github.com/subtilitas/minimosq-mqtt/blob/main/include/minimosq/transports/posix/pipe.hpp)
  (~150 lines) is the smallest worked example. See [Transports](transports.md).
* **Non-IP links** — RS-485, USB CDC, SPI to a radio module. MQTT only
  needs an ordered reliable byte stream, and the transport interface is
  agnostic about where those bytes come from.
* **Windows.** The core compiles with MSVC; the bundled transports are
  POSIX-only, so write a Winsock transport (the same shape as
  `stream_server.hpp`, with `WSAPoll`).

## Checklist for a new port

1. Define a traits struct and `static_assert` its footprint.
2. Provide a monotonic `uint32_t` millisecond clock.
3. Implement `bool send(size_t, ByteSpan)` and `void close(size_t)`.
4. Drive `conn_open` / `conn_data` / `conn_closed` from your event loop,
   and call `tick()` regularly (every 100 ms is plenty) so keep-alive and
   handshake timeouts fire.
5. Place the broker in static storage.
6. Run the test suite on your host build — it is transport-independent
   and will catch integration mistakes before the target does.
