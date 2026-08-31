# Getting started

minimosq is header-only. There is nothing to build for the library
itself — add `include/` to your include path and include what you need.

## Build the tests and examples

```sh
cmake -B build -DMINIMOSQ_WERROR=ON
cmake --build build
ctest --test-dir build --output-on-failure
```

With CMake, consuming the library from another project is one of:

```cmake
# vendored in your tree
add_subdirectory(third_party/minimosq-mqtt)

# fetched at configure time
include(FetchContent)
FetchContent_Declare(minimosq
  GIT_REPOSITORY https://github.com/subtilitas/minimosq-mqtt.git
  GIT_TAG v0.4.0)
FetchContent_MakeAvailable(minimosq)

# installed system-wide or into a prefix
find_package(minimosq 0.4 REQUIRED)

target_link_libraries(my_app PRIVATE minimosq::minimosq)
```

`minimosq::minimosq` is an INTERFACE target: it contributes the include
path and a C++17 requirement, nothing else.

Installing is a header copy plus the package config `find_package` needs:

```sh
cmake -B build -DCMAKE_INSTALL_PREFIX=/usr/local
cmake --install build
```

A vendored or installed copy identifies itself through
`<minimosq/version.hpp>`, which the umbrella header pulls in:

```cpp
static_assert(MINIMOSQ_VERSION_AT_LEAST(0, 4, 0), "minimosq too old");
```

The version compatibility rule is the 0.x one: `find_package(minimosq
0.4)` accepts any 0.4.x, and rejects 0.5 — minor versions are not
promised to be compatible before 1.0.

## A complete broker

```cpp
#include <minimosq/minimosq.hpp>
#include <minimosq/transports/posix/tcp.hpp>

using Traits = minimosq::DefaultTraits;                    // or your own
minimosq::TcpTransport<Traits::max_connections> transport; // static storage
minimosq::Broker<Traits, decltype(transport)> broker{transport};

int main() {
    if (!transport.open(1883)) return 1;
    transport.run(broker);   // poll loop: feeds the broker, drives timeouts
}
```

That is `examples/tcp_broker.cpp` minus argument parsing. Try it against
any MQTT 3.1.1 client:

```sh
./build/examples/tcp_broker 1883 &
mosquitto_sub -p 1883 -q 1 -t 'demo/#' -v &
mosquitto_pub -p 1883 -q 2 -t demo/hello -m 'hi' -r
```

The other examples differ only in their transport:
`uds_broker` (unix domain socket), `pipe_broker` (a pair of FIFOs), and
`tcp_broker_acl` (TCP with users, roles and topic ACLs).

## Choosing capacities

Every limit is a compile-time constant from a traits struct, and the
broker's whole memory cost is `sizeof(Broker<Traits, Transport>)`. Start
from `minimosq::DefaultTraits`, then tune — see
[Configuration](Configuration) for each setting and measured footprints.

## Publishing from the application

The broker is also a message source. Anything the firmware itself wants
to announce goes through the same routing as a client publish:

```cpp
broker.publish("device/status", payload, minimosq::QoS::at_least_once,
               /*retain=*/true);
```

## Where to go next

* [Configuration](Configuration) — every traits knob, and what it costs
* [Security](Security) — authentication and topic ACLs
* [Transports](Transports) — the transport contract and writing your own
* [Porting](Porting) — ESP32, bare metal, and other targets
* [Design notes](Design-Notes) — how the broker works internally
