# Transports

The broker never touches a socket. It works in terms of *connection
indices* and byte spans, and talks to the outside world through a
transport policy supplied as a template parameter — static
polymorphism, so there are no virtual calls and nothing to allocate.

## The contract

A transport provides two operations:

```cpp
struct MyTransport {
    // Queue bytes for transmission. The whole span must be accepted
    // (buffer internally). Return false only when the connection is
    // beyond saving — the broker then drops it.
    bool send(size_t conn, minimosq::ByteSpan bytes);

    // Tear a connection down. Free the slot and do NOT call
    // conn_closed() back; flush already-queued bytes first if you can,
    // so CONNACK refusals reach the peer.
    void close(size_t conn);
};
```

and drives the broker in return:

```cpp
broker.conn_open(ci, now_ms);         // a connection was accepted
broker.conn_data(ci, bytes, now_ms);  // bytes arrived
broker.conn_closed(ci);               // the peer hung up / I/O error
broker.tick(now_ms);                  // periodically, e.g. every 100 ms
```

The rules that matter:

* Connection indices are dense in `[0, Traits::max_connections)`, and the
  transport owns their allocation.
* `close()` is broker-initiated teardown; `conn_closed()` reports a
  teardown the broker did not ask for. Never call `conn_closed()` in
  response to `close()`, or a will may fire spuriously.
* Everything is single-threaded: all calls into one broker must come
  from one thread, or be serialized externally.
* `now_ms` is any monotonic millisecond counter. Wrap-around is handled.
* `tick()` must be called regularly even when no traffic arrives, or
  keep-alive and CONNECT-handshake timeouts will not fire.

The full contract, including the reasoning, is documented in
[`include/minimosq/transport.hpp`](../include/minimosq/transport.hpp).

### Publish your capacity

A transport may declare how many slots it has:

```cpp
static constexpr size_t max_connections = MaxConns;
```

When it does, `Broker` `static_assert`s that the number is at least
`Traits::max_connections`. This is worth doing. The broker hands out
indices in `[0, Traits::max_connections)`, and nothing else forces the
two numbers to agree — `TcpTransport<8>` under a traits type with
`max_connections = 16` compiles perfectly and writes past the end of the
slot array. With the constant published, that combination fails to
build instead. Transports that stay silent are assumed to be sized
correctly.

`StreamServerTransport` and `TlsAdapter` also bounds-check the index at
run time and refuse one out of range, rather than trusting the caller.
`PipeTransport` serves a single connection and ignores the index
entirely, so it has nothing to check.

### Do not drain one connection forever

`StreamServerTransport` and `PipeTransport` cap how many reads they take
from a single connection per poll pass:

```cpp
static constexpr int max_reads_per_pass = 8;
```

Reading until `EAGAIN` sounds tidier, but a peer that keeps its socket
full then starves every other connection *and* stops `tick()` from
running, which is what drives the keep-alive and handshake timeouts.
Whatever is left stays readable and the next `poll()` picks it up. A
transport you write yourself wants the same bound.

### One write per connection per pass

`send()` appends to the connection's output ring and returns. The ring is
written at the end of the poll pass, after `tick()`, so everything a pass
produced for a connection — acknowledgements, deliveries, whatever the
timeouts decided — leaves in one `send()` syscall. A ring that fills
mid-pass is written and the append retried once; `send()` returns `false`
when the span still does not fit after that write — the ring is full and
the kernel accepted too little of it — and the broker drops the connection
as a slow consumer. The pass that reads a peer's EOF, and a pass cut short
by `EINTR`, still write what they produced.

`TcpTransport` sets `TCP_NODELAY` on every accepted socket. With the
transport coalescing its own writes, Nagle's algorithm has nothing left to
merge and would only hold a finished write until the peer's ACK arrives.
The two go together: batching without `TCP_NODELAY` leaves saturated
QoS 0 throughput where it was, and `TCP_NODELAY` without batching turns
every packet into a segment.

Measured with 8 clients, 64-byte payloads, each message published and
received by the same client, loopback, a 65536-byte ring and the broker
on one core:

| | per-packet write | batched + `TCP_NODELAY` |
| --- | ---: | ---: |
| TCP, QoS 0, saturated | 227 156 msg/s | 975 660 msg/s |
| TCP, QoS 1, saturated | 138 068 msg/s | 380 640 msg/s |
| unix socket, QoS 0, saturated | 316 809 msg/s | 1 251 644 msg/s |
| TCP, QoS 0, 1000 msg/s per client, median round trip | 1020 us | 59 us |
| TCP, QoS 1, 1000 msg/s per client, median round trip | 56 us | 89 us |

The QoS 1 median rises because a reply now waits for the end of the pass
instead of leaving at once; the pass grows with load, up to
`max_reads_per_pass` reads of 2048 bytes per busy connection, so a quiet
connection's reply can wait behind its neighbours' work. With the
default 4096-byte ring, saturated TCP QoS 0 measures 771 404 msg/s. A
real network, a real NIC and lwIP are not measured.

`Broker::publish()` called from outside `poll_once()` queues the same
way: the bytes leave at the end of the next pass, which `poll()` enters
immediately because the ring is non-empty.

## Bundled transports

All POSIX-only, and all examples rather than core:

| Header | What it is |
| --- | --- |
| `transports/posix/tcp.hpp` | TCP server, `TCP_NODELAY` on accepted sockets; works on lwIP targets (ESP-IDF, Zephyr) too |
| `transports/posix/unix_socket.hpp` | Unix domain socket server, for local-only brokers |
| `transports/posix/pipe.hpp` | One connection over any pair of stream descriptors — pipes, FIFOs, a socketpair, a child process's stdio |
| `transports/posix/stream_server.hpp` | The shared nonblocking `poll()` loop behind the TCP and unix-socket transports |
| `transport.hpp` | The contract, plus `NullTransport` for tests |

`TcpTransport` and `UnixSocketTransport` differ only in how the listening
socket is created; everything else — accept handling, per-connection
output ring, slow-consumer detection, `EINTR`/`EAGAIN` handling — lives in
`StreamServerTransport`.

### Opening a listener

```cpp
// TCP. Port 0 lets the OS pick one; read it back with port().
bool open(uint16_t port, const char* bind_addr = nullptr);

// Unix domain socket. The mode is applied to the socket file.
bool open(const char* path, mode_t mode = 0600);
```

`bind_addr` restricts the listening interface and defaults to all of
them. MQTT 3.1.1 has no transport security of its own, so a broker
without TLS underneath should usually not be reachable from the network:

```cpp
transport.open(1883, "127.0.0.1");   // local processes only
```

An address that does not parse makes `open()` fail rather than quietly
falling back to every interface.

The unix-socket `mode` defaults to `0600`, because this transport's
entire security story is filesystem permissions and inheriting a typical
umask would leave the socket connectable by every local user. Widen it
deliberately — `0660` with a shared group — if clients run as someone
else.

## Writing your own

The pipe transport is 150 lines of code and implements the whole
contract, so it is the best template. The shape is always:

1. Own a fixed array of connection slots, sized by `max_connections`.
2. On accept: pick a free slot, call `conn_open(slot, now)`.
3. On readable: `conn_data(slot, bytes, now)`, for a bounded number of
   reads — see above; whatever is left waits for the next pass.
4. On EOF or error: free the slot, call `conn_closed(slot)`.
5. In `send()`: append to that slot's output buffer; if it is full,
   write it out and retry once; return `false` only if it is still full.
6. In `close()`: flush what you can, free the slot, and do not call back.
7. Call `tick(now)` once per loop iteration, then write every buffer that
   gained bytes during the iteration — one write per connection.

Buffering matters: `send()` must accept the entire span, so each
connection needs an output buffer sized for the largest burst you expect
(the bundled transports use a 4 KB ring per connection, configurable).
Returning `false` is how a slow consumer gets dropped rather than
stalling the broker.

## Layering TLS

Because the adapter that adds TLS is *itself* a transport towards the
broker and a broker towards the raw transport, it composes without either
side knowing:

```
TcpTransport  ⟷  TlsAdapter<Engine>  ⟷  Broker
 (ciphertext)     (your TLS library)     (plaintext)
```

See [TLS](tls.md) for the engine interface and the mbedTLS mapping.
