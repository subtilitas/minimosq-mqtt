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
[`include/minimosq/transport.hpp`](include/minimosq/transport.hpp).

## Bundled transports

All POSIX-only, and all examples rather than core:

| Header | What it is |
| --- | --- |
| `transports/posix/tcp.hpp` | TCP server; works on lwIP targets (ESP-IDF, Zephyr) too |
| `transports/posix/unix_socket.hpp` | Unix domain socket server, for local-only brokers |
| `transports/posix/pipe.hpp` | One connection over any pair of stream descriptors — pipes, FIFOs, a socketpair, a child process's stdio |
| `transports/posix/stream_server.hpp` | The shared nonblocking `poll()` loop behind the TCP and unix-socket transports |
| `transport.hpp` | The contract, plus `NullTransport` for tests |

`TcpTransport` and `UnixSocketTransport` differ only in how the listening
socket is created; everything else — accept handling, per-connection
output ring, slow-consumer detection, `EINTR`/`EAGAIN` handling — lives in
`StreamServerTransport`.

## Writing your own

The pipe transport is about 150 lines and implements the whole contract,
so it is the best template. The shape is always:

1. Own a fixed array of connection slots, sized by `max_connections`.
2. On accept: pick a free slot, call `conn_open(slot, now)`.
3. On readable: `conn_data(slot, bytes, now)` until the read would block.
4. On EOF or error: free the slot, call `conn_closed(slot)`.
5. In `send()`: append to that slot's output buffer, try to flush, and
   return `false` if the buffer overflowed.
6. In `close()`: flush what you can, free the slot, and do not call back.
7. Call `tick(now)` once per loop iteration.

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

See [TLS](TLS) for the engine interface and the mbedTLS mapping.
