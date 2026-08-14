# TLS integration

minimosq ships no TLS code — the core is dependency-free by design.
What it ships is a clean seam where a TLS library plugs in:
`minimosq/transports/tls_adapter.hpp`.

## Layering

```
 ciphertext                 plaintext
┌──────────────┐   drives   ┌──────────────────┐   drives   ┌────────┐
│ TcpTransport │ ─────────► │ TlsAdapter<E>    │ ─────────► │ Broker │
│ (or UDS, …)  │ ◄───────── │  Engine E per    │ ◄───────── │        │
└──────────────┘   send()   │  connection      │   send()   └────────┘
                            └──────────────────┘
```

Both interfaces already exist in the library:

- Towards the broker, the adapter is a **transport** (`send`, `close` —
  see `include/minimosq/transport.hpp`).
- Towards the raw transport, the adapter **poses as the broker**
  (`conn_open`, `conn_data`, `conn_closed`, `tick`). The raw transports
  are templated on "the broker", so they drive the adapter without any
  modification.

Wiring it up:

```cpp
minimosq::TcpTransport<Traits::max_connections> raw;
raw.open(8883);

minimosq::TlsAdapter<MyTlsEngine, decltype(raw),
                     Traits::max_connections> tls{raw};
minimosq::Broker<Traits, decltype(tls)> broker{tls};

auto driver = tls.driver(broker);
raw.run(driver);
```

## What the Engine must do

One `Engine` instance exists per connection slot. The full policy is
documented in `tls_adapter.hpp`; in short:

| Hook             | Responsibility                                        |
|------------------|-------------------------------------------------------|
| `reset()`        | new connection: drop handshake and session state      |
| `on_ciphertext()`| feed wire bytes in; may yield decrypted app data and/or handshake records to transmit |
| `encrypt()`      | wrap outbound app data into TLS records               |

Returning `false` from either I/O hook drops the connection.

## Mapping to mbedTLS (sketch)

The natural fit is mbedTLS's memory-BIO style callbacks:

- `mbedtls_ssl_set_bio(&ssl, ctx, tx_cb, rx_cb, nullptr)` — the `rx_cb`
  reads from the ciphertext the adapter passed to `on_ciphertext()`;
  the `tx_cb` appends to the `cipher` output buffer.
- During the handshake, call `mbedtls_ssl_handshake(&ssl)` from
  `on_ciphertext()` until it stops returning
  `MBEDTLS_ERR_SSL_WANT_READ/WRITE`.
- After the handshake, `on_ciphertext()` drains `mbedtls_ssl_read()`
  into the `plain` buffer, and `encrypt()` is `mbedtls_ssl_write()`.

wolfSSL offers the same shape via `wolfSSL_SetIO*` callbacks.

Keep certificates and key material in static storage, sized at compile
time, to preserve the no-allocation property. TLS records are at most
16 KiB; on constrained targets negotiate the `max_fragment_length`
extension and size `TlsAdapter`'s `BufSize` accordingly.

## Why no bundled engine?

Shipping a real TLS transport would drag a crypto library into the
dependency-free core, and pretending to do TLS without one would be
worse. `NullTlsEngine` exists purely to compile-check and demonstrate
the wiring — it copies bytes through unchanged and is **not** a
security boundary.
