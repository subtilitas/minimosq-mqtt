// minimosq — TLS integration seam (interface only, no TLS code).
//
// The broker core stays dependency-free, so minimosq does not ship a
// TLS implementation. What it ships is the *seam*: TlsAdapter slots
// between any raw transport and the broker, so that the wire carries
// ciphertext while the broker sees plaintext:
//
//   TcpTransport  ⟷  TlsAdapter<Engine>  ⟷  Broker
//   (ciphertext)      (your TLS library)     (plaintext)
//
// Both interfaces the adapter implements already exist in this
// library: towards the broker it is a Transport (send/close, see
// transport.hpp), towards the raw transport it poses as the broker
// (conn_open/conn_data/conn_closed/tick). No other component changes.
//
// You provide the Engine, one instance per connection, backed by the
// TLS library of your choice (mbedTLS and wolfSSL are the usual
// embedded picks — see docs/tls.md for the mapping):
//
//   struct MyTlsEngine {
//       // Fresh connection; drop all handshake/session state.
//       void reset();
//
//       // Wire bytes arrived. Feed them to the TLS library. Any
//       // decrypted application data goes into `plain` (up to cap,
//       // set plain_len); any handshake/alert records the library
//       // wants to transmit go into `cipher` (set cipher_len).
//       // Return false on a fatal TLS error (connection is dropped).
//       bool on_ciphertext(minimosq::ByteSpan in,
//                          uint8_t* plain, size_t plain_cap, size_t& plain_len,
//                          uint8_t* cipher, size_t cipher_cap, size_t& cipher_len);
//
//       // Encrypt application data for transmission.
//       // Return false on error (or if called before the handshake is
//       // complete and the library cannot buffer).
//       bool encrypt(minimosq::ByteSpan plain,
//                    uint8_t* cipher, size_t cipher_cap, size_t& cipher_len);
//
//       // OPTIONAL. An engine that buffers a record — accepting it from
//       // encrypt() with nothing to write yet — must offer this, or the
//       // record never leaves: encrypt() reporting success is the only
//       // signal the broker gets, and it moves on. The adapter calls it
//       // once per connection per pass and writes whatever comes back.
//       // Return false on a fatal TLS error. Engines that never buffer
//       // may omit it.
//       bool drain(uint8_t* cipher, size_t cipher_cap, size_t& cipher_len);
//
//       // OPTIONAL. Bytes a record adds to the plaintext it carries.
//       // When given, the adapter subtracts it from the buffer size it
//       // publishes, so Broker's outbound-size check accounts for the
//       // growth instead of discovering it as a refusal at run time —
//       // which is an abnormal disconnect, and publishes the will.
//       static constexpr size_t record_overhead = 0;
//   };
//
// NullTlsEngine below is a pass-through with exactly this shape — it
// demonstrates and compile-checks the wiring but performs NO
// encryption. It is not a security boundary of any kind.
//
// SPDX-License-Identifier: MIT
#ifndef MINIMOSQ_TRANSPORTS_TLS_ADAPTER_HPP
#define MINIMOSQ_TRANSPORTS_TLS_ADAPTER_HPP

#include <cstddef>
#include <cstdint>

#include "../core/error.hpp"
#include "../core/span.hpp"
#include "../transport.hpp"

namespace minimosq {

namespace tls_detail {
// Undefined: named only inside decltype, to form an lvalue of a type.
template <typename T>
T& lvalue() noexcept;
}  // namespace tls_detail

// An engine that buffers records offers drain(); one that never does may
// omit it, and the adapter then has nothing to pump.
template <typename E, typename = void>
struct engine_has_drain {
    static constexpr bool value = false;
};
template <typename E>
struct engine_has_drain<E, decltype((void)static_cast<bool>(tls_detail::lvalue<E>().drain(
                               tls_detail::lvalue<uint8_t*>(), tls_detail::lvalue<size_t>(),
                               tls_detail::lvalue<size_t>())))> {
    // The cast is the point: a drain() returning void matches the shape
    // but not the contract, and would fail to compile where the adapter
    // tests the result. It is rejected here instead.
    static constexpr bool value = true;
};

// Bytes a record adds to its plaintext; 0 when the engine does not say.
template <typename E, typename = void>
struct engine_record_overhead {
    static constexpr size_t value = 0;
};
template <typename E>
struct engine_record_overhead<E, decltype((void)size_t{E::record_overhead})> {
    // Braced, so a member that is not a non-narrowing size_t constant —
    // signed, or too wide — is not detected rather than subtracted.
    static constexpr size_t value = size_t{E::record_overhead};
};

// Wiring demonstration only: copies bytes through unchanged.
struct NullTlsEngine {
    void reset() noexcept {}

    // `cipher` is an out parameter of the Engine interface — a real TLS
    // engine writes its handshake and alert records there. This
    // pass-through engine has none to emit, but the signature has to
    // match the contract, so it cannot become a pointer to const.
    // NOLINTBEGIN(readability-non-const-parameter)
    bool on_ciphertext(ByteSpan in, uint8_t* plain, size_t plain_cap, size_t& plain_len,
                       uint8_t* cipher, size_t cipher_cap, size_t& cipher_len) noexcept {
        (void)cipher;
        (void)cipher_cap;
        cipher_len = 0;
        if (in.len > plain_cap) {
            return false;
        }
        for (size_t i = 0; i < in.len; ++i) {
            plain[i] = in.data[i];
        }
        plain_len = in.len;
        return true;
    }
    // NOLINTEND(readability-non-const-parameter)

    bool encrypt(ByteSpan plain, uint8_t* cipher, size_t cipher_cap, size_t& cipher_len) noexcept {
        if (plain.len > cipher_cap) {
            return false;
        }
        for (size_t i = 0; i < plain.len; ++i) {
            cipher[i] = plain.data[i];
        }
        cipher_len = plain.len;
        return true;
    }
};

// BufSize bounds the largest TLS record the adapter can pass in one
// piece; 16384 covers the TLS maximum, embedded deployments typically
// negotiate the max_fragment_length extension and shrink this.
template <typename Engine, typename RawTransport, size_t MaxConns, size_t BufSize = 4096>
class TlsAdapter {
public:
    // Published so Broker can static_assert against Traits.
    // The broker checks its Traits against whatever a transport
    // publishes, and this adapter is what it sees. Publishing MaxConns
    // alone would hide a raw transport with fewer slots: the broker
    // would hand out an index the raw transport refuses, and
    // StreamServerTransport answers Err::state by closing the fresh
    // socket. The narrower of the two is the real capacity.
    static constexpr size_t max_connections =
        narrower_capacity(MaxConns, transport_max_connections<RawTransport>::value);

    // send() encrypts a whole packet into cipher_, so BufSize bounds the
    // largest packet that can pass through the adapter — and then the
    // ciphertext goes to the raw transport's buffer, which bounds it
    // again. Publishing BufSize alone would have the broker check this
    // adapter's scratch buffer and never the ring the bytes land in.
    //
    // Still necessary rather than sufficient: ciphertext is larger than
    // plaintext by the record overhead, which neither number accounts
    // for, so a packet this check allows can still be refused.
    // What a packet may occupy before the engine adds its record
    // framing. Publishing BufSize itself would have Broker check a
    // number the ciphertext then exceeds, and encrypt() would refuse
    // every full-size packet — a refusal the broker reads as an abnormal
    // disconnect, which publishes the peer's will. Accounting for the
    // growth here turns that into a build failure instead.
    static constexpr size_t record_overhead = engine_record_overhead<Engine>::value;
    static_assert(BufSize > record_overhead,
                  "TlsAdapter's BufSize leaves no room for the engine's record overhead");
    static constexpr size_t out_buf_size =
        narrower_capacity(BufSize - record_overhead, transport_out_buf_size<RawTransport>::value);

    explicit TlsAdapter(RawTransport& raw) noexcept : raw_(raw) {}

    Engine* engine(size_t ci) noexcept { return ci < max_connections ? &engines_[ci] : nullptr; }

    // ------------------------- transport policy (the broker calls this)

    bool send(size_t ci, ByteSpan plaintext) {
        if (ci >= max_connections) {
            return false;
        }
        size_t cipher_len = 0;
        if (!engines_[ci].encrypt(plaintext, cipher_, sizeof cipher_, cipher_len)) {
            return false;
        }
        return cipher_len == 0 || raw_.send(ci, ByteSpan{cipher_, cipher_len});
    }

    void close(size_t ci) {
        if (ci < max_connections) {
            raw_.close(ci);
        }
    }

    // Write out whatever the engines are holding. A no-op for engines
    // that do not offer drain(), which are the ones that never buffer.
    //
    // Both failures here end the connection. A drain() refusal is a
    // fatal TLS error by the same rule as on_ciphertext(). A refused
    // write is worse than a dropped packet: the record has already left
    // the engine and cannot be put back, so the peer's stream would
    // resume mid-record. Reporting it from here is safe — this runs from
    // the driver's tick(), not from inside send(), so nothing is
    // iterating the broker's sessions.
    template <typename B>
    void drain_engines(B& broker) {
        if constexpr (engine_has_drain<Engine>::value) {
            for (size_t ci = 0; ci < max_connections; ++ci) {
                size_t cipher_len = 0;
                const bool ok = engines_[ci].drain(cipher_, sizeof cipher_, cipher_len);
                if (ok && cipher_len == 0) {
                    continue;  // nothing held
                }
                if (ok && raw_.send(ci, ByteSpan{cipher_, cipher_len})) {
                    continue;
                }
                raw_.close(ci);
                broker.conn_closed(ci);  // the transport has already closed it
            }
        } else {
            (void)broker;
        }
    }

    // ------------- broker-facing driver (the raw transport calls this)
    //
    // The raw transport is templated on "the broker", so hand it
    // driver(broker) instead of the broker itself:
    //
    //   auto driver = tls.driver(broker);
    //   raw.run(driver);

    template <typename B>
    struct Driver {
        TlsAdapter& tls;
        B& broker;

        Err conn_open(size_t ci, uint32_t now_ms) {
            if (ci >= max_connections) {
                return Err::state;
            }
            tls.engines_[ci].reset();
            return broker.conn_open(ci, now_ms);
        }

        void conn_closed(size_t ci) {
            if (ci < max_connections) {
                broker.conn_closed(ci);
            }
        }

        Err conn_data(size_t ci, ByteSpan cipher_in, uint32_t now_ms) {
            if (ci >= max_connections) {
                return Err::state;
            }
            // The record buffers live in the adapter, not on the stack:
            // 2 x BufSize is 8 KB by default, which is a real fraction of
            // a task stack on the embedded targets this library targets,
            // and it lands at the deepest point of the call chain. The
            // transport contract is single-threaded, so sharing is safe.
            size_t plain_len = 0;
            size_t cipher_out_len = 0;
            if (!tls.engines_[ci].on_ciphertext(cipher_in, tls.plain_, BufSize, plain_len,
                                                tls.cipher_out_, BufSize, cipher_out_len)) {
                tls.raw_.close(ci);
                broker.conn_closed(ci);
                return Err::malformed;
            }
            // Handshake/alert records the engine wants on the wire.
            if (cipher_out_len > 0) {
                if (!tls.raw_.send(ci, ByteSpan{tls.cipher_out_, cipher_out_len})) {
                    tls.raw_.close(ci);
                    broker.conn_closed(ci);
                    return Err::capacity;
                }
            }
            if (plain_len > 0) {
                return broker.conn_data(ci, ByteSpan{tls.plain_, plain_len}, now_ms);
            }
            return Err::ok;
        }

        void tick(uint32_t now_ms) {
            // A record the engine buffered has no other way out: nothing
            // else asks it for output, and on_ciphertext() only runs when
            // the peer sends more bytes.
            tls.drain_engines(broker);
            broker.tick(now_ms);
        }
    };

    template <typename B>
    Driver<B> driver(B& broker) noexcept {
        return Driver<B>{*this, broker};
    }

private:
    RawTransport& raw_;
    // Sized by the published capacity: an index past it never reaches
    // the wrapped transport, so an engine for it could never be used.
    Engine engines_[max_connections];
    // Shared record scratch; see Driver::conn_data. Only ever live for
    // the duration of one call.
    uint8_t plain_[BufSize];
    uint8_t cipher_out_[BufSize];
    uint8_t cipher_[BufSize];
};

}  // namespace minimosq

#endif  // MINIMOSQ_TRANSPORTS_TLS_ADAPTER_HPP
