// minimosq — the transport contract.
//
// The broker is transport-agnostic: it never touches sockets, only
// abstract connection indices. A transport is any type that satisfies
// the compile-time policy below (static polymorphism — no virtual
// dispatch, the broker is templated on the transport type).
//
//   struct MyTransport {
//       // Queue bytes for transmission on a connection. The whole span
//       // must be accepted (buffer internally). Return false when the
//       // span cannot be taken — typically the output buffer is full
//       // after the transport already tried to drain it.
//       //
//       // What the broker makes of a refusal depends on what it was
//       // sending. For traffic driven by the peer or by another client
//       // it is a slow consumer and the connection is dropped. For a
//       // burst the broker generated itself — retained replay, the
//       // queue flush on reconnect — a refusal only says the broker
//       // outran the buffer, so it pauses and resumes on a later pass
//       // rather than punishing the peer for it.
//       //
//       // Do NOT call back into the broker from here, conn_closed()
//       // included. send() runs inside the loop over sessions that
//       // routes a publish, and inside the queue flush, both of which
//       // hold a reference to the session being served; conn_closed()
//       // runs the deferred teardown, which can release that session
//       // and leave the caller reading an object that no longer
//       // exists.
//       //
//       // A peer found dead while sending is reported the same way as
//       // any other refusal: return false. What follows depends on what
//       // the broker was sending, per the paragraph above — ordinary
//       // traffic drops the connection, a self-generated burst paces
//       // and tries again. A transport that must not be asked again
//       // closes the connection on its own next pass and reports it
//       // through conn_closed() from there, not from inside send().
//       bool send(size_t conn, minimosq::ByteSpan bytes);
//
//       // Tear a connection down (broker-initiated). Free the slot and
//       // do NOT call Broker::conn_closed() back — that entry point is
//       // only for closes the broker did not initiate. Flushing
//       // already-queued bytes first is best effort but expected, so
//       // refusal packets (CONNACK with an error code) reach the peer.
//       void close(size_t conn);
//   };
//
// The transport drives the broker in return:
//
//   broker.conn_open(ci, now_ms);        // after accepting a connection
//   broker.conn_data(ci, bytes, now_ms); // whenever bytes arrive
//   broker.conn_closed(ci);              // peer hung up / io error
//                                        // (no timestamp: see below)
//   broker.tick(now_ms);                 // periodically (e.g. every 100 ms)
//
// Rules:
//   - Connection indices are dense in [0, Traits::max_connections);
//     the transport owns their allocation.
//   - Single-threaded: all calls into one broker must come from the
//     same thread (or be externally serialized).
//   - now_ms is a monotonic millisecond clock; wrap-around is handled.
//
//   - conn_closed() takes no timestamp. The disconnect it records — the
//     one Traits::session_expiry_ms measures from — is stamped with the
//     most recent time the broker was given, so it can be as stale as
//     one poll pass when a transport reports the close before its
//     tick(). Both reference transports do. The error is bounded by the
//     interval between the calls that carry a timestamp — conn_open(),
//     conn_data() and tick() — since conn_closed() is itself one that
//     does not. A session_expiry_ms comparable to that interval expires
//     up to one interval late; it is in milliseconds and nothing
//     constrains it to be larger. The
//     ordering used to pick an eviction victim is a counter, not a
//     clock, and is unaffected either way.
//
//   - A transport may publish `static constexpr size_t max_connections`.
//     When it does, Broker static_asserts that it is at least
//     Traits::max_connections, which catches a mis-sized transport at
//     compile time instead of as an out-of-bounds write.
//
//   - A transport that buffers outbound bytes may publish
//     `static constexpr size_t out_buf_size`. When it does, Broker
//     static_asserts that it is at least Broker::out_size — the framed
//     size of the widest packet the broker builds, which is more than
//     Traits::max_packet_size, that being a bound on an inbound body.
//     A buffer smaller than one packet can never send that packet, to
//     any peer, at any speed, so send() would fail forever rather than
//     transiently.
//
// See transports/posix/ for reference implementations (TCP, unix
// domain sockets, pipes) and transports/tls_adapter.hpp for how a TLS
// engine slots in between.
//
// SPDX-License-Identifier: MIT
#ifndef MINIMOSQ_TRANSPORT_HPP
#define MINIMOSQ_TRANSPORT_HPP

#include <cstddef>

#include "core/span.hpp"

namespace minimosq {

// A transport that swallows everything. Useful for tests and for
// exercising application-side publish logic without any I/O.
// A transport that publishes its connection capacity lets the broker
// check at compile time that the two agree; one that does not is
// assumed to be correctly sized (0 = "did not say").
template <typename T, typename = void>
struct transport_max_connections {
    static constexpr size_t value = 0;
};
template <typename T>
struct transport_max_connections<T, decltype((void)T::max_connections)> {
    static constexpr size_t value = T::max_connections;
};

// Likewise for the outbound buffer: a transport that publishes its
// capacity lets the broker check that a whole packet fits, and one that
// does not (or that does not buffer at all) is left alone.
template <typename T, typename = void>
struct transport_out_buf_size {
    static constexpr size_t value = 0;
};
template <typename T>
struct transport_out_buf_size<T, decltype((void)T::out_buf_size)> {
    static constexpr size_t value = T::out_buf_size;
};

// The tighter of a wrapper's own capacity and the one it wraps. A
// wrapped transport that publishes nothing (0) constrains nothing.
constexpr size_t narrower_capacity(size_t own, size_t wrapped) noexcept {
    return wrapped == 0 ? own : (wrapped < own ? wrapped : own);
}

struct NullTransport {
    bool send(size_t conn, ByteSpan bytes) noexcept {
        (void)conn;
        (void)bytes;
        return true;
    }
    void close(size_t conn) noexcept { (void)conn; }
};

}  // namespace minimosq

#endif  // MINIMOSQ_TRANSPORT_HPP
