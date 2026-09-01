// minimosq — the transport contract.
//
// The broker is transport-agnostic: it never touches sockets, only
// abstract connection indices. A transport is any type that satisfies
// the compile-time policy below (static polymorphism — no virtual
// dispatch, the broker is templated on the transport type).
//
//   struct MyTransport {
//       // Queue bytes for transmission on a connection. The whole span
//       // must be accepted (buffer internally). Return false only when
//       // the connection is beyond saving (e.g. its output buffer
//       // overflowed because of a slow consumer); the broker then
//       // drops the connection.
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
//   broker.tick(now_ms);                 // periodically (e.g. every 100 ms)
//
// Rules:
//   - Connection indices are dense in [0, Traits::max_connections);
//     the transport owns their allocation.
//   - Single-threaded: all calls into one broker must come from the
//     same thread (or be externally serialized).
//   - now_ms is a monotonic millisecond clock; wrap-around is handled.
//
//   - A transport may publish `static constexpr size_t max_connections`.
//     When it does, Broker static_asserts that it is at least
//     Traits::max_connections, which catches a mis-sized transport at
//     compile time instead of as an out-of-bounds write.
//
//   - A transport that buffers outbound bytes may publish
//     `static constexpr size_t out_buf_size`. When it does, Broker
//     static_asserts that it is at least Traits::max_packet_size: a
//     buffer smaller than one packet can never send that packet, to any
//     peer, at any speed, so send() would fail forever rather than
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
