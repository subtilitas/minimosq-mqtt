# minimosq — design notes

## Goals

- **Embedded-first**: a broker you can link into a firmware image or a
  small daemon. All state is inside the `Broker` object, sized at
  compile time by a traits struct. No heap, no exceptions, no RTTI, no
  dependencies beyond freestanding C++ headers (`<cstdint>`,
  `<cstddef>`, `<new>`).
- **Simple and readable** over clever. Linear scans over fixed pools,
  one owned copy per queued message, packets rebuilt per subscriber.
  At embedded scale (tens of connections) this is never the
  bottleneck, and every routine stays reviewable.
- **Transport-agnostic core**: the broker sees connection indices and
  byte spans, nothing else. POSIX transports are examples, not part of
  the core.

## Layering

```
core/       spans, error codes, fixed-capacity containers
protocol/   MQTT 3.1.1 wire: reader/writer, frame parser, packets
topic.hpp   topic validation + wildcard matching
broker/     sessions, retained store, the Broker state machine
            (+ observer.hpp: the event seam)
transport.hpp             the transport contract (documentation + NullTransport)
transports/posix/         TCP, unix socket, pipe reference transports
transports/tls_adapter.hpp  the TLS seam (interface only, see docs/tls.md)
```

Each layer only includes the ones above it. The tests mirror the
layering: every layer has its own suite, and the broker suites drive
real wire bytes through a capturing transport.

## Memory model

`sizeof(Broker<Traits, Transport>)` is the whole cost; the example
prints it at startup. Dominant terms:

- per connection: one `FrameParser` (≈ `max_packet_size`)
- per session: subscriptions + `max_pending_per_session` owned
  messages (≈ `max_topic_len + max_payload_len` each)
- retained store: `max_retained` owned messages
- one shared outgoing build buffer

Everything is a plain member array — the broker can live in static
storage (`.bss`), which is exactly what the examples do.

The term that actually decides the number is the per-session queue,
because it is a *product*:

```
max_sessions x max_pending_per_session x (max_topic_len + max_payload_len)
```

At `DefaultTraits` that is 8 × 8 × (128 + 512) ≈ 41 KB of the ~76 KB
total, and it is why the `Gateway` configuration in the footprint table
costs ~600 KB rather than the ~150 KB the other knobs suggest. If a
configuration comes out larger than expected, `max_pending_per_session`
and `max_payload_len` are almost always the pair to look at first —
halving either halves the dominant term. `tools/footprint.cpp` prints
the measured size for several configurations, and the
[Configuration](Configuration) page carries the generated table.

## Threading model

Single-threaded by design. All broker entry points must be called from
one thread (or be externally serialized); the broker never blocks and
never calls out except through the transport policy. Run it inside
your event loop, super-loop, or a dedicated thread.

Time is passed in (`now_ms`, monotonic, wrap-tolerant), so the core
has no clock dependency.

## Reentrancy and teardown

Dropping a connection may publish a will, which routes a message,
which may drop further connections (send failures). To keep this
iterative and to never reuse the packet build buffer mid-route,
teardown is deferred: drops set a `dead` flag, and `flush_dead()` at
the tail of each entry point tears connections down until quiescence.

## QoS implementation

- Inbound QoS 1: route, then PUBACK.
- Inbound QoS 2: packet ids are tracked per session between PUBLISH
  and PUBREL (delivery on first PUBLISH, method A of the spec);
  redeliveries are detected and not routed twice. The id table
  survives reconnects of persistent sessions.
- Outbound QoS 1/2: per-session ordered queue of owned message
  copies with per-message state (`queued`, `awaiting_puback`,
  `awaiting_pubrec`, `awaiting_pubcomp`). On reconnect of a
  persistent session, in-flight messages retransmit with DUP=1 and
  their original packet id, pending PUBRELs are repeated, then the
  offline queue flushes — in original order.
- Each session receives a message once, at min(publish QoS, max
  granted QoS across its matching subscriptions).

## Security architecture

Security follows the same policy pattern as the transport: a `Security`
template parameter authenticates each CONNECT into a per-session
principal (`Context`), which three authorization hooks then consult —
`authorize_publish`, `authorize_subscribe`, `authorize_receive`. The
receive hook is separate from the subscribe hook on purpose, so a
broad or stale subscription still cannot deliver restricted topics.

Deny paths were chosen to stay 3.1.1-conformant: refused publishes are
dropped silently but acknowledged (there is no error ack in 3.1.1, and
silence avoids leaking topic existence), refused subscriptions answer
SUBACK 0x80. Wills are authorized when they fire, not when they are
registered.

Full details, the `TableAcl` component, and the threat model are in
[security.md](security.md).

## Documented policy decisions (spec-permitted or capacity-driven)

| Situation | Behaviour |
|---|---|
| Ill-formed UTF-8 in any MQTT string | connection closed, as [MQTT-1.5.3] requires |
| Syntactically invalid topic filter in (UN)SUBSCRIBE | protocol violation: connection closed |
| Valid filter beyond `max_topic_len`, or subscription table full | SUBACK 0x80 for that entry |
| Duplicate identical filter within one SUBSCRIBE | one subscription, one return code per entry, retained messages replayed once |
| SUBSCRIBE/UNSUBSCRIBE that is a protocol error | validated in full before anything is applied, so the packet has no partial effect |
| Client connects with keep-alive 0 | never timed out, unless `max_idle_ms` is set (see [Security](security.md)) |
| Empty client id, clean session | server assigns a unique `mmq-<n>` id |
| Empty client id, persistent session | CONNACK 0x02, connection closed |
| Retained store full | best effort: not stored, still forwarded live |
| Retained message too big to store, topic already retained | the previous value is **purged**, not left to be served as current; still forwarded live |
| Offline queue full | newest message for that session is dropped, and `delivery_dropped` reported |
| Topic name longer than `max_topic_len` (PUBLISH or will) | refused: connection closed (PUBLISH) / CONNACK 0x03 (will). It could not be retained or queued, so half-delivering it is worse than refusing |
| Payload larger than `max_payload_len` | delivered QoS 0 pass-through only; QoS>0 subscribers skipped and `delivery_dropped` reported (size `max_payload_len >= max_packet_size` to avoid) |
| Inbound QoS 2 id table full | connection dropped (duplicate delivery is never risked) |
| Will topic/payload beyond capacity limits | CONNACK 0x03, connection closed |
| Session slots exhausted, some session disconnected | the longest-disconnected session is evicted for the new client |
| Session slots exhausted, every session connected | CONNACK 0x03, connection closed |
| Persistent session disconnected for `session_expiry_ms` | discarded (0 = never, the letter of the spec) |
| Unknown PUBACK/PUBREC/PUBCOMP ids | ignored |
| QoS 0 messages for offline persistent sessions | dropped (spec-sanctioned) |

## Session lifetime

MQTT 3.1.1 has no session expiry. A `clean_session=0` session is meant to
live until its client returns, and taken literally that is a liveness
bug: a client can connect, disconnect cleanly, and repeat until
`max_sessions` slots hold sessions nothing will ever come back for —
with no connection left for any timeout to reclaim. Every later client
then gets CONNACK 0x03.

Two mechanisms bound it, and they are deliberately different in kind:

- **`Traits::session_expiry_ms`** discards a session that has been
  disconnected that long. It is the policy, it is off by default (0), and
  it is what stops dead sessions accumulating.
- **Eviction** is the guarantee. When the pool is full and a new client
  authenticates, the longest-disconnected session is released to make
  room. A session with a live connection is never a victim, so this can
  only break a promise to a client that is not currently here. Ordering
  is by a monotonic ticket stamped at disconnect, not by the clock, so
  "gone longest" stays a total order however long a session has been
  idle.

Eviction is always on and needs no configuration, because "the broker
refuses everyone" is never the better answer to a full table. The timer
exists so eviction stays the exception.

## Observability

The broker reports what it decides through an `Observer` policy — the
fourth template parameter, defaulting to a `NullObserver` that compiles
away. Connection and session lifecycle, protocol violations,
authorization denials, capacity refusals and dropped deliveries all
surface as a single tagged `Event`. See
[observability.md](observability.md) for the contract and the event
table.

The seam exists because the interesting cases are otherwise invisible. A
QoS 1 PUBLISH is routed before its PUBACK goes out, so the broker knows
perfectly well that a subscriber was skipped — 3.1.1 simply gives it no
way to say so. The publisher is acknowledged regardless, and the
subscriber never learns the message existed. Without an event, nobody
can see the drop from either end.

## Out of scope (deliberately)

- MQTT 5.0 (properties, reason codes, shared subscriptions)
- `$SYS` broker status topics
- Bridging, clustering, persistence across reboots
- A bundled TLS implementation (see `docs/tls.md` for the seam)
- Logging, metrics and audit storage (see `docs/observability.md` for the
  event seam they are built from)
