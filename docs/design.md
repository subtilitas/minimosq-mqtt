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

## Documented policy decisions (spec-permitted or capacity-driven)

| Situation | Behaviour |
|---|---|
| Ill-formed UTF-8 in any MQTT string | connection closed, as [MQTT-1.5.3] requires |
| Syntactically invalid topic filter in (UN)SUBSCRIBE | protocol violation: connection closed |
| Valid filter beyond `max_topic_len`, or subscription table full | SUBACK 0x80 for that entry |
| Duplicate identical filter within one SUBSCRIBE | retained message delivered once per entry |
| Empty client id, clean session | server assigns a unique `mmq-<n>` id |
| Empty client id, persistent session | CONNACK 0x02, connection closed |
| Retained store full / message too big to store | best effort: not stored, still forwarded live |
| Offline queue full | newest message for that session is dropped |
| Payload larger than `max_payload_len` | delivered QoS 0 pass-through only; QoS>0 subscribers skipped (size `max_payload_len >= max_packet_size` to avoid) |
| Inbound QoS 2 id table full | connection dropped (duplicate delivery is never risked) |
| Will topic/payload beyond capacity limits | CONNACK 0x03, connection closed |
| Session slots exhausted | CONNACK 0x03, connection closed |
| Unknown PUBACK/PUBREC/PUBCOMP ids | ignored |
| QoS 0 messages for offline persistent sessions | dropped (spec-sanctioned) |

## Out of scope (deliberately)

- MQTT 5.0 (properties, reason codes, shared subscriptions)
- `$SYS` broker status topics
- Bridging, clustering, persistence across reboots
- A bundled TLS implementation (see `docs/tls.md` for the seam)
