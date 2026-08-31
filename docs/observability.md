# Observability

`Observer`, the fourth `Broker` template parameter, is where the broker's
decisions come out: why a connection went away, which packet was a
protocol violation, which retained message could not be stored, which
delivery was dropped and for whom.

It follows the same static-polymorphism pattern as the transport and
security policies: one method, no virtuals, no allocation. The default,
`NullObserver`, has an empty body and optimizes away, so a broker that
does not want events pays nothing for the seam.

```cpp
struct MyObserver {
    Sink* sink = nullptr;

    void on_event(const minimosq::Event& e) noexcept {
        sink->write(minimosq::event_kind_name(e.kind), e.client_id, e.topic);
    }
};

minimosq::Broker<Traits, Transport, minimosq::AllowAllSecurity, MyObserver>
    broker{transport};

broker.observer().sink = &my_sink;   // the broker owns it; reach it like security()
```

The observer is a member of the broker, default-constructed with it, so
anything it needs is configured through `observer()` after construction —
the same arrangement as `security()`.

## The contract

* `on_event()` is called from inside a broker entry point, on the same
  thread, with the broker mid-operation. **It must not call back into
  the broker** — `publish()`, `conn_data()` and friends would reenter the
  shared packet build buffer. Copy what you need and return.
* Every `StrView` in an `Event` borrows broker-owned storage and is valid
  only for the duration of the call.
* Events are notifications, not a control point. Nothing the observer
  does changes what the broker then does. Authorization decisions belong
  in the [Security](security.md) policy, which is a control point.
* Adding a new `EventKind` is not a breaking change: an observer
  switching on `kind` simply does not match the new value. That is why
  this is one method with a tagged struct rather than a method per event.

## The event

```cpp
struct Event {
    EventKind kind;
    size_t ci;              // connection index, or Event::no_conn
    StrView client_id;      // empty when not known yet
    StrView topic;          // topic name or filter, when relevant
    Err err;                // protocol_violation, delivery_dropped
    ConnackCode connack;    // connect_refused
    QoS qos;                // delivery_dropped
};
```

Which fields carry something depends on the kind; the rest hold empty
defaults, so reading one that does not apply gives you an empty view
rather than stale data.

| Kind | Meaning | Fields beyond `kind` |
| --- | --- | --- |
| `connection_opened` | the transport accepted a connection | `ci` |
| `connection_closed` | a connection is being torn down, for any reason | `ci`, `client_id` |
| `connect_refused` | CONNACK carried a refusal code | `ci`, `client_id`, `connack` |
| `protocol_violation` | the peer broke the protocol; the connection closes | `ci`, `client_id`, `err` |
| `transport_send_failed` | `Transport::send()` returned false | `ci`, `client_id` |
| `connect_timeout` | no CONNECT within `connect_timeout_ms` | `ci` |
| `keepalive_timeout` | 1.5 × keep-alive elapsed | `ci`, `client_id` |
| `idle_timeout` | `max_idle_ms` elapsed on a keep-alive-0 client | `ci`, `client_id` |
| `session_created` | a new session was allocated | `ci`, `client_id` |
| `session_resumed` | a persistent session was found and resumed | `ci`, `client_id` |
| `session_taken_over` | a second client claimed a live client id | `ci`, `client_id` |
| `session_expired` | `session_expiry_ms` elapsed while disconnected | `client_id` |
| `session_evicted` | the pool was full; the oldest promise was broken | `client_id` |
| `publish_denied` | `authorize_publish` said no | `ci`, `client_id`, `topic` |
| `subscribe_denied` | `authorize_subscribe` said no | `ci`, `client_id`, `topic` |
| `receive_denied` | `authorize_receive` said no for one delivery | `ci`, `client_id`, `topic` |
| `retained_store_failed` | the store is full, or the message is too large to own | `topic` |
| `retained_stale_purged` | an unstorable update evicted the value it replaces | `topic` |
| `delivery_dropped` | a QoS>0 delivery was skipped; the publisher is acknowledged anyway | `client_id`, `topic`, `qos`, `err` |

`err` on `delivery_dropped` distinguishes the two causes: `oversize` (the
payload is larger than `max_payload_len`, so no owned copy is possible)
and `capacity` (`max_pending_per_session` is full).

## What this is for

Three things, in rough order of how often they matter.

**Operations.** Without a seam, the only questions answerable from
outside the broker are "did it accept my credentials" and "did my message
arrive". `delivery_dropped` closes the worst hole. Routing happens before
the PUBACK, so the broker knows a subscriber was skipped — but 3.1.1 has
no "not delivered" acknowledgement, so the publisher is acknowledged
anyway and the subscriber never learns the message existed. The drop is
invisible from both ends unless the broker says so.

**Security monitoring.** `connect_refused`, `publish_denied`,
`subscribe_denied`, `receive_denied` and `session_taken_over` are the
events an intrusion-detection rule would key on. They are also the ones a
`Security` policy could partly observe on its own — the seam matters more
for the ones it cannot see, like `protocol_violation` and
`transport_send_failed`.

**Compliance.** IEC 62443-4-2 requires that security-relevant events be
recorded: CR 2.8–2.12 (auditable events, storage capacity, response to
audit processing failures, timestamps, non-repudiation) and CR 6.1–6.2
(audit log accessibility, continuous monitoring). A component that does
not surface its events cannot have that requirement delegated to it,
however good its access control. minimosq emits the events an audit log
is built from, and implements no log: that needs a clock, storage and I/O
it deliberately does not have. Timestamps are the integrator's — `now_ms`
is passed in, never read.

## What it deliberately is not

* **Not a log.** No formatting, no severity, no ring buffer, no
  timestamps. Those need policy, storage and a clock; all three belong to
  the integrator.
* **Not metrics.** There are no counters. Counting is three lines in an
  observer and would otherwise have to be paid for by everyone.
* **Not complete.** Successful publishes and normal deliveries are not
  reported: they are the hot path, and an event per message would change
  the performance character of the broker. The events are the exceptions.
