# Security and ACLs

Security in minimosq is layered, and every layer is a policy you control:

1. **Transport security** — TLS below the broker via the adapter seam
   ([TLS](tls.md)), or OS-level isolation with the unix-socket transport
   (whose socket file is created `0600` by default; pass a wider mode to
   `open()` deliberately if clients run as other users). The TCP
   transport takes an optional bind address, so `open(1883, "127.0.0.1")`
   keeps a plaintext broker off the network entirely.
2. **Authentication** — who is connecting.
3. **Authorization** — what they may publish, subscribe to, and receive.
4. **Resource protection** — every table is fixed and every refusal is
   documented behaviour, so a hostile or broken client cannot make the
   broker allocate, fragment or fail unpredictably. Precisely: this
   bounds what a client can *cost*, and — with the reclamation below —
   how long it can *occupy*. It does not mean no client is ever refused;
   a full table refuses, by design.
5. **Observability** — every refusal, denial and drop is reported through
   the [Observer](observability.md) policy, because a resource control you
   cannot see working is not one you can operate.

## The security policy

The broker's third template parameter is a security policy. It
authenticates each CONNECT and produces a per-session `Context` — the
principal — which every later authorization check receives, so
per-message checks never re-derive identity:

```cpp
struct MySecurity {
    struct Context { uint8_t role = 0; };   // any trivially copyable type

    minimosq::ConnackCode authenticate(minimosq::StrView client_id,
                                       const minimosq::StrView* username,
                                       const minimosq::ByteSpan* password,
                                       Context& ctx);

    bool authorize_publish(const Context&, minimosq::StrView topic);
    bool authorize_subscribe(const Context&, minimosq::StrView filter);
    bool authorize_receive(const Context&, minimosq::StrView topic);
};

minimosq::Broker<Traits, Transport, MySecurity> broker{transport};
```

`username` and `password` are null pointers when the client did not
supply them. Returning anything other than `ConnackCode::accepted` sends
that CONNACK code and closes the connection.

The context is stored in the session and **refreshed on every
reconnect**, so a persistent session that reauthenticates into a weaker
role immediately loses its former permissions.

The default policy, `AllowAllSecurity`, permits everything.

### Deny semantics

Each hook has a deny behaviour chosen to be MQTT 3.1.1-conformant:

| Hook | On denial |
| --- | --- |
| `authorize_publish` | Message silently discarded, but still acknowledged (PUBACK / the full PUBREC-PUBREL-PUBCOMP handshake). 3.1.1 has no "not authorized" acknowledgement, and silence avoids leaking which topics exist. Retained storage is skipped too. |
| `authorize_subscribe` | `SUBACK` returns `0x80` for that entry and no subscription is installed. Other entries in the same packet are unaffected. A refusal also suppresses the retained replay for that entry — including when the session still holds an identical subscription granted before the policy changed. |
| `authorize_receive` | That subscriber is skipped for that message — live routing, retained delivery on subscribe, and offline queueing alike. |

Wills pass through `authorize_publish` when they fire, so a client cannot
use a will to say something it could not have published directly.

Checking *receive* separately from *subscribe* is deliberate: it means a
client holding a broad filter (or one granted before a policy change)
still only ever receives what it is currently cleared for.

## TableAcl: ready-made role-based ACLs

`minimosq/broker/table_acl.hpp` implements the common case: a fixed user
table mapping credentials to roles, and a fixed rule table granting roles
read and/or write access to topic patterns. Everything not granted is
denied.

```cpp
using Acl = minimosq::TableAcl</*MaxUsers=*/8, /*MaxRules=*/16>;
minimosq::Broker<Traits, Transport, Acl> broker{transport};

constexpr uint8_t ROLE_SENSOR = 1, ROLE_DASHBOARD = 2;

Acl& acl = broker.security();
acl.add_user("sensor-1",  "s3cret", ROLE_SENSOR);
acl.add_user("dashboard", "d4sh",   ROLE_DASHBOARD);
acl.add_rule(ROLE_SENSOR,    "sensors/#", Acl::write);
acl.add_rule(ROLE_DASHBOARD, "sensors/#", Acl::read);
acl.add_rule(ROLE_DASHBOARD, "control/#", Acl::read_write);
```

Rules use ordinary topic-filter syntax, so `sensors/+/data` works. Tables
are populated at startup and static thereafter; `add_user` and `add_rule`
return `false` when a table is full or an argument is invalid — check
them, as the example does.

Behaviour worth knowing:

* **Anonymous clients are refused** (`not_authorized`) unless you call
  `allow_anonymous(role)`.
* **Unknown username and wrong password answer the same thing** — both
  `bad_credentials`. The lookup scans the whole user table and compares
  every stored password whether or not the name matched, so neither the
  response nor the number of password comparisons distinguishes them.
  **The response, not the response time.** The *username* comparison
  still short-circuits at the first differing byte, which is measurable
  in the low tens of CPU cycles — enough, given enough samples on a
  low-jitter path such as a unix socket or a co-resident attacker, to
  recover a username byte by byte. It is not reachable across a plant
  network. If your threat model includes a local attacker, compare
  usernames with `constant_time_eq` as well, or key on a
  transport-derived identity instead.
* **Passwords are compared in constant time.** The comparison has no
  data-dependent early exit; a *length* difference is still observable,
  which for passwords is an accepted trade.
* **Duplicate usernames are rejected** by `add_user` rather than
  silently shadowed, so a config typo fails loudly at startup.
* **Subscriptions are checked by filter subsumption**: the requested
  filter must lie entirely within a granted pattern. A client cleared for
  `home/#` cannot subscribe to `#`. (`topic_filter_covers()` in
  `topic.hpp` implements this and is usable on its own.)

A complete worked deployment is
[`examples/tcp_broker_acl.cpp`](../examples/tcp_broker_acl.cpp).

## Threat model and caveats

Found something this section does not account for? Report it privately —
[SECURITY.md](../SECURITY.md) has the disclosure process and the list of
limitations that are documented rather than defects.

**Passwords travel and rest in plaintext.** That is MQTT 3.1.1: the
protocol has no challenge-response, and `TableAcl` stores what it is
given. For anything exposed beyond a trusted link:

* Run TLS underneath ([TLS](tls.md)) — otherwise credentials, topics and
  payloads are all readable on the wire.
* Replace the comparison in `TableAcl::authenticate` with a salted hash
  check, or write your own policy; the interface does not care how you
  decide.
* Consider identity from the transport instead — a client certificate's
  subject, or the peer credentials of a unix socket — by having your TLS
  or socket layer stash the identity where your policy can read it.

**Authorization is only as good as your patterns.** Prefer narrow write
grants: a device that only ever reports should hold `write` on
`devices/<id>/#` and nothing else, so a compromised device cannot forge
another's telemetry or publish commands.

**`$`-topics are not special beyond the spec rule.** minimosq implements
no `$SYS` tree. Wildcard filters never match `$`-prefixed topics, but if
you publish into `$`-namespaces yourself, write ACL rules for them.

## Resource protection

These are always on, and tuned through the traits:

| Limit | Effect |
| --- | --- |
| `connect_timeout_ms` | A connection that does not complete CONNECT is dropped |
| `max_packet_size` | Larger inbound packets close the connection instead of being buffered |
| Keep-alive | Idle clients are dropped after 1.5 keep-alive periods |
| `max_idle_ms` | Reclaims clients that connected with keep-alive 0; see below |
| Transport output buffer | A client that will not drain its socket is dropped rather than stalling the broker |
| Transport read budget | One connection is drained at most `max_reads_per_pass` times per poll, so a chatty peer cannot starve the others or stall `tick()` |
| `max_topic_len` | A PUBLISH or will topic too long to store is refused outright, rather than reaching QoS 0 subscribers and silently skipping QoS>0 ones |
| `session_expiry_ms` | Discards persistent sessions whose client never came back; see below |
| Session eviction | A full session pool releases the longest-disconnected session rather than refuse a new client |
| `max_sessions`, `max_retained`, `max_pending_per_session`, `max_inbound_qos2` | Fixed tables; a full table is refused cleanly (see the policy table in [Design notes](design.md)) |

Because nothing is allocated at runtime, there is no fragmentation and no
out-of-memory path: the worst case is a refused connection or a dropped
message, both of which are documented behaviours — and both of which are
reported to the [Observer](observability.md), so "the broker is quietly
dropping things" is something you can detect rather than infer.

### Idle clients and `max_idle_ms`

Be precise about what the fixed tables buy you: they bound how much
memory a client can cost, **not** how long it can occupy a slot. MQTT
defines keep-alive 0 as "never time out", so a client that connects with
keep-alive 0 and then says nothing holds its connection *and* its session
slot indefinitely. With `max_connections` in the single digits — the
normal case for an embedded broker — a handful of such clients is all it
takes to make the broker answer `CONNACK 0x03` to everyone else.

`max_idle_ms` closes that. It applies only to connections whose client
asked for keep-alive 0, and reclaims them after that long without
traffic:

```cpp
struct MyTraits : minimosq::DefaultTraits {
    static constexpr uint32_t max_idle_ms = 300000;  // 5 minutes
};
```

It defaults to 0 (disabled), which is the letter of the spec and the
pre-existing behaviour. Anything reachable by untrusted clients should
set it. The member is optional — traits that predate it still compile
and behave as if it were 0.

**It closes the keep-alive-0 case and only that case.** A client that
asks for keep-alive 65535 rather than 0 is not idle by the broker's
reckoning until 1.5 × 65535 s — over 27 hours — has passed, and
`max_idle_ms` does not apply to it. If you need a hard ceiling on how
long any client may hold a connection, reject or clamp implausible
keep-alive values in your own `Security::authenticate`, or enforce it in
the transport; the broker honours what the client asked for.

### Sessions that outlive their clients

Connections are not the only slot a client occupies. A `clean_session=0`
session survives its connection, and MQTT 3.1.1 gives it no expiry — so
without help, a client that connects, disconnects cleanly and repeats
fills `max_sessions` with sessions nothing will reclaim, and no
connection is left for keep-alive or `max_idle_ms` to act on.

`Traits::session_expiry_ms` discards a session that has been disconnected
that long. Like `max_idle_ms` it defaults to 0 and should be set on
anything reachable by untrusted clients:

```cpp
struct MyTraits : minimosq::DefaultTraits {
    static constexpr uint32_t session_expiry_ms = 3600000;  // 1 hour
};
```

Independently of the timer, a full session pool evicts the
longest-disconnected session rather than refuse a new client, so
exhaustion degrades into "the oldest absent client loses its queued
messages" rather than "the broker stops accepting anyone". A session with
a live connection is never evicted. Both paths are reported
(`session_expired`, `session_evicted`).
