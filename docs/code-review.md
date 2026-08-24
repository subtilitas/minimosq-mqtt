# Code review — minimosq

Full-tree audit of `include/`, `tests/`, `examples/`, `tools/`, the build
files and CI, at commit `f70eac1`.

**Verdict.** This is careful, well-documented code. I found no
memory-safety defect reachable from the network, no protocol-parsing
overflow, and no authorization bypass in the shipped `TableAcl`. Every
issue below is either a hardening opportunity, a misuse-resistance gap,
or a narrow spec deviation.

> **All findings in this report have since been fixed** — see
> [Resolution](#resolution) below. The report is kept in full as the
> record of what was found and how it was verified; each section
> describes the code as it was at `f70eac1`.

## Resolution

Every finding was fixed and covered by a regression test. The suite grew
from 133 to 154 cases; all pass under ASan + UBSan with
`-Werror -Wconversion -Wsign-conversion -Wshadow`, and the fuzz and
differential harnesses were re-run against the fixed headers with
identical results.

| # | Fix |
| --- | --- |
| M1 | `ci` bounds-checked in `StreamServerTransport` and `TlsAdapter`; transports publish `max_connections` and `Broker` `static_assert`s against it, so a mis-sized transport now fails to build |
| M2 | SUBSCRIBE tracks the grants it actually made (`Subscription::retain_pending`) instead of re-deriving them from the table; a refused entry replays nothing |
| M3 | `Pool::release` validates the pointer and the slot; `pop_back` / `remove_*` no-op instead of underflowing `size_t` |
| M4 | Actions bumped to `checkout@v6` / `upload-artifact@v7`; `release.yml` added |
| L1 | `frame_packet` and the `build_*` helpers return an empty span when the writer failed |
| L2 | Duplicate filters in one SUBSCRIBE resolve to one subscription and replay retained messages once |
| L3 | SUBSCRIBE and UNSUBSCRIBE validate the whole packet before applying anything |
| L4 | `parse_publish` checks truncation before the zero-packet-id rule |
| L5 | `publish()` counts the QoS>0 packet identifier in its size guard |
| L6 | UDS socket created `0600` by default (umask around `bind` + `chmod`), mode configurable |
| L7 | `TableAcl` scans the whole user table and compares every password — no timing oracle |
| L8 | Reads per connection per poll pass capped at `max_reads_per_pass` |
| L9 | TLS record buffers moved off the stack into the adapter |
| L10 | Optional `Traits::max_idle_ms` reclaims keep-alive-0 clients; detected, so existing traits still compile |
| N1–N11 | Stale header reference, wiki-sync comment, missing `#include`, `StrView(nullptr)`, git locks, MSVC + 32-bit CI jobs, smoke-test sleeps, TCP bind address, duplicate usernames, memory-scaling docs — all addressed |

N7 (SHA-pinning actions) was **not** done: it conflicts with the
readable major-version pinning policy this repo uses, and the actions are
first-party. Worth revisiting if the workflows ever take a third-party
action.

The 32-bit CI job could not be exercised locally (no multilib in the
review sandbox), so it is the one change here verified only by
construction.

## How the findings were verified

Everything marked *confirmed* below was reproduced, not just read.

| Check | Result |
| --- | --- |
| All 15 test binaries, `-Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion -Wshadow -fno-exceptions -fno-rtti`, ASan + UBSan, `-fno-sanitize-recover=all` | 133/133 pass, **zero warnings**, zero sanitizer trips |
| `topic_matches()` differential test against an independently written reference matcher | **1,061,312** filter/topic pairs, **0 mismatches** |
| `topic_filter_covers()` soundness (does `cover` really match every topic `filter` matches?) | **7,816** cover/filter pairs, **0 unsound** |
| Random-byte fuzz into `conn_data()` across 4 connections | 60 × 60 steps, no sanitizer trip |
| Structured fuzz (valid framing, random bodies) after CONNECT | 200 × 40 packets, no sanitizer trip |

The topic-matching result is worth calling out: filter matching and
filter subsumption are the security-critical functions in this codebase,
and both survived exhaustive differential testing.

---

## Medium

### M1 — `StreamServerTransport::send()`/`close()` do not bounds-check `ci`

`include/minimosq/transports/posix/stream_server.hpp:57-78`

```cpp
bool send(size_t ci, ByteSpan bytes) {
    Slot& s = slots_[ci];        // no ci < MaxConns check
```

The broker guarantees `ci < Traits::max_connections`, and the transport
is sized by its own `MaxConns` parameter — but nothing ties the two
together. `TcpTransport<8>` under `Traits::max_connections == 16`
compiles cleanly and writes past `slots_`.

Confirmed with UBSan:

```
stream_server.hpp:58:25: runtime error: index 7 out of bounds for type 'Slot [2]'
```

`TlsAdapter` has the same shape (`transports/tls_adapter.hpp:100`,
`:125`, `:136` all index `engines_[ci]` unchecked).

**Fix.** Make the mismatch impossible to write rather than merely
documented. The cheapest version is a guard in the transport:

```cpp
bool send(size_t ci, ByteSpan bytes) {
    if (ci >= MaxConns) { return false; }
    ...
```

Better, add a compile-time tie in `Broker`'s constructor or as a
`static_assert` in a `check_transport<Traits, Transport>()` helper, so
`TcpTransport<8>` + `max_connections == 16` fails to build.

### M2 — Retained messages are replayed for a SUBSCRIBE entry the ACL refused

`include/minimosq/broker/broker.hpp:777-800`

The retained-delivery second pass decides "was this entry accepted?" by
looking the filter up in the session's subscription table:

```cpp
typename SessionT::Subscription* sub = s.find_sub(filter);
if (sub == nullptr) {
    continue;  // this entry was refused above
}
```

That inference is wrong when the session *already* holds a subscription
for the same filter from an earlier SUBSCRIBE. The current request is
correctly answered `0x80`, yet `find_sub` succeeds and the retained
replay runs anyway.

Confirmed: with a policy whose `authorize_subscribe` flips to `false`
between two identical SUBSCRIBEs, the second returns `SUBACK 0x80` **and**
still delivers the retained message.

Impact is bounded by `authorize_receive`, which is checked per delivery
inside the same loop — so with `TableAcl` (where subscribe and receive
both derive from the same `read` rules) nothing leaks. It bites policies
where subscribe is *stricter* than receive: wildcard-subscription bans,
subscription rate limits, per-filter quotas.

**Fix.** Record acceptance in the first pass instead of re-deriving it.
A bitmask over entry index is enough:

```cpp
uint32_t accepted = 0;   // bit i = entry i was granted
// first pass:  accepted |= (uint32_t{1} << i) on success
// second pass: skip entry i unless (accepted >> i) & 1
```

### M3 — `Pool::release()` and `StaticVector::pop_back()` corrupt state on misuse

`include/minimosq/core/pool.hpp:46-51`, `core/static_vector.hpp:80-83`

Neither validates its precondition, and the failure mode is silent
`size_t` underflow rather than a crash.

```cpp
void release(T* p) noexcept {
    const size_t i = index_of(p);   // no range check, no used_[i] check
    p->~T();
    used_[i] = false;
    --count_;                        // underflows on double release
}
```

Confirmed:

```
P2 size after double release = 18446744073709551615  empty=0  dtors=2
P1 StaticVector size after remove_ordered() on empty = 18446744073709551615
```

Note `dtors=2` — the object is destroyed twice, which is UB for any
non-trivially-destructible `T` (and `Session` is one).

No current call site violates the precondition; I traced all of them.
But `Pool` and `StaticVector` are the load-bearing primitives of a
library whose whole safety argument is "fixed capacity, no allocation",
and a corrupted `size_` propagates into every later iteration.

**Fix.** Guard both, matching the style already used elsewhere:

```cpp
void pop_back() noexcept {
    if (size_ == 0) { return; }
    ptr(size_ - 1)->~T();
    --size_;
}

void release(T* p) noexcept {
    const size_t i = index_of(p);
    if (i >= Capacity || !used_[i]) { return; }
    ...
```

Also guard `remove_ordered`/`remove_unordered` with `if (i >= size_) return;`.

### M4 — CI pins actions that run on unsupported Node 20; no release workflow

`.github/workflows/ci.yml:17,42,61`, `.github/workflows/docs.yml:24,43`

Per your Node 24 policy, `actions/checkout@v5` → **`@v6`** and
`actions/upload-artifact@v4` → **`@v7`**. Five call sites total. Any
`actions/cache` added later should be `@v6`.

There is also no `release.yml` triggered on tags. For a header-only
library the useful shape is: on `v*` tag, run the full test matrix, then
create a GitHub Release with an auto-generated changelog and a source
tarball of `include/` for consumers who vendor headers directly.

> **Status: fixed.** All five call sites bumped to `checkout@v6` /
> `upload-artifact@v7`, and `.github/workflows/release.yml` added — it
> re-runs the GCC/Clang matrix and the sanitizer job against the tagged
> tree, refuses a tag that disagrees with `project(minimosq VERSION ...)`,
> publishes a headers tarball with a SHA-256, and marks `v*-*` tags as
> pre-releases.

---

## Low

### L1 — `frame_packet()` ignores `Writer::ok()` and can return a span longer than what it wrote

`include/minimosq/protocol/packets.hpp:227-234`

`varint()` refuses values above `max_remaining_length` and writes
nothing, but `frame_packet` returns `ByteSpan{buf + start, 1 + vs + body_len}`
unconditionally. Confirmed:

```
frame_packet(body_len=300000000) -> len=300000005, empty=0, header bytes = 30 00
```

A caller trusting that span reads ~300 MB out of bounds. Not reachable
today — every call site caps `body_len` at `out_size` — but it is the
one place in the protocol layer where a builder can hand back a span it
did not validate, and it is 3 lines to close:

```cpp
w.varint(static_cast<uint32_t>(body_len));
if (!w.ok()) { return ByteSpan{}; }
return ByteSpan{buf + start, 1 + vs + body_len};
```

`build_connack` and `build_packet_id_only` similarly skip the `w.ok()`
check that `build_publish` performs.

### L2 — A duplicated filter in one SUBSCRIBE delivers retained messages twice

`include/minimosq/broker/broker.hpp:779-800`

`SUBSCRIBE(id=1, ["a/x", "a/x"])` produces one subscription, two SUBACK
codes (correct), and **two** copies of the retained message for `a/x`
(confirmed). [MQTT-3.3.1-6] asks for the retained message to be sent on
a successful subscription; sending it twice for one resulting
subscription is a deviation. The bitmask fix in **M2** does not cover
this — you also want to skip an entry whose filter appeared earlier in
the same packet.

### L3 — A SUBSCRIBE rejected mid-list leaves earlier entries applied

`include/minimosq/broker/broker.hpp:760-774`

`SUBSCRIBE(["good/topic", "bad/#/x"])` closes the connection (correct,
[MQTT-4.8]) but `good/topic` has already been installed. On a
`clean_session=0` session that subscription survives the reconnect —
confirmed: 1 delivery after reconnecting.

Harmless in practice (the client asked for it), but "a packet that is a
protocol error had partial effect" is worth either fixing or documenting
in `docs/design.md` alongside the other capacity policies.

### L4 — `parse_publish()` reports `malformed` for a truncated QoS>0 packet

`include/minimosq/protocol/packets.hpp:127-135`

The zero-packet-id check runs before the `r.ok()` check, so a PUBLISH
that ends after the topic yields `Err::malformed` rather than
`Err::truncated` (confirmed). Both close the connection, so this is
cosmetic — but the error taxonomy in `core/error.hpp` is otherwise
precise, and `tests/test_packets.cpp` asserts truncation elsewhere.
Move the `packet_id == 0` test below `if (!r.ok())`.

### L5 — `Broker::publish()` size guard omits the packet-id for QoS > 0

`include/minimosq/broker/broker.hpp:183-185`

```cpp
if (2 + topic.len + payload.len > out_size - packet_overhead) {
```

A QoS 1/2 PUBLISH also carries a 2-byte packet identifier, so the guard
undercounts by 2. It happens not to overflow, because `out_size` takes
the max of `max_packet_size` and `stored_body_max` and there is slack —
confirmed: a near-max QoS 1 publish returns `Err::ok` and is built
correctly. Still, the check should say what it means:

```cpp
const size_t id_len = (qos == QoS::at_most_once) ? 0 : 2;
if (2 + topic.len + id_len + payload.len > out_size - packet_overhead) {
```

### L6 — The unix-domain socket is created with the default umask

`include/minimosq/transports/posix/unix_socket.hpp:34-60`

`docs/security.md` offers the UDS transport as "OS-level isolation", but
`open()` never sets a mode, so the socket inherits the process umask —
commonly `0755`, i.e. connectable by every local user. For a transport
whose entire security value is filesystem permissions, that should not
be left to chance:

```cpp
const mode_t old = ::umask(0177);      // srw-------
const int rc = ::bind(fd, ...);
::umask(old);
```

or `fchmod`/`chmod` on the path after bind. Worth a line in
`docs/security.md` either way, since the right mode depends on whether
clients share a group.

### L7 — `TableAcl::authenticate()` is a timing oracle for usernames

`include/minimosq/broker/table_acl.hpp:104-126`

`constant_time_eq` is fine, and its comment is honest about the length
leak. The *lookup* around it is not: a matching username returns as soon
as the password comparison finishes, while an unknown username scans the
entire user table first. `docs/security.md` claims

> **Unknown username and wrong password are indistinguishable** — both
> answer `bad_credentials`, so the broker is not a user-enumeration oracle.

That holds for the response code but not for response time. Either scan
the whole table unconditionally and accumulate the result, or soften the
documentation to "the *response* does not distinguish them". Given the
threat model already assumes plaintext credentials on the wire, softening
the docs is a defensible call — but the current wording overstates it.

### L8 — `read_into_broker()` drains one connection without bound

`include/minimosq/transports/posix/stream_server.hpp:203-225`

The loop reads until `EAGAIN`. A client that keeps its socket full keeps
the loop spinning: other connections are not polled, and `broker.tick()`
— which drives keep-alive and CONNECT timeouts — does not run. On a
single-core embedded target that is a straightforward starvation vector.

**Fix.** Cap the iterations per `poll_once`, e.g. 8 reads (16 KB) per
connection per pass, and let the next `poll()` pick up the rest.

### L9 — `TlsAdapter` puts 2 × `BufSize` on the stack per call

`include/minimosq/transports/tls_adapter.hpp:132-133`

`Driver::conn_data` declares `plain[BufSize]` and `cipher_out[BufSize]`
— 8 KB at the default `BufSize = 4096`, on top of the caller's frame.
For the ESP-IDF / Zephyr targets `docs/porting.md` names, that is a
meaningful fraction of a task stack, and it appears at the deepest point
of the call chain. Consider making them members of the adapter (it is
single-threaded by contract) and documenting the stack cost either way.

### L10 — `keepalive = 0` clients hold a connection *and* a session slot forever

`include/minimosq/broker/broker.hpp:167-170`

```cpp
const bool armed = (c.session == no_session) || c.keepalive_s > 0;
```

This is deliberate, spec-conformant, and tested
(`zero_keepalive_never_expires`), so I am not calling it a bug. But
`docs/security.md` opens the resource-protection section with

> bounded everything, so a hostile or broken client cannot exhaust the broker

and that is too strong. Confirmed: three clients that CONNECT with
`keepalive=0` and then go silent still hold all 3 session slots after 24
simulated hours, and a fourth client gets `CONNACK 0x03`. The bound
holds; the *reclamation* does not exist.

**Suggestion.** Add an optional `Traits::max_idle_ms` (0 = disabled,
preserving today's behaviour) applied when `keepalive_s == 0`, and
adjust the doc to say the broker refuses new work rather than that
exhaustion is impossible.

---

## Informational / nits

| # | Where | Note |
| --- | --- | --- |
| N1 | `include/minimosq/transport.hpp:39` | References `transports/tls_skeleton.hpp`; the file is `tls_adapter.hpp`. Only stale path left in the tree. |
| N2 | `.github/workflows/docs.yml:65-68` | Comment says "leaving any hand-made page in place", but `rm -f ./*.md` deletes every top-level page. Either drop the claim or switch to removing only generated names. |
| N3 | `include/minimosq/broker/broker.hpp:872` | Uses `Pool<>` but includes it only transitively via `retained.hpp`. Add `#include "../core/pool.hpp"`. |
| N4 | `include/minimosq/core/span.hpp:69` | Implicit `StrView(const char*)` makes `StrView s = nullptr;` compile and then UB in `cstr_len`. Consider `explicit`, or a `nullptr_t` deleted overload. |
| N5 | working tree | Stale `.git/index.lock` and `.git/REBASE_HEAD.lock` will block git operations; `LICENSE` has an uncommitted CRLF-only change; `_to_delete/` is untracked (add it to `.gitignore`). |
| N6 | `.github/workflows/ci.yml` | No MSVC job despite the `/W4` `/WX` branch in `CMakeLists.txt:30-35`; no 32-bit or big-endian coverage. A `-m32` job is cheap and would exercise the `size_t` arithmetic properly. |
| N7 | `.github/workflows/` | Actions are not SHA-pinned. Low risk on first-party actions, but tag-pinning is mutable. |
| N8 | `tests/smoke_mosquitto.sh:55,79,84` | `sleep 0.5` for synchronisation will be flaky on a loaded runner. Poll for the subscriber's readiness instead. `VICTIM_PID` is not covered by the `cleanup` trap. |
| N9 | `include/minimosq/transports/posix/tcp.hpp:38` | Always binds `INADDR_ANY`. An optional bind address would let the examples default to loopback, which is a friendlier default for a plaintext broker. |
| N10 | `include/minimosq/broker/table_acl.hpp:67-79` | `add_user` silently accepts duplicate usernames; the first match wins. Returning `false` on a duplicate would catch config typos at startup. |
| N11 | `tools/footprint.cpp` output | The `Gateway` config measures **611 KB** — memory scales as `max_sessions × max_pending_per_session × (max_topic_len + max_payload_len)`, and per-session cost is already 7,248 bytes at defaults. Worth stating that product explicitly in `docs/design.md` so users size the right knob. |

---

## What is working well

Recording these so a future reader does not "fix" them.

- **Deferred teardown.** The `dead` flag plus `flush_dead()` at the tail
  of every entry point is the right answer to will-publishing re-entrancy,
  and the reasoning in the `teardown()` comment about why `s` cannot be
  released underneath the will publish is correct — I traced every path
  into `route_publish` and none releases the publishing session.
- **Sticky failure in `Reader`/`Writer`.** Parsing code stays linear with
  a single `ok()` check at the end, and the invariant genuinely holds:
  every accessor short-circuits on `!ok_`.
- **The UTF-8 validator** (`protocol/utf8.hpp`) is complete and correct —
  structure, overlongs, surrogates, `> U+10FFFF`, and `U+0000`. The
  overlong check also transitively rules out a NUL smuggled in as a
  multi-byte sequence.
- **`FrameParser`** handles byte-at-a-time delivery, multiple packets per
  feed, the 4-byte varint limit, and oversize rejection, with the body
  buffer bounded by `MaxBodySize` on every path.
- **The security-policy shape.** Checking *receive* per delivery rather
  than trusting the subscribe-time decision is the correct design, and it
  is what limits M2's blast radius. Deny-by-default with filter
  subsumption for SUBSCRIBE is right, and `topic_filter_covers` is
  provably sound over the space I tested.
- **Test suite.** 133 tests including capacity-exhaustion, QoS 2 resume,
  session takeover, will semantics, and real-socket transport tests. The
  build flags (`-Wconversion -Wsign-conversion -fno-exceptions -fno-rtti`)
  are stricter than most projects and the tree is clean under them.

## Suggested order of work

All of the above are done; see [Resolution](#resolution).

Two additions remain worth considering, neither of which was a finding:

- **An in-tree libFuzzer target** over `FrameParser::feed` and the
  `parse_*` functions. The ad-hoc harness used for this review found
  nothing across ~11,600 randomised packets, but a persistent corpus
  running in CI is worth considerably more than a one-off run.
- **Promote the differential topic test.** A second, independently
  written matcher now exists (it is what validated `topic_matches` over
  a million pairs). Checking it in as a permanent test would keep the
  security-critical matcher honest through future refactors.


---

# Second pass

A follow-up audit of the same tree at `2a9e340` (v0.3.5), re-verifying the
first review's fixes and looking specifically at what the broker does
when it runs out of room.

**Verdict.** The parts the first review vouched for held up under
re-verification: no memory-safety defect across ~1.5M fuzzed packets,
`topic_matches` clean over 11.4M differential pairs,
`topic_filter_covers` sound over 3.8M cover pairs, the UTF-8 validator
exact over 151.6M exhaustive cases, and every fix claimed above genuinely
present in the code. What this pass found is elsewhere: four capacity
behaviours that were silently wrong or unbounded, and the fact that none
of them — nor anything else the broker decides — was visible from
outside.

Two corrections to the record above, for honesty:

- **L1's fix is dead code.** `frame_packet`'s `if (!w.ok())` can never
  fire: the writer is given a capacity of exactly what it writes. What
  actually closed the repro was the `body_len > max_remaining_length`
  check, which the entry does not mention. The same is true of the guards
  added to `build_connack` and `build_packet_id_only`; only
  `build_publish`'s is live. The underlying hole is real but not
  reachable in-tree — `frame_packet` takes a raw pointer with no capacity
  argument, so it cannot validate the span it returns.
- The README claimed 177 test cases against a tree containing 193.

## Fixed in this round

| # | Finding | Fix |
| --- | --- | --- |
| H1 | Disconnected persistent sessions were never reclaimed. MQTT 3.1.1 has no session expiry, so one connection could create `max_sessions` persistent sessions, disconnect each cleanly, and lock the broker shut with **zero connections live** — nothing left for keep-alive or `max_idle_ms` to act on, and `TableAcl` ignores `client_id`, so one valid credential sufficed. `security.md`'s "cannot exhaust the broker" was false as written. | Optional `Traits::session_expiry_ms` (0 = disabled, detected like `max_idle_ms`) discards sessions disconnected that long; independently, a full pool evicts the longest-disconnected session rather than refuse a new client. Ordering is a monotonic ticket stamped at disconnect, not the clock, so "gone longest" survives wrap. A connected session is never a victim. |
| H2 | An oversized retained PUBLISH left the **previous** value in the store. Live subscribers got the new value, the publisher was acknowledged, and every later subscriber was handed a stale reading that looked current — the opposite of what a last-known-value slot is for. | `RetainedStore::set` now evicts what it cannot replace, and reports which of three things happened (`stored` / `dropped` / `stale_purged`) instead of a bool. |
| H3 | A PUBLISH whose topic exceeded `max_topic_len` reached routing and silently skipped every QoS>0 subscriber while the publisher was acknowledged — so asking for a *higher* QoS made delivery *less* reliable. `design.md`'s mitigation advice ("size `max_payload_len >= max_packet_size`") was incomplete: `max_topic_len` gated the same branch. | Topics too long to own are refused at entry — connection closed for a client PUBLISH, `Err::oversize` from `Broker::publish()`, CONNACK 0x03 for a will (already the case). `enqueue`'s topic check is gone; the payload case remains, deliberately, because QoS 0 pass-through is bounded by `max_packet_size` — but it is now reported. |
| H4 | SUBSCRIBE replayed retained messages **per matching filter**, so K granted filters over R retained messages produced K×R packets. Measured at `DefaultTraits`: one 68-byte SUBSCRIBE → 129 sends, 67 KB out; one 2040-byte read (exactly one read of the reference transport) → 3870 sends, 2.02 MB, 818 µs. `conn_data()` was therefore bounded by the segment the transport handed it rather than by the traits — roughly 400 ns per input byte, enough to starve `tick()`. | Pass 3 iterates the store once and takes the max granted QoS across the filters this packet granted, exactly as `route_publish` does for live traffic. At most R sends whatever K is; this also fixes overlapping filters delivering a retained message twice. |
| — | Nothing the broker decided was observable. The `Security` hooks could see authentication and authorization; connection teardown, protocol violations, oversize packets, capacity refusals, keep-alive timeouts, session takeover, will firing and transport failures were invisible. That makes every finding above the kind that can only be found by reading the code — a broker silently dropping messages looks exactly like one with nothing to do. | New `Observer` policy — the fourth `Broker` template parameter, defaulting to a `NullObserver` that compiles away. One `on_event(const Event&)` with a tagged struct, so a new `EventKind` never breaks an existing observer. 19 kinds covering connection and session lifecycle, denials, capacity and drops. See [observability.md](observability.md). |

## Verification

| Check | Result |
| --- | --- |
| GCC 13 and Clang 18, 32-bit, `-Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion -Wshadow -Werror -fno-exceptions -fno-rtti` | 18/18 binaries, **215 cases**, zero warnings |
| ASan + UBSan, `-fno-sanitize-recover=all` | 215/215 pass, zero trips |
| clang-format 18.1.3 / clang-tidy 18.1.1 gates | clean, 0 findings |
| End-to-end against stock `mosquitto_pub`/`mosquitto_sub` | pass |
| Coverage (`tools/coverage.py`, GCC 13, Codecov-comparable) | **89.4%** fully covered (was 87.4%), 95.6% executed, 85.0% branch — floors are 85/80 |
| `sizeof(Broker<DefaultTraits, …>)` | 78,152 → **78,288 B** (+136: 8 bytes per session for the disconnect bookkeeping, plus alignment) |

Each fix has a regression test in `tests/test_broker_lifecycle.cpp`
(21 cases), including the amplification bound, the eviction victim being
the *oldest* rather than an arbitrary session, and the stale purge being
observable from a later subscriber rather than only from
`retained_count()`.

## Not addressed here — known, ranked

Confirmed and deliberately left. These are the next round, not
oversights.

1. **No TLS engine, and `NullTlsEngine` can ship as one with no signal.**
   Wired exactly as `tls.md` documents, a raw MQTT CONNECT (no
   ClientHello) is accepted and the password crosses in cleartext, with
   no `static_assert`, `#warning` or opt-in macro anywhere in
   `transports/`. Gate it. Further: `on_ciphertext()` is called once per
   `conn_data` with no drain loop (measured: 3840 of 4096 bytes stranded
   at `BufSize=256`, still stranded after two `tick()`s), `close()` never
   calls `reset()` so session keys outlive the connection and no
   `close_notify` is ever sent, and `BufSize` must exceed the plaintext
   by the record overhead or `encrypt()` fails — which the broker treats
   as an abnormal disconnect, firing the will.
2. **Keep-alive is refreshed by bytes, not Control Packets.** One body
   byte per window holds a connection open indefinitely (measured: 580 s,
   never closed). [MQTT-3.1.2-24] speaks of a Control Packet, and there
   is no incomplete-packet timeout after CONNECT.
3. **`max_idle_ms` applies only to keep-alive 0.** Asking for 65535
   instead buys 27 h 18 m per CONNECT regardless of the setting.
   Documented now; not fixed.
4. **An unacknowledged in-flight message wedges a session's queue
   permanently.** No in-flight timeout and no retransmission while
   connected (correct per [MQTT-4.4.0-1], but consequential): a
   subscriber that never PUBACKs fills `max_pending_per_session`, and
   every later QoS>0 message for it is dropped — measured still wedged
   after 22 simulated hours, connection alive. Now at least reported
   (`delivery_dropped`), but nothing recovers the session.
5. **`max_inbound_qos2 = 8` disconnects conformant clients and fires
   their will.** Paho defaults to 10 in-flight, `mosquitto_pub` to 20.
   For a persistent session the id table survives the reconnect, so every
   reconnect is dropped again on the first new id.
6. **`TableAcl` has no rotation or revocation** — no `remove_user`, no
   `set_password`, and duplicates are rejected, so a credential is
   immutable for the process lifetime. It also accepts an empty password,
   after which the client may omit the password field entirely.
7. **The username comparison is a prefix oracle** — roughly 1.08 cycles
   per matching byte, measured over 2M interleaved samples. The password
   comparison is genuinely constant-time; `security.md` now claims only
   that.
8. **`PipeTransport::flush()` uses `write(2)` with no SIGPIPE
   handling** — measured: the process is killed. The examples set
   `SIG_IGN`; the header never says it is required. The same hazard
   returns for `StreamServerTransport` on any stack without
   `MSG_NOSIGNAL`.
9. **No zeroization anywhere.** Passwords and decrypted TLS plaintext sit
   in `.bss` for the process lifetime.
10. **`frame_packet` cannot validate the span it returns** (see the L1
    correction above): give it a capacity argument.

Non-code, cheap, and disproportionately visible to anyone evaluating the
project: a `SECURITY.md` with a disclosure policy and a contact, an SBOM
emitted from `release.yml`, signed releases, a reproducible tarball, a
version macro in a header (the version lives only in `CMakeLists.txt`, so
a vendored copy is unidentifiable), `install()` rules and a package
config — `find_package(minimosq)` cannot work today despite
`release.yml` asserting it does — and the in-tree libFuzzer target and
differential topic matcher this document already recommended.
