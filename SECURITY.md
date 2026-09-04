# Security policy

minimosq is an MQTT broker: it parses attacker-controlled bytes from the
network and decides who may publish and subscribe to what. Reports about
either are welcome.

## Reporting a vulnerability

Please report privately through GitHub, not in a public issue:

**[Report a vulnerability](https://github.com/subtilitas/minimosq-mqtt/security/advisories/new)**
— Security → Advisories → Report a vulnerability.

That opens a private advisory visible only to you and the maintainers.
Include the affected version or commit, a description of the impact, and
the smallest reproduction you have — a packet sequence, a `Traits`
configuration, a test case against `tests/`, or a patch.

What to expect: an acknowledgement within a week, an assessment of
whether it is a vulnerability or a documented limitation (see below), and
a fix with a regression test in `tests/` before any public disclosure. If
you would like credit in the advisory and release notes, say so.

## Supported versions

| Version | Supported |
| --- | --- |
| 0.6.x | yes |
| < 0.6 | no — upgrade |

minimosq is header-only, so a fix reaches you by updating the headers.
There are no binaries to patch and no runtime to restart beyond your own.

## In scope

Anything reachable by a client that has connected to the broker, or by
one that has not yet:

- Memory safety in `include/minimosq/` — out-of-bounds access, use after
  free, uninitialized reads. The library is fixed-capacity and allocates
  nothing after construction, so any of these is a bug in that argument.
- Protocol parsing: a packet that causes a crash, a hang, or a read
  outside the frame buffer.
- Authorization bypass: a publish, subscribe or delivery that the
  `Security` policy should have refused. The shipped `TableAcl` is
  deny-by-default, and `topic_matches` / `topic_filter_covers` are the
  functions that decide it.
- Resource exhaustion by a client that is not privileged to cause it —
  connection, session or queue slots that cannot be reclaimed. See
  [docs/security.md](docs/security.md#resource-protection) for what the
  broker already bounds and how.
- The reference transports under `include/minimosq/transports/`.

## Known limitations, not vulnerabilities

These are documented, deliberate, and do not need a report — though a way
to exploit one *beyond* what is described here does.

- **No TLS engine is bundled.** MQTT 3.1.1 sends usernames and passwords
  in the clear; `docs/tls.md` documents the seam a TLS library plugs
  into. `NullTlsEngine` is a wiring demonstration that copies bytes
  through unchanged — it is not a security boundary, and a deployment
  that ships it has no encryption.
- **Credentials in `TableAcl` are stored and compared in plain text.**
  Both the username and the password comparison are constant-time with
  respect to their contents; a length difference is still observable.
  Swap in a salted-hash check if plaintext storage does not fit your
  threat model — the policy interface does not care.
- **An empty password in `TableAcl` is a usable credential.**
  `add_user("bob", "", role)` registers one, and a CONNECT carrying the
  username with no password field is accepted. Reject an empty password
  before calling `add_user` if that is not what the deployment means.
- **Nothing is zeroized.** Passwords and decrypted plaintext remain in
  `.bss` for the process lifetime.
- **Capacity behaviour is a documented policy, not a failure.** Which
  message is dropped when a queue or store is full, and which session is
  evicted when the pool is full, are tabulated in
  [docs/design.md](docs/design.md#documented-policy-decisions-spec-permitted-or-capacity-driven).
  Every such decision is reported through the `Observer` policy.

[docs/code-review.md](docs/code-review.md) carries the full audit record,
including a ranked list of confirmed issues; each entry says whether it
is still open and, if not, which commit closed it. Please check it before
reporting — if you find something already on that list, a note about
impact that list underrates is still worth sending.

## Scope of the threat model

The broker trusts its embedding application completely: `Broker::publish`,
the `Traits` capacities, the `Security` policy and the transport are all
yours to get right. The documented boundary is the network-facing side —
what a connected or connecting MQTT client can do. See
[docs/security.md](docs/security.md#threat-model-and-caveats).
