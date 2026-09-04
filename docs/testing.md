# Testing

What 1.0.0 was tested with, what the numbers mean, and what is not
covered. Every figure here is produced by something in this repository or
by a run recorded against a named commit — nothing is an estimate.

## The in-tree suite

260 test cases in 18 binaries, run by `ctest` on every push.

| Binary | Cases | Area |
|---|---:|---|
| `test_packets` | 28 | CONNECT/PUBLISH/SUBSCRIBE parse and build |
| `test_broker_lifecycle` | 26 | session reclamation, expiry, capacity honesty, the observer seam |
| `test_broker_pubsub` | 25 | routing, retained messages, filter subsumption |
| `test_core` | 23 | `StaticVector`, `Pool`, `FixedString`, `FixedBuffer`, spans |
| `test_broker_protocol` | 22 | protocol violations, wills, malformed packets |
| `test_broker_connect` | 21 | CONNECT, takeover, client identifiers |
| `test_transport_tcp` | 15 | TCP transport, buffer sizing, write policy |
| `test_broker_qos` | 12 | QoS 1 and 2 flows, retransmission, PUBREL |
| `test_protocol_io` | 12 | `Reader`/`Writer` bounds |
| `test_transport_pipe` | 12 | pipe transport, descriptor ownership, EINTR |
| `test_broker_security` | 11 | authentication and authorization hooks |
| `test_frame` | 10 | stream framing, varints, partial packets |
| `test_tls_adapter` | 10 | the TLS seam, engine probes, drain |
| `test_session_state` | 9 | subscription and queue bookkeeping |
| `test_table_acl` | 9 | the `TableAcl` policy |
| `test_topic` | 9 | `topic_matches`, filter validity, subsumption |
| `test_transport_uds` | 4 | unix domain sockets |
| `test_harness` | 2 | the harness itself |

Cases are written to fail without the behaviour they pin. For a fix that
means a test verified red before the fix and green after; for a test that
pins existing behaviour it means the source was mutated, the failure
observed, and the mutation reverted. Two examples of what that catches:

- A `noexcept` assertion on `Pool::for_each` originally passed a
  `noexcept` visitor, so a *conditionally* `noexcept` member would have
  satisfied it. It now passes a plain visitor and is verified against
  both a removed and a conditional `noexcept`.
- The disconnect-stamp cases assert the session is still alive at the
  deadline the real close implies, which is what a "the stamp is never
  late" reading of the contract denies. It is denied by one of the two
  transport orderings.

## Gates on every push

| Gate | What it runs |
|---|---|
| `build & test (g++)` and `(clang++)` | full suite, `-Wall -Wextra -Wpedantic -Wconversion -Wsign-conversion -Wshadow -Werror` |
| `build & test (32-bit)` | full suite under `-m32` |
| `build & test (MSVC)` | full suite under `/W4 /WX` |
| `ASan + UBSan` | full suite, `-fsanitize=address,undefined -fno-sanitize-recover=all` |
| `coverage` | measured and gated, see below |
| `mosquitto smoke test` | end-to-end against stock `mosquitto_pub` / `mosquitto_sub` |
| `clang-format` | 18.1.3, pinned |
| `clang-tidy` | 18.1.1, pinned, 0 findings |
| `CodeQL` | `security-and-quality` queries, reporting only |

Release **and** Debug are both gated. Debug alone is not enough:
`-Warray-bounds` needs the optimiser and only fires in Release.

## Coverage

Measured over `include/minimosq/` by `tools/coverage.py` with GCC 13, the
pinned compiler. Three numbers, because they answer different questions:

| Measure | 1.0.0 | Floor |
|---|---:|---:|
| Lines fully covered (every branch on the line taken; what Codecov shows) | 89.7% | 85% |
| Lines executed at least once | 96.3% | — |
| Branches taken | 83.5% | 80% |

Over 1,854 relevant lines. Per layer:

| Layer | Lines | Fully covered |
|---|---:|---:|
| core (containers, spans) | 178 | 96.6% |
| protocol (parse/serialize) | 317 | 94.3% |
| broker (sessions, routing, ACL) | 834 | 91.5% |
| transports (POSIX, TLS seam) | 429 | 79.0% |
| top level (`topic.hpp`) | 96 | 93.8% |

The transports are the weakest layer, and the figure is honest about
where: `unix_socket.hpp` 73.0%, `pipe.hpp` 74.1%, `tcp.hpp` 75.0%,
`tls_adapter.hpp` 77.5%. These are error paths that need a failing
`syscall` to reach.

Reproduce the CI figure exactly — the compiler matters:

```sh
sudo apt-get install -y g++-13
cmake -B build -DCMAKE_BUILD_TYPE=Debug \
      -DCMAKE_CXX_COMPILER=g++-13 -DCMAKE_CXX_FLAGS="--coverage -O0 -g"
cmake --build build && ctest --test-dir build
python3 tools/coverage.py --build-dir build --gcov gcov-13 --show-missing
```

## Review

[`docs/code-review.md`](code-review.md) is the audit record: two review
passes with their findings, the fixes, and a ranked list of confirmed
issues. Each entry on that list states whether it is still open and, if
not, which commits closed it.

A third, full-tree review of `include/` before 1.0 found 15 defects. Two
needed no misconfiguration at all — stock traits, the shipped transport
defaults and a well-behaved client were enough: retained replay
overrunning the outbound ring, and predictable server-assigned client
identifiers allowing session seizure. Fourteen are fixed; the fifteenth,
`TableAcl` accepting an empty password, is an operator's configuration
choice and is documented rather than changed.

## Independent testing

An adversarial suite written against this library, kept outside the
repository and not part of CI, was run twice.

**Round 1**, against `4347871`: 21,053,015 checks, 0 failures. It found
none of the 15 defects the full-tree review found at the same commit.
That result is the more useful half of it — the reasons are structural,
and are recorded with the report.

**Round 2**, against `a52955c` (the 1.0.0 tree): the regression pass is
21,053,020 checks, 0 failures, and widening it from one hard-coded seed
to 15 seeds across all six suites gives **316,082,871 checks over 90
runs, 0 failures**. Round 2 found one documentation gap and no defect.

Two results from it worth naming:

- The suite did not compile against the new `transport.hpp`. `Broker`'s
  `out_buf_size` `static_assert` fired on the suite's own recording
  transport, which had been sized from `max_packet_size` — five bytes
  short at its traits. That is the assert doing exactly what it exists
  for, on a real mis-sized transport, and the symptom without it would
  have been a subscriber dropped as a slow consumer.
- The suite's own assertion that a full `max_inbound_qos2` table drops
  the connection was outgrown by `9bb228a`, which evicts the oldest
  identifier instead. The case is re-pinned to the new policy, including
  that redelivering the *newest* identifier evicts nothing — an
  implementation that evicted the newest would satisfy every other
  assertion.

**Interop.** The broker was run against paho-cpp-static's client over
loopback TCP — an independently written MQTT 3.1.1 client, not a double
built from the same reading of the specification. 7,011 (filter, topic)
pairs, 0 disagreements with the client's own matcher. The comparison was
shown to discriminate first: a deliberately wrong client-side matcher,
one where `+` spans a separator, produces 1,570 disagreements over the
same 7,011 pairs.

**The release artifact.** `minimosq-1.0.0-rc2-headers.tar.gz` was
downloaded from its release, checked against the shipped `.sha256`,
confirmed byte-identical to `git archive` of the tag across all 28
headers, and then used to build another project's broker with no edits.

The same checks pass on the 1.0.0 artifact.
`minimosq-1.0.0-headers.tar.gz` has sha256
`cb66c6c0a7336057ff25470593a1c051e50c1c28951eee69700a2d38a165eb9b`,
matches the shipped `.sha256`, carries 28 headers byte-identical to the
tree at `v1.0.0`, reports `MINIMOSQ_VERSION` 1.0.0, and compiles a broker
as a vendored copy under `-Wall -Wextra -Werror`.

## Not covered

Stated rather than omitted.

- **The TLS adapter is not exercised by the independent suite**, which
  drives the broker through its own recording transport and the interop
  over plain TCP. In-tree, `tls_adapter.hpp` is at 77.5%.
- **No TLS engine is bundled.** `NullTlsEngine` is a wiring
  demonstration that copies bytes through unchanged. Nothing gates it
  from shipping as if it were a TLS engine — see
  [`SECURITY.md`](../SECURITY.md).
- **The pacing paths added for 1.0** — retained-replay pacing, the queue
  flush against the outbound ring, PUBREL retransmission, paused output
  resumed from `tick()` — have in-tree regression tests but no cases of
  their own in the independent suite; it reaches them only incidentally.
- **No fuzzing campaign.** The independent suite's randomized packet
  streams are not a substitute for a coverage-guided fuzzer, and no
  libFuzzer target is in tree.
- **One toolchain for the independent runs.** GCC 13.3.0 only; the
  in-tree suite is the one that spans GCC, Clang, 32-bit and MSVC.
- **No timing measurements beyond the credential comparison.** Throughput
  and latency are unmeasured.
