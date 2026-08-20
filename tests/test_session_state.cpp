// Session bookkeeping in isolation: outbound packet-id allocation and
// the retained store's capacity refusals.
//
// These are invariants the broker relies on but that its wire-level
// tests only ever hit incidentally. A packet identifier that repeats
// while the first delivery is still in flight, or one that comes back
// as zero after 65535 messages, corrupts the QoS state machine in a way
// no single PUBLISH would reveal.
//
// SPDX-License-Identifier: MIT
#include "broker_util.hpp"

using namespace bt;

namespace {

using TestSession = Session<SmallTraits, AllowAllSecurity::Context>;

// Put an entry into the queue in a given delivery state, as the broker
// would once it had sent it.
void add_inflight(TestSession& s, uint16_t id, OutState state) {
    TestSession::OutMsg* m = s.pending.emplace_back();
    // CHECK records a failure but does not return, so the guard is not
    // redundant: without it a full queue would be a null dereference.
    CHECK(m != nullptr);
    if (m == nullptr) {
        return;
    }
    m->packet_id = id;
    m->state = state;
}

}  // namespace

TEST(packet_ids_are_never_zero_and_wrap_to_one) {
    // [MQTT-2.3.1-1]: zero is not a valid packet identifier, so the
    // counter must skip it when it wraps rather than handing one out.
    TestSession s;
    s.last_packet_id = 65534;
    CHECK_EQ(s.alloc_packet_id(), 65535);
    CHECK_EQ(s.alloc_packet_id(), 1);  // wrapped past 0
    CHECK_EQ(s.alloc_packet_id(), 2);
}

TEST(packet_ids_in_flight_are_not_reused) {
    // An identifier still awaiting its acknowledgement must not be
    // handed out again: the client would have two different messages
    // under one id and the acks would resolve against the wrong one.
    TestSession s;
    s.last_packet_id = 0;
    add_inflight(s, 1, OutState::awaiting_puback);
    add_inflight(s, 2, OutState::awaiting_pubrec);
    add_inflight(s, 3, OutState::awaiting_pubcomp);

    CHECK_EQ(s.alloc_packet_id(), 4);  // skipped 1, 2 and 3
}

TEST(queued_entries_do_not_reserve_a_packet_id) {
    // A queued entry has not been sent, so its (still zero) id is not
    // in flight and must not block allocation.
    TestSession s;
    s.last_packet_id = 0;
    TestSession::OutMsg* m = s.pending.emplace_back();
    CHECK(m != nullptr);
    if (m == nullptr) {
        return;
    }
    CHECK(m->state == OutState::queued);

    CHECK_EQ(s.alloc_packet_id(), 1);
}

TEST(find_pending_matches_id_and_state) {
    TestSession s;
    add_inflight(s, 7, OutState::awaiting_puback);
    add_inflight(s, 8, OutState::awaiting_pubcomp);

    size_t index = 99;
    CHECK(s.find_pending(7, OutState::awaiting_puback, OutState::awaiting_puback, &index) !=
          nullptr);
    CHECK_EQ(index, 0u);

    // Right id, wrong state.
    CHECK(s.find_pending(7, OutState::awaiting_pubcomp, OutState::awaiting_pubcomp, nullptr) ==
          nullptr);
    // Unknown id — a late or duplicate acknowledgement.
    CHECK(s.find_pending(99, OutState::awaiting_puback, OutState::awaiting_pubcomp, nullptr) ==
          nullptr);
    // Either of the two accepted states matches.
    CHECK(s.find_pending(8, OutState::awaiting_pubrec, OutState::awaiting_pubcomp, nullptr) !=
          nullptr);
}

TEST(inbound_qos2_ids_are_tracked_and_released) {
    TestSession s;
    CHECK(!s.has_inbound_qos2(5));
    CHECK(s.inbound_qos2.push_back(5));
    CHECK(s.inbound_qos2.push_back(6));
    CHECK(s.has_inbound_qos2(5));
    CHECK(s.has_inbound_qos2(6));

    s.remove_inbound_qos2(5);
    CHECK(!s.has_inbound_qos2(5));
    CHECK(s.has_inbound_qos2(6));

    s.remove_inbound_qos2(4242);  // unknown id is a no-op
    CHECK(s.has_inbound_qos2(6));
}

// ------------------------------------------------------ retained store

TEST(retained_store_refuses_what_it_cannot_hold) {
    // Refusal is by return value, not truncation: a retained message
    // stored short would be served to every later subscriber.
    RetainedStore<SmallTraits> store;

    char long_topic[SmallTraits::max_topic_len + 2];
    for (char& c : long_topic) {
        c = 'a';
    }
    long_topic[sizeof long_topic - 1] = '\0';
    CHECK(!store.set(long_topic, wire::bs("v"), QoS::at_most_once));

    uint8_t big[SmallTraits::max_payload_len + 1];
    for (uint8_t& b : big) {
        b = 'x';
    }
    CHECK(!store.set("fits", ByteSpan{big, sizeof big}, QoS::at_most_once));

    CHECK_EQ(store.size(), 0u);  // neither was stored

    // Exactly at the limits is accepted.
    uint8_t exact[SmallTraits::max_payload_len];
    for (uint8_t& b : exact) {
        b = 'x';
    }
    CHECK(store.set("fits", ByteSpan{exact, sizeof exact}, QoS::at_least_once));
    CHECK_EQ(store.size(), 1u);
}

TEST(retained_store_replaces_rather_than_duplicating) {
    RetainedStore<SmallTraits> store;
    CHECK(store.set("a/b", wire::bs("one"), QoS::at_most_once));
    CHECK(store.set("a/b", wire::bs("two"), QoS::at_least_once));
    CHECK_EQ(store.size(), 1u);

    size_t seen = 0;
    store.for_each_match("a/#", [&](RetainedStore<SmallTraits>::Entry& e) {
        ++seen;
        CHECK(e.payload.view() == wire::bs("two"));
        CHECK(e.qos == QoS::at_least_once);
    });
    CHECK_EQ(seen, 1u);

    store.remove("a/b");
    CHECK_EQ(store.size(), 0u);
    store.remove("a/b");  // removing again is a no-op
    CHECK_EQ(store.size(), 0u);
}

TEST(retained_store_full_refuses_new_topics_but_still_replaces) {
    RetainedStore<SmallTraits> store;
    for (size_t i = 0; i < SmallTraits::max_retained; ++i) {
        char topic[16];
        std::snprintf(topic, sizeof topic, "t/%zu", i);
        CHECK(store.set(topic, wire::bs("v"), QoS::at_most_once));
    }
    CHECK_EQ(store.size(), SmallTraits::max_retained);

    CHECK(!store.set("t/new", wire::bs("v"), QoS::at_most_once));
    // An existing topic still updates: replacement needs no free slot.
    CHECK(store.set("t/0", wire::bs("updated"), QoS::at_most_once));
    CHECK_EQ(store.size(), SmallTraits::max_retained);
}
