// Broker tests: connection lifecycle — CONNECT/CONNACK, keep-alive,
// PINGREQ, DISCONNECT, session takeover, auth.
// SPDX-License-Identifier: MIT
#include "broker_util.hpp"

using namespace bt;

TEST(connect_is_accepted) {
    Bed x;
    x.connect(0, "alice");
    expect_connack(x.t, 0, false, ConnackCode::accepted);
    expect_silence(x.t, 0);
    CHECK(!x.t.logs[0].closed);
}

TEST(connect_wrong_protocol_level_refused) {
    Bed x;
    wire::ConnectOpts o;
    o.protocol_level = 5;
    x.connect(0, "alice", o);
    expect_connack(x.t, 0, false, ConnackCode::unacceptable_protocol);
    CHECK(x.t.logs[0].closed);
}

TEST(connect_bad_protocol_name_closes_silently) {
    Bed x;
    wire::ConnectOpts o;
    o.protocol_name = "MQIsdp";
    x.connect(0, "alice", o);
    expect_silence(x.t, 0);  // no CONNACK [MQTT-3.1.2-1]
    CHECK(x.t.logs[0].closed);
}

TEST(connect_empty_client_id_rejected) {
    Bed x;
    x.connect(0, "");
    expect_connack(x.t, 0, false, ConnackCode::identifier_rejected);
    CHECK(x.t.logs[0].closed);
}

TEST(connect_overlong_client_id_rejected) {
    Bed x;
    x.connect(0, "a-very-long-client-id");  // > 16 bytes (SmallTraits)
    expect_connack(x.t, 0, false, ConnackCode::identifier_rejected);
    CHECK(x.t.logs[0].closed);
}

TEST(first_packet_must_be_connect) {
    Bed x;
    x.open(0);
    x.feed(0, wire::make_pingreq());
    expect_silence(x.t, 0);
    CHECK(x.t.logs[0].closed);
}

TEST(second_connect_is_a_violation) {
    Bed x;
    x.connect(0, "alice");
    expect_connack(x.t, 0, false, ConnackCode::accepted);
    x.feed(0, wire::make_connect("alice"));
    CHECK(x.t.logs[0].closed);
}

TEST(session_slots_exhausted) {
    Bed x;  // SmallTraits::max_sessions == 3
    x.connect(0, "a");
    x.connect(1, "b");
    x.connect(2, "c");
    x.connect(3, "d");
    expect_connack(x.t, 3, false, ConnackCode::server_unavailable);
    CHECK(x.t.logs[3].closed);
    CHECK(!x.t.logs[2].closed);
}

namespace {
struct RecordingAuth {
    char seen_user[32] = {};
    char seen_pass[32] = {};
    bool had_user = false;
    bool had_pass = false;

    minimosq::ConnackCode check(minimosq::StrView, const minimosq::StrView* username,
                                const minimosq::ByteSpan* password) {
        had_user = username != nullptr;
        had_pass = password != nullptr;
        if (username != nullptr) {
            for (size_t i = 0; i < username->len && i < 31; ++i) {
                seen_user[i] = username->data[i];
            }
        }
        if (password != nullptr) {
            for (size_t i = 0; i < password->len && i < 31; ++i) {
                seen_pass[i] = static_cast<char>(password->data[i]);
            }
        }
        if (username == nullptr || minimosq::StrView(seen_user) != minimosq::StrView("bob")) {
            return minimosq::ConnackCode::not_authorized;
        }
        if (password == nullptr || minimosq::StrView(seen_pass) != minimosq::StrView("secret")) {
            return minimosq::ConnackCode::bad_credentials;
        }
        return minimosq::ConnackCode::accepted;
    }
};
} // namespace

TEST(auth_policy_is_consulted) {
    BedT<RecordingAuth> x;
    wire::ConnectOpts o;
    o.username = "bob";
    o.password = "secret";
    x.connect(0, "c1", o);
    expect_connack(x.t, 0, false, ConnackCode::accepted);
    CHECK(x.b.auth().had_user);
    CHECK(x.b.auth().had_pass);

    wire::ConnectOpts bad;
    bad.username = "bob";
    bad.password = "wrong";
    x.connect(1, "c2", bad);
    expect_connack(x.t, 1, false, ConnackCode::bad_credentials);
    CHECK(x.t.logs[1].closed);

    x.connect(2, "c3");  // anonymous
    expect_connack(x.t, 2, false, ConnackCode::not_authorized);
}

TEST(pingreq_gets_pingresp) {
    Bed x;
    x.connect(0, "alice");
    expect_connack(x.t, 0, false, ConnackCode::accepted);
    x.feed(0, wire::make_pingreq());
    expect_pingresp(x.t, 0);
    CHECK(!x.t.logs[0].closed);
}

TEST(keepalive_expires_at_one_and_a_half_periods) {
    Bed x;
    wire::ConnectOpts o;
    o.keepalive_s = 2;  // window = 3000 ms
    x.connect(0, "alice", o);
    expect_connack(x.t, 0, false, ConnackCode::accepted);

    x.b.tick(x.now + 2999);
    CHECK(!x.t.logs[0].closed);

    // Traffic refreshes the deadline.
    x.now += 2000;
    x.feed(0, wire::make_pingreq());
    x.b.tick(x.now + 2999);
    CHECK(!x.t.logs[0].closed);

    x.b.tick(x.now + 3000);
    CHECK(x.t.logs[0].closed);
}

TEST(zero_keepalive_never_expires) {
    Bed x;
    wire::ConnectOpts o;
    o.keepalive_s = 0;
    x.connect(0, "alice", o);
    x.b.tick(x.now + 100000000);
    CHECK(!x.t.logs[0].closed);
}

TEST(connect_handshake_timeout) {
    Bed x;
    x.open(0);
    x.b.tick(x.now + SmallTraits::connect_timeout_ms - 1);
    CHECK(!x.t.logs[0].closed);
    x.b.tick(x.now + SmallTraits::connect_timeout_ms);
    CHECK(x.t.logs[0].closed);
}

TEST(disconnect_closes_without_reuse_problems) {
    Bed x;
    x.connect(0, "alice");
    expect_connack(x.t, 0, false, ConnackCode::accepted);
    x.feed(0, wire::make_disconnect());
    CHECK(x.t.logs[0].closed);

    // The connection slot is reusable afterwards.
    x.t.logs[0].closed = false;
    x.connect(0, "alice2");
    expect_connack(x.t, 0, false, ConnackCode::accepted);
}

TEST(takeover_disconnects_existing_connection) {
    Bed x;
    x.connect(0, "dup");
    expect_connack(x.t, 0, false, ConnackCode::accepted);
    x.connect(1, "dup");
    expect_connack(x.t, 1, false, ConnackCode::accepted);
    CHECK(x.t.logs[0].closed);
    CHECK(!x.t.logs[1].closed);
}

TEST(clean_session_discards_persistent_state) {
    Bed x;
    wire::ConnectOpts persistent;
    persistent.clean = false;

    x.connect(0, "alice", persistent);
    expect_connack(x.t, 0, false, ConnackCode::accepted);  // nothing stored yet
    x.b.conn_closed(0);

    // Reconnect persistent: the session was kept.
    x.connect(1, "alice", persistent);
    expect_connack(x.t, 1, true, ConnackCode::accepted);
    x.b.conn_closed(1);

    // Reconnect clean: the stored session is discarded.
    x.connect(2, "alice");
    expect_connack(x.t, 2, false, ConnackCode::accepted);
    x.b.conn_closed(2);

    // And a later persistent reconnect starts fresh again.
    x.connect(0, "alice", persistent);
    expect_connack(x.t, 0, false, ConnackCode::accepted);
}

TEST(clean_session_frees_the_slot_on_disconnect) {
    Bed x;  // max_sessions == 3
    x.connect(0, "a");
    x.feed(0, wire::make_disconnect());
    x.connect(1, "b");
    x.feed(1, wire::make_disconnect());
    x.connect(2, "c");
    x.feed(2, wire::make_disconnect());
    // All clean sessions released: a fourth distinct client fits.
    x.connect(3, "d");
    expect_connack(x.t, 3, false, ConnackCode::accepted);
}
