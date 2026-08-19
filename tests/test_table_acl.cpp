// Tests for the TableAcl policy: authentication table, deny-by-default
// rules, and an end-to-end broker scenario.
// SPDX-License-Identifier: MIT
#include "broker_util.hpp"

#include <minimosq/broker/table_acl.hpp>

using namespace bt;

namespace {

using Acl = TableAcl<4, 8>;
constexpr uint8_t ROLE_SENSOR = 1;
constexpr uint8_t ROLE_DASH = 2;

void populate(Acl& acl) {
    CHECK(acl.add_user("sensor-1", "s3cret", ROLE_SENSOR));
    CHECK(acl.add_user("dash", "d4sh", ROLE_DASH));
    CHECK(acl.add_rule(ROLE_SENSOR, "sensors/#", Acl::write));
    CHECK(acl.add_rule(ROLE_DASH, "sensors/#", Acl::read));
    CHECK(acl.add_rule(ROLE_DASH, "control/#", Acl::read_write));
}

}  // namespace

TEST(table_acl_authentication) {
    Acl acl;
    populate(acl);
    Acl::Context ctx;

    StrView user = "sensor-1";
    ByteSpan good = wire::bs("s3cret");
    ByteSpan bad = wire::bs("wrong");
    CHECK(acl.authenticate("c", &user, &good, ctx) == ConnackCode::accepted);
    CHECK_EQ(ctx.role, ROLE_SENSOR);
    CHECK(acl.authenticate("c", &user, &bad, ctx) == ConnackCode::bad_credentials);
    CHECK(acl.authenticate("c", &user, nullptr, ctx) == ConnackCode::bad_credentials);

    // Unknown user: same answer as a wrong password.
    StrView ghost = "ghost";
    CHECK(acl.authenticate("c", &ghost, &good, ctx) == ConnackCode::bad_credentials);

    // Anonymous: refused unless explicitly allowed.
    CHECK(acl.authenticate("c", nullptr, nullptr, ctx) == ConnackCode::not_authorized);
    acl.allow_anonymous(ROLE_DASH);
    CHECK(acl.authenticate("c", nullptr, nullptr, ctx) == ConnackCode::accepted);
    CHECK_EQ(ctx.role, ROLE_DASH);
}

TEST(table_acl_authorization_rules) {
    Acl acl;
    populate(acl);
    Acl::Context sensor{ROLE_SENSOR};
    Acl::Context dash{ROLE_DASH};
    Acl::Context nobody{0};

    CHECK(acl.authorize_publish(sensor, "sensors/1/temp"));
    CHECK(!acl.authorize_publish(sensor, "control/reboot"));  // write-only elsewhere
    CHECK(!acl.authorize_receive(sensor, "sensors/1/temp"));  // write != read
    CHECK(!acl.authorize_subscribe(sensor, "sensors/#"));

    CHECK(acl.authorize_subscribe(dash, "sensors/+/temp"));
    CHECK(acl.authorize_subscribe(dash, "sensors/#"));
    CHECK(!acl.authorize_subscribe(dash, "#"));  // wider than any grant
    CHECK(acl.authorize_receive(dash, "sensors/1/temp"));
    CHECK(acl.authorize_publish(dash, "control/reboot"));
    CHECK(!acl.authorize_publish(dash, "sensors/1/temp"));

    // Role without rules: everything denied.
    CHECK(!acl.authorize_publish(nobody, "sensors/1/temp"));
    CHECK(!acl.authorize_subscribe(nobody, "sensors/#"));
    CHECK(!acl.authorize_receive(nobody, "sensors/1/temp"));
}

TEST(table_acl_rejects_bad_config) {
    Acl acl;
    CHECK(!acl.add_user("", "pw", 1));                    // empty username
    CHECK(!acl.add_rule(1, "bad/#/pattern", Acl::read));  // invalid filter
    CHECK(acl.add_user("a", "", 1));                      // empty password is legal
}

TEST(table_acl_end_to_end) {
    BedT<Acl> x;
    populate(x.b.security());

    // Sensor connects and publishes; dashboard subscribes and receives.
    wire::ConnectOpts so;
    so.username = "sensor-1";
    so.password = "s3cret";
    x.connect(0, "s1", so);
    expect_connack(x.t, 0, false, ConnackCode::accepted);

    wire::ConnectOpts d;
    d.username = "dash";
    d.password = "d4sh";
    x.connect(1, "dash", d);
    expect_connack(x.t, 1, false, ConnackCode::accepted);

    // Dashboard may subscribe inside its grant, not outside it.
    x.feed(1, wire::make_subscribe(1, {{"sensors/#", 1}, {"#", 0}}));
    const uint8_t codes[] = {0x01, 0x80};
    expect_suback(x.t, 1, 1, codes);

    x.feed(0, wire::make_publish("sensors/1/temp", wire::bs("21.5"), QoS::at_least_once, false,
                                 false, 3));
    expect_ack(x.t, 0, PacketType::puback, 3);
    expect_publish(x.t, 1, "sensors/1/temp", wire::bs("21.5"), QoS::at_least_once, false);

    // The sensor may not publish outside its subtree: silently dropped.
    x.feed(0, wire::make_publish("control/reboot", wire::bs("now"), QoS::at_least_once, false,
                                 false, 4));
    expect_ack(x.t, 0, PacketType::puback, 4);
    expect_silence(x.t, 1);

    // Wrong password never gets in.
    wire::ConnectOpts bad;
    bad.username = "sensor-1";
    bad.password = "guess";
    x.connect(2, "intruder", bad);
    expect_connack(x.t, 2, false, ConnackCode::bad_credentials);
    CHECK(x.t.logs[2].closed);
}

// ------------------------------------------- post-review regressions

TEST(table_acl_rejects_duplicate_usernames) {
    TableAcl<4, 4> acl;
    CHECK(acl.add_user("alice", "pw1", 1));
    CHECK(!acl.add_user("alice", "pw2", 2));  // duplicate: config typo

    // The first registration still stands, and the second password
    // never became valid.
    TableAcl<4, 4>::Context ctx{};
    const StrView user = "alice";
    const ByteSpan pw1 = StrView("pw1").bytes();
    const ByteSpan pw2 = StrView("pw2").bytes();
    CHECK(acl.authenticate("c", &user, &pw1, ctx) == ConnackCode::accepted);
    CHECK_EQ(ctx.role, 1);
    CHECK(acl.authenticate("c", &user, &pw2, ctx) == ConnackCode::bad_credentials);
}

TEST(table_acl_scans_every_user_regardless_of_match) {
    // Whichever position a user occupies, authentication must succeed
    // with the right role: the lookup no longer returns early, so this
    // also pins the branch-free selection logic.
    TableAcl<4, 8> acl;
    CHECK(acl.add_user("first", "a", 11));
    CHECK(acl.add_user("middle", "b", 22));
    CHECK(acl.add_user("last", "c", 33));

    struct Case {
        const char* name;
        const char* pw;
        uint8_t role;
    };
    const Case cases[] = {{"first", "a", 11}, {"middle", "b", 22}, {"last", "c", 33}};
    for (const Case& c : cases) {
        TableAcl<4, 8>::Context ctx{};
        const StrView name = c.name;
        const ByteSpan pw = StrView(c.pw).bytes();
        CHECK(acl.authenticate("cid", &name, &pw, ctx) == ConnackCode::accepted);
        CHECK_EQ(ctx.role, c.role);
    }

    // Right name, wrong password; and a name that is not in the table.
    TableAcl<4, 8>::Context ctx{};
    const StrView name = "middle";
    const ByteSpan wrong = StrView("nope").bytes();
    CHECK(acl.authenticate("cid", &name, &wrong, ctx) == ConnackCode::bad_credentials);
    const StrView ghost = "nobody";
    const ByteSpan any = StrView("b").bytes();
    CHECK(acl.authenticate("cid", &ghost, &any, ctx) == ConnackCode::bad_credentials);

    // A password that matches a *different* user must not authenticate.
    const StrView first = "first";
    const ByteSpan bpw = StrView("b").bytes();
    CHECK(acl.authenticate("cid", &first, &bpw, ctx) == ConnackCode::bad_credentials);
}
