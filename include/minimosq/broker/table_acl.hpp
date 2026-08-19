// minimosq — TableAcl: a role-based, deny-by-default security policy
// backed by fixed tables.
//
// Users map credentials to a role; rules grant a role read and/or
// write access to a topic pattern (normal filter syntax, so
// "sensors/+/data" works). Everything a role is not explicitly
// granted is denied. Populate the tables at startup; the policy is
// fully static afterwards.
//
//   minimosq::TableAcl<4, 8> acl_config;   // or via Broker::security()
//   acl_config.add_user("sensor-1", "s3cret", ROLE_SENSOR);
//   acl_config.add_rule(ROLE_SENSOR, "sensors/#", TableAcl<4,8>::write);
//
// Semantics:
//   - authenticate: username/password looked up in the user table;
//     unknown user and wrong password both answer bad_credentials (no
//     username enumeration). Clients without a username are rejected
//     unless allow_anonymous(role) was called.
//   - authorize_subscribe uses filter subsumption: the requested
//     filter must lie entirely inside a granted read pattern, so a
//     client cleared for "home/#" cannot subscribe to "#". The
//     per-delivery receive check backs this up regardless.
//
// Security notes:
//   - Passwords are compared in constant time, but they are stored
//     and transmitted in plain text — that is MQTT 3.1.1. Run TLS
//     underneath (see docs/tls.md) for anything real, and swap the
//     comparison for a salted-hash check if plaintext storage does
//     not fit your threat model (the policy interface doesn't care).
//   - Identity is username-based. For client-certificate or
//     client-id-based identity, write your own policy; this file is
//     also the worked example for that.
//
// SPDX-License-Identifier: MIT
#ifndef MINIMOSQ_BROKER_TABLE_ACL_HPP
#define MINIMOSQ_BROKER_TABLE_ACL_HPP

#include <cstddef>
#include <cstdint>

#include "../core/fixed_buffer.hpp"
#include "../core/fixed_string.hpp"
#include "../core/span.hpp"
#include "../core/static_vector.hpp"
#include "../protocol/constants.hpp"
#include "../topic.hpp"

namespace minimosq {

template <size_t MaxUsers, size_t MaxRules, size_t MaxNameLen = 32, size_t MaxSecretLen = 32,
          size_t MaxPatternLen = 64>
class TableAcl {
public:
    struct Context {
        uint8_t role = 0;
    };

    enum Access : uint8_t {
        read = 1,
        write = 2,
        read_write = 3,
    };

    // ------------------------------------------- startup configuration

    // False when the table is full, an argument exceeds a capacity, or
    // the username is already registered (a duplicate is almost always a
    // config typo, and silently keeping the first entry hides it).
    bool add_user(StrView username, StrView password, uint8_t role) {
        if (username.empty() || username.len > MaxNameLen || password.len > MaxSecretLen) {
            return false;
        }
        for (const User& existing : users_) {
            if (existing.name.equals(username)) {
                return false;
            }
        }
        User* u = users_.emplace_back();
        if (u == nullptr) {
            return false;
        }
        u->name.assign(username);
        u->password.assign(password.bytes());
        u->role = role;
        return true;
    }

    // Give clients that connect without a username this role. Without
    // this call, anonymous clients are refused (not_authorized).
    void allow_anonymous(uint8_t role) {
        anon_allowed_ = true;
        anon_role_ = role;
    }

    bool add_rule(uint8_t role, StrView pattern, Access access) {
        if (!topic_filter_valid(pattern) || pattern.len > MaxPatternLen) {
            return false;
        }
        Rule* r = rules_.emplace_back();
        if (r == nullptr) {
            return false;
        }
        r->pattern.assign(pattern);
        r->role = role;
        r->access = static_cast<uint8_t>(access);
        return true;
    }

    // ------------------------------------------------ policy interface

    ConnackCode authenticate(StrView client_id, const StrView* username, const ByteSpan* password,
                             Context& ctx) {
        (void)client_id;
        if (username == nullptr) {
            if (!anon_allowed_) {
                return ConnackCode::not_authorized;
            }
            ctx.role = anon_role_;
            return ConnackCode::accepted;
        }
        // The whole table is scanned whether or not the name matches, and
        // the password of every entry is compared. An early return on the
        // matching name would make "unknown user" measurably faster than
        // "wrong password" and turn the broker into a user-enumeration
        // oracle by timing, even though both answer bad_credentials.
        const ByteSpan supplied = (password != nullptr) ? *password : ByteSpan{};
        uint8_t found = 0;
        uint8_t role = 0;
        for (const User& u : users_) {
            const uint8_t name_hit = u.name.equals(*username) ? 1u : 0u;
            const uint8_t pw_hit = constant_time_eq(u.password.view(), supplied) ? 1u : 0u;
            const uint8_t hit = static_cast<uint8_t>(name_hit & pw_hit);
            // Branch-free select: keep the first full match.
            const uint8_t take = static_cast<uint8_t>(hit & (found ^ 1u));
            role = static_cast<uint8_t>((role & (take - 1u)) | (u.role & (0u - take)));
            found = static_cast<uint8_t>(found | hit);
        }
        if (found == 0) {
            return ConnackCode::bad_credentials;
        }
        ctx.role = role;
        return ConnackCode::accepted;
    }

    bool authorize_publish(const Context& c, StrView topic) {
        return allowed(c.role, write, topic, /*as_filter=*/false);
    }

    bool authorize_receive(const Context& c, StrView topic) {
        return allowed(c.role, read, topic, /*as_filter=*/false);
    }

    bool authorize_subscribe(const Context& c, StrView filter) {
        return allowed(c.role, read, filter, /*as_filter=*/true);
    }

private:
    struct User {
        FixedString<MaxNameLen> name;
        FixedBuffer<MaxSecretLen> password;
        uint8_t role = 0;
    };

    struct Rule {
        FixedString<MaxPatternLen> pattern;
        uint8_t role = 0;
        uint8_t access = 0;
    };

    bool allowed(uint8_t role, uint8_t need, StrView subject, bool as_filter) {
        for (const Rule& r : rules_) {
            if (r.role != role || (r.access & need) == 0) {
                continue;
            }
            const bool hit = as_filter ? topic_filter_covers(r.pattern.view(), subject)
                                       : topic_matches(r.pattern.view(), subject);
            if (hit) {
                return true;
            }
        }
        return false;  // deny by default
    }

    // No data-dependent early exit; a length mismatch still leaks that
    // the length differed, which for passwords is acceptable here.
    static bool constant_time_eq(ByteSpan a, ByteSpan b) {
        uint8_t diff = (a.len == b.len) ? 0 : 1;
        const size_t n = a.len < b.len ? a.len : b.len;
        for (size_t i = 0; i < n; ++i) {
            diff = static_cast<uint8_t>(diff | (a.data[i] ^ b.data[i]));
        }
        return diff == 0;
    }

    StaticVector<User, MaxUsers> users_;
    StaticVector<Rule, MaxRules> rules_;
    uint8_t anon_role_ = 0;
    bool anon_allowed_ = false;
};

}  // namespace minimosq

#endif  // MINIMOSQ_BROKER_TABLE_ACL_HPP
