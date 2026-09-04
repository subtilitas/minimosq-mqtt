// Unit tests for the core layer: spans and fixed-capacity containers.
// SPDX-License-Identifier: MIT
#include "test.hpp"

#include <cstdio>

#include <minimosq/core/error.hpp>
#include <minimosq/core/fixed_buffer.hpp>
#include <minimosq/core/fixed_string.hpp>
#include <minimosq/core/pool.hpp>
#include <minimosq/core/span.hpp>
#include <minimosq/core/static_vector.hpp>
#include <minimosq/version.hpp>

using namespace minimosq;

// ---------------------------------------------------------------- spans

TEST(bytespan_slice_and_equality) {
    const uint8_t raw[] = {1, 2, 3, 4, 5};
    ByteSpan s{raw, sizeof raw};

    CHECK_EQ(s.len, 5u);
    CHECK_EQ(s[0], 1);
    CHECK(s.slice(1, 3) == ByteSpan(raw + 1, 3));
    CHECK(s.slice(4, 100).len == 1);  // count clamped
    CHECK(s.slice(9, 1).empty());     // offset out of range
    CHECK(ByteSpan{} == ByteSpan{});
    CHECK(s != s.slice(0, 4));
}

TEST(strview_literals_and_equality) {
    StrView a = "topic/x";
    CHECK_EQ(a.len, 7u);
    CHECK(a == StrView("topic/x"));
    CHECK(a != StrView("topic/y"));
    CHECK(StrView("").empty());
    CHECK(as_str(a.bytes()) == a);
}

TEST(err_names) {
    CHECK(is_ok(Err::ok));
    CHECK(!is_ok(Err::capacity));
    CHECK(StrView(err_name(Err::malformed)) == StrView("malformed"));
}

// -------------------------------------------------------- StaticVector

namespace {
int live_probes = 0;
struct Probe {
    int value = 0;
    Probe() { ++live_probes; }
    Probe(const Probe& o) : value(o.value) { ++live_probes; }
    Probe& operator=(const Probe&) = default;
    ~Probe() { --live_probes; }
};
}  // namespace

TEST(static_vector_push_to_capacity) {
    StaticVector<int, 3> v;
    CHECK(v.empty());
    CHECK(v.push_back(1));
    CHECK(v.push_back(2));
    CHECK(v.push_back(3));
    CHECK(v.full());
    CHECK(!v.push_back(4));  // full: rejected, size unchanged
    CHECK_EQ(v.size(), 3u);
    CHECK_EQ(v[0], 1);
    CHECK_EQ(v[2], 3);
    CHECK(v.emplace_back() == nullptr);
}

TEST(static_vector_ordered_removal_preserves_order) {
    StaticVector<int, 5> v;
    for (int i = 1; i <= 5; ++i) {
        v.push_back(i);
    }
    v.remove_ordered(1);  // remove 2
    CHECK_EQ(v.size(), 4u);
    CHECK_EQ(v[0], 1);
    CHECK_EQ(v[1], 3);
    CHECK_EQ(v[2], 4);
    CHECK_EQ(v[3], 5);
    v.remove_ordered(3);  // remove last (5)
    CHECK_EQ(v.size(), 3u);
    CHECK_EQ(v[2], 4);
}

TEST(static_vector_unordered_removal) {
    StaticVector<int, 4> v;
    for (int i = 1; i <= 4; ++i) {
        v.push_back(i);
    }
    v.remove_unordered(0);  // last element moves into slot 0
    CHECK_EQ(v.size(), 3u);
    CHECK_EQ(v[0], 4);
}

TEST(static_vector_runs_destructors) {
    live_probes = 0;
    {
        StaticVector<Probe, 4> v;
        v.push_back(Probe{});
        v.push_back(Probe{});
        v.push_back(Probe{});
        CHECK_EQ(live_probes, 3);
        v.remove_ordered(0);
        CHECK_EQ(live_probes, 2);
        v.clear();
        CHECK_EQ(live_probes, 0);
        v.push_back(Probe{});
    }
    CHECK_EQ(live_probes, 0);  // destructor drains remaining elements
}

// ---------------------------------------------------------------- Pool

TEST(pool_alloc_release_reuse) {
    Pool<int, 3> p;
    int* a = p.alloc();
    int* b = p.alloc();
    int* c = p.alloc();
    CHECK(a && b && c);
    CHECK(p.full());
    CHECK(p.alloc() == nullptr);

    CHECK_EQ(p.index_of(b), 1u);
    CHECK(p.at(1) == b);
    p.release(b);
    CHECK(p.at(1) == nullptr);
    CHECK_EQ(p.size(), 2u);

    int* d = p.alloc();  // first free slot is reused
    CHECK(d == b);
    CHECK_EQ(p.size(), 3u);
}

TEST(pool_for_each_with_release_during_iteration) {
    Pool<int, 4> p;
    for (int i = 0; i < 4; ++i) {
        *p.alloc() = i;
    }
    // Release odd values from inside the visit.
    p.for_each([&](int& v) {
        if (v % 2 == 1) {
            p.release(&v);
        }
    });
    CHECK_EQ(p.size(), 2u);
    int sum = 0;
    p.for_each([&](int& v) { sum += v; });
    CHECK_EQ(sum, 0 + 2);
}

TEST(pool_find) {
    Pool<int, 4> p;
    *p.alloc() = 10;
    *p.alloc() = 20;
    int* hit = p.find([](int v) { return v == 20; });
    CHECK(hit != nullptr);
    CHECK_EQ(*hit, 20);
    CHECK(p.find([](int v) { return v == 99; }) == nullptr);
}

TEST(pool_runs_destructors) {
    live_probes = 0;
    {
        Pool<Probe, 3> p;
        Probe* a = p.alloc();
        p.alloc();
        CHECK_EQ(live_probes, 2);
        p.release(a);
        CHECK_EQ(live_probes, 1);
    }
    CHECK_EQ(live_probes, 0);
}

// ------------------------------------------- FixedString / FixedBuffer

TEST(fixed_string_assign_and_reject) {
    FixedString<8> s;
    CHECK(s.assign("abc"));
    CHECK(s.equals("abc"));
    CHECK_EQ(s.size(), 3u);

    CHECK(!s.assign("123456789"));  // 9 chars > capacity 8: rejected...
    CHECK(s.equals("abc"));         // ...and previous value kept

    CHECK(s.assign("12345678"));  // exactly at capacity
    CHECK_EQ(s.size(), 8u);
    s.clear();
    CHECK(s.empty());
}

TEST(fixed_buffer_assign_and_reject) {
    FixedBuffer<4> b;
    const uint8_t four[] = {1, 2, 3, 4};
    const uint8_t five[] = {1, 2, 3, 4, 5};
    CHECK(b.assign(ByteSpan{four, 4}));
    CHECK(b.view() == ByteSpan(four, 4));
    CHECK(!b.assign(ByteSpan{five, 5}));
    CHECK(b.view() == ByteSpan(four, 4));
}

// ------------------------------------------------- misuse resistance
//
// These guard the precondition checks added after review: the old code
// underflowed size_t on each of these paths, which is far worse than a
// no-op because every later iteration then walks off the end.

TEST(static_vector_pop_back_on_empty_is_a_noop) {
    StaticVector<int, 4> v;
    v.pop_back();
    CHECK_EQ(v.size(), 0u);
    CHECK(v.empty());
    CHECK(!v.full());

    v.remove_ordered(0);
    CHECK_EQ(v.size(), 0u);
    v.remove_unordered(0);
    CHECK_EQ(v.size(), 0u);

    // Still usable afterwards.
    CHECK(v.push_back(7));
    CHECK_EQ(v.size(), 1u);
    CHECK_EQ(v[0], 7);
}

TEST(static_vector_remove_out_of_range_is_a_noop) {
    StaticVector<int, 4> v;
    CHECK(v.push_back(1));
    CHECK(v.push_back(2));

    v.remove_ordered(2);     // == size
    v.remove_unordered(99);  // way past the end
    CHECK_EQ(v.size(), 2u);
    CHECK_EQ(v[0], 1);
    CHECK_EQ(v[1], 2);
}

TEST(pool_double_release_is_a_noop) {
    Pool<int, 4> p;
    int* a = p.alloc();
    CHECK(a != nullptr);
    CHECK_EQ(p.size(), 1u);

    p.release(a);
    CHECK_EQ(p.size(), 0u);
    p.release(a);  // double release must not underflow count_
    CHECK_EQ(p.size(), 0u);
    CHECK(p.empty());
    CHECK(!p.full());

    // The pool still hands out all four slots.
    for (int i = 0; i < 4; ++i) {
        CHECK(p.alloc() != nullptr);
    }
    CHECK(p.full());
    CHECK(p.alloc() == nullptr);
}

TEST(pool_release_of_a_foreign_pointer_is_a_noop) {
    Pool<int, 2> p;
    int* a = p.alloc();
    CHECK(a != nullptr);

    int stack_object = 0;
    p.release(&stack_object);  // never came from this pool
    p.release(nullptr);
    CHECK_EQ(p.size(), 1u);

    p.release(a);
    CHECK_EQ(p.size(), 0u);
}

TEST(pool_alloc_zeroes_a_slot_the_previous_occupant_wrote) {
    // pool.hpp presents the zeroing as a safety property: slots are
    // reused, and a session must not start life holding the bytes of the
    // client that had the slot before it. The rule doing the work is
    // value-initialisation of a T with no user-provided default
    // constructor, so the T here is an aggregate.
    struct Payload {
        unsigned char bytes[8];
        int n;
    };
    Pool<Payload, 2> p;
    Payload* first = p.alloc();
    CHECK(first != nullptr);
    for (unsigned char& b : first->bytes) {
        b = 0xAB;
    }
    first->n = 12345;
    p.release(first);

    Payload* reused = p.alloc();
    CHECK(reused == first);  // the same storage, with the old bytes under it
    for (const unsigned char b : reused->bytes) {
        CHECK_EQ(b, 0u);
    }
    CHECK_EQ(reused->n, 0);
}

TEST(pool_for_each_is_noexcept) {
    // observer.hpp attributes the observer's no-throw requirement to
    // this member being noexcept rather than to the broker's entry
    // points, which are not. If for_each ever stops being noexcept that
    // justification goes with it.
    Pool<int, 1> p;
    const auto visit = [](int&) noexcept {};
    static_assert(noexcept(p.for_each(visit)), "Pool::for_each must stay noexcept");
    *p.alloc() = 7;
    int seen = 0;
    p.for_each([&](int& v) noexcept { seen += v; });
    CHECK_EQ(seen, 7);
}

TEST(pool_release_runs_the_destructor_exactly_once) {
    static int dtors = 0;
    struct Counted {
        ~Counted() { ++dtors; }
    };
    dtors = 0;
    Pool<Counted, 2> p;
    Counted* c = p.alloc();
    p.release(c);
    CHECK_EQ(dtors, 1);
    p.release(c);  // must not destroy it a second time
    CHECK_EQ(dtors, 1);
}

TEST(err_name_covers_every_code) {
    // err_name is public diagnostic API: examples and application code
    // print it. A missing case would silently return "unknown" for a
    // real error, so pin every enumerator.
    struct Case {
        Err code;
        const char* name;
    };
    const Case cases[] = {
        {Err::ok, "ok"},
        {Err::truncated, "truncated"},
        {Err::malformed, "malformed"},
        {Err::oversize, "oversize"},
        {Err::capacity, "capacity"},
        {Err::state, "state"},
    };
    for (const Case& c : cases) {
        CHECK(StrView(err_name(c.code)) == StrView(c.name));
    }
    CHECK(is_ok(Err::ok));
    for (const Case& c : cases) {
        if (c.code != Err::ok) {
            CHECK(!is_ok(c.code));
        }
    }
}

// -------------------------------------------------------------- version

// The version exists in three forms — macros, constexpr values and a
// string — plus a fourth in CMakeLists.txt that CMake checks against this
// header at configure time. These check that the three in the header
// cannot disagree with each other.
TEST(version_macros_agree_with_constants) {
    CHECK_EQ(version_major, MINIMOSQ_VERSION_MAJOR);
    CHECK_EQ(version_minor, MINIMOSQ_VERSION_MINOR);
    CHECK_EQ(version_patch, MINIMOSQ_VERSION_PATCH);
    CHECK_EQ(MINIMOSQ_VERSION,
             MINIMOSQ_VERSION_NUMBER(version_major, version_minor, version_patch));

    // The string is built from the same three numbers, so this is really
    // a check that the stringification survived two macro expansions
    // rather than emitting "MINIMOSQ_VERSION_MAJOR.".
    char expected[16];
    const int n = std::snprintf(expected, sizeof expected, "%d.%d.%d", version_major, version_minor,
                                version_patch);
    CHECK(n > 0);
    CHECK(static_cast<size_t>(n) < sizeof expected);
    CHECK(StrView(version_string) == StrView(expected));
    CHECK(StrView(MINIMOSQ_VERSION_STRING) == StrView(version_string));
}

// Ordering has to hold across a component boundary: the packing gives
// each component three digits, so 0.4.0 must not compare below 0.3.999.
TEST(version_at_least_orders_components) {
    CHECK(MINIMOSQ_VERSION_AT_LEAST(0, 0, 0));
    CHECK(MINIMOSQ_VERSION_AT_LEAST(MINIMOSQ_VERSION_MAJOR, MINIMOSQ_VERSION_MINOR,
                                    MINIMOSQ_VERSION_PATCH));
    CHECK(!MINIMOSQ_VERSION_AT_LEAST(MINIMOSQ_VERSION_MAJOR, MINIMOSQ_VERSION_MINOR,
                                     MINIMOSQ_VERSION_PATCH + 1));
    CHECK(!MINIMOSQ_VERSION_AT_LEAST(MINIMOSQ_VERSION_MAJOR + 1, 0, 0));

    CHECK(MINIMOSQ_VERSION_NUMBER(0, 4, 0) > MINIMOSQ_VERSION_NUMBER(0, 3, 999));
    CHECK(MINIMOSQ_VERSION_NUMBER(1, 0, 0) > MINIMOSQ_VERSION_NUMBER(0, 999, 999));
}
