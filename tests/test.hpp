// minimosq — minimal, dependency-free unit test harness.
//
// This header is used by the test binaries only; it is not part of the
// library. Each test translation unit includes this header, defines test
// cases with TEST(name) { ... }, and gets a main() that runs them all.
// Define MINITEST_NO_MAIN before including to suppress main().
//
// SPDX-License-Identifier: MIT
#ifndef MINIMOSQ_TESTS_TEST_HPP
#define MINIMOSQ_TESTS_TEST_HPP

#include <cstdio>

namespace minitest {

struct Case {
    const char* name;
    void (*fn)();
    Case* next;
};

inline Case*& cases() {
    static Case* head = nullptr;
    return head;
}

inline int& failures() {
    static int n = 0;
    return n;
}

inline const char*& current() {
    static const char* name = "";
    return name;
}

struct Registrar {
    explicit Registrar(Case* c) {
        // Append at the tail so cases run in definition order.
        Case** p = &cases();
        while (*p != nullptr) {
            p = &(*p)->next;
        }
        *p = c;
    }
};

inline void fail(const char* file, int line, const char* expr) {
    ++failures();
    std::printf("FAIL %s (%s:%d): %s\n", current(), file, line, expr);
}

// Integer-flavoured equality check that prints both values on failure.
// Only use with values convertible to long long (integers, unscoped sizes).
template <typename A, typename B>
inline void check_eq(const char* file, int line, const char* expr, const A& a, const B& b) {
    if (!(a == b)) {
        ++failures();
        std::printf("FAIL %s (%s:%d): %s (lhs=%lld rhs=%lld)\n", current(), file, line, expr,
                    static_cast<long long>(a), static_cast<long long>(b));
    }
}

inline int run_all() {
    int count = 0;
    for (Case* c = cases(); c != nullptr; c = c->next) {
        current() = c->name;
        c->fn();
        ++count;
    }
    if (failures() == 0) {
        std::printf("OK: %d test case(s) passed\n", count);
        return 0;
    }
    std::printf("FAILED: %d check(s) failed across %d test case(s)\n", failures(), count);
    return 1;
}

}  // namespace minitest

// The body has external linkage on purpose: a static function reached
// only through the Registrar's pointer reads as dead code to a
// whole-program analysis (CodeQL's unused-static-function), and every
// helper it calls then reads as dead with it. One test binary per file
// keeps the names from ever clashing.
#define TEST(name)                                                                                 \
    void minitest_fn_##name();                                                                     \
    static minitest::Case minitest_case_##name{#name, &minitest_fn_##name, nullptr};               \
    static minitest::Registrar minitest_reg_##name{&minitest_case_##name};                         \
    void minitest_fn_##name()

#define CHECK(expr)                                                                                \
    do {                                                                                           \
        if (!(expr)) {                                                                             \
            minitest::fail(__FILE__, __LINE__, #expr);                                             \
        }                                                                                          \
    } while (0)

#define CHECK_EQ(a, b) minitest::check_eq(__FILE__, __LINE__, #a " == " #b, (a), (b))

#ifndef MINITEST_NO_MAIN
int main() {
    return minitest::run_all();
}
#endif

#endif  // MINIMOSQ_TESTS_TEST_HPP
