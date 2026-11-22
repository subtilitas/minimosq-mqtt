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

#include <charconv>
#include <cstddef>
#include <iostream>
#include <type_traits>

namespace minitest {

// Fixed-capacity text builder for test fixtures that need a formatted
// name (a topic, a socket path). Appends string literals and integers.
// An append that does not fit sets the overflow flag instead of
// truncating silently; ok() reports it.
template <size_t Capacity>
class TextBuf {
    static_assert(Capacity > 1, "TextBuf needs room for a terminator");

public:
    TextBuf& add(const char* s) {
        while (*s != '\0' && len_ + 1 < Capacity) {
            data_[len_++] = *s++;
        }
        if (*s != '\0') {
            overflow_ = true;
        }
        data_[len_] = '\0';
        return *this;
    }

    template <typename T, typename = std::enable_if_t<std::is_integral_v<T>>>
    TextBuf& add(T value) {
        const auto r = std::to_chars(data_ + len_, data_ + Capacity - 1, value);
        if (r.ec == std::errc{}) {
            len_ = static_cast<size_t>(r.ptr - data_);
        } else {
            overflow_ = true;
        }
        data_[len_] = '\0';
        return *this;
    }

    const char* c_str() const { return data_; }
    size_t size() const { return len_; }
    bool ok() const { return !overflow_; }

private:
    char data_[Capacity] = {};
    size_t len_ = 0;
    bool overflow_ = false;
};

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
    std::cout << "FAIL " << current() << " (" << file << ':' << line << "): " << expr << '\n';
}

// Integer-flavoured equality check that prints both values on failure.
// Only use with values convertible to long long (integers, unscoped sizes).
template <typename A, typename B>
inline void check_eq(const char* file, int line, const char* expr, const A& a, const B& b) {
    if (!(a == b)) {
        ++failures();
        std::cout << "FAIL " << current() << " (" << file << ':' << line << "): " << expr
                  << " (lhs=" << static_cast<long long>(a) << " rhs=" << static_cast<long long>(b)
                  << ")\n";
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
        std::cout << "OK: " << count << " test case(s) passed\n";
        return 0;
    }
    std::cout << "FAILED: " << failures() << " check(s) failed across " << count
              << " test case(s)\n";
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
