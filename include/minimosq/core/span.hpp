// minimosq — non-owning views over bytes and characters.
//
// ByteSpan and StrView are the two currencies the library trades in: raw
// protocol bytes and UTF-8 topic/identifier text. Both are trivially
// copyable, never own memory, and never allocate.
//
// SPDX-License-Identifier: MIT
#ifndef MINIMOSQ_CORE_SPAN_HPP
#define MINIMOSQ_CORE_SPAN_HPP

#include <cstddef>
#include <cstdint>

namespace minimosq {

constexpr size_t cstr_len(const char* s) noexcept {
    size_t n = 0;
    while (s[n] != '\0') {
        ++n;
    }
    return n;
}

// Read-only view of a byte range.
struct ByteSpan {
    const uint8_t* data = nullptr;
    size_t len = 0;

    constexpr ByteSpan() noexcept = default;
    constexpr ByteSpan(const uint8_t* d, size_t n) noexcept : data(d), len(n) {}

    constexpr bool empty() const noexcept { return len == 0; }
    constexpr uint8_t operator[](size_t i) const noexcept { return data[i]; }

    // Subview [offset, offset + count); out-of-range requests are clamped.
    constexpr ByteSpan slice(size_t offset, size_t count) const noexcept {
        if (offset > len) {
            return ByteSpan{};
        }
        const size_t avail = len - offset;
        return ByteSpan{data + offset, count < avail ? count : avail};
    }
};

inline bool operator==(ByteSpan a, ByteSpan b) noexcept {
    if (a.len != b.len) {
        return false;
    }
    for (size_t i = 0; i < a.len; ++i) {
        if (a.data[i] != b.data[i]) {
            return false;
        }
    }
    return true;
}

inline bool operator!=(ByteSpan a, ByteSpan b) noexcept { return !(a == b); }

// Read-only view of UTF-8 text. Not NUL-terminated.
struct StrView {
    const char* data = nullptr;
    size_t len = 0;

    constexpr StrView() noexcept = default;
    constexpr StrView(const char* d, size_t n) noexcept : data(d), len(n) {}

    // Implicit construction from a string literal / C string, for ergonomics
    // in application code and tests.
    constexpr StrView(const char* zstr) noexcept : data(zstr), len(cstr_len(zstr)) {}

    constexpr bool empty() const noexcept { return len == 0; }
    constexpr char operator[](size_t i) const noexcept { return data[i]; }

    ByteSpan bytes() const noexcept {
        return ByteSpan{reinterpret_cast<const uint8_t*>(data), len};
    }
};

constexpr bool operator==(StrView a, StrView b) noexcept {
    if (a.len != b.len) {
        return false;
    }
    for (size_t i = 0; i < a.len; ++i) {
        if (a.data[i] != b.data[i]) {
            return false;
        }
    }
    return true;
}

constexpr bool operator!=(StrView a, StrView b) noexcept { return !(a == b); }

// Reinterpret protocol bytes as text (MQTT strings are UTF-8 on the wire).
inline StrView as_str(ByteSpan b) noexcept {
    return StrView{reinterpret_cast<const char*>(b.data), b.len};
}

} // namespace minimosq

#endif // MINIMOSQ_CORE_SPAN_HPP
