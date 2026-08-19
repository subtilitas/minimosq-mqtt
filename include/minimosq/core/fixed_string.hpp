// minimosq — fixed-capacity owned string.
//
// Owned storage for topic filters, client identifiers and similar short
// UTF-8 text. Assignment fails (returning false) instead of truncating,
// so capacity violations are always explicit.
//
// SPDX-License-Identifier: MIT
#ifndef MINIMOSQ_CORE_FIXED_STRING_HPP
#define MINIMOSQ_CORE_FIXED_STRING_HPP

#include <cstddef>

#include "span.hpp"

namespace minimosq {

template <size_t Capacity>
class FixedString {
    static_assert(Capacity > 0, "FixedString needs a non-zero capacity");

public:
    static constexpr size_t capacity() noexcept { return Capacity; }

    size_t size() const noexcept { return len_; }
    bool empty() const noexcept { return len_ == 0; }

    // Copy s into owned storage. Fails (unchanged) if s does not fit.
    bool assign(StrView s) noexcept {
        if (s.len > Capacity) {
            return false;
        }
        for (size_t i = 0; i < s.len; ++i) {
            data_[i] = s.data[i];
        }
        len_ = s.len;
        return true;
    }

    void clear() noexcept { len_ = 0; }

    StrView view() const noexcept { return StrView{data_, len_}; }

    bool equals(StrView s) const noexcept { return view() == s; }

private:
    char data_[Capacity];
    size_t len_ = 0;
};

}  // namespace minimosq

#endif  // MINIMOSQ_CORE_FIXED_STRING_HPP
