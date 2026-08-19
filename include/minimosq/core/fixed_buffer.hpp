// minimosq — fixed-capacity owned byte buffer.
//
// Owned storage for message payloads (retained messages, wills, queued
// deliveries). Like FixedString, assignment fails instead of truncating.
//
// SPDX-License-Identifier: MIT
#ifndef MINIMOSQ_CORE_FIXED_BUFFER_HPP
#define MINIMOSQ_CORE_FIXED_BUFFER_HPP

#include <cstddef>
#include <cstdint>

#include "span.hpp"

namespace minimosq {

template <size_t Capacity>
class FixedBuffer {
    static_assert(Capacity > 0, "FixedBuffer needs a non-zero capacity");

public:
    static constexpr size_t capacity() noexcept { return Capacity; }

    size_t size() const noexcept { return len_; }
    bool empty() const noexcept { return len_ == 0; }

    // Copy b into owned storage. Fails (unchanged) if b does not fit.
    bool assign(ByteSpan b) noexcept {
        if (b.len > Capacity) {
            return false;
        }
        for (size_t i = 0; i < b.len; ++i) {
            data_[i] = b.data[i];
        }
        len_ = b.len;
        return true;
    }

    void clear() noexcept { len_ = 0; }

    ByteSpan view() const noexcept { return ByteSpan{data_, len_}; }

private:
    uint8_t data_[Capacity];
    size_t len_ = 0;
};

}  // namespace minimosq

#endif  // MINIMOSQ_CORE_FIXED_BUFFER_HPP
