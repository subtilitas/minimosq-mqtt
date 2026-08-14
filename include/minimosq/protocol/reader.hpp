// minimosq — bounds-checked big-endian byte reader.
//
// Reader consumes a ByteSpan front to back. Failure is sticky: once any
// read runs past the end, ok() turns false, every later read yields a
// zero/empty value, and the caller checks ok() once at the end. This
// keeps parsing code linear and free of per-field error handling.
//
// SPDX-License-Identifier: MIT
#ifndef MINIMOSQ_PROTOCOL_READER_HPP
#define MINIMOSQ_PROTOCOL_READER_HPP

#include <cstddef>
#include <cstdint>

#include "../core/span.hpp"

namespace minimosq {

class Reader {
public:
    explicit Reader(ByteSpan s) noexcept : p_(s.data), end_(s.data + s.len) {}

    bool ok() const noexcept { return ok_; }
    size_t remaining() const noexcept { return static_cast<size_t>(end_ - p_); }
    bool at_end() const noexcept { return p_ == end_; }

    uint8_t u8() noexcept {
        if (!ok_ || remaining() < 1) {
            ok_ = false;
            return 0;
        }
        return *p_++;
    }

    uint16_t u16() noexcept {
        if (!ok_ || remaining() < 2) {
            ok_ = false;
            return 0;
        }
        const uint16_t v = static_cast<uint16_t>((p_[0] << 8) | p_[1]);
        p_ += 2;
        return v;
    }

    ByteSpan bytes(size_t n) noexcept {
        if (!ok_ || remaining() < n) {
            ok_ = false;
            return ByteSpan{};
        }
        const ByteSpan r{p_, n};
        p_ += n;
        return r;
    }

    // 16-bit length-prefixed binary data, [MQTT-1.5.3].
    ByteSpan len_prefixed_bytes() noexcept {
        const uint16_t n = u16();
        if (!ok_) {
            return ByteSpan{};
        }
        return bytes(n);
    }

    // 16-bit length-prefixed UTF-8 string.
    StrView utf8() noexcept { return as_str(len_prefixed_bytes()); }

    // Everything not yet consumed.
    ByteSpan rest() noexcept {
        if (!ok_) {
            return ByteSpan{};
        }
        const ByteSpan r{p_, remaining()};
        p_ = end_;
        return r;
    }

private:
    const uint8_t* p_;
    const uint8_t* end_;
    bool ok_ = true;
};

} // namespace minimosq

#endif // MINIMOSQ_PROTOCOL_READER_HPP
