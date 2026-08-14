// minimosq — bounds-checked big-endian byte writer.
//
// Writer fills a caller-provided buffer front to back. Like Reader,
// failure is sticky: an overflowing write flips ok() to false and the
// buffer contents are considered garbage from then on. Callers check
// ok() once when done.
//
// SPDX-License-Identifier: MIT
#ifndef MINIMOSQ_PROTOCOL_WRITER_HPP
#define MINIMOSQ_PROTOCOL_WRITER_HPP

#include <cstddef>
#include <cstdint>

#include "../core/span.hpp"
#include "constants.hpp"

namespace minimosq {

class Writer {
public:
    Writer(uint8_t* buf, size_t cap) noexcept : buf_(buf), cap_(cap) {}

    bool ok() const noexcept { return ok_; }
    size_t size() const noexcept { return len_; }
    ByteSpan span() const noexcept { return ByteSpan{buf_, len_}; }

    void u8(uint8_t v) noexcept {
        if (!ok_ || len_ + 1 > cap_) {
            ok_ = false;
            return;
        }
        buf_[len_++] = v;
    }

    void u16(uint16_t v) noexcept {
        if (!ok_ || len_ + 2 > cap_) {
            ok_ = false;
            return;
        }
        buf_[len_++] = static_cast<uint8_t>(v >> 8);
        buf_[len_++] = static_cast<uint8_t>(v & 0xFF);
    }

    void bytes(ByteSpan b) noexcept {
        if (!ok_ || len_ + b.len > cap_) {
            ok_ = false;
            return;
        }
        for (size_t i = 0; i < b.len; ++i) {
            buf_[len_ + i] = b.data[i];
        }
        len_ += b.len;
    }

    // 16-bit length-prefixed UTF-8 string, [MQTT-1.5.3].
    void utf8(StrView s) noexcept {
        if (s.len > max_utf8_len) {
            ok_ = false;
            return;
        }
        u16(static_cast<uint16_t>(s.len));
        bytes(s.bytes());
    }

    // MQTT Remaining Length varint, [MQTT-2.2.3].
    void varint(uint32_t v) noexcept {
        if (v > max_remaining_length) {
            ok_ = false;
            return;
        }
        do {
            uint8_t digit = static_cast<uint8_t>(v % 128);
            v /= 128;
            if (v > 0) {
                digit |= 0x80;
            }
            u8(digit);
        } while (v > 0);
    }

private:
    uint8_t* buf_;
    size_t cap_;
    size_t len_ = 0;
    bool ok_ = true;
};

} // namespace minimosq

#endif // MINIMOSQ_PROTOCOL_WRITER_HPP
