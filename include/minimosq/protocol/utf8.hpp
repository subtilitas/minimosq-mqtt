// minimosq — UTF-8 well-formedness validation for MQTT strings.
//
// [MQTT-1.5.3] requires that UTF-8 encoded strings are well-formed;
// ill-formed sequences, U+0000, and UTF-16 surrogate code points must
// cause the connection to be closed. This validator enforces exactly
// that: encoding structure, no overlong forms, no surrogates, no NUL,
// nothing above U+10FFFF.
//
// SPDX-License-Identifier: MIT
#ifndef MINIMOSQ_PROTOCOL_UTF8_HPP
#define MINIMOSQ_PROTOCOL_UTF8_HPP

#include <cstddef>
#include <cstdint>

#include "../core/span.hpp"

namespace minimosq {

inline bool utf8_valid(StrView s) noexcept {
    size_t i = 0;
    while (i < s.len) {
        const uint8_t c = static_cast<uint8_t>(s.data[i]);
        if (c == 0x00) {
            return false;  // U+0000 is forbidden [MQTT-1.5.3-2]
        }
        if (c < 0x80) {
            i += 1;
            continue;
        }
        size_t cont;      // number of continuation bytes
        uint32_t cp;      // code point being decoded
        if ((c & 0xE0) == 0xC0) {
            cont = 1;
            cp = c & 0x1Fu;
        } else if ((c & 0xF0) == 0xE0) {
            cont = 2;
            cp = c & 0x0Fu;
        } else if ((c & 0xF8) == 0xF0) {
            cont = 3;
            cp = c & 0x07u;
        } else {
            return false;  // stray continuation byte or invalid lead byte
        }
        if (i + 1 + cont > s.len) {
            return false;  // truncated sequence
        }
        for (size_t k = 1; k <= cont; ++k) {
            const uint8_t b = static_cast<uint8_t>(s.data[i + k]);
            if ((b & 0xC0) != 0x80) {
                return false;
            }
            cp = (cp << 6) | (b & 0x3Fu);
        }
        if ((cont == 1 && cp < 0x80) || (cont == 2 && cp < 0x800) ||
            (cont == 3 && cp < 0x10000)) {
            return false;  // overlong encoding
        }
        if (cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) {
            return false;  // out of range / UTF-16 surrogate [MQTT-1.5.3-1]
        }
        i += 1 + cont;
    }
    return true;
}

} // namespace minimosq

#endif // MINIMOSQ_PROTOCOL_UTF8_HPP
