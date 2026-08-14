// minimosq — MQTT topic names, topic filters, and wildcard matching.
//
// Implements the rules of [MQTT-4.7]:
//   - topic names carry no wildcards
//   - '+' matches exactly one level, '#' matches the remaining levels
//     (including the parent level: "sport/#" matches "sport")
//   - filters starting with a wildcard do not match topics starting
//     with '$' ($SYS-style topics)
//
// Matching is byte-wise, which is correct for UTF-8 because '/' and the
// wildcards are ASCII and UTF-8 never embeds ASCII bytes inside
// multi-byte sequences.
//
// SPDX-License-Identifier: MIT
#ifndef MINIMOSQ_TOPIC_HPP
#define MINIMOSQ_TOPIC_HPP

#include <cstddef>

#include "core/span.hpp"
#include "protocol/constants.hpp"

namespace minimosq {

// Valid topic name for a PUBLISH: non-empty, no wildcards, no NUL.
inline bool topic_name_valid(StrView name) {
    if (name.empty() || name.len > max_utf8_len) {
        return false;
    }
    for (size_t i = 0; i < name.len; ++i) {
        const char c = name[i];
        if (c == '#' || c == '+' || c == '\0') {
            return false;
        }
    }
    return true;
}

// Valid topic filter for a SUBSCRIBE/UNSUBSCRIBE: wildcards only in
// whole-level positions, '#' only at the end.
inline bool topic_filter_valid(StrView f) {
    if (f.empty() || f.len > max_utf8_len) {
        return false;
    }
    for (size_t i = 0; i < f.len; ++i) {
        const char c = f[i];
        if (c == '\0') {
            return false;
        }
        if (c == '#') {
            if (i + 1 != f.len) {
                return false;  // '#' must be last [MQTT-4.7.1-2]
            }
            if (i != 0 && f[i - 1] != '/') {
                return false;  // must occupy a whole level
            }
        } else if (c == '+') {
            if (i != 0 && f[i - 1] != '/') {
                return false;  // must occupy a whole level [MQTT-4.7.1-3]
            }
            if (i + 1 != f.len && f[i + 1] != '/') {
                return false;
            }
        }
    }
    return true;
}

// Does a (valid) filter match a (valid) topic name?
inline bool topic_matches(StrView filter, StrView name) {
    // Filters starting with a wildcard do not match $-topics [MQTT-4.7.2].
    if (!name.empty() && name[0] == '$' && !filter.empty() &&
        (filter[0] == '+' || filter[0] == '#')) {
        return false;
    }

    size_t fi = 0;           // start of the current filter level
    size_t ni = 0;           // start of the current name level
    bool name_active = true; // name still contributes a current level

    while (true) {
        // Current filter level is [fi, fe).
        size_t fe = fi;
        while (fe < filter.len && filter[fe] != '/') {
            ++fe;
        }
        if (fe == fi + 1 && filter[fi] == '#') {
            return true;  // '#' swallows this level and everything below
        }
        if (!name_active) {
            return false;  // filter expects another level, name is exhausted
        }

        // Current name level is [ni, ne).
        size_t ne = ni;
        while (ne < name.len && name[ne] != '/') {
            ++ne;
        }

        const bool is_plus = (fe == fi + 1 && filter[fi] == '+');
        if (!is_plus) {
            if (fe - fi != ne - ni) {
                return false;
            }
            for (size_t k = 0; k < fe - fi; ++k) {
                if (filter[fi + k] != name[ni + k]) {
                    return false;
                }
            }
        }

        const bool f_more = fe < filter.len;
        const bool n_more = ne < name.len;
        if (!f_more) {
            return !n_more;  // both must end together
        }
        fi = fe + 1;
        if (n_more) {
            ni = ne + 1;
        } else {
            name_active = false;  // e.g. filter "a/#" vs name "a"
        }
    }
}

} // namespace minimosq

#endif // MINIMOSQ_TOPIC_HPP
