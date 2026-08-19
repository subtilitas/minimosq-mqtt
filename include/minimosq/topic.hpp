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
#include "protocol/utf8.hpp"

namespace minimosq {

// Valid topic name for a PUBLISH: non-empty, well-formed UTF-8, no
// wildcards.
inline bool topic_name_valid(StrView name) {
    if (name.empty() || name.len > max_utf8_len || !utf8_valid(name)) {
        return false;
    }
    for (size_t i = 0; i < name.len; ++i) {
        const char c = name[i];
        if (c == '#' || c == '+') {
            return false;
        }
    }
    return true;
}

// Valid topic filter for a SUBSCRIBE/UNSUBSCRIBE: well-formed UTF-8,
// wildcards only in whole-level positions, '#' only at the end.
inline bool topic_filter_valid(StrView f) {
    if (f.empty() || f.len > max_utf8_len || !utf8_valid(f)) {
        return false;
    }
    for (size_t i = 0; i < f.len; ++i) {
        const char c = f[i];
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

    size_t fi = 0;            // start of the current filter level
    size_t ni = 0;            // start of the current name level
    bool name_active = true;  // name still contributes a current level

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

// Filter subsumption: does `cover` (a topic filter used as an ACL
// pattern) match every topic name that `filter` matches? Used to
// decide whether a subscription request stays inside a permitted
// subtree, e.g. cover "home/#" covers filter "home/+/temp" but
// "home/+" does not cover "home/#".
inline bool topic_filter_covers(StrView cover, StrView filter) {
    // A filter for $-topics can only be covered by a cover that also
    // names the '$' level literally (wildcards never match it).
    if (!filter.empty() && filter[0] == '$' && !cover.empty() &&
        (cover[0] == '+' || cover[0] == '#')) {
        return false;
    }

    size_t ci = 0;              // start of the current cover level
    size_t fi = 0;              // start of the current filter level
    bool filter_active = true;  // filter still contributes a current level

    while (true) {
        size_t ce = ci;
        while (ce < cover.len && cover[ce] != '/') {
            ++ce;
        }
        if (ce == ci + 1 && cover[ci] == '#') {
            return true;  // '#' covers this level and everything below
        }
        if (!filter_active) {
            return false;  // cover expects another level, filter is done
        }

        size_t fe = fi;
        while (fe < filter.len && filter[fe] != '/') {
            ++fe;
        }
        const bool c_plus = (ce == ci + 1 && cover[ci] == '+');
        const bool f_hash = (fe == fi + 1 && filter[fi] == '#');
        const bool f_plus = (fe == fi + 1 && filter[fi] == '+');

        if (f_hash) {
            return false;  // only '#' covers '#', and that returned above
        }
        if (f_plus && !c_plus) {
            return false;  // '+' matches every level; a literal cannot cover it
        }
        if (!f_plus && !c_plus) {
            if (fe - fi != ce - ci) {
                return false;
            }
            for (size_t k = 0; k < fe - fi; ++k) {
                if (cover[ci + k] != filter[fi + k]) {
                    return false;
                }
            }
        }
        // c_plus covering a literal or '+' level: fine either way.

        const bool c_more = ce < cover.len;
        const bool f_more = fe < filter.len;
        if (!c_more) {
            return !f_more;  // both must end together
        }
        ci = ce + 1;
        if (f_more) {
            fi = fe + 1;
        } else {
            filter_active = false;  // e.g. cover "a/#" vs filter "a"
        }
    }
}

}  // namespace minimosq

#endif  // MINIMOSQ_TOPIC_HPP
