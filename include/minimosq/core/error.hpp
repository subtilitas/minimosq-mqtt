// minimosq — error codes.
//
// The library never throws. Every operation that can fail reports one of
// these codes (or returns a bool/nullptr where the failure mode is obvious).
//
// SPDX-License-Identifier: MIT
#ifndef MINIMOSQ_CORE_ERROR_HPP
#define MINIMOSQ_CORE_ERROR_HPP

namespace minimosq {

enum class Err : unsigned char {
    ok = 0,
    truncated,  // input ended in the middle of a structure
    malformed,  // input violates the MQTT specification
    oversize,   // input exceeds a compile-time capacity (e.g. max packet size)
    capacity,   // a fixed-size pool or table is full
    state,      // operation is not valid in the current state
};

constexpr bool is_ok(Err e) noexcept { return e == Err::ok; }

// Human-readable name, intended for examples, tests and diagnostics.
inline const char* err_name(Err e) noexcept {
    switch (e) {
    case Err::ok:
        return "ok";
    case Err::truncated:
        return "truncated";
    case Err::malformed:
        return "malformed";
    case Err::oversize:
        return "oversize";
    case Err::capacity:
        return "capacity";
    case Err::state:
        return "state";
    }
    return "unknown";
}

} // namespace minimosq

#endif // MINIMOSQ_CORE_ERROR_HPP
