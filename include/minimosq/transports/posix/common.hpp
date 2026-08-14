// minimosq — shared bits for the POSIX example transports.
//
// These transports are reference implementations for hosted POSIX
// systems; the broker core itself never includes OS headers.
//
// SPDX-License-Identifier: MIT
#ifndef MINIMOSQ_TRANSPORTS_POSIX_COMMON_HPP
#define MINIMOSQ_TRANSPORTS_POSIX_COMMON_HPP

#include <cstddef>
#include <cstdint>
#include <ctime>

#include <fcntl.h>
#include <unistd.h>

#include "../../core/span.hpp"

namespace minimosq {

// Monotonic milliseconds. Wraps every ~49 days, which the broker's
// deadline arithmetic is built to tolerate.
inline uint32_t posix_now_ms() noexcept {
    timespec ts{};
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<uint32_t>(static_cast<uint64_t>(ts.tv_sec) * 1000u +
                                 static_cast<uint64_t>(ts.tv_nsec) / 1000000u);
}

inline bool set_nonblocking(int fd) noexcept {
    const int flags = ::fcntl(fd, F_GETFL, 0);
    return flags >= 0 && ::fcntl(fd, F_SETFL, flags | O_NONBLOCK) == 0;
}

// Fixed-size output ring buffer: bytes the peer has not accepted yet.
template <size_t Capacity>
class OutRing {
public:
    size_t size() const noexcept { return len_; }
    bool empty() const noexcept { return len_ == 0; }

    // Append the whole span or nothing (false = overflow).
    bool append(ByteSpan b) noexcept {
        if (len_ + b.len > Capacity) {
            return false;
        }
        for (size_t i = 0; i < b.len; ++i) {
            buf_[(head_ + len_ + i) % Capacity] = b.data[i];
        }
        len_ += b.len;
        return true;
    }

    // Longest contiguous readable chunk (for a single write()).
    ByteSpan front_chunk() const noexcept {
        const size_t tail_room = Capacity - head_;
        return ByteSpan{buf_ + head_, len_ < tail_room ? len_ : tail_room};
    }

    void consume(size_t n) noexcept {
        head_ = (head_ + n) % Capacity;
        len_ -= n;
    }

    void clear() noexcept {
        head_ = 0;
        len_ = 0;
    }

private:
    uint8_t buf_[Capacity];
    size_t head_ = 0;
    size_t len_ = 0;
};

} // namespace minimosq

#endif // MINIMOSQ_TRANSPORTS_POSIX_COMMON_HPP
