// minimosq — incremental MQTT frame parser.
//
// A transport hands the broker whatever bytes arrived — half a packet,
// three packets, one byte. FrameParser reassembles the stream into
// complete control packets without ever allocating: the body buffer is
// a template-sized array inside the parser (one parser per connection).
//
// SPDX-License-Identifier: MIT
#ifndef MINIMOSQ_PROTOCOL_FRAME_HPP
#define MINIMOSQ_PROTOCOL_FRAME_HPP

#include <cstddef>
#include <cstdint>

#include "../core/error.hpp"
#include "../core/span.hpp"
#include "constants.hpp"

namespace minimosq {

// MaxBodySize bounds the Remaining Length (variable header + payload) of
// an accepted inbound packet; larger packets yield Err::oversize.
template <size_t MaxBodySize>
class FrameParser {
public:
    // Consume data, invoking on_packet(first_byte, body) for every
    // complete packet. body points into the parser's buffer and is only
    // valid during the call. on_packet returns false to stop consuming
    // (the caller is tearing the connection down); remaining input is
    // discarded and feed() returns Err::ok.
    //
    // On any non-ok result the parser is left in an undefined state and
    // the connection must be closed (or reset() called).
    template <typename F>
    Err feed(ByteSpan data, F&& on_packet) {
        size_t i = 0;
        while (i < data.len) {
            switch (state_) {
            case State::first_byte:
                first_byte_ = data[i++];
                rem_len_ = 0;
                len_shift_ = 0;
                body_len_ = 0;
                state_ = State::length;
                break;

            case State::length: {
                const uint8_t b = data[i++];
                rem_len_ |= static_cast<uint32_t>(b & 0x7F) << len_shift_;
                if ((b & 0x80) != 0) {
                    if (len_shift_ >= 21) {
                        return Err::malformed;  // varint longer than 4 bytes [MQTT-2.2.3]
                    }
                    len_shift_ = static_cast<uint8_t>(len_shift_ + 7);
                    break;
                }
                if (rem_len_ > MaxBodySize) {
                    return Err::oversize;
                }
                if (rem_len_ == 0) {
                    if (!on_packet(first_byte_, ByteSpan{})) {
                        return Err::ok;
                    }
                    state_ = State::first_byte;
                } else {
                    state_ = State::body;
                }
                break;
            }

            case State::body: {
                const size_t want = rem_len_ - body_len_;
                const size_t have = data.len - i;
                const size_t take = want < have ? want : have;
                for (size_t k = 0; k < take; ++k) {
                    body_[body_len_ + k] = data[i + k];
                }
                body_len_ += take;
                i += take;
                if (body_len_ == rem_len_) {
                    if (!on_packet(first_byte_, ByteSpan{body_, body_len_})) {
                        return Err::ok;
                    }
                    state_ = State::first_byte;
                }
                break;
            }
            }
        }
        return Err::ok;
    }

    void reset() noexcept {
        state_ = State::first_byte;
        rem_len_ = 0;
        body_len_ = 0;
        len_shift_ = 0;
    }

private:
    enum class State : uint8_t { first_byte, length, body };

    uint8_t body_[MaxBodySize];
    size_t body_len_ = 0;
    uint32_t rem_len_ = 0;
    State state_ = State::first_byte;
    uint8_t first_byte_ = 0;
    uint8_t len_shift_ = 0;
};

}  // namespace minimosq

#endif  // MINIMOSQ_PROTOCOL_FRAME_HPP
