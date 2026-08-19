// minimosq — retained message store.
//
// One entry per topic, in a fixed pool with linear lookup — retained
// stores on embedded brokers are small, and simplicity wins over an
// index structure.
//
// SPDX-License-Identifier: MIT
#ifndef MINIMOSQ_BROKER_RETAINED_HPP
#define MINIMOSQ_BROKER_RETAINED_HPP

#include <cstddef>

#include "../core/fixed_buffer.hpp"
#include "../core/fixed_string.hpp"
#include "../core/pool.hpp"
#include "../protocol/constants.hpp"
#include "../topic.hpp"

namespace minimosq {

template <typename Traits>
class RetainedStore {
public:
    struct Entry {
        FixedString<Traits::max_topic_len> topic;
        FixedBuffer<Traits::max_payload_len> payload;
        QoS qos = QoS::at_most_once;
    };

    // Store or replace the retained message for a topic. Returns false
    // when it cannot be stored: store full, or topic/payload exceed the
    // compile-time limits. (The broker treats that as best-effort and
    // still forwards the message to live subscribers.)
    bool set(StrView topic, ByteSpan payload, QoS qos) noexcept {
        if (topic.len > Traits::max_topic_len || payload.len > Traits::max_payload_len) {
            return false;
        }
        Entry* e = find(topic);
        if (e == nullptr) {
            e = pool_.alloc();
            if (e == nullptr) {
                return false;
            }
            e->topic.assign(topic);
        }
        e->payload.assign(payload);
        e->qos = qos;
        return true;
    }

    void remove(StrView topic) noexcept {
        Entry* e = find(topic);
        if (e != nullptr) {
            pool_.release(e);
        }
    }

    // Visit every retained message matching a topic filter.
    template <typename F>
    void for_each_match(StrView filter, F&& f) noexcept {
        pool_.for_each([&](Entry& e) {
            if (topic_matches(filter, e.topic.view())) {
                f(e);
            }
        });
    }

    size_t size() const noexcept { return pool_.size(); }

private:
    Entry* find(StrView topic) noexcept {
        return pool_.find([&](Entry& e) { return e.topic.equals(topic); });
    }

    Pool<Entry, Traits::max_retained> pool_;
};

}  // namespace minimosq

#endif  // MINIMOSQ_BROKER_RETAINED_HPP
