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

// Outcome of RetainedStore::set().
enum class RetainStatus : unsigned char {
    stored,        // the new value is now the retained value for this topic
    dropped,       // could not be stored, and no retained value existed
    stale_purged,  // could not be stored, so the previous value was removed
};

template <typename Traits>
class RetainedStore {
public:
    struct Entry {
        FixedString<Traits::max_topic_len> topic;
        FixedBuffer<Traits::max_payload_len> payload;
        QoS qos = QoS::at_most_once;
    };

    // Store or replace the retained message for a topic.
    //
    // A message too large to own, or a full store, cannot be kept: the
    // broker treats that as best-effort and still forwards the message
    // to live subscribers. What must not happen is the *previous* value
    // surviving — a retained topic is a last-known-value slot, and a
    // subscriber joining later would be handed a stale reading that
    // looks current, with nothing anywhere saying it is stale. So a
    // refused update evicts what was there and reports stale_purged.
    RetainStatus set(StrView topic, ByteSpan payload, QoS qos) noexcept {
        Entry* e = find(topic);
        if (topic.len > Traits::max_topic_len || payload.len > Traits::max_payload_len) {
            if (e == nullptr) {
                return RetainStatus::dropped;
            }
            pool_.release(e);
            return RetainStatus::stale_purged;
        }
        if (e == nullptr) {
            e = pool_.alloc();
            if (e == nullptr) {
                return RetainStatus::dropped;  // store full; nothing to purge
            }
            e->topic.assign(topic);
        }
        e->payload.assign(payload);
        e->qos = qos;
        return RetainStatus::stored;
    }

    void remove(StrView topic) noexcept {
        Entry* e = find(topic);
        if (e != nullptr) {
            pool_.release(e);
        }
    }

    // Visit every retained message, matched or not. Used by SUBSCRIBE,
    // which decides per message which of the session's freshly granted
    // filters cover it — so it must see each stored message once, not
    // once per filter.
    template <typename F>
    void for_each(F&& f) noexcept {
        pool_.for_each(f);
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
