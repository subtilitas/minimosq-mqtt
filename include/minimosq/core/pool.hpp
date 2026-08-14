// minimosq — fixed-capacity object pool.
//
// Slot-stable storage for objects with independent lifetimes (sessions,
// retained messages). Objects keep their address from alloc() to
// release(), so raw pointers/indices into the pool stay valid.
//
// SPDX-License-Identifier: MIT
#ifndef MINIMOSQ_CORE_POOL_HPP
#define MINIMOSQ_CORE_POOL_HPP

#include <cstddef>
#include <new>

namespace minimosq {

template <typename T, size_t Capacity>
class Pool {
    static_assert(Capacity > 0, "Pool needs a non-zero capacity");

public:
    Pool() = default;
    ~Pool() { clear(); }

    Pool(const Pool&) = delete;
    Pool& operator=(const Pool&) = delete;

    size_t size() const noexcept { return count_; }
    bool empty() const noexcept { return count_ == 0; }
    bool full() const noexcept { return count_ == Capacity; }
    static constexpr size_t capacity() noexcept { return Capacity; }

    // Default-construct an object in the first free slot; nullptr when full.
    T* alloc() noexcept {
        for (size_t i = 0; i < Capacity; ++i) {
            if (!used_[i]) {
                T* p = new (slot(i)) T();
                used_[i] = true;
                ++count_;
                return p;
            }
        }
        return nullptr;
    }

    // Destroy an object previously returned by alloc().
    void release(T* p) noexcept {
        const size_t i = index_of(p);
        p->~T();
        used_[i] = false;
        --count_;
    }

    void clear() noexcept {
        for (size_t i = 0; i < Capacity; ++i) {
            if (used_[i]) {
                ptr(i)->~T();
                used_[i] = false;
            }
        }
        count_ = 0;
    }

    // Slot index of an object owned by this pool.
    size_t index_of(const T* p) const noexcept {
        return static_cast<size_t>(reinterpret_cast<const unsigned char*>(p) - storage_) /
               sizeof(T);
    }

    // Object in slot i, or nullptr if the slot is free.
    T* at(size_t i) noexcept { return (i < Capacity && used_[i]) ? ptr(i) : nullptr; }

    // Visit every live object. Iteration is by slot, so releasing the
    // current element (or any other) from inside f is safe; objects
    // allocated during iteration into earlier slots are not visited.
    template <typename F>
    void for_each(F&& f) noexcept {
        for (size_t i = 0; i < Capacity; ++i) {
            if (used_[i]) {
                f(*ptr(i));
            }
        }
    }

    // First live object satisfying pred, or nullptr.
    template <typename Pred>
    T* find(Pred&& pred) noexcept {
        for (size_t i = 0; i < Capacity; ++i) {
            if (used_[i] && pred(*ptr(i))) {
                return ptr(i);
            }
        }
        return nullptr;
    }

private:
    void* slot(size_t i) noexcept { return storage_ + i * sizeof(T); }

    T* ptr(size_t i) noexcept {
        return std::launder(reinterpret_cast<T*>(storage_ + i * sizeof(T)));
    }

    alignas(T) unsigned char storage_[Capacity * sizeof(T)];
    bool used_[Capacity] = {};
    size_t count_ = 0;
};

} // namespace minimosq

#endif // MINIMOSQ_CORE_POOL_HPP
