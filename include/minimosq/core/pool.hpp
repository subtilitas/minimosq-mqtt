// minimosq — fixed-capacity object pool.
//
// Slot-stable storage for objects with independent lifetimes (sessions,
// retained messages). Objects keep their address from alloc() to
// release(), so raw pointers/indices into the pool stay valid.
//
// alloc() value-initialises: new (slot) T(). For a T with no
// user-provided default constructor, value-initialisation itself
// zero-initialises the object before any constructor or default member
// initialiser runs. The zeroing is that rule, not a constructor doing
// the work. It is what the broker relies on: slots are reused, and a
// session must not start life holding the topic and payload bytes of
// the client that had the slot before it. The guarantee covers members,
// not the padding between them, which may still hold what the previous
// occupant left; nothing here reads padding. A T with a user-provided
// default constructor gets no zero-initialisation at all — that
// constructor runs on its own — so a reuser relying on this must check
// which case its type is in. Note that T() = default; declared in the
// class is not user-provided and stays in the first case.
//
// It costs one zeroing of sizeof(T) per alloc(). Measured with GCC 13 on
// x86-64, a session at DefaultTraits is a little over 7 KB, so that is
// roughly 7 KB per CONNECT; the figure moves with the traits, the
// compiler and the ABI.
//
// T must not throw on construction or destruction, and neither must a
// callable passed to for_each(): both run inside noexcept members, so a
// throwing one terminates. Within the library the only user-supplied
// code reaching for_each() is the Observer, whose own contract carries
// the same requirement.
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

    // Destroy an object previously returned by alloc(). A null pointer,
    // a pointer outside this pool, an interior pointer, or a slot that
    // is already free is ignored: without the check a double release
    // destroys the object twice and underflows count_ to SIZE_MAX.
    void release(T* p) noexcept {
        const size_t i = slot_index(p);
        if (i >= Capacity || !used_[i]) {
            return;
        }
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
    // Slot index of p, or Capacity if p is null, outside the pool, or
    // not exactly at a slot boundary. Comparison goes through the byte
    // representation so a foreign pointer never reaches the division.
    size_t slot_index(const T* p) const noexcept {
        if (p == nullptr) {
            return Capacity;
        }
        const unsigned char* q = reinterpret_cast<const unsigned char*>(p);
        for (size_t i = 0; i < Capacity; ++i) {
            if (q == storage_ + i * sizeof(T)) {
                return i;
            }
        }
        return Capacity;
    }

    void* slot(size_t i) noexcept { return storage_ + i * sizeof(T); }

    T* ptr(size_t i) noexcept {
        return std::launder(reinterpret_cast<T*>(storage_ + i * sizeof(T)));
    }

    alignas(T) unsigned char storage_[Capacity * sizeof(T)];
    bool used_[Capacity] = {};
    size_t count_ = 0;
};

}  // namespace minimosq

#endif  // MINIMOSQ_CORE_POOL_HPP
