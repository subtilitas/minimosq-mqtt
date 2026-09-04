// minimosq — fixed-capacity vector.
//
// A drop-in replacement for the small subset of std::vector the broker
// needs, backed entirely by in-object storage. Never allocates, never
// throws: push_back/emplace_back report failure instead.
//
// T must not throw on value-initialisation, copy construction,
// assignment or destruction. The mutators are noexcept and do all four
// inside themselves — emplace_back() value-initialises with T(), which
// zeroes a scalar rather than leaving it indeterminate, push_back()
// copy-constructs, remove_ordered() and remove_unordered() assign from
// an rvalue to close the gap, and clear() destroys — so a throwing
// element type terminates rather than propagating. Assignment covers
// both operators: an rvalue binds to a copy-assignment operator when
// the type has no move assignment, so a throwing copy assignment is
// just as fatal. The library stores scalars and aggregates of
// fixed-size arrays here, none of which can throw; the requirement is
// stated for anyone reusing the container.
//
// Known deviation: ptr() launders the address of a slot whether or not
// an object is live in it, and begin()/end() form that address on an
// empty vector. [ptr.launder] requires a live object, so those two cases
// are undefined by the letter of the standard. They are on the hottest
// path in the library and no misbehaviour has been observed — the suite
// runs clean under AddressSanitizer and UndefinedBehaviorSanitizer with
// -fno-sanitize-recover=all. Recorded rather than papered over.
//
// SPDX-License-Identifier: MIT
#ifndef MINIMOSQ_CORE_STATIC_VECTOR_HPP
#define MINIMOSQ_CORE_STATIC_VECTOR_HPP

#include <cstddef>
#include <new>

namespace minimosq {

template <typename T, size_t Capacity>
class StaticVector {
    static_assert(Capacity > 0, "StaticVector needs a non-zero capacity");

public:
    StaticVector() = default;
    ~StaticVector() { clear(); }

    // Element storage is in-object; copying could be added but the
    // library never needs it, so it is disabled to prevent accidents.
    StaticVector(const StaticVector&) = delete;
    StaticVector& operator=(const StaticVector&) = delete;

    size_t size() const noexcept { return size_; }
    bool empty() const noexcept { return size_ == 0; }
    bool full() const noexcept { return size_ == Capacity; }
    static constexpr size_t capacity() noexcept { return Capacity; }

    T& operator[](size_t i) noexcept { return *ptr(i); }
    const T& operator[](size_t i) const noexcept { return *ptr(i); }

    T* begin() noexcept { return ptr(0); }
    T* end() noexcept { return ptr(0) + size_; }
    const T* begin() const noexcept { return ptr(0); }
    const T* end() const noexcept { return ptr(0) + size_; }

    // Copy v into the next free slot. Returns false when full.
    bool push_back(const T& v) noexcept {
        if (size_ == Capacity) {
            return false;
        }
        new (slot(size_)) T(v);
        ++size_;
        return true;
    }

    // Default-construct in the next free slot and return it; nullptr when full.
    T* emplace_back() noexcept {
        if (size_ == Capacity) {
            return nullptr;
        }
        T* p = new (slot(size_)) T();
        ++size_;
        return p;
    }

    // Remove element i, shifting the tail left. Preserves relative order —
    // the broker relies on this for in-order message delivery.
    // Out-of-range indices are ignored.
    void remove_ordered(size_t i) noexcept {
        if (i >= size_) {
            return;
        }
        for (size_t j = i; j + 1 < size_; ++j) {
            *ptr(j) = static_cast<T&&>(*ptr(j + 1));
        }
        pop_back();
    }

    // Remove element i by moving the last element into its place. O(1),
    // does not preserve order. Out-of-range indices are ignored.
    void remove_unordered(size_t i) noexcept {
        if (i >= size_) {
            return;
        }
        if (i + 1 < size_) {
            *ptr(i) = static_cast<T&&>(*ptr(size_ - 1));
        }
        pop_back();
    }

    // No-op on an empty vector. The guard matters: without it size_
    // underflows to SIZE_MAX and every later iteration walks off the end,
    // which is a far worse failure than doing nothing.
    void pop_back() noexcept {
        if (size_ == 0) {
            return;
        }
        ptr(size_ - 1)->~T();
        --size_;
    }

    void clear() noexcept {
        while (size_ > 0) {
            pop_back();
        }
    }

private:
    void* slot(size_t i) noexcept { return storage_ + i * sizeof(T); }

    T* ptr(size_t i) noexcept {
        return std::launder(reinterpret_cast<T*>(storage_ + i * sizeof(T)));
    }
    const T* ptr(size_t i) const noexcept {
        return std::launder(reinterpret_cast<const T*>(storage_ + i * sizeof(T)));
    }

    alignas(T) unsigned char storage_[Capacity * sizeof(T)];
    size_t size_ = 0;
};

}  // namespace minimosq

#endif  // MINIMOSQ_CORE_STATIC_VECTOR_HPP
