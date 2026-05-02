#pragma once

#ifndef ASAN_HEAP_TRACKER_H
#define ASAN_HEAP_TRACKER_H

#include "asan_types.h"
#include "asan_config.h"

#include <cstddef>
#include <cstdint>
#include <unordered_map>
#include <mutex>

class HeapTracker
{
    friend HeapTracker &get_heap_tracker();

public:
    HeapTracker() = default;
    ~HeapTracker() = default;

    HeapTracker(const HeapTracker &) = delete;
    HeapTracker &operator=(const HeapTracker &) = delete;

    // allocation-deallocation hooks
    void *on_malloc(size_t size);                    // alocates space for redzones, poison/upoisoning user region
    void *on_calloc(size_t count, size_t elem_size); // zero initailises user region after on_malloc
    void *on_realloc(void *ptr, size_t new_size);

    void on_free(void *ptr); // looks up metadtaa, validates pointer, records free stack trace

    // metadata queries
    bool get_alloc_info(uintptr_t user_ptr, AllocInfo &out) const;
    bool find_allocation_for_addr(uintptr_t addr, AllocInfo &out) const;
    bool is_known_freed(uintptr_t user_ptr, AllocInfo &out) const;

    size_t live_count() const;
    size_t total_allocated() const;

private:
    void *allocate_with_redzones(size_t user_size, AllocInfo &out);

    mutable std::mutex mutex_;
    std::unordered_map<uintptr_t, AllocInfo> live_;
    std::unordered_map<uintptr_t, AllocInfo> freed_;

    size_t total_allocated_ = 0;
};

HeapTracker &get_heap_tracker();

#endif