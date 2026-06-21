#pragma once

#ifndef ASAN_HEAP_TRACKER_H
#define ASAN_HEAP_TRACKER_H

#include "asan_types.h"
#include "asan_config.h"

#include <cstddef>
#include <cstdint>
#include <unordered_map>
// #include <mutex>
#define WIN32_LEAN_AND_MEAN
#include <windows.h>

class HeapTracker
{
public:
    HeapTracker()
    {
        InitializeCriticalSection(&cs_);
        live_ = nullptr;
        freed_ = nullptr;
    }
    ~HeapTracker()
    {
        delete live_;
        delete freed_;
        DeleteCriticalSection(&cs_);
    }

    HeapTracker(const HeapTracker &) = delete;
    HeapTracker &operator=(const HeapTracker &) = delete;

    void *on_malloc(size_t size);
    void *on_calloc(size_t count, size_t elem_size);
    void *on_realloc(void *ptr, size_t new_size);
    void on_free(void *ptr);

    bool get_alloc_info(uintptr_t user_ptr, AllocInfo &out) const;
    bool find_allocation_for_addr(uintptr_t user_ptr, AllocInfo &out) const;
    bool is_known_freed(uintptr_t user_ptr, AllocInfo &out) const;
    size_t live_count() const;
    size_t total_allocated() const;

private:
    using AllocMap = std::unordered_map<uintptr_t, AllocInfo>;
    void *allocate_with_redzones(size_t user_size, AllocInfo &out);
    void ensure_maps()
    {
        if (!live_)
            live_ = new AllocMap();
        if (!freed_)
            freed_ = new AllocMap();
        }

    mutable CRITICAL_SECTION cs_;
    AllocMap *live_;
    AllocMap *freed_;
    size_t total_allocated_ = 0;
};

HeapTracker &get_heap_tracker();

#endif