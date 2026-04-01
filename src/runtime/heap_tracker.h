#pragma once

#ifndef ASAN_HEAP_TRACKER_H
#define ASAN_HEAP_TRACKER_H

#include "asan_types.h"
#include "asan_config.h"

#include <cstddef>
#include <cstdint>
#include <unordered_map>
#include <mutex>

class HeapTracker {
    HeapTracker() = default;
    ~HeapTracker() = default;

    HeapTracker(const HeapTracker&) = delete;
    HeapTracker& operator =(const HeapTracker&) = delete;

    // allocation-deallocation hooks
    void *on_malloc(size_t size); //alocates space for redzones, poison/upoisoning user region
    void *on_calloc(size_t count, size_t elem_size);    //zero initailises user region after on_malloc
    void *on_realloc(void *ptr, size_t new_size);

    void on_free(void *ptr);//looks up metadtaa, validates pointer, records free stack trace
};


#endif