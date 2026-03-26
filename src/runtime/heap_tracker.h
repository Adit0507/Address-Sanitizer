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

};


#endif