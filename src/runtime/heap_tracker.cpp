#include "heap_tracker.h"
#include "shadow_memory.h"
#include "quarantine.h"
#include "../reporting/stack_trace.h"
#include "../reporting/error_reporter.h"
#include "asan_types.h"

#include <cstdlib>
#include <cstring>
#include <cassert>
#include <cstdio>

static constexpr size_t kRedzoneSize = ASAN_REDZONE_SIZE;
static constexpr size_t kMaxFreedRecords = 4096; // max no of freed alllocation records to keep double free

void *HeapTracker::allocate_with_redzones(size_t user_size, AllocInfo &info_out)
{
    size_t user_size_aligned = (user_size + 7) & ~7ULL;                  // user size upto 8byte boundary
    size_t total_size = kRedzoneSize + user_size_aligned + kRedzoneSize; // left redzone + aligned user data + right redzone

    void *raw = ::malloc(total_size);
    if (!raw)
        return nullptr;

    uintptr_t raw_addr = reinterpret_cast<uintptr_t>(raw);
    uintptr_t user_addr = raw_addr + kRedzoneSize;

    ShadowMemory &shadow = get_shadow_memory();
    shadow.poison(raw_addr, kRedzoneSize, shadow::kHeapLeftRedZone);       // poisonin left redzone
    uintptr_t right_rz_addr = raw_addr + kRedzoneSize + user_size_aligned; // poisonin right redzone
    shadow.poison(right_rz_addr, kRedzoneSize, shadow::kHeapRightRedZone);

    info_out.user_ptr = user_addr;
    info_out.user_size = user_size;
    info_out.alloc_ptr = raw_addr;
    info_out.alloc_size = total_size;
    info_out.is_freed = false;

    return reinterpret_cast<void *>(user_addr);
}

void *HeapTracker::on_malloc(size_t size)
{
    if (size == 0)
        size = 1;

    if (!get_shadow_memory().is_initialized())
    {
        return ::malloc(size);
    }

    AllocInfo info;
    void *ptr = allocate_with_redzones(size, info);
    if (!ptr)
        return nullptr;

    capture_stack_trace(info.alloc_trace, ASAN_MAX_STACK_FRAMES);
    {
        std::lock_guard<std::mutex> lock(mutex_);
        live_[info.user_ptr] = info;
        total_allocated_ += size;
    }

    return ptr;
}

void *HeapTracker::on_calloc(size_t count, size_t elem_size)
{
    size_t total = count * elem_size;

    void *ptr = on_malloc(total);
    if (ptr)
        memset(ptr, 0, total);

    return ptr;
}
void *HeapTracker::on_realloc(void *ptr, size_t new_size)
{
    if (!ptr)
        return on_malloc(new_size);
    if (!new_size)
    {
        on_free(ptr);
        return nullptr;
    }

    AllocInfo old_info;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = live_.find(reinterpret_cast<uintptr_t>(ptr));
        if (it == live_.end())
        {
            report_invalid_free(reinterpret_cast<uintptr_t>(ptr));
            return nullptr;
        }
        old_info = it->second;
    }

    void *new_ptr = on_malloc(new_size);
    if (!new_ptr)
        return nullptr;

    size_t copy_size = old_info.user_size < new_size ? old_info.user_size : new_size;
    memcpy(new_ptr, ptr, copy_size);

    on_free(ptr);
    return new_ptr;
}

HeapTracker &get_heap_tracker()
{
    static HeapTracker instance;
    return instance;
}
