#include "heap_tracker.h"
#include "shadow_memory.h"
#include "quarantine.h"
#include "../reporting/stack_trace.h"
#include "../reporting/error_reporter.h"
#include "asan_types.h"

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

HeapTracker &get_heap_tracker()
{
    static HeapTracker instance;
    return instance;
}
