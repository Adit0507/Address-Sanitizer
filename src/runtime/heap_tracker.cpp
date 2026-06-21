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

struct CSLock
{
    CRITICAL_SECTION &cs;
    CSLock(CRITICAL_SECTION &c) : cs(c) { EnterCriticalSection(&cs); }
    ~CSLock() { LeaveCriticalSection(&cs); }
};
struct ReentrancyGuard
{
    bool &flag;
    ReentrancyGuard(bool &f) : flag(f) { flag = true; }
    ~ReentrancyGuard() { flag = false; }
};

static thread_local int tl_tracker_depth_;

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

void *HeapTracker ::on_malloc(size_t size)
{
    if (tl_tracker_depth_ > 0)
        return ::malloc(size);
    ++tl_tracker_depth_;

    if (size == 0)
        size = 1;
    if (!get_shadow_memory().is_initialized())
    {
        --tl_tracker_depth_;
        return ::malloc(size);
    }

    ensure_maps();

    AllocInfo info;
    void *ptr = allocate_with_redzones(size, info);
    if (ptr)
    {
        if(freed_){
            freed_->erase(info.user_ptr);
        }
        (*live_)[info.user_ptr] = info;
        total_allocated_ += size;
    }

    --tl_tracker_depth_;
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
    if(tl_tracker_depth_ >0){
        return ::realloc(ptr, new_size);
    }

    AllocInfo old_info;
    bool found = false;
    {
        ++tl_tracker_depth_;
        if(live_){
            auto it = live_->find(reinterpret_cast<uintptr_t> (ptr));
            if(it != live_->end()){
                old_info = it->second;
                found = true;
            }
        }
        --tl_tracker_depth_;
    }

    if(!found){
        report_invalid_free(reinterpret_cast<uintptr_t>(ptr));
        return nullptr;
    }   

    void *new_ptr = on_malloc(new_size);
    if (!new_ptr)
        return nullptr;

    size_t copy_size = old_info.user_size < new_size ? old_info.user_size : new_size;
    memcpy(new_ptr, ptr, copy_size);

    on_free(ptr);
    return new_ptr;
}

// on free
void HeapTracker::on_free(void *ptr)
{
    fprintf(stderr, "[on_free] called with ptr= %p\n", ptr);
    if (tl_tracker_depth_ > 0)
    {
        ::free(ptr);
        return;
    }
    ++tl_tracker_depth_;

    if (!ptr)
    {
        --tl_tracker_depth_;
        return;
    }

    if (!get_shadow_memory().is_initialized())
    {
        ::free(ptr);
        --tl_tracker_depth_;
        return;
    }

    ensure_maps(); // ← safe to construct maps now

    uintptr_t user_addr = reinterpret_cast<uintptr_t>(ptr);

    auto freed_it = freed_->find(user_addr);
    if (freed_it != freed_->end())
    {
        --tl_tracker_depth_;
        report_double_free(user_addr, freed_it->second);
        return;
    }

    auto live_it = live_->find(user_addr);
    if (live_it == live_->end())
    {
        --tl_tracker_depth_;
        report_invalid_free(user_addr);
        return;
    }

    AllocInfo info = live_it->second;
    live_->erase(live_it);
    info.is_freed = true;

    if (freed_->size() >= kMaxFreedRecords)
        freed_->erase(freed_->begin());
    (*freed_)[user_addr] = info;

    --tl_tracker_depth_;
    get_quarantine().enqueue(info);
}

// metdata queries
bool HeapTracker::get_alloc_info(uintptr_t user_ptr, AllocInfo &out) const
{
    if (!live_)
        return false;
    CSLock lock(cs_);

    auto it = live_->find(user_ptr);
    if (it == live_->end())
        return false;
    out = it->second;

    return true;
}

bool HeapTracker::find_allocation_for_addr(uintptr_t addr, AllocInfo &out) const
{
    if (!live_)
        return false;
    CSLock lock(cs_);

    for (const auto &[key, info] : *live_)
    {
        if (addr >= info.alloc_ptr && addr < info.alloc_ptr + info.alloc_size)
        {
            out = info;
            return true;
        }
    }
    if (!freed_)
        return false;
    for (const auto &[key, info] : *freed_)
    {
        if (addr >= info.alloc_ptr && addr < info.alloc_ptr + info.alloc_size)
        {
            out = info;
            return true;
        }
    }

    return false;
}

bool HeapTracker::is_known_freed(uintptr_t user_ptr, AllocInfo &out) const
{
    if (!freed_)
        return false;
    CSLock lock(cs_);

    auto it = freed_->find(user_ptr);
    if (it == freed_->end())
        return false;
    out = it->second;

    return true;
}

size_t HeapTracker::live_count() const
{
    if (!live_)
        return 0;
    CSLock lock(cs_);
    return live_->size();
}
size_t HeapTracker::total_allocated() const
{
    CSLock lock(cs_);
    return total_allocated_;
}

HeapTracker &get_heap_tracker()
{
    static HeapTracker instance;
    return instance;
}
