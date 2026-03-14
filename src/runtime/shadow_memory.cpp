#include "shadow_memory.h"
#include "../platform/win32_memory.h"
#include <cassert>
#include <cstdio>
#include <cstring>
#include <algorithm>

bool ShadowMemory ::init()
{
    if (shadow_base_ != nullptr)
        return true;

    void *base = platform_reserve(shadow::kShadowSize);
    if (!base)
    {
        fprintf(stderr, "[asan] FATAL: Failed to reserve %.0f TB shadow region.\n", static_cast<double>(shadow::kShadowSize) / (1ULL << 40));
        return false;
    }

    shadow_base_ = base;
    committed_end_ = 0;

    fprintf(stderr, "[asan] Shadow memory initialised. Base %p, size: 16TB\n", shadow_base_);

    return true;
}

void ShadowMemory::shutdown()
{
    if (shadow_base_ == nullptr)
        return;
    platform_release(shadow_base_);
    shadow_base_ = nullptr;
    committed_end_ = 0;
}

ShadowMemory::~ShadowMemory()
{
    shutdown();
}

bool ShadowMemory ::ensure_committed(uint8_t *shadow_ptr, size_t len)
{
    uintptr_t base = reinterpret_cast<uintptr_t>(shadow_base_);
    uintptr_t start = reinterpret_cast<uintptr_t>(shadow_ptr);

    assert(start >= base && "shadow_ptr is below shadow_base_");
    size_t offset_end = (start - base) + len;

    if (offset_end <= committed_end_)
        return true;

    size_t gran = platform_alloc_granularity();
    size_t commit_start = committed_end_ & ~(gran - 1);
    size_t commit_end = (offset_end + gran - 1) & ~(gran - 1);
    size_t commit_size = commit_end - commit_start;

    if (commit_start + commit_size > shadow::kShadowSize)
    {
        fprintf(stderr, "[my_asan] FATAL: Shadow commit would exceed 16TB.\n");
        return false;
    }

    void *result = platform_commit(reinterpret_cast<void *>(base + commit_start), commit_size);
    if (!result)
        return false;

    committed_end_ = commit_end;

    return true;
}

void ShadowMemory ::poison(uintptr_t addr, size_t size, uint8_t value)
{
    assert(shadow_base_ != nullptr && "Shadow Memory not initialised");
    assert((size % shadow::kGranularity) == 0 && "size must be a multiple of 8 for aligned poison()");

    if (size == 0)
        return;

    uint8_t *sptr = shadow_ptr_of(addr);
    size_t slen = size >> shadow::kGranularityLog2;

    if (!ensure_committed(sptr, slen))
        return;

    memset(sptr, value, slen);
}
void ShadowMemory::unpoison(uintptr_t addr, size_t size)
{
    poison(addr, size, shadow::kAccessible);
}

void ShadowMemory::poison_partial(uintptr_t addr, size_t size, uint8_t value)
{
    assert(shadow_base_ != nullptr && "Shadow Memory not initialised");
    if (size == 0)
        return;

    size_t full_slots = size / shadow::kGranularity; // handlin all fully covered 8byte slots
    if (full_slots > 0)
    {
        poison(addr, full_slots * shadow::kGranularity, value);
    }

    size_t remainder = size % shadow::kGranularity;
    if (remainder != 0)
    {
        uintptr_t partial_addr = addr + full_slots * shadow::kGranularity;
        uint8_t *sptr = shadow_ptr_of(partial_addr);
        if (!ensure_committed(sptr, 1))
            return;

        *sptr = value;
    }
}

void ShadowMemory ::unpoison_partial(uintptr_t addr, size_t size)
{
    assert(shadow_base_ != nullptr && "Shadow Memory not initialised");
    if (size == 0)
        return;

    size_t full_slots = size / shadow::kGranularity;
    if (full_slots > 0)
    {
        unpoison(addr, full_slots * shadow::kGranularity);
    }

    size_t remainder = size % shadow::kGranularity;
    if (remainder != 0)
    {
        uintptr_t partial_addr = addr + full_slots * shadow::kGranularity;
        uint8_t *sptr = shadow_ptr_of(partial_addr);

        if (!ensure_committed(sptr, 1))
            return;

        *sptr = static_cast<uint8_t>(remainder);
    }
}

// querying stuff
uint8_t ShadowMemory::get_shadow_byte(uintptr_t addr) const
{
    assert(shadow_base_ != nullptr && "Shadow Memory not initialised");

    const uint8_t *sptr = shadow_ptr_of(addr);
    if (!platform_is_committed(const_cast<uint8_t *>(sptr), 1))
        return shadow::kAccessible;

    return *sptr;
}

bool ShadowMemory ::is_poisoned(uintptr_t addr, size_t access_size) const
{
    assert(shadow_base_ != nullptr && "ShadowMemory not initialised");
    assert((access_size == 1 || access_size == 2 || access_size == 4 || access_size == 8) && "access_size must be 1, 2, 4, or 8");

    uint8_t shadow_val = get_shadow_byte(addr);

    if (shadow_val == shadow::kAccessible)
        return false;
    if (shadow_val >= shadow::kGranularity)
        return true;

    size_t offset = addr & (shadow::kGranularity - 1);

    return (offset + access_size) > static_cast<size_t>(shadow_val);
}

bool ShadowMemory::is_range_poisoned(uintptr_t addr, size_t size) const
{
    assert(shadow_base_ != nullptr && "ShadowMemory isnt initialized");

    if (size == 0)
        return false;

    uintptr_t end = addr + size;
    for (uintptr_t cur = addr; cur < end; cur += shadow::kGranularity)
    {
        size_t remaining = end - cur;
        size_t check_size = std::min(remaining, shadow::kGranularity);

        if (is_poisoned(cur, check_size))
            return true;
    }

    return false;
}

// diagnostics
uintptr_t ShadowMemory::shadow_addr_of(uintptr_t real_addr) const
{
    return reinterpret_cast<uintptr_t>(shadow_addr_of(real_addr));
}

void ShadowMemory ::dump_shadow_region(uintptr_t addr, size_t context_bytes) const
{
    uintptr_t start = (addr - context_bytes) & ~(shadow::kGranularity - 1ULL);
    uintptr_t end = (addr + context_bytes);

    fprintf(stderr, "\n[asan] Shadow map around %p:\n", reinterpret_cast<void *>(addr));
    fprintf(stderr, "  %-18s  %-6s  %s\n", "Real Addr", "Shadow", "State");
    fprintf(stderr, "  %-18s  %-6s  %s\n", "---------", "------", "-----");

    for (uintptr_t curr = start; curr < end; curr += shadow::kGranularity)
    {
        uint8_t sb = get_shadow_byte(curr);
        const char *state = "accessible";
        if (sb == shadow::kHeapLeftRedZone)
            state = "HEAP LEFT REDZONE";
        else if (sb == shadow::kHeapRightRedZone)
            state = "HEAP RIGHT REDZONE";
        else if (sb == shadow::kFreedMemory)
            state = "FREED MEMORY";
        else if (sb == shadow::kStackRedzone)
            state = "STACK REDZONE";
        else if (sb == shadow::kGlobalRedzone)
            state = "GLOBAL REDZONE";
        else if (sb >= 1 && sb <= 7)
        {
            state = "partial";
        }

        const char *marker = (curr <= addr && addr < curr + shadow::kGranularity) ? ">>" : "  ";
        fprintf(stderr, "%s  0x%016llx   0x%02x   %s\n", marker, static_cast<unsigned long long>(curr), sb, state);
    }

    fprintf(stderr, "\n");
}

ShadowMemory &get_shadow_memory()
{
    static ShadowMemory instance;
    return instance;
}