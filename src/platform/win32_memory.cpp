#include "win32_memory.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>

static SYSTEM_INFO get_system_info()
{
    static SYSTEM_INFO si = []
    {
        SYSTEM_INFO info{};

        GetSystemInfo(&info);
        return info;
    }();

    return si;
}

void *platform_reserve(size_t size)
{
    void *ptr = VirtualAlloc(nullptr, size, MEM_RESERVE, PAGE_READWRITE);
    if (!ptr)
    {
        fprintf(stderr, "asan platform_reserve(%zu) failed: error %lu\n", size, GetLastError());
    }

    return ptr;
}

// platform commit
void *platform_commit(void *base, size_t size)
{
    void *ptr = VirtualAlloc(base, size, MEM_COMMIT, PAGE_READWRITE);
    if (!ptr)
    {
        fprintf(stderr, "[asan] platform_commit(%p, %zu) failed: error %lu\n", base, size, GetLastError());
    }

    return ptr;
}

void platform_release(void *base)
{
    if (base)
        VirtualFree(base, 0, MEM_RELEASE);
}

size_t platform_page_size()
{
    return static_cast<size_t>(get_system_info().dwPageSize);
}
size_t platform_alloc_granularity()
{
    return static_cast<size_t>(get_system_info().dwAllocationGranularity);
}

bool platform_is_committed(void *addr, size_t size)
{
    MEMORY_BASIC_INFORMATION mbi{};
    size_t queried = 0;
    uint8_t *cur = static_cast<uint8_t *>(addr);

    while (queried < size)
    {
        if (VirtualQuery(cur, &mbi, sizeof(mbi) == 0))
            return false;

        if (mbi.State != MEM_COMMIT)
            return false;
        queried += mbi.RegionSize;
        cur += mbi.RegionSize;
    }

    return true;
}