#include "win32_memory.h"

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>

static SYSTEM_INFO get_system_info() {
    static SYSTEM_INFO si = []{
        SYSTEM_INFO info {};
        
        GetSystemInfo(&info);
        return info;
    }();

    return si;
}

void *platform_reserve(size_t size){
    void *ptr = VirtualAlloc(nullptr, size, MEM_RESERVE, PAGE_READWRITE);
    if(!ptr){
        fprintf(stderr, "asan platform_reserve(%zu) failed: error %lu\n", size, GetLastError());
    }

    return ptr;
}

// platform commit
void *platform_commit(void *base, size_t size){
    void* ptr = VirtualAlloc(base, size, MEM_COMMIT, PAGE_READWRITE);
    if(!ptr){
        fprintf(stderr, "[asan] platform_commit(%p, %zu) failed: error %lu\n", base, size, GetLastError());
    }

    return ptr;
}