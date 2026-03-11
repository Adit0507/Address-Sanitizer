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