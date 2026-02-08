#include "asan_stack.h"
#include "asan_shadow.h"
#include <cstdlib>
#include <cstring>

namespace miniasan
{
    StackProtector &StackProtector::getInstance()
    {
        static StackProtector instance;

        return instance;
    }

    void StackProtector::poisonStackRedZone(void *addr, size_t size)
    {
        ShadowMemory::getInstance().poison((uintptr_t)addr, size, kAsanStackRedzoneMagic);
    }
}
