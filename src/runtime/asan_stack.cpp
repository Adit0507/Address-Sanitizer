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

    void StackProtector::unpoisonStackRedZone(void *addr, size_t size)
    {
        ShadowMemory::getInstance().unpoison((uintptr_t)addr, size);
    }

    void StackProtector::protectStackVariable(void *addr, size_t size, void **left_rz, void **right_rz)
    {
        uintptr_t var_addr = (uintptr_t)addr;
        uintptr_t left_rz_addr = var_addr - kStackRedZoneSize;
        uintptr_t right_rz_addr = var_addr + size;

        *left_rz = (void *)left_rz_addr;
        *right_rz = (void *)right_rz_addr;

        poisonStackRedZone(*left_rz, kStackRedZoneSize);
        poisonStackRedZone(*right_rz, kStackRedZoneSize);

        ShadowMemory::getInstance().unpoison(var_addr, size);
    }

    void StackProtector::unprotectStackVariable(void *left_rz, void *right_rz)
    {
        if (left_rz)
        {
            unpoisonStackRedZone(left_rz, kStackRedZoneSize);
        }
        if (right_rz)
        {
            unpoisonStackRedZone(right_rz, kStackRedZoneSize);
        }
    }

    StackVariableGuard::StackVariableGuard(void *addr, size_t size) : addr_(addr), size_(size)
    {
        StackProtector::getInstance().protectStackVariable(addr, size, &left_redzone_, &right_redzone_);
    }
    StackVariableGuard::~StackVariableGuard()
    {
        StackProtector::getInstance().unprotectStackVariable(left_redzone_, right_redzone_);
    }
}
