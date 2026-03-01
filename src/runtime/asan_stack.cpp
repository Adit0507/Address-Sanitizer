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

    void StackProtector::protectStackVariable(void *left_rz,void *var, size_t var_size, void *right_rz)
    {
        poisonStackRedZone(left_rz, kStackRedZoneSize);
        poisonStackRedZone(right_rz, kStackRedZoneSize);
        
        ShadowMemory:: getInstance().unpoison((uintptr_t)var, var_size);
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

    StackVariableGuard::StackVariableGuard(void *left_rz, void* var,  size_t var_size, void *right_rz) : left_redzone_(left_rz), right_redzone_(right_rz)
    {
        StackProtector::getInstance().protectStackVariable(left_rz, var, var_size, right_rz);
    }
    StackVariableGuard::~StackVariableGuard()
    {
        StackProtector::getInstance().unprotectStackVariable(left_redzone_, right_redzone_);
    }
}
