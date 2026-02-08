#ifndef ASAN_STACK_H
#define ASAN_STACK_H

#include <cstddef>
#include <cstdint>

namespace miniasan
{
    static const size_t kStackRedZoneSize = 32;

    class StackProtector
    {
    public:
        static StackProtector &getInstance();

        void poisonStackRedZone(void *addr, size_t size);
        void unpoisonStackRedZone(void *addr, size_t size);

        void protectStackVariable(void *addr, size_t size, void **left_rz, void **right_rz);
        void unprotectStackVariable(void *left_rz, void *right_rz);

    private:
        StackProtector() = default;
        StackProtector(const StackProtector &) = delete;
        StackProtector &operator=(const StackProtector &) = delete;
    };
}

#endif