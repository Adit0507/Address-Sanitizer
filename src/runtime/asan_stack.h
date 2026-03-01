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

        void protectStackVariable(void *left_rz, void *var, size_t var_size, void *right_rz);
        void unprotectStackVariable(void *left_rz, void *right_rz);

    private:
        StackProtector() = default;
        StackProtector(const StackProtector &) = delete;
        StackProtector &operator=(const StackProtector &) = delete;
    };

    // raii wrapper
    class StackVariableGuard
    {
    public:
        StackVariableGuard(void *left_rz, void *var, size_t var_size, void *right_rz);
        ~StackVariableGuard();

    private:
        void *left_redzone_;
        void *right_redzone_;
    };
}

#define ASAN_PROTECT_STACK_VAR(var)                   \
    char __asan_left_rz_##var[32];                    \
    char __asan_right_rz_##var[32];                   \
    miniasan::StackVariableGuard __stack_guard_##var( \
        __asan_left_rz_##var, &var, sizeof(var), __asan_right_rz_##var)

#endif