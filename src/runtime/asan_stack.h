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

    // raii wrapper
    class StackVariableGuard {
        public:
            StackVariableGuard(void *addr, size_t size);
            ~StackVariableGuard();

        private:
            void *left_redzone_;
            void *right_redzone_;
            void *addr_;
            size_t size_;
    };
}

#define ASAN_PROTECT_STACK_VAR(var) \
    miniasan::StackVariableGuard __stack_guard_##var(&var, sizeof(var))

#endif