#ifndef ASAN_REPORT_H
#define ASAN_REPORT_H

#include "asan_allocator.h"

namespace miniasan
{
    class ErrorReporter
    {
    public:
        static ErrorReporter &getInstance();
        void reportMemoryError(void *addr, size_t size);
        void reportInvalidFree(void *ptr);
        void reportDoubleFree(void *ptr, AllocationMetaData *metadata);
        void reportUseAfterFree(void *ptr, AllocationMetaData *metadata);

    private:
        ErrorReporter() = default;

        void printStackTrace(void **stack, size_t size, const char *label);
        void printShadowBytes(void *addr, size_t range);
        const char *shadowByteToDescription(int8_t value);
    };
}

#endif