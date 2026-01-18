#ifndef ASAN_ALLOCATOR_H
#define ASAN_ALLOCATOR_H

#include <cstddef>
#include <cstdint>
#include <unordered_map>
#include <mutex>
#include <deque>

namespace miniasan
{
    static const size_t kRedZoneSize = 32;

    struct AllocationMetaData
    {
        void *user_ptr;   // pointer returned to user
        size_t user_size; // size requested by pointer
        void *real_ptr;   // allocated pointr
        size_t real_size; // total size including red zones
        void *alloc_stack[16];
        size_t alloc_stack_size;
        void *free_stack[16]; // Stack trace at free
        size_t free_stack_size;
        bool is_freed;
    };

}

#endif