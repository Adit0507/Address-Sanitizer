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

    class AsanAllocator
    {
    public:
        static AsanAllocator &getInstance();

        void init();
        void *allocate(size_t size);
        void deallocate(void *ptr);

        bool isValidAllocation(void *ptr);
        AllocationMetaData *getMetaData(void *ptr);
        bool checkAccess(void *ptr, size_t size);

    private:
        AsanAllocator();
        ~AsanAllocator();
        AsanAllocator(const AsanAllocator &) = delete;
        AsanAllocator &operator=(const AsanAllocator &) = delete;

        size_t captureStackTrace(void **buffer, size_t max_frames); // capture stack trace
        void addToQuarantine(AllocationMetaData *metadata);
        void processQuarantine();

        std::unordered_map<void *, AllocationMetaData *> allocations_;
        std::mutex mutex_;

        // quarantine queue
        std::deque<AllocationMetaData *> quarantine_;
        size_t quarantine_size_;
        static const size_t kMaxQuarantineSize = 64 * 1024 * 1024;
        bool initialized_;
    };

}

#endif