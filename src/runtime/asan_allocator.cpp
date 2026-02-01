#include "asan_allocator.h"
#include "asan_shadow.h"
#include "asan_report.h"
#include <cstdlib>
#include <cstring>
#ifdef _WIN32
#include <windows.h>
#else
#include <execinfo.h>
#include <dlfcn.h>
#endif

namespace miniasan
{
    AsanAllocator &AsanAllocator::getInstance()
    {
        static AsanAllocator instance;
        return instance;
    }

    AsanAllocator::AsanAllocator() : quarantine_size_(0), initialized_(false) {}
    AsanAllocator::~AsanAllocator()
    {
        // Clean up quarantine
        for (auto *meta : quarantine_)
        {
            ::free(meta->real_ptr);
            delete meta;
        }
    }

    void AsanAllocator::init()
    {
        if (initialized_)
            return;

        ShadowMemory::getInstance().init();
        initialized_ = true;
    }

    size_t AsanAllocator::captureStackTrace(void **buffer, size_t max_frames)
    {
        return CaptureStackBackTrace(0, max_frames, buffer, nullptr);
    }

    static bool g_in_allocator = false; // preventing recursion

    void *GetRealMalloc(size_t size)
    {
        static HANDLE process_heap = GetProcessHeap();
        return HeapAlloc(process_heap, 0, size);
    }
    void RealFree(void *ptr)
    {
        static HANDLE procss_heap = GetProcessHeap();
        HeapFree(procss_heap, 0, ptr);
    }

    void *AsanAllocator::allocate(size_t size)
    {
        if (!initialized_)
            init();
        if (size == 0)
            size = 1;

        size_t total_size = kRedZoneSize + size + kRedZoneSize; // total size(both left and right)

        void *real_ptr = GetRealMalloc(total_size);
        if (!real_ptr)
            return nullptr;

        void *user_ptr = (char *)real_ptr + kRedZoneSize;

        // creatin metadata
        AllocationMetaData *metadata = new AllocationMetaData();
        metadata->user_ptr = user_ptr;
        metadata->user_size = size;
        metadata->real_ptr = real_ptr;
        metadata->real_size = total_size;
        metadata->is_freed = false;
        metadata->alloc_stack_size = captureStackTrace(metadata->alloc_stack, 16);
        metadata->free_stack_size = 0;

        // poisoning red zones
        ShadowMemory &shadow = ShadowMemory::getInstance();
        shadow.poisonRedZone((uintptr_t)real_ptr, kRedZoneSize, kAsanHeapLeftRedzoneMagic);
        shadow.poisonRedZone((uintptr_t)user_ptr + size, kRedZoneSize, kAsanHeapLeftRedzoneMagic);

        shadow.unpoison((uintptr_t)user_ptr, size); // unpoisin user area

        std::lock_guard<std::mutex> lock(mutex_);
        allocations_[user_ptr] = metadata;

        return user_ptr;
    }

    void AsanAllocator::deallocate(void *ptr)
    {
        if (!ptr)
            return;
        if (!initialized_)
            init();

        AllocationMetaData *metadata = nullptr;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            auto it = allocations_.find(ptr);
            if (it == allocations_.end())
            {
                ErrorReporter::getInstance().reportInvalidFree(ptr);
                return;
            }

            metadata = it->second;

            if (metadata->is_freed)
            {
                ErrorReporter::getInstance().reportDoubleFree(ptr, metadata);
                return;
            }

            metadata->is_freed = true;
            metadata->free_stack_size = captureStackTrace(metadata->free_stack, 16);
            allocations_.erase(it); // remvin from active allocations
        }

        // poison entire region including user space
        ShadowMemory &shadow = ShadowMemory::getInstance();
        shadow.poison((uintptr_t)metadata->real_ptr, metadata->real_size, kAsanHeapFreeMagic);

        addToQuarantine(metadata); // adding to quarantine instead of freeing immediately
    }

    void AsanAllocator::addToQuarantine(AllocationMetaData *metadata)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        quarantine_.push_back(metadata);
        quarantine_size_ += metadata->real_size;

        while (quarantine_size_ > kMaxQuarantineSize && !quarantine_.empty())
        {
            AllocationMetaData *old = quarantine_.front();
            quarantine_.pop_front();
            quarantine_size_ -= old->real_size;

            RealFree(old->real_ptr);
            delete old;
        }
    }

    bool AsanAllocator::isValidAllocation(void *ptr)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return allocations_.find(ptr) != allocations_.end();
    }

    AllocationMetaData*AsanAllocator:: getMetaData(void *ptr){
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = allocations_.find(ptr);

        return (it!= allocations_.end()) ? it->second: nullptr;
    }

}