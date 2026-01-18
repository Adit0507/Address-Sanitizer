#include "asan_allocator.h"
#include "asan_shadow.h"
#include "asan_report.h"
#include <cstdlib>
#include <cstring>
#include <execinfo.h>
#include <dlfcn.h>

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

    void AsanAllocator::init(){
        if(initialized_) return;

        ShadowMemory:: getInstance().init();
        initialized_ = true;
    }

}