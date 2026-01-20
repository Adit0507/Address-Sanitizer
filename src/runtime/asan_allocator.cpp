#include "asan_allocator.h"
#include "asan_shadow.h"
#include "asan_report.h"
#include <cstdlib>
#include <cstring>
#ifdef _WIN32
  #include <windows.h>
  #include <dbghelp.h>
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

    void AsanAllocator::init(){
        if(initialized_) return;

        ShadowMemory:: getInstance().init();
        initialized_ = true;
    }

}