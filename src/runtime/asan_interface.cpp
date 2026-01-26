#include "asan_interface.h"
#include "asan_shadow.h"
#include "asan_allocator.h"
#include "asan_report.h"

using namespace miniasan;

extern "C"
{
    void __asan_check_read(void *ptr, size_t size)
    {
        AsanAllocator::getInstance().checkAccess(ptr, size);
    }
    void __asan_check_write(void *ptr, size_t size)
    {
        AsanAllocator::getInstance().checkAccess(ptr, size);
    }

    void __asan_poison_memory_region(void *addr, size_t size)
    {
        ShadowMemory::getInstance().poison((uintptr_t)addr, size, kAsanStackRedzoneMagic);
    }
    void __asan_unpoison_memory_region(void *addr, size_t size)
    {
        ShadowMemory::getInstance().unpoison((uintptr_t)addr, size);
    }
    void __asan_handle_no_return(void) {}
    void __asan_report_error(void* addr, size_t size, bool is_write){
        ErrorReporter:: getInstance().reportMemoryError(addr, size);
    }
}