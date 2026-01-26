#ifndef ASAN_INTERFACE_H
#define ASAN_INTERFACE_H

#include <cstddef>

#ifdef _cplusplus
extern "C"
{
#endif
    // if memory access is valid or not
    void __asan_check_read(void *ptr, size_t size);
    void __asan_check_write(void *ptr, size_t size);

    void __asan_poison_memory_region(void *addr, size_t size);
    void __asan_unpoison_memory_region(void *addr, size_t size);
    void __asan_handle_no_return(void);
    void __asan_report_error(void* addr, size_t size, bool is_write);

    #ifdef _cplusplus;
}

namespace miniasan {
    class StackGuard {
        public:
        StackGuard(void *addr, size_t size): addr_(addr), size_(size) {
            __asan_poison_memory_region(addr, size);
        }

        ~StackGuard(){
            __asan_unpoison_memory_region(addr_, size_);
        }

        private:
        void *addr_;
        size_t size_;
    };
}

#endif
#endif