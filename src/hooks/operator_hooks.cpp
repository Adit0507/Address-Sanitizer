#include "operator_hooks.h"
#include "../runtime/heap_tracker.h"
#include <new>
#include <cstdlib>

// new operator
void *operator new(size_t size)
{
    void *ptr = get_heap_tracker().on_malloc(size);
    if (!ptr)
        throw std::bad_alloc();

    return ptr;
}

void *operator new[](size_t size)
{
    void *ptr = get_heap_tracker().on_malloc(size);
    if (!ptr)
        throw std::bad_alloc();

    return ptr;
}
//nothrow returns nullptr instead of throwing failure
void *operator new(size_t size, const std::nothrow_t &) noexcept
{
    return get_heap_tracker().on_malloc(size);
}
void *operator new[](size_t size, const std::nothrow_t &) noexcept
{
    return get_heap_tracker().on_malloc(size);
}

// delete operator
void operator delete(void *ptr) noexcept
{
    get_heap_tracker().on_free(ptr);
}
void operator delete[](void *ptr) noexcept
{
    get_heap_tracker().on_free(ptr);
}
void operator delete(void *ptr, const std:: nothrow_t&) noexcept
{
    get_heap_tracker().on_free(ptr);
}
void operator delete[](void *ptr, const std::nothrow_t &) noexcept
{
    get_heap_tracker().on_free(ptr);
}

void operator  delete(void *ptr, size_t ) noexcept {
    get_heap_tracker().on_free(ptr);
}
void operator  delete[] (void *ptr, size_t ) noexcept {
    get_heap_tracker().on_free(ptr);
}