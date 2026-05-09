#include "malloc_hooks.h"
#include "../runtime/heap_tracker.h"
#include <cstddef>

#ifdef __cplusplus
extern "C"
{
#endif

    void *asan_crt_malloc(size_t size)
    {
        return get_heap_tracker().on_malloc(size);
    }
    void *asan_crt_calloc(size_t count, size_t size)
    {
        return get_heap_tracker().on_calloc(count, size);
    }
    void *asan_crt_realloc(void *ptr, size_t size)
    {
        return get_heap_tracker().on_realloc(ptr, size);
    }
    void asan_crt_free(void *ptr)
    {
        get_heap_tracker().on_free(ptr);
    }

#ifdef __cplusplus
}
#endif