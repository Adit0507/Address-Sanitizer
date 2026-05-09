#pragma once

#ifndef ASAN_MALLOC_HOOKS_H
#define ASAN_MALLOC_HOOKS_H

#include <cstddef>

#ifdef __cplusplus
extern "C"
{
#endif

    void *asan_crt_malloc(size_t size);
    void *asan_crt_calloc(size_t count, size_t size);
    void *asan_crt_realloc(void *ptr, size_t size);
    void asan_crt_free(void *ptr);

#ifdef __cplusplus
}
#endif

#ifdef ASAN_REDIRECT_MALLOC
#define malloc(sz) asan_crt_malloc(sz)
#define calloc(n,sz) asan_crt_calloc(n, sz)
#define realloc(p, sz) asan_crt_realloc(p, sz)
#define free(p) asan_crt_free(p)

#endif

#endif