#pragma once
#ifdef ASAN_H
#define ASAN_H

#include "asan_config.h"
#include "asan_types.h"

#include <cstddef>
#include <cstdint>
#include <type_traits>

void asan_init();     // reseving shadow memory & installing heap hooks
void asan_shutdown(); // flush quarantine, printin summary & release shadow memory

void asan_check(uinptr_t addr, size_t size, bool is_write);

inline void asan_check_read(const void *ptr, size_t size)
{
    asan_check(reinterpret_cast<uintptr_t>(ptr), size, false);
}
inline void asan_check_write(void *ptr, size_t size)
{
    asan_check(reinterpret_cast<uintptr_t>(ptr), size, true);
}

// allocatin size bytes with redzone poisoning & metadata registration
void *asan_malloc(size_t size);
void *asan_calloc(size_t count, size_t size);
void *asan_realloc(void *ptr, size_t new_size);
void asan_free(void *ptr);

// convience macros
#define SAFE_MALLOC(T, count) static_cast<T *>(asan_malloc(sizeof(T) * (count)))
#define SAFE_CALLOC(T, count) static_cast<T *>(asan_calloc((count), sizeof(T)))
#define SAFE_FREE(ptr) asan_free(ptr)

#define SAFE_NEW(T, ...) new (asan_malloc(sizeof(T))) T(__VA_ARGS__)
#define SAFE_DELETE(ptr)                                           \
    do                                                             \
    {                                                              \
        if (ptr)                                                   \
        {                                                          \
            using _Tp = std::remove_reference_t<decltype(*(ptr))>; \
            (ptr)->~_Tp();                                         \
            asan_free(ptr);                                        \
            (ptr) = nullptr;                                       \
        }                                                          \
    } while (0)

void asan_report_summary(); // sumary of all errors
int asan_error_count();

void asan_poison(void *ptr, size_t size, uint8_t shadow_value);
void asan_poison_partial(void *ptr, size_t size, uint8_t shadow_value);
void asan_unpoison(void *ptr, size_t size);

// Common poison values exposed for advanced users
#define ASAN_POISON_HEAP_LEFT_REDZONE 0xFA
#define ASAN_POISON_HEAP_RIGHT_REDZONE 0xFB
#define ASAN_POISON_FREED 0xFD
#define ASAN_POISON_STACK_REDZONE 0xF1

#endif