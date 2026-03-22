#pragma once
#ifndef ASAN_CONFIG_H
#define ASAN_CONFIG_H

// no of bytes placed before and after every heap allocation
#ifndef ASAN_REDZONE_SIZE
#define ASAN_REDZONE_SIZE 32
#endif

static_assert(ASAN_REDZONE_SIZE % 8 == 0, "ASAN_REDZONE_SIZE must be a multiple of 8");
static_assert(ASAN_REDZONE_SIZE >= 8, "ASAN_REDZONE_SIZE must be atleast 8");

// max total bytes hedl in quarantine queue before forced flush
#ifndef ASAN_QUARANTINE_MAX_BYTES
#define ASAN_QUARANTINE_MAX_BYTES (64ULL * 1024 * 1024) // 64 MB
#endif

// stack trace depth
// max frames
#ifndef ASAN_MAX_STACK_FRAMES
#define ASAN_MAX_STACK_FRAMES 32
#endif

// output
#ifndef ASAN_PRINT_SHADOW_CONTEXT
#define ASAN_PRINT_SHADOW_CONTEXT 1
#endif

#ifndef ASAN_SHADOW_CONTEXT_BYTES
#define ASAN_SHADOW_CONTEXT_BYTES 32
#endif

#ifndef ASAN_ABORT_ON_ERROR
#define ASAN_ABORT_ON_ERROR 1
#endif

#endif