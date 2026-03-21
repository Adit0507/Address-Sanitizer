#pragma once

#ifndef ASAN_TYPES_H
#define ASAN_TYPES_H

#include <cstdint>
#include <cstddef>

// error classificatios
enum class ErrorType : uint8_t
{
    None = 0,
    HeapBufferOverflow,  // write-read past end of heap allocation
    HeapBufferUnderflow, // write-read before start of heap allocation
    UseAfterFree,        // acces to freed memory
    DoubleFree,          // free called twice on same pointer
    InvalidFree,
    StackBufferOverflow,
    StackBufferUnderflow,
    UseAfterReturn,
    Unknown,
};

enum class ShadowState : uint8_t
{
    Accessible = 0x00,
    Partial = 0x01,
    HeapLeftRedzone = 0xFA,
    HeapRightRedzone = 0xFB,
    FreedMemory = 0xFD,
    StackRedzone = 0xF1,
    GlobalRedzone = 0xFF,
};

// stack frame
static constexpr int kMaxStackFrame = 64;
struct StackTrace
{
    void *frames[kMaxStackFrame];
    int depth;

    StackTrace() : depth(0)
    {
        for (auto &f : frames)
            f = nullptr;
    }
};

// allocation metadata
struct AllocInfo
{
    uintptr_t   user_ptr;  // pointer returned to user
    size_t      user_size;    // size requested by user
    uintptr_t   alloc_ptr; // pointer from underlying alllocator
    size_t      alloc_size;
    StackTrace  alloc_trace;
    bool        is_freed;

    AllocInfo() : user_ptr(0), user_size(0), alloc_ptr(0), alloc_size(0), is_freed(false) {}
};


#endif