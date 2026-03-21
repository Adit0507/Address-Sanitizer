#pragma once

#ifndef ASAN_TYPES_H
#define ASAN_TYPES_H

#include <cstdint>
#include <cstddef>

//error classificatios
enum class ErrorType : uint8_t
{
    None = 0,
    HeapBufferOverflow, //write-read past end of heap allocation
    HeapBufferUnderflow,    //write-read before start of heap allocation
    UseAfterFree,   //acces to freed memory
    DoubleFree, //free called twice on same pointer
    InvalidFree,
    StackBufferOverflow,
    StackBufferUnderflow,
    UseAfterReturn,
    Unknown

};




#endif