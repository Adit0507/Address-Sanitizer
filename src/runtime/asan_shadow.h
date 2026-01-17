#ifndef ASAN_SHADOW_H
#define ASAN_SHADOW_H

#include <cstdint>
#include <cstddef>

namespace miniasn
{
    static const int SHADOW_SCALE = 3;
    static const size_t SHADOW_GRANULARITY = 1ULL << SHADOW_SCALE; // 8 bytes

    // shadow memory encoding
    static const int8_t kAsanHeapLeftRedzoneMagic = -6;
    static const int8_t kAsanHeapRightRedzoneMagic = -7;
    static const int8_t kAsanHeapFreeMagic = -3;
    static const int8_t kAsanStackRedzoneMagic = -16;
    static const int8_t kAsanStackMidRedzoneMagic = -13;
    static const int8_t kAsanStackLeftRedzoneMagic = -15;
    static const int8_t kAsanStackRightRedzoneMagic = -14;
    
}

#endif