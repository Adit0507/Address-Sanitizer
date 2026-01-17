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

    class ShadowMemory
    {
    public:
        static ShadowMemory &getInstance();
        void init();                              // initializn shadow memory
        int8_t *getShadowAddress(uintptr_t addr); // shadow address for given memory address
        bool isAccessible(uintptr_t addr, size_t size);

        void poison(uintptr_t addr, size_t size, int8_t magic); // inaccesible memory
        void unpoison(uintptr_t addr, size_t size);             // marking memory as unaccessible

        void poisonRedZone(uintptr_t addr, size_t size, int8_t magic);
        int8_t getShadowValue(uintptr_t addr);

    private:
        ShadowMemory();
        ~ShadowMemory();

        // preventing copying
        ShadowMemory(const ShadowMemory &) = delete;
        ShadowMemory &operator=(const ShadowMemory &) = delete;

        int8_t *shadow_base_;
        bool initialized_;
        static const uintptr_t kShadowOffset = 0;
    };

}

#endif