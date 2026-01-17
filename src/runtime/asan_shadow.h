#ifndef ASAN_SHADOW_H
#define ASAN_SHADOW_H

#include <cstdint>
#include <cstddef>

namespace miniasan
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

    inline int8_t *memToShadow(uintptr_t addr)
    {
        return ShadowMemory::getInstance().getShadowAddress(addr);
    }
    inline bool addressIsPoisoned(uintptr_t addr)
    {
        int8_t shadow_value = *memToShadow(addr);
        if (shadow_value == 0)
            return false;

        int8_t last_accessible_byte = shadow_value;
        int8_t offset_in_granule = addr & (SHADOW_GRANULARITY - 1);

        return offset_in_granule >= last_accessible_byte;
    }
}

#endif