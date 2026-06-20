#pragma once

#ifndef ASAN_SHADOW_MEMORY_H
#define ASAN_SHADOW_MEMORY_H

#include <cstdint>
#include <cstddef>
#include <windows.h>

namespace shadow
{
    constexpr uint8_t kAccessible = 0x00;
    constexpr uint8_t kPartialBase = 0x01;
    constexpr uint8_t kHeapLeftRedZone = 0xFA;
    constexpr uint8_t kHeapRightRedZone = 0xFB;
    constexpr uint8_t kFreedMemory = 0xFD;
    constexpr uint8_t kStackRedzone = 0xF1;
    constexpr uint8_t kGlobalRedzone = 0xFF;

    // one shadow byte coveers ths many real bytes
    constexpr size_t kGranularity = 8;
    constexpr size_t kGranularityLog2 = 3;

    constexpr size_t kShadowSize = (1ULL << 44);
}

class ShadowMemory
{
public:
    ShadowMemory() = default;
    ~ShadowMemory();

    ShadowMemory(const ShadowMemory &) = delete;
    ShadowMemory &operator=(const ShadowMemory &) = delete;
    ShadowMemory(ShadowMemory &&) = delete;
    ShadowMemory &operator=(ShadowMemory &&) = delete;

    bool init();
    void shutdown(); // releases the reserved shadwo region
    bool is_initialized() const { return shadow_base_ != nullptr; };

    // poisoning and unpoisioning
    void poison(uintptr_t addr, size_t size, uint8_t value);
    void unpoison(uintptr_t addr, size_t size);

    // poisoning a region whose size isnt multiple of 8
    void poison_partial(uintptr_t addr, size_t size, uint8_t value);
    void unpoison_partial(uintptr_t addr, size_t size); // unpoisoning region whose size may not be a multiple of 8

    uint8_t get_shadow_byte(uintptr_t addr) const;              // shadw byte for 8byte slot containing 'addr'
    bool is_poisoned(uintptr_t addr, size_t access_size) const; // true if the access [addr, addr+access_size) would be invalid.
    bool is_range_poisoned(uintptr_t addr, size_t size) const;  // true if any byte in [addr, addr +size] is poisoned

    uintptr_t shadow_addr_of(uintptr_t real_addr) const;                                 // returns shadow memory addres corresponding to real address
    uintptr_t shadow_base() const { return reinterpret_cast<uintptr_t>(shadow_base_); }; // returns base address of shadow region
    void dump_shadow_region(uintptr_t addr, size_t context_bytes = 32) const;

private:
    inline uint8_t *shadow_ptr_of(uintptr_t real_addr) const
    {
        return reinterpret_cast<uint8_t *>(shadow_base_) + (real_addr >> shadow::kGranularityLog2);
    };

    bool ensure_committed(uint8_t *shadow_ptr, size_t len);

    void *shadow_base_ = nullptr;
    size_t committed_end_ = 0;
};

ShadowMemory &get_shadow_memory();

#endif