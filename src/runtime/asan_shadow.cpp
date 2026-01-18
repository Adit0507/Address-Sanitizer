#include "asan_shadow.h"
#include <cstdlib>
#include <cstring>
#include <iostream>

#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#endif

namespace miniasan
{
  ShadowMemory &ShadowMemory ::getInstance()
  {
    static ShadowMemory instance;
    return instance;
  }

  ShadowMemory::ShadowMemory() : shadow_base_(nullptr), initialized_(false) {}
  ShadowMemory::~ShadowMemory()
  {
    if (!shadow_base_)
      return;

    VirtualFree(shadow_base_, 0, MEM_RELEASE);
  }

  void ShadowMemory::init()
  {
    if (initialized_)
      return;

    size_t shadow_size = 1ULL << 32;
    shadow_base_ = (int8_t *)VirtualAlloc(nullptr, shadow_size, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

    if (!shadow_base_)
    {
      std::cerr << "Failed to allocate shadow memory (VirtualAlloc)\n";
      std::exit(1);
    }

    memset(shadow_base_, kAsanHeapFreeMagic, shadow_size);
    initialized_ = true;
  }

  int8_t *ShadowMemory::getShadowAddress(uintptr_t addr)
  {
    uintptr_t shadow_offset = addr >> SHADOW_SCALE;

    return shadow_base_ + shadow_offset;
  }

  int8_t ShadowMemory::getShadowValue(uintptr_t addr)
  {
    return *getShadowAddress(addr);
  }

  bool ShadowMemory ::isAccessible(uintptr_t addr, size_t size)
  {
    uintptr_t end_addr = addr + size;

    uintptr_t aligned_start = addr & ~(SHADOW_GRANULARITY - 1);
    uintptr_t aligned_end = (end_addr + SHADOW_GRANULARITY - 1) & ~(SHADOW_GRANULARITY - 1);

    for (uintptr_t a = aligned_start; a < aligned_end; a += SHADOW_GRANULARITY)
    {
      int8_t *shadow = getShadowAddress(a);
      int8_t shadow_value = *shadow;

      if (shadow_value < 0)
      {
        return false;
      }
      if (shadow_value > 0)
      {
        uintptr_t region_start = a;
        uintptr_t region_end = a + SHADOW_GRANULARITY;

        if (addr >= region_start && addr < region_start + shadow_value)
        {
          if (end_addr > region_start + shadow_value)
          {
            return false;
          }
        }
        else if (addr >= region_start + shadow_value)
        {
          return false;
        }
      }
    }

    return true;
  }

  void ShadowMemory::poison(uintptr_t addr, size_t size, int8_t magic)
  {
    int8_t *shadow_start = getShadowAddress(addr);
    size_t shadow_size = (size + SHADOW_GRANULARITY - 1) >> SHADOW_SCALE;

    memset(shadow_start, magic, shadow_size);
  }
  void ShadowMemory::unpoison(uintptr_t addr, size_t size)
  {
    int8_t *shadow_start = getShadowAddress(addr);
    size_t full_regions = size >> SHADOW_SCALE;

    memset(shadow_start, 0, full_regions); // markin regions as accesible

    size_t remainder = size & (SHADOW_GRANULARITY - 1);
    if (remainder > 0)
    {
      shadow_start[full_regions] = remainder;
    }
  }
}
